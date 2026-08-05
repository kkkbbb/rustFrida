#![cfg(all(target_os = "android", target_arch = "aarch64"))]

//! Spawn 注入模式：向 Zygote 注入 Zymbiote 载荷，拦截新 App 启动。
//!
//! 核心流程：
//! 1. 向 Zygote 进程注入 zymbiote payload（hook setArgV0 JNI 指针）
//! 2. 解析进程名并启动目标 App（am start -S）
//! 3. 子进程中 zymbiote 触发，连接 socket 发送 hello
//! 4. rustFrida 收到 hello 后注入 agent
//! 5. 发送 ACK 恢复子进程

use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use crate::injection::{inject_via_bootstrapper, InjectionResult};
use crate::proc_mem::ProcMem;
use crate::process::{parse_proc_maps, wait_until_stopped, MapEntry};
use crate::{log_error, log_info, log_step, log_success, log_verbose, log_warn};

/// 嵌入编译好的 zymbiote ELF
const ZYMBIOTE_ELF: &[u8] = include_bytes!("../../zymbiote/build/zymbiote.elf");

/// ACK 字节
const ACK_BYTE: u8 = 0x42;

/// Spawn hello 消息
#[derive(Debug, Clone)]
struct SpawnHello {
    pid: u32,
    ppid: u32,
    package_name: String,
}

#[derive(Debug, Clone)]
struct SpawnTarget {
    package: String,
    process_name: String,
    request_keys: Vec<String>,
}

/// Zygote patch 信息（用于退出时还原）
struct ZygotePatch {
    pid: u32,
    /// payload 写入位置和原始数据
    payload_base: u64,
    payload_backup: Vec<u8>,
    /// payload 的 backing 文件路径和偏移（用于 COW 场景下读取真正的原始数据）
    #[allow(dead_code)]
    payload_path: String,
    #[allow(dead_code)]
    payload_file_offset: u64,
    /// setArgV0 指针位置和原始值（None = 三层扫描均 miss，走 setcontext-only 降级）
    setargv0_slot: Option<(u64, [u8; 8])>,
    /// setcontext GOT slot（可选）
    setcontext_got: Option<(u64, [u8; 8])>,
    /// capset GOT slot（可选，用于属性 profile mount）
    capset_got: Option<(u64, [u8; 8])>,
}

/// 全局状态
static ZYGOTE_PATCHES: OnceLock<Mutex<Vec<ZygotePatch>>> = OnceLock::new();
static SERVER_SOCKET_PATH: OnceLock<String> = OnceLock::new();
static SPAWN_REQUESTS: OnceLock<Mutex<HashMap<String, Arc<SpawnNotifier>>>> = OnceLock::new();
/// 属性 profile 目录（由 --profile 设置，None = 禁用）
static PROP_PROFILE_DIR: OnceLock<Option<String>> = OnceLock::new();

fn diag_env_flag(name: &str) -> bool {
    std::env::var(name)
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes"))
        .unwrap_or(false)
}

/// 设置属性 profile 目录（在 spawn_and_inject 之前调用）
pub(crate) fn set_prop_profile(profile_dir: Option<String>) {
    let _ = PROP_PROFILE_DIR.set(profile_dir);
}

/// Spawn 通知器：线程安全的单次值传递
struct SpawnNotifier {
    mutex: Mutex<Option<SpawnHello>>,
    cvar: std::sync::Condvar,
}

impl SpawnNotifier {
    fn new() -> Self {
        SpawnNotifier {
            mutex: Mutex::new(None),
            cvar: std::sync::Condvar::new(),
        }
    }

    fn send(&self, hello: SpawnHello) {
        let mut guard = self.mutex.lock().unwrap();
        *guard = Some(hello);
        self.cvar.notify_all();
    }

    fn recv_timeout(&self, dur: std::time::Duration) -> Option<SpawnHello> {
        let guard = self.mutex.lock().unwrap();
        match self.cvar.wait_timeout_while(guard, dur, |v| v.is_none()) {
            Ok((mut guard, timeout)) => {
                if timeout.timed_out() {
                    None
                } else {
                    guard.take()
                }
            }
            Err(_) => None,
        }
    }

    /// 非阻塞检查是否有值到达（用于超时后二次检查）
    fn try_recv(&self) -> Option<SpawnHello> {
        let mut guard = self.mutex.lock().unwrap();
        guard.take()
    }
}

fn unregister_spawn_keys(keys: &[String]) {
    if let Some(requests) = SPAWN_REQUESTS.get() {
        if let Ok(mut map) = requests.lock() {
            for key in keys {
                map.remove(key);
            }
        }
    }
}

fn cleanup_orphan_spawn_connections() {
    // 延迟短暂等待后检查，给 listener 线程一点时间完成存储
    std::thread::sleep(std::time::Duration::from_millis(100));

    let Some(conns) = ACTIVE_CONNECTIONS.get() else {
        return;
    };

    let orphan_entries: Vec<(u32, (std::os::unix::net::UnixStream, u32))> = {
        let mut map = conns.lock().unwrap();
        map.drain().collect()
    };

    for (orphan_pid, (mut stream, ppid)) in orphan_entries {
        log_warn!("清理超时孤儿连接: pid={}", orphan_pid);
        // 发 ACK 恢复子进程，避免永远挂起
        let _ = stream.write_all(&[ACK_BYTE]);
        // 等 EOF → 等 SIGSTOP → 还原 → SIGCONT（同步执行，
        // 防止 fire-and-forget 线程未完成就 exit 导致子进程卡在 SIGSTOP）
        drain_until_eof(&mut stream, std::time::Duration::from_secs(5));
        drop(stream);
        if let Err(e) = wait_until_stopped(orphan_pid) {
            log_verbose!("等待孤儿子进程 {} SIGSTOP 失败: {}", orphan_pid, e);
        } else {
            let _ = revert_child_patch_by_ppid(orphan_pid, ppid);
        }
        unsafe { libc::kill(orphan_pid as i32, libc::SIGCONT) };
    }
}

// ZymbioteContext 字段偏移常量（与 zymbiote.c 布局完全一致）
const CTX_SOCKET_PATH: usize = 0;
const CTX_PAYLOAD_BASE: usize = 64;
const CTX_PAYLOAD_SIZE: usize = 72;
const CTX_PAYLOAD_ORIGINAL_PROT: usize = 80;
const CTX_PACKAGE_NAME: usize = 88;
const CTX_ORIGINAL_SETCONTEXT: usize = 96;
const CTX_ORIGINAL_SET_ARGV0: usize = 104;
const CTX_MPROTECT: usize = 112;
const CTX_STRDUP: usize = 120;
const CTX_FREE: usize = 128;
const CTX_SOCKET: usize = 136;
const CTX_CONNECT: usize = 144;
const CTX_ERRNO: usize = 152;
const CTX_GETPID: usize = 160;
const CTX_GETPPID: usize = 168;
const CTX_SENDMSG: usize = 176;
const CTX_RECV: usize = 184;
const CTX_CLOSE: usize = 192;
const CTX_RAISE: usize = 200;
const CTX_PROP_REMAP: usize = 208;
const CTX_BLOCK_IN_SETCONTEXT: usize = 216;
const CTX_PASSIVE_SETARGV0: usize = 224;
const SETARGV0_SCAN_CHUNK_SIZE: usize = 8 * 1024 * 1024;
/// 读取 stream 直到 EOF 或错误（用于等待子进程关闭 socket）
fn drain_until_eof(stream: &mut std::os::unix::net::UnixStream, timeout: std::time::Duration) {
    stream.set_read_timeout(Some(timeout)).ok();
    let mut discard = [0u8; 1];
    loop {
        match stream.read(&mut discard) {
            Ok(0) | Err(_) => break,
            Ok(_) => continue,
        }
    }
}

/// 判断 maps 条目是否为 boot heap 区域（boot image / dalvik-LinearAlloc）
fn is_boot_heap(entry: &MapEntry) -> bool {
    entry.is_readable()
        && entry.is_writable()
        && !entry.is_executable()
        && !entry.is_shared()
        && (entry.path.contains("boot.art")
            || entry.path.contains("boot-framework.art")
            || entry.path.contains("boot-image-methods.art")
            || entry.path.contains("dalvik-LinearAlloc"))
}

/// 判断给定地址是否在 boot heap 区域中
fn is_boot_heap_addr(addr: u64, maps: &[MapEntry]) -> bool {
    maps.iter().any(|e| is_boot_heap(e) && addr >= e.start && addr < e.end)
}

fn is_private_rw_mapping(entry: &MapEntry) -> bool {
    entry.is_readable() && entry.is_writable() && !entry.is_executable() && !entry.is_shared()
}

fn is_readable_mapping(entry: &MapEntry) -> bool {
    entry.is_readable()
}

fn is_setargv0_rw_fallback_candidate(entry: &MapEntry) -> bool {
    entry.path.contains("dalvik-")
        || entry.path.contains("boot-image")
        || entry.path.contains("boot.art")
        || entry.path.contains("boot-framework")
        || entry.path.contains("[anon:stack_and_tls:")
}

fn is_setargv0_readable_fallback_candidate(entry: &MapEntry) -> bool {
    // libandroid_runtime.so 的 rodata 中也会保留静态 JNINativeMethod 表，
    // 里面包含 setArgV0 函数指针，但 zygote 已完成 RegisterNatives，
    // 该表不是后续 fork app 时使用的可写 native slot。选中它会导致
    // 对 r--p 文件映射 pwrite 失败，且即使写入成功也不能稳定拦截。
    entry.path.contains("dalvik-")
        || entry.path.contains("boot-image")
        || entry.path.contains("boot.art")
        || entry.path.contains("boot-framework")
}

/// 在 ELF dynsyms 中查找符号地址
fn find_dynsym_addr(elf: &goblin::elf::Elf, name: &str, base: u64) -> Option<u64> {
    elf.dynsyms
        .iter()
        .find(|sym| elf.dynstrtab.get_at(sym.st_name).map_or(false, |n| n == name))
        .map(|sym| base + sym.st_value)
}

fn map_load_bias(entry: &MapEntry) -> Option<u64> {
    entry.start.checked_sub(entry.offset)
}

fn find_loaded_module(maps: &[MapEntry], suffix: &str) -> Option<(u64, String)> {
    let matches_suffix = |entry: &MapEntry| entry.path.ends_with(suffix);
    let has_matching_exec = |base: u64, path: &str| {
        maps.iter().any(|entry| {
            entry.path == path && entry.is_executable() && map_load_bias(entry).map_or(false, |bias| bias == base)
        })
    };

    maps.iter()
        .filter(|entry| matches_suffix(entry) && entry.offset == 0 && !entry.is_shared())
        .find(|entry| has_matching_exec(entry.start, &entry.path))
        .or_else(|| {
            maps.iter()
                .filter(|entry| matches_suffix(entry) && entry.offset == 0)
                .find(|entry| has_matching_exec(entry.start, &entry.path))
        })
        .or_else(|| {
            maps.iter()
                .find(|entry| matches_suffix(entry) && entry.offset == 0 && !entry.is_shared())
        })
        .or_else(|| maps.iter().find(|entry| matches_suffix(entry) && entry.offset == 0))
        .map(|entry| (entry.start, entry.path.clone()))
        .or_else(|| {
            maps.iter()
                .find(|entry| matches_suffix(entry) && entry.is_executable())
                .and_then(|entry| map_load_bias(entry).map(|base| (base, entry.path.clone())))
        })
}

/// 共享的 spawn 前置步骤：确保 zymbiote 加载、注册请求、启动 App、等待 hello
/// 返回收到的 SpawnHello（子进程此时处于暂停状态）
fn spawn_and_wait_hello(package: &str) -> Result<SpawnHello, String> {
    // 1. 确保 zymbiote 已加载到所有 zygote 进程
    ensure_zymbiote_loaded()?;

    // 2. 解析启动目标并注册 spawn 请求。
    //    --spawn com.foo 按 launcher Activity 的 android:process 精确匹配；
    //    --spawn com.foo:remote 表示显式指定子进程，仍启动 com.foo 包。
    let target = resolve_spawn_target(package);
    if target.process_name != target.package {
        log_info!("主进程解析: {} -> {}", target.package, target.process_name);
    } else {
        log_verbose!("主进程解析: {} 使用默认包进程", target.package);
    }
    let notifier = Arc::new(SpawnNotifier::new());
    {
        let requests = SPAWN_REQUESTS.get_or_init(|| Mutex::new(HashMap::new()));
        let mut map = requests.lock().unwrap();
        // 检查重复 spawn 请求（与 Frida 一致：拒绝重复，防止前一个 spawn 永远收不到 hello）
        for key in &target.request_keys {
            if map.contains_key(key) {
                return Err(format!("已有一个针对 {} 的 spawn 请求正在进行中", key));
            }
        }
        for key in &target.request_keys {
            map.insert(key.clone(), notifier.clone());
        }
    }

    // 3. 强制停止并启动目标应用
    log_info!("正在启动应用 {}...", target.package);
    launch_app(&target.package)?;

    // 4. 等待 SpawnHello（20s 超时）
    log_info!("等待进程 {} 启动... (最长 20s)", target.process_name);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let poll_interval = std::time::Duration::from_millis(100);
    let hello = loop {
        if let Some(hello) = notifier.try_recv() {
            break hello;
        }

        if signal_received() {
            unregister_spawn_keys(&target.request_keys);
            return Err(format!("等待进程 {} 启动时收到终止信号", target.process_name));
        }

        let now = std::time::Instant::now();
        let Some(remaining) = deadline.checked_duration_since(now) else {
            // 超时后再 try_recv 一次：防止在极短窗口内 hello 刚到达但 condvar 已超时
            if let Some(late_hello) = notifier.try_recv() {
                log_verbose!("超时后发现晚到的 hello (pid={})", late_hello.pid);
                break late_hello;
            }

            unregister_spawn_keys(&target.request_keys);
            cleanup_orphan_spawn_connections();
            let live_processes = list_package_processes(&target.package);
            let live_hint = if live_processes.is_empty() {
                "  4. 未发现目标包相关进程".to_string()
            } else {
                format!("  4. 当前目标包相关进程:\n{}", live_processes.join("\n"))
            };
            return Err(format!(
                "等待进程 {} 启动超时 (20s)，请检查:\n  1. 包名是否正确\n  2. 应用是否已安装\n  3. Zygote 是否已被正确 patch\n{}",
                target.process_name, live_hint
            ));
        };

        let wait = remaining.min(poll_interval);
        if let Some(hello) = notifier.recv_timeout(wait) {
            break hello;
        }
    };

    // 清理剩余的 key（handle_zymbiote_connection 已 remove 一个，清理其它 key）
    unregister_spawn_keys(&target.request_keys);

    log_success!(
        "收到 spawn hello: pid={}, ppid={}, package={}",
        hello.pid,
        hello.ppid,
        hello.package_name
    );

    Ok(hello)
}

/// Spawn 注入主入口
pub(crate) fn spawn_and_inject(
    package: &str,
    string_overrides: &HashMap<String, String>,
) -> Result<(i32, InjectionResult), String> {
    log_info!("Spawn 模式: 准备注入 {}", package);

    let hello = spawn_and_wait_hello(package)?;

    // 属性伪装: mount 在 capset hook 中完成，remap 在 setArgV0 中完成

    // 5. 注入 agent 到子进程
    let pid = hello.pid as i32;
    log_info!("正在向子进程 {} 注入 agent...", pid);
    let injection = match inject_via_bootstrapper(pid, string_overrides) {
        Ok(result) => result,
        Err(e) => {
            log_warn!("注入子进程 {} 失败，正在恢复子进程: {}", pid, e);
            let _ = resume_child(hello.pid);
            return Err(e);
        }
    };

    // 6. 不立即恢复子进程 — 由 main.rs 在脚本加载完成后调用 resume_child
    //    子进程主线程仍阻塞在 zymbiote recv(ACK)，agent 线程可独立工作

    Ok((pid, injection))
}

/// Diagnostic path: run only the zygote spawn handshake and resume the child.
/// No loader, agent, memfd, or agent threads are installed.
pub(crate) fn spawn_only_and_resume(package: &str) -> Result<u32, String> {
    log_info!("Spawn-only 诊断: 只启动并恢复 {}", package);
    let hello = spawn_and_wait_hello(package)?;
    resume_child(hello.pid)?;
    Ok(hello.pid)
}

/// Diagnostic path: patch zygote and launch the app, but use a passive setArgV0
/// replacement that only calls the original function. No zymbiote hello is expected.
pub(crate) fn spawn_passive_setargv0_launch(package: &str) -> Result<u32, String> {
    log_info!("Passive setArgV0 诊断: 只保留 setArgV0 指针改写并启动 {}", package);
    ensure_zymbiote_loaded()?;

    let target = resolve_spawn_target(package);
    if target.process_name != target.package {
        log_info!("主进程解析: {} -> {}", target.package, target.process_name);
    } else {
        log_verbose!("主进程解析: {} 使用默认包进程", target.package);
    }

    launch_app(&target.package)?;
    wait_for_process_name(&target.process_name, std::time::Duration::from_secs(10)).ok_or_else(|| {
        let live_processes = list_package_processes(&target.package);
        let live_hint = if live_processes.is_empty() {
            "未发现目标包相关进程".to_string()
        } else {
            format!("当前目标包相关进程:\n{}", live_processes.join("\n"))
        };
        format!("等待进程 {} 启动超时: {}", target.process_name, live_hint)
    })
}

/// 确保 zymbiote 已加载到所有 zygote 进程
/// 与 Frida ensure_loaded 一致：可重入，检测新出现的 USAP 进程
pub(crate) fn ensure_zymbiote_loaded() -> Result<(), String> {
    let already_initialized = ZYGOTE_PATCHES.get().is_some();

    if !already_initialized {
        // 修补 SELinux 策略，允许子进程连接 abstract socket
        if let Err(e) = crate::selinux::patch_selinux() {
            log_warn!("SELinux 策略修补失败: {}（继续尝试注入）", e);
        }

        // 首次初始化：生成 socket 名称，启动 listener
        let socket_name = generate_socket_name();
        log_verbose!("Zymbiote socket 名称: {}", socket_name);

        // 初始化全局状态（必须在 start_listener_thread 之前，否则子进程连接时 ACTIVE_CONNECTIONS 未就绪）
        let _ = SERVER_SOCKET_PATH.set(socket_name.clone());
        let _ = SPAWN_REQUESTS.get_or_init(|| Mutex::new(HashMap::new()));
        let _ = ACTIVE_CONNECTIONS.get_or_init(|| Mutex::new(HashMap::new()));

        // 创建 abstract Unix socket 并启动 listener 线程
        start_listener_thread(&socket_name)?;
    }

    let socket_name = SERVER_SOCKET_PATH
        .get()
        .ok_or_else(|| "SERVER_SOCKET_PATH 未初始化".to_string())?
        .clone();

    // 枚举所有 zygote 进程
    let zygotes = find_zygote_pids()?;
    if zygotes.is_empty() {
        return Err("未找到任何 zygote 进程".to_string());
    }

    // 清理已失效的 patch（PID 不再是 zygote/usap 进程）
    // 防止 PID 回收后新 zygote 被误认为已注入而跳过
    // 此问题 Frida 同样存在（zymbiote_patches.has_key 不检查进程存活）
    if let Some(patches_lock) = ZYGOTE_PATCHES.get() {
        let live_zygote_pids: Vec<u32> = zygotes.iter().map(|(pid, _)| *pid).collect();
        let mut patches = patches_lock.lock().unwrap();
        let before = patches.len();
        patches.retain(|p| live_zygote_pids.contains(&p.pid));
        let pruned = before - patches.len();
        if pruned > 0 {
            log_verbose!("清理 {} 个已失效的 zygote patch（PID 已回收或进程已退出）", pruned);
        }
    }

    // 过滤掉已注入的 pid
    let already_patched_pids: Vec<u32> = if let Some(patches_lock) = ZYGOTE_PATCHES.get() {
        let patches = patches_lock.lock().unwrap();
        patches.iter().map(|p| p.pid).collect()
    } else {
        Vec::new()
    };

    let new_zygotes: Vec<&(u32, String)> = zygotes
        .iter()
        .filter(|(pid, _)| !already_patched_pids.contains(pid))
        .collect();

    if new_zygotes.is_empty() {
        if already_initialized {
            log_verbose!("Zymbiote 已加载，无新 zygote 进程");
        }
        // 首次初始化时也可能没有新的（所有 zygote 都失败）
        if !already_initialized && already_patched_pids.is_empty() {
            return Err("未找到可注入的 zygote 进程".to_string());
        }
        return Ok(());
    }

    log_info!("找到 {} 个新 zygote 进程", new_zygotes.len());
    let mut new_patches = Vec::new();

    for (pid, name) in &new_zygotes {
        log_step!("正在注入 zymbiote 到 {} (pid={})...", name, pid);
        match inject_zymbiote(*pid, &socket_name) {
            Ok(patch) => {
                log_success!("Zymbiote 注入成功: {} (pid={})", name, pid);
                new_patches.push(patch);
            }
            Err(e) => {
                log_error!("Zymbiote 注入 {} (pid={}) 失败: {}", name, pid, e);
            }
        }
    }

    if new_patches.is_empty() && !already_initialized {
        return Err("所有 zygote 进程注入失败".to_string());
    }

    // 追加新 patches 到全局列表
    if !new_patches.is_empty() {
        let patches_lock = ZYGOTE_PATCHES.get_or_init(|| Mutex::new(Vec::new()));
        let mut patches = patches_lock.lock().unwrap();
        patches.extend(new_patches);
    }

    Ok(())
}

/// 生成随机 socket 名称
fn generate_socket_name() -> String {
    use rand::Rng;
    use std::fmt::Write;
    let mut rng = rand::thread_rng();
    let mut hex = String::with_capacity(32);
    for _ in 0..32 {
        let _ = write!(hex, "{:x}", rng.gen::<u8>() & 0xf);
    }
    format!("rustfrida-zymbiote-{}", hex)
}

/// 检查进程是否为 64 位（读取 /proc/<pid>/exe 的 ELF header）
fn is_process_64bit(pid: u32) -> bool {
    use std::os::unix::io::AsRawFd;

    let exe_path = format!("/proc/{}/exe", pid);
    let file = match std::fs::File::open(&exe_path) {
        Ok(f) => f,
        Err(_) => return false,
    };

    // 读取 ELF header 前 5 字节: e_ident[0..4] = magic, e_ident[4] = EI_CLASS
    let mut header = [0u8; 5];
    let fd = file.as_raw_fd();
    let n = loop {
        let ret = unsafe { libc::pread(fd, header.as_mut_ptr() as *mut libc::c_void, 5, 0) };
        if ret >= 0 {
            break ret;
        }
        if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        break ret;
    };
    if n < 5 {
        return false;
    }

    // 验证 ELF magic: 0x7f 'E' 'L' 'F'
    if header[0] != 0x7f || header[1] != b'E' || header[2] != b'L' || header[3] != b'F' {
        return false;
    }

    // EI_CLASS: 1 = ELFCLASS32, 2 = ELFCLASS64
    header[4] == 2
}

fn proc_name_implies_64bit(proc_name: &str) -> bool {
    proc_name == "zygote64" || proc_name == "usap64"
}

/// 枚举所有 64 位 zygote 进程 PID
fn find_zygote_pids() -> Result<Vec<(u32, String)>, String> {
    use std::fs;

    let mut results = Vec::new();
    let proc_dir = fs::read_dir("/proc").map_err(|e| format!("读取 /proc 失败: {}", e))?;

    for entry in proc_dir.flatten() {
        let fname = entry.file_name();
        let fname_str = fname.to_string_lossy();
        if !fname_str.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let pid: u32 = match fname_str.parse() {
            Ok(n) => n,
            Err(_) => continue,
        };

        let cmdline_path = format!("/proc/{}/cmdline", pid);
        if let Ok(data) = fs::read(&cmdline_path) {
            let proc_name = data
                .split(|&b| b == 0)
                .next()
                .and_then(|s| std::str::from_utf8(s).ok())
                .unwrap_or("");

            if proc_name == "zygote" || proc_name == "zygote64" || proc_name == "usap32" || proc_name == "usap64" {
                // 过滤 App Zygote：Android 为 isolated service 创建的应用级 zygote，
                // 进程名也叫 "zygote" 但 UID 不是 root。注入会失败（内存布局不同）。
                let status_path = format!("/proc/{}/status", pid);
                if let Ok(status) = fs::read_to_string(&status_path) {
                    let uid_line = status.lines().find(|l| l.starts_with("Uid:"));
                    if let Some(line) = uid_line {
                        let uid: u32 = line
                            .split_whitespace()
                            .nth(1)
                            .and_then(|s| s.parse().ok())
                            .unwrap_or(u32::MAX);
                        if uid != 0 {
                            log_verbose!("跳过 App Zygote {} (pid={}, uid={})", proc_name, pid, uid);
                            continue;
                        }
                    }
                }
                // 过滤 32 位进程：zymbiote payload 是 ARM64 ELF，注入 32 位进程会崩溃
                if !proc_name_implies_64bit(proc_name) && !is_process_64bit(pid) {
                    log_verbose!("跳过 32 位进程 {} (pid={})", proc_name, pid);
                    continue;
                }
                results.push((pid, proc_name.to_string()));
            }
        }
    }

    Ok(results)
}

/// 启动 listener 线程，接受子进程连接
fn start_listener_thread(socket_name: &str) -> Result<(), String> {
    // 创建 abstract Unix socket
    let (addr, addrlen) = socket_addr_abstract(socket_name)?;

    let socket_fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if socket_fd < 0 {
        return Err(format!("创建 socket 失败: {}", std::io::Error::last_os_error()));
    }

    let ret = unsafe {
        libc::bind(
            socket_fd,
            &addr as *const libc::sockaddr_un as *const libc::sockaddr,
            addrlen,
        )
    };
    if ret < 0 {
        unsafe { libc::close(socket_fd) };
        return Err(format!("bind socket 失败: {}", std::io::Error::last_os_error()));
    }

    let ret = unsafe { libc::listen(socket_fd, 16) };
    if ret < 0 {
        unsafe { libc::close(socket_fd) };
        return Err(format!("listen socket 失败: {}", std::io::Error::last_os_error()));
    }

    // 用 UnixListener::from_raw_fd 包装以利用 Rust 的 accept
    let listener = unsafe {
        use std::os::unix::io::FromRawFd;
        UnixListener::from_raw_fd(socket_fd)
    };

    std::thread::Builder::new()
        .name("wwb-zymacc".into())
        .spawn(move || {
            for stream in listener.incoming() {
                match stream {
                    Ok(stream) => {
                        std::thread::Builder::new()
                            .name("wwb-zymconn".into())
                            .spawn(move || {
                                if let Err(e) = handle_zymbiote_connection(stream) {
                                    log_verbose!("Zymbiote 连接处理错误: {}", e);
                                }
                            })
                            .expect("spawn wwb-zymconn thread");
                    }
                    Err(e) => {
                        log_verbose!("Zymbiote accept 错误: {}", e);
                        break;
                    }
                }
            }
        })
        .expect("spawn wwb-zymacc thread");

    Ok(())
}

/// 构造 abstract Unix socket 地址，返回 (sockaddr_un, addrlen)
/// addrlen = offsetof(sun_path) + 1 + name.len()，与 zymbiote C 端 connect() 一致
fn socket_addr_abstract(name: &str) -> Result<(libc::sockaddr_un, u32), String> {
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as u16;

    // abstract socket: sun_path[0] = 0, 后续为名称
    let name_bytes = name.as_bytes();
    if name_bytes.len() + 1 > addr.sun_path.len() {
        return Err("socket 名称过长".to_string());
    }
    addr.sun_path[0] = 0;
    for (i, &b) in name_bytes.iter().enumerate() {
        addr.sun_path[i + 1] = b;
    }

    // 精确 addrlen: offsetof(sockaddr_un, sun_path) + 1(NUL前缀) + name长度
    // 与 zymbiote C 端 connect() 使用的 offsetof(sun_path) + 1 + name_len 一致
    let addrlen = std::mem::offset_of!(libc::sockaddr_un, sun_path) + 1 + name_bytes.len();

    Ok((addr, addrlen as u32))
}

/// 处理来自 zymbiote 子进程的连接
fn handle_zymbiote_connection(mut stream: std::os::unix::net::UnixStream) -> Result<(), String> {
    // 读取 header: {pid: u32, ppid: u32, name_len: u32}
    let mut header = [0u8; 12];
    stream
        .read_exact(&mut header)
        .map_err(|e| format!("读取 hello header 失败: {}", e))?;

    let pid = u32::from_ne_bytes(header[0..4].try_into().unwrap());
    let ppid = u32::from_ne_bytes(header[4..8].try_into().unwrap());
    let name_len = u32::from_ne_bytes(header[8..12].try_into().unwrap());

    // 读取包名
    let mut name_buf = vec![0u8; name_len as usize];
    stream
        .read_exact(&mut name_buf)
        .map_err(|e| format!("读取包名失败: {}", e))?;
    let package_name = String::from_utf8_lossy(&name_buf).to_string();

    log_verbose!("Zymbiote hello: pid={}, ppid={}, package={}", pid, ppid, package_name);

    let hello = SpawnHello {
        pid,
        ppid,
        package_name: package_name.clone(),
    };

    // 查找匹配的 spawn 请求（匹配时立即移除，与 Frida unset 一致，防止重复消费）
    // spawn 只做精确进程名匹配，避免误消费 service/isolated 等非目标进程。
    let notifier = if let Some(requests) = SPAWN_REQUESTS.get() {
        let mut map = requests.lock().unwrap();
        map.remove(&package_name)
    } else {
        None
    };

    if let Some(notifier) = notifier {
        // 保持连接，等待 agent 注入完成后再发 ACK
        // ACK 由 resume_child 通过这个 stream 发送
        // 必须在 notifier.send 之前存储 stream，否则 spawn_and_inject 被唤醒后
        // 调用 resume_child 时可能在 ACTIVE_CONNECTIONS 中找不到连接（竞态条件）
        if let Some(conns) = ACTIVE_CONNECTIONS.get() {
            let mut map = conns.lock().unwrap();
            map.insert(pid, (stream, ppid));
        }

        // 发送 hello 到等待的 spawn 请求（唤醒 spawn_and_inject）
        notifier.send(hello);
    } else {
        // 没有匹配的请求，执行完整 resume 流程放行子进程
        // 与 Frida 一致：ACK → 等 EOF → wait SIGSTOP → revert patches → SIGCONT
        log_verbose!("未找到 {} 的 spawn 请求，放行 pid={}", package_name, pid);
        do_resume_unmatched(pid, ppid, stream);
    }

    Ok(())
}

/// 对未匹配 spawn 请求的子进程执行完整 resume 流程
/// 与 Frida connection.resume() 一致：ACK → 等 EOF → wait SIGSTOP → revert → SIGCONT
fn do_resume_unmatched(pid: u32, ppid: u32, mut stream: std::os::unix::net::UnixStream) {
    // 1. 发送 ACK
    if stream.write_all(&[ACK_BYTE]).is_err() {
        return;
    }

    // 2. 等待子进程关闭连接（EOF）
    drain_until_eof(&mut stream, std::time::Duration::from_secs(10));
    drop(stream);

    // 3. 检查子进程是否仍存在
    if !std::path::Path::new(&format!("/proc/{}", pid)).exists() {
        log_verbose!("未匹配子进程 {} 已不存在，跳过还原", pid);
        return;
    }

    // 4. 等待子进程 SIGSTOP（与 resume_child 一致：即使失败也尝试还原和 SIGCONT）
    if let Err(e) = wait_until_stopped(pid) {
        log_verbose!("等待未匹配子进程 {} SIGSTOP 失败: {}，仍尝试还原", pid, e);
    }

    // 5. 还原子进程 patch（使用 ppid 匹配正确的 zygote patch）
    if let Err(e) = revert_child_patch_by_ppid(pid, ppid) {
        log_verbose!("还原未匹配子进程 {} patch 失败: {}", pid, e);
    }

    // 6. SIGCONT 恢复子进程
    unsafe { libc::kill(pid as i32, libc::SIGCONT) };
}

/// 活跃连接（等待 ACK 的子进程 stream + fork 时刻的 ppid）
static ACTIVE_CONNECTIONS: OnceLock<Mutex<HashMap<u32, (std::os::unix::net::UnixStream, u32)>>> = OnceLock::new();

/// 恢复子进程：发 ACK → 等子进程关闭 socket → 等 SIGSTOP → 还原 patch → SIGCONT
/// 与 Frida 一致的流程：先等 EOF 确保子进程已通过 recv(ACK) 并关闭连接，
/// 再 wait_until_stopped 等待 raise(SIGSTOP) 完成。
pub(crate) fn resume_child(pid: u32) -> Result<(), String> {
    log_step!("正在恢复子进程 {}...", pid);

    // 1. 发送 ACK 到子进程
    let conns = ACTIVE_CONNECTIONS.get_or_init(|| Mutex::new(HashMap::new()));
    let (mut stream, ppid) = {
        let mut map = conns.lock().unwrap();
        map.remove(&pid)
            .ok_or_else(|| format!("未找到子进程 {} 的活跃连接", pid))?
    };

    stream
        .write_all(&[ACK_BYTE])
        .map_err(|e| format!("发送 ACK 失败: {}", e))?;

    // 2. 等待子进程关闭 socket（子进程收到 ACK 后会 close(fd)，然后 raise(SIGSTOP)）
    //    Frida 也这样做：先等 EOF，确保子进程已处理完 ACK 并关闭连接
    log_verbose!("等待子进程 {} 关闭 socket...", pid);
    drain_until_eof(&mut stream, std::time::Duration::from_secs(10));
    drop(stream);

    // 3. 等待子进程收到 ACK 后 raise(SIGSTOP)
    //    即使等待失败也继续尝试还原和恢复（比 Frida 更健壮：
    //    Frida 在 wait_until_stopped 失败时直接 throw，跳过 revert + SIGCONT）
    log_verbose!("等待子进程 {} SIGSTOP...", pid);
    if let Err(e) = wait_until_stopped(pid) {
        log_warn!("等待子进程 {} SIGSTOP 失败: {}，仍尝试还原", pid, e);
    } else {
        log_verbose!("子进程 {} 已停止", pid);
    }

    // 4. 还原子进程的 zymbiote patch（使用 hello 消息中的 ppid，而非 /proc 读取）
    //    revert_child_patch_by_ppid 内部已检查进程是否存在，安全调用
    if let Err(e) = revert_child_patch_by_ppid(pid, ppid) {
        log_warn!("还原子进程 {} patch 失败: {}", pid, e);
    }

    // 5. SIGCONT 恢复子进程
    let ret = unsafe { libc::kill(pid as i32, libc::SIGCONT) };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::ESRCH) {
            return Err(format!("SIGCONT 子进程 {} 失败: {}", pid, err));
        }
        // ESRCH = 进程已退出，不是真正的错误
        log_verbose!("子进程 {} 已退出 (ESRCH)", pid);
    }

    log_success!("子进程 {} 已恢复运行", pid);
    Ok(())
}

/// 用给定 ppid 还原子进程的 zymbiote patch
fn revert_child_patch_by_ppid(pid: u32, ppid: u32) -> Result<(), String> {
    // 检查子进程是否仍存在
    if !std::path::Path::new(&format!("/proc/{}", pid)).exists() {
        log_verbose!("子进程 {} 已不存在，跳过 patch 还原", pid);
        return Ok(());
    }

    let patches_lock = match ZYGOTE_PATCHES.get() {
        Some(lock) => lock,
        None => return Ok(()),
    };
    let patches = patches_lock.lock().unwrap();
    // 按 ppid 精确匹配父 Zygote 的 patch（与 Frida 一致：不做 fallback，避免多 zygote 时用错 patch）
    let patch = match patches.iter().find(|p| p.pid == ppid) {
        Some(p) => p,
        None => {
            log_warn!("未找到 ppid={} 对应的 zygote patch，跳过子进程 {} 的还原", ppid, pid);
            return Ok(());
        }
    };

    let mem = ProcMem::open(pid)?;

    // 还原 payload 区域
    log_verbose!(
        "还原子进程 {} payload at 0x{:x} ({} bytes)",
        pid,
        patch.payload_base,
        patch.payload_backup.len()
    );
    mem.pwrite_all(&patch.payload_backup, patch.payload_base)?;

    // 还原 setArgV0 指针（降级模式下为 None）
    if let Some((addr, backup)) = &patch.setargv0_slot {
        log_verbose!("还原子进程 {} setArgV0 指针 at 0x{:x}", pid, addr);
        mem.pwrite_all(backup, *addr)?;
    }

    // 还原 setcontext GOT（如果有）
    if let Some((addr, backup)) = &patch.setcontext_got {
        log_verbose!("还原子进程 {} setcontext GOT at 0x{:x}", pid, addr);
        mem.pwrite_all(backup, *addr)?;
    }

    // 还原 capset GOT（如果有）
    if let Some((addr, backup)) = &patch.capset_got {
        log_verbose!("还原子进程 {} capset GOT at 0x{:x}", pid, addr);
        mem.pwrite_all(backup, *addr)?;
    }

    Ok(())
}

fn resolve_spawn_target(target: &str) -> SpawnTarget {
    if let Some((package, _suffix)) = target.split_once(':') {
        if !package.is_empty() {
            return SpawnTarget {
                package: package.to_string(),
                process_name: target.to_string(),
                request_keys: vec![target.to_string()],
            };
        }
    }

    let package = target.to_string();
    let process_name = resolve_launch_process_name(&package).unwrap_or_else(|| package.clone());
    let request_keys = vec![process_name.clone()];

    SpawnTarget {
        package,
        process_name,
        request_keys,
    }
}

fn resolve_launch_process_name(package: &str) -> Option<String> {
    let component = resolve_launch_activity(package);
    if let Some(ref comp) = component {
        if let Some(process) = resolve_activity_process_from_manifest(package, comp) {
            return Some(process);
        }
        log_verbose!("无法从 manifest 解析 {} 的进程名，回退到包进程", comp);
    }

    resolve_application_process_from_manifest(package)
}

/// 启动应用：先 force-stop，再启动（与 Frida 分离 stop/start 一致）
fn launch_app(package: &str) -> Result<(), String> {
    // 1. 先显式 force-stop（与 Frida stop_package 一致，分离 stop 和 start）
    log_verbose!("正在停止应用 {}...", package);
    let stop_result = std::process::Command::new("am")
        .args(["force-stop", package])
        .output()
        .map_err(|e| format!("停止应用失败: {}", e))?;
    if !stop_result.status.success() {
        log_warn!(
            "am force-stop {} 返回非零: {}",
            package,
            String::from_utf8_lossy(&stop_result.stderr)
        );
    }

    // 2. 尝试解析 launch activity 组件名
    let component = resolve_launch_activity(package);

    // 3. 启动应用
    let started = if let Some(ref comp) = component {
        log_verbose!("Launch activity: {}", comp);
        let result = std::process::Command::new("am")
            .args(["start", "-n", comp])
            .output()
            .map_err(|e| format!("启动应用失败: {}", e))?;
        let stdout = String::from_utf8_lossy(&result.stdout);
        if result.status.success() && !stdout.contains("Error:") {
            true
        } else {
            log_verbose!("am start -n {} 失败: {}", comp, stdout.trim());
            false
        }
    } else {
        false
    };

    if !started {
        // fallback: -a/-c/-p 方式（不带 -S，因为已经 force-stop 过了）
        log_verbose!("尝试 am start -a/-c 方式启动...");
        let result = std::process::Command::new("am")
            .args([
                "start",
                "-a",
                "android.intent.action.MAIN",
                "-c",
                "android.intent.category.LAUNCHER",
                "-p",
                package,
            ])
            .output()
            .map_err(|e| format!("启动应用失败: {}", e))?;
        let stdout = String::from_utf8_lossy(&result.stdout);
        if !result.status.success() || stdout.contains("Error:") {
            // monkey fallback
            log_verbose!("am start 失败 ({}), 尝试 monkey fallback", stdout.trim());
            let monkey_result = std::process::Command::new("monkey")
                .args(["-p", package, "-c", "android.intent.category.LAUNCHER", "1"])
                .output();
            match monkey_result {
                Ok(r) if !r.status.success() => {
                    return Err(format!(
                        "启动应用 {} 失败: am start 和 monkey 均无法启动，请检查包名是否正确、应用是否已安装",
                        package
                    ));
                }
                Err(e) => {
                    return Err(format!("启动应用 {} 失败: monkey 执行错误: {}", package, e));
                }
                _ => {} // monkey succeeded
            }
        }
    }

    Ok(())
}

/// 解析应用的 launch activity 组件名（如 com.example.app/.MainActivity）
fn resolve_launch_activity(package: &str) -> Option<String> {
    let output = std::process::Command::new("cmd")
        .args(["package", "resolve-activity", "--brief", package])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    // 输出格式：第一行是 priority/match 信息，第二行是组件名
    // 例如：
    //   priority=0 preferredOrder=0 match=0x108000 specificIndex=-1 isDefault=false
    //   com.example.crcdemo/.MainActivity
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.contains('/') && !trimmed.contains('=') {
            return Some(trimmed.to_string());
        }
    }

    None
}

fn resolve_activity_process_from_manifest(package: &str, component: &str) -> Option<String> {
    let manifest = read_manifest_from_base_apk(package)?;
    let manifest = BinaryManifest::parse(&manifest)?;
    let activity_name = component_to_activity_name(package, component)?;
    manifest.launch_activity_process(package, &activity_name)
}

fn resolve_application_process_from_manifest(package: &str) -> Option<String> {
    let manifest = read_manifest_from_base_apk(package)?;
    let manifest = BinaryManifest::parse(&manifest)?;
    manifest
        .application_process
        .map(|p| normalize_process_name(package, &p))
}

fn read_manifest_from_base_apk(package: &str) -> Option<Vec<u8>> {
    let output = std::process::Command::new("pm").args(["path", package]).output().ok()?;
    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let apk_path = stdout
        .lines()
        .find_map(|line| line.trim().strip_prefix("package:"))
        .map(str::trim)?;

    let output = std::process::Command::new("unzip")
        .args(["-p", apk_path, "AndroidManifest.xml"])
        .output()
        .ok()?;
    if output.status.success() && !output.stdout.is_empty() {
        Some(output.stdout)
    } else {
        None
    }
}

fn component_to_activity_name(package: &str, component: &str) -> Option<String> {
    let (_, class_name) = component.split_once('/')?;
    Some(normalize_component_name(package, class_name))
}

fn normalize_component_name(package: &str, name: &str) -> String {
    if name.starts_with('.') {
        format!("{}{}", package, name)
    } else if name.contains('.') {
        name.to_string()
    } else {
        format!("{}.{}", package, name)
    }
}

fn normalize_process_name(package: &str, process: &str) -> String {
    if process.starts_with(':') {
        format!("{}{}", package, process)
    } else if process.starts_with('.') {
        format!("{}{}", package, process)
    } else {
        process.to_string()
    }
}

fn list_package_processes(package: &str) -> Vec<String> {
    let mut out = Vec::new();
    let Ok(proc_dir) = std::fs::read_dir("/proc") else {
        return out;
    };

    for entry in proc_dir.flatten() {
        let fname = entry.file_name();
        let fname_str = fname.to_string_lossy();
        if !fname_str.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let pid: i32 = match fname_str.parse() {
            Ok(pid) => pid,
            Err(_) => continue,
        };
        let cmdline_path = format!("/proc/{}/cmdline", pid);
        let Ok(data) = std::fs::read(cmdline_path) else {
            continue;
        };
        let proc_name = data
            .split(|&b| b == 0)
            .next()
            .and_then(|s| std::str::from_utf8(s).ok())
            .unwrap_or("");
        if proc_name == package || proc_name.starts_with(&format!("{}:", package)) {
            out.push(format!("     PID {:6}: {}", pid, proc_name));
        }
    }
    out.sort();
    out
}

fn wait_for_process_name(process_name: &str, timeout: std::time::Duration) -> Option<u32> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if let Some(pid) = find_process_by_exact_name(process_name) {
            return Some(pid);
        }
        if std::time::Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

fn find_process_by_exact_name(process_name: &str) -> Option<u32> {
    let proc_dir = std::fs::read_dir("/proc").ok()?;
    for entry in proc_dir.flatten() {
        let fname = entry.file_name();
        let fname_str = fname.to_string_lossy();
        if !fname_str.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let pid: u32 = match fname_str.parse() {
            Ok(pid) => pid,
            Err(_) => continue,
        };
        let cmdline_path = format!("/proc/{}/cmdline", pid);
        let Ok(data) = std::fs::read(cmdline_path) else {
            continue;
        };
        let proc_name = data
            .split(|&b| b == 0)
            .next()
            .and_then(|s| std::str::from_utf8(s).ok())
            .unwrap_or("");
        if proc_name == process_name {
            return Some(pid);
        }
    }
    None
}

#[derive(Debug, Clone)]
struct BinaryManifest {
    package_name: Option<String>,
    application_process: Option<String>,
    activities: HashMap<String, ManifestActivity>,
    aliases: Vec<ManifestAlias>,
}

#[derive(Debug, Clone, Default)]
struct ManifestActivity {
    process: Option<String>,
    has_main: bool,
    has_launcher: bool,
}

#[derive(Debug, Clone)]
struct ManifestAlias {
    name: String,
    target: Option<String>,
    has_main: bool,
    has_launcher: bool,
}

#[derive(Debug, Clone)]
enum ManifestTag {
    Activity(String),
    Alias(usize),
    IntentFilter,
}

impl BinaryManifest {
    fn parse(data: &[u8]) -> Option<Self> {
        let strings = parse_axml_strings(data)?;
        let mut cursor = 8usize; // XML chunk header
        let mut manifest = BinaryManifest {
            package_name: None,
            application_process: None,
            activities: HashMap::new(),
            aliases: Vec::new(),
        };
        let mut stack: Vec<ManifestTag> = Vec::new();

        while cursor + 8 <= data.len() {
            let chunk_type = read_u16(data, cursor)?;
            let header_size = read_u16(data, cursor + 2)? as usize;
            let chunk_size = read_u32(data, cursor + 4)? as usize;
            if chunk_size < 8 || cursor + chunk_size > data.len() {
                break;
            }

            match chunk_type {
                0x0102 => {
                    let name_idx = read_u32(data, cursor + 20)? as usize;
                    let tag_name = strings.get(name_idx).cloned().unwrap_or_default();
                    let attrs = parse_start_tag_attrs(data, cursor, &strings)?;

                    match tag_name.as_str() {
                        "manifest" => {
                            manifest.package_name = attrs.get("package").cloned();
                        }
                        "application" => {
                            manifest.application_process = attrs.get("process").cloned();
                        }
                        "activity" => {
                            if let Some(name) = attrs.get("name") {
                                let pkg = manifest.package_name.as_deref().unwrap_or("");
                                let full_name = normalize_component_name(pkg, name);
                                let entry = manifest.activities.entry(full_name.clone()).or_default();
                                entry.process = attrs.get("process").cloned();
                                stack.push(ManifestTag::Activity(full_name));
                            }
                        }
                        "activity-alias" => {
                            if let Some(name) = attrs.get("name") {
                                let pkg = manifest.package_name.as_deref().unwrap_or("");
                                let alias = ManifestAlias {
                                    name: normalize_component_name(pkg, name),
                                    target: attrs.get("targetActivity").map(|v| normalize_component_name(pkg, v)),
                                    has_main: false,
                                    has_launcher: false,
                                };
                                let idx = manifest.aliases.len();
                                manifest.aliases.push(alias);
                                stack.push(ManifestTag::Alias(idx));
                            }
                        }
                        "intent-filter" => stack.push(ManifestTag::IntentFilter),
                        "action" => {
                            if attrs.get("name").map(String::as_str) == Some("android.intent.action.MAIN") {
                                mark_current_intent(&mut manifest, &stack, true, false);
                            }
                        }
                        "category" => {
                            if attrs.get("name").map(String::as_str) == Some("android.intent.category.LAUNCHER") {
                                mark_current_intent(&mut manifest, &stack, false, true);
                            }
                        }
                        _ => {}
                    }
                }
                0x0103 => {
                    let name_idx = read_u32(data, cursor + 20)? as usize;
                    let tag_name = strings.get(name_idx).map(String::as_str).unwrap_or("");
                    match tag_name {
                        "activity" => pop_tag(&mut stack, |t| matches!(t, ManifestTag::Activity(_))),
                        "activity-alias" => pop_tag(&mut stack, |t| matches!(t, ManifestTag::Alias(_))),
                        "intent-filter" => pop_tag(&mut stack, |t| matches!(t, ManifestTag::IntentFilter)),
                        _ => {}
                    }
                }
                _ => {
                    let _ = header_size;
                }
            }

            cursor += chunk_size;
        }

        Some(manifest)
    }

    fn launch_activity_process(&self, package: &str, activity_name: &str) -> Option<String> {
        if let Some(activity) = self.activities.get(activity_name) {
            let process = activity
                .process
                .as_deref()
                .or(self.application_process.as_deref())
                .unwrap_or(package);
            return Some(normalize_process_name(package, process));
        }

        if let Some(alias) = self.aliases.iter().find(|a| a.name == activity_name) {
            if let Some(target) = alias.target.as_deref() {
                if let Some(activity) = self.activities.get(target) {
                    let process = activity
                        .process
                        .as_deref()
                        .or(self.application_process.as_deref())
                        .unwrap_or(package);
                    return Some(normalize_process_name(package, process));
                }
            }
            let process = self.application_process.as_deref().unwrap_or(package);
            return Some(normalize_process_name(package, process));
        }

        self.activities
            .iter()
            .find(|(_, a)| a.has_main && a.has_launcher)
            .map(|(_, a)| {
                normalize_process_name(
                    package,
                    a.process
                        .as_deref()
                        .or(self.application_process.as_deref())
                        .unwrap_or(package),
                )
            })
    }
}

fn mark_current_intent(manifest: &mut BinaryManifest, stack: &[ManifestTag], main: bool, launcher: bool) {
    if !stack.iter().any(|t| matches!(t, ManifestTag::IntentFilter)) {
        return;
    }

    for tag in stack.iter().rev() {
        match tag {
            ManifestTag::Activity(name) => {
                if let Some(activity) = manifest.activities.get_mut(name) {
                    activity.has_main |= main;
                    activity.has_launcher |= launcher;
                }
                return;
            }
            ManifestTag::Alias(idx) => {
                if let Some(alias) = manifest.aliases.get_mut(*idx) {
                    alias.has_main |= main;
                    alias.has_launcher |= launcher;
                }
                return;
            }
            ManifestTag::IntentFilter => {}
        }
    }
}

fn pop_tag<F>(stack: &mut Vec<ManifestTag>, pred: F)
where
    F: Fn(&ManifestTag) -> bool,
{
    while let Some(tag) = stack.pop() {
        if pred(&tag) {
            break;
        }
    }
}

fn parse_start_tag_attrs(data: &[u8], chunk_start: usize, strings: &[String]) -> Option<HashMap<String, String>> {
    let attr_start = read_u16(data, chunk_start + 24)? as usize;
    let attr_size = read_u16(data, chunk_start + 26)? as usize;
    let attr_count = read_u16(data, chunk_start + 28)? as usize;
    let attr_base = chunk_start + 16 + attr_start;
    let mut attrs = HashMap::new();

    for i in 0..attr_count {
        let off = attr_base + i * attr_size;
        if off + 20 > data.len() {
            return None;
        }
        let name_idx = read_u32(data, off + 4)? as usize;
        let raw_idx = read_u32(data, off + 8)?;
        let data_type = *data.get(off + 15)?;
        let typed_data = read_u32(data, off + 16)?;

        let name = strings.get(name_idx)?.clone();
        let value = if raw_idx != u32::MAX {
            strings.get(raw_idx as usize).cloned().unwrap_or_default()
        } else if data_type == 0x03 {
            strings.get(typed_data as usize).cloned().unwrap_or_default()
        } else {
            typed_data.to_string()
        };
        attrs.insert(name, value);
    }

    Some(attrs)
}

fn parse_axml_strings(data: &[u8]) -> Option<Vec<String>> {
    let mut cursor = 8usize;
    while cursor + 8 <= data.len() {
        let chunk_type = read_u16(data, cursor)?;
        let header_size = read_u16(data, cursor + 2)? as usize;
        let chunk_size = read_u32(data, cursor + 4)? as usize;
        if chunk_size < 8 || cursor + chunk_size > data.len() {
            return None;
        }
        if chunk_type == 0x0001 {
            if header_size < 28 || cursor + header_size > data.len() {
                return None;
            }
            let string_count = read_u32(data, cursor + 8)? as usize;
            let flags = read_u32(data, cursor + 16)?;
            let strings_start = cursor + read_u32(data, cursor + 20)? as usize;
            let utf8 = (flags & 0x0000_0100) != 0;
            let offsets_base = cursor + header_size;
            let mut strings = Vec::with_capacity(string_count);
            for i in 0..string_count {
                let off = read_u32(data, offsets_base + i * 4)? as usize;
                strings.push(read_string_pool_entry(data, strings_start + off, utf8)?);
            }
            return Some(strings);
        }
        cursor += chunk_size;
    }
    None
}

fn read_string_pool_entry(data: &[u8], offset: usize, utf8: bool) -> Option<String> {
    if utf8 {
        let (_, pos) = read_length8(data, offset)?;
        let (byte_len, pos) = read_length8(data, pos)?;
        let end = pos + byte_len;
        if end > data.len() {
            return None;
        }
        Some(String::from_utf8_lossy(&data[pos..end]).to_string())
    } else {
        let (unit_len, pos) = read_length16(data, offset)?;
        let byte_len = unit_len.checked_mul(2)?;
        let end = pos + byte_len;
        if end > data.len() {
            return None;
        }
        let mut units = Vec::with_capacity(unit_len);
        for i in 0..unit_len {
            let b = pos + i * 2;
            units.push(u16::from_le_bytes([data[b], data[b + 1]]));
        }
        String::from_utf16(&units).ok()
    }
}

fn read_length8(data: &[u8], offset: usize) -> Option<(usize, usize)> {
    let first = *data.get(offset)? as usize;
    if (first & 0x80) != 0 {
        let second = *data.get(offset + 1)? as usize;
        Some((((first & 0x7f) << 8) | second, offset + 2))
    } else {
        Some((first, offset + 1))
    }
}

fn read_length16(data: &[u8], offset: usize) -> Option<(usize, usize)> {
    let first = read_u16(data, offset)? as usize;
    if (first & 0x8000) != 0 {
        let second = read_u16(data, offset + 2)? as usize;
        Some((((first & 0x7fff) << 16) | second, offset + 4))
    } else {
        Some((first, offset + 2))
    }
}

fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    let bytes: [u8; 2] = data.get(offset..offset + 2)?.try_into().ok()?;
    Some(u16::from_le_bytes(bytes))
}

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes: [u8; 4] = data.get(offset..offset + 4)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

/// 向单个 zygote 进程注入 zymbiote
fn inject_zymbiote(pid: u32, socket_name: &str) -> Result<ZygotePatch, String> {
    let maps = parse_proc_maps(pid)?;
    let diag_passive_setargv0 = diag_env_flag("RF_DIAG_ZYM_PASSIVE_SETARGV0");
    let diag_no_setcontext = diag_env_flag("RF_DIAG_ZYM_NO_SETCONTEXT") || diag_passive_setargv0;
    let diag_no_setargv0 = diag_env_flag("RF_DIAG_ZYM_NO_SETARGV0");

    if diag_no_setcontext && diag_no_setargv0 {
        return Err("RF_DIAG_ZYM_NO_SETCONTEXT 和 RF_DIAG_ZYM_NO_SETARGV0 不能同时启用".to_string());
    }
    if diag_passive_setargv0 && diag_no_setargv0 {
        return Err("RF_DIAG_ZYM_PASSIVE_SETARGV0 和 RF_DIAG_ZYM_NO_SETARGV0 不能同时启用".to_string());
    }
    if diag_no_setcontext {
        log_warn!("诊断模式: 跳过 zymbiote setcontext GOT hook");
    }
    if diag_no_setargv0 {
        log_warn!("诊断模式: 跳过 zymbiote setArgV0 指针 hook，强制 setcontext-only 阻塞");
    }
    if diag_passive_setargv0 {
        log_warn!("诊断模式: setArgV0 replacement 只调用原函数并返回，不发 hello/ACK/SIGSTOP");
    }

    // 1. 找到 payload 写入位置（libstagefright.so 的 R+X 段末尾页）
    let loc = find_payload_location(&maps)?;
    log_verbose!(
        "Payload 写入位置: 0x{:x} (backing: {} +0x{:x})",
        loc.base,
        loc.path,
        loc.file_offset
    );

    // 2. 与 Frida 一致：提前检查 boot heap 候选区是否存在
    let has_heap_candidates = maps.iter().any(|e| is_boot_heap(e));
    if !has_heap_candidates {
        return Err("未检测到 VM heap 候选区域（boot image / dalvik-LinearAlloc）".to_string());
    }

    // 3. 解析 libc.so 获取函数地址
    let libc_funcs = resolve_libc_functions(&maps)?;
    log_verbose!("libc 函数地址已解析");

    // 4. 找到 setArgV0 函数地址
    let setargv0_addr = find_export_in_maps(
        &maps,
        "libandroid_runtime.so",
        "_Z27android_os_Process_setArgV0P7_JNIEnvP8_jobjectP8_jstring",
    )?;
    log_verbose!("setArgV0 地址: 0x{:x}", setargv0_addr);

    // 5. 找到 selinux_android_setcontext（可选）
    let setcontext_info = find_setcontext_info(&maps);
    if let Some((addr, _)) = &setcontext_info {
        log_verbose!("selinux_android_setcontext 地址: 0x{:x}", addr);
    }
    let setcontext_info = if diag_no_setcontext { None } else { setcontext_info };

    // 6. 先构建 payload 获取替换函数地址（用于 already-patched 检测）
    let (
        payload_data,
        replacement_setargv0_addr,
        replacement_setcontext_addr,
        replacement_prctl_addr,
        ctx_base_in_payload,
    ) = build_payload(
        socket_name,
        loc.base,
        loc.prot,
        &libc_funcs,
        setargv0_addr,
        setcontext_info.as_ref().map(|(addr, _)| *addr),
    )?;
    log_verbose!("Payload 构建完成: {} bytes", payload_data.len());

    // 验证 payload 不超过一页（payload 占用目标段的末尾一页）
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
    if payload_data.len() > page_size {
        return Err(format!(
            "payload 大小 ({} bytes) 超过页面大小 ({} bytes)",
            payload_data.len(),
            page_size
        ));
    }

    // 7. 找到 setArgV0 指针（三层兜底扫描：boot heap → ART RW private → ART readable）
    //    None: 三层全 miss，启用 setcontext-only 降级阻塞（要求 setcontext GOT 可用）
    let mut payload_data = payload_data;
    let block_in_setcontext_flag_offset = ctx_base_in_payload + CTX_BLOCK_IN_SETCONTEXT - CTX_SOCKET_PATH;
    let setargv0_search = if diag_no_setargv0 {
        None
    } else {
        find_setargv0_pointer_in_heap(pid, &maps, setargv0_addr, Some(replacement_setargv0_addr))?
    };
    let already_patched = setargv0_search.as_ref().map(|(_, _, p)| *p).unwrap_or(false);

    if let Some((addr, backup, patched)) = &setargv0_search {
        log_verbose!(
            "setArgV0 指针位置: 0x{:x} (原始值 0x{:x}){}",
            addr,
            u64::from_ne_bytes(*backup),
            if *patched { " [already patched]" } else { "" }
        );
    } else {
        // 降级模式或诊断模式：要求 setcontext GOT 必须可用
        if !matches!(&setcontext_info, Some((_, Some(_)))) {
            return Err("boot heap / ART RW private / ART readable 映射均未命中 setArgV0 指针，\
                 且 setcontext GOT 不可用 — 无法建立阻塞点，目标 Android 版本可能不兼容。"
                .to_string());
        }
        if diag_no_setargv0 {
            log_warn!("诊断模式: setcontext-only 阻塞已启用");
        } else {
            log_warn!("降级为 setcontext-only 阻塞（Android 版本兼容路径）");
        }
        if block_in_setcontext_flag_offset + 8 > payload_data.len() {
            return Err(format!(
                "block_in_setcontext 偏移越界: {} + 8 > {}",
                block_in_setcontext_flag_offset,
                payload_data.len()
            ));
        }
        payload_data[block_in_setcontext_flag_offset..block_in_setcontext_flag_offset + 8]
            .copy_from_slice(&1u64.to_ne_bytes());
    }

    // 8. SIGSTOP zygote
    let ret = unsafe { libc::kill(pid as i32, libc::SIGSTOP) };
    if ret < 0 {
        return Err(format!(
            "SIGSTOP zygote {} 失败: {}",
            pid,
            std::io::Error::last_os_error()
        ));
    }
    wait_until_stopped(pid)?;

    // Drop guard: 确保 SIGCONT 一定执行，即使中间操作 ? 返回 Err
    struct SigcontGuard(u32);
    impl Drop for SigcontGuard {
        fn drop(&mut self) {
            unsafe {
                libc::kill(self.0 as i32, libc::SIGCONT);
            }
        }
    }
    let sigcont_guard = SigcontGuard(pid);

    // 9. 通过 /proc/<pid>/mem 写入 payload
    let mem = ProcMem::open(pid)?;

    // 写入前边界检查：对齐、VMA 覆盖、邻接 VMA 不重叠
    let write_end = loc.base.checked_add(payload_data.len() as u64).ok_or_else(|| {
        format!(
            "payload 写入范围溢出 u64: base=0x{:x} len={}",
            loc.base,
            payload_data.len()
        )
    })?;
    if (loc.base & (page_size as u64 - 1)) != 0 {
        return Err(format!(
            "payload base 非页对齐: 0x{:x} page_size=0x{:x}{}",
            loc.base,
            page_size,
            dump_maps_near(&maps, loc.base, 2)
        ));
    }
    if write_end > loc.vma_end {
        return Err(format!(
            "payload 写入越过 VMA 末端: base=0x{:x} len={} write_end=0x{:x} vma=[0x{:x},0x{:x}) perms={} path={}{}",
            loc.base,
            payload_data.len(),
            write_end,
            loc.vma_start,
            loc.vma_end,
            loc.perms,
            loc.path,
            dump_maps_near(&maps, loc.base, 2)
        ));
    }
    log_verbose!(
        "payload 写入范围: [0x{:x},0x{:x}) len={} vma=[0x{:x},0x{:x}) perms={} page_size=0x{:x}",
        loc.base,
        write_end,
        payload_data.len(),
        loc.vma_start,
        loc.vma_end,
        loc.perms,
        page_size
    );

    // 备份原始数据
    // 与 Frida 一致：already-patched 时从 backing 文件读取真正的原始数据（COW 场景）
    let payload_backup = if already_patched {
        read_backing_file_data(&loc.path, loc.file_offset, payload_data.len())?
    } else {
        let mut buf = vec![0u8; payload_data.len()];
        mem.pread_exact(&mut buf, loc.base).map_err(|e| {
            format!(
                "payload 预读失败 (用于备份): {}{}",
                e,
                dump_maps_near(&maps, loc.base, 2)
            )
        })?;
        buf
    };

    // 写入 payload
    mem.pwrite_all(&payload_data, loc.base).map_err(|e| {
        format!(
            "payload 写入失败: {} vma=[0x{:x},0x{:x}) perms={} path={}{}",
            e,
            loc.vma_start,
            loc.vma_end,
            loc.perms,
            loc.path,
            dump_maps_near(&maps, loc.base, 2)
        )
    })?;
    log_verbose!("Payload 写入完成");

    // 10. 替换 setArgV0 指针 → zymbiote replacement（Some 时）
    let setargv0_slot = if let Some((addr, backup, _)) = setargv0_search {
        match mem.pwrite_all(&replacement_setargv0_addr.to_ne_bytes(), addr) {
            Ok(()) => {
                log_verbose!(
                    "setArgV0 指针已替换: 0x{:x} → 0x{:x}",
                    u64::from_ne_bytes(backup),
                    replacement_setargv0_addr
                );
                Some((addr, backup))
            }
            Err(e) => {
                if !matches!(&setcontext_info, Some((_, Some(_)))) {
                    return Err(format!("setArgV0 指针写入失败且 setcontext GOT 不可用: {}", e));
                }
                if block_in_setcontext_flag_offset + 8 > payload_data.len() {
                    return Err(format!(
                        "block_in_setcontext 偏移越界: {} + 8 > {}",
                        block_in_setcontext_flag_offset,
                        payload_data.len()
                    ));
                }
                let flag_addr = loc.base + block_in_setcontext_flag_offset as u64;
                mem.pwrite_all(&1u64.to_ne_bytes(), flag_addr).map_err(|flag_err| {
                    format!(
                        "setArgV0 指针写入失败后启用 setcontext-only 也失败: setArgV0_error={} flag_error={}",
                        e, flag_err
                    )
                })?;
                log_warn!(
                    "setArgV0 指针写入失败，改用 setcontext-only 阻塞: slot=0x{:x}, error={}",
                    addr,
                    e
                );
                None
            }
        }
    } else {
        // 降级模式：block_in_setcontext 已置 1，阻塞由 setcontext GOT 替换承担
        None
    };

    // 11. 替换 setcontext GOT slot（可选）
    //     与 Frida 一致：already-patched 时 GOT 中可能是旧的替换值，
    //     必须用原始函数地址作为备份，而非从内存中读取当前值
    let setcontext_got = if let Some((func_addr, got_addr)) = &setcontext_info {
        if let Some(got) = got_addr {
            let backup = if already_patched {
                // already-patched: GOT 中是旧 patch 的替换值，使用原始函数地址
                func_addr.to_ne_bytes()
            } else {
                let mut buf = [0u8; 8];
                mem.pread_exact(&mut buf, *got)?;
                buf
            };
            mem.pwrite_all(&replacement_setcontext_addr.to_ne_bytes(), *got)?;
            log_verbose!("setcontext GOT 已替换: 0x{:x}", got);
            Some((*got, backup))
        } else {
            None
        }
    } else {
        None
    };

    // 12. 属性伪装: 替换 capset GOT（仅指定 --profile 时）
    //     capset hook 在 cap drop 前执行 mount --bind
    let capset_got = if PROP_PROFILE_DIR.get().and_then(|v| v.as_ref()).is_some() {
        let got = find_got_entry_for_import(&maps, "libandroid_runtime.so", "capset");
        if let Some(got) = got {
            let backup = if already_patched {
                libc_funcs.capset.to_ne_bytes()
            } else {
                let mut buf = [0u8; 8];
                mem.pread_exact(&mut buf, got)?;
                buf
            };
            mem.pwrite_all(&replacement_prctl_addr.to_ne_bytes(), got)?;
            log_verbose!("capset GOT 已替换: 0x{:x}", got);
            Some((got, backup))
        } else {
            log_warn!("未找到 capset GOT，属性 mount 将不可用");
            None
        }
    } else {
        None
    };

    // 13. SIGCONT 恢复 zygote — guard 在 drop 时自动发送
    //     正常路径：显式 drop guard 触发 SIGCONT
    //     异常路径：? 返回 Err 时 guard 自动 drop 触发 SIGCONT
    drop(sigcont_guard);

    Ok(ZygotePatch {
        pid,
        payload_base: loc.base,
        payload_backup,
        payload_path: loc.path,
        payload_file_offset: loc.file_offset,
        setargv0_slot,
        setcontext_got,
        capset_got,
    })
}

/// 从 backing 文件读取原始数据（COW 场景下 /proc/pid/mem 中已是旧 patch）
fn read_backing_file_data(path: &str, file_offset: u64, len: usize) -> Result<Vec<u8>, String> {
    use std::os::unix::io::AsRawFd;

    let file = std::fs::File::open(path).map_err(|e| format!("打开 backing 文件 {} 失败: {}", path, e))?;

    let mut buf = vec![0u8; len];
    let fd = file.as_raw_fd();
    let n = loop {
        let ret = unsafe {
            libc::pread(
                fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                len,
                file_offset as libc::off_t,
            )
        };
        if ret >= 0 {
            break ret;
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        return Err(format!("读取 backing 文件 {} 失败: {}", path, err));
    };
    if (n as usize) < len {
        log_warn!("Backing 文件短读: 期望 {} 字节，实际 {} 字节", len, n);
    }
    Ok(buf)
}

/// Payload 写入位置信息
struct PayloadLocation {
    base: u64,
    vma_start: u64,
    vma_end: u64,
    prot: u64,
    perms: String,
    path: String,     // 映射的backing文件路径（用于 COW 还原）
    file_offset: u64, // backing文件中的偏移
}

/// 找到 payload 写入位置：libstagefright.so 的 R+X 段末尾页
/// 与 Frida 一致：取第一个匹配的 libstagefright.so R+X 段
fn find_payload_location(maps: &[MapEntry]) -> Result<PayloadLocation, String> {
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
    if page_size == 0 || (page_size & (page_size - 1)) != 0 {
        return Err(format!("非法 page_size: {}", page_size));
    }

    // 查找 libstagefright.so 的第一个 r-x 段（与 Frida payload_base == 0 guard 一致）
    for entry in maps {
        if entry.path.ends_with("/libstagefright.so") && entry.is_readable() && entry.is_executable() {
            if entry.end <= entry.start || entry.end - entry.start < page_size {
                return Err(format!(
                    "libstagefright.so R+X 段过小: start=0x{:x} end=0x{:x} size=0x{:x} page_size=0x{:x}",
                    entry.start,
                    entry.end,
                    entry.end - entry.start,
                    page_size
                ));
            }
            if (entry.start & (page_size - 1)) != 0 || (entry.end & (page_size - 1)) != 0 {
                return Err(format!(
                    "libstagefright.so VMA 非页对齐: start=0x{:x} end=0x{:x} page_size=0x{:x}",
                    entry.start, entry.end, page_size
                ));
            }
            let base = entry.end - page_size;
            // 与 Frida 一致：基础 prot = R|X，如果段可写则加 W
            let mut prot = (libc::PROT_READ | libc::PROT_EXEC) as u64;
            if entry.is_writable() {
                prot |= libc::PROT_WRITE as u64;
            }
            // file_offset 对应 payload 实际写入位置（段末页），而非映射起始
            let file_offset = entry.offset + (base - entry.start);
            return Ok(PayloadLocation {
                base,
                vma_start: entry.start,
                vma_end: entry.end,
                prot,
                perms: entry.perms.clone(),
                path: entry.path.clone(),
                file_offset,
            });
        }
    }

    Err("未找到 libstagefright.so 的 R+X 段，无法写入 payload".to_string())
}

/// 格式化给定虚拟地址范围附近的 VMA 列表（用于写入失败时诊断）
fn dump_maps_near(maps: &[MapEntry], addr: u64, radius: usize) -> String {
    let mut idx_hit = None;
    for (i, e) in maps.iter().enumerate() {
        if addr >= e.start && addr < e.end {
            idx_hit = Some(i);
            break;
        }
        if addr < e.start {
            idx_hit = Some(i);
            break;
        }
    }
    let center = idx_hit.unwrap_or(maps.len().saturating_sub(1));
    let lo = center.saturating_sub(radius);
    let hi = (center + radius + 1).min(maps.len());
    let mut out = String::new();
    for e in &maps[lo..hi] {
        let marker = if addr >= e.start && addr < e.end {
            " <== HIT"
        } else {
            ""
        };
        out.push_str(&format!(
            "\n    0x{:x}-0x{:x} {} off=0x{:x} {}{}",
            e.start, e.end, e.perms, e.offset, e.path, marker
        ));
    }
    out
}

/// libc 函数地址集合
struct LibcFunctions {
    mprotect: u64,
    strdup: u64,
    free: u64,
    socket: u64,
    connect: u64,
    __errno: u64,
    getpid: u64,
    getppid: u64,
    sendmsg: u64,
    recv: u64,
    close: u64,
    raise: u64,
    capset: u64,
}

/// 解析 libc.so 获取所需函数地址
fn resolve_libc_functions(maps: &[MapEntry]) -> Result<LibcFunctions, String> {
    // 找到 libc.so 在目标进程中的真实装载基址和路径。
    let (libc_base, libc_path) = find_loaded_module(maps, "/libc.so").ok_or_else(|| "未找到 libc.so".to_string())?;

    log_verbose!("libc.so 基址: 0x{:x}, 路径: {}", libc_base, libc_path);

    // 读取 libc ELF 文件解析导出表
    let elf_data = std::fs::read(&libc_path).map_err(|e| format!("读取 {} 失败: {}", libc_path, e))?;
    let elf = goblin::elf::Elf::parse(&elf_data).map_err(|e| format!("解析 libc ELF 失败: {}", e))?;

    let resolve = |name: &str| -> Result<u64, String> {
        find_dynsym_addr(&elf, name, libc_base).ok_or_else(|| format!("libc.so 中未找到 {}", name))
    };

    Ok(LibcFunctions {
        mprotect: resolve("mprotect")?,
        strdup: resolve("strdup")?,
        free: resolve("free")?,
        socket: resolve("socket")?,
        connect: resolve("connect")?,
        __errno: resolve("__errno")?,
        getpid: resolve("getpid")?,
        getppid: resolve("getppid")?,
        sendmsg: resolve("sendmsg")?,
        recv: resolve("recv")?,
        close: resolve("close")?,
        raise: resolve("raise")?,
        capset: resolve("capset")?,
    })
}

/// 在 maps 中找到指定 SO 的导出符号地址
fn find_export_in_maps(maps: &[MapEntry], so_name: &str, symbol_name: &str) -> Result<u64, String> {
    let suffix = format!("/{}", so_name);
    let (base, path) = find_loaded_module(maps, &suffix).ok_or_else(|| format!("未找到 {}", so_name))?;

    let elf_data = std::fs::read(&path).map_err(|e| format!("读取 {} 失败: {}", path, e))?;
    let elf = goblin::elf::Elf::parse(&elf_data).map_err(|e| format!("解析 {} 失败: {}", so_name, e))?;

    find_dynsym_addr(&elf, symbol_name, base).ok_or_else(|| format!("{} 中未找到 {}", so_name, symbol_name))
}

/// 查找 selinux_android_setcontext 的地址和 GOT slot
/// 返回 Some((函数地址, Option<GOT地址>))
fn find_setcontext_info(maps: &[MapEntry]) -> Option<(u64, Option<u64>)> {
    // 先找 libselinux.so 中的导出
    let func_addr = if let Some((base, path)) = find_loaded_module(maps, "/libselinux.so") {
        std::fs::read(path).ok().and_then(|data| {
            goblin::elf::Elf::parse(&data)
                .ok()
                .and_then(|elf| find_dynsym_addr(&elf, "selinux_android_setcontext", base))
        })
    } else {
        None
    };

    let func_addr = func_addr?;

    // 尝试在 libandroid_runtime.so 的 GOT 中找到引用
    let got_addr = find_got_entry_for_import(maps, "libandroid_runtime.so", "selinux_android_setcontext");

    Some((func_addr, got_addr))
}

/// 在指定 SO 的 GOT 中查找对某个导入符号的引用
fn find_got_entry_for_import(maps: &[MapEntry], so_name: &str, import_name: &str) -> Option<u64> {
    let suffix = format!("/{}", so_name);
    let (base, path) = find_loaded_module(maps, &suffix)?;

    let elf_data = std::fs::read(path).ok()?;
    let elf = goblin::elf::Elf::parse(&elf_data).ok()?;

    // 在动态重定位表中查找
    for reloc in elf.dynrelas.iter() {
        let sym_idx = reloc.r_sym;
        if let Some(sym) = elf.dynsyms.get(sym_idx) {
            if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                if name == import_name {
                    return Some(base + reloc.r_offset);
                }
            }
        }
    }

    // 也检查 pltrelocs
    for reloc in elf.pltrelocs.iter() {
        let sym_idx = reloc.r_sym;
        if let Some(sym) = elf.dynsyms.get(sym_idx) {
            if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                if name == import_name {
                    return Some(base + reloc.r_offset);
                }
            }
        }
    }

    None
}

/// 在 boot image 相关映射中搜索 setArgV0 函数指针
/// 与 Frida 一致：同时搜索原始指针和已被替换的指针（already-patched 检测）。
/// 如果发现指针已被替换（如另一个 rustFrida 实例），仍能正确定位 slot。
fn find_setargv0_pointer_in_heap(
    pid: u32,
    maps: &[MapEntry],
    setargv0_addr: u64,
    replaced_setargv0_addr: Option<u64>,
) -> Result<Option<(u64, [u8; 8], bool)>, String> {
    let original_needle = setargv0_addr.to_ne_bytes();
    let replaced_needle = replaced_setargv0_addr.map(|a| a.to_ne_bytes());
    let mem = ProcMem::open(pid)?;

    let search_candidates = |candidates: &[&MapEntry]| -> Result<Option<(u64, [u8; 8], bool)>, String> {
        let mut matches = Vec::new();

        for entry in candidates {
            let size = entry.end.saturating_sub(entry.start);
            let mut pos = 0u64;
            let mut buf = vec![0u8; SETARGV0_SCAN_CHUNK_SIZE];
            let mut read_errors = 0usize;

            let mut scan_buf = |chunk_base: u64, chunk: &[u8]| {
                // 搜索 original needle（指针 8 字节对齐）
                for offset in (0..chunk.len().saturating_sub(7)).step_by(8) {
                    if chunk[offset..offset + 8] == original_needle {
                        let addr = chunk_base + offset as u64;
                        let mut backup = [0u8; 8];
                        backup.copy_from_slice(&original_needle);
                        matches.push((addr, backup, false, entry.path.clone(), entry.is_executable()));
                    }
                }

                // 搜索 replaced needle（already-patched 检测）
                if let Some(ref replaced) = replaced_needle {
                    for offset in (0..chunk.len().saturating_sub(7)).step_by(8) {
                        if chunk[offset..offset + 8] == *replaced {
                            let addr = chunk_base + offset as u64;
                            let mut backup = [0u8; 8];
                            backup.copy_from_slice(&original_needle);
                            matches.push((addr, backup, true, entry.path.clone(), entry.is_executable()));
                        }
                    }
                }
            };

            while pos < size {
                let want = SETARGV0_SCAN_CHUNK_SIZE.min((size - pos) as usize);
                let chunk_base = entry.start + pos;
                match mem.pread_exact(&mut buf[..want], chunk_base) {
                    Ok(()) => scan_buf(chunk_base, &buf[..want]),
                    Err(_) => {
                        read_errors += 1;
                        let mut page_pos = 0usize;
                        while page_pos < want {
                            let page_want = 4096usize.min(want - page_pos);
                            let page_base = chunk_base + page_pos as u64;
                            if mem.pread_exact(&mut buf[..page_want], page_base).is_ok() {
                                scan_buf(page_base, &buf[..page_want]);
                            }
                            page_pos += page_want;
                        }
                    }
                }
                pos += want as u64;
            }

            if read_errors > 0 {
                log_verbose!(
                    "setArgV0 扫描 {} 发生 {} 个大块读取失败，已按页回退",
                    entry.path,
                    read_errors
                );
            }
        }

        if matches.is_empty() {
            return Ok(None);
        }

        matches.sort_by_key(|(addr, _, _, _, _)| *addr);
        matches.dedup_by_key(|(addr, _, _, _, _)| *addr);

        if matches.len() > 1 {
            let non_exec_matches: Vec<_> = matches
                .iter()
                .filter(|(_, _, _, _, is_exec)| !*is_exec)
                .cloned()
                .collect();
            if non_exec_matches.len() == 1 {
                let (addr, backup, already_patched, _, _) = non_exec_matches[0].clone();
                log_warn!("多个 setArgV0 候选中优先选择非可执行映射内的 slot: 0x{:x}", addr);
                return Ok(Some((addr, backup, already_patched)));
            }

            let summary = matches
                .iter()
                .take(4)
                .map(|(addr, _, already_patched, path, is_exec)| {
                    format!(
                        "0x{:x}{}{} @ {}",
                        addr,
                        if *already_patched { " [patched]" } else { "" },
                        if *is_exec { " [exec]" } else { "" },
                        path
                    )
                })
                .collect::<Vec<_>>()
                .join(", ");
            return Err(format!(
                "找到多个 setArgV0 指针候选 ({} 个): {}",
                matches.len(),
                summary
            ));
        }

        let (addr, backup, already_patched, _, _) = matches.remove(0);
        if already_patched {
            log_warn!("setArgV0 指针已被替换（already patched），slot at 0x{:x}", addr);
        }
        Ok(Some((addr, backup, already_patched)))
    };

    // 搜索候选区域：boot image / dalvik-LinearAlloc（R+W 非 X 非 shared）
    // 与 Frida is_boot_heap() 一致
    let preferred: Vec<&MapEntry> = maps.iter().filter(|e| is_boot_heap(e)).collect();
    log_verbose!("搜索 {} 个 boot heap 区域查找 setArgV0 指针", preferred.len());
    if let Some(found) = search_candidates(&preferred)? {
        return Ok(Some(found));
    }

    // Android 16 / 新版本 ART 上，slot 可能不再落在传统 boot heap/LinearAlloc 区域。
    // 回退只扫描 ART 相关 RW private 映射，并要求唯一命中，避免误扫 malloc/stack/random 残留值。
    let fallback: Vec<&MapEntry> = maps
        .iter()
        .filter(|e| is_private_rw_mapping(e))
        .filter(|e| !is_boot_heap(e))
        .filter(|e| is_setargv0_rw_fallback_candidate(e))
        .collect();
    log_warn!(
        "boot heap 中未命中 setArgV0 指针，回退扫描 {} 个 ART 相关 RW private 区域",
        fallback.len()
    );
    if let Some(found) = search_candidates(&fallback)? {
        return Ok(Some(found));
    }

    // 再退一层：某些新系统可能把 slot 放在只读或 shared 映射中。
    // 继续限制在 ART 相关可读映射，仍要求唯一命中。
    let final_fallback: Vec<&MapEntry> = maps
        .iter()
        .filter(|e| is_readable_mapping(e))
        .filter(|e| !is_private_rw_mapping(e))
        .filter(|e| is_setargv0_readable_fallback_candidate(e))
        .collect();
    log_warn!(
        "ART 相关 RW private 区域未命中 setArgV0 指针，继续扫描 {} 个 ART 相关可读区域",
        final_fallback.len()
    );
    if let Some(found) = search_candidates(&final_fallback)? {
        return Ok(Some(found));
    }

    // 所有层均未命中：返回 None，上层降级为 setcontext GOT 阻塞（最后的兼容路径）
    log_warn!(
        "未在 boot heap、ART 相关 RW private 或 ART 相关可读区域中找到 setArgV0 指针 (0x{:x})，切换降级模式",
        setargv0_addr
    );
    Ok(None)
}

/// 构建 zymbiote payload：解析 ELF，填充上下文
/// 与 Frida 一致：使用可执行 LOAD 段（而非 section）提取 payload，
/// 用 segment vm_address 计算符号偏移。不做 GOT 重定位（ARM64 PC-relative 寻址）。
/// 返回: (payload, replacement_setargv0, replacement_setcontext, replacement_prctl, ctx_base_in_payload)
fn build_payload(
    socket_name: &str,
    payload_base: u64,
    payload_original_prot: u64,
    libc_funcs: &LibcFunctions,
    original_setargv0: u64,
    original_setcontext: Option<u64>,
) -> Result<(Vec<u8>, u64, u64, u64, usize), String> {
    // 解析 zymbiote ELF
    let elf = goblin::elf::Elf::parse(ZYMBIOTE_ELF).map_err(|e| format!("解析 zymbiote ELF 失败: {}", e))?;

    // 找到可执行 LOAD 段（与 Frida enumerate_segments 找 EXECUTE 段一致）
    let text_seg = elf
        .program_headers
        .iter()
        .find(|ph| {
            ph.p_type == goblin::elf::program_header::PT_LOAD && (ph.p_flags & goblin::elf::program_header::PF_X) != 0
        })
        .ok_or_else(|| "zymbiote ELF 中未找到可执行 LOAD 段".to_string())?;

    let seg_file_offset = text_seg.p_offset as usize;
    let seg_file_size = text_seg.p_filesz as usize;
    let seg_vm_address = text_seg.p_vaddr;

    if seg_file_offset + seg_file_size > ZYMBIOTE_ELF.len() {
        return Err(format!(
            "可执行段越界: offset={} size={} elf_len={}",
            seg_file_offset,
            seg_file_size,
            ZYMBIOTE_ELF.len()
        ));
    }

    // 复制 payload 模板（从段的 file_offset 开始，长度为 file_size）
    let mut payload = ZYMBIOTE_ELF[seg_file_offset..seg_file_offset + seg_file_size].to_vec();

    // 找到符号在 payload 内的偏移（sym.st_value - segment.vm_address）
    // 与 Frida 一致：replacement = payload_base + (export.address - text.vm_address)
    let find_symbol_offset = |name: &str| -> Result<u64, String> {
        // 先搜索 dynsyms（导出符号）
        let result = elf.dynsyms.iter().find(|sym| {
            if let Some(sym_name) = elf.dynstrtab.get_at(sym.st_name) {
                sym_name == name
            } else {
                false
            }
        });
        if let Some(sym) = result {
            return Ok(sym.st_value - seg_vm_address);
        }
        // 再搜索完整 symtab（包含 LOCAL/HIDDEN 符号，如 zymbiote context）
        let result = elf.syms.iter().find(|sym| {
            if let Some(sym_name) = elf.strtab.get_at(sym.st_name) {
                sym_name == name
            } else {
                false
            }
        });
        result
            .map(|sym| sym.st_value - seg_vm_address)
            .ok_or_else(|| format!("zymbiote ELF 中未找到符号 {}", name))
    };

    let replacement_setargv0_offset = find_symbol_offset("rustfrida_zymbiote_replacement_setargv0")?;
    let replacement_setcontext_offset = find_symbol_offset("rustfrida_zymbiote_replacement_setcontext")?;
    let replacement_prctl_offset = find_symbol_offset("rustfrida_zymbiote_replacement_capset")?;
    let zymbiote_offset = find_symbol_offset("zymbiote")?;

    // 绝对地址 = payload_base + 段内偏移
    let replacement_setargv0_addr = payload_base + replacement_setargv0_offset;
    let replacement_setcontext_addr = payload_base + replacement_setcontext_offset;
    let replacement_prctl_addr = payload_base + replacement_prctl_offset;
    let ctx_base = zymbiote_offset as usize;
    log_verbose!(
        "ZymbioteContext: ctx_base=0x{:x}, payload_len=0x{:x}",
        ctx_base,
        payload.len()
    );

    // 填充 ZymbioteContext
    // socket_path
    let name_bytes = socket_name.as_bytes();
    let path_len = name_bytes.len().min(63);
    payload[ctx_base..ctx_base + path_len].copy_from_slice(&name_bytes[..path_len]);
    payload[ctx_base + path_len] = 0;

    // payload_base
    let ctx = &mut payload[ctx_base..];
    write_u64(ctx, CTX_PAYLOAD_BASE - CTX_SOCKET_PATH, payload_base);
    write_u64(ctx, CTX_PAYLOAD_SIZE - CTX_SOCKET_PATH, seg_file_size as u64);
    write_u64(ctx, CTX_PAYLOAD_ORIGINAL_PROT - CTX_SOCKET_PATH, payload_original_prot);
    write_u64(ctx, CTX_PACKAGE_NAME - CTX_SOCKET_PATH, 0); // NULL
    write_u64(
        ctx,
        CTX_ORIGINAL_SETCONTEXT - CTX_SOCKET_PATH,
        original_setcontext.unwrap_or(0),
    );
    write_u64(ctx, CTX_ORIGINAL_SET_ARGV0 - CTX_SOCKET_PATH, original_setargv0);

    // libc 函数指针
    write_u64(ctx, CTX_MPROTECT - CTX_SOCKET_PATH, libc_funcs.mprotect);
    write_u64(ctx, CTX_STRDUP - CTX_SOCKET_PATH, libc_funcs.strdup);
    write_u64(ctx, CTX_FREE - CTX_SOCKET_PATH, libc_funcs.free);
    write_u64(ctx, CTX_SOCKET - CTX_SOCKET_PATH, libc_funcs.socket);
    write_u64(ctx, CTX_CONNECT - CTX_SOCKET_PATH, libc_funcs.connect);
    write_u64(ctx, CTX_ERRNO - CTX_SOCKET_PATH, libc_funcs.__errno);
    write_u64(ctx, CTX_GETPID - CTX_SOCKET_PATH, libc_funcs.getpid);
    write_u64(ctx, CTX_GETPPID - CTX_SOCKET_PATH, libc_funcs.getppid);
    write_u64(ctx, CTX_SENDMSG - CTX_SOCKET_PATH, libc_funcs.sendmsg);
    write_u64(ctx, CTX_RECV - CTX_SOCKET_PATH, libc_funcs.recv);
    write_u64(ctx, CTX_CLOSE - CTX_SOCKET_PATH, libc_funcs.close);
    write_u64(ctx, CTX_RAISE - CTX_SOCKET_PATH, libc_funcs.raise);
    // prop_remap: 有 profile 时启用
    let prop_remap = if PROP_PROFILE_DIR.get().and_then(|v| v.as_ref()).is_some() {
        1u64
    } else {
        0u64
    };
    log_verbose!(
        "build_payload: prop_remap={} (PROP_PROFILE_DIR={:?})",
        prop_remap,
        PROP_PROFILE_DIR.get()
    );
    write_u64(ctx, CTX_PROP_REMAP - CTX_SOCKET_PATH, prop_remap);
    // block_in_setcontext 默认 0，由调用者在三层 slot 全部 miss 时 flip 为 1
    write_u64(ctx, CTX_BLOCK_IN_SETCONTEXT - CTX_SOCKET_PATH, 0);
    let passive_setargv0 = if diag_env_flag("RF_DIAG_ZYM_PASSIVE_SETARGV0") {
        1u64
    } else {
        0u64
    };
    write_u64(ctx, CTX_PASSIVE_SETARGV0 - CTX_SOCKET_PATH, passive_setargv0);
    // 无需 GOT 重定位：zymbiote 用 -shared -nostdlib 构建，
    // ARM64 ADRP+ADD 为 PC-relative 寻址，代码和数据在同一段内，
    // 移动到新地址后相对偏移不变。实测 .got 为空且无动态重定位。

    Ok((
        payload,
        replacement_setargv0_addr,
        replacement_setcontext_addr,
        replacement_prctl_addr,
        ctx_base,
    ))
}

/// 在 payload 缓冲区内写入 u64 值
fn write_u64(buf: &mut [u8], offset: usize, value: u64) {
    if offset + 8 <= buf.len() {
        buf[offset..offset + 8].copy_from_slice(&value.to_ne_bytes());
    }
}

#[derive(Clone, Copy)]
enum PendingConnectionCleanup {
    Resume,
    KillAfterRevert,
}

/// 处理所有挂起的子进程连接。
/// 正常退出走 Resume，避免 child 永远卡在 recv(ACK)；
/// pre-resume Java hook 失败走 KillAfterRevert，避免放行后错过早期 hook。
fn cleanup_pending_connections(mode: PendingConnectionCleanup) {
    let conns = match ACTIVE_CONNECTIONS.get() {
        Some(lock) => lock,
        None => return,
    };

    let entries: Vec<(u32, (std::os::unix::net::UnixStream, u32))> = {
        let mut map = match conns.lock() {
            Ok(m) => m,
            Err(_) => return,
        };
        map.drain().collect()
    };

    if entries.is_empty() {
        return;
    }

    match mode {
        PendingConnectionCleanup::Resume => log_info!("正在恢复 {} 个挂起的子进程...", entries.len()),
        PendingConnectionCleanup::KillAfterRevert => log_info!("正在终止 {} 个未放行的子进程...", entries.len()),
    }

    for (pid, (mut stream, ppid)) in entries {
        match mode {
            PendingConnectionCleanup::Resume => log_verbose!("恢复挂起的子进程 {} (ppid={})...", pid, ppid),
            PendingConnectionCleanup::KillAfterRevert => {
                log_verbose!("终止未放行的子进程 {} (ppid={})...", pid, ppid)
            }
        }

        // 检查子进程是否仍存在
        if !std::path::Path::new(&format!("/proc/{}", pid)).exists() {
            log_verbose!("子进程 {} 已不存在，跳过处理", pid);
            drop(stream);
            continue;
        }

        // 1. 发送 ACK 解除子进程阻塞
        if stream.write_all(&[ACK_BYTE]).is_err() {
            // 连接已断开，子进程可能已退出；按清理模式处理剩余进程。
            match mode {
                PendingConnectionCleanup::Resume => unsafe { libc::kill(pid as i32, libc::SIGCONT) },
                PendingConnectionCleanup::KillAfterRevert => unsafe { libc::kill(pid as i32, libc::SIGKILL) },
            };
            continue;
        }

        // 2. 等待子进程关闭 socket（收到 ACK 后 close(fd)）
        drain_until_eof(&mut stream, std::time::Duration::from_secs(2));
        drop(stream);

        // 3. 等待子进程 raise(SIGSTOP)，然后还原 patch 并恢复
        if wait_until_stopped(pid).is_ok() {
            let _ = revert_child_patch_by_ppid(pid, ppid);
        }
        match mode {
            PendingConnectionCleanup::Resume => unsafe { libc::kill(pid as i32, libc::SIGCONT) },
            PendingConnectionCleanup::KillAfterRevert => unsafe { libc::kill(pid as i32, libc::SIGKILL) },
        };
    }
}

fn cleanup_zygote_patches_with_pending_mode(mode: PendingConnectionCleanup) {
    CLEANUP_STARTED.store(true, Ordering::SeqCst);

    // 幂等保护：所有调用路径（正常退出 + 信号处理）共享此检查
    if CLEANUP_DONE.swap(true, Ordering::SeqCst) {
        return;
    }

    // 1. 先恢复所有挂起的子进程连接（与 Frida close() 顺序一致）
    //    必须在还原 Zygote 之前执行：子进程持有 COW 副本，需要独立还原
    cleanup_pending_connections(mode);

    // 2. 再还原 Zygote patch
    let patches = match ZYGOTE_PATCHES.get() {
        Some(lock) => lock,
        None => return,
    };

    let mut patches = match patches.lock() {
        Ok(p) => p,
        Err(_) => return,
    };

    for patch in patches.iter() {
        log_info!("正在还原 zygote {} 的 patch...", patch.pid);

        // 检查进程是否仍然存在（与 Frida catch (Error e) {} 一致：进程不存在时跳过）
        if !std::path::Path::new(&format!("/proc/{}", patch.pid)).exists() {
            log_warn!("Zygote {} 已不存在，跳过还原", patch.pid);
            continue;
        }

        // SIGSTOP zygote
        let ret = unsafe { libc::kill(patch.pid as i32, libc::SIGSTOP) };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ESRCH) {
                log_warn!("Zygote {} 已退出 (ESRCH)，跳过还原", patch.pid);
                continue;
            }
            log_error!("SIGSTOP zygote {} 失败: {}", patch.pid, err);
            // 与 Frida 一致：即使 SIGSTOP 失败也尝试还原（进程可能已停止）
        }

        if wait_until_stopped(patch.pid).is_err() {
            log_error!("等待 zygote {} 停止超时", patch.pid);
            // 仍然尝试还原，与 Frida try/finally 一致
        }

        match ProcMem::open(patch.pid) {
            Ok(mem) => {
                // 还原 payload
                if let Err(e) = mem.pwrite_all(&patch.payload_backup, patch.payload_base) {
                    log_error!("还原 zygote {} payload 失败: {}", patch.pid, e);
                }

                // 还原 setArgV0 指针（降级模式下为 None）
                if let Some((addr, backup)) = &patch.setargv0_slot {
                    if let Err(e) = mem.pwrite_all(backup, *addr) {
                        log_error!("还原 zygote {} setArgV0 指针失败: {}", patch.pid, e);
                    }
                }

                // 还原 setcontext GOT
                if let Some((addr, backup)) = &patch.setcontext_got {
                    if let Err(e) = mem.pwrite_all(backup, *addr) {
                        log_error!("还原 zygote {} setcontext GOT 失败: {}", patch.pid, e);
                    }
                }

                // 还原 capset GOT
                if let Some((addr, backup)) = &patch.capset_got {
                    if let Err(e) = mem.pwrite_all(backup, *addr) {
                        log_error!("还原 zygote {} capset GOT 失败: {}", patch.pid, e);
                    }
                }

                log_success!("Zygote {} patch 已还原", patch.pid);
            }
            Err(e) => {
                log_error!("打开 /proc/{}/mem 失败: {}", patch.pid, e);
            }
        }

        // SIGCONT 恢复 zygote（无论还原是否成功，与 Frida finally 一致）
        unsafe { libc::kill(patch.pid as i32, libc::SIGCONT) };
    }

    patches.clear();

    // 还原 SELinux 状态
    crate::selinux::restore_selinux();
}

/// 退出时还原所有 Zygote patch（幂等：多次调用只执行一次）
/// 与 Frida close() 顺序一致：先恢复挂起的子进程，再还原 Zygote patch
pub(crate) fn cleanup_zygote_patches() {
    cleanup_zygote_patches_with_pending_mode(PendingConnectionCleanup::Resume);
}

/// pre-resume Java hook 失败时使用：还原 child patch 后终止 child，避免放行错过早期 hook。
pub(crate) fn abort_pending_children_and_cleanup_zygote_patches() {
    cleanup_zygote_patches_with_pending_mode(PendingConnectionCleanup::KillAfterRevert);
}

/// 是否已执行过清理（幂等保护，cleanup_zygote_patches 内部使用）
static CLEANUP_DONE: AtomicBool = AtomicBool::new(false);
/// 清理是否已经开始（第二次 Ctrl+C 仅在此阶段允许强退）
static CLEANUP_STARTED: AtomicBool = AtomicBool::new(false);

/// 信号是否已收到（信号处理函数只设标记，不做清理，避免死锁）
static SIGNAL_RECEIVED: AtomicBool = AtomicBool::new(false);
/// 信号计数器：第一次设标记；清理开始后第二次 _exit 强制退出
static SIGNAL_COUNT: AtomicI32 = AtomicI32::new(0);

/// 检查是否收到了终止信号
pub(crate) fn signal_received() -> bool {
    SIGNAL_RECEIVED.load(Ordering::Relaxed)
}

/// 信号处理函数：仅设置标记（async-signal-safe）。
/// 不调用 cleanup_zygote_patches（会获取 Mutex 导致死锁），
/// 清理由 main 退出路径中的 cleanup_zygote_patches() 完成。
/// 第一次信号：设标记，保持 handler 不变（不恢复 SIG_DFL）。
/// 清理开始后的第二次信号：_exit(1) 强制退出（async-signal-safe，不经过 cleanup）。
extern "C" fn signal_cleanup_handler(_sig: libc::c_int) {
    let prev = SIGNAL_COUNT.fetch_add(1, Ordering::Relaxed);
    SIGNAL_RECEIVED.store(true, Ordering::Relaxed);
    if prev > 0 && CLEANUP_STARTED.load(Ordering::Relaxed) {
        // 清理过程中再次收到信号：强制退出，避免卡死
        unsafe { libc::_exit(1) };
    }
}

/// 注册 SIGINT/SIGTERM 信号处理函数
pub(crate) fn register_cleanup_handler() {
    unsafe {
        libc::signal(libc::SIGINT, signal_cleanup_handler as libc::sighandler_t);
        libc::signal(libc::SIGTERM, signal_cleanup_handler as libc::sighandler_t);
    }
}
