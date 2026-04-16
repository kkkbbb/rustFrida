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
use std::os::unix::io::RawFd;
use std::os::unix::net::UnixListener;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use crate::injection::inject_via_bootstrapper;
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
    /// prctl GOT slot（可选，用于保留 CAP_SYS_ADMIN）
    prctl_got: Option<(u64, [u8; 8])>,
}

/// 全局状态
static ZYGOTE_PATCHES: OnceLock<Mutex<Vec<ZygotePatch>>> = OnceLock::new();
static SERVER_SOCKET_PATH: OnceLock<String> = OnceLock::new();
static SPAWN_REQUESTS: OnceLock<Mutex<HashMap<String, Arc<SpawnNotifier>>>> = OnceLock::new();
/// 属性 profile 目录（由 --profile 设置，None = 禁用）
static PROP_PROFILE_DIR: OnceLock<Option<String>> = OnceLock::new();

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

fn unregister_spawn_request(process_name: &str, package: &str, dual_key: bool) {
    if let Some(requests) = SPAWN_REQUESTS.get() {
        if let Ok(mut map) = requests.lock() {
            map.remove(process_name);
            if dual_key {
                map.remove(package);
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

/// 判断 maps 条目是否为 boot heap 区域（boot.art / dalvik-LinearAlloc）
fn is_boot_heap(entry: &MapEntry) -> bool {
    entry.is_readable()
        && entry.is_writable()
        && !entry.is_executable()
        && !entry.is_shared()
        && (entry.path.contains("boot.art")
            || entry.path.contains("boot-framework.art")
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

/// 在 ELF dynsyms 中查找符号地址
fn find_dynsym_addr(elf: &goblin::elf::Elf, name: &str, base: u64) -> Option<u64> {
    elf.dynsyms
        .iter()
        .find(|sym| elf.dynstrtab.get_at(sym.st_name).map_or(false, |n| n == name))
        .map(|sym| base + sym.st_value)
}

/// 共享的 spawn 前置步骤：确保 zymbiote 加载、注册请求、启动 App、等待 hello
/// 返回收到的 SpawnHello（子进程此时处于暂停状态）
fn spawn_and_wait_hello(package: &str) -> Result<SpawnHello, String> {
    // 1. 确保 zymbiote 已加载到所有 zygote 进程
    ensure_zymbiote_loaded()?;

    // 2. 解析进程名并注册 spawn 请求
    //    同时注册 process_name 和原始 package name，因为 zymbiote hello 发送的是
    //    setcontext 的 name 参数（= 包名），而 processName 可能不同（android:process 属性）
    let process_name = resolve_process_name(package);
    let dual_key = process_name != package;
    if dual_key {
        log_info!("进程名解析: {} -> {}（两者均注册）", package, process_name);
    }
    let notifier = Arc::new(SpawnNotifier::new());
    {
        let requests = SPAWN_REQUESTS.get_or_init(|| Mutex::new(HashMap::new()));
        let mut map = requests.lock().unwrap();
        // 检查重复 spawn 请求（与 Frida 一致：拒绝重复，防止前一个 spawn 永远收不到 hello）
        if map.contains_key(&process_name) {
            return Err(format!("已有一个针对 {} 的 spawn 请求正在进行中", process_name));
        }
        if dual_key && map.contains_key(package) {
            return Err(format!("已有一个针对 {} 的 spawn 请求正在进行中", package));
        }
        map.insert(process_name.clone(), notifier.clone());
        if dual_key {
            map.insert(package.to_string(), notifier.clone());
        }
    }

    // 3. 强制停止并启动目标应用
    log_info!("正在启动应用 {}...", package);
    launch_app(package)?;

    // 4. 等待 SpawnHello（20s 超时）
    log_info!("等待应用 {} 启动... (最长 20s)", package);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let poll_interval = std::time::Duration::from_millis(100);
    let hello = loop {
        if let Some(hello) = notifier.try_recv() {
            break hello;
        }

        if signal_received() {
            unregister_spawn_request(&process_name, package, dual_key);
            return Err(format!("等待应用 {} 启动时收到终止信号", package));
        }

        let now = std::time::Instant::now();
        let Some(remaining) = deadline.checked_duration_since(now) else {
            // 超时后再 try_recv 一次：防止在极短窗口内 hello 刚到达但 condvar 已超时
            if let Some(late_hello) = notifier.try_recv() {
                log_verbose!("超时后发现晚到的 hello (pid={})", late_hello.pid);
                break late_hello;
            }

            unregister_spawn_request(&process_name, package, dual_key);
            cleanup_orphan_spawn_connections();
            return Err(format!(
                "等待应用 {} 启动超时 (20s)，请检查:\n  1. 包名是否正确\n  2. 应用是否已安装\n  3. Zygote 是否已被正确 patch",
                package
            ));
        };

        let wait = remaining.min(poll_interval);
        if let Some(hello) = notifier.recv_timeout(wait) {
            break hello;
        }
    };

    // 清理剩余的 key（handle_zymbiote_connection 已 remove 一个，清理另一个）
    unregister_spawn_request(&process_name, package, dual_key);

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
) -> Result<(i32, RawFd), String> {
    log_info!("Spawn 模式: 准备注入 {}", package);

    let hello = spawn_and_wait_hello(package)?;

    // 属性伪装: mount 在 capset hook 中完成，remap 在 setArgV0 中完成

    // 5. 注入 agent 到子进程
    let pid = hello.pid as i32;
    log_info!("正在向子进程 {} 注入 agent...", pid);
    let host_fd = match inject_via_bootstrapper(pid, string_overrides) {
        Ok(fd) => fd,
        Err(e) => {
            log_warn!("注入子进程 {} 失败，正在恢复子进程: {}", pid, e);
            let _ = resume_child(hello.pid);
            return Err(e);
        }
    };

    // 6. 不立即恢复子进程 — 由 main.rs 在脚本加载完成后调用 resume_child
    //    子进程主线程仍阻塞在 zymbiote recv(ACK)，agent 线程可独立工作

    Ok((pid, host_fd))
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
                        let uid: u32 = line.split_whitespace().nth(1)
                            .and_then(|s| s.parse().ok()).unwrap_or(u32::MAX);
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

    std::thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    std::thread::spawn(move || {
                        if let Err(e) = handle_zymbiote_connection(stream) {
                            log_verbose!("Zymbiote 连接处理错误: {}", e);
                        }
                    });
                }
                Err(e) => {
                    log_verbose!("Zymbiote accept 错误: {}", e);
                    break;
                }
            }
        }
    });

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
    // 先精确匹配，再前缀匹配（处理 android:process 自定义进程名，如 "pkg:suffix"）
    let notifier = if let Some(requests) = SPAWN_REQUESTS.get() {
        let mut map = requests.lock().unwrap();
        if let Some(n) = map.remove(&package_name) {
            Some(n)
        } else {
            // 前缀匹配: "com.foo.bar:service" 匹配注册的 "com.foo.bar"
            let prefix_key = map
                .keys()
                .find(|k| package_name.starts_with(k.as_str()) && package_name[k.len()..].starts_with(':'))
                .cloned();
            prefix_key.and_then(|k| map.remove(&k))
        }
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

    // 还原 prctl GOT（如果有）
    if let Some((addr, backup)) = &patch.prctl_got {
        log_verbose!("还原子进程 {} capset GOT at 0x{:x}", pid, addr);
        mem.pwrite_all(backup, *addr)?;
    }

    Ok(())
}

/// 读取进程的 ppid
/// 解析应用的进程名（通过 dumpsys package）
/// 大多数应用进程名等于包名，但使用 android:process 属性的应用除外
fn resolve_process_name(package: &str) -> String {
    let output = std::process::Command::new("dumpsys")
        .args(["package", package])
        .output();

    if let Ok(output) = output {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let trimmed = line.trim();
            if let Some(name) = trimmed.strip_prefix("processName=") {
                let name = name.trim();
                if !name.is_empty() {
                    return name.to_string();
                }
            }
        }
    }

    package.to_string()
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

/// 向单个 zygote 进程注入 zymbiote
fn inject_zymbiote(pid: u32, socket_name: &str) -> Result<ZygotePatch, String> {
    let maps = parse_proc_maps(pid)?;

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
        return Err("未检测到 VM heap 候选区域（boot.art / dalvik-LinearAlloc）".to_string());
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

    // 7. 找到 setArgV0 指针（三层兜底扫描：boot heap → RW private → 全读）
    //    None: 三层全 miss，启用 setcontext-only 降级阻塞（要求 setcontext GOT 可用）
    let mut payload_data = payload_data;
    let setargv0_search = find_setargv0_pointer_in_heap(pid, &maps, setargv0_addr, Some(replacement_setargv0_addr))?;
    let already_patched = setargv0_search.as_ref().map(|(_, _, p)| *p).unwrap_or(false);

    if let Some((addr, backup, patched)) = &setargv0_search {
        log_verbose!(
            "setArgV0 指针位置: 0x{:x} (原始值 0x{:x}){}",
            addr,
            u64::from_ne_bytes(*backup),
            if *patched { " [already patched]" } else { "" }
        );
    } else {
        // 降级模式：要求 setcontext GOT 必须可用
        if !matches!(&setcontext_info, Some((_, Some(_)))) {
            return Err(
                "boot heap / RW private / 全读映射均未命中 setArgV0 指针，\
                 且 setcontext GOT 不可用 — 无法建立阻塞点，目标 Android 版本可能不兼容。"
                    .to_string(),
            );
        }
        log_warn!("降级为 setcontext-only 阻塞（Android 版本兼容路径）");
        let flag_offset = ctx_base_in_payload + CTX_BLOCK_IN_SETCONTEXT - CTX_SOCKET_PATH;
        if flag_offset + 8 > payload_data.len() {
            return Err(format!(
                "block_in_setcontext 偏移越界: {} + 8 > {}",
                flag_offset,
                payload_data.len()
            ));
        }
        payload_data[flag_offset..flag_offset + 8].copy_from_slice(&1u64.to_ne_bytes());
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

    // 备份原始数据
    // 与 Frida 一致：already-patched 时从 backing 文件读取真正的原始数据（COW 场景）
    let payload_backup = if already_patched {
        read_backing_file_data(&loc.path, loc.file_offset, payload_data.len())?
    } else {
        let mut buf = vec![0u8; payload_data.len()];
        mem.pread_exact(&mut buf, loc.base)?;
        buf
    };

    // 写入 payload
    mem.pwrite_all(&payload_data, loc.base)?;
    log_verbose!("Payload 写入完成");

    // 10. 替换 setArgV0 指针 → zymbiote replacement（Some 时）
    let setargv0_slot = if let Some((addr, backup, _)) = setargv0_search {
        mem.pwrite_all(&replacement_setargv0_addr.to_ne_bytes(), addr)?;
        log_verbose!(
            "setArgV0 指针已替换: 0x{:x} → 0x{:x}",
            u64::from_ne_bytes(backup),
            replacement_setargv0_addr
        );
        Some((addr, backup))
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
    let prctl_got = if PROP_PROFILE_DIR.get().and_then(|v| v.as_ref()).is_some() {
        let got = find_got_entry_for_import(&maps, "libandroid_runtime.so", "capset");
        if let Some(got) = got {
            let backup = if already_patched {
                libc_funcs.prctl.to_ne_bytes()
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
        prctl_got,
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
    prot: u64,
    path: String,     // 映射的backing文件路径（用于 COW 还原）
    file_offset: u64, // backing文件中的偏移
}

/// 找到 payload 写入位置：libstagefright.so 的 R+X 段末尾页
/// 与 Frida 一致：取第一个匹配的 libstagefright.so R+X 段
fn find_payload_location(maps: &[MapEntry]) -> Result<PayloadLocation, String> {
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;

    // 查找 libstagefright.so 的第一个 r-x 段（与 Frida payload_base == 0 guard 一致）
    for entry in maps {
        if entry.path.ends_with("/libstagefright.so") && entry.is_readable() && entry.is_executable() {
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
                prot,
                path: entry.path.clone(),
                file_offset,
            });
        }
    }

    Err("未找到 libstagefright.so 的 R+X 段，无法写入 payload".to_string())
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
    prctl: u64,
}

/// 解析 libc.so 获取所需函数地址
fn resolve_libc_functions(maps: &[MapEntry]) -> Result<LibcFunctions, String> {
    // 找到 libc.so 在目标进程中的基址和路径
    // 取所有 libc.so 映射中 start 最小的作为基址（与 Frida find_module_by_path 一致）
    let (libc_base, libc_path) = maps
        .iter()
        .filter(|e| e.path.ends_with("/libc.so"))
        .min_by_key(|e| e.start)
        .map(|e| (e.start, e.path.clone()))
        .ok_or_else(|| "未找到 libc.so".to_string())?;

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
        prctl: resolve("prctl")?,
    })
}

/// 在 maps 中找到指定 SO 的导出符号地址
fn find_export_in_maps(maps: &[MapEntry], so_name: &str, symbol_name: &str) -> Result<u64, String> {
    let suffix = format!("/{}", so_name);
    let (base, path) = maps
        .iter()
        .find(|e| e.path.ends_with(&suffix) && e.offset == 0)
        .map(|e| (e.start, e.path.clone()))
        .ok_or_else(|| format!("未找到 {}", so_name))?;

    let elf_data = std::fs::read(&path).map_err(|e| format!("读取 {} 失败: {}", path, e))?;
    let elf = goblin::elf::Elf::parse(&elf_data).map_err(|e| format!("解析 {} 失败: {}", so_name, e))?;

    find_dynsym_addr(&elf, symbol_name, base).ok_or_else(|| format!("{} 中未找到 {}", so_name, symbol_name))
}

/// 查找 selinux_android_setcontext 的地址和 GOT slot
/// 返回 Some((函数地址, Option<GOT地址>))
fn find_setcontext_info(maps: &[MapEntry]) -> Option<(u64, Option<u64>)> {
    // 先找 libselinux.so 中的导出
    let selinux_entry = maps
        .iter()
        .find(|e| e.path.ends_with("/libselinux.so") && e.offset == 0);

    let func_addr = if let Some(entry) = selinux_entry {
        let path = &entry.path;
        let base = entry.start;

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
    let entry = maps.iter().find(|e| e.path.ends_with(&suffix) && e.offset == 0)?;
    let base = entry.start;
    let path = &entry.path;

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

/// 在 boot heap 中搜索 setArgV0 函数指针
/// 与 Frida 一致：同时搜索原始指针和已被替换的指针（already-patched 检测）。
/// 如果发现 boot heap 中指针已被替换（如另一个 rustFrida 实例），仍能正确定位 slot。
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
            let size = (entry.end - entry.start) as usize;
            let mut buf = vec![0u8; size];

            if mem.pread_exact(&mut buf, entry.start).is_err() {
                continue;
            }

            // 搜索 original needle（指针 8 字节对齐）
            for offset in (0..buf.len().saturating_sub(7)).step_by(8) {
                if buf[offset..offset + 8] == original_needle {
                    let addr = entry.start + offset as u64;
                    let mut backup = [0u8; 8];
                    backup.copy_from_slice(&original_needle);
                    matches.push((addr, backup, false, entry.path.clone(), entry.is_executable()));
                }
            }

            // 搜索 replaced needle（already-patched 检测）
            if let Some(ref replaced) = replaced_needle {
                for offset in (0..buf.len().saturating_sub(7)).step_by(8) {
                    if buf[offset..offset + 8] == *replaced {
                        let addr = entry.start + offset as u64;
                        let mut backup = [0u8; 8];
                        backup.copy_from_slice(&original_needle);
                        matches.push((addr, backup, true, entry.path.clone(), entry.is_executable()));
                    }
                }
            }
        }

        if matches.is_empty() {
            return Ok(None);
        }

        matches.sort_by_key(|(addr, _, _, _, _)| *addr);
        matches.dedup_by_key(|(addr, _, _, _, _)| *addr);

        if matches.len() > 1 {
            let runtime_matches: Vec<_> = matches
                .iter()
                .filter(|(_, _, _, path, _)| path.ends_with("/libandroid_runtime.so"))
                .cloned()
                .collect();
            if runtime_matches.len() == 1 {
                let (addr, backup, already_patched, _, _) = runtime_matches[0].clone();
                log_warn!(
                    "多个 setArgV0 候选中优先选择 libandroid_runtime.so 内的 slot: 0x{:x}",
                    addr
                );
                return Ok(Some((addr, backup, already_patched)));
            }

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

    // 搜索候选区域：boot.art / boot-framework.art / dalvik-LinearAlloc（R+W 非 X 非 shared）
    // 与 Frida is_boot_heap() 一致
    let preferred: Vec<&MapEntry> = maps.iter().filter(|e| is_boot_heap(e)).collect();
    log_verbose!("搜索 {} 个 boot heap 区域查找 setArgV0 指针", preferred.len());
    if let Some(found) = search_candidates(&preferred)? {
        return Ok(Some(found));
    }

    // Android 16 / 新版本 ART 上，slot 可能不再落在传统 boot heap/LinearAlloc 区域。
    // 回退到所有 RW private 映射，并要求唯一命中，避免误改。
    let fallback: Vec<&MapEntry> = maps
        .iter()
        .filter(|e| is_private_rw_mapping(e))
        .filter(|e| !is_boot_heap(e))
        .collect();
    log_warn!(
        "boot heap 中未命中 setArgV0 指针，回退扫描 {} 个 RW private 区域",
        fallback.len()
    );
    if let Some(found) = search_candidates(&fallback)? {
        return Ok(Some(found));
    }

    // 再退一层：某些新系统可能把 slot 放在只读或 shared 映射中。
    // 这里扩大到所有可读映射，但仍要求唯一命中。
    let final_fallback: Vec<&MapEntry> = maps
        .iter()
        .filter(|e| is_readable_mapping(e))
        .filter(|e| !is_private_rw_mapping(e))
        .collect();
    log_warn!(
        "RW private 区域未命中 setArgV0 指针，继续扫描 {} 个其余可读区域",
        final_fallback.len()
    );
    if let Some(found) = search_candidates(&final_fallback)? {
        return Ok(Some(found));
    }

    // 所有层均未命中：返回 None，上层降级为 setcontext GOT 阻塞（最后的兼容路径）
    log_warn!(
        "未在 boot heap、RW private 或其余可读区域中找到 setArgV0 指针 (0x{:x})，切换降级模式",
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
    log_verbose!("ZymbioteContext: ctx_base=0x{:x}, payload_len=0x{:x}", ctx_base, payload.len());

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
    let prop_remap = if PROP_PROFILE_DIR.get().and_then(|v| v.as_ref()).is_some() { 1u64 } else { 0u64 };
    log_verbose!("build_payload: prop_remap={} (PROP_PROFILE_DIR={:?})", prop_remap, PROP_PROFILE_DIR.get());
    write_u64(ctx, CTX_PROP_REMAP - CTX_SOCKET_PATH, prop_remap);
    // block_in_setcontext 默认 0，由调用者在三层 slot 全部 miss 时 flip 为 1
    write_u64(ctx, CTX_BLOCK_IN_SETCONTEXT - CTX_SOCKET_PATH, 0);
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

/// 恢复所有挂起的子进程连接（发 ACK → 等 EOF → 等 SIGSTOP → 还原 → SIGCONT）
/// 与 Frida close() 一致：退出前先恢复所有 gated connections，防止子进程永远卡在 recv(ACK)
fn cleanup_pending_connections() {
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

    log_info!("正在恢复 {} 个挂起的子进程...", entries.len());

    for (pid, (mut stream, ppid)) in entries {
        log_verbose!("恢复挂起的子进程 {} (ppid={})...", pid, ppid);

        // 检查子进程是否仍存在
        if !std::path::Path::new(&format!("/proc/{}", pid)).exists() {
            log_verbose!("子进程 {} 已不存在，跳过恢复", pid);
            drop(stream);
            continue;
        }

        // 1. 发送 ACK 解除子进程阻塞
        if stream.write_all(&[ACK_BYTE]).is_err() {
            // 连接已断开，子进程可能已退出，仍尝试 SIGCONT
            unsafe { libc::kill(pid as i32, libc::SIGCONT) };
            continue;
        }

        // 2. 等待子进程关闭 socket（收到 ACK 后 close(fd)）
        drain_until_eof(&mut stream, std::time::Duration::from_secs(2));
        drop(stream);

        // 3. 等待子进程 raise(SIGSTOP)，然后还原 patch 并恢复
        if wait_until_stopped(pid).is_ok() {
            let _ = revert_child_patch_by_ppid(pid, ppid);
        }
        unsafe { libc::kill(pid as i32, libc::SIGCONT) };
    }
}

/// 退出时还原所有 Zygote patch（幂等：多次调用只执行一次）
/// 与 Frida close() 顺序一致：先恢复挂起的子进程，再还原 Zygote patch
pub(crate) fn cleanup_zygote_patches() {
    CLEANUP_STARTED.store(true, Ordering::SeqCst);

    // 幂等保护：所有调用路径（正常退出 + 信号处理）共享此检查
    if CLEANUP_DONE.swap(true, Ordering::SeqCst) {
        return;
    }

    // 1. 先恢复所有挂起的子进程连接（与 Frida close() 顺序一致）
    //    必须在还原 Zygote 之前执行：子进程持有 COW 副本，需要独立还原
    cleanup_pending_connections();

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

                // 还原 prctl GOT
                if let Some((addr, backup)) = &patch.prctl_got {
                    if let Err(e) = mem.pwrite_all(backup, *addr) {
                        log_error!("还原 zygote {} prctl GOT 失败: {}", patch.pid, e);
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
