#![cfg(all(target_os = "android", target_arch = "aarch64"))]

use libc::{c_void, close};
use nix::errno::Errno;
use nix::sys::ptrace;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;
use std::mem::size_of;
use std::os::unix::io::RawFd;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

use crate::proc_mem::ProcMem;
use crate::process::{attach_to_process, call_target_function};
use crate::types::{bootstrap_status, message_type, FridaBootstrapContext, FridaLibcApi, RustFridaLoaderContext};
use crate::{log_error, log_info, log_success, log_verbose, log_warn};

pub(crate) const BOOTSTRAPPER: &[u8] = include_bytes!("../../loader/build/bootstrapper.bin");
pub(crate) const FRIDA_LOADER: &[u8] = include_bytes!("../../loader/build/rustfrida-loader.bin");

#[cfg(debug_assertions)]
pub(crate) const AGENT_SO: &[u8] = include_bytes!("../../target/aarch64-linux-android/debug/libagent.so");

#[cfg(not(debug_assertions))]
pub(crate) const AGENT_SO: &[u8] = include_bytes!("../../target/aarch64-linux-android/release/libagent.so");

#[cfg(feature = "qbdi")]
pub(crate) const QBDI_HELPER_SO: &[u8] = include_bytes!(env!("QBDI_HELPER_SO_PATH"));

// aarch64 syscall numbers
const SYS_PIDFD_OPEN: i64 = 434;
const SYS_PIDFD_GETFD: i64 = 438;
const PAGE_SIZE: u64 = 4096;
const LOADER_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const LOADER_IO_POLL_INTERVAL: Duration = Duration::from_millis(20);

fn align_down(value: u64, alignment: u64) -> u64 {
    value & !(alignment - 1)
}

fn align_up(value: u64, alignment: u64) -> u64 {
    (value + alignment - 1) & !(alignment - 1)
}

fn padded_agent_memfd_len() -> Result<usize, String> {
    let elf = goblin::elf::Elf::parse(AGENT_SO).map_err(|e| format!("解析 agent ELF 失败: {}", e))?;
    let mut len = AGENT_SO.len() as u64;

    for phdr in elf
        .program_headers
        .iter()
        .filter(|phdr| phdr.p_type == goblin::elf::program_header::PT_LOAD && phdr.p_memsz != 0)
    {
        let seg_start = align_down(phdr.p_vaddr, PAGE_SIZE);
        let seg_end = align_up(phdr.p_vaddr + phdr.p_memsz, PAGE_SIZE);
        let file_page_start = align_down(phdr.p_offset, PAGE_SIZE);
        let required = file_page_start + (seg_end - seg_start);
        len = len.max(required);
    }

    usize::try_from(len).map_err(|_| "agent padded memfd 长度溢出".to_string())
}

fn mem_write_value<T>(mem: &ProcMem, addr: usize, value: &T) -> Result<(), String> {
    let bytes = unsafe { std::slice::from_raw_parts(value as *const T as *const u8, size_of::<T>()) };
    mem.pwrite_all(bytes, addr as u64)
}

fn mem_read_value<T: Default>(mem: &ProcMem, addr: usize) -> Result<T, String> {
    let mut value = T::default();
    let bytes = unsafe { std::slice::from_raw_parts_mut(&mut value as *mut T as *mut u8, size_of::<T>()) };
    mem.pread_exact(bytes, addr as u64)?;
    Ok(value)
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct InjectionResult {
    pub(crate) host_fd: RawFd,
    pub(crate) target_pid: i32,
    pub(crate) loader_ctx_addr: u64,
    pub(crate) agent_current_thread_eval_impl: u64,
    pub(crate) loader_alloc_base: u64,
    pub(crate) loader_alloc_size: u64,
    pub(crate) loader_stack: u64,
    pub(crate) loader_stack_size: u64,
    pub(crate) libc_munmap: u64,
}

/// 通过 pidfd_getfd 从目标进程提取文件描述符到 host
fn extract_fd_from_target(pid: i32, target_fd: i32) -> Result<RawFd, String> {
    // pidfd_open(pid, flags=0)
    let pidfd = unsafe { libc::syscall(SYS_PIDFD_OPEN, pid, 0) };
    if pidfd < 0 {
        return Err(format!("pidfd_open({}) 失败: {}", pid, std::io::Error::last_os_error()));
    }

    // pidfd_getfd(pidfd, target_fd, flags=0)
    let host_fd = unsafe { libc::syscall(SYS_PIDFD_GETFD, pidfd as i32, target_fd, 0u32) };
    unsafe { close(pidfd as i32) };

    if host_fd < 0 {
        return Err(format!(
            "pidfd_getfd(pid={}, fd={}) 失败: {}",
            pid,
            target_fd,
            std::io::Error::last_os_error()
        ));
    }

    log_verbose!("pidfd_getfd: pid={} target_fd={} → host_fd={}", pid, target_fd, host_fd);
    Ok(host_fd as RawFd)
}

/// 设置 fd 的 SELinux label，使 untrusted_app 能通过 SCM_RIGHTS 接收。
///
/// Android MLS/MCS 会阻止 untrusted_app (带 categories) 访问 tmpfs:s0 (无 categories)。
/// 修复：读取目标进程的 SELinux context 提取 MLS range（如 s0:c15,c257,c512,c768），
/// 用目标的 MLS categories + tmpfs 类型标记 memfd。
///
/// 注意：不使用 frida_memfd 类型——即使该类型存在（Frida 残留），其 MLS range
/// 定义可能不完整，导致 fsetxattr 返回 0 但 kernel 无法验证 context、退回 unlabeled:s0。
/// tmpfs 是原生类型，天然支持所有 MLS ranges，且 selinux.rs 已有 TE allow 规则。
fn relabel_fd_for_injection(fd: RawFd, target_pid: i32) {
    // 读取目标进程的 MLS range
    let mls = read_target_mls_range(target_pid).unwrap_or_else(|| "s0".to_string());

    // tmpfs 优先（memfd 底层就是 tmpfs），然后 app_data_file
    let labels = [
        format!("u:object_r:tmpfs:{}", mls),
        format!("u:object_r:app_data_file:{}", mls),
    ];
    for label in &labels {
        let label_cstr = format!("{}\0", label);
        let ret = unsafe {
            libc::fsetxattr(
                fd,
                b"security.selinux\0".as_ptr() as *const libc::c_char,
                label_cstr.as_ptr() as *const c_void,
                label_cstr.len() - 1, // 不包含 NUL
                0,
            )
        };
        if ret == 0 {
            // 验证 label 是否真正生效（防止 fsetxattr 假成功、kernel 退回 unlabeled）
            let mut readback = [0u8; 128];
            let n = unsafe {
                libc::fgetxattr(
                    fd,
                    b"security.selinux\0".as_ptr() as *const libc::c_char,
                    readback.as_mut_ptr() as *mut c_void,
                    readback.len(),
                )
            };
            if n > 0 {
                let actual = std::str::from_utf8(&readback[..n as usize])
                    .unwrap_or("")
                    .trim_end_matches('\0');
                if actual.contains("unlabeled") {
                    log_verbose!("memfd SELinux label {} → kernel 退回 unlabeled，尝试下一个", label);
                    continue;
                }
            }
            log_verbose!("memfd SELinux label → {}", label);
            return;
        }
    }
    log_verbose!("memfd SELinux relabel 全部失败，使用默认 tmpfs label");
}

/// 读取目标进程的 SELinux MLS range（例如 "s0:c15,c257,c512,c768"）
fn read_target_mls_range(pid: i32) -> Option<String> {
    let ctx = std::fs::read_to_string(format!("/proc/{}/attr/current", pid)).ok()?;
    let ctx = ctx.trim_end_matches('\0').trim();
    // 格式: u:r:untrusted_app:s0:c15,c257,c512,c768
    // MLS range 从第 4 个 ':' 分隔的字段开始（可能包含多个 ':'）
    let mut parts = ctx.splitn(4, ':');
    let _user = parts.next()?;
    let _role = parts.next()?;
    let _type = parts.next()?;
    let mls = parts.next()?;
    if mls.is_empty() {
        return None;
    }
    Some(mls.to_string())
}

/// 根据 UID 查找 /data/data/ 目录下对应的应用数据目录
fn find_data_dir_by_uid(uid: u32) -> Option<String> {
    use std::fs;
    use std::os::unix::fs::MetadataExt;

    let data_dir = "/data/data";

    match fs::read_dir(data_dir) {
        Ok(entries) => {
            for entry in entries.flatten() {
                if let Ok(metadata) = entry.metadata() {
                    if metadata.uid() == uid {
                        if let Some(path) = entry.path().to_str() {
                            return Some(path.to_string());
                        }
                    }
                }
            }
            None
        }
        Err(e) => {
            log_error!("读取 /data/data 目录失败: {}", e);
            None
        }
    }
}

/// 使用 eBPF 监听 SO 加载并自动附加
#[cfg(feature = "ldmonitor")]
pub(crate) fn watch_and_inject(
    so_pattern: &str,
    timeout_secs: Option<u64>,
    string_overrides: &std::collections::HashMap<String, String>,
) -> Result<InjectionResult, String> {
    use ldmonitor::DlopenMonitor;
    use std::time::Duration;

    log_info!("正在启动 eBPF 监听器，等待加载: {}", so_pattern);

    let monitor = DlopenMonitor::new(None).map_err(|e| format!("启动 eBPF 监听失败: {}", e))?;

    let info = if let Some(secs) = timeout_secs {
        log_info!("超时时间: {} 秒", secs);
        monitor.wait_for_path_timeout(so_pattern, Duration::from_secs(secs))
    } else {
        log_info!("无超时限制，持续监听中...");
        monitor.wait_for_path(so_pattern)
    };

    monitor.stop();

    match info {
        Some(dlopen_info) => {
            let pid = dlopen_info.pid();
            if let Some(ns_pid) = dlopen_info.ns_pid {
                if ns_pid != dlopen_info.host_pid {
                    log_success!(
                        "检测到 SO 加载: pid={} (host_pid={}), uid={}, path={}",
                        ns_pid,
                        dlopen_info.host_pid,
                        dlopen_info.uid,
                        dlopen_info.path
                    );
                } else {
                    log_success!(
                        "检测到 SO 加载: pid={}, uid={}, path={}",
                        pid,
                        dlopen_info.uid,
                        dlopen_info.path
                    );
                }
            } else {
                log_success!(
                    "检测到 SO 加载: host_pid={}, uid={}, path={}",
                    dlopen_info.host_pid,
                    dlopen_info.uid,
                    dlopen_info.path
                );
            }

            // 克隆 string_overrides 以便修改
            let mut overrides = string_overrides.clone();

            // 根据 uid 自动检测 /data/data/ 目录
            if let Some(data_dir) = find_data_dir_by_uid(dlopen_info.uid) {
                log_info!("自动检测到应用数据目录: {}", data_dir);
                overrides.insert("output_path".to_string(), data_dir);
            } else {
                log_warn!("未能找到 uid {} 对应的 /data/data/ 目录", dlopen_info.uid);
            }

            inject_via_bootstrapper(pid as i32, &overrides)
        }
        None => Err("监听超时，未检测到匹配的 SO 加载".to_string()),
    }
}

// =============================================================================
// Frida-style 注入：bootstrapper + loader 两阶段
// =============================================================================

/// 在目标进程中找到一个足够大的 r-xp 区域用于 code-swap
/// 优先选择 linker64（所有 Android 进程都有），避免覆盖 libc 的热代码
fn find_executable_region(pid: i32, min_size: usize) -> Result<usize, String> {
    let maps_path = format!("/proc/{}/maps", pid);
    let raw = std::fs::read(&maps_path).map_err(|e| format!("读取 {} 失败: {}", maps_path, e))?;
    let maps = String::from_utf8_lossy(&raw);

    // 优先找 linker64 的 r-xp 段
    for line in maps.lines() {
        if !line.contains("r-xp") {
            continue;
        }
        if !line.contains("linker64") {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if let Some(range) = parts.first() {
            let mut it = range.split('-');
            if let (Some(start_s), Some(end_s)) = (it.next(), it.next()) {
                let start = usize::from_str_radix(start_s, 16).unwrap_or(0);
                let end = usize::from_str_radix(end_s, 16).unwrap_or(0);
                if end - start >= min_size {
                    return Ok(start);
                }
            }
        }
    }

    // fallback: 任何足够大的 r-xp 区域
    for line in maps.lines() {
        if !line.contains("r-xp") {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if let Some(range) = parts.first() {
            let mut it = range.split('-');
            if let (Some(start_s), Some(end_s)) = (it.next(), it.next()) {
                let start = usize::from_str_radix(start_s, 16).unwrap_or(0);
                let end = usize::from_str_radix(end_s, 16).unwrap_or(0);
                if end - start >= min_size {
                    return Ok(start);
                }
            }
        }
    }

    Err("未找到可用的 r-xp 区域".into())
}

pub(crate) fn choose_injection_thread(pid: i32) -> i32 {
    crate::process::thaw_cgroup_freezer(pid);
    let mut fallback = pid;
    for _ in 0..20 {
        let (tid, score) = choose_injection_thread_once(pid);
        fallback = tid;
        if tid != pid && score >= 0 {
            log_injection_thread_candidate(pid, tid);
            return tid;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    if fallback != pid {
        log_injection_thread_candidate(pid, fallback);
    }
    fallback
}

fn choose_injection_thread_once(pid: i32) -> (i32, i32) {
    let task_dir = format!("/proc/{}/task", pid);
    let mut best_tid = pid;
    let mut best_score = i32::MIN;

    let entries = match std::fs::read_dir(task_dir) {
        Ok(entries) => entries,
        Err(_) => return (pid, i32::MIN),
    };

    for entry in entries.flatten() {
        let tid = match entry.file_name().to_str().and_then(|s| s.parse::<i32>().ok()) {
            Some(tid) => tid,
            None => continue,
        };

        let status = std::fs::read_to_string(format!("/proc/{}/task/{}/status", pid, tid)).unwrap_or_default();
        let comm = std::fs::read_to_string(format!("/proc/{}/task/{}/comm", pid, tid)).unwrap_or_default();
        let wchan = std::fs::read_to_string(format!("/proc/{}/task/{}/wchan", pid, tid)).unwrap_or_default();

        let mut score = 0;
        if tid == pid {
            score -= 1000;
        }
        if status.contains("State:\tS") {
            score += 100;
        } else if status.contains("State:\tR") {
            score -= 400;
        }
        if wchan.contains("freezer") {
            score -= 1200;
        } else if wchan.trim() == "0" {
            score -= 600;
        } else if wchan.contains("epoll") {
            score += 80;
        } else if wchan.contains("futex") || wchan.contains("poll") {
            score += 80;
        }
        if comm.contains("LigIO")
            || comm.contains("LightHTing")
            || comm.contains("AsyncHTing")
            || comm.contains("soul_im")
            || comm.contains("RxCached")
            || comm.contains("FinalizerWatchd")
        {
            score += 120;
        }
        if comm.contains("Signal Catcher")
            || comm.contains("ADB-JDWP")
            || comm.contains("perfetto")
            || comm.contains("binder:")
            || comm.contains("crash")
            || comm.contains("npth")
            || comm.contains("process reaper")
            || comm.contains("Jit thread")
            || comm.contains("RenderThread")
            || comm.contains("HeapTaskDaemon")
            || comm.contains("FinalizerDaemon")
            || comm.contains("ReferenceQueue")
        {
            score -= 200;
        }

        if score > best_score {
            best_score = score;
            best_tid = tid;
        }
    }

    (best_tid, best_score)
}

fn log_injection_thread_candidate(pid: i32, tid: i32) {
    let comm = std::fs::read_to_string(format!("/proc/{}/task/{}/comm", pid, tid))
        .unwrap_or_default()
        .trim()
        .to_string();
    let wchan = std::fs::read_to_string(format!("/proc/{}/task/{}/wchan", pid, tid))
        .unwrap_or_default()
        .trim()
        .to_string();
    log_verbose!("注入线程候选: tid={} comm={} wchan={}", tid, comm, wchan);
}

pub(crate) fn choose_java_eval_thread(pid: i32) -> i32 {
    let task_dir = format!("/proc/{}/task", pid);
    let mut best_tid = pid;
    let mut best_score = i32::MIN;

    let entries = match std::fs::read_dir(task_dir) {
        Ok(entries) => entries,
        Err(_) => return pid,
    };

    for entry in entries.flatten() {
        let tid = match entry.file_name().to_str().and_then(|s| s.parse::<i32>().ok()) {
            Some(tid) => tid,
            None => continue,
        };

        let status = std::fs::read_to_string(format!("/proc/{}/task/{}/status", pid, tid)).unwrap_or_default();
        let comm = std::fs::read_to_string(format!("/proc/{}/task/{}/comm", pid, tid)).unwrap_or_default();
        let wchan = std::fs::read_to_string(format!("/proc/{}/task/{}/wchan", pid, tid)).unwrap_or_default();
        let comm_trimmed = comm.trim();
        let comm_lower = comm_trimmed.to_ascii_lowercase();
        let wchan_lower = wchan.to_ascii_lowercase();

        let mut score = 0;

        if tid == pid {
            score += 2000;
        }
        if status.contains("State:\tS") {
            score += 120;
        } else if status.contains("State:\tR") {
            score += 40;
        }
        if wchan_lower.contains("epoll") || wchan_lower.contains("poll") {
            score += 80;
        } else if wchan_lower.contains("futex") {
            score += 30;
        }
        if comm_lower.contains("main") || comm_lower.contains("ui") {
            score += 100;
        }

        let bad_java_eval_thread = comm_lower.contains("signal catcher")
            || comm_lower.contains("adb-jdwp")
            || comm_lower.contains("perfetto")
            || comm_lower.contains("binder:")
            || comm_lower.contains("crash")
            || comm_lower.contains("sentry")
            || comm_lower.contains("npth")
            || comm_lower.contains("process reaper")
            || comm_lower.contains("jit thread")
            || comm_lower.contains("renderthread")
            || comm_lower.contains("heaptaskdaemon")
            || comm_lower.contains("finalizer")
            || comm_lower.contains("referencequeue")
            || comm_lower.contains("rxcached")
            || comm_lower.contains("rxcomputation")
            || comm_lower.contains("rxscheduler")
            || comm_lower.contains("okhttp")
            || comm_lower.contains("okio")
            || comm_lower.contains("pool-")
            || comm_lower.contains("threadpool")
            || comm_lower.starts_with("thread-")
            || comm_lower.contains("chromium")
            || comm_lower.contains("cronet")
            || comm_lower.contains("mali-")
            || comm_lower.contains("hwuitask")
            || comm_lower.contains("audio")
            || comm_lower.contains("profile saver");
        if bad_java_eval_thread {
            score -= 600;
        }

        if score > best_score {
            best_score = score;
            best_tid = tid;
        }
    }

    let comm = std::fs::read_to_string(format!("/proc/{}/task/{}/comm", pid, best_tid))
        .unwrap_or_default()
        .trim()
        .to_string();
    let wchan = std::fs::read_to_string(format!("/proc/{}/task/{}/wchan", pid, best_tid))
        .unwrap_or_default()
        .trim()
        .to_string();
    log_verbose!(
        "Java remote eval 线程候选: tid={} comm={} wchan={}",
        best_tid,
        comm,
        wchan
    );

    best_tid
}

struct StopWorldSession {
    tids: Vec<i32>,
    active: bool,
}

impl StopWorldSession {
    fn new(selected_tid: i32) -> Self {
        Self {
            tids: vec![selected_tid],
            active: true,
        }
    }

    fn attach_siblings(&mut self, pid: i32, selected_tid: i32) -> Result<(), String> {
        let mut attached_count = 0usize;

        for _ in 0..3 {
            let entries = match std::fs::read_dir(format!("/proc/{}/task", pid)) {
                Ok(entries) => entries,
                Err(e) => return Err(format!("读取线程列表失败: {}", e)),
            };
            let mut changed = false;

            for entry in entries.flatten() {
                let tid = match entry.file_name().to_str().and_then(|s| s.parse::<i32>().ok()) {
                    Some(tid) => tid,
                    None => continue,
                };
                if tid == selected_tid || self.tids.contains(&tid) {
                    continue;
                }

                let target = Pid::from_raw(tid);
                match ptrace::attach(target) {
                    Ok(()) => {}
                    Err(Errno::ESRCH) => continue,
                    Err(e) => return Err(format!("暂停线程 {} 失败: {}", tid, e)),
                }

                match waitpid(target, None) {
                    Ok(WaitStatus::Stopped(_, _)) => {
                        self.tids.push(tid);
                        attached_count += 1;
                        changed = true;
                    }
                    Ok(WaitStatus::Exited(_, code)) => {
                        log_verbose!("stop-the-world: 线程 {} attach 期间已退出(code={})，跳过", tid, code);
                    }
                    Ok(WaitStatus::Signaled(_, signal, _)) => {
                        log_verbose!("stop-the-world: 线程 {} attach 期间被信号 {:?} 结束，跳过", tid, signal);
                    }
                    Ok(status) => {
                        let _ = ptrace::detach(target, None);
                        return Err(format!("暂停线程 {} 状态异常: {:?}", tid, status));
                    }
                    Err(Errno::ECHILD) | Err(Errno::ESRCH) => {
                        let _ = ptrace::detach(target, None);
                    }
                    Err(e) => {
                        let _ = ptrace::detach(target, None);
                        return Err(format!("等待线程 {} 停止失败: {}", tid, e));
                    }
                }
            }

            if !changed {
                break;
            }
        }

        log_verbose!("stop-the-world: 已暂停 {} 个其他线程", attached_count);
        Ok(())
    }

    fn detach_all(&mut self) {
        if !self.active {
            return;
        }
        for &tid in self.tids.iter().rev() {
            let _ = ptrace::detach(Pid::from_raw(tid), None);
        }
        self.active = false;
    }
}

impl Drop for StopWorldSession {
    fn drop(&mut self) {
        self.detach_all();
    }
}

/// 写入 StringTable 到预分配的内存区域（不使用 malloc）
fn write_string_table_at(
    mem: &ProcMem,
    base_addr: usize,
    overrides: &std::collections::HashMap<String, String>,
) -> Result<usize, String> {
    // 复用 types.rs 中定义的字符串列表
    let entries: Vec<(&str, Vec<u8>)> = vec![
        (
            "sym_name",
            overrides
                .get("sym_name")
                .map(|s| s.as_bytes().to_vec())
                .unwrap_or_else(|| b"hello_entry".to_vec()),
        ),
        (
            "dlsym_err",
            overrides
                .get("dlsym_err")
                .map(|s| s.as_bytes().to_vec())
                .unwrap_or_else(|| b"dlsymFail".to_vec()),
        ),
        (
            "cmdline",
            overrides
                .get("cmdline")
                .map(|s| s.as_bytes().to_vec())
                .unwrap_or_else(|| b"novalue".to_vec()),
        ),
        (
            "output_path",
            overrides
                .get("output_path")
                .map(|s| s.as_bytes().to_vec())
                .unwrap_or_else(|| b"novalue".to_vec()),
        ),
    ];

    // 每个条目: u64 (ptr) + u32 (len) + 4 bytes padding = 16 bytes
    let table_size = entries.len() * 16;
    let mut strings_data = Vec::new();
    let mut string_offsets = Vec::new();

    for (_, value) in &entries {
        let mut v = value.clone();
        v.push(0); // NULL 结尾
        string_offsets.push((strings_data.len(), v.len()));
        strings_data.extend_from_slice(&v);
    }

    let table_addr = base_addr;
    let strings_base = base_addr + table_size;

    // 构建 StringTable 二进制数据
    let mut table_data = Vec::with_capacity(table_size);
    for (offset, len) in &string_offsets {
        let ptr = (strings_base + offset) as u64;
        table_data.extend_from_slice(&ptr.to_le_bytes()); // u64 ptr
        table_data.extend_from_slice(&(*len as u32).to_le_bytes()); // u32 len
        table_data.extend_from_slice(&[0u8; 4]); // padding
    }

    // 写入 StringTable struct
    mem.pwrite_all(&table_data, table_addr as u64)?;
    // 写入字符串数据
    mem.pwrite_all(&strings_data, strings_base as u64)?;

    Ok(table_addr)
}

struct OwnedFd {
    fd: RawFd,
}

impl OwnedFd {
    fn new(fd: RawFd) -> Self {
        Self { fd }
    }

    fn raw(&self) -> RawFd {
        self.fd
    }

    fn into_raw(mut self) -> RawFd {
        let fd = self.fd;
        self.fd = -1;
        fd
    }
}

impl Drop for OwnedFd {
    fn drop(&mut self) {
        if self.fd >= 0 {
            unsafe { close(self.fd) };
            self.fd = -1;
        }
    }
}

struct CgroupThawGuard {
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl CgroupThawGuard {
    fn start(pid: i32) -> Self {
        crate::process::thaw_cgroup_freezer(pid);
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let handle = std::thread::spawn(move || {
            while !worker_stop.load(Ordering::Acquire) {
                crate::process::thaw_cgroup_freezer(pid);
                std::thread::sleep(Duration::from_millis(100));
            }
        });
        Self {
            stop,
            handle: Some(handle),
        }
    }
}

impl Drop for CgroupThawGuard {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn read_trimmed(path: String) -> String {
    std::fs::read_to_string(path).unwrap_or_default().trim().to_string()
}

fn cgroup_freezer_state(pid: i32) -> String {
    let cgroup_path = format!("/proc/{}/cgroup", pid);
    let content = match std::fs::read_to_string(&cgroup_path) {
        Ok(content) => content,
        Err(e) => return format!("unavailable({})", e),
    };

    for line in content.lines() {
        let parts: Vec<&str> = line.splitn(3, ':').collect();
        if parts.len() != 3 {
            continue;
        }
        let cgroup_rel = parts[2].trim_start_matches('/');
        let freeze_path = format!("/sys/fs/cgroup/{}/cgroup.freeze", cgroup_rel);
        if let Ok(value) = std::fs::read_to_string(&freeze_path) {
            return format!("{}={}", freeze_path, value.trim());
        }
    }

    "none".to_string()
}

fn loader_thread_diagnostics(pid: i32, tid: i32) -> String {
    let status = std::fs::read_to_string(format!("/proc/{}/task/{}/status", pid, tid)).unwrap_or_default();
    let state = status
        .lines()
        .find_map(|line| line.strip_prefix("State:"))
        .map(|line| line.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let tracer = status
        .lines()
        .find_map(|line| line.strip_prefix("TracerPid:"))
        .map(|line| line.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let comm = read_trimmed(format!("/proc/{}/task/{}/comm", pid, tid));
    let wchan = read_trimmed(format!("/proc/{}/task/{}/wchan", pid, tid));

    format!(
        "loader_diag: tid={} comm={} state={} wchan={} tracer={} freezer={}",
        tid,
        if comm.is_empty() { "unknown" } else { &comm },
        state,
        if wchan.is_empty() { "unknown" } else { &wchan },
        tracer,
        cgroup_freezer_state(pid)
    )
}

fn loader_timeout_left(deadline: Instant, context: &str) -> Result<Duration, String> {
    deadline
        .checked_duration_since(Instant::now())
        .ok_or_else(|| format!("{} 超时({}ms)", context, LOADER_HANDSHAKE_TIMEOUT.as_millis()))
}

fn poll_loader_fd(sockfd: RawFd, events: libc::c_short, deadline: Instant, context: &str) -> Result<(), String> {
    loop {
        let left = loader_timeout_left(deadline, context)?;
        let wait = left.min(LOADER_IO_POLL_INTERVAL);
        let timeout_ms = wait.as_millis().clamp(1, i32::MAX as u128) as i32;
        let mut pfd = libc::pollfd {
            fd: sockfd,
            events,
            revents: 0,
        };
        let ret = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        if ret > 0 {
            let revents = pfd.revents;
            if (revents & events) != 0 {
                return Ok(());
            }
            if (revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL)) != 0 {
                return Err(format!("{}: ctrl socket 关闭/异常 revents=0x{:x}", context, revents));
            }
            continue;
        }
        if ret == 0 {
            continue;
        }

        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        return Err(format!("{} poll 失败: {}", context, err));
    }
}

/// Unix socket fd-passing: 通过 SCM_RIGHTS 发送 fd
fn send_fd_timeout(sockfd: RawFd, fd_to_send: RawFd, deadline: Instant, context: &str) -> Result<(), String> {
    use std::io::IoSlice;

    let dummy = [0u8; 1];
    let iov = [IoSlice::new(&dummy)];

    let mut cmsg_buf = vec![0u8; unsafe { libc::CMSG_SPACE(size_of::<i32>() as u32) } as usize];

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = iov.as_ptr() as *mut libc::iovec;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut c_void;
    msg.msg_controllen = cmsg_buf.len();

    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    unsafe {
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(size_of::<i32>() as u32) as usize;
        std::ptr::copy_nonoverlapping(&fd_to_send as *const i32, libc::CMSG_DATA(cmsg) as *mut i32, 1);
    }

    loop {
        poll_loader_fd(sockfd, libc::POLLOUT, deadline, context)?;
        let ret = unsafe { libc::sendmsg(sockfd, &msg, libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT) };
        if ret > 0 {
            return Ok(());
        }
        if ret == 0 {
            return Err(format!("{}: sendmsg(SCM_RIGHTS) 写入 0 字节", context));
        }

        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::EINTR) | Some(libc::EAGAIN) => continue,
            _ => return Err(format!("{}: sendmsg(SCM_RIGHTS) 失败: {}", context, err)),
        }
    }
}

/// 从 ctrl socket 读取指定字节数
fn recv_exact_timeout(sockfd: RawFd, buf: &mut [u8], deadline: Instant, context: &str) -> Result<(), String> {
    let mut done = 0;
    while done < buf.len() {
        poll_loader_fd(sockfd, libc::POLLIN, deadline, context)?;
        let n = unsafe {
            libc::recv(
                sockfd,
                buf[done..].as_mut_ptr() as *mut c_void,
                buf.len() - done,
                libc::MSG_DONTWAIT,
            )
        };
        if n > 0 {
            done += n as usize;
            continue;
        }
        if n == 0 {
            return Err(format!("{}: ctrl socket EOF (done={}/{})", context, done, buf.len()));
        }

        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::EINTR) | Some(libc::EAGAIN) => continue,
            _ => return Err(format!("{}: recv 失败: {} (done={}/{})", context, err, done, buf.len())),
        }
    }
    Ok(())
}

/// 向 ctrl socket 写入数据
fn send_exact_timeout(sockfd: RawFd, buf: &[u8], deadline: Instant, context: &str) -> Result<(), String> {
    let mut done = 0;
    while done < buf.len() {
        poll_loader_fd(sockfd, libc::POLLOUT, deadline, context)?;
        let n = unsafe {
            libc::send(
                sockfd,
                buf[done..].as_ptr() as *const c_void,
                buf.len() - done,
                libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
            )
        };
        if n > 0 {
            done += n as usize;
            continue;
        }
        if n == 0 {
            return Err(format!("{}: send 写入 0 字节", context));
        }

        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::EINTR) | Some(libc::EAGAIN) => continue,
            _ => return Err(format!("{}: send 失败: {}", context, err)),
        }
    }
    Ok(())
}

/// Host 端执行 loader IPC 握手协议
/// 返回 REPL 用的 host_fd
fn run_loader_handshake(
    ctrl_fd: RawFd,
    target_pid: i32,
    loader_ctx_addr: usize,
    loader_alloc_base: usize,
    loader_alloc_size: usize,
    libc_munmap: u64,
) -> Result<InjectionResult, String> {
    let deadline = Instant::now() + LOADER_HANDSHAKE_TIMEOUT;
    let _thaw_guard = CgroupThawGuard::start(target_pid);

    // 1. 接收 HELLO 消息: [type:u8][thread_id:i32]
    let mut msg_type = [0u8; 1];
    recv_exact_timeout(ctrl_fd, &mut msg_type, deadline, "等待 loader HELLO")?;
    if msg_type[0] != message_type::HELLO {
        return Err(format!("期望 HELLO({}), 收到 {}", message_type::HELLO, msg_type[0]));
    }
    let mut tid_buf = [0u8; 4];
    recv_exact_timeout(ctrl_fd, &mut tid_buf, deadline, "读取 loader tid")?;
    let thread_id = i32::from_le_bytes(tid_buf);
    log_verbose!("Loader worker tid: {}", thread_id);

    // 2. 发送 agent SO fd (创建 memfd → 写入 AGENT_SO → sendmsg)
    //    关键: 必须设置 SELinux label 为 frida_memfd (带 mlstrustedobject 属性)，
    //    否则 untrusted_app 因 MLS 分类不匹配无法通过 SCM_RIGHTS 接收 tmpfs fd。
    let agent_memfd = unsafe { libc::memfd_create(b"wwb_so\0".as_ptr() as _, 0) };
    if agent_memfd < 0 {
        return Err(format!("memfd_create 失败: {}", std::io::Error::last_os_error()));
    }
    let agent_memfd = OwnedFd::new(agent_memfd);
    // relabel memfd：匹配目标进程的 MLS categories，绕过 MLS/MCS 检查
    relabel_fd_for_injection(agent_memfd.raw(), target_pid);
    let mut written = 0usize;
    while written < AGENT_SO.len() {
        let n = unsafe {
            libc::write(
                agent_memfd.raw(),
                AGENT_SO[written..].as_ptr() as *const c_void,
                AGENT_SO.len() - written,
            )
        };
        if n <= 0 {
            return Err("写入 agent SO 到 memfd 失败".to_string());
        }
        written += n as usize;
    }
    let padded_len = padded_agent_memfd_len()?;
    if padded_len > AGENT_SO.len() {
        if unsafe { libc::ftruncate(agent_memfd.raw(), padded_len as libc::off_t) } != 0 {
            return Err(format!("扩展 agent SO memfd 失败: {}", std::io::Error::last_os_error()));
        }
    }
    send_fd_timeout(ctrl_fd, agent_memfd.raw(), deadline, "发送 agent SO fd")?;
    log_verbose!("agent SO fd 已发送 ({} bytes, padded {})", AGENT_SO.len(), padded_len);

    // 3. 创建 REPL socketpair 并发送一端给 loader
    //    注意：loader 先接收 agent_ctrlfd，然后才发送 READY
    let mut sv = [0i32; 2];
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) } != 0 {
        return Err(format!("host socketpair 失败: {}", std::io::Error::last_os_error()));
    }
    let host_repl_fd = OwnedFd::new(sv[0]);
    let agent_repl_fd = OwnedFd::new(sv[1]);
    // 注意：socketpair 在 sockfs 上，不支持 fsetxattr relabel（associate 被拒），
    // 但 Unix socket fd 的 SCM_RIGHTS 传递不受 MLS file 检查约束，无需 relabel
    send_fd_timeout(ctrl_fd, agent_repl_fd.raw(), deadline, "发送 REPL socket fd")?;
    drop(agent_repl_fd);
    log_verbose!("REPL socketpair fd 已发送");

    // 4. 等待 READY（或错误）— loader 在自定义 linker + entrypoint 查找 + recv agent_ctrlfd 之后才发送
    loop {
        match recv_exact_timeout(ctrl_fd, &mut msg_type, deadline, "等待 loader READY") {
            Ok(()) => {}
            Err(e) => {
                return Err(format!("{}; {}", e, loader_thread_diagnostics(target_pid, thread_id)));
            }
        }
        match msg_type[0] {
            t if t == message_type::READY => {
                log_success!("Loader: agent 加载成功");
                break;
            }
            t if t == message_type::ERROR_DLOPEN || t == message_type::ERROR_DLSYM || t == message_type::LOG => {
                let mut len_buf = [0u8; 2];
                recv_exact_timeout(ctrl_fd, &mut len_buf, deadline, "读取 loader 消息长度")?;
                let msg_len = u16::from_le_bytes(len_buf) as usize;
                let mut msg_buf = vec![0u8; msg_len];
                recv_exact_timeout(ctrl_fd, &mut msg_buf, deadline, "读取 loader 消息")?;
                if t == message_type::LOG {
                    log_verbose!("Loader: {}", String::from_utf8_lossy(&msg_buf));
                    continue;
                }
                let kind = if t == message_type::ERROR_DLOPEN {
                    "link"
                } else {
                    "entrypoint"
                };
                let msg = String::from_utf8_lossy(&msg_buf);
                return Err(format!("Loader {} 失败: {}", kind, msg));
            }
            t => {
                return Err(format!("Loader 协议错误: 期望 READY/ERROR, 收到 {}", t));
            }
        }
    }

    let loader_ctx = read_loader_runtime_context(target_pid, loader_ctx_addr)?;
    if loader_ctx.agent_current_thread_eval_impl == 0 {
        return Err("Loader 未解析 rustfrida_loadjs_current_thread".to_string());
    }

    // 5. 发送 ACK
    send_exact_timeout(ctrl_fd, &[message_type::ACK], deadline, "发送 loader ACK")?;

    // ctrl_fd 保持打开用于生命周期管理（BYE 消息）
    // 但对于 rustFrida，REPL 通信走 host_repl_fd
    Ok(InjectionResult {
        host_fd: host_repl_fd.into_raw(),
        target_pid,
        loader_ctx_addr: loader_ctx_addr as u64,
        agent_current_thread_eval_impl: loader_ctx.agent_current_thread_eval_impl,
        loader_alloc_base: loader_alloc_base as u64,
        loader_alloc_size: loader_alloc_size as u64,
        loader_stack: loader_ctx.loader_stack,
        loader_stack_size: loader_ctx.loader_stack_size,
        libc_munmap,
    })
}

fn read_loader_runtime_context(pid: i32, loader_ctx_addr: usize) -> Result<RustFridaLoaderContext, String> {
    let mem = ProcMem::open(pid as u32)?;
    let mut ctx = RustFridaLoaderContext::default();
    let bytes = unsafe {
        std::slice::from_raw_parts_mut(
            &mut ctx as *mut RustFridaLoaderContext as *mut u8,
            std::mem::size_of::<RustFridaLoaderContext>(),
        )
    };
    mem.pread_exact(bytes, loader_ctx_addr as u64)?;
    Ok(ctx)
}

/// Frida-style 注入：bootstrapper 在目标进程内探测 libc/linker API，
/// loader 在 worker 线程中完成自定义 linker + entrypoint 查找 + hello_entry 调用。
/// 使用 code-swap 技术：零 host 端偏移计算，bootstrapper 通过 raw syscall 自行分配内存。
pub(crate) fn inject_via_bootstrapper(
    pid: i32,
    string_overrides: &std::collections::HashMap<String, String>,
) -> Result<InjectionResult, String> {
    let mut last_err = String::new();

    for attempt in 0..3 {
        match inject_via_bootstrapper_once(pid, string_overrides) {
            Ok(result) => return Ok(result),
            Err(e) => {
                let retryable = e.contains("错误码: 3")
                    || e.contains("目标进程不存在")
                    || e.contains("No such process")
                    || e.contains("ESRCH");
                last_err = e;

                if !retryable || !std::path::Path::new(&format!("/proc/{}", pid)).exists() {
                    break;
                }

                log_warn!("注入线程失效，重新选择线程重试 ({}/3): {}", attempt + 1, last_err);
                std::thread::sleep(std::time::Duration::from_millis(80));
            }
        }
    }

    Err(last_err)
}

fn inject_via_bootstrapper_once(
    pid: i32,
    string_overrides: &std::collections::HashMap<String, String>,
) -> Result<InjectionResult, String> {
    log_info!("正在附加到进程 PID: {} (Frida-style bootstrapper)", pid);

    let trace_tid = choose_injection_thread(pid);
    if trace_tid != pid {
        log_verbose!("选择工作线程执行注入: tid={}", trace_tid);
    }

    // 附加到选中的目标线程
    attach_to_process(trace_tid)?;
    let mut stop_world = StopWorldSession::new(trace_tid);
    stop_world.attach_siblings(pid, trace_tid)?;

    let mem = ProcMem::open(pid as u32)?;

    let initial_regs = match crate::process::get_registers_pub(trace_tid) {
        Ok(regs) => regs,
        Err(e) => return Err(e),
    };

    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size <= 0 || (page_size & (page_size - 1)) != 0 {
        return Err(format!("非法 page size: {}", page_size));
    }
    let page_size = page_size as usize;
    let code_size = BOOTSTRAPPER.len().max(FRIDA_LOADER.len());
    let code_pages = ((code_size + page_size - 1) / page_size) * page_size;
    let data_size = 4 * page_size;
    let total_alloc = code_pages + data_size;
    // === Code-swap: 临时覆盖目标进程可执行区域运行 bootstrapper ===
    // 1. 找到目标进程的一个 r-xp 区域（linker64 最安全，所有进程都有）
    let swap_addr = find_executable_region(pid, BOOTSTRAPPER.len())?;
    log_verbose!("code-swap 区域: 0x{:x} ({} bytes)", swap_addr, BOOTSTRAPPER.len());

    // 2. 保存原始代码
    let mut original_code = vec![0u8; BOOTSTRAPPER.len()];
    mem.pread_exact(&mut original_code, swap_addr as u64)?;

    // 3. 写入 bootstrapper
    mem.pwrite_all(BOOTSTRAPPER, swap_addr as u64)?;

    // 4. 在 swap 区域旁找一块可写区域放 BootstrapContext + LibcApi
    //    用目标线程栈来存放（SP 下方有空间）
    let stack_ctx_addr = (initial_regs.sp as usize - 512) & !0xF; // 16 字节对齐
    let stack_libc_addr = stack_ctx_addr - size_of::<FridaLibcApi>();

    // 5. 准备 Phase 1 context: allocation_base = NULL → bootstrapper 自行 mmap
    let zero_api = FridaLibcApi::default();
    mem_write_value(&mem, stack_libc_addr, &zero_api)?;

    let mut phase1_ctx = FridaBootstrapContext::default();
    phase1_ctx.allocation_base = 0; // NULL → 触发 Phase 1 mmap
    phase1_ctx.allocation_size = total_alloc as u64;
    phase1_ctx.page_size = page_size as u64;
    phase1_ctx.libc = stack_libc_addr as u64;
    mem_write_value(&mem, stack_ctx_addr, &phase1_ctx)?;

    // 6. 调用 bootstrapper Phase 1（raw mmap syscall 分配内存）
    log_verbose!("bootstrapper Phase 1: mmap 分配...");
    let status = call_target_function(trace_tid, swap_addr, &[stack_ctx_addr], None).map_err(|e| {
        // 恢复原始代码后再报错
        let _ = mem.pwrite_all(&original_code, swap_addr as u64);
        format!("bootstrapper Phase 1 失败: {}", e)
    })?;

    if status != bootstrap_status::ALLOCATION_SUCCESS {
        let _ = mem.pwrite_all(&original_code, swap_addr as u64);
        return Err(format!("bootstrapper mmap 失败 (status={})", status));
    }

    // 读回 allocation_base
    let phase1_result: FridaBootstrapContext = mem_read_value(&mem, stack_ctx_addr)?;
    let alloc_base = phase1_result.allocation_base as usize;
    log_verbose!("bootstrapper 分配 RWX 区域: 0x{:x} ({} bytes)", alloc_base, total_alloc);

    // 7. 恢复 code-swap 区域的原始代码
    mem.pwrite_all(&original_code, swap_addr as u64)?;
    log_verbose!("code-swap 区域已恢复");

    // === 阶段 1: 在新分配的区域执行 bootstrapper Phase 2 ===
    mem.pwrite_all(BOOTSTRAPPER, alloc_base as u64)?;
    log_verbose!("bootstrapper 写入完成 ({} bytes)", BOOTSTRAPPER.len());

    let data_base = alloc_base + code_pages;
    let libc_api_addr = data_base;
    let ctx_addr = libc_api_addr + size_of::<FridaLibcApi>();

    let zero_api = FridaLibcApi::default();
    mem_write_value(&mem, libc_api_addr, &zero_api)?;

    let mut bootstrap_ctx = FridaBootstrapContext::default();
    bootstrap_ctx.allocation_base = alloc_base as u64; // 非 NULL → Phase 2
    bootstrap_ctx.allocation_size = total_alloc as u64;
    bootstrap_ctx.page_size = page_size as u64;
    bootstrap_ctx.enable_ctrlfds = 1;
    bootstrap_ctx.libc = libc_api_addr as u64;
    mem_write_value(&mem, ctx_addr, &bootstrap_ctx)?;

    log_verbose!("调用 bootstrapper Phase 2...");
    let status = call_target_function(trace_tid, alloc_base, &[ctx_addr], None)
        .map_err(|e| format!("bootstrapper Phase 2 失败: {}", e))?;

    match status {
        s if s == bootstrap_status::SUCCESS => {
            log_success!("bootstrapper 完成: libc API 已解析");
        }
        s if s == bootstrap_status::AUXV_NOT_FOUND => {
            return Err("bootstrapper: 未找到 /proc/self/auxv".into());
        }
        s if s == bootstrap_status::TOO_EARLY => {
            return Err("bootstrapper: libc 尚未加载（TOO_EARLY）".into());
        }
        s if s == bootstrap_status::LIBC_UNSUPPORTED => {
            return Err("bootstrapper: libc API 不完整".into());
        }
        s => {
            return Err(format!("bootstrapper 返回未知状态: {}", s));
        }
    }

    // 读回结果
    let bootstrap_ctx: FridaBootstrapContext = mem_read_value(&mem, ctx_addr)?;
    let libc_api: FridaLibcApi = mem_read_value(&mem, libc_api_addr)?;

    log_verbose!("rtld_flavor: {}", bootstrap_ctx.rtld_flavor);
    log_verbose!(
        "platform bases: libc=0x{:x}, linker=0x{:x}",
        bootstrap_ctx.fallback_libc,
        bootstrap_ctx.rtld_base
    );
    log_verbose!("ctrlfds: [{}, {}]", bootstrap_ctx.ctrlfds[0], bootstrap_ctx.ctrlfds[1]);
    log_verbose!("agent linker: 自解析 ELF/重定位/外部符号，不调用 dlopen/dlsym");
    log_verbose!("loader thread: raw clone，不调用 libc pthread");

    // 提取 ctrlfds[0] 到 host
    let host_ctrl_fd = extract_fd_from_target(pid, bootstrap_ctx.ctrlfds[0])?;
    log_verbose!(
        "已提取 ctrl fd: target {} → host {}",
        bootstrap_ctx.ctrlfds[0],
        host_ctrl_fd
    );

    // === 写入 StringTable ===
    let string_table_offset = size_of::<FridaLibcApi>()
        + size_of::<FridaBootstrapContext>()
        + size_of::<RustFridaLoaderContext>()
        + size_of::<FridaLibcApi>()
        + 256; // 预留字符串区
    let string_table_base = data_base + string_table_offset;
    let string_table_addr = write_string_table_at(&mem, string_table_base, string_overrides)?;
    log_verbose!("StringTable 写入: 0x{:x}", string_table_addr);

    // === 阶段 2: 写入 + 执行 loader ===
    mem.pwrite_all(FRIDA_LOADER, alloc_base as u64)?;
    log_verbose!("loader 写入完成 ({} bytes)", FRIDA_LOADER.len());

    // Loader 数据区（复用 data_base 后面的区域）
    let loader_data_base = data_base + size_of::<FridaLibcApi>() + size_of::<FridaBootstrapContext>();
    let loader_ctx_addr = loader_data_base;
    let loader_libc_addr = loader_ctx_addr + size_of::<RustFridaLoaderContext>();

    // 写入字符串字面量
    let str_base = loader_libc_addr + size_of::<FridaLibcApi>();
    let entrypoint_str = b"hello_entry\0";
    let current_thread_eval_str = b"rustfrida_loadjs_current_thread\0";
    let data_str = b"\0";
    let fallback_str = format!("\x00rustfrida-{}\0", pid); // abstract socket: \0 prefix
    mem.pwrite_all(entrypoint_str, str_base as u64)?;
    let current_thread_eval_str_addr = str_base + entrypoint_str.len();
    mem.pwrite_all(current_thread_eval_str, current_thread_eval_str_addr as u64)?;
    let data_str_addr = current_thread_eval_str_addr + current_thread_eval_str.len();
    mem.pwrite_all(data_str, data_str_addr as u64)?;
    let fallback_str_addr = data_str_addr + data_str.len();
    mem.pwrite_all(fallback_str.as_bytes(), fallback_str_addr as u64)?;

    // 构造 LoaderContext
    let mut loader_ctx = RustFridaLoaderContext::default();
    loader_ctx.ctrlfds = bootstrap_ctx.ctrlfds;
    loader_ctx.agent_entrypoint = str_base as u64;
    loader_ctx.agent_data = data_str_addr as u64;
    loader_ctx.fallback_address = fallback_str_addr as u64;
    loader_ctx.libc = loader_libc_addr as u64;
    loader_ctx.string_table_addr = string_table_addr as u64;
    loader_ctx.agent_current_thread_eval = current_thread_eval_str_addr as u64;
    loader_ctx.libc_base = bootstrap_ctx.fallback_libc;
    loader_ctx.linker_base = bootstrap_ctx.rtld_base;
    mem_write_value(&mem, loader_ctx_addr, &loader_ctx)?;

    // 写入 LibcApi（给 loader 用）
    mem_write_value(&mem, loader_libc_addr, &libc_api)?;

    // 调用 loader（执行 raw clone 后立即返回）
    log_verbose!("调用 loader...");
    let _ = call_target_function(trace_tid, alloc_base, &[loader_ctx_addr], None).map_err(|e| {
        unsafe { close(host_ctrl_fd) };
        format!("loader 执行失败: {}", e)
    })?;

    // === 分离前验证寄存器状态 ===
    {
        let final_regs = crate::process::get_registers_pub(trace_tid);
        if let Ok(r) = final_regs {
            log_verbose!(
                "分离前寄存器: PC={:#x} SP={:#x} LR={:#x} FP(x29)={:#x} x19={:#x}",
                r.pc,
                r.sp,
                r.regs[30],
                r.regs[29],
                r.regs[19]
            );
        }
    }

    // === ptrace 分离 ===
    stop_world.detach_all();
    log_success!("已分离目标进程");

    // === Host 端 loader IPC 握手 ===
    let result = run_loader_handshake(
        host_ctrl_fd,
        pid,
        loader_ctx_addr,
        alloc_base,
        total_alloc,
        libc_api.munmap_fn,
    )
    .map_err(|e| {
        unsafe { close(host_ctrl_fd) };
        e
    })?;

    Ok(result)
}
