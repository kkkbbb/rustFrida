#![cfg(all(target_os = "android", target_arch = "aarch64"))]

use libc::{c_void, close};
use nix::sys::ptrace;
use nix::unistd::Pid;
use std::mem::size_of;
use std::os::unix::io::RawFd;

use crate::process::{
    attach_to_process, call_target_function, read_memory, read_remote_mem, write_bytes, write_memory,
};
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
pub(crate) fn watch_and_inject(
    so_pattern: &str,
    timeout_secs: Option<u64>,
    string_overrides: &std::collections::HashMap<String, String>,
) -> Result<RawFd, String> {
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

/// 写入 StringTable 到预分配的内存区域（不使用 malloc）
fn write_string_table_at(
    pid: i32,
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
            "pthread_err",
            overrides
                .get("pthread_err")
                .map(|s| s.as_bytes().to_vec())
                .unwrap_or_else(|| b"pthreadded".to_vec()),
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
    write_bytes(pid, table_addr, &table_data)?;
    // 写入字符串数据
    write_bytes(pid, strings_base, &strings_data)?;

    Ok(table_addr)
}

/// Unix socket fd-passing: 通过 SCM_RIGHTS 发送 fd
fn send_fd(sockfd: RawFd, fd_to_send: RawFd) -> Result<(), String> {
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

    let ret = unsafe { libc::sendmsg(sockfd, &msg, libc::MSG_NOSIGNAL) };
    if ret < 0 {
        return Err(format!("sendmsg(SCM_RIGHTS) 失败: {}", std::io::Error::last_os_error()));
    }
    Ok(())
}

/// 从 ctrl socket 读取指定字节数
fn recv_exact(sockfd: RawFd, buf: &mut [u8]) -> Result<(), String> {
    let mut done = 0;
    while done < buf.len() {
        let n = unsafe { libc::read(sockfd, buf[done..].as_mut_ptr() as *mut c_void, buf.len() - done) };
        if n <= 0 {
            return Err(format!("recv_exact: read 失败 (n={}, done={}/{})", n, done, buf.len()));
        }
        done += n as usize;
    }
    Ok(())
}

/// 向 ctrl socket 写入数据
fn send_exact(sockfd: RawFd, buf: &[u8]) -> Result<(), String> {
    let mut done = 0;
    while done < buf.len() {
        let n = unsafe {
            libc::send(
                sockfd,
                buf[done..].as_ptr() as *const c_void,
                buf.len() - done,
                libc::MSG_NOSIGNAL,
            )
        };
        if n <= 0 {
            return Err(format!("send_exact: send 失败 (n={})", n));
        }
        done += n as usize;
    }
    Ok(())
}

/// Host 端执行 loader IPC 握手协议
/// 返回 REPL 用的 host_fd
fn run_loader_handshake(ctrl_fd: RawFd, target_pid: i32) -> Result<RawFd, String> {
    // 1. 接收 HELLO 消息: [type:u8][thread_id:i32]
    let mut msg_type = [0u8; 1];
    recv_exact(ctrl_fd, &mut msg_type)?;
    if msg_type[0] != message_type::HELLO {
        return Err(format!("期望 HELLO({}), 收到 {}", message_type::HELLO, msg_type[0]));
    }
    let mut tid_buf = [0u8; 4];
    recv_exact(ctrl_fd, &mut tid_buf)?;
    let thread_id = i32::from_le_bytes(tid_buf);
    log_verbose!("Loader worker tid: {}", thread_id);

    // 2. 发送 agent SO fd (创建 memfd → 写入 AGENT_SO → sendmsg)
    //    关键: 必须设置 SELinux label 为 frida_memfd (带 mlstrustedobject 属性)，
    //    否则 untrusted_app 因 MLS 分类不匹配无法通过 SCM_RIGHTS 接收 tmpfs fd。
    let agent_memfd = unsafe { libc::memfd_create(b"wwb_so\0".as_ptr() as _, 0) };
    if agent_memfd < 0 {
        return Err(format!("memfd_create 失败: {}", std::io::Error::last_os_error()));
    }
    // relabel memfd：匹配目标进程的 MLS categories，绕过 MLS/MCS 检查
    relabel_fd_for_injection(agent_memfd, target_pid);
    let mut written = 0usize;
    while written < AGENT_SO.len() {
        let n = unsafe {
            libc::write(
                agent_memfd,
                AGENT_SO[written..].as_ptr() as *const c_void,
                AGENT_SO.len() - written,
            )
        };
        if n <= 0 {
            unsafe { close(agent_memfd) };
            return Err("写入 agent SO 到 memfd 失败".to_string());
        }
        written += n as usize;
    }
    send_fd(ctrl_fd, agent_memfd)?;
    unsafe { close(agent_memfd) };
    log_verbose!("agent SO fd 已发送 ({} bytes)", AGENT_SO.len());

    // 3. 创建 REPL socketpair 并发送一端给 loader
    //    注意：loader 先接收 agent_ctrlfd，然后才发送 READY
    let mut sv = [0i32; 2];
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) } != 0 {
        return Err(format!("host socketpair 失败: {}", std::io::Error::last_os_error()));
    }
    let host_repl_fd = sv[0];
    let agent_repl_fd = sv[1];
    // 注意：socketpair 在 sockfs 上，不支持 fsetxattr relabel（associate 被拒），
    // 但 Unix socket fd 的 SCM_RIGHTS 传递不受 MLS file 检查约束，无需 relabel
    send_fd(ctrl_fd, agent_repl_fd)?;
    unsafe { close(agent_repl_fd) };
    log_verbose!("REPL socketpair fd 已发送");

    // 4. 等待 READY（或错误）— loader 在 dlopen + dlsym + recv agent_ctrlfd 之后才发送
    recv_exact(ctrl_fd, &mut msg_type)?;
    match msg_type[0] {
        t if t == message_type::READY => {
            log_success!("Loader: agent 加载成功");
        }
        t if t == message_type::ERROR_DLOPEN || t == message_type::ERROR_DLSYM => {
            let mut len_buf = [0u8; 2];
            recv_exact(ctrl_fd, &mut len_buf)?;
            let msg_len = u16::from_le_bytes(len_buf) as usize;
            let mut msg_buf = vec![0u8; msg_len];
            recv_exact(ctrl_fd, &mut msg_buf)?;
            let kind = if t == message_type::ERROR_DLOPEN {
                "dlopen"
            } else {
                "dlsym"
            };
            let msg = String::from_utf8_lossy(&msg_buf);
            unsafe { close(host_repl_fd) };
            return Err(format!("Loader {} 失败: {}", kind, msg));
        }
        t => {
            unsafe { close(host_repl_fd) };
            return Err(format!("Loader 协议错误: 期望 READY/ERROR, 收到 {}", t));
        }
    }

    // 5. 发送 ACK
    send_exact(ctrl_fd, &[message_type::ACK])?;

    // ctrl_fd 保持打开用于生命周期管理（BYE 消息）
    // 但对于 rustFrida，REPL 通信走 host_repl_fd
    Ok(host_repl_fd)
}

/// Frida-style 注入：bootstrapper 在目标进程内探测 libc/linker API，
/// loader 在 worker 线程中完成 dlopen + dlsym + hello_entry 调用。
/// 使用 code-swap 技术：零 host 端偏移计算，bootstrapper 通过 raw syscall 自行分配内存。
pub(crate) fn inject_via_bootstrapper(
    pid: i32,
    string_overrides: &std::collections::HashMap<String, String>,
) -> Result<RawFd, String> {
    log_info!("正在附加到进程 PID: {} (Frida-style bootstrapper)", pid);

    // 附加到目标进程
    attach_to_process(pid)?;

    let page_size = 4096usize;
    let code_size = BOOTSTRAPPER.len().max(FRIDA_LOADER.len());
    let code_pages = ((code_size + page_size - 1) / page_size) * page_size;
    let data_size = 4 * page_size;
    let total_alloc = code_pages + data_size;

    // === Code-swap: 临时覆盖目标进程可执行区域运行 bootstrapper ===
    // 1. 找到目标进程的一个 r-xp 区域（linker64 最安全，所有进程都有）
    let swap_addr = find_executable_region(pid, BOOTSTRAPPER.len())?;
    log_verbose!("code-swap 区域: 0x{:x} ({} bytes)", swap_addr, BOOTSTRAPPER.len());

    // 2. 保存原始代码
    let original_code = read_remote_mem(pid, swap_addr, BOOTSTRAPPER.len())?;

    // 3. 写入 bootstrapper
    write_bytes(pid, swap_addr, BOOTSTRAPPER)?;

    // 4. 在 swap 区域旁找一块可写区域放 BootstrapContext + LibcApi
    //    用目标线程栈来存放（SP 下方有空间）
    let regs = crate::process::get_registers_pub(pid)?;
    let stack_ctx_addr = (regs.sp as usize - 512) & !0xF; // 16 字节对齐
    let stack_libc_addr = stack_ctx_addr - size_of::<FridaLibcApi>();

    // 5. 准备 Phase 1 context: allocation_base = NULL → bootstrapper 自行 mmap
    let zero_api = FridaLibcApi::default();
    write_memory(pid, stack_libc_addr, &zero_api)?;

    let mut phase1_ctx = FridaBootstrapContext::default();
    phase1_ctx.allocation_base = 0; // NULL → 触发 Phase 1 mmap
    phase1_ctx.allocation_size = total_alloc as u64;
    phase1_ctx.page_size = page_size as u64;
    phase1_ctx.libc = stack_libc_addr as u64;
    write_memory(pid, stack_ctx_addr, &phase1_ctx)?;

    // 6. 调用 bootstrapper Phase 1（raw mmap syscall 分配内存）
    log_verbose!("bootstrapper Phase 1: mmap 分配...");
    let status = call_target_function(pid, swap_addr, &[stack_ctx_addr], None).map_err(|e| {
        // 恢复原始代码后再报错
        let _ = write_bytes(pid, swap_addr, &original_code);
        let _ = ptrace::detach(Pid::from_raw(pid), None);
        format!("bootstrapper Phase 1 失败: {}", e)
    })?;

    if status != bootstrap_status::ALLOCATION_SUCCESS {
        let _ = write_bytes(pid, swap_addr, &original_code);
        let _ = ptrace::detach(Pid::from_raw(pid), None);
        return Err(format!("bootstrapper mmap 失败 (status={})", status));
    }

    // 读回 allocation_base
    let phase1_result: FridaBootstrapContext = read_memory(pid, stack_ctx_addr)?;
    let alloc_base = phase1_result.allocation_base as usize;
    log_verbose!("bootstrapper 分配 RWX 区域: 0x{:x} ({} bytes)", alloc_base, total_alloc);

    // 7. 恢复 code-swap 区域的原始代码
    write_bytes(pid, swap_addr, &original_code)?;
    log_verbose!("code-swap 区域已恢复");

    // === 阶段 1: 在新分配的区域执行 bootstrapper Phase 2 ===
    write_bytes(pid, alloc_base, BOOTSTRAPPER)?;
    log_verbose!("bootstrapper 写入完成 ({} bytes)", BOOTSTRAPPER.len());

    let data_base = alloc_base + code_pages;
    let libc_api_addr = data_base;
    let ctx_addr = libc_api_addr + size_of::<FridaLibcApi>();

    let zero_api = FridaLibcApi::default();
    write_memory(pid, libc_api_addr, &zero_api)?;

    let mut bootstrap_ctx = FridaBootstrapContext::default();
    bootstrap_ctx.allocation_base = alloc_base as u64; // 非 NULL → Phase 2
    bootstrap_ctx.allocation_size = total_alloc as u64;
    bootstrap_ctx.page_size = page_size as u64;
    bootstrap_ctx.enable_ctrlfds = 1;
    bootstrap_ctx.libc = libc_api_addr as u64;
    write_memory(pid, ctx_addr, &bootstrap_ctx)?;

    log_verbose!("调用 bootstrapper Phase 2...");
    let status = call_target_function(pid, alloc_base, &[ctx_addr], None).map_err(|e| {
        let _ = ptrace::detach(Pid::from_raw(pid), None);
        format!("bootstrapper Phase 2 失败: {}", e)
    })?;

    match status {
        s if s == bootstrap_status::SUCCESS => {
            log_success!("bootstrapper 完成: libc API 已解析");
        }
        s if s == bootstrap_status::AUXV_NOT_FOUND => {
            let _ = ptrace::detach(Pid::from_raw(pid), None);
            return Err("bootstrapper: 未找到 /proc/self/auxv".into());
        }
        s if s == bootstrap_status::TOO_EARLY => {
            let _ = ptrace::detach(Pid::from_raw(pid), None);
            return Err("bootstrapper: libc 尚未加载（TOO_EARLY）".into());
        }
        s if s == bootstrap_status::LIBC_UNSUPPORTED => {
            let _ = ptrace::detach(Pid::from_raw(pid), None);
            return Err("bootstrapper: libc API 不完整".into());
        }
        s => {
            let _ = ptrace::detach(Pid::from_raw(pid), None);
            return Err(format!("bootstrapper 返回未知状态: {}", s));
        }
    }

    // 读回结果
    let bootstrap_ctx: FridaBootstrapContext = read_memory(pid, ctx_addr)?;
    let libc_api: FridaLibcApi = read_memory(pid, libc_api_addr)?;

    log_verbose!("rtld_flavor: {}", bootstrap_ctx.rtld_flavor);
    log_verbose!("ctrlfds: [{}, {}]", bootstrap_ctx.ctrlfds[0], bootstrap_ctx.ctrlfds[1]);
    log_verbose!("dlopen: 0x{:x}, dlsym: 0x{:x}", libc_api.dlopen, libc_api.dlsym);
    log_verbose!("pthread_create: 0x{:x}", libc_api.pthread_create);

    if libc_api.dlopen == 0 || libc_api.dlsym == 0 || libc_api.pthread_create == 0 {
        let _ = ptrace::detach(Pid::from_raw(pid), None);
        return Err("bootstrapper: 关键函数未解析 (dlopen/dlsym/pthread_create)".into());
    }

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
    let string_table_addr = write_string_table_at(pid, string_table_base, string_overrides)?;
    log_verbose!("StringTable 写入: 0x{:x}", string_table_addr);

    // === 阶段 2: 写入 + 执行 loader ===
    write_bytes(pid, alloc_base, FRIDA_LOADER)?;
    log_verbose!("loader 写入完成 ({} bytes)", FRIDA_LOADER.len());

    // Loader 数据区（复用 data_base 后面的区域）
    let loader_data_base = data_base + size_of::<FridaLibcApi>() + size_of::<FridaBootstrapContext>();
    let loader_ctx_addr = loader_data_base;
    let loader_libc_addr = loader_ctx_addr + size_of::<RustFridaLoaderContext>();

    // 写入字符串字面量
    let str_base = loader_libc_addr + size_of::<FridaLibcApi>();
    let entrypoint_str = b"hello_entry\0";
    let data_str = b"\0";
    let fallback_str = format!("\x00rustfrida-{}\0", pid); // abstract socket: \0 prefix
    write_bytes(pid, str_base, entrypoint_str)?;
    write_bytes(pid, str_base + entrypoint_str.len(), data_str)?;
    write_bytes(
        pid,
        str_base + entrypoint_str.len() + data_str.len(),
        fallback_str.as_bytes(),
    )?;

    // 构造 LoaderContext
    let mut loader_ctx = RustFridaLoaderContext::default();
    loader_ctx.ctrlfds = bootstrap_ctx.ctrlfds;
    loader_ctx.agent_entrypoint = str_base as u64;
    loader_ctx.agent_data = (str_base + entrypoint_str.len()) as u64;
    loader_ctx.fallback_address = (str_base + entrypoint_str.len() + data_str.len()) as u64;
    loader_ctx.libc = loader_libc_addr as u64;
    loader_ctx.string_table_addr = string_table_addr as u64;
    write_memory(pid, loader_ctx_addr, &loader_ctx)?;

    // 写入 LibcApi（给 loader 用）
    write_memory(pid, loader_libc_addr, &libc_api)?;

    // 调用 loader（执行 pthread_create 后立即返回）
    log_verbose!("调用 loader...");
    let _ = call_target_function(pid, alloc_base, &[loader_ctx_addr], None).map_err(|e| {
        unsafe { close(host_ctrl_fd) };
        let _ = ptrace::detach(Pid::from_raw(pid), None);
        format!("loader 执行失败: {}", e)
    })?;

    // === 分离前验证寄存器状态 ===
    {
        let final_regs = crate::process::get_registers_pub(pid);
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
    if let Err(e) = ptrace::detach(Pid::from_raw(pid), None) {
        log_error!("分离目标进程失败: {}", e);
    } else {
        log_success!("已分离目标进程");
    }

    // === Host 端 loader IPC 握手 ===
    let host_repl_fd = run_loader_handshake(host_ctrl_fd, pid).map_err(|e| {
        unsafe { close(host_ctrl_fd) };
        e
    })?;

    Ok(host_repl_fd)
}
