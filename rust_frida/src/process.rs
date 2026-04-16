#![cfg(all(target_os = "android", target_arch = "aarch64"))]

use libc::{c_int, c_void, iovec, pid_t, PTRACE_CONT, PTRACE_GETREGSET, PTRACE_SETREGSET};
use nix::errno::Errno;
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;
use std::fs::File;
use std::mem::size_of_val;
use std::path::Path;
use std::process;

use crate::types::{UserFpRegs, UserRegs};
use crate::{log_info, log_success, log_warn};

/// 获取指定库的基址
///
/// # 参数
/// * `pid`      - 进程ID，`None` 表示查询当前进程
/// * `lib_name` - 要查找的库名称（如 "libc.so"、"libdl.so"）
#[allow(dead_code)]
pub(crate) fn get_lib_base(pid: Option<i32>, lib_name: &str) -> Result<usize, String> {
    let maps_path = match pid {
        Some(pid) => format!("/proc/{}/maps", pid),
        None => "/proc/self/maps".to_string(),
    };

    if !Path::new(&maps_path).exists() {
        return Err(format!("进程 {} 不存在", pid.unwrap_or(-1)));
    }

    let mut file = File::open(&maps_path).map_err(|e| format!("无法打开maps文件: {}", e))?;
    let mut raw = Vec::new();
    std::io::Read::read_to_end(&mut file, &mut raw).map_err(|e| format!("读取maps文件失败: {}", e))?;

    for line in String::from_utf8_lossy(&raw).lines() {
        if line.contains(lib_name) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(addr_range) = parts.get(0) {
                if let Some(start_addr) = addr_range.split('-').next() {
                    return usize::from_str_radix(start_addr, 16).map_err(|e| format!("解析地址失败: {}", e));
                }
            }
        }
    }

    Err(format!("未找到进程 {} 的{}加载地址", pid.unwrap_or(-1), lib_name))
}

fn find_map_line_for_addr(pid: i32, addr: u64) -> Option<String> {
    let maps_path = format!("/proc/{}/maps", pid);
    let mut file = File::open(&maps_path).ok()?;
    let mut raw = Vec::new();
    std::io::Read::read_to_end(&mut file, &mut raw).ok()?;

    for line in String::from_utf8_lossy(&raw).lines() {
        let mut parts = line.split_whitespace();
        let range = parts.next()?;
        let mut it = range.split('-');
        let start = u64::from_str_radix(it.next()?, 16).ok()?;
        let end = u64::from_str_radix(it.next()?, 16).ok()?;
        if addr >= start && addr < end {
            return Some(line.to_string());
        }
    }
    None
}

/// 解冻 cgroup v2 freezer（Android 12+ 会冻结后台进程）
/// 冻结状态下 ptrace attach 的 SIGSTOP 无法送达，waitpid 会永远阻塞。
fn thaw_cgroup_freezer(pid: i32) {
    // cgroup v2 freezer 路径格式：/sys/fs/cgroup/<slice>/uid_<uid>/pid_<pid>/cgroup.freeze
    let cgroup_path = format!("/proc/{}/cgroup", pid);
    let content = match std::fs::read_to_string(&cgroup_path) {
        Ok(c) => c,
        Err(_) => return,
    };
    // 解析 cgroup 路径，例如 "0::/system/uid_1000/pid_13323"
    for line in content.lines() {
        let parts: Vec<&str> = line.splitn(3, ':').collect();
        if parts.len() == 3 {
            let cgroup_rel = parts[2].trim_start_matches('/');
            let freeze_path = format!("/sys/fs/cgroup/{}/cgroup.freeze", cgroup_rel);
            if let Ok(val) = std::fs::read_to_string(&freeze_path) {
                if val.trim() == "1" {
                    log_info!("解冻 cgroup freezer: {}", freeze_path);
                    let _ = std::fs::write(&freeze_path, "0");
                }
            }
        }
    }
}

pub(crate) fn attach_to_process(pid: i32) -> Result<(), String> {
    let target_pid = Pid::from_raw(pid);

    // 解冻 cgroup freezer（Android 12+ 后台进程可能被冻结）
    thaw_cgroup_freezer(pid);

    // 尝试附加到目标进程
    match ptrace::attach(target_pid) {
        Ok(_) => {
            log_success!("成功附加到进程 {}，等待 SIGSTOP...", pid);
            match waitpid(target_pid, None) {
                Ok(WaitStatus::Stopped(_, _)) => {
                    log_success!("进程已停止，可以操作寄存器");
                    Ok(())
                }
                other => Err(format!("waitpid 状态异常: {:?}", other)),
            }
        }
        Err(errno) => {
            let err_msg = match errno {
                Errno::EPERM => "权限不足，请使用root权限运行",
                Errno::ESRCH => "目标进程不存在",
                _ => "附加失败，未知错误",
            };
            Err(err_msg.to_string())
        }
    }
}

/// 获取进程寄存器（pub 接口供 code-swap 使用）
/// 轮询 /proc/pid/status 等待进程进入 stopped 状态
pub(crate) fn wait_process_stopped(pid: u32, timeout: std::time::Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if let Ok(data) = std::fs::read(format!("/proc/{}/status", pid)) {
            let status = String::from_utf8_lossy(&data);
            for line in status.lines() {
                if line.starts_with("State:") && line.contains("stopped") {
                    return true;
                }
            }
        } else {
            return false; // 进程不存在
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

pub(crate) fn get_registers_pub(pid: i32) -> Result<UserRegs, String> {
    get_registers(pid)
}

/// 获取进程寄存器
fn get_registers(pid: i32) -> Result<UserRegs, String> {
    let mut regs = UserRegs::default();
    let mut iov = iovec {
        iov_base: &mut regs as *mut _ as *mut c_void,
        iov_len: size_of_val(&mut regs),
    };
    let result = unsafe {
        libc::ptrace(
            PTRACE_GETREGSET,
            pid as pid_t,
            1, // 通用寄存器
            &mut iov as *mut _ as *mut c_void,
        )
    };

    if result == -1 {
        let errno = unsafe { *libc::__errno() };
        return Err(format!("获取寄存器失败，错误码: {}", errno));
    }
    Ok(regs)
}

/// 设置进程寄存器
fn set_registers(pid: i32, regs: &UserRegs) -> Result<(), String> {
    let mut iov = iovec {
        iov_base: regs as *const _ as *mut c_void,
        iov_len: size_of_val(regs),
    };
    let result = unsafe { libc::ptrace(PTRACE_SETREGSET, pid as pid_t, 1, &mut iov as *mut _ as *mut c_void) };
    if result == -1 {
        let errno = unsafe { *libc::__errno() };
        return Err(format!("设置寄存器失败，错误码: {}", errno));
    }
    Ok(())
}

/// 获取 FP/SIMD 寄存器 (NT_FPREGSET = 2)
fn get_fp_registers(pid: i32) -> Result<UserFpRegs, String> {
    let mut regs = UserFpRegs::default();
    let mut iov = iovec {
        iov_base: &mut regs as *mut _ as *mut c_void,
        iov_len: size_of_val(&regs),
    };
    let result = unsafe {
        libc::ptrace(
            PTRACE_GETREGSET,
            pid as pid_t,
            2, // NT_FPREGSET
            &mut iov as *mut _ as *mut c_void,
        )
    };
    if result == -1 {
        let errno = unsafe { *libc::__errno() };
        return Err(format!("获取 FP 寄存器失败，错误码: {}", errno));
    }
    Ok(regs)
}

/// 设置 FP/SIMD 寄存器 (NT_FPREGSET = 2)
fn set_fp_registers(pid: i32, regs: &UserFpRegs) -> Result<(), String> {
    let mut iov = iovec {
        iov_base: regs as *const _ as *mut c_void,
        iov_len: size_of_val(regs),
    };
    let result = unsafe { libc::ptrace(PTRACE_SETREGSET, pid as pid_t, 2, &mut iov as *mut _ as *mut c_void) };
    if result == -1 {
        let errno = unsafe { *libc::__errno() };
        return Err(format!("设置 FP 寄存器失败，错误码: {}", errno));
    }
    Ok(())
}

/// 调用目标进程的 libc 函数
///
/// # 参数
/// * `pid` - 目标进程ID
/// * `func_addr` - 要调用的函数地址
/// * `args` - 函数参数列表
///
/// # 返回值
/// * `Ok(usize)` - 函数返回值
/// * `Err(String)` - 错误信息
pub(crate) fn call_target_function(
    pid: i32,
    func_addr: usize,
    args: &[usize],
    debug: Option<bool>,
) -> Result<usize, String> {
    // 获取当前寄存器状态（GP + FP/SIMD）
    let orig_regs = get_registers(pid)?;
    let orig_fp_regs = get_fp_registers(pid).ok(); // FP 保存失败不阻塞

    // 设置新的寄存器状态
    let mut new_regs = orig_regs;

    // 设置参数寄存器（ARM64 使用 X0-X7 寄存器传递参数）
    for (i, &arg) in args.iter().enumerate() {
        if i < 8 {
            new_regs.regs[i] = arg as u64;
        } else {
            break;
        }
    }

    // 设置返回地址为 0x340
    new_regs.regs[30] = 0x340; // X30 是链接寄存器 (LR)

    // 设置 PC 指向函数地址
    new_regs.pc = func_addr as u64;

    // 写入新寄存器值
    set_registers(pid, &new_regs)?;

    // 验证寄存器是否正确设置
    {
        let verify = get_registers(pid)?;
        if verify.pc != new_regs.pc {
            log_warn!("PC 设置验证失败: 期望 0x{:x}, 实际 0x{:x}", new_regs.pc, verify.pc);
        }
        if verify.regs[30] != new_regs.regs[30] {
            log_warn!(
                "LR 设置验证失败: 期望 0x{:x}, 实际 0x{:x}",
                new_regs.regs[30],
                verify.regs[30]
            );
        }
    }

    // 继续执行
    if debug.unwrap_or(false) {
        let _ = ptrace::cont(Pid::from_raw(pid), Some(Signal::SIGSTOP));
        process::exit(1);
    }

    let target_pid = Pid::from_raw(pid);

    // 重试循环：处理 spawn 模式下的 pending SIGSTOP
    // 子进程 raise(SIGSTOP) + ptrace attach 的 SIGSTOP 会产生 pending 信号，
    // 导致 PTRACE_CONT 后进程立即被 SIGSTOP 再次停止。
    // 遇到 SIGSTOP 时吞掉信号并重新 CONT，最多重试 3 次。
    let max_sigstop_retries = 50; // 多线程进程可能产生大量信号
    for attempt in 0..=max_sigstop_retries {
        let result = unsafe { libc::ptrace(PTRACE_CONT as c_int, pid as pid_t, 0, 0) };

        if result == -1 {
            return Err(format!("继续执行失败，错误码: {}", unsafe {
                *libc::__errno()
            }));
        }

        // 等待进程停止（可能收到其他线程的信号，需要过滤）
        match waitpid(target_pid, None).map_err(|e| format!("等待进程失败: {}", e))? {
            WaitStatus::Stopped(stopped_pid, Signal::SIGSEGV) if stopped_pid.as_raw() != pid => {
                // 其他线程的 SIGSEGV，转发信号并继续等待
                log_warn!("其他线程 {} 收到 SIGSEGV，转发并继续", stopped_pid);
                let _ = unsafe { libc::ptrace(PTRACE_CONT as c_int, stopped_pid.as_raw() as pid_t, 0, libc::SIGSEGV) };
                continue;
            }
            WaitStatus::Stopped(stopped_pid, sig) if stopped_pid.as_raw() != pid && sig != Signal::SIGSTOP => {
                // 其他线程的其他信号，转发并继续
                log_warn!("其他线程 {} 收到 {:?}，转发并继续", stopped_pid, sig);
                let _ = unsafe { libc::ptrace(PTRACE_CONT as c_int, stopped_pid.as_raw() as pid_t, 0, sig as i32) };
                continue;
            }
            WaitStatus::Stopped(_, Signal::SIGSEGV) => {
                // 目标线程的 SIGSEGV — 检查 PC 是否为预期值
                let regs = get_registers(pid)?;

                if regs.pc == 0x340 {
                    // 函数执行完成，获取返回值（ARM64 使用 X0 寄存器返回值）
                    let return_value = regs.regs[0] as usize;

                    // 恢复原始寄存器状态（GP + FP/SIMD）
                    set_registers(pid, &orig_regs)?;
                    if let Some(ref fp) = orig_fp_regs {
                        let _ = set_fp_registers(pid, fp);
                    }

                    // 验证恢复后的寄存器
                    let verify = get_registers(pid)?;
                    if verify.pc != orig_regs.pc || verify.sp != orig_regs.sp || verify.regs[29] != orig_regs.regs[29] {
                        log_warn!(
                            "寄存器恢复验证: PC={:#x}→{:#x} SP={:#x}→{:#x} FP={:#x}→{:#x} LR={:#x}→{:#x}",
                            orig_regs.pc,
                            verify.pc,
                            orig_regs.sp,
                            verify.sp,
                            orig_regs.regs[29],
                            verify.regs[29],
                            orig_regs.regs[30],
                            verify.regs[30]
                        );
                    }

                    return Ok(return_value);
                } else {
                    let pc_map =
                        find_map_line_for_addr(pid, regs.pc).unwrap_or_else(|| "<unknown mapping>".to_string());
                    let lr_map =
                        find_map_line_for_addr(pid, regs.regs[30]).unwrap_or_else(|| "<unknown mapping>".to_string());
                    return Err(format!(
                        concat!(
                            "函数执行异常，",
                            "PC=0x{:x} [{}], ",
                            "LR=0x{:x} [{}], ",
                            "SP=0x{:x}, ",
                            "X0=0x{:x}, X1=0x{:x}, X2=0x{:x}, X3=0x{:x}\n\
                         X19=0x{:x}, X20=0x{:x}, X21=0x{:x}, X22=0x{:x}, X29=0x{:x}"
                        ),
                        regs.pc,
                        pc_map,
                        regs.regs[30],
                        lr_map,
                        regs.sp,
                        regs.regs[0],
                        regs.regs[1],
                        regs.regs[2],
                        regs.regs[3],
                        regs.regs[19],
                        regs.regs[20],
                        regs.regs[21],
                        regs.regs[22],
                        regs.regs[29]
                    ));
                }
            }
            WaitStatus::Stopped(_, Signal::SIGSTOP) => {
                // spawn 模式下 pending SIGSTOP：吞掉信号，重新 CONT
                if attempt < max_sigstop_retries {
                    log_warn!("检测到 pending SIGSTOP (第{}次)，跳过并重试", attempt + 1);
                    continue;
                } else {
                    return Err("多次 SIGSTOP 中断，无法执行目标函数".to_string());
                }
            }
            WaitStatus::Stopped(_, sig) => {
                let regs = get_registers(pid).ok();
                let info = if let Some(r) = &regs {
                    format!("PC=0x{:x} LR=0x{:x} X0=0x{:x}", r.pc, r.regs[30], r.regs[0])
                } else {
                    "regs unavailable".into()
                };
                return Err(format!("进程异常停止: {:?} {}", sig, info));
            }
            status => return Err(format!("进程异常停止: {:?}", status)),
        }
    }
    Err("call_target_function: 超出重试次数".to_string())
}

/// 向远程进程内存写入任意类型的数据
///
/// # 参数
/// * `pid` - 目标进程ID
/// * `addr` - 目标地址
/// * `data` - 要写入的数据指针
/// * `size` - 数据大小（字节数）
fn write_remote_mem(pid: i32, addr: usize, data: *const u8, size: usize) -> Result<(), String> {
    // 去掉 MTE 标签位（高 byte），ptrace 不支持带标签的地址
    let addr = addr & 0x00FFFFFFFFFFFFFF;
    let mut offset = 0;
    while offset < size {
        let remaining = size - offset;
        let write_size = if remaining >= 8 { 8 } else { remaining };

        // 非对齐尾部（< 8 字节）：先 PEEKTEXT 读取原始 8 字节，再 merge 新字节，
        // 避免 POKETEXT 始终写满 8 字节时覆盖紧随其后的数据。
        let mut word: u64 = if write_size < 8 {
            unsafe { *libc::__errno() = 0 };
            let existing = unsafe {
                libc::ptrace(
                    libc::PTRACE_PEEKTEXT,
                    pid as pid_t,
                    (addr + offset) as *mut c_void,
                    std::ptr::null_mut::<c_void>(),
                )
            };
            let errno_val = unsafe { *libc::__errno() };
            if existing == -1 && errno_val != 0 {
                return Err(format!(
                    "读取内存失败(PEEKTEXT) addr=0x{:x} offset={} errno={}",
                    addr, offset, errno_val
                ));
            }
            existing as u64
        } else {
            0
        };

        // 合并新字节到 word（低字节 → 低地址，ARM64 小端序）
        unsafe {
            std::ptr::copy_nonoverlapping(data.add(offset), &mut word as *mut u64 as *mut u8, write_size);
        }

        // 写入目标进程
        let result = unsafe {
            libc::ptrace(
                libc::PTRACE_POKETEXT,
                pid as pid_t,
                (addr + offset) as *mut c_void,
                word as usize as *mut c_void,
            )
        };

        if result == -1 {
            let errno = unsafe { *libc::__errno() };
            return Err(format!(
                "写入内存失败 addr=0x{:x} offset={} size={} errno={}",
                addr, offset, size, errno
            ));
        }

        offset += write_size;
    }

    Ok(())
}

/// 向远程进程内存写入任意类型的数据的泛型包装
///
/// # 参数
/// * `pid` - 目标进程ID
/// * `addr` - 目标地址
/// * `data` - 要写入的数据（任意类型）
pub(crate) fn write_memory<T>(pid: i32, addr: usize, data: &T) -> Result<(), String> {
    write_remote_mem(pid, addr, data as *const T as *const u8, size_of_val(data))
}

/// 向远程进程内存写入字节数组
///
/// # 参数
/// * `pid` - 目标进程ID
/// * `addr` - 目标地址
/// * `data` - 要写入的字节数组
pub(crate) fn write_bytes(pid: i32, addr: usize, data: &[u8]) -> Result<(), String> {
    write_remote_mem(pid, addr, data.as_ptr(), data.len())
}

/// 从远程进程内存读取数据
///
/// # 参数
/// * `pid` - 目标进程ID
/// * `addr` - 目标地址
/// * `size` - 读取字节数
pub(crate) fn read_remote_mem(pid: i32, addr: usize, size: usize) -> Result<Vec<u8>, String> {
    let addr = addr & 0x00FFFFFFFFFFFFFF; // 去掉 MTE 标签位
    let mut result = vec![0u8; size];
    let mut offset = 0;
    while offset < size {
        unsafe { *libc::__errno() = 0 };
        let word = unsafe {
            libc::ptrace(
                libc::PTRACE_PEEKTEXT,
                pid as pid_t,
                (addr + offset) as *mut c_void,
                std::ptr::null_mut::<c_void>(),
            )
        };
        let errno_val = unsafe { *libc::__errno() };
        if word == -1 && errno_val != 0 {
            return Err(format!(
                "读取内存失败(PEEKTEXT) addr=0x{:x} offset={} errno={}",
                addr, offset, errno_val
            ));
        }
        let remaining = size - offset;
        let copy_size = remaining.min(8);
        unsafe {
            std::ptr::copy_nonoverlapping(
                &word as *const i64 as *const u8,
                result.as_mut_ptr().add(offset),
                copy_size,
            );
        }
        offset += 8;
    }
    Ok(result)
}

/// 从远程进程读取任意类型的数据
///
/// # 参数
/// * `pid` - 目标进程ID
/// * `addr` - 目标地址（目标进程中的内存地址）
pub(crate) fn read_memory<T: Default>(pid: i32, addr: usize) -> Result<T, String> {
    let bytes = read_remote_mem(pid, addr, std::mem::size_of::<T>())?;
    let mut val = T::default();
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), &mut val as *mut T as *mut u8, std::mem::size_of::<T>());
    }
    Ok(val)
}

/// maps 条目结构
#[derive(Debug, Clone)]
pub(crate) struct MapEntry {
    pub(crate) start: u64,
    pub(crate) end: u64,
    pub(crate) perms: String,
    pub(crate) offset: u64,
    pub(crate) path: String,
}

impl MapEntry {
    pub(crate) fn is_readable(&self) -> bool {
        self.perms.starts_with('r')
    }

    pub(crate) fn is_writable(&self) -> bool {
        self.perms.len() >= 2 && self.perms.as_bytes()[1] == b'w'
    }

    pub(crate) fn is_executable(&self) -> bool {
        self.perms.len() >= 3 && self.perms.as_bytes()[2] == b'x'
    }

    pub(crate) fn is_shared(&self) -> bool {
        self.perms.contains('s')
    }
}

/// 结构化解析 /proc/<pid>/maps
pub(crate) fn parse_proc_maps(pid: u32) -> Result<Vec<MapEntry>, String> {
    let maps_path = format!("/proc/{}/maps", pid);
    let mut file = File::open(&maps_path).map_err(|e| format!("无法打开 {}: {}", maps_path, e))?;
    let mut raw = Vec::new();
    std::io::Read::read_to_end(&mut file, &mut raw).map_err(|e| format!("读取 {} 失败: {}", maps_path, e))?;
    let mut entries = Vec::new();

    for line in String::from_utf8_lossy(&raw).lines() {
        let line = line.to_string();
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }

        let addr_parts: Vec<&str> = parts[0].split('-').collect();
        if addr_parts.len() != 2 {
            continue;
        }

        let start = u64::from_str_radix(addr_parts[0], 16).map_err(|e| format!("解析地址失败: {}", e))?;
        let end = u64::from_str_radix(addr_parts[1], 16).map_err(|e| format!("解析地址失败: {}", e))?;

        let perms = parts[1].to_string();
        let offset = if parts.len() > 2 {
            u64::from_str_radix(parts[2], 16).unwrap_or(0)
        } else {
            0
        };
        let path = if parts.len() >= 6 {
            parts[5..].join(" ")
        } else {
            String::new()
        };

        entries.push(MapEntry {
            start,
            end,
            perms,
            offset,
            path,
        });
    }

    Ok(entries)
}

/// 读取 /proc/<pid>/stat 判断进程是否处于 stopped 状态
pub(crate) fn is_process_stopped(pid: u32) -> bool {
    let stat_path = format!("/proc/{}/stat", pid);
    if let Ok(data) = std::fs::read_to_string(&stat_path) {
        // /proc/pid/stat 格式: pid (comm) state ...
        // state 在最后一个 ')' 之后的第一个非空字符
        if let Some(pos) = data.rfind(')') {
            let rest = &data[pos + 1..];
            let state = rest.trim().chars().next().unwrap_or('?');
            return state == 'T' || state == 't';
        }
    }
    false
}

/// 递增延迟轮询等待进程停止（0/1/2/5/10/20/50/250ms），5s 超时
pub(crate) fn wait_until_stopped(pid: u32) -> Result<(), String> {
    let delays = [0, 1, 2, 5, 10, 20, 50, 250];
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut idx = 0;

    loop {
        if is_process_stopped(pid) {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!("等待进程 {} 停止超时 (5s)", pid));
        }
        let delay = delays[idx.min(delays.len() - 1)];
        if delay > 0 {
            std::thread::sleep(std::time::Duration::from_millis(delay));
        }
        idx += 1;
    }
}

/// 通过读 /proc/*/cmdline 按进程名查找 PID。
/// 精确匹配（含末路径组件）；多匹配列出并返回错误。
pub(crate) fn find_pid_by_name(name: &str) -> Result<i32, String> {
    use std::fs;

    let mut matches: Vec<i32> = Vec::new();
    let proc_dir = fs::read_dir("/proc").map_err(|e| format!("读取 /proc 失败: {}", e))?;

    for entry in proc_dir.flatten() {
        let fname = entry.file_name();
        let fname_str = fname.to_string_lossy();
        if !fname_str.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let pid: i32 = match fname_str.parse() {
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
            let base_name = proc_name.rsplit('/').next().unwrap_or(proc_name);
            if proc_name == name || base_name == name {
                matches.push(pid);
            }
        }
    }

    match matches.len() {
        0 => Err(format!("未找到进程名匹配 '{}'", name)),
        1 => Ok(matches[0]),
        _ => {
            log_warn!("找到多个匹配进程，请使用 --pid 指定:");
            for pid in &matches {
                let cmdline_path = format!("/proc/{}/cmdline", pid);
                let display = if let Ok(data) = std::fs::read(&cmdline_path) {
                    data.split(|&b| b == 0)
                        .filter(|s| !s.is_empty())
                        .take(2)
                        .flat_map(|s| std::str::from_utf8(s))
                        .collect::<Vec<_>>()
                        .join(" ")
                } else {
                    "?".to_string()
                };
                println!("  PID {:6}: {}", pid, display);
            }
            Err(format!("找到 {} 个匹配进程，请使用 --pid <n> 精确指定", matches.len()))
        }
    }
}
