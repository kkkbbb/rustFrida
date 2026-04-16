//! crash/panic 处理模块 - 安装信号处理器和 panic hook
//!
//! 关键设计: 必须正确 chain 到旧的信号处理器（特别是 ART 的 FaultManager）。
//! ART 运行时依赖 SIGSEGV handler 实现隐式空指针检查、栈溢出检测等。
//! 如果不 chain，app 在触发 ART 隐式 null check 时会直接崩溃，
//! 而不是正常抛出 NullPointerException。

use crate::communication::{log_msg, write_stream_raw};
use libc::{
    c_char, c_int, c_void, sigaction, siginfo_t, SA_ONSTACK, SA_SIGINFO, SIGABRT, SIGBUS, SIGFPE, SIGILL, SIGSEGV,
    SIGTRAP,
};
use std::ffi::CStr;
use std::mem::zeroed;
use std::process;
use std::sync::atomic::{AtomicUsize, Ordering};

#[cfg(feature = "frida-gum")]
use frida_gum::ModuleMap;

// ============================================================================
// 旧信号处理器存储（用于 chain）
// ============================================================================
// 最大信号编号（SIGTRAP=5, SIGABRT=6, SIGBUS=7, SIGFPE=8, SIGSEGV=11, SIGILL=4）
// 用 32 个 slot 足够覆盖所有需要的信号
const MAX_SIG: usize = 32;

/// 保存旧 handler 的 sa_sigaction（函数指针或 SIG_DFL/SIG_IGN）
static OLD_HANDLER_FN: [AtomicUsize; MAX_SIG] = {
    const INIT: AtomicUsize = AtomicUsize::new(0);
    [INIT; MAX_SIG]
};

/// 保存旧 handler 的 sa_flags（用于判断是 SA_SIGINFO 还是传统 handler）
static OLD_HANDLER_FLAGS: [AtomicUsize; MAX_SIG] = {
    const INIT: AtomicUsize = AtomicUsize::new(0);
    [INIT; MAX_SIG]
};

/// 内存映射信息
struct MapEntry {
    start: usize,
    end: usize,
    name: String,
}

/// 根据地址查找所属的映射
fn find_map_for_addr(addr: usize, maps: &[MapEntry]) -> Option<&MapEntry> {
    maps.iter().find(|m| addr >= m.start && addr < m.end)
}

/// 判断是否是 memfd（agent 代码）
fn is_memfd(name: &String) -> bool {
    name.contains("memfd:")
}

// _Unwind_Backtrace 相关定义
type UnwindReasonCode = c_int;
type UnwindContext = c_void;

extern "C" {
    fn _Unwind_Backtrace(
        trace_fn: extern "C" fn(*mut UnwindContext, *mut c_void) -> UnwindReasonCode,
        data: *mut c_void,
    ) -> UnwindReasonCode;
    fn _Unwind_GetIP(ctx: *mut UnwindContext) -> usize;
}

/// dladdr 返回的符号信息结构体
#[repr(C)]
struct DlInfo {
    dli_fname: *const c_char, // 包含地址的共享库路径
    dli_fbase: *mut c_void,   // 共享库的基地址
    dli_sname: *const c_char, // 最近符号的名称
    dli_saddr: *mut c_void,   // 最近符号的地址
}

extern "C" {
    fn dladdr(addr: *const c_void, info: *mut DlInfo) -> c_int;
}

/// 使用 dladdr 解析地址的符号信息
fn resolve_symbol(addr: usize) -> (Option<String>, Option<String>, usize) {
    unsafe {
        let mut info: DlInfo = zeroed();
        if dladdr(addr as *const c_void, &mut info) != 0 {
            // 获取库名
            let lib_name = if !info.dli_fname.is_null() {
                CStr::from_ptr(info.dli_fname)
                    .to_str()
                    .ok()
                    .map(|s| s.rsplit('/').next().unwrap_or(s).to_string())
            } else {
                None
            };

            // 获取符号名
            let sym_name = if !info.dli_sname.is_null() {
                CStr::from_ptr(info.dli_sname).to_str().ok().map(|s| s.to_string())
            } else {
                None
            };

            // 计算相对偏移（相对于库基址或符号地址）
            let offset = if !info.dli_saddr.is_null() {
                addr.saturating_sub(info.dli_saddr as usize)
            } else if !info.dli_fbase.is_null() {
                addr.saturating_sub(info.dli_fbase as usize)
            } else {
                0
            };

            (lib_name, sym_name, offset)
        } else {
            (None, None, 0)
        }
    }
}

struct BacktraceData {
    frames: Vec<usize>,
    max_frames: usize,
}

extern "C" fn unwind_callback(ctx: *mut UnwindContext, data: *mut c_void) -> UnwindReasonCode {
    unsafe {
        let bt_data = &mut *(data as *mut BacktraceData);
        if bt_data.frames.len() >= bt_data.max_frames {
            return 5; // _URC_END_OF_STACK
        }
        let ip = _Unwind_GetIP(ctx);
        if ip != 0 {
            bt_data.frames.push(ip);
        }
        0 // _URC_NO_REASON (continue)
    }
}

/// 使用 _Unwind_Backtrace 获取调用栈
fn collect_backtrace() -> Vec<usize> {
    let mut data = BacktraceData {
        frames: Vec::with_capacity(64),
        max_frames: 64,
    };
    unsafe {
        _Unwind_Backtrace(unwind_callback, &mut data as *mut _ as *mut c_void);
    }
    data.frames
}

/// abort_msg_t 结构体，与 bionic 中的定义一致
#[repr(C)]
struct AbortMsgT {
    size: usize,
    // msg[0] 紧随其后，是变长字符数组
}

/// 获取 Android abort message
/// Android bionic 在 abort() 时会将消息存储在 __abort_message
fn get_abort_message() -> Option<String> {
    unsafe {
        let libc_name = std::ffi::CString::new("libc.so").ok()?;
        let handle = libc::dlopen(libc_name.as_ptr(), libc::RTLD_NOLOAD);
        if handle.is_null() {
            return None;
        }

        // 方法1：尝试使用 android_get_abort_message() API (API 21+)
        let api_name = std::ffi::CString::new("android_get_abort_message").ok()?;
        let api_ptr = libc::dlsym(handle, api_name.as_ptr());

        if !api_ptr.is_null() {
            let get_abort_msg: extern "C" fn() -> *const c_char = std::mem::transmute(api_ptr);
            let msg_ptr = get_abort_msg();
            libc::dlclose(handle);
            if !msg_ptr.is_null() {
                let c_str = CStr::from_ptr(msg_ptr);
                return c_str.to_str().ok().map(|s| s.to_string());
            }
            return None;
        }

        // 方法2：直接读取 __abort_message 全局变量
        let sym_name = std::ffi::CString::new("__abort_message").ok()?;
        let ptr = libc::dlsym(handle, sym_name.as_ptr());
        libc::dlclose(handle);

        if ptr.is_null() {
            return None;
        }

        // __abort_message 是 abort_msg_t** 类型（全局变量的地址）
        let msg_ptr_ptr = ptr as *const *const AbortMsgT;
        let msg_ptr = *msg_ptr_ptr;

        if msg_ptr.is_null() {
            return None;
        }

        let msg_size = (*msg_ptr).size;
        if msg_size == 0 {
            return None;
        }

        // msg 字符串紧跟在 size 字段之后
        let msg_data = (msg_ptr as *const u8).add(std::mem::size_of::<usize>()) as *const c_char;
        let c_str = CStr::from_ptr(msg_data);
        c_str.to_str().ok().map(|s| s.to_string())
    }
}

/// 从 ucontext 提取 ARM64 寄存器状态
unsafe fn dump_registers(ucontext: *mut c_void) -> String {
    if ucontext.is_null() {
        return "  (ucontext is NULL)\n".to_string();
    }
    // ucontext_t on aarch64-linux-android (bionic):
    //   uc_flags(8) + uc_link(8) + uc_stack(24) + uc_sigmask(8) + __padding(120) = 168
    //   + 8 bytes alignment padding → mcontext_t at offset 176
    //   mcontext_t (struct sigcontext):
    //     fault_address(8) + regs[31](248) + sp(8) + pc(8) + pstate(8)
    let uc = ucontext as *const u8;
    let mctx = 176usize; // mcontext_t offset in ucontext_t
    let regs = uc.add(mctx + 8) as *const u64; // regs[0..31]
    let sp = *(uc.add(mctx + 256) as *const u64); // sp
    let pc = *(uc.add(mctx + 264) as *const u64); // pc
    let pstate = *(uc.add(mctx + 272) as *const u64); // pstate

    let mut s = String::new();
    // PC with symbol resolution
    let (pc_lib, pc_sym, pc_off) = resolve_symbol(pc as usize);
    s.push_str(&format!("  PC:  0x{:016x}", pc));
    match (pc_lib, pc_sym) {
        (Some(lib), Some(sym)) => s.push_str(&format!(" ({} {}+0x{:x})", lib, sym, pc_off)),
        (Some(lib), None) => s.push_str(&format!(" ({} +0x{:x})", lib, pc_off)),
        _ => {}
    }
    s.push('\n');
    s.push_str(&format!("  SP:  0x{:016x}  PSTATE: 0x{:x}\n", sp, pstate));

    // x0-x30 in rows of 4
    for row in 0..8 {
        for col in 0..4 {
            let i = row * 4 + col;
            if i > 30 {
                break;
            }
            s.push_str(&format!("  x{:<2}=0x{:016x}", i, *regs.add(i)));
        }
        s.push('\n');
    }
    s
}

unsafe fn extract_pc_from_ucontext(ucontext: *mut c_void) -> Option<usize> {
    if ucontext.is_null() {
        return None;
    }
    let uc = ucontext as *const u8;
    let mctx = 176usize;
    Some(*(uc.add(mctx + 264) as *const u64) as usize)
}

unsafe fn dump_code_bytes(addr: usize, label: &str) -> String {
    if addr == 0 {
        return String::new();
    }

    let start = addr.saturating_sub(32);
    let mut s = String::new();
    s.push_str(&format!("\n=== {} BYTES ===\n", label));

    for line_start in (start..start + 64).step_by(16) {
        s.push_str(&format!("  0x{line_start:016x}:"));
        for i in 0..16 {
            let cur = line_start + i;
            let byte = *(cur as *const u8);
            s.push_str(&format!(" {:02x}", byte));
        }
        if addr >= line_start && addr < line_start + 16 {
            s.push_str("  <==");
        }
        s.push('\n');
    }

    s
}

// ============================================================================
// 信号处理函数
// ============================================================================

/// 64 字节全零 dummy OAT header — WalkStack NULL header 修复用
static DUMMY_OAT_HEADER_BUF: [u8; 64] = [0u8; 64];

/// 使用 dladdr 快速判断崩溃 PC 是否在 agent 代码（memfd 加载的 SO）中
unsafe fn is_crash_in_agent(ucontext: *mut c_void) -> bool {
    let pc = match extract_pc_from_ucontext(ucontext) {
        Some(pc) => pc,
        None => return false,
    };
    let mut info: DlInfo = zeroed();
    if dladdr(pc as *const c_void, &mut info) != 0 && !info.dli_fname.is_null() {
        let fname = CStr::from_ptr(info.dli_fname);
        if let Ok(s) = fname.to_str() {
            return s.contains("memfd:");
        }
    }
    false
}

/// chain 到旧的信号处理器
/// 返回 true 表示已成功 chain（旧 handler 存在且不是 SIG_DFL/SIG_IGN）
unsafe fn chain_to_old_handler(sig: c_int, info: *mut siginfo_t, ucontext: *mut c_void) -> bool {
    if (sig as usize) >= MAX_SIG {
        return false;
    }

    let old_fn = OLD_HANDLER_FN[sig as usize].load(Ordering::Acquire);
    let old_flags = OLD_HANDLER_FLAGS[sig as usize].load(Ordering::Acquire);

    // SIG_DFL = 0, SIG_IGN = 1
    if old_fn <= 1 {
        return false;
    }

    if (old_flags & SA_SIGINFO as usize) != 0 {
        // SA_SIGINFO 风格 handler（ART FaultManager 使用这种）
        let handler: extern "C" fn(c_int, *mut siginfo_t, *mut c_void) = std::mem::transmute(old_fn);
        handler(sig, info, ucontext);
    } else {
        // 传统风格 handler
        let handler: extern "C" fn(c_int) = std::mem::transmute(old_fn);
        handler(sig);
    }

    true
}

extern "C" fn crash_signal_handler(sig: c_int, info: *mut siginfo_t, ucontext: *mut c_void) {
    unsafe {
        // --- WalkStack/GetDexPc NULL OatQuickMethodHeader 修复 (API 36) ---
        // ART 的 WalkStack/GetDexPc/DecodeGcMasksOnly 在处理被 hook 方法的栈帧时，
        // 可能对 NULL OatQuickMethodHeader 执行字段读取，既可能是 NULL+0x18，
        // 也可能是 NULL+0x0 等前 64 字节访问。
        // 修复: 解码当前 load 指令找到 base 寄存器 Xn，将其指向全零 dummy buffer。
        if sig == SIGSEGV && !info.is_null() && !ucontext.is_null() {
            let fault_addr = (*info).si_addr() as u64;
            if fault_addr < DUMMY_OAT_HEADER_BUF.len() as u64 {
                // bionic ucontext_t 布局: mcontext_t at offset 176
                // regs[0..30] at +8, sp at +256, pc at +264
                let uc_raw = ucontext as *mut u8;
                let regs_ptr = uc_raw.add(176 + 8) as *mut u64;
                let pc = *(uc_raw.add(176 + 264) as *const u64);
                // 读取崩溃指令 (ARM64 little-endian 4 bytes)
                let insn = *(pc as *const u32);
                // 解码 LDR (unsigned offset): 1x11 1001 01ii iiii iiii iinn nnnt tttt
                // 或 LDR Wt: 1011 1001 01.. ....
                // 提取 Rn (base register): bits [9:5]
                let is_ldr_unsigned = (insn & 0x3B000000) == 0x39000000;
                if is_ldr_unsigned {
                    let rn = ((insn >> 5) & 0x1F) as usize;
                    if rn < 31 && *regs_ptr.add(rn) == 0 {
                        *regs_ptr.add(rn) = DUMMY_OAT_HEADER_BUF.as_ptr() as u64;
                        return; // 恢复执行
                    }
                }
            }
        }

        // --- 信号 chain 策略 ---
        // 1. 如果崩溃不在 agent 代码中，优先 chain 到旧 handler（ART FaultManager 等）
        //    ART 需要 SIGSEGV 实现隐式 null check、栈溢出检测、安全点等
        // 2. 如果崩溃在 agent 代码中，先做 crash 报告，再 chain
        // 3. 如果没有旧 handler，做 crash 报告后 SIG_DFL 终止

        let in_agent = is_crash_in_agent(ucontext);

        if !in_agent {
            // 非 agent 代码中的信号 → 直接 chain 到旧 handler
            // ART 的 FaultManager 会处理隐式 null check (修改 ucontext 抛 NPE) 并返回
            if chain_to_old_handler(sig, info, ucontext) {
                return; // 旧 handler 已处理（如 ART null check），恢复执行
            }
            // 无旧 handler，fall through 到 crash 报告
        }

        // --- Crash 报告 ---
        // 仅在 agent 代码崩溃或无旧 handler 时执行

        let sig_name = match sig {
            SIGSEGV => "SIGSEGV (Segmentation Fault)",
            SIGBUS => "SIGBUS (Bus Error)",
            SIGABRT => "SIGABRT (Abort)",
            SIGFPE => "SIGFPE (Floating Point Exception)",
            SIGILL => "SIGILL (Illegal Instruction)",
            SIGTRAP => "SIGTRAP (Trap)",
            _ => "Unknown signal",
        };

        let fault_addr = if !info.is_null() { (*info).si_addr() as usize } else { 0 };

        // 构建崩溃信息
        let mut crash_msg = format!(
            "\n\n=== CRASH DETECTED ===\n\
             Signal: {} ({})\n\
             Fault Address: 0x{:x}\n\
             PID: {}\n\
             TID: {}\n",
            sig_name,
            sig,
            fault_addr,
            process::id(),
            libc::gettid()
        );

        // 如果是 SIGABRT，尝试获取 abort message
        if sig == SIGABRT {
            if let Some(abort_msg) = get_abort_message() {
                crash_msg.push_str(&format!("Abort Message: {}\n", abort_msg));
            }
        }

        // 打印寄存器状态
        crash_msg.push_str("\n=== REGISTERS ===\n");
        crash_msg.push_str(&dump_registers(ucontext));

        if let Some(pc) = extract_pc_from_ucontext(ucontext) {
            crash_msg.push_str(&dump_code_bytes(pc, "PC"));
        }
        crash_msg.push_str("\n=== BACKTRACE ===\n");

        // 使用 _Unwind_Backtrace 获取调用栈
        let frames = collect_backtrace();

        #[cfg(feature = "frida-gum")]
        {
            // 解析内存映射（需要 frida-gum）
            let mut mdmap = ModuleMap::new();
            mdmap.update();

            for (idx, &addr) in frames.iter().enumerate() {
                crash_msg.push_str(&format!("#{:<3} 0x{:016x}", idx, addr));

                if let Some(map) = mdmap.find(addr as u64) {
                    let offset = addr - map.range().base_address().0 as usize;
                    let mdname = map.name();
                    if is_memfd(&mdname) {
                        crash_msg.push_str(&format!(" (memfd+0x{:x})", offset));
                    } else {
                        let lib_name = mdname.rsplit('/').next().unwrap_or(mdname.as_str());
                        crash_msg.push_str(&format!(" {} +0x{:x}", lib_name, offset));
                    }
                } else {
                    crash_msg.push_str(" <unknown mapping>");
                }
                crash_msg.push('\n');
            }
        }

        #[cfg(not(feature = "frida-gum"))]
        {
            // 使用 dladdr 获取符号信息
            for (idx, &addr) in frames.iter().enumerate() {
                crash_msg.push_str(&format!("#{:<3} 0x{:016x}", idx, addr));

                let (lib_name, sym_name, offset) = resolve_symbol(addr);

                match (lib_name, sym_name) {
                    (Some(lib), Some(sym)) => {
                        if is_memfd(&lib) {
                            crash_msg.push_str(&format!(" (memfd) {}+0x{:x}", sym, offset));
                        } else {
                            crash_msg.push_str(&format!(" {} ({}+0x{:x})", lib, sym, offset));
                        }
                    }
                    (Some(lib), None) => {
                        if is_memfd(&lib) {
                            crash_msg.push_str(&format!(" (memfd+0x{:x})", offset));
                        } else {
                            crash_msg.push_str(&format!(" {} +0x{:x}", lib, offset));
                        }
                    }
                    _ => {
                        crash_msg.push_str(" <unknown>");
                    }
                }
                crash_msg.push('\n');
            }
        }

        crash_msg.push_str("=== END BACKTRACE ===\n\n");

        // 尝试通过 socket 发送
        write_stream_raw(crash_msg.as_bytes());

        // agent 代码崩溃 → 尝试 chain 到旧 handler（让系统生成 tombstone）
        if in_agent {
            if chain_to_old_handler(sig, info, ucontext) {
                return; // 旧 handler 也处理了（不太可能，但安全起见）
            }
        }

        // 重新抛出信号以便系统处理（生成 tombstone/core dump）
        libc::signal(sig, libc::SIG_DFL);
        libc::raise(sig);
    }
}

/// 安装崩溃信号处理器
///
/// 关键: 通过 sigaction 的第三个参数保存旧 handler，在 crash_signal_handler 中
/// 正确 chain。这样 ART 的 FaultManager 等关键 handler 不会被破坏。
pub(crate) fn install_crash_handlers() {
    let signals = [SIGSEGV, SIGBUS, SIGABRT, SIGFPE, SIGILL, SIGTRAP];

    for &sig in &signals {
        unsafe {
            let mut sa: sigaction = std::mem::zeroed();
            sa.sa_sigaction = crash_signal_handler as usize;
            sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
            libc::sigemptyset(&mut sa.sa_mask);

            let mut old_sa: sigaction = std::mem::zeroed();

            if sigaction(sig, &sa, &mut old_sa) == 0 {
                // 保存旧 handler 用于 chain
                if (sig as usize) < MAX_SIG {
                    OLD_HANDLER_FN[sig as usize].store(old_sa.sa_sigaction, Ordering::Release);
                    OLD_HANDLER_FLAGS[sig as usize].store(old_sa.sa_flags as usize, Ordering::Release);
                }
            } else {
                log_msg(format!("Failed to install handler for signal {}\n", sig));
            }
        }
    }
}

/// 卸载崩溃信号处理器，恢复旧的 handler
///
/// 必须在 agent SO 被 dlclose 之前调用！否则 sigaction 表中的函数指针
/// 指向已卸载的内存，任何信号触发都会导致进程崩溃。
pub(crate) fn uninstall_crash_handlers() {
    let signals = [SIGSEGV, SIGBUS, SIGABRT, SIGFPE, SIGILL, SIGTRAP];

    for &sig in &signals {
        if (sig as usize) >= MAX_SIG {
            continue;
        }
        unsafe {
            let old_fn = OLD_HANDLER_FN[sig as usize].load(Ordering::Acquire);
            let old_flags = OLD_HANDLER_FLAGS[sig as usize].load(Ordering::Acquire);

            let mut sa: sigaction = std::mem::zeroed();
            sa.sa_sigaction = old_fn;
            sa.sa_flags = old_flags as c_int;
            libc::sigemptyset(&mut sa.sa_mask);

            sigaction(sig, &sa, std::ptr::null_mut());
        }
    }
}

/// 安装Rust panic hook，捕获panic并输出带符号的backtrace
pub(crate) fn install_panic_hook() {
    use std::backtrace::Backtrace;

    std::panic::set_hook(Box::new(|panic_info| {
        // 强制捕获backtrace，无视环境变量
        let bt = Backtrace::force_capture();

        // 获取panic位置
        let location = panic_info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "unknown".to_string());

        // 获取panic消息
        let payload = panic_info
            .payload()
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| panic_info.payload().downcast_ref::<String>().map(|s| s.as_str()))
            .unwrap_or("unknown panic");

        let msg = format!(
            "\n\n=== RUST PANIC ===\n\
             Location: {}\n\
             Message: {}\n\
             PID: {}, TID: {}\n\n\
             Backtrace:\n{}\n\
             =================\n\n",
            location,
            payload,
            process::id(),
            unsafe { libc::gettid() },
            bt
        );

        log_msg(msg);
    }));
}
