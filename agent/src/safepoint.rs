//! 全线程 PC/LR 安全点检查
//!
//! 用于 cleanup 前确认没有任何线程的 PC 或 LR 落在 hook_engine 扩展 pool
//! 或 recomp 页范围内，再做 munmap，避免 "pc=lr=unmapped" 崩溃。
//!
//! 机制：
//!   1. 给每个工作线程发 SIGRTMIN+7
//!   2. 信号 handler 读 ucontext 的 pc/x30/sp，并扫描当前活动栈里的返回地址
//!   3. 主线程 spin 等 handler 标记完成，检查 pc/lr/stack 是否在保护区间
//!   4. 任一线程命中区间 → 短暂 sleep 后重试；超时则放弃 munmap (leak)
//!
//! ucontext_t 布局 (aarch64 bionic):
//!   mcontext_t @ +176，regs[31] @ +184 (x0..x30)，sp @ +432，pc @ +440
//!   x30 (LR) @ +184 + 30*8 = +424

use crate::communication::log_msg;
use libc::{
    c_int, c_void, gettid, pid_t, sigaction, sigemptyset, siginfo_t, syscall, SYS_tgkill, SA_RESTART, SA_SIGINFO,
};
use std::fs;
use std::mem::zeroed;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// 用于探测的 RT 信号。Bionic SIGRTMIN=32，+7=39，ART/pthread 未占用
fn probe_signal() -> c_int {
    unsafe { libc::SIGRTMIN() + 7 }
}

static PROBE_INSTALLED: AtomicBool = AtomicBool::new(false);
static PROBE_PC: AtomicU64 = AtomicU64::new(0);
static PROBE_LR: AtomicU64 = AtomicU64::new(0);
static PROBE_SP: AtomicU64 = AtomicU64::new(0);
static PROBE_STACK_HIGH: AtomicU64 = AtomicU64::new(0);
static PROBE_STACK_HITS: AtomicUsize = AtomicUsize::new(0);
static PROBE_STACK_FIRST_HIT: AtomicU64 = AtomicU64::new(0);
static PROBE_DONE: AtomicBool = AtomicBool::new(false);
static PROBE_BUSY: Mutex<()> = Mutex::new(());

const MAX_PROBE_RANGES: usize = 128;
const MAX_STACK_SCAN_BYTES: u64 = 2 * 1024 * 1024;
static PROBE_RANGE_COUNT: AtomicUsize = AtomicUsize::new(0);
static PROBE_RANGE_BASES: [AtomicU64; MAX_PROBE_RANGES] = [const { AtomicU64::new(0) }; MAX_PROBE_RANGES];
static PROBE_RANGE_ENDS: [AtomicU64; MAX_PROBE_RANGES] = [const { AtomicU64::new(0) }; MAX_PROBE_RANGES];

fn strip_addr(addr: u64) -> u64 {
    addr & 0x0000_ffff_ffff_fffc
}

fn signal_in_any_range(addr: u64) -> bool {
    let stripped = strip_addr(addr);
    if stripped == 0 {
        return false;
    }
    let count = PROBE_RANGE_COUNT.load(Ordering::Acquire).min(MAX_PROBE_RANGES);
    for i in 0..count {
        let base = PROBE_RANGE_BASES[i].load(Ordering::Acquire);
        let end = PROBE_RANGE_ENDS[i].load(Ordering::Acquire);
        if base != 0 && stripped >= base && stripped < end {
            return true;
        }
    }
    false
}

fn install_probe_ranges(ranges: &[(u64, u64)]) {
    let count = ranges.len().min(MAX_PROBE_RANGES);
    for i in 0..MAX_PROBE_RANGES {
        if i < count {
            let (base, size) = ranges[i];
            PROBE_RANGE_BASES[i].store(base, Ordering::Release);
            PROBE_RANGE_ENDS[i].store(base.saturating_add(size), Ordering::Release);
        } else {
            PROBE_RANGE_BASES[i].store(0, Ordering::Release);
            PROBE_RANGE_ENDS[i].store(0, Ordering::Release);
        }
    }
    PROBE_RANGE_COUNT.store(count, Ordering::Release);
}

/// 信号 handler：读 PC 和 LR，写入 atomic
extern "C" fn probe_handler(_sig: c_int, _info: *mut siginfo_t, ctx: *mut c_void) {
    if ctx.is_null() {
        PROBE_DONE.store(true, Ordering::SeqCst);
        return;
    }
    unsafe {
        let uc = ctx as *const u8;
        let pc = *(uc.add(176 + 264) as *const u64); // mcontext + 264
        let lr = *(uc.add(176 + 8 + 30 * 8) as *const u64); // regs[30]
        let sp = *(uc.add(176 + 256) as *const u64); // mcontext.sp
        PROBE_PC.store(pc, Ordering::SeqCst);
        PROBE_LR.store(lr, Ordering::SeqCst);
        PROBE_SP.store(sp, Ordering::SeqCst);

        let stack_high = PROBE_STACK_HIGH.load(Ordering::Acquire);
        let mut hits = 0usize;
        let mut first = 0u64;
        if sp != 0 && stack_high > sp {
            let start = (sp & !7) as *const u64;
            let scan_end = stack_high.min(sp.saturating_add(MAX_STACK_SCAN_BYTES)) & !7;
            let words = scan_end.saturating_sub(start as u64) / 8;
            for idx in 0..words {
                let value = core::ptr::read_volatile(start.add(idx as usize));
                if signal_in_any_range(value) {
                    hits = hits.saturating_add(1);
                    if first == 0 {
                        first = value;
                    }
                }
            }
        }
        PROBE_STACK_HITS.store(hits, Ordering::SeqCst);
        PROBE_STACK_FIRST_HIT.store(first, Ordering::SeqCst);
        PROBE_DONE.store(true, Ordering::SeqCst);
    }
}

fn install_probe_handler() {
    if PROBE_INSTALLED.swap(true, Ordering::SeqCst) {
        return;
    }
    unsafe {
        let mut sa: sigaction = zeroed();
        sa.sa_sigaction = probe_handler as *const () as usize;
        sa.sa_flags = SA_SIGINFO | SA_RESTART;
        sigemptyset(&mut sa.sa_mask);
        if sigaction(probe_signal(), &sa, std::ptr::null_mut()) != 0 {
            log_msg(format!(
                "[safepoint] sigaction install failed: errno={}",
                std::io::Error::last_os_error()
            ));
        }
    }
}

/// 一次性对某 tid 发信号并等待 handler 标记，返回 (pc, lr, sp, stack_hits, first_stack_hit)
/// 超时或 tid 已死返回 None
fn probe_one_thread(tid: pid_t, pid: pid_t, stack_high: u64) -> Option<(u64, u64, u64, usize, u64)> {
    PROBE_DONE.store(false, Ordering::SeqCst);
    PROBE_PC.store(0, Ordering::SeqCst);
    PROBE_LR.store(0, Ordering::SeqCst);
    PROBE_SP.store(0, Ordering::SeqCst);
    PROBE_STACK_HIGH.store(stack_high, Ordering::SeqCst);
    PROBE_STACK_HITS.store(0, Ordering::SeqCst);
    PROBE_STACK_FIRST_HIT.store(0, Ordering::SeqCst);
    let sig = probe_signal();
    let rc = unsafe { syscall(SYS_tgkill, pid, tid, sig) };
    if rc != 0 {
        // 线程可能刚退出；忽略
        return None;
    }
    let start = Instant::now();
    loop {
        if PROBE_DONE.load(Ordering::SeqCst) {
            return Some((
                PROBE_PC.load(Ordering::SeqCst),
                PROBE_LR.load(Ordering::SeqCst),
                PROBE_SP.load(Ordering::SeqCst),
                PROBE_STACK_HITS.load(Ordering::SeqCst),
                PROBE_STACK_FIRST_HIT.load(Ordering::SeqCst),
            ));
        }
        if start.elapsed() > Duration::from_millis(50) {
            return None; // 信号未被接收 / 线程阻塞在不可中断状态
        }
        std::hint::spin_loop();
    }
}

fn in_any_range(addr: u64, ranges: &[(u64, u64)]) -> bool {
    let addr = strip_addr(addr);
    if addr == 0 {
        return false;
    }
    for &(base, size) in ranges {
        if addr >= base && addr < base + size {
            return true;
        }
    }
    false
}

fn find_stack_high_for_tid(tid: pid_t) -> Option<u64> {
    let maps = fs::read_to_string(format!("/proc/self/task/{}/maps", tid)).ok()?;
    let marker = format!("stack_and_tls:{}", tid);
    let mut fallback = None;
    for line in maps.lines() {
        if !(line.contains("[stack") || line.contains(&marker)) {
            continue;
        }
        let range = line.split_whitespace().next()?;
        let (_, end) = range.split_once('-')?;
        let high = u64::from_str_radix(end, 16).ok()?;
        if line.contains(&marker) {
            return Some(high);
        }
        fallback = Some(high);
    }
    fallback
}

/// 逐线程检查 PC/LR/活动栈是否落在保护区间。
/// 返回 (ok, busy_pc_hits, busy_lr_hits, busy_stack_hits, first_stack_hit, probed, skipped)
fn check_all_threads(ranges: &[(u64, u64)], scan_stack: bool) -> (bool, usize, usize, usize, u64, usize, usize) {
    let pid = unsafe { libc::getpid() };
    let self_tid = unsafe { gettid() };
    let dir = match fs::read_dir("/proc/self/task") {
        Ok(d) => d,
        Err(_) => return (true, 0, 0, 0, 0, 0, 0),
    };
    let mut pc_hits = 0usize;
    let mut lr_hits = 0usize;
    let mut stack_hits = 0usize;
    let mut first_stack_hit = 0u64;
    let mut probed = 0usize;
    let mut skipped = 0usize;
    for entry in dir.flatten() {
        let name = entry.file_name();
        let s = name.to_string_lossy();
        let tid: pid_t = match s.parse() {
            Ok(n) => n,
            Err(_) => continue,
        };
        if tid == self_tid {
            continue;
        }
        let stack_high = if scan_stack {
            find_stack_high_for_tid(tid).unwrap_or(0)
        } else {
            0
        };
        match probe_one_thread(tid, pid, stack_high) {
            Some((pc, lr, _sp, stack, first)) => {
                probed += 1;
                if in_any_range(pc, ranges) {
                    pc_hits += 1;
                }
                if in_any_range(lr, ranges) {
                    lr_hits += 1;
                }
                stack_hits = stack_hits.saturating_add(stack);
                if first_stack_hit == 0 && first != 0 {
                    first_stack_hit = first;
                }
            }
            None => skipped += 1,
        }
    }
    let ok = pc_hits == 0 && lr_hits == 0 && stack_hits == 0;
    (ok, pc_hits, lr_hits, stack_hits, first_stack_hit, probed, skipped)
}

fn wait_until_clean_impl(ranges: &[(u64, u64)], total_timeout_ms: u64, scan_stack: bool) -> bool {
    if ranges.is_empty() {
        return true;
    }
    install_probe_handler();
    install_probe_ranges(ranges);
    // 同一进程只允许一个 probe 同时跑（PROBE_PC/LR atomic 是共享的）
    let _lock = match PROBE_BUSY.try_lock() {
        Ok(g) => g,
        Err(_) => {
            log_msg("[safepoint] another probe already running, skip".to_string());
            return false;
        }
    };

    let start = Instant::now();
    let mut attempt = 0usize;
    let mut last_report = Instant::now();
    loop {
        attempt += 1;
        let (ok, pc, lr, stack, first_stack, probed, skipped) = check_all_threads(ranges, scan_stack);
        if ok {
            log_msg(format!(
                "[safepoint] clean after {} attempt(s), mode={}, probed={} skipped={}, elapsed={}ms",
                attempt,
                if scan_stack { "pc/lr/stack" } else { "pc/lr" },
                probed,
                skipped,
                start.elapsed().as_millis()
            ));
            return true;
        }
        let elapsed = start.elapsed().as_millis() as u64;
        if elapsed > total_timeout_ms {
            log_msg(format!(
                "[safepoint] TIMEOUT after {}ms (attempt {}) — pc_hits={} lr_hits={} stack_hits={} first_stack={:#x} probed={} skipped={}",
                elapsed, attempt, pc, lr, stack, first_stack, probed, skipped
            ));
            return false;
        }
        // 周期性进度日志（每 200ms）
        if last_report.elapsed() > Duration::from_millis(200) {
            log_msg(format!(
                "[safepoint] still busy after {}ms: pc_hits={} lr_hits={} stack_hits={} first_stack={:#x}",
                elapsed, pc, lr, stack, first_stack
            ));
            last_report = Instant::now();
        }
        crate::raw_thread::sleep_ms(20);
    }
}

/// 等待所有线程 PC/LR 和活动栈离开保护区间。超时返回 false (应放弃 munmap)。
pub fn wait_until_clean(ranges: &[(u64, u64)], total_timeout_ms: u64) -> bool {
    wait_until_clean_impl(ranges, total_timeout_ms, true)
}

/// Native-only hook cleanup 不需要 ART quick stack 的返回地址保护，避免在大型
/// 进程里为 Java/ART 专用场景扫描所有线程栈。
pub fn wait_until_pc_lr_clean(ranges: &[(u64, u64)], total_timeout_ms: u64) -> bool {
    wait_until_clean_impl(ranges, total_timeout_ms, false)
}
