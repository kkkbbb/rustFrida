//! ARM64 页级代码重编译器
//!
//! 用户层职责：
//!   1. 读取原始页代码
//!   2. 重编译到新地址（调整 PC 相对指令）
//!   3. prctl(PR_RECOMPILE_REGISTER) 注册映射
//!
//! 内核层职责（不在本模块）：
//!   - 去掉原始页的 X 权限
//!   - 捕获执行异常，修改 PC 跳转到重编译页（同偏移）
//!
//! 用途：stealth hook — 在重编译页上修改代码，原始页不变。

use crate::communication::log_msg;
use crate::vma_name::set_anon_vma_name_raw;
use libc::{mprotect, munmap, sysconf, PROT_EXEC, PROT_READ, PROT_WRITE, _SC_PAGESIZE};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Error;
use std::os::unix::fs::FileExt;
use std::ptr;
use std::sync::{LazyLock, Mutex};

type Result<T> = std::result::Result<T, String>;

// 内核 prctl 接口
const PR_RECOMPILE_REGISTER: i32 = 0x52430001;
const PR_RECOMPILE_RELEASE: i32 = 0x52430002;

const PAGE_SIZE: usize = 4096;
const MAX_TRAMPOLINE_PAGES: usize = 16; // 远距 recomp 时需要更多跳板空间
const TRAMPOLINE_PAGE_CANDIDATES: &[usize] = &[1, 2, 4, 8, MAX_TRAMPOLINE_PAGES];
const MIN_HOOK_SLOT_BYTES: usize = 32;
const RECOMP_NEAR_RANGE: i64 = 112 * 1024 * 1024; // Keep original-page fallback B within ARM64 imm26 range.

static VMA_RECOMP_CODE: &[u8] = b"wwb_recomp_code\0";
static VMA_RECOMP_TRAMP: &[u8] = b"wwb_recomp_tramp\0";

// C FFI
extern "C" {
    fn recompile_page(
        orig_code: *const u8,
        orig_base: u64,
        recomp_buf: *mut u8,
        recomp_base: u64,
        tramp_buf: *mut u8,
        tramp_base: u64,
        tramp_cap: usize,
        tramp_used: *mut usize,
        suspend_entrypoint: u64,
        translate_existing: Option<unsafe extern "C" fn(u64, *mut libc::c_void) -> u64>,
        translate_user_data: *mut libc::c_void,
        stats: *mut RecompileStatsC,
    ) -> i32;

    fn hook_flush_cache(start: *mut libc::c_void, size: usize);
    fn hook_write_jump(dst: *mut libc::c_void, target: *mut libc::c_void) -> i32;
    fn hook_mmap_near_range(target: *mut libc::c_void, alloc_size: usize, max_range: i64) -> *mut libc::c_void;
    fn hook_register_pool(base: *mut libc::c_void, size: usize) -> i32;
    fn arm64_install_user_patch(
        user_bytes: *const u8,
        user_len: usize,
        user_src_pc: u64,
        slot_buf: *mut u8,
        slot_cap: usize,
        slot_pc: u64,
        fall_through_target: u64,
        orig_page_base: u64,
        recomp_page_base: u64,
        redirect_page_size: usize,
        err_buf: *mut u8,
        err_cap: usize,
    ) -> i32;
    fn hook_rebuild_trampoline(
        trampoline: *mut libc::c_void,
        trampoline_size: usize,
        orig_bytes: *const u8,
        orig_pc: u64,
        jump_back_target: *mut libc::c_void,
    ) -> i32;
}

/// C 侧的 RecompileStats 对应结构
#[repr(C)]
struct RecompileStatsC {
    num_copied: i32,
    num_intra_page: i32,
    num_direct_reloc: i32,
    num_trampolines: i32,
    error: i32,
    error_msg: [u8; 256],
}

impl RecompileStatsC {
    fn new() -> Self {
        RecompileStatsC {
            num_copied: 0,
            num_intra_page: 0,
            num_direct_reloc: 0,
            num_trampolines: 0,
            error: 0,
            error_msg: [0u8; 256],
        }
    }
}

/// 重编译统计信息
pub struct RecompileStats {
    pub num_copied: i32,
    pub num_intra_page: i32,
    pub num_direct_reloc: i32,
    pub num_trampolines: i32,
}

impl From<&RecompileStatsC> for RecompileStats {
    fn from(c: &RecompileStatsC) -> Self {
        RecompileStats {
            num_copied: c.num_copied,
            num_intra_page: c.num_intra_page,
            num_direct_reloc: c.num_direct_reloc,
            num_trampolines: c.num_trampolines,
        }
    }
}

/// alloc_trampoline_slot 保存的原始指令信息
struct SlotInfo {
    /// recomp 代码页上被 B 覆盖的地址
    recomp_addr: usize,
    /// slot 地址（跳板区）
    slot_addr: usize,
    /// 被覆盖前的原始 4 字节指令
    orig_insn: [u8; 4],
    /// slot 字节数；决定能否放进固定 32B free list
    slot_size: usize,
    /// true = 32B 可复用 hook slot；false = writest 变长 slot，不进 free list
    reusable: bool,
}

/// 一个已重编译的页
struct RecompiledPage {
    /// 原始页基地址（用于内核注销时传参）
    #[allow(dead_code)]
    orig_base: usize,
    /// 重编译区域基地址（包含重编译页 + 跳板区）
    recomp_ptr: *mut u8,
    /// 重编译区域总大小
    recomp_total_size: usize,
    /// 跳板区已使用字节数
    tramp_used: usize,
    /// 跳板区总容量（字节）
    tramp_capacity: usize,
    /// 是否已在内核注册
    registered: bool,
    /// 是否从全局 recomp arena 子分配。arena-backed 页不能单独 munmap。
    arena_backed: bool,
    /// slot 分配记录: orig_addr → (recomp_addr, 原始指令)
    slots: HashMap<usize, SlotInfo>,
    /// 回收的 32B hook slot 地址（从 revert_slot_patch 归还），alloc 优先 pop 复用
    free_hook_slots: Vec<usize>,
}

// SAFETY: 指针只在当前进程内使用，由 Mutex 保护
unsafe impl Send for RecompiledPage {}

/// 全局重编译页管理器
static RECOMP_PAGES: Mutex<Option<HashMap<usize, RecompiledPage>>> = Mutex::new(None);
static RECOMP_IN_PROGRESS: LazyLock<Mutex<HashSet<usize>>> = LazyLock::new(|| Mutex::new(HashSet::new()));
static SUSPEND_POLLS_ENTRYPOINT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

struct PendingRecompilePage {
    orig_base: usize,
    recomp_ptr: *mut u8,
    tramp_capacity: usize,
}

pub fn set_suspend_poll_entrypoint(entrypoint: usize) {
    SUSPEND_POLLS_ENTRYPOINT.store(entrypoint as u64, std::sync::atomic::Ordering::Release);
}

fn suspend_poll_entrypoint() -> u64 {
    SUSPEND_POLLS_ENTRYPOINT.load(std::sync::atomic::Ordering::Acquire)
}

fn page_permissions(page: usize) -> Option<(bool, bool)> {
    let Ok(maps) = fs::read_to_string("/proc/self/maps") else {
        return None;
    };

    for line in maps.lines() {
        let mut parts = line.split_whitespace();
        let Some(range) = parts.next() else { continue };
        let Some(perms) = parts.next() else { continue };

        let Some((start, end)) = range.split_once('-') else {
            continue;
        };
        let (Ok(start), Ok(end)) = (usize::from_str_radix(start, 16), usize::from_str_radix(end, 16)) else {
            continue;
        };
        if page >= start && page < end {
            let readable = perms.as_bytes().get(0).is_some_and(|b| *b == b'r');
            let executable = perms.as_bytes().get(2).is_some_and(|b| *b == b'x');
            return Some((readable, executable));
        }
    }

    None
}

fn read_code_page(page: usize, buf: &mut [u8]) -> Result<()> {
    match page_permissions(page) {
        Some((true, true)) => unsafe {
            ptr::copy_nonoverlapping(page as *const u8, buf.as_mut_ptr(), buf.len());
            Ok(())
        },
        Some((false, true)) => {
            let file =
                fs::File::open("/proc/self/mem").map_err(|e| format!("open /proc/self/mem for 0x{:x}: {}", page, e))?;
            let mut done = 0usize;
            while done < buf.len() {
                let n = file
                    .read_at(&mut buf[done..], (page + done) as u64)
                    .map_err(|e| format!("read /proc/self/mem page 0x{:x}: {}", page, e))?;
                if n == 0 {
                    return Err(format!("read /proc/self/mem page 0x{:x}: short read", page));
                }
                done += n;
            }
            Ok(())
        }
        Some((_, false)) => Err(format!("page 0x{:x} is not executable", page)),
        None => Err(format!("page 0x{:x} not found in /proc/self/maps", page)),
    }
}

unsafe extern "C" fn translate_existing_for_recompile(orig_addr: u64, _user_data: *mut libc::c_void) -> u64 {
    translate_addr(orig_addr as usize).unwrap_or(0) as u64
}

struct RecompileInProgressGuard {
    orig_bases: Vec<usize>,
}

impl RecompileInProgressGuard {
    fn enter(orig_base: usize) -> Result<Self> {
        let mut guard = RECOMP_IN_PROGRESS.lock().unwrap();
        if guard.contains(&orig_base) {
            return Err(format!("页 0x{:x} 正在重编译", orig_base));
        }
        guard.insert(orig_base);
        Ok(Self {
            orig_bases: vec![orig_base],
        })
    }
}

impl Drop for RecompileInProgressGuard {
    fn drop(&mut self) {
        let mut guard = RECOMP_IN_PROGRESS.lock().unwrap();
        for orig_base in &self.orig_bases {
            guard.remove(orig_base);
        }
    }
}

fn ensure_init() {
    let mut guard = RECOMP_PAGES.lock().unwrap();
    if guard.is_none() {
        *guard = Some(HashMap::new());
    }
}

fn log_recomp_range(prefix: &str, orig_base: usize, page: &RecompiledPage) {
    let base = page.recomp_ptr as usize;
    let code_end = base.saturating_add(PAGE_SIZE);
    let tramp_end = code_end.saturating_add(page.tramp_capacity);
    log_msg(format!(
        "[recompiler-range] {} orig=0x{:x} code=0x{:x}-0x{:x} tramp=0x{:x}-0x{:x} used={} total={}",
        prefix, orig_base, base, code_end, code_end, tramp_end, page.tramp_used, page.recomp_total_size
    ));
}

fn ensure_slot_in_range(page: &RecompiledPage, slot_addr: usize, slot_size: usize, context: &str) -> Result<()> {
    let tramp_start = page.recomp_ptr as usize + PAGE_SIZE;
    let tramp_end = tramp_start.saturating_add(page.tramp_capacity);
    let slot_end = slot_addr.saturating_add(slot_size);
    if slot_addr < tramp_start || slot_end > tramp_end || slot_end < slot_addr {
        return Err(format!(
            "{} slot 越界: slot=0x{:x}-0x{:x} tramp=0x{:x}-0x{:x}",
            context, slot_addr, slot_end, tramp_start, tramp_end
        ));
    }
    Ok(())
}

fn ensure_recomp_region_writable(page: &RecompiledPage, context: &str) -> Result<()> {
    let rc = unsafe {
        mprotect(
            page.recomp_ptr as *mut _,
            page.recomp_total_size,
            PROT_READ | PROT_WRITE | PROT_EXEC,
        )
    };
    if rc != 0 {
        return Err(format!(
            "{} mprotect(RWX) recomp region 0x{:x}-0x{:x}: {}",
            context,
            page.recomp_ptr as usize,
            page.recomp_ptr as usize + page.recomp_total_size,
            Error::last_os_error()
        ));
    }
    Ok(())
}

fn recompiled_page_exists(orig_base: usize) -> bool {
    let guard = RECOMP_PAGES.lock().unwrap();
    guard.as_ref().is_some_and(|pages| pages.contains_key(&orig_base))
}

fn reserve_recompile_page(orig_base: usize, tramp_pages: usize) -> Result<PendingRecompilePage> {
    let (recomp_ptr, total_size, tramp_capacity) = alloc_recomp_region(orig_base, tramp_pages)?;
    {
        let mut guard = RECOMP_PAGES.lock().unwrap();
        guard.as_mut().unwrap().insert(
            orig_base,
            RecompiledPage {
                orig_base,
                recomp_ptr,
                recomp_total_size: total_size,
                tramp_used: 0,
                tramp_capacity,
                registered: false,
                arena_backed: false,
                slots: HashMap::new(),
                free_hook_slots: Vec::new(),
            },
        );
        if let Some(page) = guard.as_ref().unwrap().get(&orig_base) {
            log_recomp_range("reserve", orig_base, page);
        }
    }

    Ok(PendingRecompilePage {
        orig_base,
        recomp_ptr,
        tramp_capacity,
    })
}

fn is_trampoline_capacity_error(msg: &str) -> bool {
    msg.contains("跳板区空间不足") || msg.contains("reserved hook slot insufficient")
}

fn reserve_and_compile_page(
    orig_base: usize,
    orig_code: &[u8],
) -> Result<(PendingRecompilePage, usize, RecompileStatsC)> {
    let mut last_error = None;

    for &tramp_pages in TRAMPOLINE_PAGE_CANDIDATES {
        let pending = match reserve_recompile_page(orig_base, tramp_pages) {
            Ok(pending) => pending,
            Err(e) => {
                if tramp_pages == MAX_TRAMPOLINE_PAGES {
                    return Err(e);
                }
                log_msg(format!(
                    "[recompiler] mmap near recomp region failed (tramp_pages={}): {}",
                    tramp_pages, e
                ));
                last_error = Some(e);
                continue;
            }
        };

        let compile_result =
            compile_reserved_page(pending.orig_base, orig_code, pending.recomp_ptr, pending.tramp_capacity).and_then(
                |(tramp_used, stats)| {
                    if pending.tramp_capacity.saturating_sub(tramp_used) >= MIN_HOOK_SLOT_BYTES {
                        Ok((tramp_used, stats))
                    } else {
                        Err(format!(
                            "reserved hook slot insufficient (tramp_used={} tramp_capacity={})",
                            tramp_used, pending.tramp_capacity
                        ))
                    }
                },
            );

        match compile_result {
            Ok((tramp_used, stats)) => return Ok((pending, tramp_used, stats)),
            Err(e) => {
                rollback_reserved_recompile_pages(std::slice::from_ref(&pending));
                if !is_trampoline_capacity_error(&e) || tramp_pages == MAX_TRAMPOLINE_PAGES {
                    return Err(e);
                }
                log_msg(format!(
                    "[recompiler] tramp_pages={} 不足，升级跳板区后重试: 0x{:x} ({})",
                    tramp_pages, orig_base, e
                ));
                last_error = Some(e);
            }
        }
    }

    Err(last_error.unwrap_or_else(|| "重编译失败: 未找到可用的跳板区配置".to_string()))
}

fn rollback_reserved_recompile_pages(pending: &[PendingRecompilePage]) {
    if pending.is_empty() {
        return;
    }

    let mut guard = RECOMP_PAGES.lock().unwrap();
    let Some(pages) = guard.as_mut() else {
        return;
    };
    for page in pending {
        if let Some(removed) = pages.remove(&page.orig_base) {
            if !removed.arena_backed {
                unsafe {
                    munmap(removed.recomp_ptr as *mut _, removed.recomp_total_size);
                }
            }
        }
    }
    log_msg(format!(
        "[recompiler] rollback {} reserved recomp page(s)",
        pending.len()
    ));
}

fn register_recompile_page(orig_base: usize, recomp_base: u64) -> Result<()> {
    let rc = unsafe { libc::prctl(PR_RECOMPILE_REGISTER, 0u64, orig_base as u64, recomp_base, 0u64) };
    if rc == 0 {
        log_msg(format!(
            "[recompiler] prctl 注册成功: 0x{:x} → 0x{:x}",
            orig_base, recomp_base
        ));
        return Ok(());
    }

    let err = Error::last_os_error();
    if err.raw_os_error() != Some(libc::EEXIST) {
        return Err(format!("recomp prctl 注册失败: {}", err));
    }

    log_msg(format!(
        "[recompiler] prctl register EEXIST: release stale mapping for 0x{:x} then retry",
        orig_base
    ));
    let release_rc = unsafe { libc::prctl(PR_RECOMPILE_RELEASE, 0u64, orig_base as u64, 0u64, 0u64) };
    if release_rc != 0 {
        return Err(format!(
            "recomp stale release failed for 0x{:x}: {}",
            orig_base,
            Error::last_os_error()
        ));
    }

    let retry_rc = unsafe { libc::prctl(PR_RECOMPILE_REGISTER, 0u64, orig_base as u64, recomp_base, 0u64) };
    if retry_rc != 0 {
        return Err(format!("recomp prctl 注册重试失败: {}", Error::last_os_error()));
    }

    log_msg(format!(
        "[recompiler] prctl 注册成功(after stale release): 0x{:x} → 0x{:x}",
        orig_base, recomp_base
    ));
    Ok(())
}

/// 重编译指定地址所在的页
///
/// - `addr`: 页内任意地址（自动对齐到页边界）
/// - `pid`: 目标进程 pid（0 = 当前进程）
///
/// 返回重编译页的基地址和统计信息
pub fn recompile(addr: usize, pid: u32) -> Result<(usize, RecompileStats)> {
    let _ = pid;
    ensure_init();

    let orig_base = addr & !(PAGE_SIZE - 1);

    if recompiled_page_exists(orig_base) {
        return Err(format!("页 0x{:x} 已重编译", orig_base));
    }

    let _in_progress = RecompileInProgressGuard::enter(orig_base)?;
    let mut orig_code = vec![0u8; PAGE_SIZE];
    read_code_page(orig_base, &mut orig_code)?;

    let (pending, tramp_used, stats_c) = reserve_and_compile_page(orig_base, &orig_code)?;

    let stats = RecompileStats::from(&stats_c);
    let recomp_base = pending.recomp_ptr as u64;

    let tramp_ptr = unsafe { pending.recomp_ptr.add(PAGE_SIZE) };
    let _ = set_anon_vma_name_raw(pending.recomp_ptr, PAGE_SIZE, VMA_RECOMP_CODE);
    let _ = set_anon_vma_name_raw(tramp_ptr, pending.tramp_capacity, VMA_RECOMP_TRAMP);

    unsafe {
        hook_flush_cache(pending.recomp_ptr as *mut _, PAGE_SIZE + tramp_used);
    }

    log_msg(format!(
        "[recompiler] 0x{:x} → 0x{:x} | copied={} intra={} reloc={} tramp={} tramp_bytes={}",
        pending.orig_base,
        recomp_base,
        stats.num_copied,
        stats.num_intra_page,
        stats.num_direct_reloc,
        stats.num_trampolines,
        tramp_used,
    ));

    if let Err(e) = register_recompile_page(pending.orig_base, recomp_base) {
        rollback_reserved_recompile_pages(std::slice::from_ref(&pending));
        return Err(e);
    }

    let mut guard = RECOMP_PAGES.lock().unwrap();
    let pages = guard
        .as_mut()
        .ok_or_else(|| "recomp pages not initialized".to_string())?;
    let page = pages
        .get_mut(&pending.orig_base)
        .ok_or_else(|| format!("页 0x{:x} 未重编译", pending.orig_base))?;

    page.tramp_used = tramp_used;
    page.registered = true;
    log_recomp_range("compiled", pending.orig_base, page);

    Ok((recomp_base as usize, stats))
}

/// 释放重编译页
pub fn release(addr: usize, _pid: u32) -> Result<()> {
    ensure_init();

    let page_size = unsafe { sysconf(_SC_PAGESIZE) as usize };
    let orig_base = addr & !(page_size - 1);

    let mut guard = RECOMP_PAGES.lock().unwrap();
    let pages = guard.as_mut().unwrap();

    let page = pages
        .remove(&orig_base)
        .ok_or_else(|| format!("页 0x{:x} 未重编译", orig_base))?;

    // 从内核注销（pid=0 表示当前进程）
    if page.registered {
        unsafe {
            libc::prctl(PR_RECOMPILE_RELEASE, 0u64, orig_base as u64, 0u64, 0u64);
        }
    }

    if !page.arena_backed {
        unsafe {
            munmap(page.recomp_ptr as *mut _, page.recomp_total_size);
        }
    }

    log_msg(format!("[recompiler] 释放 0x{:x}", orig_base));
    Ok(())
}

/// 释放所有重编译页（agent cleanup 时调用）
///
/// 注销所有 prctl 注册 + munmap。释放后内核不再重定向执行到 recomp 页，
/// 原始页恢复 X 权限，代码从原始位置正常执行。
pub fn release_all() {
    ensure_init();

    let mut guard = RECOMP_PAGES.lock().unwrap();
    let pages = match guard.as_mut() {
        Some(p) => p,
        None => return,
    };

    let mut snapshot = Vec::with_capacity(pages.len());
    let mut release_ok = 0usize;
    let mut release_fail = 0usize;
    for (orig_base, page) in pages.iter_mut() {
        if page.registered {
            let rc = unsafe { libc::prctl(PR_RECOMPILE_RELEASE, 0u64, *orig_base as u64, 0u64, 0u64) };
            if rc == 0 {
                release_ok += 1;
                page.registered = false;
            } else {
                release_fail += 1;
                log_msg(format!(
                    "[recompiler] release_all: PR_RECOMPILE_RELEASE failed base=0x{:x} errno={}\n",
                    *orig_base,
                    std::io::Error::last_os_error()
                ));
            }
        }
        // arena-backed recomp 页不能单独 munmap。保留映射表，直到 safepoint
        // 后统一释放 arena；WalkStack guard 在等待期间仍可反向翻译 PC。
        if !page.arena_backed {
            snapshot.push((page.recomp_ptr as u64, page.recomp_total_size as u64));
        }
    }
    let mut retained = RETAINED_RANGES.lock().unwrap();
    retained.clear();
    retained.extend(snapshot.iter().cloned());
    log_msg(format!(
        "[recompiler] release_all: snapshot {} recomp range(s) for caller-side munmap (release_ok={} fail={})",
        snapshot.len(),
        release_ok,
        release_fail
    ));
}

/// 全局保留：release_all 快照的 recomp 页区间 (base, size)。
/// 由 quickjs_loader 的 safepoint 路径读取并 munmap。
static RETAINED_RANGES: Mutex<Vec<(u64, u64)>> = Mutex::new(Vec::new());

/// 获取上次 release_all 快照的 recomp 页区间列表
pub fn get_retained_ranges() -> Vec<(u64, u64)> {
    RETAINED_RANGES.lock().unwrap().clone()
}

/// Rust 侧完成 munmap 后清空快照
pub fn clear_retained_ranges() {
    RETAINED_RANGES.lock().unwrap().clear();
}

/// munmap 已快照的 recomp 页。调用者必须已通过 safepoint 验证无线程 PC 驻留。
/// 返回 (munmap 成功数, 失败数, 释放字节数)
pub unsafe fn munmap_retained_ranges() -> (usize, usize, u64) {
    let ranges: Vec<(u64, u64)> = RETAINED_RANGES.lock().unwrap().drain(..).collect();
    let mut unmapped = Vec::with_capacity(ranges.len());
    let mut ok = 0usize;
    let mut fail = 0usize;
    let mut bytes = 0u64;
    for &(base, size) in &ranges {
        if munmap(base as *mut _, size as usize) == 0 {
            ok += 1;
            bytes += size;
            unmapped.push((base, size));
        } else {
            fail += 1;
        }
    }
    if ok > 0 {
        let mut guard = RECOMP_PAGES.lock().unwrap();
        if let Some(pages) = guard.as_mut() {
            pages.retain(|_, page| {
                let base = page.recomp_ptr as u64;
                !unmapped.iter().any(|(range_base, range_size)| {
                    let end = range_base.saturating_add(*range_size);
                    base >= *range_base && base < end
                })
            });
        }
    }
    (ok, fail, bytes)
}

/// 获取重编译页的可写指针（用于 hook 修改代码）
///
/// 调用方负责：修改前 mprotect RWX，修改后 mprotect RX + flush icache
pub fn get_recomp_ptr(addr: usize) -> Result<*mut u8> {
    ensure_init();

    let page_size = unsafe { sysconf(_SC_PAGESIZE) as usize };
    let orig_base = addr & !(page_size - 1);

    let guard = RECOMP_PAGES.lock().unwrap();
    let pages = guard.as_ref().unwrap();

    let page = pages
        .get(&orig_base)
        .ok_or_else(|| format!("页 0x{:x} 未重编译", orig_base))?;

    Ok(page.recomp_ptr)
}

/// 确保地址所在页已重编译，返回翻译后的地址
/// 供 quickjs-hook 的 JS hook API 通过回调调用
pub fn ensure_and_translate(addr: usize) -> Result<usize> {
    ensure_init();

    let page_size = unsafe { sysconf(_SC_PAGESIZE) as usize };
    let orig_base = addr & !(page_size - 1);

    // 如果还没重编译，先重编译
    let need_recomp = {
        let guard = RECOMP_PAGES.lock().unwrap();
        !guard.as_ref().unwrap().contains_key(&orig_base)
    };

    if need_recomp {
        recompile(addr, 0)?;
    }

    translate_addr(addr)
}

/// 获取地址在重编译页中的对应地址
pub fn translate_addr(addr: usize) -> Result<usize> {
    ensure_init();

    let page_size = unsafe { sysconf(_SC_PAGESIZE) as usize };
    let orig_base = addr & !(page_size - 1);
    let offset = addr - orig_base;

    let guard = RECOMP_PAGES.lock().unwrap();
    let pages = guard.as_ref().unwrap();

    let page = pages
        .get(&orig_base)
        .ok_or_else(|| format!("页 0x{:x} 未重编译", orig_base))?;

    Ok(page.recomp_ptr as usize + offset)
}

/// 将 recomp 页里的 PC 反向翻译回原始 OAT PC。
pub fn translate_recomp_to_orig(addr: usize) -> Option<usize> {
    ensure_init();

    let guard = RECOMP_PAGES.lock().ok()?;
    let pages = guard.as_ref()?;

    for page in pages.values() {
        let base = page.recomp_ptr as usize;
        let end = base.saturating_add(PAGE_SIZE);
        if addr >= base && addr < end {
            return Some(page.orig_base + (addr - base));
        }
    }
    None
}

pub fn patch_suspend_polls(orig_addr: usize, implicit_suspend_entry: usize) -> Result<()> {
    if implicit_suspend_entry == 0 {
        return Ok(());
    }
    set_suspend_poll_entrypoint(implicit_suspend_entry);
    if orig_addr == 0 {
        return Ok(());
    }

    ensure_init();

    let orig_base = orig_addr & !(PAGE_SIZE - 1);
    let mut guard = RECOMP_PAGES.lock().unwrap();
    let pages = guard
        .as_mut()
        .ok_or_else(|| "recomp pages not initialized".to_string())?;
    let page = pages
        .get_mut(&orig_base)
        .ok_or_else(|| format!("页 0x{:x} 未重编译", orig_base))?;

    let tramp_base = unsafe { page.recomp_ptr.add(PAGE_SIZE) };
    let tramp_cap = page.tramp_capacity;
    let mut patched = 0usize;
    ensure_recomp_region_writable(page, "patch_suspend_polls")?;

    for offset in (0..PAGE_SIZE).step_by(4) {
        let orig_insn = unsafe { ptr::read_unaligned((orig_base + offset) as *const u32) };
        if orig_insn != 0xf940_02b5 {
            continue;
        }

        let recomp_code_addr = unsafe { page.recomp_ptr.add(offset) as usize };
        let current = unsafe { ptr::read_unaligned(recomp_code_addr as *const u32) };
        if current != 0xf940_02b5 {
            // recompile_page() may already have translated this implicit
            // suspend poll into a guard trampoline. Do not overwrite a
            // non-original instruction here.
            continue;
        }

        page.tramp_used = (page.tramp_used + 7) & !7;
        let slot_size = 56usize;
        if page.tramp_used + slot_size > tramp_cap {
            return Err("recomp 跳板区已满，无法 patch suspend poll".into());
        }

        let slot_ptr = unsafe { tramp_base.add(page.tramp_used) };
        let slot_addr = slot_ptr as usize;
        ensure_slot_in_range(page, slot_addr, slot_size, "suspend poll")?;
        let orig_next = (orig_base + offset + 4) as u64;
        let recomp_next = (recomp_code_addr + 4) as u64;

        let b_offset = (slot_addr as i64) - (recomp_code_addr as i64);
        if b_offset < -(1 << 27) || b_offset >= (1 << 27) {
            return Err(format!("suspend poll B 指令范围超限: offset={}", b_offset));
        }
        let b_imm26 = ((b_offset >> 2) & 0x03ff_ffff) as u32;
        let b_insn = 0x1400_0000 | b_imm26;

        unsafe {
            let w = slot_ptr as *mut u32;
            // Preserve ART's implicit suspend-check semantics:
            //   if (x21 != 0) { ldr x21, [x21]; goto recomp_next; }
            //   lr = orig_next; goto art_quick_test_suspend;
            // The normal path must not call into ART; GC threads can execute
            // suspend polls while holding runtime locks.
            ptr::write_unaligned(w.add(0), 0xb500_0095); // cbnz x21, +16
            ptr::write_unaligned(w.add(1), 0x5800_00fe); // ldr x30, #28 -> orig_next
            ptr::write_unaligned(w.add(2), 0x5800_0110); // ldr x16, #32 -> entry
            ptr::write_unaligned(w.add(3), 0xd61f_0200); // br x16
            ptr::write_unaligned(w.add(4), 0xf940_02b5); // ldr x21, [x21]
            ptr::write_unaligned(w.add(5), 0x5800_00f0); // ldr x16, #28 -> recomp_next
            ptr::write_unaligned(w.add(6), 0xd61f_0200); // br x16
            ptr::write_unaligned(w.add(7), 0xd503_201f); // nop / align literals
            ptr::write_unaligned(w.add(8) as *mut u64, orig_next);
            ptr::write_unaligned(w.add(10) as *mut u64, implicit_suspend_entry as u64);
            ptr::write_unaligned(w.add(12) as *mut u64, recomp_next);
            ptr::write_volatile(recomp_code_addr as *mut u32, b_insn);
            hook_flush_cache(slot_ptr as *mut _, slot_size);
            hook_flush_cache(recomp_code_addr as *mut _, 4);
        }

        page.tramp_used += slot_size;
        patched += 1;
    }

    log_msg(format!(
        "[recompiler] patched {} suspend poll(s) on 0x{:x} -> suspend_entry={:#x}",
        patched, orig_base, implicit_suspend_entry
    ));
    Ok(())
}

/// 在重编译页上 patch 指令
///
/// `addr`: 原始地址（自动翻译到重编译页对应偏移）
/// `insns`: 要写入的指令（u32 数组）
pub fn patch_insns(addr: usize, insns: &[u32]) -> Result<()> {
    ensure_init();

    let page_size = unsafe { sysconf(_SC_PAGESIZE) as usize };
    let orig_base = addr & !(page_size - 1);
    let offset = addr - orig_base;

    let guard = RECOMP_PAGES.lock().unwrap();
    let pages = guard.as_ref().unwrap();

    let page = pages
        .get(&orig_base)
        .ok_or_else(|| format!("页 0x{:x} 未重编译", orig_base))?;

    let patch_size = insns.len() * 4;
    if offset + patch_size > PAGE_SIZE {
        return Err("patch 超出页边界".into());
    }
    ensure_recomp_region_writable(page, "patch_insns")?;

    unsafe {
        let dst = page.recomp_ptr.add(offset) as *mut u32;
        for (i, &insn) in insns.iter().enumerate() {
            ptr::write_volatile(dst.add(i), insn);
        }
        hook_flush_cache(page.recomp_ptr.add(offset) as *mut _, patch_size);
    }

    Ok(())
}

/// 在 recomp 页的跳板区分配 slot 并写入跳转，在代码页写 B 指令。
///
/// 保持 recomp 页 offset 一一对应：代码页只改 1 条指令（B tramp_slot），
/// 完整跳转（ADRP+ADD+BR 或 MOVZ+MOVK+BR）写在跳板区。
///
/// `orig_addr`: 原始代码地址（自动翻译到 recomp 页偏移）
/// `jump_dest`: 跳转目标（如 router thunk）
/// 返回 recomp 页内被 patch 的地址（供调用方记录）
pub fn patch_with_trampoline(orig_addr: usize, jump_dest: usize) -> Result<usize> {
    ensure_init();

    let page_size = unsafe { sysconf(_SC_PAGESIZE) as usize };
    let orig_base = orig_addr & !(page_size - 1);
    let offset = orig_addr - orig_base;

    let mut guard = RECOMP_PAGES.lock().unwrap();
    let pages = guard.as_mut().unwrap();

    let page = pages
        .get_mut(&orig_base)
        .ok_or_else(|| format!("页 0x{:x} 未重编译", orig_base))?;
    ensure_recomp_region_writable(page, "patch_with_trampoline")?;

    // 跳板区在 recomp 页之后 (recomp_ptr + PAGE_SIZE)
    let tramp_base = unsafe { page.recomp_ptr.add(PAGE_SIZE) };
    let tramp_cap = page.tramp_capacity;
    let slot_size = 20usize; // ADRP+ADD+BR (12) 或 MOVZ+MOVK+BR (16)，留 20 足够
    if page.tramp_used + slot_size > tramp_cap {
        return Err("recomp 跳板区已满".into());
    }

    let slot_ptr = unsafe { tramp_base.add(page.tramp_used) };
    let slot_addr = slot_ptr as usize;
    ensure_slot_in_range(page, slot_addr, slot_size, "patch_with_trampoline")?;

    unsafe {
        // 1. 在跳板 slot 写 full jump → jump_dest
        let jump_len = hook_write_jump(slot_ptr as *mut _, jump_dest as *mut _);
        if jump_len <= 0 {
            return Err(format!("hook_write_jump failed: {}", jump_len));
        }

        // 2. 在 recomp 代码页写 B slot（ARM64 B imm26: ±128MB）
        let recomp_code_addr = page.recomp_ptr.add(offset) as usize;
        let b_offset = (slot_addr as i64) - (recomp_code_addr as i64);
        if b_offset < -(1 << 27) || b_offset >= (1 << 27) {
            return Err(format!("B 指令范围超限: offset={}", b_offset));
        }
        let b_imm26 = ((b_offset >> 2) & 0x3FF_FFFF) as u32;
        let b_insn: u32 = 0x14000000 | b_imm26;
        ptr::write_volatile(recomp_code_addr as *mut u32, b_insn);

        hook_flush_cache(slot_ptr as *mut _, jump_len as usize);
        hook_flush_cache(recomp_code_addr as *mut _, 4);
    }

    page.tramp_used += slot_size;
    Ok(unsafe { page.recomp_ptr.add(offset) as usize })
}

/// 在 recomp 跳板区分配 slot，在 recomp 代码页写 B 指令指向 slot。
/// 返回 slot 地址（hook engine 后续在 slot 上写 full jump→thunk）。
///
/// 调用链: recomp 代码页[offset] → B slot → (hook engine 写) full jump → thunk
pub fn alloc_trampoline_slot(orig_addr: usize) -> Result<usize> {
    ensure_init();

    let page_size = unsafe { sysconf(_SC_PAGESIZE) as usize };
    let orig_base = orig_addr & !(page_size - 1);
    let offset = orig_addr - orig_base;

    let mut guard = RECOMP_PAGES.lock().unwrap();
    let pages = guard.as_mut().unwrap();

    let page = pages
        .get_mut(&orig_base)
        .ok_or_else(|| format!("页 0x{:x} 未重编译", orig_base))?;

    // 跳板区在 recomp 页之后
    let tramp_base = unsafe { page.recomp_ptr.add(PAGE_SIZE) };
    let slot_size = 32usize; // 预留足够空间给 hook engine 写 full jump + trampoline

    // 优先复用 unhook 归还的 slot；否则 bump tramp_used。
    // 不清零 —— hook engine 在 slot 上写 full jump 覆盖前 16~20B, fixup_slot_trampoline
    // 会用 SlotInfo.orig_insn 重建 callOriginal trampoline 不依赖 slot 内容。
    let slot_addr = if let Some(reused) = page.free_hook_slots.pop() {
        reused
    } else {
        if page.tramp_used + slot_size > page.tramp_capacity {
            return Err("recomp 跳板区已满".into());
        }
        let s = unsafe { tramp_base.add(page.tramp_used) as usize };
        ensure_slot_in_range(page, s, slot_size, "alloc_trampoline_slot")?;
        page.tramp_used += slot_size;
        s
    };
    ensure_slot_in_range(page, slot_addr, slot_size, "alloc_trampoline_slot")?;

    let recomp_code_addr = unsafe { page.recomp_ptr.add(offset) as usize };

    // 保存 recomp 代码页上将被 B 覆盖的原始指令
    let mut orig_insn = [0u8; 4];
    unsafe {
        ptr::copy_nonoverlapping(recomp_code_addr as *const u8, orig_insn.as_mut_ptr(), 4);
    }

    // B 指令范围预检查（commit_slot_patch 时才真正写入）
    let b_offset = (slot_addr as i64) - (recomp_code_addr as i64);
    if b_offset < -(1 << 27) || b_offset >= (1 << 27) {
        return Err(format!("B 指令范围超限: offset={}", b_offset));
    }

    page.slots.insert(
        orig_addr,
        SlotInfo {
            recomp_addr: recomp_code_addr,
            slot_addr,
            orig_insn,
            slot_size,
            reusable: true,
        },
    );
    log_msg(format!(
        "[recompiler-slot] orig=0x{:x} recomp=0x{:x} slot=0x{:x} size={} used={}/{}",
        orig_addr, recomp_code_addr, slot_addr, slot_size, page.tramp_used, page.tramp_capacity
    ));
    // 注意: 此时 recomp 代码页上的原始指令未被修改，slot 已分配但内容是 0。
    // 调用方必须在 hook engine 写好 thunk + fixup trampoline 后调用 commit_slot_patch。
    Ok(slot_addr)
}

/// 在 recomp 页对应位置安装 "1 指令 → N 指令" 用户 patch (writest stealth-2)。
///
/// 步骤：
/// 1. 分配 slot（足够大小：patch + reloc 膨胀 + fall-through B）
/// 2. 通过 arm64_install_user_patch 把 user_bytes relocate 到 slot，末尾追加
///    `B → recomp_addr + 4`（除非 patch 本身以 RET/B 等无条件终止）
/// 3. flush_cache 整个 slot
/// 4. 原子写 recomp 页对应 4 字节为 `B → slot`
///
/// 原页始终不动，取指通过 prctl 重定向到 recomp 页 → B→slot → reloc 后 patch。
pub fn install_patch(orig_addr: usize, user_bytes: &[u8]) -> Result<()> {
    ensure_init();

    if orig_addr % 4 != 0 {
        return Err("orig_addr must be 4-byte aligned".into());
    }
    if user_bytes.is_empty() || user_bytes.len() % 4 != 0 {
        return Err("patch must be non-empty and 4-byte multiple".into());
    }

    let page_size = unsafe { sysconf(_SC_PAGESIZE) as usize };
    let orig_base = orig_addr & !(page_size - 1);
    let offset = orig_addr - orig_base;

    let mut guard = RECOMP_PAGES.lock().unwrap();
    let pages = guard.as_mut().unwrap();

    let page = pages
        .get_mut(&orig_base)
        .ok_or_else(|| format!("页 0x{:x} 未重编译", orig_base))?;
    ensure_recomp_region_writable(page, "install_patch")?;

    if page.slots.contains_key(&orig_addr) {
        return Err(format!("地址 0x{:x} 已被占用（hook 或 patch 已在位）", orig_addr));
    }

    // Reloc 最坏情况：每条 PC-rel 指令膨胀到 ~20 字节（ADRP→MOVZ+MOVK*3）。
    // 预留 user_len × 5 + 20 字节（fall-through put_b_safe 兜底）。
    let slot_size_raw = user_bytes.len().saturating_mul(5).saturating_add(32);
    let slot_size = (slot_size_raw + 15) & !15;

    let tramp_base = unsafe { page.recomp_ptr.add(PAGE_SIZE) };
    if page.tramp_used + slot_size > page.tramp_capacity {
        return Err(format!(
            "recomp 跳板区已满 (need {} bytes, avail {})",
            slot_size,
            page.tramp_capacity - page.tramp_used
        ));
    }

    let slot_ptr = unsafe { tramp_base.add(page.tramp_used) };
    let slot_addr = slot_ptr as usize;
    let recomp_code_addr = unsafe { page.recomp_ptr.add(offset) as usize };
    ensure_slot_in_range(page, slot_addr, slot_size, "install_patch")?;

    // 备份被覆盖的 4 字节原始指令（供 unhook 恢复）
    let mut orig_insn = [0u8; 4];
    unsafe {
        ptr::copy_nonoverlapping(recomp_code_addr as *const u8, orig_insn.as_mut_ptr(), 4);
    }

    // B 指令范围预检查
    let b_offset = (slot_addr as i64) - (recomp_code_addr as i64);
    if b_offset < -(1 << 27) || b_offset >= (1 << 27) {
        return Err(format!("B range exceeded: offset={}", b_offset));
    }

    // Relocate user patch into slot via C helper
    let mut err_buf = [0u8; 128];
    let fall_through_target = (recomp_code_addr + 4) as u64;
    let recomp_page_base_addr = page.recomp_ptr as u64;
    let written = unsafe {
        arm64_install_user_patch(
            user_bytes.as_ptr(),
            user_bytes.len(),
            orig_addr as u64,
            slot_ptr,
            slot_size,
            slot_addr as u64,
            fall_through_target,
            orig_base as u64,
            recomp_page_base_addr,
            PAGE_SIZE,
            err_buf.as_mut_ptr(),
            err_buf.len(),
        )
    };
    if written < 0 {
        let nul = err_buf.iter().position(|&b| b == 0).unwrap_or(err_buf.len());
        let msg = std::str::from_utf8(&err_buf[..nul]).unwrap_or("?");
        return Err(format!("arm64_install_user_patch: {}", msg));
    }

    unsafe {
        hook_flush_cache(slot_ptr as *mut _, written as usize);
    }

    page.tramp_used += slot_size;
    page.slots.insert(
        orig_addr,
        SlotInfo {
            recomp_addr: recomp_code_addr,
            slot_addr,
            orig_insn,
            slot_size,
            reusable: false, // writest 变长 slot，不进 free list
        },
    );

    // 原子写 B→slot
    let b_imm26 = ((b_offset >> 2) & 0x3FF_FFFF) as u32;
    let b_insn: u32 = 0x14000000 | b_imm26;
    unsafe {
        ptr::write_volatile(recomp_code_addr as *mut u32, b_insn);
        hook_flush_cache(recomp_code_addr as *mut libc::c_void, 4);
    }

    Ok(())
}

/// 在 recomp 代码页上写 B→slot 指令（原子 4 字节写入）。
///
/// 必须在 hook engine 已将 thunk 写入 slot 之后调用。
/// B 指令写入后，其他线程执行到此处会立即跳到 slot 里的 thunk。
pub fn commit_slot_patch(orig_addr: usize) -> Result<()> {
    ensure_init();

    let page_size = unsafe { sysconf(_SC_PAGESIZE) as usize };
    let orig_base = orig_addr & !(page_size - 1);

    let guard = RECOMP_PAGES.lock().unwrap();
    let pages = guard.as_ref().unwrap();

    let page = match pages.get(&orig_base) {
        Some(p) => p,
        None => return Ok(()),
    };
    ensure_recomp_region_writable(page, "commit_slot_patch")?;

    let info = match page.slots.get(&orig_addr) {
        Some(i) => i,
        None => return Ok(()),
    };

    let recomp_code_addr = info.recomp_addr;
    let slot_addr = info.slot_addr;
    let b_offset = (slot_addr as i64) - (recomp_code_addr as i64);
    let b_imm26 = ((b_offset >> 2) & 0x3FF_FFFF) as u32;
    let b_insn: u32 = 0x14000000 | b_imm26;

    unsafe {
        // 原子 4 字节写入 + icache flush
        ptr::write_volatile(recomp_code_addr as *mut u32, b_insn);
        hook_flush_cache(recomp_code_addr as *mut libc::c_void, 4);
    }

    Ok(())
}

/// 恢复 recomp 代码页上被 B 覆盖的原始指令（unhook 时调用）。
///
/// commit_slot_patch 写入 B→slot，本函数做逆操作：
/// 从 SlotInfo.orig_insn 恢复被覆盖的 4 字节原始指令，并移除 slot 记录。
/// 同 `revert_slot_patch`, 但返回 bool: true = 有 slot 被清；false = 该地址没 slot 记录.
/// 供 js_unhook 判断"是否真的 revert 了 writest/hook"。
pub fn try_revert_slot_patch(orig_addr: usize) -> bool {
    ensure_init();
    let page_size = unsafe { sysconf(_SC_PAGESIZE) as usize };
    let orig_base = orig_addr & !(page_size - 1);
    let mut guard = RECOMP_PAGES.lock().unwrap();
    let pages = match guard.as_mut() {
        Some(p) => p,
        None => return false,
    };
    let page = match pages.get_mut(&orig_base) {
        Some(p) => p,
        None => return false,
    };
    if let Err(e) = ensure_recomp_region_writable(page, "try_revert_slot_patch") {
        log_msg(format!("[recompiler] {}", e));
        return false;
    }
    let info = match page.slots.remove(&orig_addr) {
        Some(i) => i,
        None => return false,
    };
    unsafe {
        ptr::write_volatile(info.recomp_addr as *mut u32, u32::from_le_bytes(info.orig_insn));
        hook_flush_cache(info.recomp_addr as *mut libc::c_void, 4);
    }
    if info.reusable {
        page.free_hook_slots.push(info.slot_addr);
    }
    true
}

/// Restore a committed hook slot by its slot address.
///
/// ART controller hooks store the address actually passed to hook_engine as the
/// target. In recomp stealth mode that target is the 32-byte slot, while the
/// branch that reaches it lives at the translated original PC. Cleanup must
/// restore that branch before freeing hook pools.
pub fn try_revert_slot_patch_by_slot(slot_addr: usize) -> bool {
    ensure_init();

    let mut guard = RECOMP_PAGES.lock().unwrap();
    let pages = match guard.as_mut() {
        Some(p) => p,
        None => return false,
    };

    for page in pages.values_mut() {
        let orig_addr = page
            .slots
            .iter()
            .find_map(|(&orig, info)| (info.slot_addr == slot_addr).then_some(orig));
        let Some(orig_addr) = orig_addr else {
            continue;
        };
        if let Err(e) = ensure_recomp_region_writable(page, "try_revert_slot_patch_by_slot") {
            log_msg(format!("[recompiler] {}", e));
            return false;
        }
        let Some(info) = page.slots.remove(&orig_addr) else {
            return false;
        };
        unsafe {
            ptr::write_volatile(info.recomp_addr as *mut u32, u32::from_le_bytes(info.orig_insn));
            hook_flush_cache(info.recomp_addr as *mut libc::c_void, 4);
        }
        if info.reusable {
            page.free_hook_slots.push(info.slot_addr);
        }
        return true;
    }

    false
}

pub fn revert_slot_patch(orig_addr: usize) -> Result<()> {
    ensure_init();

    let page_size = unsafe { sysconf(_SC_PAGESIZE) as usize };
    let orig_base = orig_addr & !(page_size - 1);

    let mut guard = RECOMP_PAGES.lock().unwrap();
    let pages = guard.as_mut().unwrap();

    let page = match pages.get_mut(&orig_base) {
        Some(p) => p,
        None => return Ok(()), // 非 recomp 模式
    };
    ensure_recomp_region_writable(page, "revert_slot_patch")?;

    let info = match page.slots.remove(&orig_addr) {
        Some(i) => i,
        None => return Ok(()), // 无 slot 记录
    };

    unsafe {
        ptr::write_volatile(info.recomp_addr as *mut u32, u32::from_le_bytes(info.orig_insn));
        hook_flush_cache(info.recomp_addr as *mut libc::c_void, 4);
    }

    // 归还可复用的 32B hook slot 到 free list；writest 变长 slot 不回收。
    if info.reusable {
        page.free_hook_slots.push(info.slot_addr);
    }

    Ok(())
}

/// 修复 hook engine 为 slot 自动生成的 trampoline。
///
/// hook engine 的 build_trampoline 从 slot 地址读 "original bytes"（清零后是 NOP/0），
/// 生成的 trampoline 无法正确 call original。本函数用 recomp 代码页上被 B 覆盖的
/// 真正原始指令重建 trampoline: 重定位原始指令 + 跳回 recomp_addr+4。
pub fn fixup_slot_trampoline(trampoline: *mut u8, orig_addr: usize) -> Result<()> {
    ensure_init();

    let page_size = unsafe { sysconf(_SC_PAGESIZE) as usize };
    let orig_base = orig_addr & !(page_size - 1);

    let guard = RECOMP_PAGES.lock().unwrap();
    let pages = guard.as_ref().unwrap();

    let page = match pages.get(&orig_base) {
        Some(p) => p,
        None => return Ok(()), // 非 recomp 模式，无需 fixup
    };

    let info = match page.slots.get(&orig_addr) {
        Some(i) => i,
        None => return Ok(()), // 无 slot 记录（非 stealth2 路径或已释放）
    };

    let ret = unsafe {
        hook_rebuild_trampoline(
            trampoline as *mut libc::c_void,
            256, // TRAMPOLINE_ALLOC_SIZE
            info.orig_insn.as_ptr(),
            info.recomp_addr as u64,
            (info.recomp_addr + 4) as *mut libc::c_void,
        )
    };

    if ret < 0 {
        return Err(format!("hook_rebuild_trampoline failed: {}", ret));
    }

    Ok(())
}

fn alloc_recomp_region(orig_base: usize, tramp_pages: usize) -> Result<(*mut u8, usize, usize)> {
    let total_size = PAGE_SIZE + tramp_pages * PAGE_SIZE;
    let tramp_cap = tramp_pages * PAGE_SIZE;

    let recomp_ptr = unsafe { hook_mmap_near_range(orig_base as *mut libc::c_void, total_size, RECOMP_NEAR_RANGE) };
    if recomp_ptr == libc::MAP_FAILED || recomp_ptr.is_null() {
        return Err(format!(
            "mmap near recomp region for 0x{:x}: {}",
            orig_base,
            Error::last_os_error()
        ));
    }

    Ok((recomp_ptr as *mut u8, total_size, tramp_cap))
}

fn try_compile_temp(orig_base: usize, orig_code: &[u8], tramp_pages: usize) -> Result<TempRecomp> {
    let total_size = PAGE_SIZE + tramp_pages * PAGE_SIZE;
    let tramp_cap = tramp_pages * PAGE_SIZE;
    let recomp_ptr = unsafe { hook_mmap_near_range(orig_base as *mut libc::c_void, total_size, RECOMP_NEAR_RANGE) };
    if recomp_ptr == libc::MAP_FAILED || recomp_ptr.is_null() {
        return Err(format!("mmap near recomp region: {}", Error::last_os_error()));
    }

    let recomp_ptr = recomp_ptr as *mut u8;
    let recomp_base = recomp_ptr as u64;
    let tramp_ptr = unsafe { recomp_ptr.add(PAGE_SIZE) };
    let tramp_base = recomp_base + PAGE_SIZE as u64;

    let mut tramp_used: usize = 0;
    let mut stats = RecompileStatsC::new();

    let ret = unsafe {
        recompile_page(
            orig_code.as_ptr(),
            orig_base as u64,
            recomp_ptr,
            recomp_base,
            tramp_ptr,
            tramp_base,
            tramp_cap,
            &mut tramp_used,
            suspend_poll_entrypoint(),
            Some(translate_existing_for_recompile),
            std::ptr::null_mut(),
            &mut stats,
        )
    };

    if ret == 0 {
        if tramp_cap.saturating_sub(tramp_used) >= MIN_HOOK_SLOT_BYTES {
            return Ok(TempRecomp {
                orig_code: orig_code.to_vec(),
                recomp_ptr,
                total_size,
                recomp_base,
                tramp_used,
                tramp_capacity: tramp_cap,
                stats,
            });
        }

        unsafe { munmap(recomp_ptr as *mut _, total_size) };
        return Err(format!(
            "reserved hook slot insufficient (tramp_used={} tramp_capacity={})",
            tramp_used, tramp_cap
        ));
    }

    let msg = std::str::from_utf8(&stats.error_msg)
        .unwrap_or("?")
        .trim_end_matches('\0');
    unsafe { munmap(recomp_ptr as *mut _, total_size) };

    Err(format!("重编译失败: {}", msg))
}

fn compile_reserved_page(
    orig_base: usize,
    orig_code: &[u8],
    recomp_ptr: *mut u8,
    tramp_cap: usize,
) -> Result<(usize, RecompileStatsC)> {
    let recomp_base = recomp_ptr as u64;
    let tramp_ptr = unsafe { recomp_ptr.add(PAGE_SIZE) };
    let tramp_base = recomp_base + PAGE_SIZE as u64;

    let mut tramp_used: usize = 0;
    let mut stats = RecompileStatsC::new();

    let ret = unsafe {
        recompile_page(
            orig_code.as_ptr(),
            orig_base as u64,
            recomp_ptr,
            recomp_base,
            tramp_ptr,
            tramp_base,
            tramp_cap,
            &mut tramp_used,
            suspend_poll_entrypoint(),
            Some(translate_existing_for_recompile),
            std::ptr::null_mut(),
            &mut stats,
        )
    };

    if ret == 0 {
        return Ok((tramp_used, stats));
    }

    let msg = std::str::from_utf8(&stats.error_msg)
        .unwrap_or("?")
        .trim_end_matches('\0');
    Err(format!("重编译失败: {}", msg))
}

struct TempRecomp {
    orig_code: Vec<u8>,
    recomp_ptr: *mut u8,
    total_size: usize,
    recomp_base: u64,
    tramp_used: usize,
    tramp_capacity: usize,
    stats: RecompileStatsC,
}

impl Drop for TempRecomp {
    fn drop(&mut self) {
        unsafe { munmap(self.recomp_ptr as *mut _, self.total_size) };
    }
}

fn do_recompile_temp(orig_base: usize) -> Result<TempRecomp> {
    let mut orig_code = vec![0u8; PAGE_SIZE];
    read_code_page(orig_base, &mut orig_code)?;

    // dry-run 也使用 near-range 分配，覆盖真实 stealth2 的 B-only 跳转约束。
    for &tramp_pages in TRAMPOLINE_PAGE_CANDIDATES {
        match try_compile_temp(orig_base, &orig_code, tramp_pages) {
            Ok(temp) => return Ok(temp),
            Err(e) => {
                let mmap_error = e.starts_with("mmap near recomp region:");
                let capacity_error = is_trampoline_capacity_error(&e);
                if (!mmap_error && !capacity_error) || tramp_pages == MAX_TRAMPOLINE_PAGES {
                    return Err(e);
                }
                let prefix = if mmap_error {
                    "mmap near recomp region failed"
                } else {
                    "tramp_pages 不足"
                };
                log_msg(format!("[recompiler] {} (tramp_pages={}): {}", prefix, tramp_pages, e));
            }
        }
    }

    Err("重编译失败: 未找到可用的跳板区配置".to_string())
}

/// Dry-run：只重编译不注册 prctl，对比原始 vs 重编译指令
pub fn dry_run(addr: usize) -> Result<String> {
    let page_size = unsafe { sysconf(_SC_PAGESIZE) as usize };
    let orig_base = addr & !(page_size - 1);

    let t = do_recompile_temp(orig_base)?;

    let mut output = format!(
        "orig=0x{:x} recomp=0x{:x} delta=0x{:x}\n\
         copied={} intra={} reloc={} tramp={} tramp_bytes={}\n",
        orig_base,
        t.recomp_base,
        t.recomp_base.wrapping_sub(orig_base as u64),
        t.stats.num_copied,
        t.stats.num_intra_page,
        t.stats.num_direct_reloc,
        t.stats.num_trampolines,
        t.tramp_used
    );

    let orig_insns = unsafe { std::slice::from_raw_parts(t.orig_code.as_ptr() as *const u32, 1024) };
    let recomp_insns = unsafe { std::slice::from_raw_parts(t.recomp_ptr as *const u32, 1024) };

    let mut changed = 0;
    for i in 0..1024 {
        if orig_insns[i] != recomp_insns[i] {
            let off = i * 4;
            let recomp = recomp_insns[i];
            let is_b = (recomp & 0xFC000000) == 0x14000000;
            let is_bl = (recomp & 0xFC000000) == 0x94000000;
            if is_b || is_bl {
                let imm26 = recomp & 0x03FFFFFF;
                let sext = ((imm26 as i32) << 6) >> 6;
                let target = (t.recomp_base as i64 + off as i64 + (sext as i64) * 4) as u64;
                output.push_str(&format!(
                    "  +0x{:03x} {:08x} {} 0x{:x}\n",
                    off,
                    orig_insns[i],
                    if is_bl { "BL" } else { "B " },
                    target
                ));
            } else {
                output.push_str(&format!("  +0x{:03x} {:08x} → {:08x}\n", off, orig_insns[i], recomp));
            }
            changed += 1;
        }
    }
    output.push_str(&format!("changed: {}/1024\n", changed));
    Ok(output)
    // TempRecomp Drop 自动 munmap
}

/// 列出所有已重编译的页
pub fn list_pages() -> Vec<(usize, usize, usize)> {
    ensure_init();
    let guard = RECOMP_PAGES.lock().unwrap();
    match guard.as_ref() {
        Some(pages) => pages
            .iter()
            .map(|(&orig, p)| (orig, p.recomp_ptr as usize, p.tramp_used))
            .collect(),
        None => vec![],
    }
}
