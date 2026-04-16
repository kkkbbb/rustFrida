//! 安全内存读取工具 — 防止扫描未映射内存导致 SIGSEGV
//!
//! 通过解析 /proc/self/maps 构建可读内存区间表，在裸指针读取前验证地址有效性。
//! 仅用于初始化阶段的 ART 结构体扫描探测，不用于 hot-path (hook callback)。

use std::cell::RefCell;

/// 内存映射区间
struct MemRegion {
    start: u64,
    end: u64,
}

thread_local! {
    /// 当前线程缓存的可读内存映射区间表
    static MEM_REGIONS: RefCell<Vec<MemRegion>> = RefCell::new(Vec::new());
}

/// 刷新当前线程的内存映射缓存（在开始扫描前调用一次）
pub(super) fn refresh_mem_regions() {
    let regions = parse_proc_maps();
    MEM_REGIONS.with(|r| {
        *r.borrow_mut() = regions;
    });
}

/// 检查地址范围是否在有效可读映射内
pub(super) fn is_readable(addr: u64, len: usize) -> bool {
    let end = addr + len as u64;
    MEM_REGIONS.with(|r| {
        let regions = r.borrow();
        regions.iter().any(|reg| addr >= reg.start && end <= reg.end)
    })
}

/// 安全读取 u64，地址无效时返回 0
pub(super) unsafe fn safe_read_u64(addr: u64) -> u64 {
    if !is_readable(addr, 8) {
        return 0;
    }
    std::ptr::read_unaligned(addr as *const u64)
}

/// 安全读取 u32，地址无效时返回 0
pub(super) unsafe fn safe_read_u32(addr: u64) -> u32 {
    if !is_readable(addr, 4) {
        return 0;
    }
    std::ptr::read_unaligned(addr as *const u32)
}

/// 安全读取 u16，地址无效时返回 0
#[allow(dead_code)]
pub(super) unsafe fn safe_read_u16(addr: u64) -> u16 {
    if !is_readable(addr, 2) {
        return 0;
    }
    std::ptr::read_unaligned(addr as *const u16)
}

/// 解析 /proc/self/maps，提取所有可读 ('r') 区间
fn parse_proc_maps() -> Vec<MemRegion> {
    let content = match crate::jsapi::util::read_proc_self_maps() {
        Some(s) => s,
        None => return Vec::new(),
    };

    crate::jsapi::util::proc_maps_entries(&content)
        .filter(|entry| entry.prot_flags() & libc::PROT_READ != 0)
        .map(|entry| MemRegion {
            start: entry.start,
            end: entry.end,
        })
        .collect()
}
