//! Memory helper functions

use crate::ffi;
use crate::jsapi::ptr::get_native_pointer_addr;
use crate::jsapi::util::{proc_maps_entries, read_proc_self_maps};
use crate::value::JSValue;

/// Helper to get address from argument
pub(super) unsafe fn get_addr_from_arg(ctx: *mut ffi::JSContext, val: JSValue) -> Option<u64> {
    get_native_pointer_addr(ctx, val).or_else(|| val.to_u64(ctx))
}

/// 从 NativePointer this 或 argv[0] 取地址，返回 (addr, remaining_argv, remaining_argc)。
/// 适配两种调用风格:
///   - `Memory.readU32(addr)` → this 不是 NativePointer, addr = argv[0]
///   - `ptr(addr).readU32()` → this 是 NativePointer, addr = this
pub(super) unsafe fn get_addr_this_or_arg(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> Option<(u64, *mut ffi::JSValue, i32)> {
    // 先尝试从 this 取（NativePointer 方法风格）
    if let Some(addr) = get_native_pointer_addr(ctx, JSValue(this)) {
        return Some((addr, argv, argc));
    }
    // Fallback: Memory.readXxx(addr, ...) 风格，argv[0] 是地址
    if argc < 1 { return None; }
    let addr = get_addr_from_arg(ctx, JSValue(*argv))?;
    Some((addr, argv.add(1), argc - 1))
}

/// Parse page permissions for `addr` from /proc/self/maps.
/// Returns the libc PROT_* flags for the page, or `None` if not found.
fn get_page_prot(addr: u64) -> Option<i32> {
    let maps = read_proc_self_maps()?;
    let prot = proc_maps_entries(&maps)
        .find(|entry| entry.contains(addr))
        .map(|entry| entry.prot_flags());
    prot
}

/// 尝试在 `addr` 处执行 `write_fn`。**不再自动 mprotect** — 避免跨页限制、
/// 权限恢复失败等隐性问题。行为明确:
///   - 目标页已含 `PROT_WRITE` (rw- / rwx) → 直接执行 write
///   - `/proc/self/maps` 查不到该页的权限 → 保守按"可写"处理（alloc 的匿名
///     页、部分特殊映射可能不在 maps 里）
///   - 目标页只读 (r-x / r-- / ---) → 返回 false, 调用方应抛错提示 user
///     先调 `Memory.protect(addr, size, "rwx")` 或 `p.protect(size, "rwx")`
///
/// 返回 `true` = 写入已执行; `false` = 目标页不可写, 未执行。
pub(super) unsafe fn write_with_perm(addr: u64, _size: usize, write_fn: impl FnOnce()) -> bool {
    let orig_prot = get_page_prot(addr);
    if orig_prot.map_or(true, |p| (p & libc::PROT_WRITE) != 0) {
        write_fn();
        return true;
    }
    false
}
