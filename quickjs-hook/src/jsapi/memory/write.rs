//! Memory write operations

use super::helpers::{get_addr_this_or_arg, write_with_perm};
use super::writest::extract_bytes;
use crate::ffi;
use crate::jsapi::util::is_addr_accessible;
use crate::value::JSValue;
use std::collections::HashSet;
use std::sync::Mutex;

/// 追踪 writeBytes(bytes, 1) 装过的 wxshadow patch 地址, 供 cleanup 批量
/// wxshadow_release. 这些 patch 不走 hook_engine, 不在 g_engine.hooks 链表上,
/// hook_engine_cleanup 看不到它们.
static WXSHADOW_PATCH_ADDRS: Mutex<Option<HashSet<u64>>> = Mutex::new(None);

fn track_wxshadow_addr(addr: u64) {
    let mut guard = WXSHADOW_PATCH_ADDRS.lock().unwrap_or_else(|e| e.into_inner());
    guard.get_or_insert_with(HashSet::new).insert(addr);
}

pub(crate) fn untrack_wxshadow_addr(addr: u64) {
    let mut guard = WXSHADOW_PATCH_ADDRS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(set) = guard.as_mut() {
        set.remove(&addr);
    }
}

/// 清理所有 writeBytes(bytes, 1) 装过的 wxshadow patch. cleanup 时在
/// hook_engine_cleanup 之后调用, 释放内核 shadow 页, 防止 --pid 场景下
/// agent dlclose 后 patch 残留.
pub fn cleanup_wxshadow_patches() {
    let addrs = {
        let mut guard = WXSHADOW_PATCH_ADDRS.lock().unwrap_or_else(|e| e.into_inner());
        guard.take().unwrap_or_default()
    };
    for addr in addrs {
        unsafe {
            ffi::hook::wxshadow_release(addr as *mut std::ffi::c_void);
        }
    }
}

/// 生成 Memory.writeXXX(ptr, value) 和 ptr.writeXXX(value) 双风格 write 函数。
/// rem_argv 指向 value（自动剥离 Memory 风格的 addr 参数）。
macro_rules! define_memory_write {
    ($name:ident, $js_name:literal, $rust_type:ty, $size:expr,
     ($ctx_id:ident, $argv_id:ident) => $extract:expr) => {
        pub(super) unsafe extern "C" fn $name(
            $ctx_id: *mut ffi::JSContext,
            this: ffi::JSValue,
            argc: i32,
            argv: *mut ffi::JSValue,
        ) -> ffi::JSValue {
            let (addr, rem_argv, rem_argc) = match get_addr_this_or_arg($ctx_id, this, argc, argv) {
                Some(v) => v,
                None => return ffi::JS_ThrowTypeError(
                    $ctx_id,
                    concat!($js_name, "() requires a pointer\0").as_ptr() as *const _,
                ),
            };
            if rem_argc < 1 {
                return ffi::JS_ThrowTypeError(
                    $ctx_id,
                    concat!($js_name, "() requires value argument\0").as_ptr() as *const _,
                );
            }
            let $argv_id = rem_argv;
            if !is_addr_accessible(addr, $size) {
                return ffi::JS_ThrowRangeError($ctx_id, b"Invalid memory address\0".as_ptr() as *const _);
            }
            let val: $rust_type = $extract;
            if !write_with_perm(addr, $size, || {
                std::ptr::write_unaligned(addr as *mut $rust_type, val);
            }) {
                return ffi::JS_ThrowRangeError(
                    $ctx_id,
                    concat!($js_name, "(): target page is not writable; call Memory.protect(addr, size, \"rwx\") first\0").as_ptr() as *const _,
                );
            }
            JSValue::undefined().raw()
        }
    };
}

define_memory_write!(memory_write_u8, "writeU8", u8, 1,
    (ctx, argv) => JSValue(*argv).to_i64(ctx).unwrap_or(0) as u8);
define_memory_write!(memory_write_u16, "writeU16", u16, 2,
    (ctx, argv) => JSValue(*argv).to_i64(ctx).unwrap_or(0) as u16);
define_memory_write!(memory_write_u32, "writeU32", u32, 4,
    (ctx, argv) => JSValue(*argv).to_i64(ctx).unwrap_or(0) as u32);
define_memory_write!(memory_write_u64, "writeU64", u64, 8,
    (ctx, argv) => JSValue(*argv).to_u64(ctx).unwrap_or(0));

/// Memory.writePointer(ptr, value) / ptr.writePointer(value)
pub(super) unsafe extern "C" fn memory_write_pointer(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    // Same as writeU64
    memory_write_u64(ctx, this, argc, argv)
}

/// `Memory.writeBytes(ptr, bytes, stealth?)` / `ptr.writeBytes(bytes, stealth?)`
///
/// Multi-byte write with an optional stealth flag:
///   - `stealth=0` or omitted: classic mprotect RWX → memcpy → restore
///   - `stealth=1`: kernel wxshadow PATCH (shadow page visible only to I-fetch)
///
/// For the "1 instruction → N instruction" replacement semantics (PC-rel
/// aware, atomic B→slot in recomp page), use `writest()` (stealth-2) instead.
pub(super) unsafe extern "C" fn memory_write_bytes(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let (addr, rem_argv, rem_argc) = match get_addr_this_or_arg(ctx, this, argc, argv) {
        Some(v) => v,
        None => {
            return ffi::JS_ThrowTypeError(
                ctx,
                b"writeBytes() requires a pointer\0".as_ptr() as *const _,
            );
        }
    };
    if rem_argc < 1 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"writeBytes() requires bytes argument\0".as_ptr() as *const _,
        );
    }

    let bytes = match extract_bytes(ctx, JSValue(*rem_argv)) {
        Ok(b) => b,
        Err(e) => return e,
    };
    if bytes.is_empty() {
        return JSValue::undefined().raw();
    }

    let stealth = if rem_argc >= 2 {
        JSValue(*rem_argv.add(1)).to_i64(ctx).unwrap_or(0)
    } else {
        0
    };

    match stealth {
        0 => {
            if !is_addr_accessible(addr, bytes.len()) {
                return ffi::JS_ThrowRangeError(
                    ctx,
                    b"writeBytes: invalid memory address\0".as_ptr() as *const _,
                );
            }
            let src = bytes.as_ptr();
            let len = bytes.len();
            if !write_with_perm(addr, len, || {
                std::ptr::copy_nonoverlapping(src, addr as *mut u8, len);
            }) {
                return ffi::JS_ThrowRangeError(
                    ctx,
                    b"writeBytes: target page is not writable; call Memory.protect(addr, size, \"rwx\") first, or use writeBytes(bytes, 1)/writest() for stealth code patch\0".as_ptr() as *const _,
                );
            }
            ffi::hook::hook_flush_cache(addr as *mut _, len);
            JSValue::undefined().raw()
        }
        1 => {
            // wxshadow_patch 走 KPM copy_from_user_via_pte，单次只能写一页。
            // bytes 跨 4KB 边界时手工拆成两段：先写第二段 (jump 尾部，未含取指首
            // 字节)，再写第一段；首段失败回滚第二段。> 2 页直接拒绝。
            let len = bytes.len();
            let page_off = (addr & 0xFFF) as usize;
            if page_off + len > 0x2000 {
                let msg = format!(
                    "writeBytes(stealth=1): bytes len={} 跨 >2 页 (page_off=0x{:x})，wxshadow 不支持\0",
                    len, page_off
                );
                return ffi::JS_ThrowInternalError(ctx, b"%s\0".as_ptr() as *const _, msg.as_ptr());
            }
            if page_off + len > 0x1000 {
                let first_len = 0x1000 - page_off;
                let second_len = len - first_len;
                let second_addr = addr + first_len as u64;
                let rc2 = ffi::hook::wxshadow_patch(
                    second_addr as *mut std::ffi::c_void,
                    bytes.as_ptr().add(first_len) as *const std::ffi::c_void,
                    second_len,
                );
                if rc2 != 0 {
                    let msg = format!(
                        "writeBytes(stealth=1): wxshadow_patch second-page rc={}\0", rc2
                    );
                    return ffi::JS_ThrowInternalError(ctx, b"%s\0".as_ptr() as *const _, msg.as_ptr());
                }
                let rc1 = ffi::hook::wxshadow_patch(
                    addr as *mut std::ffi::c_void,
                    bytes.as_ptr() as *const std::ffi::c_void,
                    first_len,
                );
                if rc1 != 0 {
                    ffi::hook::wxshadow_release(second_addr as *mut std::ffi::c_void);
                    let msg = format!(
                        "writeBytes(stealth=1): first-page rc={}, second 已回滚\0", rc1
                    );
                    return ffi::JS_ThrowInternalError(ctx, b"%s\0".as_ptr() as *const _, msg.as_ptr());
                }
                ffi::hook::hook_flush_cache(addr as *mut _, len);
                track_wxshadow_addr(addr);
                track_wxshadow_addr(second_addr);
            } else {
                let rc = ffi::hook::wxshadow_patch(
                    addr as *mut std::ffi::c_void,
                    bytes.as_ptr() as *const std::ffi::c_void,
                    len,
                );
                if rc != 0 {
                    let msg = format!("writeBytes(stealth=1): wxshadow_patch rc={}\0", rc);
                    return ffi::JS_ThrowInternalError(
                        ctx,
                        b"%s\0".as_ptr() as *const _,
                        msg.as_ptr(),
                    );
                }
                ffi::hook::hook_flush_cache(addr as *mut _, len);
                track_wxshadow_addr(addr);
            }
            JSValue::undefined().raw()
        }
        other => {
            let msg = format!(
                "writeBytes: unsupported stealth mode {} (expected 0 or 1; use writest for mode 2)\0",
                other
            );
            ffi::JS_ThrowInternalError(ctx, b"%s\0".as_ptr() as *const _, msg.as_ptr())
        }
    }
}
