//! Memory read operations

use super::helpers::get_addr_this_or_arg;
use crate::ffi;
use crate::jsapi::ptr::create_native_pointer;
use crate::jsapi::util::is_addr_accessible;
use crate::value::JSValue;

/// 生成 Memory.readXXX(ptr) 和 ptr.readXXX() 双风格 read 函数。
macro_rules! define_memory_read {
    ($name:ident, $js_name:literal, $rust_type:ty, $size:expr,
     ($ctx_id:ident, $val_id:ident) => $convert:expr) => {
        pub(super) unsafe extern "C" fn $name(
            $ctx_id: *mut ffi::JSContext,
            this: ffi::JSValue,
            argc: i32,
            argv: *mut ffi::JSValue,
        ) -> ffi::JSValue {
            let (addr, _rem_argv, _rem_argc) = match get_addr_this_or_arg($ctx_id, this, argc, argv) {
                Some(v) => v,
                None => return ffi::JS_ThrowTypeError(
                    $ctx_id,
                    concat!($js_name, "() requires a pointer\0").as_ptr() as *const _,
                ),
            };
            if !is_addr_accessible(addr, $size) {
                return ffi::JS_ThrowRangeError($ctx_id, b"Invalid memory address\0".as_ptr() as *const _);
            }
            let $val_id = std::ptr::read_unaligned(addr as *const $rust_type);
            $convert
        }
    };
}

define_memory_read!(memory_read_u8, "readU8", u8, 1,
    (_ctx, val) => JSValue::int(val as i32).raw());
define_memory_read!(memory_read_u16, "readU16", u16, 2,
    (_ctx, val) => JSValue::int(val as i32).raw());
define_memory_read!(memory_read_u32, "readU32", u32, 4,
    (ctx, val) => ffi::JS_NewBigUint64(ctx, val as u64));
define_memory_read!(memory_read_u64, "readU64", u64, 8,
    (ctx, val) => ffi::JS_NewBigUint64(ctx, val));
define_memory_read!(memory_read_pointer, "readPointer", u64, 8,
    (ctx, val) => create_native_pointer(ctx, val).raw());

/// Memory.readCString(ptr) / ptr.readCString()
pub(super) unsafe extern "C" fn memory_read_cstring(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let addr = match get_addr_this_or_arg(ctx, this, argc, argv) {
        Some((a, _, _)) => a,
        None => return ffi::JS_ThrowTypeError(ctx, b"readCString() requires a pointer\0".as_ptr() as *const _),
    };

    if !is_addr_accessible(addr, 1) {
        return ffi::JS_ThrowRangeError(ctx, b"Invalid memory address\0".as_ptr() as *const _);
    }
    // Bounded scan: find '\0' within MAX_CSTRING_LEN bytes to avoid SEGV on unterminated buffers.
    // Only call is_addr_accessible at page boundaries (every 4096 bytes) for performance.
    const MAX_CSTRING_LEN: usize = 4096;
    const PAGE_SIZE: u64 = 4096;
    let mut len = 0usize;
    // Track next page boundary that needs checking
    let mut next_page_check = (addr + PAGE_SIZE) & !(PAGE_SIZE - 1);
    while len < MAX_CSTRING_LEN {
        let byte_addr = addr + len as u64;
        // Check accessibility when we cross into a new page
        if byte_addr >= next_page_check {
            if !is_addr_accessible(byte_addr, 1) {
                break;
            }
            next_page_check = (byte_addr + PAGE_SIZE) & !(PAGE_SIZE - 1);
        }
        if *(byte_addr as *const u8) == 0 {
            break;
        }
        len += 1;
    }
    if len >= MAX_CSTRING_LEN {
        return ffi::JS_ThrowRangeError(
            ctx,
            b"readCString: string exceeds maximum length (4096)\0".as_ptr() as *const _,
        );
    }
    let slice = std::slice::from_raw_parts(addr as *const u8, len);
    let s = String::from_utf8_lossy(slice);
    JSValue::string(ctx, &s).raw()
}

/// Memory.readUtf8String(ptr) / ptr.readUtf8String()
pub(super) unsafe extern "C" fn memory_read_utf8_string(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    // Same as readCString for now
    memory_read_cstring(ctx, this, argc, argv)
}

/// Memory.readByteArray(ptr, length) / ptr.readByteArray(length)
pub(super) unsafe extern "C" fn memory_read_byte_array(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let (addr, rem_argv, rem_argc) = match get_addr_this_or_arg(ctx, this, argc, argv) {
        Some(v) => v,
        None => return ffi::JS_ThrowTypeError(ctx, b"readByteArray() requires a pointer\0".as_ptr() as *const _),
    };
    if rem_argc < 1 {
        return ffi::JS_ThrowTypeError(ctx, b"readByteArray() requires length argument\0".as_ptr() as *const _);
    }

    let length_raw = match JSValue(*rem_argv).to_i64(ctx) {
        Some(v) => v,
        None => return ffi::JS_ThrowTypeError(ctx, b"readByteArray: length must be a number\0".as_ptr() as *const _),
    };
    if length_raw <= 0 {
        return ffi::JS_ThrowRangeError(ctx, b"readByteArray: length must be positive\0".as_ptr() as *const _);
    }
    const MAX_READ_SIZE: i64 = 1024 * 1024 * 1024; // 1GB
    if length_raw > MAX_READ_SIZE {
        return ffi::JS_ThrowRangeError(
            ctx,
            b"readByteArray: length exceeds maximum (1GB)\0".as_ptr() as *const _,
        );
    }
    let length = length_raw as usize;

    if !is_addr_accessible(addr, length) {
        return ffi::JS_ThrowRangeError(ctx, b"Invalid memory address\0".as_ptr() as *const _);
    }
    // Create ArrayBuffer
    let slice = std::slice::from_raw_parts(addr as *const u8, length);
    ffi::JS_NewArrayBufferCopy(ctx, slice.as_ptr(), length)
}
