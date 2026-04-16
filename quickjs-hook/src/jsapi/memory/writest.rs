//! `writest(bytes)` — stealth-2 指令 patch（1 条指令 → N 条指令）
//!
//! 语义：替换 `addr` 处的 1 条原始指令（4 字节）为 N 条用户指令，执行完
//! 用户指令后自然 fall-through 到原函数 `addr+4` 继续执行。所有写入都在
//! recomp 页的跳板区 slot 里，recomp 代码页只原子写 4 字节 B→slot；原始
//! SO 不动。PC-relative 指令通过 arm64_relocator 自动修正到 slot 运行位置。
//!
//! Stealth-1 (wxshadow) 不再走本路径 — 改为 `writeBytes(bytes, 1)`。

use super::helpers::get_addr_this_or_arg;
use crate::ffi;
use crate::value::JSValue;

/// 提取 JS 端 bytes 参数（ArrayBuffer / TypedArray / Array<number>）到 `Vec<u8>`。
pub(super) unsafe fn extract_bytes(
    ctx: *mut ffi::JSContext,
    val: JSValue,
) -> Result<Vec<u8>, ffi::JSValue> {
    // JS_GetArrayBuffer 对合法 ArrayBuffer 返回 (data_ptr, byte_length)；对非 AB
    // 返回 NULL+size=0. 空 AB 会返回非 NULL + size=0（data 分配存在但长度 0），
    // 我们把它视作有效输入并返回空 Vec，避免上层 reject empty ArrayBuffer 输入。
    let mut size: usize = 0;
    let buf_ptr = ffi::JS_GetArrayBuffer(ctx, &mut size, val.raw());
    if !buf_ptr.is_null() {
        let slice = std::slice::from_raw_parts(buf_ptr, size);
        return Ok(slice.to_vec());
    }

    let mut byte_offset: usize = 0;
    let mut byte_length: usize = 0;
    let mut bpe: usize = 0;
    let typed_ab =
        ffi::JS_GetTypedArrayBuffer(ctx, val.raw(), &mut byte_offset, &mut byte_length, &mut bpe);
    if ffi::qjs_is_exception(typed_ab) != 0 {
        let exc = ffi::JS_GetException(ctx);
        ffi::qjs_free_value(ctx, exc);
    } else {
        // 非异常 = val 是 TypedArray (含空 TypedArray)。typed_ab 持有 ArrayBuffer
        // 引用必须 free。空 TypedArray 直接返回空 Vec，不再 fall-through 到 Array
        // 分支误判为非法输入。
        let typed_ab_val = JSValue(typed_ab);
        let mut result: Option<Vec<u8>> = None;
        if byte_length == 0 {
            result = Some(Vec::new());
        } else {
            let mut ab_size: usize = 0;
            let ab_ptr = ffi::JS_GetArrayBuffer(ctx, &mut ab_size, typed_ab);
            if !ab_ptr.is_null() && byte_offset + byte_length <= ab_size {
                let slice = std::slice::from_raw_parts(ab_ptr.add(byte_offset), byte_length);
                result = Some(slice.to_vec());
            }
        }
        typed_ab_val.free(ctx);
        if let Some(v) = result {
            return Ok(v);
        }
    }

    if ffi::JS_IsArray(ctx, val.raw()) != 0 {
        let len_val_raw = ffi::qjs_get_property(
            ctx,
            val.raw(),
            ffi::JS_NewAtom(ctx, b"length\0".as_ptr() as *const _),
        );
        let len_val = JSValue(len_val_raw);
        let len_i = len_val.to_i64(ctx).unwrap_or(0);
        len_val.free(ctx);
        if len_i < 0 {
            return Err(ffi::JS_ThrowRangeError(
                ctx,
                b"byte array length must be non-negative\0".as_ptr() as *const _,
            ));
        }
        let len = len_i as usize;
        let mut out = Vec::with_capacity(len);
        for i in 0..len {
            let elem_raw = ffi::JS_GetPropertyUint32(ctx, val.raw(), i as u32);
            let elem = JSValue(elem_raw);
            let byte = elem.to_i64(ctx).unwrap_or(0) as u8;
            elem.free(ctx);
            out.push(byte);
        }
        return Ok(out);
    }

    Err(ffi::JS_ThrowTypeError(
        ctx,
        b"bytes must be ArrayBuffer, TypedArray or Array<number>\0".as_ptr() as *const _,
    ))
}

/// `ptr.writest(bytes)` / `Memory.writest(ptr, bytes)` — stealth-2 patch.
///
/// `bytes` 长度必须 4 字节倍数（每条 ARM64 指令 4B），`addr` 必须 4 字节对齐。
/// 失败时抛 InternalError 并附带原因（页未 recomp、patch 非法、跳板区满等）。
pub(super) unsafe extern "C" fn memory_writest(
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
                b"writest() requires a pointer\0".as_ptr() as *const _,
            );
        }
    };
    if rem_argc < 1 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"writest() requires bytes argument\0".as_ptr() as *const _,
        );
    }

    let bytes = match extract_bytes(ctx, JSValue(*rem_argv)) {
        Ok(b) => b,
        Err(e) => return e,
    };

    // ensure_and_translate 先触发页 recomp + prctl 注册；缺失则报错。
    if let Err(e) = crate::recomp::ensure_and_translate(addr as usize) {
        let msg = format!("writest: recomp init failed: {}\0", e);
        return ffi::JS_ThrowInternalError(
            ctx,
            b"%s\0".as_ptr() as *const _,
            msg.as_ptr(),
        );
    }

    match crate::recomp::install_patch(addr as usize, &bytes) {
        Ok(()) => JSValue::undefined().raw(),
        Err(msg) => {
            let cmsg = format!("writest: {}\0", msg);
            ffi::JS_ThrowInternalError(
                ctx,
                b"%s\0".as_ptr() as *const _,
                cmsg.as_ptr(),
            )
        }
    }
}
