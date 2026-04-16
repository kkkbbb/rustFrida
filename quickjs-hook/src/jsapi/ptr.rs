//! ptr() function implementation

use crate::context::JSContext;
use crate::ffi;
use crate::jsapi::util::add_cfunction_to_object;
use crate::value::JSValue;
use std::sync::atomic::{AtomicU32, Ordering};

/// Class ID for NativePointer — global (not thread_local) so hook callbacks on
/// arbitrary threads share the same ID and inherit the prototype (toString etc.).
static NATIVE_POINTER_CLASS_ID: AtomicU32 = AtomicU32::new(0);

/// NativePointer class name
const NATIVE_POINTER_CLASS_NAME: &[u8] = b"NativePointer\0";

/// Finalizer called by QuickJS GC when a NativePointer object is collected.
/// Frees the 8-byte heap allocation created by Box::into_raw in create_native_pointer.
unsafe extern "C" fn native_pointer_finalizer(_rt: *mut ffi::JSRuntime, val: ffi::JSValue) {
    let class_id = NATIVE_POINTER_CLASS_ID.load(Ordering::Relaxed);
    if class_id == 0 {
        return;
    }
    let opaque = ffi::JS_GetOpaque(val, class_id);
    if !opaque.is_null() {
        drop(Box::from_raw(opaque as *mut u64));
    }
}

/// Get (or allocate + register) the NativePointer class ID on the given runtime.
///
/// Allocation is global (AtomicU32), so all threads share the same class ID.
/// JS_NewClass is called unconditionally — it returns -1 (no-op) if already
/// registered on this runtime.
fn get_or_init_class_id(ctx: *mut ffi::JSContext) -> u32 {
    let mut class_id = NATIVE_POINTER_CLASS_ID.load(Ordering::Relaxed);

    if class_id == 0 {
        // Allocate a globally unique class ID (JS_NewClassID uses a global counter).
        let mut new_id: u32 = 0;
        new_id = unsafe { ffi::JS_NewClassID(&mut new_id) };
        // CAS: if another thread beat us, use theirs.
        match NATIVE_POINTER_CLASS_ID.compare_exchange(0, new_id, Ordering::SeqCst, Ordering::Relaxed) {
            Ok(_) => class_id = new_id,
            Err(existing) => class_id = existing,
        }
    }

    unsafe {
        let rt = ffi::JS_GetRuntime(ctx);
        let class_def = ffi::JSClassDef {
            class_name: NATIVE_POINTER_CLASS_NAME.as_ptr() as *const _,
            finalizer: Some(native_pointer_finalizer),
            gc_mark: None,
            call: None,
            exotic: std::ptr::null_mut(),
        };
        let _ = ffi::JS_NewClass(rt, class_id, &class_def);
    }

    class_id
}

/// Create a NativePointer object
pub fn create_native_pointer(ctx: *mut ffi::JSContext, addr: u64) -> JSValue {
    let class_id = get_or_init_class_id(ctx);

    unsafe {
        let obj = ffi::JS_NewObjectClass(ctx, class_id as i32);

        // OOM 时 JS_NewObjectClass 返回 JS_EXCEPTION，不能在异常值上调用 JS_SetOpaque
        if ffi::qjs_is_exception(obj) != 0 {
            return JSValue(obj);
        }

        // Store the address as opaque data
        let addr_ptr = Box::into_raw(Box::new(addr));
        ffi::JS_SetOpaque(obj, addr_ptr as *mut _);

        JSValue(obj)
    }
}

/// Get address from NativePointer object
pub fn get_native_pointer_addr(_ctx: *mut ffi::JSContext, val: JSValue) -> Option<u64> {
    let class_id = NATIVE_POINTER_CLASS_ID.load(Ordering::Relaxed);
    if class_id == 0 {
        return None;
    }

    unsafe {
        let opaque = ffi::JS_GetOpaque(val.raw(), class_id);
        if opaque.is_null() {
            return None;
        }
        Some(*(opaque as *const u64))
    }
}

fn format_native_pointer(addr: u64) -> String {
    format!("0x{:x}", addr)
}

/// ptr() function implementation
/// Accepts: number, string (hex), BigInt, or NativePointer
unsafe extern "C" fn js_ptr(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(ctx, b"ptr() requires 1 argument\0".as_ptr() as *const _);
    }

    let arg = JSValue(*argv);
    let addr: u64;

    // Check argument type
    if arg.is_string() {
        // Parse hex string
        let s = match arg.to_string(ctx) {
            Some(s) => s,
            None => return ffi::JS_ThrowTypeError(ctx, b"Invalid string\0".as_ptr() as *const _),
        };

        // Remove 0x prefix if present
        let s = s.trim().trim_start_matches("0x").trim_start_matches("0X");

        addr = match u64::from_str_radix(s, 16) {
            Ok(v) => v,
            Err(_) => return ffi::JS_ThrowTypeError(ctx, b"Invalid hex string\0".as_ptr() as *const _),
        };
    } else if arg.is_int() || arg.is_float() || ffi::qjs_is_big_int(ctx, arg.raw()) != 0 {
        // Number or BigInt (hook ctx.thisObj / ctx.args[] / ctx.x0-x30)
        let mut v: u64 = 0;
        if ffi::qjs_value_to_u64(ctx, &mut v, arg.raw()) != 0 {
            return ffi::JS_ThrowTypeError(ctx, b"ptr() failed to convert numeric value\0".as_ptr() as *const _);
        }
        addr = v;
    } else if let Some(ptr_addr) = get_native_pointer_addr(ctx, arg) {
        // Already a NativePointer
        addr = ptr_addr;
    } else {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"ptr() argument must be number, string, or BigInt\0".as_ptr() as *const _,
        );
    }

    create_native_pointer(ctx, addr).raw()
}

/// Parse an offset argument for add()/sub() with strict type checking.
/// Accepts: int, float, BigInt, hex string ("0x..."), or NativePointer.
/// Rejects: plain strings, objects, booleans, null, undefined → TypeError.
unsafe fn parse_offset(ctx: *mut ffi::JSContext, arg: JSValue) -> Result<i64, ffi::JSValue> {
    if arg.is_int() || arg.is_float() || ffi::qjs_is_big_int(ctx, arg.raw()) != 0 {
        // Number or BigInt — safe to use to_i64
        match arg.to_i64(ctx) {
            Some(v) => Ok(v),
            None => Err(ffi::JS_ThrowTypeError(
                ctx,
                b"failed to convert numeric offset\0".as_ptr() as *const _,
            )),
        }
    } else if arg.is_string() {
        // Only accept hex strings with 0x/0X prefix
        let s = match arg.to_string(ctx) {
            Some(s) => s,
            None => {
                return Err(ffi::JS_ThrowTypeError(
                    ctx,
                    b"invalid string argument\0".as_ptr() as *const _,
                ));
            }
        };
        let trimmed = s.trim();
        if !trimmed.starts_with("0x") && !trimmed.starts_with("0X") {
            return Err(ffi::JS_ThrowTypeError(
                ctx,
                b"string offset must be hex (0x...)\0".as_ptr() as *const _,
            ));
        }
        let hex = &trimmed[2..];
        match u64::from_str_radix(hex, 16) {
            Ok(v) => Ok(v as i64),
            Err(_) => Err(ffi::JS_ThrowTypeError(
                ctx,
                b"invalid hex string\0".as_ptr() as *const _,
            )),
        }
    } else if let Some(ptr_addr) = get_native_pointer_addr(ctx, arg) {
        // NativePointer — use its address as offset
        Ok(ptr_addr as i64)
    } else {
        Err(ffi::JS_ThrowTypeError(
            ctx,
            b"offset must be a number, hex string, or NativePointer\0".as_ptr() as *const _,
        ))
    }
}

/// NativePointer.add() implementation
unsafe extern "C" fn native_pointer_add(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let this_val = JSValue(this);
    let addr = match get_native_pointer_addr(ctx, this_val) {
        Some(a) => a,
        None => return ffi::JS_ThrowTypeError(ctx, b"Not a NativePointer\0".as_ptr() as *const _),
    };

    if argc < 1 {
        return ffi::JS_ThrowTypeError(ctx, b"add() requires 1 argument\0".as_ptr() as *const _);
    }

    let offset = match parse_offset(ctx, JSValue(*argv)) {
        Ok(v) => v,
        Err(exc) => return exc,
    };
    let new_addr = (addr as i64 + offset) as u64;

    create_native_pointer(ctx, new_addr).raw()
}

/// NativePointer.sub() implementation
unsafe extern "C" fn native_pointer_sub(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let this_val = JSValue(this);
    let addr = match get_native_pointer_addr(ctx, this_val) {
        Some(a) => a,
        None => return ffi::JS_ThrowTypeError(ctx, b"Not a NativePointer\0".as_ptr() as *const _),
    };

    if argc < 1 {
        return ffi::JS_ThrowTypeError(ctx, b"sub() requires 1 argument\0".as_ptr() as *const _);
    }

    let offset = match parse_offset(ctx, JSValue(*argv)) {
        Ok(v) => v,
        Err(exc) => return exc,
    };
    let new_addr = (addr as i64 - offset) as u64;

    create_native_pointer(ctx, new_addr).raw()
}

/// NativePointer.toString() implementation
unsafe extern "C" fn native_pointer_to_string(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let this_val = JSValue(this);
    let addr = match get_native_pointer_addr(ctx, this_val) {
        Some(a) => a,
        None => return ffi::JS_ThrowTypeError(ctx, b"Not a NativePointer\0".as_ptr() as *const _),
    };

    let s = format_native_pointer(addr);
    JSValue::string(ctx, &s).raw()
}

/// NativePointer.toJSON() implementation
unsafe extern "C" fn native_pointer_to_json(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let this_val = JSValue(this);
    let addr = match get_native_pointer_addr(ctx, this_val) {
        Some(a) => a,
        None => return ffi::JS_ThrowTypeError(ctx, b"Not a NativePointer\0".as_ptr() as *const _),
    };

    let s = format_native_pointer(addr);
    JSValue::string(ctx, &s).raw()
}

/// NativePointer.toInt() / toNumber() implementation
unsafe extern "C" fn native_pointer_to_number(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let this_val = JSValue(this);
    let addr = match get_native_pointer_addr(ctx, this_val) {
        Some(a) => a,
        None => return ffi::JS_ThrowTypeError(ctx, b"Not a NativePointer\0".as_ptr() as *const _),
    };

    // Return as BigInt for 64-bit addresses
    ffi::JS_NewBigUint64(ctx, addr)
}

/// Register ptr() function and NativePointer class
pub fn register_ptr(ctx: &JSContext) {
    let class_id = get_or_init_class_id(ctx.as_ptr());

    let global = ctx.global_object();

    unsafe {
        let ctx_ptr = ctx.as_ptr();

        // Register ptr() function
        add_cfunction_to_object(ctx_ptr, global.raw(), "ptr", js_ptr, 1);

        // Create NativePointer prototype with methods
        let proto = ffi::JS_NewObject(ctx_ptr);

        add_cfunction_to_object(ctx_ptr, proto, "add", native_pointer_add, 1);
        add_cfunction_to_object(ctx_ptr, proto, "sub", native_pointer_sub, 1);
        add_cfunction_to_object(ctx_ptr, proto, "toString", native_pointer_to_string, 0);
        add_cfunction_to_object(ctx_ptr, proto, "toJSON", native_pointer_to_json, 0);
        add_cfunction_to_object(ctx_ptr, proto, "toNumber", native_pointer_to_number, 0);
        add_cfunction_to_object(ctx_ptr, proto, "toInt", native_pointer_to_number, 0);

        // Frida 兼容: 注册 Memory 读写方法到 NativePointer prototype
        // 支持 ptr.readU32() / ptr.writeU32(val) 调用风格
        crate::jsapi::memory::register_ptr_methods(ctx_ptr, proto);

        // Set as class prototype
        ffi::JS_SetClassProto(ctx_ptr, class_id, proto);
    }

    global.free(ctx.as_ptr());
}

#[cfg(test)]
mod tests {
    use super::format_native_pointer;

    #[test]
    fn formats_native_pointer_as_hex_string() {
        assert_eq!(format_native_pointer(0x1234_abcd), "0x1234abcd");
    }
}
