//! JS API: Java._inspectArtMethod / Java._setForcedInterpretOnly / Java._initArtController
//!
//! 检测面测试用 — 不执行任何 hook，仅提供 ArtMethod 信息和独立操作。

use crate::ffi;
use crate::value::JSValue;
use std::ffi::CString;

use super::art_controller::ensure_art_controller_initialized;
use super::art_method::*;
use super::jni_core::*;
use super::reflect::*;
use crate::jsapi::callback_util::set_js_u64_property;

// ============================================================================
// Java._inspectArtMethod(class, method, sig) → object
//
// 返回 ArtMethod 的所有关键信息，不做任何修改。
// 用于检测面测试：调用者可根据返回的地址+偏移用 Memory.writeU32/U64 单独修改字段。
// ============================================================================

pub(super) unsafe extern "C" fn js_java_inspect_art_method(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 3 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"_inspectArtMethod(class, method, sig) requires 3 arguments\0".as_ptr() as *const _,
        );
    }

    let class_arg = JSValue(*argv);
    let method_arg = JSValue(*argv.add(1));
    let sig_arg = JSValue(*argv.add(2));

    let class_name = match class_arg.to_string(ctx) {
        Some(s) => s,
        None => return ffi::JS_ThrowTypeError(ctx, b"arg 0 must be string\0".as_ptr() as *const _),
    };
    let method_name = match method_arg.to_string(ctx) {
        Some(s) => s,
        None => return ffi::JS_ThrowTypeError(ctx, b"arg 1 must be string\0".as_ptr() as *const _),
    };
    let sig_str = match sig_arg.to_string(ctx) {
        Some(s) => s,
        None => return ffi::JS_ThrowTypeError(ctx, b"arg 2 must be string\0".as_ptr() as *const _),
    };

    // 解析 "static:" 前缀
    let (actual_sig, force_static) = if let Some(stripped) = sig_str.strip_prefix("static:") {
        (stripped.to_string(), true)
    } else {
        (sig_str.clone(), false)
    };

    let env = match ensure_jni_initialized() {
        Ok(e) => e,
        Err(msg) => {
            let err = CString::new(msg).unwrap();
            return ffi::JS_ThrowInternalError(ctx, err.as_ptr());
        }
    };

    let (art_method, is_static) = match resolve_art_method(env, &class_name, &method_name, &actual_sig, force_static) {
        Ok(r) => r,
        Err(msg) => {
            let err = CString::new(msg).unwrap();
            return ffi::JS_ThrowInternalError(ctx, err.as_ptr());
        }
    };

    let spec = get_art_method_spec(env, art_method);
    let bridge = find_art_bridge_functions(env, spec.entry_point_offset);

    // 读取当前字段值
    let access_flags = std::ptr::read_volatile((art_method as usize + spec.access_flags_offset) as *const u32);
    let data = std::ptr::read_volatile((art_method as usize + spec.data_offset) as *const u64);
    let entry_point = read_entry_point(art_method, spec.entry_point_offset);
    let has_independent_code = !is_art_quick_entrypoint(entry_point, bridge);

    // 构建返回对象
    let result = ffi::JS_NewObject(ctx);

    // artMethod 地址
    set_js_u64_property(ctx, result, "artMethod", art_method);

    // 当前字段值
    set_js_u64_property(ctx, result, "accessFlags", access_flags as u64);
    set_js_u64_property(ctx, result, "entryPoint", entry_point);
    set_js_u64_property(ctx, result, "data", data);
    JSValue(result).set_property(ctx, "isStatic", JSValue::bool(is_static));
    JSValue(result).set_property(ctx, "hasIndependentCode", JSValue::bool(has_independent_code));

    // offsets 子对象
    let offsets = ffi::JS_NewObject(ctx);
    JSValue(offsets).set_property(ctx, "accessFlags", JSValue::int(spec.access_flags_offset as i32));
    JSValue(offsets).set_property(ctx, "entryPoint", JSValue::int(spec.entry_point_offset as i32));
    JSValue(offsets).set_property(ctx, "data", JSValue::int(spec.data_offset as i32));
    JSValue(offsets).set_property(ctx, "size", JSValue::int(spec.size as i32));
    JSValue(result).set_property(ctx, "offsets", JSValue(offsets));

    // bridges 子对象
    let bridges = ffi::JS_NewObject(ctx);
    set_js_u64_property(ctx, bridges, "nterp", bridge.nterp_entry_point);
    set_js_u64_property(ctx, bridges, "interpreterBridge", bridge.quick_to_interpreter_bridge);
    set_js_u64_property(ctx, bridges, "jniTrampoline", bridge.quick_generic_jni_trampoline);
    set_js_u64_property(ctx, bridges, "resolution", bridge.quick_resolution_trampoline);
    JSValue(result).set_property(ctx, "bridges", JSValue(bridges));

    // flags 常量子对象（方便 JS 层使用）
    let consts = ffi::JS_NewObject(ctx);
    set_js_u64_property(ctx, consts, "kAccNative", K_ACC_NATIVE as u64);
    set_js_u64_property(ctx, consts, "kAccCompileDontBother", k_acc_compile_dont_bother() as u64);
    set_js_u64_property(
        ctx,
        consts,
        "kAccFastInterpToInterp",
        K_ACC_FAST_INTERP_TO_INTERP as u64,
    );
    set_js_u64_property(
        ctx,
        consts,
        "kAccSingleImplementation",
        K_ACC_SINGLE_IMPLEMENTATION as u64,
    );
    set_js_u64_property(
        ctx,
        consts,
        "kAccNterpEntryPointFastPath",
        K_ACC_NTERP_ENTRY_POINT_FAST_PATH as u64,
    );
    set_js_u64_property(ctx, consts, "kAccSkipAccessChecks", K_ACC_SKIP_ACCESS_CHECKS as u64);
    set_js_u64_property(ctx, consts, "kAccFastNative", K_ACC_FAST_NATIVE as u64);
    set_js_u64_property(ctx, consts, "kAccCriticalNative", K_ACC_CRITICAL_NATIVE as u64);
    JSValue(result).set_property(ctx, "consts", JSValue(consts));

    result
}

// ============================================================================
// Java._setForcedInterpretOnly(enable) — 单独设置/恢复 forced_interpret_only_
// ============================================================================

pub(super) unsafe extern "C" fn js_java_set_forced_interpret_only(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"_setForcedInterpretOnly(bool) requires 1 argument\0".as_ptr() as *const _,
        );
    }

    let enable = JSValue(*argv).to_bool().unwrap_or(false);

    let _env = match ensure_jni_initialized() {
        Ok(e) => e,
        Err(msg) => {
            let err = CString::new(msg).unwrap();
            return ffi::JS_ThrowInternalError(ctx, err.as_ptr());
        }
    };

    let spec = match get_instrumentation_spec() {
        Some(s) => s,
        None => {
            return ffi::JS_ThrowInternalError(ctx, b"InstrumentationSpec not available\0".as_ptr() as *const _);
        }
    };

    let runtime = match get_runtime_addr() {
        Some(r) => r,
        None => {
            return ffi::JS_ThrowInternalError(ctx, b"Cannot get Runtime address\0".as_ptr() as *const _);
        }
    };

    use super::PAC_STRIP_MASK;
    let instrumentation_base = if spec.is_pointer_mode {
        let ptr = *((runtime as usize + spec.runtime_instrumentation_offset) as *const u64);
        let stripped = ptr & PAC_STRIP_MASK;
        if stripped == 0 {
            return ffi::JS_ThrowInternalError(ctx, b"Instrumentation pointer is null\0".as_ptr() as *const _);
        }
        stripped as usize
    } else {
        runtime as usize + spec.runtime_instrumentation_offset
    };

    let field_addr = (instrumentation_base + spec.force_interpret_only_offset) as *mut u8;
    let old_val = std::ptr::read_volatile(field_addr);
    let new_val: u8 = if enable { 1 } else { 0 };
    std::ptr::write_volatile(field_addr, new_val);

    crate::jsapi::console::output_verbose(&format!(
        "[test] forced_interpret_only_: {} → {} (addr={:#x})",
        old_val, new_val, field_addr as u64
    ));

    JSValue::bool(true).raw()
}

// ============================================================================
// Java._initArtController() — 单独初始化 Layer 1+2（不 hook 任何方法）
// ============================================================================

pub(super) unsafe extern "C" fn js_java_init_art_controller(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let env = match ensure_jni_initialized() {
        Ok(e) => e,
        Err(msg) => {
            let err = CString::new(msg).unwrap();
            return ffi::JS_ThrowInternalError(ctx, err.as_ptr());
        }
    };

    // 需要一个 ArtMethod 来探测 spec，用 Object.toString
    let cls = find_class_safe(env, "java.lang.Object");
    if cls.is_null() {
        return ffi::JS_ThrowInternalError(ctx, b"FindClass Object failed\0".as_ptr() as *const _);
    }

    let c_name = CString::new("toString").unwrap();
    let c_sig = CString::new("()Ljava/lang/String;").unwrap();
    let get_method_id: GetMethodIdFn = jni_fn!(env, GetMethodIdFn, JNI_GET_METHOD_ID);
    let method_id = get_method_id(env, cls, c_name.as_ptr(), c_sig.as_ptr());
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
    delete_local_ref(env, cls);

    if method_id.is_null() {
        jni_check_exc(env);
        return ffi::JS_ThrowInternalError(ctx, b"GetMethodID toString failed\0".as_ptr() as *const _);
    }

    let art_method = method_id as u64;
    let spec = get_art_method_spec(env, art_method);
    let bridge = find_art_bridge_functions(env, spec.entry_point_offset);

    ensure_art_controller_initialized(bridge, spec.entry_point_offset, env as *mut std::ffi::c_void);

    crate::jsapi::console::output_verbose("[test] artController Layer 1+2 已初始化 (无方法 hook)");

    JSValue::bool(true).raw()
}
