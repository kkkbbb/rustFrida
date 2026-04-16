use crate::context::JSContext;
use crate::ffi;
use crate::jsapi::callback_util::extract_pointer_address;
use crate::jsapi::java::ensure_jni_initialized;
use crate::jsapi::ptr::create_native_pointer;
use crate::jsapi::util::add_cfunction_to_object;
use crate::value::JSValue;
use std::ffi::CString;

use super::load_jni_boot_script;

unsafe fn resolve_env_ptr(
    ctx: *mut ffi::JSContext,
    argc: i32,
    argv: *mut ffi::JSValue,
    func_name: &str,
    argc_with_explicit_env: i32,
) -> Result<(u64, usize), ffi::JSValue> {
    if argc >= argc_with_explicit_env {
        let env_ptr = extract_pointer_address(ctx, JSValue(*argv), func_name)?;
        Ok((env_ptr, 1))
    } else {
        let env = ensure_jni_initialized().map_err(|err| {
            let msg = CString::new(format!("Jni current thread env init failed: {}", err)).unwrap_or_default();
            ffi::JS_ThrowInternalError(ctx, msg.as_ptr())
        })?;
        Ok((env as usize as u64, 0))
    }
}

unsafe fn resolve_ref_arg(
    ctx: *mut ffi::JSContext,
    argv: *mut ffi::JSValue,
    index: usize,
    func_name: &str,
) -> Result<u64, ffi::JSValue> {
    extract_pointer_address(ctx, JSValue(*argv.add(index)), func_name)
}

unsafe fn resolve_env_and_ref(
    ctx: *mut ffi::JSContext,
    argc: i32,
    argv: *mut ffi::JSValue,
    func_name: &str,
    argc_with_explicit_env: i32,
) -> Result<(u64, u64), ffi::JSValue> {
    let (env_ptr, ref_index) = resolve_env_ptr(ctx, argc, argv, func_name, argc_with_explicit_env)?;
    let ref_ptr = resolve_ref_arg(ctx, argv, ref_index, func_name)?;
    Ok((env_ptr, ref_ptr))
}

unsafe fn resolve_env_and_two_refs(
    ctx: *mut ffi::JSContext,
    argc: i32,
    argv: *mut ffi::JSValue,
    func_name: &str,
    argc_with_explicit_env: i32,
) -> Result<(u64, u64, u64), ffi::JSValue> {
    let (env_ptr, first_index) = resolve_env_ptr(ctx, argc, argv, func_name, argc_with_explicit_env)?;
    let first_ptr = resolve_ref_arg(ctx, argv, first_index, func_name)?;
    let second_ptr = resolve_ref_arg(ctx, argv, first_index + 1, func_name)?;
    Ok((env_ptr, first_ptr, second_ptr))
}

unsafe extern "C" fn js_jni_class_name(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Jni._className() requires 2 arguments: envPtr, classPtr\0".as_ptr() as *const _,
        );
    }

    let env_ptr = match extract_pointer_address(ctx, JSValue(*argv), "Jni._className") {
        Ok(v) => v,
        Err(err) => return err,
    };
    let cls_ptr = match extract_pointer_address(ctx, JSValue(*argv.add(1)), "Jni._className") {
        Ok(v) => v,
        Err(err) => return err,
    };

    match crate::jsapi::java::try_get_class_name(env_ptr, cls_ptr) {
        Some(name) => JSValue::string(ctx, &name).raw(),
        None => JSValue::null().raw(),
    }
}

unsafe extern "C" fn js_jni_thread_env(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    match ensure_jni_initialized() {
        Ok(env) => create_native_pointer(ctx, env as usize as u64).raw(),
        Err(err) => {
            let msg = CString::new(format!("Jni current thread env init failed: {}", err)).unwrap_or_default();
            ffi::JS_ThrowInternalError(ctx, msg.as_ptr())
        }
    }
}

unsafe extern "C" fn js_jni_read_jstring(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Jni._readJString() requires at least 1 argument: jstringPtr\0".as_ptr() as *const _,
        );
    }

    let (env_ptr, str_ptr) = match resolve_env_and_ref(ctx, argc, argv, "Jni._readJString", 2) {
        Ok(v) => v,
        Err(err) => return err,
    };

    match crate::jsapi::java::try_read_jstring(env_ptr, str_ptr) {
        Some(text) => JSValue::string(ctx, &text).raw(),
        None => JSValue::null().raw(),
    }
}

unsafe extern "C" fn js_jni_get_object_class(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Jni._getObjectClass() requires at least 1 argument: objPtr\0".as_ptr() as *const _,
        );
    }

    let (env_ptr, obj_ptr) = match resolve_env_and_ref(ctx, argc, argv, "Jni._getObjectClass", 2) {
        Ok(v) => v,
        Err(err) => return err,
    };

    match crate::jsapi::java::try_get_object_class(env_ptr, obj_ptr) {
        Some(cls) => create_native_pointer(ctx, cls).raw(),
        None => JSValue::null().raw(),
    }
}

unsafe extern "C" fn js_jni_get_superclass(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Jni._getSuperclass() requires at least 1 argument: classPtr\0".as_ptr() as *const _,
        );
    }

    let (env_ptr, cls_ptr) = match resolve_env_and_ref(ctx, argc, argv, "Jni._getSuperclass", 2) {
        Ok(v) => v,
        Err(err) => return err,
    };

    match crate::jsapi::java::try_get_superclass(env_ptr, cls_ptr) {
        Some(cls) => create_native_pointer(ctx, cls).raw(),
        None => JSValue::null().raw(),
    }
}

unsafe extern "C" fn js_jni_is_same_object(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Jni._isSameObject() requires at least 2 arguments: aPtr, bPtr\0".as_ptr() as *const _,
        );
    }

    let (env_ptr, a_ptr, b_ptr) = match resolve_env_and_two_refs(ctx, argc, argv, "Jni._isSameObject", 3) {
        Ok(v) => v,
        Err(err) => return err,
    };

    JSValue::bool(crate::jsapi::java::try_is_same_object(env_ptr, a_ptr, b_ptr)).raw()
}

unsafe extern "C" fn js_jni_is_instance_of(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Jni._isInstanceOf() requires at least 2 arguments: objPtr, classPtr\0".as_ptr() as *const _,
        );
    }

    let (env_ptr, obj_ptr, cls_ptr) = match resolve_env_and_two_refs(ctx, argc, argv, "Jni._isInstanceOf", 3) {
        Ok(v) => v,
        Err(err) => return err,
    };

    JSValue::bool(crate::jsapi::java::try_is_instance_of(env_ptr, obj_ptr, cls_ptr)).raw()
}

unsafe extern "C" fn js_jni_get_object_class_name(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Jni._getObjectClassName() requires at least 1 argument: objPtr\0".as_ptr() as *const _,
        );
    }

    let (env_ptr, obj_ptr) = match resolve_env_and_ref(ctx, argc, argv, "Jni._getObjectClassName", 2) {
        Ok(v) => v,
        Err(err) => return err,
    };

    match crate::jsapi::java::try_get_object_class_name(env_ptr, obj_ptr) {
        Some(name) => JSValue::string(ctx, &name).raw(),
        None => JSValue::null().raw(),
    }
}

pub fn register_jni_api(ctx: &JSContext) {
    let global = ctx.global_object();

    unsafe {
        let ctx_ptr = ctx.as_ptr();
        let jni_obj = ffi::JS_NewObject(ctx_ptr);
        add_cfunction_to_object(ctx_ptr, jni_obj, "_className", js_jni_class_name, 2);
        add_cfunction_to_object(ctx_ptr, jni_obj, "_getObjectClass", js_jni_get_object_class, 2);
        add_cfunction_to_object(ctx_ptr, jni_obj, "_getSuperclass", js_jni_get_superclass, 2);
        add_cfunction_to_object(ctx_ptr, jni_obj, "_isSameObject", js_jni_is_same_object, 3);
        add_cfunction_to_object(ctx_ptr, jni_obj, "_isInstanceOf", js_jni_is_instance_of, 3);
        add_cfunction_to_object(ctx_ptr, jni_obj, "_getObjectClassName", js_jni_get_object_class_name, 2);
        add_cfunction_to_object(ctx_ptr, jni_obj, "_readJString", js_jni_read_jstring, 2);
        add_cfunction_to_object(ctx_ptr, jni_obj, "_threadEnv", js_jni_thread_env, 0);
        global.set_property(ctx_ptr, "Jni", JSValue(jni_obj));
    }

    global.free(ctx.as_ptr());
    load_jni_boot_script(ctx);
}
