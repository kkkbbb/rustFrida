//! JS API: Java field access
//!   - Java.getField(objPtr, cls, name, sig) — 显式低层 API
//!   - Java._fieldMeta / _readField / _writeField — Frida-style FieldWrapper 后端（无 FIELD_CACHE 锁）

use crate::ffi;
use crate::value::JSValue;
use std::ffi::CString;

use super::art_method::*;
use super::callback::*;
use super::jni_core::*;
use super::reflect::*;

// ============================================================================
// Shared field-value reader (used by getField and _readField)
// ============================================================================

pub(super) enum ObjectFieldMode {
    RawPointer,
    WrappedProxy { type_name: String },
}

/// Read a single field value from a JNI object (or class for static fields),
/// dispatching on the JNI type signature.
/// For 'L'/'[' fields: String fields become JS strings; other objects are handled
/// according to `mode` (RawPointer returns BigUint64, WrappedProxy returns {__jptr, __jclass}).
///
/// `obj_or_cls`: for instance fields, this is the JNI local ref to the object;
///               for static fields, this is the jclass.
unsafe fn read_field_value(
    ctx: *mut ffi::JSContext,
    env: JniEnv,
    obj_or_cls: *mut std::ffi::c_void,
    field_id: *mut std::ffi::c_void,
    jni_sig: &str,
    is_static: bool,
    mode: ObjectFieldMode,
) -> ffi::JSValue {
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);

    let sig_bytes = jni_sig.as_bytes();
    match sig_bytes.first() {
        Some(b'Z') => {
            if is_static {
                let f: GetStaticBooleanFieldFn = jni_fn!(env, GetStaticBooleanFieldFn, JNI_GET_STATIC_BOOLEAN_FIELD);
                JSValue::bool(f(env, obj_or_cls, field_id) != 0).raw()
            } else {
                let f: GetBooleanFieldFn = jni_fn!(env, GetBooleanFieldFn, JNI_GET_BOOLEAN_FIELD);
                JSValue::bool(f(env, obj_or_cls, field_id) != 0).raw()
            }
        }
        Some(b'B') => {
            if is_static {
                let f: GetStaticByteFieldFn = jni_fn!(env, GetStaticByteFieldFn, JNI_GET_STATIC_BYTE_FIELD);
                JSValue::int(f(env, obj_or_cls, field_id) as i32).raw()
            } else {
                let f: GetByteFieldFn = jni_fn!(env, GetByteFieldFn, JNI_GET_BYTE_FIELD);
                JSValue::int(f(env, obj_or_cls, field_id) as i32).raw()
            }
        }
        Some(b'C') => {
            if is_static {
                let f: GetStaticCharFieldFn = jni_fn!(env, GetStaticCharFieldFn, JNI_GET_STATIC_CHAR_FIELD);
                JSValue::int(f(env, obj_or_cls, field_id) as i32).raw()
            } else {
                let f: GetCharFieldFn = jni_fn!(env, GetCharFieldFn, JNI_GET_CHAR_FIELD);
                JSValue::int(f(env, obj_or_cls, field_id) as i32).raw()
            }
        }
        Some(b'S') => {
            if is_static {
                let f: GetStaticShortFieldFn = jni_fn!(env, GetStaticShortFieldFn, JNI_GET_STATIC_SHORT_FIELD);
                JSValue::int(f(env, obj_or_cls, field_id) as i32).raw()
            } else {
                let f: GetShortFieldFn = jni_fn!(env, GetShortFieldFn, JNI_GET_SHORT_FIELD);
                JSValue::int(f(env, obj_or_cls, field_id) as i32).raw()
            }
        }
        Some(b'I') => {
            if is_static {
                let f: GetStaticIntFieldFn = jni_fn!(env, GetStaticIntFieldFn, JNI_GET_STATIC_INT_FIELD);
                JSValue::int(f(env, obj_or_cls, field_id)).raw()
            } else {
                let f: GetIntFieldFn = jni_fn!(env, GetIntFieldFn, JNI_GET_INT_FIELD);
                JSValue::int(f(env, obj_or_cls, field_id)).raw()
            }
        }
        Some(b'J') => {
            if is_static {
                let f: GetStaticLongFieldFn = jni_fn!(env, GetStaticLongFieldFn, JNI_GET_STATIC_LONG_FIELD);
                ffi::JS_NewBigUint64(ctx, f(env, obj_or_cls, field_id) as u64)
            } else {
                let f: GetLongFieldFn = jni_fn!(env, GetLongFieldFn, JNI_GET_LONG_FIELD);
                ffi::JS_NewBigUint64(ctx, f(env, obj_or_cls, field_id) as u64)
            }
        }
        Some(b'F') => {
            if is_static {
                let f: GetStaticFloatFieldFn = jni_fn!(env, GetStaticFloatFieldFn, JNI_GET_STATIC_FLOAT_FIELD);
                JSValue::float(f(env, obj_or_cls, field_id) as f64).raw()
            } else {
                let f: GetFloatFieldFn = jni_fn!(env, GetFloatFieldFn, JNI_GET_FLOAT_FIELD);
                JSValue::float(f(env, obj_or_cls, field_id) as f64).raw()
            }
        }
        Some(b'D') => {
            if is_static {
                let f: GetStaticDoubleFieldFn = jni_fn!(env, GetStaticDoubleFieldFn, JNI_GET_STATIC_DOUBLE_FIELD);
                JSValue::float(f(env, obj_or_cls, field_id)).raw()
            } else {
                let f: GetDoubleFieldFn = jni_fn!(env, GetDoubleFieldFn, JNI_GET_DOUBLE_FIELD);
                JSValue::float(f(env, obj_or_cls, field_id)).raw()
            }
        }
        Some(b'L') | Some(b'[') => {
            let obj_val = if is_static {
                let f: GetStaticObjectFieldFn = jni_fn!(env, GetStaticObjectFieldFn, JNI_GET_STATIC_OBJECT_FIELD);
                f(env, obj_or_cls, field_id)
            } else {
                let f: GetObjectFieldFn = jni_fn!(env, GetObjectFieldFn, JNI_GET_OBJECT_FIELD);
                f(env, obj_or_cls, field_id)
            };

            if obj_val.is_null() {
                return ffi::qjs_null();
            }

            // Check if String type
            if jni_sig == "Ljava/lang/String;" {
                let get_str: GetStringUtfCharsFn = jni_fn!(env, GetStringUtfCharsFn, JNI_GET_STRING_UTF_CHARS);
                let rel_str: ReleaseStringUtfCharsFn =
                    jni_fn!(env, ReleaseStringUtfCharsFn, JNI_RELEASE_STRING_UTF_CHARS);

                let chars = get_str(env, obj_val, std::ptr::null_mut());
                let js_result = if !chars.is_null() {
                    let s = std::ffi::CStr::from_ptr(chars).to_string_lossy().to_string();
                    rel_str(env, obj_val, chars);
                    JSValue::string(ctx, &s).raw()
                } else {
                    ffi::qjs_null()
                };
                delete_local_ref(env, obj_val);
                return js_result;
            }

            match mode {
                ObjectFieldMode::RawPointer => {
                    let ptr_val = obj_val as u64;
                    delete_local_ref(env, obj_val);
                    ffi::JS_NewBigUint64(ctx, ptr_val)
                }
                ObjectFieldMode::WrappedProxy { ref type_name } => {
                    marshal_local_java_object_to_js(ctx, env, obj_val, Some(type_name))
                }
            }
        }
        _ => ffi::qjs_undefined(),
    }
}

// ============================================================================
// JS API: Java.getField(objPtr, className, fieldName, fieldSig)
// ============================================================================

pub(super) unsafe extern "C" fn js_java_get_field(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    use crate::jsapi::ptr::get_native_pointer_addr;

    if argc < 4 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Java.getField() requires 4 arguments: objPtr, className, fieldName, fieldSig\0".as_ptr() as *const _,
        );
    }

    let obj_arg = JSValue(*argv);
    let class_arg = JSValue(*argv.add(1));
    let method_arg = JSValue(*argv.add(2));
    let sig_arg = JSValue(*argv.add(3));

    // Extract objPtr — try NativePointer first, then BigUint64/Number
    let obj_ptr = if let Some(addr) = get_native_pointer_addr(ctx, obj_arg) {
        addr
    } else if let Some(addr) = obj_arg.to_u64(ctx) {
        addr
    } else {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Java.getField() first argument must be a pointer (BigUint64/Number/NativePointer)\0".as_ptr() as *const _,
        );
    };

    if obj_ptr == 0 {
        return ffi::JS_ThrowTypeError(ctx, b"Java.getField() objPtr is null\0".as_ptr() as *const _);
    }

    let class_name = match class_arg.to_string(ctx) {
        Some(s) => s,
        None => {
            return ffi::JS_ThrowTypeError(
                ctx,
                b"Java.getField() className must be a string\0".as_ptr() as *const _,
            )
        }
    };

    let field_name = match method_arg.to_string(ctx) {
        Some(s) => s,
        None => {
            return ffi::JS_ThrowTypeError(
                ctx,
                b"Java.getField() fieldName must be a string\0".as_ptr() as *const _,
            )
        }
    };

    let field_sig = match sig_arg.to_string(ctx) {
        Some(s) => s,
        None => {
            return ffi::JS_ThrowTypeError(ctx, b"Java.getField() fieldSig must be a string\0".as_ptr() as *const _)
        }
    };

    // Get thread-safe JNIEnv*
    let env = match get_thread_env() {
        Ok(e) => e,
        Err(msg) => {
            let err = CString::new(msg).unwrap();
            return ffi::JS_ThrowInternalError(ctx, err.as_ptr());
        }
    };

    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
    let new_local_ref: NewLocalRefFn = jni_fn!(env, NewLocalRefFn, JNI_NEW_LOCAL_REF);
    let get_field_id: GetFieldIdFn = jni_fn!(env, GetFieldIdFn, JNI_GET_FIELD_ID);

    // FindClass — use find_class_safe to support app classes
    let cls = find_class_safe(env, &class_name);
    if cls.is_null() {
        let err = CString::new(format!("FindClass('{}') failed", class_name)).unwrap();
        return ffi::JS_ThrowInternalError(ctx, err.as_ptr());
    }

    // NewLocalRef — wrap raw mirror pointer as a proper JNI local ref
    let local_obj = new_local_ref(env, obj_ptr as *mut std::ffi::c_void);
    if local_obj.is_null() {
        delete_local_ref(env, cls);
        return ffi::JS_ThrowInternalError(ctx, b"NewLocalRef failed for objPtr\0".as_ptr() as *const _);
    }

    // GetFieldID
    let c_field = match CString::new(field_name.as_str()) {
        Ok(c) => c,
        Err(_) => {
            delete_local_ref(env, local_obj);
            delete_local_ref(env, cls);
            return ffi::JS_ThrowTypeError(ctx, b"invalid field name\0".as_ptr() as *const _);
        }
    };
    let c_sig = match CString::new(field_sig.as_str()) {
        Ok(c) => c,
        Err(_) => {
            delete_local_ref(env, local_obj);
            delete_local_ref(env, cls);
            return ffi::JS_ThrowTypeError(ctx, b"invalid field signature\0".as_ptr() as *const _);
        }
    };

    let field_id = get_field_id(env, cls, c_field.as_ptr(), c_sig.as_ptr());
    if field_id.is_null() || jni_check_exc(env) {
        delete_local_ref(env, local_obj);
        delete_local_ref(env, cls);
        let err = CString::new(format!(
            "GetFieldID failed: {}.{} (sig={})",
            class_name, field_name, field_sig
        ))
        .unwrap();
        return ffi::JS_ThrowInternalError(ctx, err.as_ptr());
    }

    // Check for unsupported signature before calling read_field_value
    let sig_first = field_sig.as_bytes().first().copied();
    if !matches!(
        sig_first,
        Some(b'Z' | b'B' | b'C' | b'S' | b'I' | b'J' | b'F' | b'D' | b'L' | b'[')
    ) {
        delete_local_ref(env, local_obj);
        delete_local_ref(env, cls);
        let err = CString::new(format!("unsupported field signature: {}", field_sig)).unwrap();
        return ffi::JS_ThrowTypeError(ctx, err.as_ptr());
    }

    // Dispatch via shared helper (RawPointer mode — returns BigUint64 for objects)
    // Note: js_java_get_field only supports instance fields (GetFieldID was used above)
    let result = read_field_value(
        ctx,
        env,
        local_obj,
        field_id,
        &field_sig,
        false,
        ObjectFieldMode::RawPointer,
    );

    // Check for JNI exception after field access
    if jni_check_exc(env) {
        delete_local_ref(env, local_obj);
        delete_local_ref(env, cls);
        let err = CString::new(format!("JNI exception reading field {}.{}", class_name, field_name)).unwrap();
        return ffi::JS_ThrowInternalError(ctx, err.as_ptr());
    }

    delete_local_ref(env, local_obj);
    delete_local_ref(env, cls);
    result
}

// ============================================================================
// FIELD_CACHE 查找 + runtime class 探测（_fieldMeta / _readField / _writeField 共用）
// ============================================================================

/// Try to look up a field in FIELD_CACHE for the given class.
/// Returns (jni_sig, field_id, is_static, type_name) or None if not found.
unsafe fn lookup_field_in_cache(
    class_name: &str,
    field_name: &str,
) -> Option<(String, *mut std::ffi::c_void, bool, String)> {
    let guard = FIELD_CACHE.lock().unwrap_or_else(|e| e.into_inner());
    let cache = guard.as_ref()?;
    let class_fields = cache.get(class_name)?;
    let info = class_fields.get(field_name)?;
    let tn = match info.jni_sig.as_bytes().first() {
        Some(b'L') => {
            let inner = &info.jni_sig[1..info.jni_sig.len() - 1];
            inner.replace('/', ".")
        }
        Some(b'[') => info.jni_sig.clone(),
        _ => String::new(),
    };
    Some((info.jni_sig.clone(), info.field_id, info.is_static, tn))
}

/// Check if a class is already in FIELD_CACHE.
unsafe fn is_class_cached(class_name: &str) -> bool {
    let guard = FIELD_CACHE.lock().unwrap_or_else(|e| e.into_inner());
    match guard.as_ref() {
        Some(cache) => cache.contains_key(class_name),
        None => false,
    }
}

/// Get the runtime class name of a JNI object via GetObjectClass + Class.getName().
unsafe fn get_runtime_class_name(env: JniEnv, obj: *mut std::ffi::c_void) -> Option<String> {
    let get_object_class: GetObjectClassFn = jni_fn!(env, GetObjectClassFn, JNI_GET_OBJECT_CLASS);
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
    let call_obj: CallObjectMethodAFn = jni_fn!(env, CallObjectMethodAFn, JNI_CALL_OBJECT_METHOD_A);
    let get_str: GetStringUtfCharsFn = jni_fn!(env, GetStringUtfCharsFn, JNI_GET_STRING_UTF_CHARS);
    let rel_str: ReleaseStringUtfCharsFn = jni_fn!(env, ReleaseStringUtfCharsFn, JNI_RELEASE_STRING_UTF_CHARS);

    let reflect = REFLECT_IDS.get()?;

    let cls_obj = get_object_class(env, obj);
    if cls_obj.is_null() {
        jni_check_exc(env);
        return None;
    }

    let name_jstr = call_obj(env, cls_obj, reflect.class_get_name_mid, std::ptr::null());
    delete_local_ref(env, cls_obj);
    if name_jstr.is_null() {
        jni_check_exc(env);
        return None;
    }

    let chars = get_str(env, name_jstr, std::ptr::null_mut());
    if chars.is_null() {
        delete_local_ref(env, name_jstr);
        jni_check_exc(env);
        return None;
    }
    let name = std::ffi::CStr::from_ptr(chars).to_string_lossy().to_string();
    rel_str(env, name_jstr, chars);
    delete_local_ref(env, name_jstr);
    Some(name)
}

/// 写入字段值的核心分发（实例字段和静态字段共用）
unsafe fn write_field_value_dispatch(
    ctx: *mut ffi::JSContext,
    env: JniEnv,
    target: *mut std::ffi::c_void,
    field_id: *mut std::ffi::c_void,
    jni_sig: &str,
    is_static: bool,
    value: JSValue,
) {
    match jni_sig.as_bytes().first().copied() {
        Some(b'Z') => {
            let v = if value.is_bool() { value.to_bool().unwrap_or(false) as u8 }
                    else { value.to_i64(ctx).map(|n| (n != 0) as u8).unwrap_or(0) };
            if is_static {
                type F = unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, u8);
                let f: F = jni_fn!(env, F, JNI_SET_STATIC_BOOLEAN_FIELD);
                f(env, target, field_id, v);
            } else {
                type F = unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, u8);
                let f: F = jni_fn!(env, F, JNI_SET_BOOLEAN_FIELD);
                f(env, target, field_id, v);
            }
        }
        Some(b'B') => {
            let v = value.to_i64(ctx).unwrap_or(0) as i8;
            if is_static {
                type F = unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, i8);
                let f: F = jni_fn!(env, F, JNI_SET_STATIC_BYTE_FIELD);
                f(env, target, field_id, v);
            } else {
                type F = unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, i8);
                let f: F = jni_fn!(env, F, JNI_SET_BYTE_FIELD);
                f(env, target, field_id, v);
            }
        }
        Some(b'C') => {
            let v = if let Some(s) = value.to_string(ctx) {
                s.chars().next().map(|c| c as u16).unwrap_or(0)
            } else { value.to_i64(ctx).unwrap_or(0) as u16 };
            if is_static {
                type F = unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, u16);
                let f: F = jni_fn!(env, F, JNI_SET_STATIC_CHAR_FIELD);
                f(env, target, field_id, v);
            } else {
                type F = unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, u16);
                let f: F = jni_fn!(env, F, JNI_SET_CHAR_FIELD);
                f(env, target, field_id, v);
            }
        }
        Some(b'S') => {
            let v = value.to_i64(ctx).unwrap_or(0) as i16;
            if is_static {
                type F = unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, i16);
                let f: F = jni_fn!(env, F, JNI_SET_STATIC_SHORT_FIELD);
                f(env, target, field_id, v);
            } else {
                type F = unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, i16);
                let f: F = jni_fn!(env, F, JNI_SET_SHORT_FIELD);
                f(env, target, field_id, v);
            }
        }
        Some(b'I') => {
            let v = value.to_i64(ctx).unwrap_or(0) as i32;
            if is_static {
                type F = unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, i32);
                let f: F = jni_fn!(env, F, JNI_SET_STATIC_INT_FIELD);
                f(env, target, field_id, v);
            } else {
                type F = unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, i32);
                let f: F = jni_fn!(env, F, JNI_SET_INT_FIELD);
                f(env, target, field_id, v);
            }
        }
        Some(b'J') => {
            let v = value.to_i64(ctx).unwrap_or(0);
            if is_static {
                type F = unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, i64);
                let f: F = jni_fn!(env, F, JNI_SET_STATIC_LONG_FIELD);
                f(env, target, field_id, v);
            } else {
                type F = unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, i64);
                let f: F = jni_fn!(env, F, JNI_SET_LONG_FIELD);
                f(env, target, field_id, v);
            }
        }
        Some(b'F') => {
            let v = value.to_float().unwrap_or(0.0) as f32;
            if is_static {
                type F = unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, f32);
                let f: F = jni_fn!(env, F, JNI_SET_STATIC_FLOAT_FIELD);
                f(env, target, field_id, v);
            } else {
                type F = unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, f32);
                let f: F = jni_fn!(env, F, JNI_SET_FLOAT_FIELD);
                f(env, target, field_id, v);
            }
        }
        Some(b'D') => {
            let v = value.to_float().unwrap_or(0.0);
            if is_static {
                type F = unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, f64);
                let f: F = jni_fn!(env, F, JNI_SET_STATIC_DOUBLE_FIELD);
                f(env, target, field_id, v);
            } else {
                type F = unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, f64);
                let f: F = jni_fn!(env, F, JNI_SET_DOUBLE_FIELD);
                f(env, target, field_id, v);
            }
        }
        Some(b'L') | Some(b'[') => {
            use super::callback::marshal_js_to_jvalue;
            let jval = marshal_js_to_jvalue(ctx, env, value, Some(jni_sig));
            if is_static {
                type F = unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, *mut std::ffi::c_void);
                let f: F = jni_fn!(env, F, JNI_SET_STATIC_OBJECT_FIELD);
                f(env, target, field_id, jval as *mut std::ffi::c_void);
            } else {
                type F = unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, *mut std::ffi::c_void);
                let f: F = jni_fn!(env, F, JNI_SET_OBJECT_FIELD);
                f(env, target, field_id, jval as *mut std::ffi::c_void);
            }
        }
        _ => {}
    }
}

/// 写入实例字段值
unsafe fn write_instance_field(
    ctx: *mut ffi::JSContext,
    env: JniEnv,
    obj_ptr: u64,
    jni_sig: &str,
    field_id: *mut std::ffi::c_void,
    value: JSValue,
) -> bool {
    let new_local_ref: NewLocalRefFn = jni_fn!(env, NewLocalRefFn, JNI_NEW_LOCAL_REF);
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);

    let local_obj = new_local_ref(env, obj_ptr as *mut std::ffi::c_void);
    if local_obj.is_null() {
        return false;
    }

    write_field_value_dispatch(ctx, env, local_obj, field_id, jni_sig, false, value);

    let ok = !jni_check_exc(env);
    delete_local_ref(env, local_obj);
    ok
}

/// 写入静态字段值
unsafe fn write_static_field(
    ctx: *mut ffi::JSContext,
    env: JniEnv,
    class_name: &str,
    jni_sig: &str,
    field_id: *mut std::ffi::c_void,
    value: JSValue,
) -> bool {
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
    let cls = find_class_safe(env, class_name);
    if cls.is_null() {
        return false;
    }

    write_field_value_dispatch(ctx, env, cls, field_id, jni_sig, true, value);

    let ok = !jni_check_exc(env);
    delete_local_ref(env, cls);
    ok
}

// ============================================================================
// Frida-style FieldWrapper 后端: _fieldMeta / _readField / _writeField
// 前端 FieldWrapper 缓存 meta，后续读写跳过 FIELD_CACHE 锁
// ============================================================================

/// 从 JNI sig 提取 type_name（用于 WrappedProxy mode）
fn type_name_from_sig(sig: &str) -> String {
    match sig.as_bytes().first() {
        Some(b'L') => {
            let inner = &sig[1..sig.len().saturating_sub(1)];
            inner.replace('/', ".")
        }
        Some(b'[') => sig.to_string(),
        _ => String::new(),
    }
}

/// 构造 {id: BigUint64(field_id), sig: string, st: boolean, cls: string}
unsafe fn make_field_meta_obj(
    ctx: *mut ffi::JSContext,
    field_id: *mut std::ffi::c_void,
    sig: &str,
    is_static: bool,
    class_name: &str,
) -> ffi::JSValue {
    let obj = ffi::JS_NewObject(ctx);
    let obj_val = JSValue(obj);
    obj_val.set_property(ctx, "id", JSValue(ffi::JS_NewBigUint64(ctx, field_id as u64)));
    obj_val.set_property(ctx, "sig", JSValue::string(ctx, sig));
    obj_val.set_property(ctx, "st", JSValue::bool(is_static));
    obj_val.set_property(ctx, "cls", JSValue::string(ctx, class_name));
    obj
}

// JS API: Java._fieldMeta(className, fieldName, [objPtr])
// 返回 {id, sig, st, cls} 或 undefined（一次性解析，JS 侧缓存）
pub(super) unsafe extern "C" fn js_java_field_meta(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return ffi::qjs_undefined();
    }

    let class_arg = JSValue(*argv);
    let field_arg = JSValue(*argv.add(1));

    let class_name = match class_arg.to_string(ctx) {
        Some(s) => s,
        None => return ffi::qjs_undefined(),
    };
    let field_name = match field_arg.to_string(ctx) {
        Some(s) => s,
        None => return ffi::qjs_undefined(),
    };

    let env = match get_thread_env() {
        Ok(e) => e,
        Err(_) => return ffi::qjs_undefined(),
    };

    // 确保声明类已缓存
    if !is_class_cached(&class_name) {
        cache_fields_for_class(env, &class_name);
    }

    // 查找声明类
    if let Some((sig, field_id, is_static, _)) = lookup_field_in_cache(&class_name, &field_name) {
        return make_field_meta_obj(ctx, field_id, &sig, is_static, &class_name);
    }

    // Runtime class fallback（需要 objPtr）
    if argc >= 3 {
        use crate::jsapi::ptr::get_native_pointer_addr;
        let obj_arg = JSValue(*argv.add(2));
        let obj_ptr = get_native_pointer_addr(ctx, obj_arg)
            .or_else(|| obj_arg.to_u64(ctx))
            .unwrap_or(0);

        if obj_ptr != 0 {
            let new_local_ref: NewLocalRefFn = jni_fn!(env, NewLocalRefFn, JNI_NEW_LOCAL_REF);
            let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);

            let local_obj = new_local_ref(env, obj_ptr as *mut std::ffi::c_void);
            if !local_obj.is_null() {
                if let Some(ref rt_cls) = get_runtime_class_name(env, local_obj) {
                    if rt_cls != &class_name {
                        if !is_class_cached(rt_cls) {
                            cache_fields_for_class(env, rt_cls);
                        }
                        if let Some((sig, field_id, is_static, _)) =
                            lookup_field_in_cache(rt_cls, &field_name)
                        {
                            delete_local_ref(env, local_obj);
                            return make_field_meta_obj(ctx, field_id, &sig, is_static, rt_cls);
                        }
                    }
                }
                delete_local_ref(env, local_obj);
            }
        }
    }

    ffi::qjs_undefined()
}

// JS API: Java._readField(objPtr, fieldId, sig, isStatic, cls)
// 直接用预解析的 field_id 读值，无 FIELD_CACHE 锁
pub(super) unsafe extern "C" fn js_java_read_field(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    use crate::jsapi::ptr::get_native_pointer_addr;

    if argc < 5 {
        return ffi::qjs_undefined();
    }

    let obj_arg = JSValue(*argv);
    let id_arg = JSValue(*argv.add(1));
    let sig_arg = JSValue(*argv.add(2));
    let static_arg = JSValue(*argv.add(3));
    let cls_arg = JSValue(*argv.add(4));

    let field_id = id_arg.to_u64(ctx).unwrap_or(0) as *mut std::ffi::c_void;
    if field_id.is_null() {
        return ffi::qjs_undefined();
    }
    let sig = match sig_arg.to_string(ctx) {
        Some(s) => s,
        None => return ffi::qjs_undefined(),
    };
    let is_static = static_arg.to_bool().unwrap_or(false);
    let cls_name = match cls_arg.to_string(ctx) {
        Some(s) => s,
        None => return ffi::qjs_undefined(),
    };

    let env = match get_thread_env() {
        Ok(e) => e,
        Err(_) => return ffi::qjs_undefined(),
    };

    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
    let type_name = type_name_from_sig(&sig);
    let mode = ObjectFieldMode::WrappedProxy { type_name };

    if is_static {
        let cls = find_class_safe(env, &cls_name);
        if cls.is_null() {
            return ffi::qjs_undefined();
        }
        let result = read_field_value(ctx, env, cls, field_id, &sig, true, mode);
        jni_check_exc(env);
        delete_local_ref(env, cls);
        result
    } else {
        let obj_ptr = get_native_pointer_addr(ctx, obj_arg)
            .or_else(|| obj_arg.to_u64(ctx))
            .unwrap_or(0);
        if obj_ptr == 0 {
            return ffi::qjs_undefined();
        }
        let new_local_ref: NewLocalRefFn = jni_fn!(env, NewLocalRefFn, JNI_NEW_LOCAL_REF);
        let local_obj = new_local_ref(env, obj_ptr as *mut std::ffi::c_void);
        if local_obj.is_null() {
            return ffi::qjs_undefined();
        }
        let result = read_field_value(ctx, env, local_obj, field_id, &sig, false, mode);
        jni_check_exc(env);
        delete_local_ref(env, local_obj);
        result
    }
}

// JS API: Java._writeField(objPtr, fieldId, sig, isStatic, cls, value)
// 直接用预解析的 field_id 写值，无 FIELD_CACHE 锁
pub(super) unsafe extern "C" fn js_java_write_field(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    use crate::jsapi::ptr::get_native_pointer_addr;

    if argc < 6 {
        return ffi::qjs_undefined();
    }

    let obj_arg = JSValue(*argv);
    let id_arg = JSValue(*argv.add(1));
    let sig_arg = JSValue(*argv.add(2));
    let static_arg = JSValue(*argv.add(3));
    let cls_arg = JSValue(*argv.add(4));
    let value_arg = JSValue(*argv.add(5));

    let field_id = id_arg.to_u64(ctx).unwrap_or(0) as *mut std::ffi::c_void;
    if field_id.is_null() {
        return ffi::qjs_undefined();
    }
    let sig = match sig_arg.to_string(ctx) {
        Some(s) => s,
        None => return ffi::qjs_undefined(),
    };
    let is_static = static_arg.to_bool().unwrap_or(false);
    let cls_name = match cls_arg.to_string(ctx) {
        Some(s) => s,
        None => return ffi::qjs_undefined(),
    };

    let env = match get_thread_env() {
        Ok(e) => e,
        Err(_) => return ffi::qjs_undefined(),
    };

    if is_static {
        write_static_field(ctx, env, &cls_name, &sig, field_id, value_arg);
    } else {
        let obj_ptr = get_native_pointer_addr(ctx, obj_arg)
            .or_else(|| obj_arg.to_u64(ctx))
            .unwrap_or(0);
        if obj_ptr != 0 {
            write_instance_field(ctx, env, obj_ptr, &sig, field_id, value_arg);
        }
    }

    ffi::qjs_undefined()
}
