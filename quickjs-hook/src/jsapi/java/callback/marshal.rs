// ============================================================================
// ARM64 JNI calling convention helpers
// ============================================================================

std::thread_local! {
    /// 控制 marshal 是否强制返回 Java 对象 wrapper。为 true 时不做任何自动
    /// 类型转换（String 不转 JS string、Integer/Long/... 不 unbox、容器不转
    /// Array），用户拿到的一定是可以继续链式调用 Java 方法的 wrapper。
    /// 目前只在 `Java.use(...).$new(...)` 中打开。
    static RETURN_RAW_WRAPPER: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

pub(super) fn set_return_raw_wrapper(skip: bool) {
    RETURN_RAW_WRAPPER.with(|c| c.set(skip));
}

/// 判断 JNI 类型签名是否表示浮点类型 (float/double)
#[inline]
fn is_floating_point_type(sig: Option<&str>) -> bool {
    matches!(sig, Some(s) if s.starts_with('F') || s.starts_with('D'))
}

/// 从 HookContext 中按 ARM64 JNI 调用约定提取单个参数值。
///
/// ARM64 JNI: GP 寄存器 (x2-x7) 和 FP 寄存器 (d0-d7) 有独立计数器。
/// 返回 (gp_value, fp_value) — 只有一个有意义。
#[inline]
unsafe fn extract_jni_arg(
    hook_ctx: &hook_ffi::HookContext,
    is_fp: bool,
    gp_index: &mut usize,
    fp_index: &mut usize,
) -> (u64, u64) {
    if is_fp {
        let fp_val = if *fp_index < 8 {
            hook_ctx.d[*fp_index]
        } else {
            0u64
        };
        *fp_index += 1;
        (0u64, fp_val)
    } else {
        let gp_val = if *gp_index < 6 {
            hook_ctx.x[2 + *gp_index]
        } else {
            let sp = hook_ctx.sp as usize;
            *((sp + (*gp_index - 6) * 8) as *const u64)
        };
        *gp_index += 1;
        (gp_val, 0u64)
    }
}

#[inline]
fn jni_object_sig_to_class_name(jni_sig: &str) -> String {
    if jni_sig.starts_with('L') && jni_sig.ends_with(';') && jni_sig.len() >= 2 {
        jni_sig[1..jni_sig.len() - 1].replace('/', ".")
    } else {
        jni_sig.replace('/', ".")
    }
}

unsafe fn get_runtime_class_name(env: JniEnv, obj: *mut std::ffi::c_void) -> Option<String> {
    let reflect = REFLECT_IDS.get()?;
    let get_object_class: GetObjectClassFn = jni_fn!(env, GetObjectClassFn, JNI_GET_OBJECT_CLASS);
    let call_obj: CallObjectMethodAFn = jni_fn!(env, CallObjectMethodAFn, JNI_CALL_OBJECT_METHOD_A);
    let get_str: GetStringUtfCharsFn = jni_fn!(env, GetStringUtfCharsFn, JNI_GET_STRING_UTF_CHARS);
    let rel_str: ReleaseStringUtfCharsFn =
        jni_fn!(env, ReleaseStringUtfCharsFn, JNI_RELEASE_STRING_UTF_CHARS);
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);

    let cls_obj = get_object_class(env, obj);
    if cls_obj.is_null() || jni_check_exc(env) {
        return None;
    }

    let name_jstr = call_obj(env, cls_obj, reflect.class_get_name_mid, std::ptr::null());
    delete_local_ref(env, cls_obj);
    if name_jstr.is_null() || jni_check_exc(env) {
        return None;
    }

    let chars = get_str(env, name_jstr, std::ptr::null_mut());
    if chars.is_null() {
        delete_local_ref(env, name_jstr);
        jni_check_exc(env);
        return None;
    }

    let name = std::ffi::CStr::from_ptr(chars)
        .to_string_lossy()
        .to_string();
    rel_str(env, name_jstr, chars);
    delete_local_ref(env, name_jstr);
    Some(name)
}

unsafe fn wrap_java_object_value(
    ctx: *mut ffi::JSContext,
    raw_ptr: u64,
    class_name: &str,
) -> ffi::JSValue {
    let wrapper = ffi::JS_NewObject(ctx);
    let wrapper_val = JSValue(wrapper);

    let ptr_val = ffi::JS_NewBigUint64(ctx, raw_ptr);
    wrapper_val.set_property(ctx, "__jptr", JSValue(ptr_val));

    let cls_val = JSValue::string(ctx, class_name);
    wrapper_val.set_property(ctx, "__jclass", cls_val);

    wrapper
}

const MAX_JAVA_CONTAINER_DEPTH: usize = 16;

unsafe fn wrap_java_object_ref(
    ctx: *mut ffi::JSContext,
    env: JniEnv,
    obj: *mut std::ffi::c_void,
    class_name: &str,
    globalize: bool,
) -> ffi::JSValue {
    if obj.is_null() {
        return ffi::qjs_null();
    }

    if !globalize {
        return wrap_java_object_value(ctx, obj as u64, class_name);
    }

    let new_global_ref: NewGlobalRefFn = jni_fn!(env, NewGlobalRefFn, JNI_NEW_GLOBAL_REF);
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
    let global_ref = new_global_ref(env, obj);
    delete_local_ref(env, obj);
    if global_ref.is_null() || jni_check_exc(env) {
        return ffi::qjs_null();
    }

    wrap_java_object_value(ctx, global_ref as u64, class_name)
}

#[allow(dead_code)]
unsafe fn try_unbox_boxed_primitive(
    ctx: *mut ffi::JSContext,
    env: JniEnv,
    obj: *mut std::ffi::c_void,
    class_name: &str,
    release_local: bool,
) -> Option<ffi::JSValue> {
    let reflect = REFLECT_IDS.get()?;
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);

    let value = match class_name {
        "java.lang.Boolean" => {
            if reflect.boolean_value_mid.is_null() {
                return None;
            }
            let f: CallBooleanMethodAFn =
                jni_fn!(env, CallBooleanMethodAFn, JNI_CALL_BOOLEAN_METHOD_A);
            JSValue::bool(f(env, obj, reflect.boolean_value_mid, std::ptr::null()) != 0).raw()
        }
        "java.lang.Byte" => {
            if reflect.byte_value_mid.is_null() {
                return None;
            }
            let f: CallByteMethodAFn = jni_fn!(env, CallByteMethodAFn, JNI_CALL_BYTE_METHOD_A);
            JSValue::int(f(env, obj, reflect.byte_value_mid, std::ptr::null()) as i32).raw()
        }
        "java.lang.Character" => {
            if reflect.char_value_mid.is_null() {
                return None;
            }
            let f: CallCharMethodAFn = jni_fn!(env, CallCharMethodAFn, JNI_CALL_CHAR_METHOD_A);
            let ch = std::char::from_u32(f(env, obj, reflect.char_value_mid, std::ptr::null()) as u32)
                .unwrap_or('\0')
                .to_string();
            JSValue::string(ctx, &ch).raw()
        }
        "java.lang.Short" => {
            if reflect.short_value_mid.is_null() {
                return None;
            }
            let f: CallShortMethodAFn =
                jni_fn!(env, CallShortMethodAFn, JNI_CALL_SHORT_METHOD_A);
            JSValue::int(f(env, obj, reflect.short_value_mid, std::ptr::null()) as i32).raw()
        }
        "java.lang.Integer" => {
            if reflect.int_value_mid.is_null() {
                return None;
            }
            let f: CallIntMethodAFn = jni_fn!(env, CallIntMethodAFn, JNI_CALL_INT_METHOD_A);
            JSValue::int(f(env, obj, reflect.int_value_mid, std::ptr::null())).raw()
        }
        "java.lang.Long" => {
            if reflect.long_value_mid.is_null() {
                return None;
            }
            let f: CallLongMethodAFn = jni_fn!(env, CallLongMethodAFn, JNI_CALL_LONG_METHOD_A);
            ffi::JS_NewBigUint64(ctx, f(env, obj, reflect.long_value_mid, std::ptr::null()) as u64)
        }
        "java.lang.Float" => {
            if reflect.float_value_mid.is_null() {
                return None;
            }
            let f: CallFloatMethodAFn = jni_fn!(env, CallFloatMethodAFn, JNI_CALL_FLOAT_METHOD_A);
            JSValue::float(f(env, obj, reflect.float_value_mid, std::ptr::null()) as f64).raw()
        }
        "java.lang.Double" => {
            if reflect.double_value_mid.is_null() {
                return None;
            }
            let f: CallDoubleMethodAFn =
                jni_fn!(env, CallDoubleMethodAFn, JNI_CALL_DOUBLE_METHOD_A);
            JSValue::float(f(env, obj, reflect.double_value_mid, std::ptr::null())).raw()
        }
        _ => return None,
    };

    if release_local {
        delete_local_ref(env, obj);
    }

    if jni_check_exc(env) {
        return Some(ffi::qjs_null());
    }

    Some(value)
}

unsafe fn marshal_java_object_to_js_inner(
    ctx: *mut ffi::JSContext,
    env: JniEnv,
    obj: *mut std::ffi::c_void,
    class_name_hint: Option<&str>,
    release_local: bool,
    globalize_wrappers: bool,
    depth: usize,
) -> ffi::JSValue {
    if obj.is_null() {
        return ffi::qjs_null();
    }

    let class_name = get_runtime_class_name(env, obj).unwrap_or_else(|| {
        class_name_hint
            .map(jni_object_sig_to_class_name)
            .unwrap_or_else(|| "java.lang.Object".to_string())
    });

    // `$new` 强制返回 wrapper：跳过 String/Boxed-primitive/容器的自动转换，
    // 让 `Java.use("...").$new(...)` 一定返回可链式调用的 Java 对象代理。
    if RETURN_RAW_WRAPPER.get() {
        if release_local {
            return wrap_java_object_ref(ctx, env, obj, &class_name, globalize_wrappers);
        }
        return wrap_java_object_value(ctx, obj as u64, &class_name);
    }

    if class_name == "java.lang.String" {
        let get_str: GetStringUtfCharsFn = jni_fn!(env, GetStringUtfCharsFn, JNI_GET_STRING_UTF_CHARS);
        let rel_str: ReleaseStringUtfCharsFn =
            jni_fn!(env, ReleaseStringUtfCharsFn, JNI_RELEASE_STRING_UTF_CHARS);
        let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);

        let chars = get_str(env, obj, std::ptr::null_mut());
        if !chars.is_null() {
            let s = std::ffi::CStr::from_ptr(chars)
                .to_string_lossy()
                .to_string();
            rel_str(env, obj, chars);
            if release_local {
                delete_local_ref(env, obj);
            }
            return JSValue::string(ctx, &s).raw();
        }

        jni_check_exc(env);
    }

    // Java 数组 → JS Array。List 与装箱原始值保留为 Java wrapper，
    // 交给用户显式处理（可链式调 list.size()/list.get(i)、integer.intValue() 等）。
    if depth < MAX_JAVA_CONTAINER_DEPTH && class_name.starts_with('[') {
        if let Some(value) = convert_java_array_to_js(
            ctx,
            env,
            obj,
            &class_name,
            release_local,
            globalize_wrappers,
            depth + 1,
        ) {
            return value;
        }
    }

    if release_local {
        return wrap_java_object_ref(ctx, env, obj, &class_name, globalize_wrappers);
    }

    wrap_java_object_value(ctx, obj as u64, &class_name)
}

/// Java 数组 → JS Array。
///
/// 原始类型数组走 `Get<Type>ArrayRegion` 一次批量拷贝到 Rust 缓冲，无装箱、无
/// Release；对象数组用 `GetObjectArrayElement` 直接取引用，递归 marshal。
/// 绕开 `java.lang.reflect.Array` 反射路径。
unsafe fn convert_java_array_to_js(
    ctx: *mut ffi::JSContext,
    env: JniEnv,
    array_obj: *mut std::ffi::c_void,
    class_name: &str,
    release_local: bool,
    globalize_wrappers: bool,
    depth: usize,
) -> Option<ffi::JSValue> {
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
    let get_len: GetArrayLengthFn = jni_fn!(env, GetArrayLengthFn, JNI_GET_ARRAY_LENGTH);

    let len = get_len(env, array_obj);
    if jni_check_exc(env) || len < 0 {
        if release_local {
            delete_local_ref(env, array_obj);
        }
        return None;
    }

    let arr = ffi::JS_NewArray(ctx);
    let elem_type = class_name.as_bytes().get(1).copied().unwrap_or(b'L');
    let len_usize = len as usize;

    // 原始类型 region 读取：一次 JNI 调用把整段元素拷到 Rust vec
    macro_rules! read_region {
        ($elem:ty, $init:expr, $fn_ty:ident, $idx:ident) => {{
            let mut buf: Vec<$elem> = vec![$init; len_usize];
            let f: $fn_ty = jni_fn!(env, $fn_ty, $idx);
            f(env, array_obj, 0, len, buf.as_mut_ptr());
            if jni_check_exc(env) {
                if release_local {
                    delete_local_ref(env, array_obj);
                }
                return None;
            }
            buf
        }};
    }

    match elem_type {
        b'Z' => {
            let buf = read_region!(u8, 0, GetBooleanArrayRegionFn, JNI_GET_BOOLEAN_ARRAY_REGION);
            for i in 0..len_usize {
                let v = JSValue::bool(buf[i] != 0).raw();
                ffi::JS_SetPropertyUint32(ctx, arr, i as u32, v);
            }
        }
        b'B' => {
            let buf = read_region!(i8, 0, GetByteArrayRegionFn, JNI_GET_BYTE_ARRAY_REGION);
            for i in 0..len_usize {
                let v = JSValue::int(buf[i] as i32).raw();
                ffi::JS_SetPropertyUint32(ctx, arr, i as u32, v);
            }
        }
        b'C' => {
            let buf = read_region!(u16, 0, GetCharArrayRegionFn, JNI_GET_CHAR_ARRAY_REGION);
            for i in 0..len_usize {
                let c = std::char::from_u32(buf[i] as u32)
                    .unwrap_or('\0')
                    .to_string();
                let v = JSValue::string(ctx, &c).raw();
                ffi::JS_SetPropertyUint32(ctx, arr, i as u32, v);
            }
        }
        b'S' => {
            let buf = read_region!(i16, 0, GetShortArrayRegionFn, JNI_GET_SHORT_ARRAY_REGION);
            for i in 0..len_usize {
                let v = JSValue::int(buf[i] as i32).raw();
                ffi::JS_SetPropertyUint32(ctx, arr, i as u32, v);
            }
        }
        b'I' => {
            let buf = read_region!(i32, 0, GetIntArrayRegionFn, JNI_GET_INT_ARRAY_REGION);
            for i in 0..len_usize {
                let v = JSValue::int(buf[i]).raw();
                ffi::JS_SetPropertyUint32(ctx, arr, i as u32, v);
            }
        }
        b'J' => {
            let buf = read_region!(i64, 0, GetLongArrayRegionFn, JNI_GET_LONG_ARRAY_REGION);
            for i in 0..len_usize {
                let v = ffi::JS_NewBigInt64(ctx, buf[i]);
                ffi::JS_SetPropertyUint32(ctx, arr, i as u32, v);
            }
        }
        b'F' => {
            let buf = read_region!(f32, 0.0, GetFloatArrayRegionFn, JNI_GET_FLOAT_ARRAY_REGION);
            for i in 0..len_usize {
                let v = JSValue::float(buf[i] as f64).raw();
                ffi::JS_SetPropertyUint32(ctx, arr, i as u32, v);
            }
        }
        b'D' => {
            let buf = read_region!(f64, 0.0, GetDoubleArrayRegionFn, JNI_GET_DOUBLE_ARRAY_REGION);
            for i in 0..len_usize {
                let v = JSValue::float(buf[i]).raw();
                ffi::JS_SetPropertyUint32(ctx, arr, i as u32, v);
            }
        }
        b'L' | b'[' => {
            // 对象 / 嵌套数组：逐个取引用，递归 marshal
            let get_elem: GetObjectArrayElementFn =
                jni_fn!(env, GetObjectArrayElementFn, JNI_GET_OBJECT_ARRAY_ELEMENT);
            for i in 0..len {
                let elem = get_elem(env, array_obj, i);
                if jni_check_exc(env) {
                    if !elem.is_null() {
                        delete_local_ref(env, elem);
                    }
                    if release_local {
                        delete_local_ref(env, array_obj);
                    }
                    return None;
                }
                let value = marshal_java_object_to_js_inner(
                    ctx,
                    env,
                    elem,
                    None,
                    true,
                    globalize_wrappers,
                    depth,
                );
                ffi::JS_SetPropertyUint32(ctx, arr, i as u32, value);
            }
        }
        _ => {
            if release_local {
                delete_local_ref(env, array_obj);
            }
            return None;
        }
    }

    if release_local {
        delete_local_ref(env, array_obj);
    }

    Some(arr)
}

unsafe fn marshal_borrowed_java_object_to_js(
    ctx: *mut ffi::JSContext,
    env: JniEnv,
    obj: *mut std::ffi::c_void,
    class_name_hint: Option<&str>,
) -> ffi::JSValue {
    marshal_java_object_to_js_inner(ctx, env, obj, class_name_hint, false, false, 0)
}

pub(super) unsafe fn marshal_local_java_object_to_js(
    ctx: *mut ffi::JSContext,
    env: JniEnv,
    obj: *mut std::ffi::c_void,
    class_name_hint: Option<&str>,
) -> ffi::JSValue {
    marshal_java_object_to_js_inner(ctx, env, obj, class_name_hint, true, true, 0)
}

#[inline]
unsafe fn js_throw_type_error(ctx: *mut ffi::JSContext, msg: &[u8]) -> ffi::JSValue {
    throw_type_error(ctx, msg)
}

#[inline]
unsafe fn js_throw_internal_error(
    ctx: *mut ffi::JSContext,
    message: impl AsRef<str>,
) -> ffi::JSValue {
    throw_internal_error(ctx, message)
}

unsafe fn read_invoke_target_ptr(
    ctx: *mut ffi::JSContext,
    arg: JSValue,
) -> Result<u64, ffi::JSValue> {
    let obj_ptr = extract_pointer_address(ctx, arg, "Java._invokeMethod").map_err(|_| {
        ffi::JS_ThrowTypeError(
            ctx,
            b"Java._invokeMethod() first argument must be a pointer (BigUint64/Number/NativePointer)\0"
                .as_ptr() as *const _,
        )
    })?;

    if obj_ptr == 0 {
        return Err(ffi::JS_ThrowTypeError(
            ctx,
            b"Java._invokeMethod() objPtr is null\0".as_ptr() as *const _,
        ));
    }

    Ok(obj_ptr)
}

unsafe fn read_string_arg(
    ctx: *mut ffi::JSContext,
    arg: JSValue,
    error_msg: &[u8],
) -> Result<String, ffi::JSValue> {
    extract_string_arg(ctx, arg, error_msg)
}

unsafe fn cleanup_local_refs(
    env: JniEnv,
    local_obj: *mut std::ffi::c_void,
    cls: *mut std::ffi::c_void,
) {
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);

    if !local_obj.is_null() {
        delete_local_ref(env, local_obj);
    }
    if !cls.is_null() {
        delete_local_ref(env, cls);
    }
}

unsafe fn cleanup_and_throw_internal(
    ctx: *mut ffi::JSContext,
    env: JniEnv,
    local_obj: *mut std::ffi::c_void,
    cls: *mut std::ffi::c_void,
    message: impl AsRef<str>,
) -> ffi::JSValue {
    cleanup_local_refs(env, local_obj, cls);
    throw_internal_error(ctx, message)
}

unsafe fn cleanup_and_throw_type(
    ctx: *mut ffi::JSContext,
    env: JniEnv,
    local_obj: *mut std::ffi::c_void,
    cls: *mut std::ffi::c_void,
    msg: &[u8],
) -> ffi::JSValue {
    cleanup_local_refs(env, local_obj, cls);
    ffi::JS_ThrowTypeError(ctx, msg.as_ptr() as *const _)
}

unsafe fn build_invoke_jargs(
    ctx: *mut ffi::JSContext,
    env: JniEnv,
    argv: *mut ffi::JSValue,
    param_types: &[String],
) -> Vec<u64> {
    build_jargs_from_argv(ctx, env, argv, 4, param_types)
}

unsafe fn build_jargs_from_argv(
    ctx: *mut ffi::JSContext,
    env: JniEnv,
    argv: *mut ffi::JSValue,
    start_index: usize,
    param_types: &[String],
) -> Vec<u64> {
    let mut jargs = Vec::with_capacity(param_types.len());
    for (i, type_sig) in param_types.iter().enumerate() {
        let js_arg = JSValue(*argv.add(start_index + i));
        jargs.push(marshal_js_to_jvalue(
            ctx,
            env,
            js_arg,
            Some(type_sig.as_str()),
        ));
    }
    jargs
}

unsafe fn wrap_invoke_return_object(
    ctx: *mut ffi::JSContext,
    env: JniEnv,
    obj: *mut std::ffi::c_void,
    return_type_sig: &str,
) -> Result<ffi::JSValue, String> {
    if obj.is_null() {
        return Ok(ffi::qjs_null());
    }
    let value = marshal_local_java_object_to_js(ctx, env, obj, Some(return_type_sig));
    if JSValue(value).is_null() && !jni_check_exc(env) {
        return Err("Java._invokeMethod: failed to marshal return object".to_string());
    }
    Ok(value)
}
