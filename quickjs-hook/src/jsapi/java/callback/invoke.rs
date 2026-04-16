// ============================================================================
// Java._invokeMethod(objPtr, className, methodName, methodSig, ...args)
// ============================================================================
//
// Instance method invocation helper used by Java Proxy wrappers.
// - objPtr:    BigUint64 / Number / NativePointer (jobject mirror pointer)
// - className: "java.lang.Foo" / "java/lang/Foo"
// - methodName: Java method name (e.g. "bar")
// - methodSig: JNI signature string, e.g. "(Ljava/lang/String;I)V"
// - args...:   JS arguments, converted to jvalue[] according to methodSig
//
// Return value:
// - primitives → JS number / boolean / BigInt (for long)
// - String     → JS string
// - boxed primitives (Integer/Long/...) → JS primitive (unboxed)
// - 数组 / List → JS Array（元素递归转换：基础类型 unbox，复杂对象保留 wrapper）
// - 其他 Object → {__jptr, __jclass} wrapper (Proxy-wrapped on JS side)
pub(super) unsafe extern "C" fn js_java_invoke_method(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 4 {
        return js_throw_type_error(
            ctx,
            b"Java._invokeMethod() requires at least 4 arguments: objPtr, className, methodName, methodSig\0",
        );
    }

    let obj_arg = JSValue(*argv);
    let class_arg = JSValue(*argv.add(1));
    let method_arg = JSValue(*argv.add(2));
    let sig_arg = JSValue(*argv.add(3));

    let obj_ptr = match read_invoke_target_ptr(ctx, obj_arg) {
        Ok(ptr) => ptr,
        Err(err) => return err,
    };
    let class_name = match read_string_arg(
        ctx,
        class_arg,
        b"Java._invokeMethod() className must be a string\0",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let method_name = match read_string_arg(
        ctx,
        method_arg,
        b"Java._invokeMethod() methodName must be a string\0",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let method_sig = match read_string_arg(
        ctx,
        sig_arg,
        b"Java._invokeMethod() methodSig must be a JNI signature string\0",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };

    // Parse parameter + return types from JNI signature
    let param_types = parse_jni_param_types(&method_sig);
    let param_count = param_types.len();
    if (argc - 4) < param_count as i32 {
        return js_throw_type_error(
            ctx,
            b"Java._invokeMethod() not enough JS arguments for method signature\0",
        );
    }

    let return_type = get_return_type_from_sig(&method_sig);
    let return_type_sig = get_return_type_sig(&method_sig);

    // Get JNIEnv* for current thread
    let env = match get_thread_env() {
        Ok(e) => e,
        Err(msg) => return js_throw_internal_error(ctx, msg),
    };

    // Resolve declaring class
    let cls = find_class_safe(env, &class_name);
    if cls.is_null() || jni_check_exc(env) {
        return js_throw_internal_error(
            ctx,
            format!("Java._invokeMethod: FindClass('{}') failed", class_name),
        );
    }

    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
    let new_local_ref: NewLocalRefFn = jni_fn!(env, NewLocalRefFn, JNI_NEW_LOCAL_REF);

    // Wrap raw mirror pointer as a proper local ref
    let local_obj = new_local_ref(env, obj_ptr as *mut std::ffi::c_void);
    if local_obj.is_null() || jni_check_exc(env) {
        delete_local_ref(env, cls);
        return js_throw_internal_error(ctx, "Java._invokeMethod: NewLocalRef failed for objPtr");
    }

    // Resolve method ID
    let get_mid: GetMethodIdFn = jni_fn!(env, GetMethodIdFn, JNI_GET_METHOD_ID);
    let c_name = match CString::new(method_name.as_str()) {
        Ok(c) => c,
        Err(_) => {
            return cleanup_and_throw_type(
                ctx,
                env,
                local_obj,
                cls,
                b"Java._invokeMethod() invalid methodName\0",
            );
        }
    };
    let c_sig = match CString::new(method_sig.as_str()) {
        Ok(c) => c,
        Err(_) => {
            return cleanup_and_throw_type(
                ctx,
                env,
                local_obj,
                cls,
                b"Java._invokeMethod() invalid methodSig\0",
            );
        }
    };

    let mid = get_mid(env, cls, c_name.as_ptr(), c_sig.as_ptr());
    if mid.is_null() || jni_check_exc(env) {
        return cleanup_and_throw_internal(
            ctx,
            env,
            local_obj,
            cls,
            format!(
                "Java._invokeMethod: GetMethodID failed: {}.{}{}",
                class_name, method_name, method_sig
            ),
        );
    }

    // Build jvalue args from JS values
    let jargs = build_invoke_jargs(ctx, env, argv, &param_types);
    let jargs_ptr = if param_count > 0 {
        jargs.as_ptr() as *const std::ffi::c_void
    } else {
        std::ptr::null()
    };
    let invoke_exception = || {
        format!(
            "Java._invokeMethod: exception in {}.{}{}",
            class_name, method_name, method_sig
        )
    };

    // Dispatch based on return type using CallNonvirtual*MethodA (avoids needing all Call*MethodA indices)
    let result = match return_type {
        b'V' => {
            type F = unsafe extern "C" fn(
                JniEnv,
                *mut std::ffi::c_void,
                *mut std::ffi::c_void,
                *mut std::ffi::c_void,
                *const std::ffi::c_void,
            );
            let f: F = jni_fn!(env, F, JNI_CALL_NONVIRTUAL_VOID_METHOD_A);
            f(env, local_obj, cls, mid, jargs_ptr);
            if let Some(exc_msg) = jni_take_exception(env) {
                return cleanup_and_throw_internal(
                    ctx,
                    env,
                    local_obj,
                    cls,
                    format!("{}\n  Java: {}", invoke_exception(), exc_msg),
                );
            }
            ffi::qjs_undefined()
        }
        b'Z' => {
            type F = unsafe extern "C" fn(
                JniEnv,
                *mut std::ffi::c_void,
                *mut std::ffi::c_void,
                *mut std::ffi::c_void,
                *const std::ffi::c_void,
            ) -> u8;
            let f: F = jni_fn!(env, F, JNI_CALL_NONVIRTUAL_BOOLEAN_METHOD_A);
            let ret = f(env, local_obj, cls, mid, jargs_ptr);
            if let Some(exc_msg) = jni_take_exception(env) {
                return cleanup_and_throw_internal(
                    ctx,
                    env,
                    local_obj,
                    cls,
                    format!("{}\n  Java: {}", invoke_exception(), exc_msg),
                );
            }
            JSValue::bool(ret != 0).raw()
        }
        b'I' | b'B' | b'C' | b'S' => {
            type F = unsafe extern "C" fn(
                JniEnv,
                *mut std::ffi::c_void,
                *mut std::ffi::c_void,
                *mut std::ffi::c_void,
                *const std::ffi::c_void,
            ) -> i32;
            let f: F = jni_fn!(env, F, JNI_CALL_NONVIRTUAL_INT_METHOD_A);
            let ret = f(env, local_obj, cls, mid, jargs_ptr);
            if let Some(exc_msg) = jni_take_exception(env) {
                return cleanup_and_throw_internal(
                    ctx,
                    env,
                    local_obj,
                    cls,
                    format!("{}\n  Java: {}", invoke_exception(), exc_msg),
                );
            }
            match return_type {
                b'I' => JSValue::int(ret).raw(),
                b'B' => JSValue::int(ret as i8 as i32).raw(),
                b'C' => {
                    let ch = std::char::from_u32(ret as u32).unwrap_or('\0');
                    JSValue::string(ctx, &ch.to_string()).raw()
                }
                b'S' => JSValue::int(ret as i16 as i32).raw(),
                _ => ffi::qjs_undefined(),
            }
        }
        b'J' => {
            type F = unsafe extern "C" fn(
                JniEnv,
                *mut std::ffi::c_void,
                *mut std::ffi::c_void,
                *mut std::ffi::c_void,
                *const std::ffi::c_void,
            ) -> i64;
            let f: F = jni_fn!(env, F, JNI_CALL_NONVIRTUAL_LONG_METHOD_A);
            let ret = f(env, local_obj, cls, mid, jargs_ptr);
            if let Some(exc_msg) = jni_take_exception(env) {
                return cleanup_and_throw_internal(
                    ctx,
                    env,
                    local_obj,
                    cls,
                    format!("{}\n  Java: {}", invoke_exception(), exc_msg),
                );
            }
            ffi::JS_NewBigUint64(ctx, ret as u64)
        }
        b'F' => {
            type F = unsafe extern "C" fn(
                JniEnv,
                *mut std::ffi::c_void,
                *mut std::ffi::c_void,
                *mut std::ffi::c_void,
                *const std::ffi::c_void,
            ) -> f32;
            let f: F = jni_fn!(env, F, JNI_CALL_NONVIRTUAL_FLOAT_METHOD_A);
            let ret = f(env, local_obj, cls, mid, jargs_ptr);
            if let Some(exc_msg) = jni_take_exception(env) {
                return cleanup_and_throw_internal(
                    ctx,
                    env,
                    local_obj,
                    cls,
                    format!("{}\n  Java: {}", invoke_exception(), exc_msg),
                );
            }
            JSValue::float(ret as f64).raw()
        }
        b'D' => {
            type F = unsafe extern "C" fn(
                JniEnv,
                *mut std::ffi::c_void,
                *mut std::ffi::c_void,
                *mut std::ffi::c_void,
                *const std::ffi::c_void,
            ) -> f64;
            let f: F = jni_fn!(env, F, JNI_CALL_NONVIRTUAL_DOUBLE_METHOD_A);
            let ret = f(env, local_obj, cls, mid, jargs_ptr);
            if let Some(exc_msg) = jni_take_exception(env) {
                return cleanup_and_throw_internal(
                    ctx,
                    env,
                    local_obj,
                    cls,
                    format!("{}\n  Java: {}", invoke_exception(), exc_msg),
                );
            }
            JSValue::float(ret).raw()
        }
        b'L' | b'[' => {
            // Object/array return — use CallNonvirtualObjectMethodA, then wrap result.
            type F = unsafe extern "C" fn(
                JniEnv,
                *mut std::ffi::c_void,
                *mut std::ffi::c_void,
                *mut std::ffi::c_void,
                *const std::ffi::c_void,
            ) -> *mut std::ffi::c_void;
            let f: F = jni_fn!(env, F, JNI_CALL_NONVIRTUAL_OBJECT_METHOD_A);
            let obj = f(env, local_obj, cls, mid, jargs_ptr);
            if let Some(exc_msg) = jni_take_exception(env) {
                if !obj.is_null() {
                    delete_local_ref(env, obj);
                }
                return cleanup_and_throw_internal(
                    ctx,
                    env,
                    local_obj,
                    cls,
                    format!("{}\n  Java: {}", invoke_exception(), exc_msg),
                );
            }
            match wrap_invoke_return_object(ctx, env, obj, &return_type_sig) {
                Ok(value) => value,
                Err(message) => {
                    return cleanup_and_throw_internal(ctx, env, local_obj, cls, message);
                }
            }
        }
        _ => ffi::qjs_undefined(),
    };

    cleanup_local_refs(env, local_obj, cls);
    result
}


// ============================================================================
// Java._invokeStaticMethod(className, methodName, methodSig, ...args)
// ============================================================================
//
// Static method invocation helper used by Java.use(...).method(...).
// - className:  "java.lang.Foo" / "java/lang/Foo"
// - methodName: Java static method name (e.g. "bar")
// - methodSig:  JNI signature string, e.g. "(Ljava/lang/String;I)V"
// - args...:    JS arguments, converted to jvalue[] according to methodSig
pub(super) unsafe extern "C" fn js_java_invoke_static_method(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 3 {
        return js_throw_type_error(
            ctx,
            b"Java._invokeStaticMethod() requires at least 3 arguments: className, methodName, methodSig\0",
        );
    }

    let class_arg = JSValue(*argv);
    let method_arg = JSValue(*argv.add(1));
    let sig_arg = JSValue(*argv.add(2));

    let class_name = match read_string_arg(
        ctx,
        class_arg,
        b"Java._invokeStaticMethod() className must be a string\0",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let method_name = match read_string_arg(
        ctx,
        method_arg,
        b"Java._invokeStaticMethod() methodName must be a string\0",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let method_sig = match read_string_arg(
        ctx,
        sig_arg,
        b"Java._invokeStaticMethod() methodSig must be a JNI signature string\0",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };

    let param_types = parse_jni_param_types(&method_sig);
    let param_count = param_types.len();
    if (argc - 3) < param_count as i32 {
        return js_throw_type_error(
            ctx,
            b"Java._invokeStaticMethod() not enough JS arguments for method signature\0",
        );
    }

    let return_type = get_return_type_from_sig(&method_sig);
    let return_type_sig = get_return_type_sig(&method_sig);

    let env = match get_thread_env() {
        Ok(e) => e,
        Err(msg) => return js_throw_internal_error(ctx, msg),
    };

    let cls = find_class_safe(env, &class_name);
    if cls.is_null() || jni_check_exc(env) {
        return js_throw_internal_error(
            ctx,
            format!("Java._invokeStaticMethod: FindClass('{}') failed", class_name),
        );
    }

    let get_mid: GetStaticMethodIdFn = jni_fn!(env, GetStaticMethodIdFn, JNI_GET_STATIC_METHOD_ID);
    let c_name = match CString::new(method_name.as_str()) {
        Ok(c) => c,
        Err(_) => {
            return cleanup_and_throw_type(
                ctx,
                env,
                std::ptr::null_mut(),
                cls,
                b"Java._invokeStaticMethod() invalid methodName\0",
            );
        }
    };
    let c_sig = match CString::new(method_sig.as_str()) {
        Ok(c) => c,
        Err(_) => {
            return cleanup_and_throw_type(
                ctx,
                env,
                std::ptr::null_mut(),
                cls,
                b"Java._invokeStaticMethod() invalid methodSig\0",
            );
        }
    };

    let mid = get_mid(env, cls, c_name.as_ptr(), c_sig.as_ptr());
    if mid.is_null() || jni_check_exc(env) {
        return cleanup_and_throw_internal(
            ctx,
            env,
            std::ptr::null_mut(),
            cls,
            format!(
                "Java._invokeStaticMethod: GetStaticMethodID failed: {}.{}{}",
                class_name, method_name, method_sig
            ),
        );
    }

    let jargs = build_jargs_from_argv(ctx, env, argv, 3, &param_types);
    let jargs_ptr = if param_count > 0 {
        jargs.as_ptr() as *const std::ffi::c_void
    } else {
        std::ptr::null()
    };
    let invoke_exception = || {
        format!(
            "Java._invokeStaticMethod: exception in {}.{}{}",
            class_name, method_name, method_sig
        )
    };

    let result = match return_type {
        b'V' => {
            type F = unsafe extern "C" fn(
                JniEnv,
                *mut std::ffi::c_void,
                *mut std::ffi::c_void,
                *const std::ffi::c_void,
            );
            let f: F = jni_fn!(env, F, JNI_CALL_STATIC_VOID_METHOD_A);
            f(env, cls, mid, jargs_ptr);
            if let Some(exc_msg) = jni_take_exception(env) {
                return cleanup_and_throw_internal(
                    ctx,
                    env,
                    std::ptr::null_mut(),
                    cls,
                    format!("{}\n  Java: {}", invoke_exception(), exc_msg),
                );
            }
            ffi::qjs_undefined()
        }
        b'Z' => {
            type F = unsafe extern "C" fn(
                JniEnv,
                *mut std::ffi::c_void,
                *mut std::ffi::c_void,
                *const std::ffi::c_void,
            ) -> u8;
            let f: F = jni_fn!(env, F, JNI_CALL_STATIC_BOOLEAN_METHOD_A);
            JSValue::bool(f(env, cls, mid, jargs_ptr) != 0).raw()
        }
        b'B' => {
            type F = unsafe extern "C" fn(
                JniEnv,
                *mut std::ffi::c_void,
                *mut std::ffi::c_void,
                *const std::ffi::c_void,
            ) -> i8;
            let f: F = jni_fn!(env, F, JNI_CALL_STATIC_BYTE_METHOD_A);
            let ret = f(env, cls, mid, jargs_ptr);
            if let Some(exc_msg) = jni_take_exception(env) {
                return cleanup_and_throw_internal(
                    ctx,
                    env,
                    std::ptr::null_mut(),
                    cls,
                    format!("{}\n  Java: {}", invoke_exception(), exc_msg),
                );
            }
            JSValue::int(ret as i32).raw()
        }
        b'C' => {
            type F = unsafe extern "C" fn(
                JniEnv,
                *mut std::ffi::c_void,
                *mut std::ffi::c_void,
                *const std::ffi::c_void,
            ) -> u16;
            let f: F = jni_fn!(env, F, JNI_CALL_STATIC_CHAR_METHOD_A);
            let ret = f(env, cls, mid, jargs_ptr);
            if let Some(exc_msg) = jni_take_exception(env) {
                return cleanup_and_throw_internal(
                    ctx,
                    env,
                    std::ptr::null_mut(),
                    cls,
                    format!("{}\n  Java: {}", invoke_exception(), exc_msg),
                );
            }
            let ch = std::char::from_u32(ret as u32).unwrap_or('\0');
            JSValue::string(ctx, &ch.to_string()).raw()
        }
        b'S' => {
            type F = unsafe extern "C" fn(
                JniEnv,
                *mut std::ffi::c_void,
                *mut std::ffi::c_void,
                *const std::ffi::c_void,
            ) -> i16;
            let f: F = jni_fn!(env, F, JNI_CALL_STATIC_SHORT_METHOD_A);
            let ret = f(env, cls, mid, jargs_ptr);
            if let Some(exc_msg) = jni_take_exception(env) {
                return cleanup_and_throw_internal(
                    ctx,
                    env,
                    std::ptr::null_mut(),
                    cls,
                    format!("{}\n  Java: {}", invoke_exception(), exc_msg),
                );
            }
            JSValue::int(ret as i32).raw()
        }
        b'I' => {
            type F = unsafe extern "C" fn(
                JniEnv,
                *mut std::ffi::c_void,
                *mut std::ffi::c_void,
                *const std::ffi::c_void,
            ) -> i32;
            let f: F = jni_fn!(env, F, JNI_CALL_STATIC_INT_METHOD_A);
            let ret = f(env, cls, mid, jargs_ptr);
            if let Some(exc_msg) = jni_take_exception(env) {
                return cleanup_and_throw_internal(
                    ctx,
                    env,
                    std::ptr::null_mut(),
                    cls,
                    format!("{}\n  Java: {}", invoke_exception(), exc_msg),
                );
            }
            JSValue::int(ret).raw()
        }
        b'J' => {
            type F = unsafe extern "C" fn(
                JniEnv,
                *mut std::ffi::c_void,
                *mut std::ffi::c_void,
                *const std::ffi::c_void,
            ) -> i64;
            let f: F = jni_fn!(env, F, JNI_CALL_STATIC_LONG_METHOD_A);
            let ret = f(env, cls, mid, jargs_ptr);
            if let Some(exc_msg) = jni_take_exception(env) {
                return cleanup_and_throw_internal(
                    ctx,
                    env,
                    std::ptr::null_mut(),
                    cls,
                    format!("{}\n  Java: {}", invoke_exception(), exc_msg),
                );
            }
            ffi::JS_NewBigUint64(ctx, ret as u64)
        }
        b'F' => {
            type F = unsafe extern "C" fn(
                JniEnv,
                *mut std::ffi::c_void,
                *mut std::ffi::c_void,
                *const std::ffi::c_void,
            ) -> f32;
            let f: F = jni_fn!(env, F, JNI_CALL_STATIC_FLOAT_METHOD_A);
            let ret = f(env, cls, mid, jargs_ptr);
            if let Some(exc_msg) = jni_take_exception(env) {
                return cleanup_and_throw_internal(
                    ctx,
                    env,
                    std::ptr::null_mut(),
                    cls,
                    format!("{}\n  Java: {}", invoke_exception(), exc_msg),
                );
            }
            JSValue::float(ret as f64).raw()
        }
        b'D' => {
            type F = unsafe extern "C" fn(
                JniEnv,
                *mut std::ffi::c_void,
                *mut std::ffi::c_void,
                *const std::ffi::c_void,
            ) -> f64;
            let f: F = jni_fn!(env, F, JNI_CALL_STATIC_DOUBLE_METHOD_A);
            let ret = f(env, cls, mid, jargs_ptr);
            if let Some(exc_msg) = jni_take_exception(env) {
                return cleanup_and_throw_internal(
                    ctx,
                    env,
                    std::ptr::null_mut(),
                    cls,
                    format!("{}\n  Java: {}", invoke_exception(), exc_msg),
                );
            }
            JSValue::float(ret).raw()
        }
        b'L' | b'[' => {
            type F = unsafe extern "C" fn(
                JniEnv,
                *mut std::ffi::c_void,
                *mut std::ffi::c_void,
                *const std::ffi::c_void,
            ) -> *mut std::ffi::c_void;
            let f: F = jni_fn!(env, F, JNI_CALL_STATIC_OBJECT_METHOD_A);
            let obj = f(env, cls, mid, jargs_ptr);
            if let Some(exc_msg) = jni_take_exception(env) {
                if !obj.is_null() {
                    let delete_local_ref: DeleteLocalRefFn =
                        jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
                    delete_local_ref(env, obj);
                }
                return cleanup_and_throw_internal(
                    ctx,
                    env,
                    std::ptr::null_mut(),
                    cls,
                    format!("{}\n  Java: {}", invoke_exception(), exc_msg),
                );
            }
            match wrap_invoke_return_object(ctx, env, obj, &return_type_sig) {
                Ok(value) => value,
                Err(message) => {
                    return cleanup_and_throw_internal(
                        ctx,
                        env,
                        std::ptr::null_mut(),
                        cls,
                        message,
                    );
                }
            }
        }
        _ => ffi::qjs_undefined(),
    };

    if matches!(return_type, b'Z' | b'B' | b'C' | b'S' | b'I' | b'J' | b'F' | b'D')
        && jni_check_exc(env)
    {
        return cleanup_and_throw_internal(ctx, env, std::ptr::null_mut(), cls, invoke_exception());
    }

    cleanup_local_refs(env, std::ptr::null_mut(), cls);
    result
}

// ============================================================================
// Java._newObject(className, ctorSig, ...args)
// ============================================================================
//
// Constructor invocation helper used by Java.use(...).$new(...).
// - className: "java.lang.Foo" / "java/lang/Foo"
// - ctorSig:   JNI signature string for <init>, e.g. "(Ljava/lang/String;I)V"
// - args...:   JS arguments, converted to jvalue[] according to ctorSig
//
// Return value:
// - object     → {__jptr, __jclass} wrapper (Proxy-wrapped on JS side)
pub(super) unsafe extern "C" fn js_java_new_object(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return js_throw_type_error(
            ctx,
            b"Java._newObject() requires at least 2 arguments: className, ctorSig\0",
        );
    }

    let class_arg = JSValue(*argv);
    let sig_arg = JSValue(*argv.add(1));

    let class_name = match read_string_arg(
        ctx,
        class_arg,
        b"Java._newObject() className must be a string\0",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let ctor_sig = match read_string_arg(
        ctx,
        sig_arg,
        b"Java._newObject() ctorSig must be a JNI signature string\0",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };

    if get_return_type_from_sig(&ctor_sig) != b'V' {
        return js_throw_type_error(
            ctx,
            b"Java._newObject() ctorSig must be a constructor signature ending in V\0",
        );
    }

    let param_types = parse_jni_param_types(&ctor_sig);
    let param_count = param_types.len();
    if (argc - 2) < param_count as i32 {
        return js_throw_type_error(
            ctx,
            b"Java._newObject() not enough JS arguments for constructor signature\0",
        );
    }

    let env = match get_thread_env() {
        Ok(e) => e,
        Err(msg) => return js_throw_internal_error(ctx, msg),
    };

    let cls = find_class_safe(env, &class_name);
    if cls.is_null() || jni_check_exc(env) {
        return js_throw_internal_error(
            ctx,
            format!("Java._newObject: FindClass('{}') failed", class_name),
        );
    }

    let get_mid: GetMethodIdFn = jni_fn!(env, GetMethodIdFn, JNI_GET_METHOD_ID);
    let new_object_a: NewObjectAFn = jni_fn!(env, NewObjectAFn, JNI_NEW_OBJECT_A);

    let c_ctor_name = CString::new("<init>").unwrap();
    let c_sig = match CString::new(ctor_sig.as_str()) {
        Ok(c) => c,
        Err(_) => {
            return cleanup_and_throw_type(
                ctx,
                env,
                std::ptr::null_mut(),
                cls,
                b"Java._newObject() invalid ctorSig\0",
            );
        }
    };

    let mid = get_mid(env, cls, c_ctor_name.as_ptr(), c_sig.as_ptr());
    if mid.is_null() || jni_check_exc(env) {
        return cleanup_and_throw_internal(
            ctx,
            env,
            std::ptr::null_mut(),
            cls,
            format!("Java._newObject: GetMethodID failed: {}.<init>{}", class_name, ctor_sig),
        );
    }

    let jargs = build_jargs_from_argv(ctx, env, argv, 2, &param_types);
    let jargs_ptr = if param_count > 0 {
        jargs.as_ptr() as *const std::ffi::c_void
    } else {
        std::ptr::null()
    };

    let obj = new_object_a(env, cls, mid, jargs_ptr);
    if obj.is_null() || jni_check_exc(env) {
        return cleanup_and_throw_internal(
            ctx,
            env,
            std::ptr::null_mut(),
            cls,
            format!(
                "Java._newObject: exception in {}.<init>{}",
                class_name, ctor_sig
            ),
        );
    }

    // $new 语义：**总是**返回 Java wrapper，不做 String/boxed primitive/容器
    // 的自动 JS 类型转换。例如 `Java.use("java.lang.String").$new("hi")` 返回
    // 可继续调用 `.length()` 的 wrapper，而不是 JS string "hi"；
    // `Java.use("java.lang.Integer").$new(42)` 返回 Integer wrapper 而不是 42。
    set_return_raw_wrapper(true);
    let class_sig = format!("L{};", class_name.replace('.', "/"));
    let result = match wrap_invoke_return_object(ctx, env, obj, &class_sig) {
        Ok(value) => value,
        Err(_) => ffi::qjs_null(),
    };
    set_return_raw_wrapper(false);

    cleanup_local_refs(env, std::ptr::null_mut(), cls);
    result
}
