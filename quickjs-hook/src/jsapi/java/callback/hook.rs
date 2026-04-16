// ============================================================================
// Argument marshalling — convert raw JNI register values to JS values
// ============================================================================

/// Convert a raw JNI argument (from register) to a JS value based on its JNI type descriptor.
///
/// Primitive types become JS numbers/booleans/bigints.
/// String objects become JS strings (read via GetStringUTFChars).
/// Other objects become wrapped `{__jptr, __jclass}` for Proxy-based field access.
/// Falls back to BigUint64 if type info is unavailable.
///
/// `fp_raw`: value from the corresponding d-register (for float/double args).
unsafe fn marshal_jni_arg_to_js(
    ctx: *mut ffi::JSContext,
    env: JniEnv,
    raw: u64,
    fp_raw: u64,
    type_sig: Option<&str>,
) -> ffi::JSValue {
    let sig = match type_sig {
        Some(s) if !s.is_empty() => s,
        _ => return ffi::JS_NewBigUint64(ctx, raw),
    };

    match sig.as_bytes()[0] {
        b'Z' => JSValue::bool(raw != 0).raw(),
        b'B' => JSValue::int(raw as i8 as i32).raw(),
        b'C' => {
            // char → JS string (single UTF-16 character)
            let ch = std::char::from_u32(raw as u32).unwrap_or('\0');
            let s = ch.to_string();
            JSValue::string(ctx, &s).raw()
        }
        b'S' => JSValue::int(raw as i16 as i32).raw(),
        b'I' => JSValue::int(raw as i32).raw(),
        b'J' => ffi::JS_NewBigUint64(ctx, raw),
        b'F' => {
            // ARM64 ABI: floats are passed in d0-d7 (FP registers).
            // fp_raw comes from HookContext.d[fp_index].
            let f = f32::from_bits(fp_raw as u32);
            JSValue::float(f as f64).raw()
        }
        b'D' => {
            // ARM64 ABI: doubles are passed in d0-d7 (FP registers).
            // fp_raw comes from HookContext.d[fp_index].
            let d = f64::from_bits(fp_raw);
            JSValue::float(d).raw()
        }
        b'L' | b'[' => {
            // Object or array — raw is a jobject local ref
            let obj = raw as *mut std::ffi::c_void;
            if obj.is_null() {
                return ffi::qjs_null();
            }
            // 快速路径: 签名是 String 时直接读 UTF，避免 get_runtime_class_name
            if sig == "Ljava/lang/String;" {
                let get_str: GetStringUtfCharsFn = jni_fn!(env, GetStringUtfCharsFn, JNI_GET_STRING_UTF_CHARS);
                let rel_str: ReleaseStringUtfCharsFn = jni_fn!(env, ReleaseStringUtfCharsFn, JNI_RELEASE_STRING_UTF_CHARS);
                let chars = get_str(env, obj, std::ptr::null_mut());
                if !chars.is_null() {
                    let s = std::ffi::CStr::from_ptr(chars).to_string_lossy().to_string();
                    rel_str(env, obj, chars);
                    return JSValue::string(ctx, &s).raw();
                }
                jni_check_exc(env);
                return ffi::qjs_null();
            }
            // 轻量路径: 用签名类名直接构造 {__jptr, __jclass} wrapper
            // 跳过 get_runtime_class_name (省 2-3 次 JNI/参数)
            let class_name = jni_object_sig_to_class_name(sig);
            wrap_java_object_value(ctx, raw, &class_name)
        }
        _ => ffi::JS_NewBigUint64(ctx, raw),
    }
}

// ============================================================================
// Hook callback (runs in hooked thread, called by ART JNI trampoline)
// ============================================================================

/// Callback invoked by the native hook trampoline when a hooked Java method is called.
/// After "replace with native", ART's JNI trampoline calls our thunk which calls this.
///
/// HookContext contains JNI calling convention registers:
///   x0 = JNIEnv*, x1 = jobject this (instance) or jclass (static), x2-x7 = Java args
///
/// user_data = ArtMethod* address (used for registry lookup).
pub(super) unsafe extern "C" fn java_hook_callback(
    ctx_ptr: *mut hook_ffi::HookContext,
    user_data: *mut std::ffi::c_void,
) {
    if ctx_ptr.is_null() || user_data.is_null() {
        return;
    }
    let _in_flight_guard = InFlightJavaHookGuard::enter();
    let _callback_scope = JavaHookCallbackScope::enter();

    // user_data is ArtMethod* address (used as registry key)
    let art_method_addr = user_data as u64;

    // Copy callback data then release lock before QuickJS operations.
    let (
        ctx_usize,
        callback_bytes,
        is_static,
        param_count,
        return_type,
        return_type_sig,
        param_types,
        class_global_ref,
    ) = {
        let guard = match JAVA_HOOK_REGISTRY.lock() {
            Ok(g) => g,
            Err(_) => {
                // Lock poisoned during cleanup — zero x0 to prevent returning garbage
                (*ctx_ptr).x[0] = 0;
                return;
            }
        };
        let registry = match guard.as_ref() {
            Some(r) => r,
            None => {
                // Registry taken during cleanup — zero x0 to prevent returning JNIEnv* as object
                (*ctx_ptr).x[0] = 0;
                return;
            }
        };
        let hook_data = match registry.get(&art_method_addr) {
            Some(d) => d,
            None => {
                // Hook data removed during cleanup — zero x0
                (*ctx_ptr).x[0] = 0;
                return;
            }
        };
        (
            hook_data.ctx,
            hook_data.callback_bytes,
            hook_data.is_static,
            hook_data.param_count,
            hook_data.return_type,
            hook_data.return_type_sig.clone(),
            hook_data.param_types.clone(),
            hook_data.class_global_ref,
        )
    }; // lock released

    let hook_ctx_env: JniEnv = (*ctx_ptr).x[0] as JniEnv;

    // Track whether handle_result was called (false if JS exception occurred)
    let mut result_was_set = false;

    invoke_hook_callback_common(
        ctx_usize,
        &callback_bytes,
        "java hook",
        art_method_addr,
        // 构建 JS 上下文对象：thisObj, args[], env, orig()
        |ctx| {
            let js_ctx = ffi::JS_NewObject(ctx);
            let hook_ctx = &*ctx_ptr;
            let env: JniEnv = hook_ctx.x[0] as JniEnv;

            // thisObj for instance methods (x1 = jobject this)
            if !is_static {
                set_js_u64_property(ctx, js_ctx, "thisObj", hook_ctx.x[1]);
            }

            // args[] — ARM64 JNI calling convention (GP x2-x7, FP d0-d7 independent)
            {
                let arr = ffi::JS_NewArray(ctx);
                let mut gp_index: usize = 0;
                let mut fp_index: usize = 0;
                for i in 0..param_count {
                    let type_sig = param_types.get(i).map(|s| s.as_str());
                    let (raw, fp_raw) = extract_jni_arg(
                        hook_ctx,
                        is_floating_point_type(type_sig),
                        &mut gp_index,
                        &mut fp_index,
                    );
                    let val = marshal_jni_arg_to_js(ctx, env, raw, fp_raw, type_sig);
                    ffi::JS_SetPropertyUint32(ctx, arr, i as u32, val);
                }
                JSValue(js_ctx).set_property(ctx, "args", JSValue(arr));
            }

            // env (JNIEnv* — from x0)
            set_js_u64_property(ctx, js_ctx, "env", hook_ctx.x[0]);

            // Bind per-callback state to the JS context object so orig()
            // remains valid across nested hook callbacks and JS-side wrappers.
            set_js_u64_property(ctx, js_ctx, "__hookCtxPtr", ctx_ptr as usize as u64);
            set_js_u64_property(ctx, js_ctx, "__hookArtMethod", art_method_addr);

            // orig()
            set_js_cfunction_property(ctx, js_ctx, "orig", js_call_original, 0);

            js_ctx
        },
        // 处理返回值：根据 return_type 将 JS 返回值写入 HookContext.x[0]
        |ctx, _js_ctx, result| {
            result_was_set = true;
            if return_type != b'V' {
                let result_val = JSValue(result);
                let ret_u64 = match return_type {
                    b'F' => {
                        if let Some(f) = result_val.to_float() {
                            (f as f32).to_bits() as u64
                        } else {
                            0u64
                        }
                    }
                    b'D' => {
                        if let Some(f) = result_val.to_float() {
                            f.to_bits()
                        } else {
                            0u64
                        }
                    }
                    b'L' | b'[' => {
                        // 优先从 __origJobject 读取原始 JNI ref（ctx.orig() 对 unboxed 值设置）。
                        // 确保 String/Integer/Boolean/Array 等所有类型安全 round-trip。
                        if result_val.is_object() {
                            let orig = result_val.get_property(ctx, "__origJobject");
                            if !orig.is_undefined() && !orig.is_null() {
                                let r = js_value_to_u64_or_zero(ctx, orig);
                                orig.free(ctx);
                                r
                            } else {
                                orig.free(ctx);
                                let env: JniEnv = hook_ctx_env;
                                if !env.is_null() {
                                    marshal_js_to_jvalue(ctx, env, result_val, Some(&return_type_sig))
                                } else {
                                    js_value_to_u64_or_zero(ctx, result_val)
                                }
                            }
                        } else if result_val.is_null() || result_val.is_undefined() {
                            0u64
                        } else {
                            // JS primitive (string/number/boolean) — 用户自己构造的返回值
                            let env: JniEnv = hook_ctx_env;
                            if !env.is_null() {
                                marshal_js_to_jvalue(ctx, env, result_val, Some(&return_type_sig))
                            } else {
                                0u64
                            }
                        }
                    }
                    _ => {
                        js_value_to_u64_or_zero(ctx, result_val)
                    }
                };
                (*ctx_ptr).x[0] = ret_u64;
            }
        },
    );

    // Fallback: if JS callback threw an exception, handle_result was NOT called.
    // We must still invoke the original method to preserve semantics.
    //
    // 注意: JS engine busy 导致的 skip 不会走到这里 — art_router_stack_check
    // 在路由前检测到 JS lock 不可用时直接 bypass（走 not_found → trampoline），
    // 完整保留 Quick 约定寄存器，方法以原始状态执行，不进入 replacement/callback。
    // 这里只处理 JS 异常等极端情况。
    if !result_was_set {
        let hook_ctx = &*ctx_ptr;
        let env: JniEnv = hook_ctx.x[0] as JniEnv;
        if !env.is_null() {
            let jargs = build_jargs_from_registers(hook_ctx, param_count, &param_types);
            let jargs_ptr = if param_count > 0 {
                jargs.as_ptr() as *const std::ffi::c_void
            } else {
                std::ptr::null()
            };
            let ret_raw = invoke_original_jni(
                env,
                art_method_addr,
                class_global_ref,
                hook_ctx.x[1],
                return_type,
                is_static,
                jargs_ptr,
            );
            if return_type == b'V' {
                (*ctx_ptr).x[0] = hook_ctx.x[0];
            } else {
                (*ctx_ptr).x[0] = ret_raw;
            }
        } else {
            (*ctx_ptr).x[0] = 0;
        }
    }

}

// ============================================================================
// Quick dispatch — 从 art_router found path 直接调用 JS callback
// ============================================================================

/// ART Quick 调用约定 → JS callback dispatch
///
/// 从 art_router found path 直接调用。HookContext 包含 Quick 调用约定寄存器：
///   x0 = ArtMethod* (original, 通过 user_data 传入)
///   x1 = this (instance) 或 jclass (static)
///   x2-x7 = Java 参数 (GP)
///   d0-d7 = Java 参数 (FP)
///   x19 = Thread* (ART 约定)
///
/// 不经过 JNI trampoline，直接调用 JS callback 并将结果写回 HookContext。
/// 跳过了 ART 的 JNI epilogue，因此:
///   - 需要手动 MonitorEnter/Exit (synchronized 方法)
///   - 对象参数是裸 mirror::Object*，需要标记为 JniTransition 后 NewLocalRef 包装
///   - float/double 返回值写入 d[0]

/// 将裸 mirror::Object* 转为 JNI local ref (jobject)。
///
/// Quick 调用约定中的对象参数是堆上的裸 mirror::Object* 指针。
/// JNI 标准 NewLocalRef 期望 jobject (IndirectRef)，不能直接传裸指针。
/// 使用 ART 内部导出的 JNIEnvExt::NewLocalRef(mirror::Object*) 直接接受裸指针。
///
/// 缓存 dlsym 结果，避免每次调用都查找。
#[allow(dead_code)]
static mut ART_NEW_LOCAL_REF: Option<unsafe extern "C" fn(*mut std::ffi::c_void, *mut std::ffi::c_void) -> *mut std::ffi::c_void> = None;

#[allow(dead_code)]
unsafe fn raw_mirror_to_local_ref(env: JniEnv, raw: u64) -> *mut std::ffi::c_void {
    if raw == 0 || env.is_null() {
        return std::ptr::null_mut();
    }

    // 尝试用 ART 内部 JNIEnvExt::NewLocalRef(mirror::Object*) — 直接接受裸指针
    let add_ref = ART_NEW_LOCAL_REF.get_or_insert_with(|| {
        let sym = crate::jsapi::module::libart_dlsym(
            "_ZN3art9JNIEnvExt11NewLocalRefEPNS_6mirror6ObjectE",
        );
        if sym.is_null() {
            // fallback: 标准 JNI NewLocalRef (可能不兼容裸指针)
            let vtable = *(env as *const *const usize);
            let new_local: unsafe extern "C" fn(*mut std::ffi::c_void, *mut std::ffi::c_void) -> *mut std::ffi::c_void =
                std::mem::transmute(*(vtable.add(25))); // JNI_NEW_LOCAL_REF = 25
            new_local
        } else {
            std::mem::transmute(sym)
        }
    });
    add_ref(env as *mut std::ffi::c_void, raw as *mut std::ffi::c_void)
}
#[no_mangle]
#[allow(dead_code)]
pub unsafe extern "C" fn java_hook_dispatch_from_quick(
    ctx_ptr: *mut hook_ffi::HookContext,
    user_data: *mut std::ffi::c_void,
) {
    // 最早的 log — 确认函数是否被调用
    crate::jsapi::console::output_verbose("[dispatch] ENTRY");
    if ctx_ptr.is_null() || user_data.is_null() {
        return;
    }
    let _in_flight_guard = InFlightJavaHookGuard::enter();
    let _callback_scope = JavaHookCallbackScope::enter();

    let art_method_addr = user_data as u64;

    // 复制 callback 数据，然后释放 lock
    let (
        ctx_usize,
        callback_bytes,
        is_static,
        param_count,
        return_type,
        return_type_sig,
        param_types,
        class_global_ref,
    ) = {
        let guard = match JAVA_HOOK_REGISTRY.lock() {
            Ok(g) => g,
            Err(_) => {
                (*ctx_ptr).x[0] = 0;
                return;
            }
        };
        let registry = match guard.as_ref() {
            Some(r) => r,
            None => {
                (*ctx_ptr).x[0] = 0;
                return;
            }
        };
        let hook_data = match registry.get(&art_method_addr) {
            Some(d) => d,
            None => {
                (*ctx_ptr).x[0] = 0;
                return;
            }
        };
        (
            hook_data.ctx,
            hook_data.callback_bytes,
            hook_data.is_static,
            hook_data.param_count,
            hook_data.return_type,
            hook_data.return_type_sig.clone(),
            hook_data.param_types.clone(),
            hook_data.class_global_ref,
        )
    }; // lock released

    // 通过 JNI 标准接口获取当前线程的 JNIEnv*
    // Android 16+ Thread* 通过 TLS 访问，x19 不再是 Thread*
    let env: JniEnv = match crate::jsapi::java::jni_core::get_thread_env() {
        Ok(e) => e,
        Err(e) => {
            crate::jsapi::console::output_verbose(&format!(
                "[dispatch] get_thread_env failed: {}, art_method={:#x}",
                e, art_method_addr
            ));
            return;
        }
    };

    // Quick code 上下文中不能调 JNI 函数 (没有 JNI transition frame)。
    // 参数不做 marshal, 对象参数以原始值传给 JS (BigUint64)。
    // callOriginal (ctx.orig()) 走 clone+JNI, 有完整 JNI 环境。
    let mut result_was_set = false;

    crate::jsapi::console::output_verbose(&format!(
        "[dispatch] BEFORE invoke_hook_callback_common: art_method={:#x}, ctx={:#x}",
        art_method_addr, ctx_usize
    ));

    // DEBUG: 跳过所有操作，纯 return（验证 dispatch+RET 本身是否安全）
    crate::jsapi::console::output_verbose("[dispatch] PURE RETURN (no JS, no clone)");
    (*ctx_ptr).x[0] = 0; // 返回 null/0
    return;

    #[allow(unreachable_code)]
    invoke_hook_callback_common(
        ctx_usize,
        &callback_bytes,
        "java hook (quick)",
        art_method_addr,
        // 构建 JS 上下文对象 — 纯数值, 不调 JNI
        |ctx| {
            let js_ctx = ffi::JS_NewObject(ctx);
            let hook_ctx = &*ctx_ptr;

            // thisObj: 原始值 (BigUint64)
            if !is_static {
                set_js_u64_property(ctx, js_ctx, "thisObj", hook_ctx.x[1]);
            }

            // args[] — 从寄存器读取原始值, 不转 JNI handle
            {
                let arr = ffi::JS_NewArray(ctx);
                let mut gp_index: usize = 0;
                let mut fp_index: usize = 0;
                for i in 0..param_count {
                    let type_sig = param_types.get(i).map(|s| s.as_str());
                    let is_fp = is_floating_point_type(type_sig);
                    let (raw, fp_raw) =
                        extract_jni_arg(hook_ctx, is_fp, &mut gp_index, &mut fp_index);
                    // 所有参数以原始值传递, 不调 JNI marshal
                    let val = match type_sig.map(|s| s.as_bytes().first().copied()) {
                        Some(Some(b'Z')) => JSValue::bool(raw != 0).raw(),
                        Some(Some(b'B')) => JSValue::int(raw as i8 as i32).raw(),
                        Some(Some(b'S')) => JSValue::int(raw as i16 as i32).raw(),
                        Some(Some(b'I')) => JSValue::int(raw as i32).raw(),
                        Some(Some(b'F')) => JSValue::float(f32::from_bits(fp_raw as u32) as f64).raw(),
                        Some(Some(b'D')) => JSValue::float(f64::from_bits(fp_raw)).raw(),
                        _ => ffi::JS_NewBigUint64(ctx, raw), // J, L, [, 等 → BigUint64
                    };
                    ffi::JS_SetPropertyUint32(ctx, arr, i as u32, val);
                }
                JSValue(js_ctx).set_property(ctx, "args", JSValue(arr));
            }

            set_js_u64_property(ctx, js_ctx, "env", env as u64);
            set_js_u64_property(ctx, js_ctx, "__hookCtxPtr", ctx_ptr as usize as u64);
            set_js_u64_property(ctx, js_ctx, "__hookArtMethod", art_method_addr);
            set_js_cfunction_property(ctx, js_ctx, "orig", js_call_original, 0);

            js_ctx
        },
        // 处理返回值
        |_ctx, _js_ctx, _result| {
            result_was_set = true;
            // 返回值由 ctx.orig() 设置 (通过 invoke_original_jni)
            // 如果 JS 没调 orig(), 返回值为 0/null
        },
    );

    // Fallback + 默认路径: 调用原始方法 via JNI (2-ArtMethod 模型)
    // JNI CallNonvirtualMethodA 会建立完整的 JNI transition frame
    if !result_was_set {
        if !env.is_null() {
            let hook_ctx = &*ctx_ptr;
            let jargs = build_jargs_from_registers(hook_ctx, param_count, &param_types);
            let jargs_ptr = if param_count > 0 {
                jargs.as_ptr() as *const std::ffi::c_void
            } else {
                std::ptr::null()
            };
            // x[1] 在 Layer 1/2 路径不是 receiver, 强制静态调用
            let ret_raw = invoke_original_jni(
                env,
                art_method_addr,
                class_global_ref,
                0, // receiver=0, 用静态调用
                return_type,
                true, // 强制 is_static
                jargs_ptr,
            );
            if return_type != b'V' {
                (*ctx_ptr).x[0] = ret_raw;
            }
        } else {
            (*ctx_ptr).x[0] = 0;
        }
    }
}
