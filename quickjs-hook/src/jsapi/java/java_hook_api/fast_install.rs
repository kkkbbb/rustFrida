use crate::ffi;
use crate::jsapi::callback_util::{extract_string_arg, throw_internal_error, with_registry_mut};
use crate::value::JSValue;

use super::super::art_controller::ensure_art_controller_initialized;
use super::super::art_method::*;
use super::super::callback::*;
use super::super::jni_core::*;
use super::install_support::{
    create_class_global_ref, create_quick_stack_sentinel_art_method, install_per_method_router_hook,
    JavaHookInstallGuard,
};

unsafe fn install_fast_hook_inner(class_name: &str, method_name: &str, sig: &str, dsl: &str) -> Result<(), String> {
    let env = ensure_jni_initialized()?;
    install_fast_hook_with_env(env, class_name, method_name, sig, dsl)
}

pub(in crate::jsapi::java) unsafe fn install_fast_hook_with_env(
    env: JniEnv,
    class_name: &str,
    method_name: &str,
    sig: &str,
    dsl: &str,
) -> Result<(), String> {
    let (actual_sig, force_static) = if let Some(stripped) = sig.strip_prefix("static:") {
        (stripped.to_string(), true)
    } else {
        (sig.to_string(), false)
    };

    let (art_method, is_static) = resolve_art_method(env, class_name, method_name, &actual_sig, force_static)?;

    init_java_registry();

    if crate::jsapi::callback_util::with_registry(&JAVA_HOOK_REGISTRY, |r| r.contains_key(&art_method)).unwrap_or(false)
    {
        return Err("method already hooked — unhook first".to_string());
    }

    let spec = get_art_method_spec(env, art_method);
    let ep_offset = spec.entry_point_offset;
    let data_off = spec.data_offset;
    let original_access_flags = std::ptr::read_volatile((art_method as usize + spec.access_flags_offset) as *const u32);
    let original_data = std::ptr::read_volatile((art_method as usize + data_off) as *const u64);
    let original_entry_point = read_entry_point(art_method, ep_offset);
    let bridge = find_art_bridge_functions(env, ep_offset);
    if !is_code_pointer(original_entry_point) {
        return Err(format!(
            "resolved ArtMethod entry_point is not executable for Java.fastHook {}.{}{} (ArtMethod={:#x}, ep={:#x}, spec={:?})",
            class_name, method_name, actual_sig, art_method, original_entry_point, spec
        ));
    }
    let has_independent_code = !is_art_quick_entrypoint(original_entry_point, bridge);
    if !has_independent_code {
        return Err("Java.fastHook currently requires compiled quick code; use Java.compileMethod() first".to_string());
    }

    let return_type = get_return_type_from_sig(&actual_sig);
    let rule = crate::fast_hook::compile_fast_rule(dsl, is_static, parse_jni_param_types(&actual_sig), return_type)?;

    let class_global_ref = create_class_global_ref(env, class_name)?;
    let mut install_guard = JavaHookInstallGuard::new(
        art_method,
        spec.access_flags_offset,
        data_off,
        ep_offset,
        original_access_flags,
        original_data,
        original_entry_point,
        class_global_ref,
    );

    let (per_method_hook_target, quick_trampoline, use_blr, router_thunk_body, _original_entry_mutated) =
        install_per_method_router_hook(
            true,
            original_entry_point,
            &bridge,
            ep_offset,
            env,
            art_method,
            false,
            method_name == "<init>",
            false,
            false,
        )?;
    let stack_entry_point = router_thunk_body.ok_or("fastHook requires router thunk body")?;
    let (replacement_addr, sentinel_source) =
        create_quick_stack_sentinel_art_method(art_method, spec.size, spec, data_off, ep_offset, stack_entry_point)?;
    install_guard.set_replacement_addr(replacement_addr);

    ensure_art_controller_initialized(&bridge, ep_offset, env as *mut std::ffi::c_void);
    crate::fast_hook::register_fast_rule(art_method, rule);
    set_quick_callback_method_mode(
        art_method,
        replacement_addr as u64,
        Some(crate::fast_hook::fast_hook_dispatch_from_quick),
        2,
    );
    install_guard.set_replacement_registered();

    with_registry_mut(&JAVA_HOOK_REGISTRY, |registry| {
        registry.insert(
            art_method,
            JavaHookData {
                art_method,
                original_access_flags,
                original_entry_point,
                original_data,
                hook_type: HookType::Quick {
                    replacement_addr,
                    per_method_hook_target,
                    declaring_class_source: sentinel_source,
                },
                clone_addr: 0,
                class_global_ref,
                return_type,
                return_type_sig: get_return_type_sig(&actual_sig),
                ctx: 0,
                callback_bytes: [0u8; 16],
                method_key: method_key(class_name, method_name, &actual_sig),
                is_static,
                param_count: count_jni_params(&actual_sig),
                param_types: parse_jni_param_types(&actual_sig),
                class_name: class_name.to_string(),
                quick_trampoline,
                use_blr,
                native_entry_hook_target: 0,
                native_entry_trampoline: 0,
                native_entry_critical: false,
            },
        );
    });

    cache_fields_for_class(env, class_name);
    crate::jsapi::console::output_message(&format!(
        "[fastHook] installed: {}.{}{} ArtMethod={:#x}, trampoline={:#x}",
        class_name, method_name, actual_sig, art_method, quick_trampoline
    ));
    install_guard.commit();
    Ok(())
}

fn java_type_to_jni_for_fast_hook(type_name: &str) -> Result<String, String> {
    let type_name = type_name.trim();
    if type_name.is_empty() {
        return Err("empty Java type in fastHook signature".to_string());
    }
    if let Some(base) = type_name.strip_suffix("[]") {
        return Ok(format!("[{}", java_type_to_jni_for_fast_hook(base)?));
    }
    let sig = match type_name {
        "void" => "V".to_string(),
        "boolean" => "Z".to_string(),
        "byte" => "B".to_string(),
        "char" => "C".to_string(),
        "short" => "S".to_string(),
        "int" => "I".to_string(),
        "long" => "J".to_string(),
        "float" => "F".to_string(),
        "double" => "D".to_string(),
        _ if type_name.starts_with('[') => type_name.replace('.', "/"),
        _ if type_name.starts_with('L') && type_name.ends_with(';') => type_name.replace('.', "/"),
        _ => format!("L{};", type_name.replace('.', "/")),
    };
    Ok(sig)
}

unsafe fn js_array_len(ctx: *mut ffi::JSContext, value: JSValue) -> u64 {
    let len_value = value.get_property(ctx, "length");
    let len = len_value.to_u64(ctx).unwrap_or(0);
    len_value.free(ctx);
    len
}

unsafe fn extract_signature_arg(
    ctx: *mut ffi::JSContext,
    arg: JSValue,
    name: &'static str,
) -> Result<String, ffi::JSValue> {
    if arg.is_string() {
        return extract_string_arg(ctx, arg, b"signature must be a string or [params, ret]\0");
    }
    if ffi::JS_IsArray(ctx, arg.raw()) == 0 {
        let msg = format!(
            "{} must be a JNI signature string or Frida-style [params, returnType]",
            name
        );
        return Err(throw_internal_error(ctx, msg));
    }

    let len = js_array_len(ctx, arg);
    if len != 2 {
        let msg = format!("{} array signature must be [paramsArray, returnType]", name);
        return Err(throw_internal_error(ctx, msg));
    }

    let params_raw = ffi::JS_GetPropertyUint32(ctx, arg.raw(), 0);
    let params = JSValue(params_raw);
    if ffi::JS_IsArray(ctx, params.raw()) == 0 {
        params.free(ctx);
        return Err(throw_internal_error(ctx, "signature params must be an array"));
    }

    let mut sig = String::from("(");
    let params_len = js_array_len(ctx, params);
    for i in 0..params_len {
        let elem_raw = ffi::JS_GetPropertyUint32(ctx, params.raw(), i as u32);
        let elem = JSValue(elem_raw);
        let Some(type_name) = elem.to_string(ctx) else {
            elem.free(ctx);
            params.free(ctx);
            return Err(throw_internal_error(ctx, "signature param type must be a string"));
        };
        elem.free(ctx);
        match java_type_to_jni_for_fast_hook(&type_name) {
            Ok(jni) => sig.push_str(&jni),
            Err(e) => {
                params.free(ctx);
                return Err(throw_internal_error(ctx, e));
            }
        }
    }
    params.free(ctx);

    let ret_raw = ffi::JS_GetPropertyUint32(ctx, arg.raw(), 1);
    let ret = JSValue(ret_raw);
    let Some(ret_type) = ret.to_string(ctx) else {
        ret.free(ctx);
        return Err(throw_internal_error(ctx, "signature return type must be a string"));
    };
    ret.free(ctx);
    let ret_sig = match java_type_to_jni_for_fast_hook(&ret_type) {
        Ok(v) => v,
        Err(e) => return Err(throw_internal_error(ctx, e)),
    };
    sig.push(')');
    sig.push_str(&ret_sig);
    Ok(sig)
}

unsafe fn extract_string_prop(ctx: *mut ffi::JSContext, obj: JSValue, names: &[&str]) -> Result<String, ffi::JSValue> {
    for name in names {
        let value = obj.get_property(ctx, name);
        if !value.is_undefined() && !value.is_null() {
            let result = value.to_string(ctx);
            value.free(ctx);
            if let Some(result) = result {
                return Ok(result);
            }
            return Err(throw_internal_error(
                ctx,
                format!("fastHook option '{}' must be a string", name),
            ));
        }
        value.free(ctx);
    }
    Err(throw_internal_error(
        ctx,
        format!("fastHook option missing: {}", names.join("/")),
    ))
}

unsafe fn extract_signature_prop(ctx: *mut ffi::JSContext, obj: JSValue) -> Result<String, ffi::JSValue> {
    for name in ["signature", "sig"] {
        let value = obj.get_property(ctx, name);
        if !value.is_undefined() && !value.is_null() {
            let result = extract_signature_arg(ctx, value, name);
            value.free(ctx);
            return result;
        }
        value.free(ctx);
    }
    Err(throw_internal_error(ctx, "fastHook option missing: signature/sig"))
}

unsafe fn extract_fast_hook_args(
    ctx: *mut ffi::JSContext,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> Result<(String, String, String, String), ffi::JSValue> {
    if argc == 1 {
        let opts = JSValue(*argv);
        if !opts.is_object() || ffi::JS_IsArray(ctx, opts.raw()) != 0 {
            return Err(ffi::JS_ThrowTypeError(
                ctx,
                b"Java.fastHook(object) requires an options object\0".as_ptr() as *const _,
            ));
        }
        let class_name = extract_string_prop(ctx, opts, &["className", "class"])?;
        let method_name = extract_string_prop(ctx, opts, &["methodName", "method"])?;
        let sig = extract_signature_prop(ctx, opts)?;
        let dsl = extract_string_prop(ctx, opts, &["dsl", "code"])?;
        return Ok((class_name, method_name, sig, dsl));
    }

    if argc < 4 {
        return Err(ffi::JS_ThrowTypeError(
            ctx,
            b"Java.fastHook() requires 4 args or one options object\0".as_ptr() as *const _,
        ));
    }

    let class_name = extract_string_arg(ctx, JSValue(*argv), b"arg1 must be class name\0")?;
    let method_name = extract_string_arg(ctx, JSValue(*argv.add(1)), b"arg2 must be method name\0")?;
    let sig = extract_signature_arg(ctx, JSValue(*argv.add(2)), "arg3")?;
    let dsl = extract_string_arg(ctx, JSValue(*argv.add(3)), b"arg4 must be fastHook DSL\0")?;
    Ok((class_name, method_name, sig, dsl))
}

pub(in crate::jsapi::java) unsafe extern "C" fn js_fast_hook(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let (class_name, method_name, sig, dsl) = match extract_fast_hook_args(ctx, argc, argv) {
        Ok(v) => v,
        Err(e) => return e,
    };

    let result = if crate::is_raw_clone_js_thread() {
        super::super::callback::fast_hook_via_executor(class_name, method_name, sig, dsl)
    } else {
        super::super::lazy_init_reflect_cache();
        install_fast_hook_inner(&class_name, &method_name, &sig, &dsl)
    };

    match result {
        Ok(()) => JSValue::bool(true).raw(),
        Err(e) => throw_internal_error(ctx, e),
    }
}

pub(in crate::jsapi::java) unsafe extern "C" fn js_fast_hook_signature(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Java.fastHookSig() requires a JNI string or [params, returnType]\0".as_ptr() as *const _,
        );
    }
    match extract_signature_arg(ctx, JSValue(*argv), "signature") {
        Ok(sig) => JSValue::string(ctx, &sig).raw(),
        Err(e) => e,
    }
}

pub(in crate::jsapi::java) unsafe extern "C" fn js_fast_hook_check(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    super::super::lazy_init_reflect_cache();
    if argc < 1 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Java.fastHookCheck() requires dsl[, signature]\0".as_ptr() as *const _,
        );
    }
    let dsl = match extract_string_arg(ctx, JSValue(*argv), b"arg1 must be fastHook DSL\0") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let sig = if argc >= 2 {
        match extract_signature_arg(ctx, JSValue(*argv.add(1)), "arg2") {
            Ok(v) => v,
            Err(e) => return e,
        }
    } else {
        "()Ljava/lang/Object;".to_string()
    };
    let is_static = if argc >= 3 {
        JSValue(*argv.add(2)).to_bool().unwrap_or(false)
    } else {
        false
    };
    let return_type = get_return_type_from_sig(&sig);
    let result = crate::fast_hook::compile_fast_rule(&dsl, is_static, parse_jni_param_types(&sig), return_type);
    let obj = ffi::JS_NewObject(ctx);
    let obj_val = JSValue(obj);
    match result {
        Ok(_) => {
            obj_val.set_property(ctx, "ok", JSValue::bool(true));
            obj_val.set_property(ctx, "signature", JSValue::string(ctx, &sig));
            obj_val.set_property(ctx, "paramCount", JSValue::int(count_jni_params(&sig) as i32));
            obj_val.set_property(ctx, "returnType", JSValue::string(ctx, &get_return_type_sig(&sig)));
        }
        Err(e) => {
            obj_val.set_property(ctx, "ok", JSValue::bool(false));
            obj_val.set_property(ctx, "signature", JSValue::string(ctx, &sig));
            obj_val.set_property(ctx, "error", JSValue::string(ctx, &e));
        }
    }
    obj
}

pub(in crate::jsapi::java) unsafe extern "C" fn js_fast_hook_stats(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let stats = crate::fast_hook::fast_stats();
    let (art_exception_seen, art_exception_cleared) = crate::jsapi::java::java_fast_api::fast_art_exception_stats();
    let (
        handle_scope_enter,
        handle_scope_unavailable,
        handle_scope_leaked,
        handle_scope_max_roots,
        handle_scope_root_failed,
        handle_scope_capacity_exceeded,
    ) = crate::jsapi::java::java_fast_api::fast_art_handle_scope_stats();
    let obj = ffi::JS_NewObject(ctx);
    let obj_val = JSValue(obj);
    obj_val.set_property(ctx, "total", JSValue(ffi::JS_NewBigUint64(ctx, stats.total)));
    obj_val.set_property(ctx, "matched", JSValue(ffi::JS_NewBigUint64(ctx, stats.matched)));
    obj_val.set_property(ctx, "totalNs", JSValue(ffi::JS_NewBigUint64(ctx, stats.total_ns)));
    obj_val.set_property(ctx, "maxNs", JSValue(ffi::JS_NewBigUint64(ctx, stats.max_ns)));
    obj_val.set_property(ctx, "over100us", JSValue(ffi::JS_NewBigUint64(ctx, stats.over_100us)));
    obj_val.set_property(ctx, "over500us", JSValue(ffi::JS_NewBigUint64(ctx, stats.over_500us)));
    obj_val.set_property(ctx, "over1ms", JSValue(ffi::JS_NewBigUint64(ctx, stats.over_1ms)));
    obj_val.set_property(ctx, "over5ms", JSValue(ffi::JS_NewBigUint64(ctx, stats.over_5ms)));
    obj_val.set_property(ctx, "over16ms", JSValue(ffi::JS_NewBigUint64(ctx, stats.over_16ms)));
    obj_val.set_property(ctx, "over100ms", JSValue(ffi::JS_NewBigUint64(ctx, stats.over_100ms)));
    obj_val.set_property(ctx, "newTotal", JSValue(ffi::JS_NewBigUint64(ctx, stats.new_total)));
    obj_val.set_property(ctx, "newFailed", JSValue(ffi::JS_NewBigUint64(ctx, stats.new_failed)));
    obj_val.set_property(
        ctx,
        "newTotalNs",
        JSValue(ffi::JS_NewBigUint64(ctx, stats.new_total_ns)),
    );
    obj_val.set_property(ctx, "newMaxNs", JSValue(ffi::JS_NewBigUint64(ctx, stats.new_max_ns)));
    obj_val.set_property(
        ctx,
        "newOver100us",
        JSValue(ffi::JS_NewBigUint64(ctx, stats.new_over_100us)),
    );
    obj_val.set_property(
        ctx,
        "newOver500us",
        JSValue(ffi::JS_NewBigUint64(ctx, stats.new_over_500us)),
    );
    obj_val.set_property(
        ctx,
        "newOver1ms",
        JSValue(ffi::JS_NewBigUint64(ctx, stats.new_over_1ms)),
    );
    obj_val.set_property(
        ctx,
        "newOver5ms",
        JSValue(ffi::JS_NewBigUint64(ctx, stats.new_over_5ms)),
    );
    obj_val.set_property(
        ctx,
        "newOver16ms",
        JSValue(ffi::JS_NewBigUint64(ctx, stats.new_over_16ms)),
    );
    obj_val.set_property(
        ctx,
        "newOver100ms",
        JSValue(ffi::JS_NewBigUint64(ctx, stats.new_over_100ms)),
    );
    obj_val.set_property(
        ctx,
        "newTlabHit",
        JSValue(ffi::JS_NewBigUint64(ctx, stats.new_tlab_hit)),
    );
    obj_val.set_property(
        ctx,
        "newTlabMiss",
        JSValue(ffi::JS_NewBigUint64(ctx, stats.new_tlab_miss)),
    );
    obj_val.set_property(
        ctx,
        "newSlowPath",
        JSValue(ffi::JS_NewBigUint64(ctx, stats.new_slow_path)),
    );
    obj_val.set_property(
        ctx,
        "artExceptionSeen",
        JSValue(ffi::JS_NewBigUint64(ctx, art_exception_seen)),
    );
    obj_val.set_property(
        ctx,
        "artExceptionCleared",
        JSValue(ffi::JS_NewBigUint64(ctx, art_exception_cleared)),
    );
    obj_val.set_property(
        ctx,
        "handleScopeEnter",
        JSValue(ffi::JS_NewBigUint64(ctx, handle_scope_enter)),
    );
    obj_val.set_property(
        ctx,
        "handleScopeUnavailable",
        JSValue(ffi::JS_NewBigUint64(ctx, handle_scope_unavailable)),
    );
    obj_val.set_property(
        ctx,
        "handleScopeLeaked",
        JSValue(ffi::JS_NewBigUint64(ctx, handle_scope_leaked)),
    );
    obj_val.set_property(
        ctx,
        "handleScopeMaxRoots",
        JSValue(ffi::JS_NewBigUint64(ctx, handle_scope_max_roots)),
    );
    obj_val.set_property(
        ctx,
        "handleScopeRootFailed",
        JSValue(ffi::JS_NewBigUint64(ctx, handle_scope_root_failed)),
    );
    obj_val.set_property(
        ctx,
        "handleScopeCapacityExceeded",
        JSValue(ffi::JS_NewBigUint64(ctx, handle_scope_capacity_exceeded)),
    );
    obj
}
