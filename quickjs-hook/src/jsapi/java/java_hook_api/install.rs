use crate::ffi;
use crate::ffi::hook as hook_ffi;
use crate::jsapi::callback_util::{
    dup_callback_to_bytes, ensure_function_arg, extract_string_arg, throw_internal_error, with_registry,
    with_registry_mut,
};
use crate::jsapi::console::output_verbose;
use crate::value::JSValue;

use super::super::art_controller::ensure_art_controller_initialized;
use super::super::art_method::*;
use super::super::callback::*;
use super::super::jni_core::*;
use super::install_support::{
    create_class_global_ref, create_replacement_art_method,
    install_per_method_router_hook, update_original_method_flags_for_hook, JavaHookInstallGuard,
};

pub(in crate::jsapi::java) unsafe extern "C" fn js_java_hook(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 4 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Java.hook() requires 4 arguments: class, method, signature, callback\0".as_ptr() as *const _,
        );
    }

    let class_arg = JSValue(*argv);
    let method_arg = JSValue(*argv.add(1));
    let sig_arg = JSValue(*argv.add(2));
    let callback_arg = JSValue(*argv.add(3));

    let class_name = match extract_string_arg(
        ctx,
        class_arg,
        b"Java.hook() first argument must be a class name string\0",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };

    let method_name = match extract_string_arg(
        ctx,
        method_arg,
        b"Java.hook() second argument must be a method name string\0",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };

    let sig_str = match extract_string_arg(ctx, sig_arg, b"Java.hook() third argument must be a signature string\0") {
        Ok(value) => value,
        Err(err) => return err,
    };

    if let Err(err) = ensure_function_arg(ctx, callback_arg, b"Java.hook() fourth argument must be a function\0") {
        return err;
    }

    let (actual_sig, force_static) = if let Some(stripped) = sig_str.strip_prefix("static:") {
        (stripped.to_string(), true)
    } else {
        (sig_str.clone(), false)
    };

    let env = match ensure_jni_initialized() {
        Ok(e) => e,
        Err(msg) => return throw_internal_error(ctx, msg),
    };

    let (art_method, is_static) = match resolve_art_method(env, &class_name, &method_name, &actual_sig, force_static) {
        Ok(r) => r,
        Err(msg) => return throw_internal_error(ctx, msg),
    };

    init_java_registry();
    if with_registry(&JAVA_HOOK_REGISTRY, |r| r.contains_key(&art_method)).unwrap_or(false) {
        let new_callback_bytes = dup_callback_to_bytes(ctx, callback_arg.raw());

        let old_callback_bytes = with_registry_mut(&JAVA_HOOK_REGISTRY, |registry| {
            if let Some(hook_data) = registry.get_mut(&art_method) {
                let old_bytes = hook_data.callback_bytes;
                hook_data.callback_bytes = new_callback_bytes;
                hook_data.ctx = ctx as usize;
                Some(old_bytes)
            } else {
                None
            }
        })
        .flatten();

        if let Some(old_bytes) = old_callback_bytes {
            let old_callback: ffi::JSValue = std::ptr::read(old_bytes.as_ptr() as *const ffi::JSValue);
            ffi::qjs_free_value(ctx, old_callback);
        }

        output_verbose(&format!(
            "[java hook] 回调已替换: {}.{}{}",
            class_name, method_name, actual_sig
        ));

        return JSValue::bool(true).raw();
    }

    let spec = get_art_method_spec(env, art_method);
    let ep_offset = spec.entry_point_offset;
    let data_off = spec.data_offset;

    let original_access_flags = std::ptr::read_volatile((art_method as usize + spec.access_flags_offset) as *const u32);
    let original_data = std::ptr::read_volatile((art_method as usize + data_off) as *const u64);
    let original_entry_point = read_entry_point(art_method, ep_offset);

    output_verbose(&format!(
        "[java hook] Step 1 fetchArtMethod: art_method={:#x}, flags={:#x}, data_={:#x}, ep={:#x}",
        art_method, original_access_flags, original_data, original_entry_point
    ));

    {
        let api_level = get_android_api_level();
        if api_level < 30 && (original_access_flags & K_ACC_XPOSED_HOOKED_METHOD) != 0 {
            output_verbose(&format!(
                "[java hook] Step 2: Xposed hooked method detected (flags={:#x}), proceeding with caution",
                original_access_flags
            ));
        }
    }

    // 2-ArtMethod 模型: 不再分配 clone，callOriginal 直接用原始 ArtMethod

    let bridge = find_art_bridge_functions(env, ep_offset);
    let jni_trampoline = bridge.quick_generic_jni_trampoline;
    if jni_trampoline == 0 {
        return throw_internal_error(ctx, "failed to find art_quick_generic_jni_trampoline");
    }

    let class_global_ref = match create_class_global_ref(env, &class_name) {
        Ok(gref) => gref,
        Err(msg) => {
            return throw_internal_error(ctx, msg);
        }
    };
    let clone_size = spec.size;
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

    let return_type = get_return_type_from_sig(&actual_sig);
    let has_independent_code = !is_art_quick_entrypoint(original_entry_point, bridge);
    let is_constructor = method_name == "<init>";

    output_verbose(&format!(
        "[java hook] Step 4: has_independent_code={} (ep={:#x})",
        has_independent_code, original_entry_point
    ));

    // Clone+Replace 模式 (对标 Frida):
    // 原始 ArtMethod 仅修改 flags (deopt)，不设 kAccNative。
    // replacement ArtMethod (heap) 设为 kAccNative + jniCode=thunk + quickCode=jni_trampoline。
    // 通过 artController Layer 1+2+3 路由 original → replacement。

    // current_pc_hint 统一传 0: replacement 已标记 kAccNative，
    // ART JNI 路径会正确处理 native 方法的 frame。
    let thunk = hook_ffi::hook_create_native_trampoline(
        art_method,
        Some(java_hook_callback),
        art_method as *mut std::ffi::c_void,
        0,
    );

    if thunk.is_null() {
        return throw_internal_error(ctx, "hook_create_native_trampoline failed");
    }
    install_guard.set_redirect_installed();

    let replacement_addr = match create_replacement_art_method(
        art_method,
        clone_size,
        spec,
        original_access_flags,
        data_off,
        ep_offset,
        thunk,
        jni_trampoline,
    ) {
        Ok(addr) => addr,
        Err(msg) => return throw_internal_error(ctx, msg),
    };
    install_guard.set_replacement_addr(replacement_addr);

    // B1: 确保 artController 已初始化 (Layer 1 + Layer 2 全局 hook)
    ensure_art_controller_initialized(&bridge, ep_offset, env as *mut std::ffi::c_void);

    // B2: 注册 replacement 到 replacedMethods 映射 (art_router 查表用)
    set_replacement_method(art_method, replacement_addr as u64);
    install_guard.set_replacement_registered();

    // B3: 修改原始 ArtMethod flags (对标 Frida android.js:3732-3741)
    // 不设 kAccNative! 仅 deopt + 清除快速路径标志
    update_original_method_flags_for_hook(art_method, spec.access_flags_offset, original_access_flags);
    install_guard.set_original_method_mutated();

    // B4: nterp → interpreter_bridge 降级 (对标 Frida android.js:3747-3750)
    if bridge.nterp_entry_point != 0 && original_entry_point == bridge.nterp_entry_point {
        let interp_bridge = bridge.quick_to_interpreter_bridge;
        if interp_bridge != 0 {
            std::ptr::write_volatile((art_method as usize + ep_offset) as *mut u64, interp_bridge);
            hook_ffi::hook_flush_cache((art_method as usize + ep_offset) as *mut std::ffi::c_void, 8);
            output_verbose(&format!(
                "[java hook] nterp → interpreter_bridge: {:#x} → {:#x}",
                original_entry_point, interp_bridge
            ));
        }
    }

    // B5: Layer 3 per-method router hook (对标 Frida ArtQuickCodeInterceptor)
    let (per_method_hook_target, quick_trampoline) = match install_per_method_router_hook(
        has_independent_code,
        original_entry_point,
        &bridge,
        ep_offset,
        env,
        art_method,
        is_constructor,
    ) {
        Ok(v) => v,
        Err(msg) => return throw_internal_error(ctx, msg),
    };

    let callback_bytes = dup_callback_to_bytes(ctx, callback_arg.raw());

    with_registry_mut(&JAVA_HOOK_REGISTRY, |registry| {
        registry.insert(
            art_method,
            JavaHookData {
                art_method,
                original_access_flags,
                original_entry_point,
                original_data,
                hook_type: HookType::Replaced {
                    replacement_addr,
                    per_method_hook_target,
                },
                clone_addr: 0, // 2-ArtMethod 模型: 不再使用 clone
                class_global_ref,
                return_type,
                return_type_sig: get_return_type_sig(&actual_sig),
                ctx: ctx as usize,
                callback_bytes,
                method_key: method_key(&class_name, &method_name, &actual_sig),
                is_static,
                param_count: count_jni_params(&actual_sig),
                param_types: parse_jni_param_types(&actual_sig),
                class_name: class_name.clone(),
                quick_trampoline,
            },
        );
    });

    cache_fields_for_class(env, &class_name);

    let strategy = if has_independent_code {
        "compiled+router"
    } else {
        "shared_stub"
    };
    output_verbose(&format!(
        "[java hook] 完成: {}.{}{} (ArtMethod={:#x}, strategy={})",
        class_name, method_name, actual_sig, art_method, strategy
    ));

    install_guard.commit();
    JSValue::bool(true).raw()
}
