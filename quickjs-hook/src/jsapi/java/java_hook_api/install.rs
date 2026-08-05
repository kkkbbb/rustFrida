use crate::ffi;
use crate::ffi::hook as hook_ffi;
use crate::jsapi::callback_util::{
    dup_callback_to_bytes, ensure_function_arg, extract_string_arg, throw_internal_error, with_registry,
    with_registry_mut,
};
use crate::jsapi::console::output_verbose;
use crate::value::JSValue;

use super::super::art_controller::{ensure_art_controller_initialized, ensure_shared_entry_router_hook};
use super::super::art_method::*;
use super::super::callback::*;
use super::super::jni_core::*;
use super::install_support::{
    alloc_art_method_clone, create_class_global_ref, create_replacement_art_method, install_per_method_router_hook,
    JavaHookInstallGuard,
};

fn is_registered_native_entry_candidate(addr: u64, bridge: &ArtBridgeFunctions) -> bool {
    if addr < 0x10000 {
        return false;
    }
    if addr == bridge.quick_generic_jni_trampoline
        || addr == bridge.quick_to_interpreter_bridge
        || addr == bridge.quick_resolution_trampoline
        || addr == bridge.quick_imt_conflict_trampoline
        || addr == bridge.nterp_entry_point
        || addr == bridge.nterp_with_clinit_entry_point
        || (bridge.resolved_jni_entrypoint != 0 && addr == bridge.resolved_jni_entrypoint)
        || (bridge.resolved_interpreter_bridge_entrypoint != 0 && addr == bridge.resolved_interpreter_bridge_entrypoint)
        || (bridge.resolved_resolution_entrypoint != 0 && addr == bridge.resolved_resolution_entrypoint)
    {
        return false;
    }
    if !crate::jsapi::util::is_addr_accessible(addr, 4) {
        return false;
    }
    let Some(maps) = crate::jsapi::util::read_proc_self_maps() else {
        return false;
    };
    let Some(entry) = crate::jsapi::util::proc_maps_entries(&maps).find(|entry| entry.contains(addr)) else {
        return false;
    };
    if entry.path.map(|path| path.contains("/libart.so")).unwrap_or(false) {
        return false;
    }
    (entry.prot_flags() & libc::PROT_EXEC) != 0
}

fn is_known_shared_router_entry(addr: u64, bridge: &ArtBridgeFunctions) -> bool {
    addr == bridge.quick_to_interpreter_bridge || addr == bridge.quick_resolution_trampoline
}

unsafe fn normalize_internal_shared_entry_if_needed(
    art_method: u64,
    ep_offset: usize,
    env: JniEnv,
    bridge: &ArtBridgeFunctions,
    reason: &str,
) -> bool {
    if bridge.quick_to_interpreter_bridge == 0 {
        return false;
    }
    let current_entry_point = read_entry_point(art_method, ep_offset);
    if !is_art_quick_entrypoint(current_entry_point, bridge)
        || is_known_shared_router_entry(current_entry_point, bridge)
    {
        return false;
    }

    std::ptr::write_volatile(
        (art_method as usize + ep_offset) as *mut u64,
        bridge.quick_to_interpreter_bridge,
    );
    hook_ffi::hook_flush_cache((art_method as usize + ep_offset) as *mut std::ffi::c_void, 8);
    if let Err(msg) = ensure_shared_entry_router_hook(reason, bridge.quick_to_interpreter_bridge, ep_offset, env, false)
    {
        output_verbose(&format!(
            "[java hook] {} interpreter bridge router ensure failed: {}",
            reason, msg
        ));
    }
    output_verbose(&format!(
        "[java hook] {} shared entry normalized: {:#x} -> interpreter bridge {:#x}",
        reason, current_entry_point, bridge.quick_to_interpreter_bridge
    ));
    true
}

fn mark_original_entry_mutated(art_method: u64) {
    with_registry_mut(&JAVA_HOOK_REGISTRY, |registry| {
        if let Some(hook_data) = registry.get_mut(&art_method) {
            if let HookType::Replaced {
                original_entry_mutated, ..
            } = &mut hook_data.hook_type
            {
                *original_entry_mutated = true;
            }
        }
    });
}

fn schedule_internal_shared_entry_refresh(art_method: u64, ep_offset: usize, bridge: &'static ArtBridgeFunctions) {
    let _ = crate::raw_thread::spawn_detached(b"rf-art-refresh\0", move || {
        for delay_ms in [120_i64, 400, 900] {
            crate::raw_thread::sleep_ms(delay_ms);
            let still_registered =
                with_registry(&JAVA_HOOK_REGISTRY, |registry| registry.contains_key(&art_method)).unwrap_or(false);
            if !still_registered {
                return;
            }
            let refreshed = unsafe {
                normalize_internal_shared_entry_if_needed(
                    art_method,
                    ep_offset,
                    std::ptr::null_mut(),
                    bridge,
                    "delayed-entry-refresh",
                )
            };
            if refreshed {
                mark_original_entry_mutated(art_method);
            }
        }
    });
}

unsafe fn free_callback_bytes(ctx: *mut ffi::JSContext, callback_bytes: [u8; 16]) {
    let callback: ffi::JSValue = std::ptr::read(callback_bytes.as_ptr() as *const ffi::JSValue);
    ffi::qjs_free_value(ctx, callback);
}

fn is_critical_native_signature_supported(is_static: bool, return_type_sig: &str, param_types: &[String]) -> bool {
    if !is_static {
        return false;
    }
    if matches!(return_type_sig.as_bytes().first(), Some(b'L' | b'[')) {
        return false;
    }
    param_types
        .iter()
        .all(|sig| !matches!(sig.as_bytes().first(), Some(b'L' | b'[')))
}

pub(in crate::jsapi::java) unsafe extern "C" fn js_java_hook(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    super::super::lazy_init_reflect_cache();
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

    let raw_clone = crate::is_raw_clone_js_thread();
    let env = if raw_clone {
        std::ptr::null_mut()
    } else {
        match ensure_jni_initialized() {
            Ok(e) => e,
            Err(msg) => return throw_internal_error(ctx, msg),
        }
    };

    let (art_method, is_static) = if raw_clone {
        match resolve_art_method(env, &class_name, &method_name, &actual_sig, force_static) {
            Ok(r) => r,
            Err(msg) => return throw_internal_error(ctx, msg),
        }
    } else {
        match resolve_art_method(env, &class_name, &method_name, &actual_sig, force_static) {
            Ok(r) => r,
            Err(msg) => return throw_internal_error(ctx, msg),
        }
    };

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

    let bridge = find_art_bridge_functions(env, ep_offset);
    let jni_trampoline = bridge.quick_generic_jni_trampoline;
    if jni_trampoline == 0 {
        return throw_internal_error(ctx, "failed to find art_quick_generic_jni_trampoline");
    }

    init_java_registry();
    if with_registry(&JAVA_HOOK_REGISTRY, |r| r.contains_key(&art_method)).unwrap_or(false) {
        let refreshed_entry = (original_access_flags & K_ACC_NATIVE) == 0
            && normalize_internal_shared_entry_if_needed(art_method, ep_offset, env, bridge, "existing-hook-refresh");
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
        if refreshed_entry {
            mark_original_entry_mutated(art_method);
        }
        if (original_access_flags & K_ACC_NATIVE) == 0 {
            schedule_internal_shared_entry_refresh(art_method, ep_offset, bridge);
        }

        output_verbose(&format!(
            "[java hook] 回调已替换: {}.{}{} entry_refreshed={}",
            class_name, method_name, actual_sig, refreshed_entry
        ));

        return JSValue::bool(true).raw();
    }

    let clone_size = spec.size;
    let clone_addr = match alloc_art_method_clone(art_method, clone_size) {
        Ok(addr) => addr,
        Err(msg) => return throw_internal_error(ctx, msg),
    };

    let class_global_ref = match create_class_global_ref(env, &class_name) {
        Ok(gref) => gref,
        Err(msg) => {
            return throw_internal_error(ctx, msg);
        }
    };
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
    let return_type_sig = get_return_type_sig(&actual_sig);
    let param_count = count_jni_params(&actual_sig);
    let param_types = parse_jni_param_types(&actual_sig);
    let has_critical_native_flag = (original_access_flags & K_ACC_CRITICAL_NATIVE) != 0;
    let critical_native_signature_supported =
        is_critical_native_signature_supported(is_static, &return_type_sig, &param_types);
    let is_critical_native = has_critical_native_flag && critical_native_signature_supported;
    if has_critical_native_flag && !critical_native_signature_supported {
        output_verbose(&format!(
            "[java hook] critical-native flag ignored as ART noise: flags={:#x}, sig={}",
            original_access_flags, actual_sig
        ));
    }
    let original_entry_is_code = is_code_pointer(original_entry_point);
    if !original_entry_is_code {
        return throw_internal_error(
            ctx,
            format!(
                "resolved ArtMethod entry_point is not executable for {}.{}{} (ArtMethod={:#x}, ep={:#x}, spec={:?})",
                class_name, method_name, actual_sig, art_method, original_entry_point, spec
            ),
        );
    }
    let has_independent_code = !is_art_quick_entrypoint(original_entry_point, bridge);
    let enable_fast_orig = false;
    let is_native_method = (original_access_flags & K_ACC_NATIVE) != 0;
    let is_shared_jni_entry = original_entry_point == bridge.quick_generic_jni_trampoline
        || (bridge.resolved_jni_entrypoint != 0 && original_entry_point == bridge.resolved_jni_entrypoint);
    let has_registered_native_entry =
        is_native_method && original_data != 0 && is_registered_native_entry_candidate(original_data, bridge);
    let shared_native_art_entry = is_native_method && !has_independent_code && !has_registered_native_entry;
    let native_entry_is_quick_entry = has_registered_native_entry && original_entry_point == original_data;
    let route_has_independent_code = (has_independent_code && !native_entry_is_quick_entry) || shared_native_art_entry;
    let mutate_original_method_flags = false;

    output_verbose(&format!(
        "[java hook] Step 4: has_independent_code={} route_independent={} native={} shared_jni={} shared_native_art_entry={} registered_native={} (data={:#x}, ep={:#x})",
        has_independent_code,
        route_has_independent_code,
        is_native_method,
        is_shared_jni_entry,
        shared_native_art_entry,
        has_registered_native_entry,
        original_data,
        original_entry_point
    ));

    if has_registered_native_entry {
        let callback_bytes = dup_callback_to_bytes(ctx, callback_arg.raw());
        with_registry_mut(&JAVA_HOOK_REGISTRY, |registry| {
            registry.insert(
                art_method,
                JavaHookData {
                    art_method,
                    original_access_flags,
                    original_entry_point,
                    original_data,
                    hook_type: HookType::NativeEntry,
                    clone_addr,
                    class_global_ref,
                    return_type,
                    return_type_sig: return_type_sig.clone(),
                    ctx: ctx as usize,
                    callback_bytes,
                    method_key: method_key(&class_name, &method_name, &actual_sig),
                    is_static,
                    param_count,
                    param_types: param_types.clone(),
                    class_name: class_name.clone(),
                    quick_trampoline: 0,
                    use_blr: false,
                    native_entry_hook_target: 0,
                    native_entry_trampoline: 0,
                    native_entry_critical: is_critical_native,
                },
            );
        });

        let native_callback: hook_ffi::HookCallback = if is_critical_native {
            Some(java_critical_native_hook_callback)
        } else {
            Some(java_hook_callback)
        };
        let install_native_entry = (|| -> Result<(u64, u64, u64), String> {
            let (hook_addr, sflag, real_addr) =
                super::super::art_controller::prepare_hook_target(original_data, std::ptr::null_mut())
                    .map_err(|e| format!("registered native entry prepare: {}", e))?;
            let trampoline = hook_ffi::hook_replace(
                hook_addr as *mut std::ffi::c_void,
                native_callback,
                art_method as *mut std::ffi::c_void,
                sflag,
            );
            if trampoline.is_null() {
                return Err(format!(
                    "registered native entry hook failed: target={:#x}, hook={:#x}",
                    original_data, hook_addr
                ));
            }
            super::super::art_controller::try_fixup_trampoline_pub(trampoline, real_addr);
            std::ptr::write_volatile((clone_addr as usize + data_off) as *mut u64, trampoline as u64);
            std::ptr::write_volatile((clone_addr as usize + ep_offset) as *mut u64, jni_trampoline);
            Ok((original_data, hook_addr, trampoline as u64))
        })();

        match install_native_entry {
            Ok((target, hook_target, trampoline)) => {
                with_registry_mut(&JAVA_HOOK_REGISTRY, |registry| {
                    if let Some(hook_data) = registry.get_mut(&art_method) {
                        hook_data.native_entry_hook_target = hook_target;
                        hook_data.native_entry_trampoline = trampoline;
                        hook_data.native_entry_critical = is_critical_native;
                    }
                });
                install_guard.set_native_entry_hook_target(hook_target);
                output_verbose(&format!(
                    "[java hook] registered native entry hooked without original ArtMethod mutation: target={:#x}, hook={:#x}, trampoline={:#x}, clone={:#x}, critical={}",
                    target, hook_target, trampoline, clone_addr, is_critical_native
                ));
                output_verbose(&format!(
                    "[java hook] 完成: {}.{}{} (ArtMethod={:#x}, strategy=native-entry-only)",
                    class_name, method_name, actual_sig, art_method
                ));
                install_guard.commit();
                return JSValue::bool(true).raw();
            }
            Err(msg) => {
                if let Some(removed) =
                    with_registry_mut(&JAVA_HOOK_REGISTRY, |registry| registry.remove(&art_method)).flatten()
                {
                    free_callback_bytes(ctx, removed.callback_bytes);
                } else {
                    free_callback_bytes(ctx, callback_bytes);
                }
                libc::free(clone_addr as *mut std::ffi::c_void);
                return throw_internal_error(ctx, &msg);
            }
        }
    }

    // Clone+Replace 模式:
    // 原始 ArtMethod 不改 flags，不设 kAccNative；避免安装 hook 时触发 deopt 可观测面。
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
                    per_method_hook_target: None,
                    original_flags_mutated: mutate_original_method_flags,
                    original_entry_mutated: false,
                },
                clone_addr,
                class_global_ref,
                return_type,
                return_type_sig: return_type_sig.clone(),
                ctx: ctx as usize,
                callback_bytes,
                method_key: method_key(&class_name, &method_name, &actual_sig),
                is_static,
                param_count,
                param_types: param_types.clone(),
                class_name: class_name.clone(),
                quick_trampoline: 0,
                use_blr: false,
                native_entry_hook_target: 0,
                native_entry_trampoline: 0,
                native_entry_critical: false,
            },
        );
    });

    // B2: Layer 3 per-method router hook (对标 Frida ArtQuickCodeInterceptor)。
    // 此时 replacement 尚未加入 art_router 表；若其他线程打到 quickCode，会继续走原始方法，
    // 避免热点方法在半安装窗口进入 JS callback。
    let (per_method_hook_target, quick_trampoline, use_blr, _router_thunk_body, mut original_entry_mutated) =
        match install_per_method_router_hook(
            route_has_independent_code,
            original_entry_point,
            &bridge,
            ep_offset,
            env,
            art_method,
            is_native_method,
            shared_native_art_entry,
            enable_fast_orig,
            true,
        ) {
            Ok(v) => v,
            Err(msg) => {
                if let Some(removed) =
                    with_registry_mut(&JAVA_HOOK_REGISTRY, |registry| registry.remove(&art_method)).flatten()
                {
                    free_callback_bytes(ctx, removed.callback_bytes);
                }
                return throw_internal_error(ctx, msg);
            }
        };
    if original_entry_mutated {
        install_guard.set_original_entry_mutated();
    }

    with_registry_mut(&JAVA_HOOK_REGISTRY, |registry| {
        if let Some(hook_data) = registry.get_mut(&art_method) {
            hook_data.hook_type = HookType::Replaced {
                replacement_addr,
                per_method_hook_target,
                original_flags_mutated: mutate_original_method_flags,
                original_entry_mutated,
            };
            hook_data.quick_trampoline = quick_trampoline;
            hook_data.use_blr = use_blr;
        }
    });

    // B3: 注册 replacement 到 replacedMethods 映射 (art_router 查表用)
    set_replacement_method(art_method, replacement_addr as u64);
    install_guard.set_replacement_registered();

    output_verbose(&format!(
        "[java hook] no-deopt: original ArtMethod flags unchanged ({:#x})",
        original_access_flags
    ));

    if !is_native_method
        && normalize_internal_shared_entry_if_needed(art_method, ep_offset, env, bridge, "post-install")
    {
        original_entry_mutated = true;
        install_guard.set_original_entry_mutated();
    }

    if original_entry_mutated {
        mark_original_entry_mutated(art_method);
    }
    if !is_native_method {
        schedule_internal_shared_entry_refresh(art_method, ep_offset, bridge);
    }

    let jni_trampoline_router_ready = super::super::art_controller::jni_trampoline_router_installed();
    if (original_access_flags & K_ACC_NATIVE) != 0 {
        output_verbose(&format!(
            "[java hook] registered native entry skipped: data_={:#x}, candidate=false, jni_router={}",
            original_data, jni_trampoline_router_ready
        ));
    }

    output_verbose(&format!(
        "[java hook] post-install field cache deferred for {}",
        class_name
    ));

    let strategy = if is_native_method && shared_native_art_entry && !has_registered_native_entry {
        "native-shared-jni-router"
    } else if has_independent_code {
        if route_has_independent_code {
            "compiled+router"
        } else {
            "registered-native-entry"
        }
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

pub(in crate::jsapi::java) unsafe extern "C" fn js_java_hook_quick(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    super::super::lazy_init_reflect_cache();
    if argc < 4 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Java.hookQuick() requires 4 arguments: class, method, signature, callback\0".as_ptr() as *const _,
        );
    }

    let class_arg = JSValue(*argv);
    let method_arg = JSValue(*argv.add(1));
    let sig_arg = JSValue(*argv.add(2));
    let callback_arg = JSValue(*argv.add(3));

    let class_name = match extract_string_arg(
        ctx,
        class_arg,
        b"Java.hookQuick() first argument must be a class name string\0",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let method_name = match extract_string_arg(
        ctx,
        method_arg,
        b"Java.hookQuick() second argument must be a method name string\0",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let sig_str = match extract_string_arg(
        ctx,
        sig_arg,
        b"Java.hookQuick() third argument must be a signature string\0",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };
    if let Err(err) = ensure_function_arg(
        ctx,
        callback_arg,
        b"Java.hookQuick() fourth argument must be a function\0",
    ) {
        return err;
    }

    let (actual_sig, force_static) = if let Some(stripped) = sig_str.strip_prefix("static:") {
        (stripped.to_string(), true)
    } else {
        (sig_str.clone(), false)
    };

    let raw_clone = crate::is_raw_clone_js_thread();
    let env = if raw_clone {
        std::ptr::null_mut()
    } else {
        match ensure_jni_initialized() {
            Ok(e) => e,
            Err(msg) => return throw_internal_error(ctx, msg),
        }
    };

    let (art_method, is_static) = if raw_clone {
        match resolve_method_via_executor(
            class_name.clone(),
            method_name.clone(),
            actual_sig.clone(),
            force_static,
        ) {
            Ok(r) => r,
            Err(msg) => return throw_internal_error(ctx, msg),
        }
    } else {
        match resolve_art_method(env, &class_name, &method_name, &actual_sig, force_static) {
            Ok(r) => r,
            Err(msg) => return throw_internal_error(ctx, msg),
        }
    };

    init_java_registry();
    if with_registry(&JAVA_HOOK_REGISTRY, |r| r.contains_key(&art_method)).unwrap_or(false) {
        let new_callback_bytes = dup_callback_to_bytes(ctx, callback_arg.raw());
        let old_callback_bytes = with_registry_mut(&JAVA_HOOK_REGISTRY, |registry| {
            registry.get_mut(&art_method).map(|hook_data| {
                let old_bytes = hook_data.callback_bytes;
                hook_data.callback_bytes = new_callback_bytes;
                hook_data.ctx = ctx as usize;
                old_bytes
            })
        })
        .flatten();
        if let Some(old_bytes) = old_callback_bytes {
            let old_callback: ffi::JSValue = std::ptr::read(old_bytes.as_ptr() as *const ffi::JSValue);
            ffi::qjs_free_value(ctx, old_callback);
        }
        return JSValue::bool(true).raw();
    }

    let spec = get_art_method_spec(env, art_method);
    let ep_offset = spec.entry_point_offset;
    let data_off = spec.data_offset;
    let original_access_flags = std::ptr::read_volatile((art_method as usize + spec.access_flags_offset) as *const u32);
    let original_data = std::ptr::read_volatile((art_method as usize + data_off) as *const u64);
    let original_entry_point = read_entry_point(art_method, ep_offset);
    let clone_addr = match alloc_art_method_clone(art_method, spec.size) {
        Ok(addr) => addr,
        Err(msg) => return throw_internal_error(ctx, msg),
    };

    let bridge = find_art_bridge_functions(env, ep_offset);
    let jni_trampoline = bridge.quick_generic_jni_trampoline;
    if jni_trampoline == 0 {
        return throw_internal_error(ctx, "failed to find art_quick_generic_jni_trampoline");
    }

    let original_entry_is_code = is_code_pointer(original_entry_point);
    if !original_entry_is_code {
        return throw_internal_error(
            ctx,
            format!(
                "resolved ArtMethod entry_point is not executable for Java.hookQuick {}.{}{} (ArtMethod={:#x}, ep={:#x}, spec={:?})",
                class_name, method_name, actual_sig, art_method, original_entry_point, spec
            ),
        );
    }
    let has_independent_code = !is_art_quick_entrypoint(original_entry_point, bridge);
    if !has_independent_code {
        return throw_internal_error(
            ctx,
            format!(
                "Java.hookQuick requires compiled independent quick code for {}.{}{} (ep={:#x})",
                class_name, method_name, actual_sig, original_entry_point
            ),
        );
    }

    let class_global_ref = match create_class_global_ref(env, &class_name) {
        Ok(gref) => gref,
        Err(msg) => return throw_internal_error(ctx, msg),
    };
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

    let replacement_addr = match create_replacement_art_method(
        art_method,
        spec.size,
        spec,
        original_access_flags,
        data_off,
        ep_offset,
        std::ptr::null_mut(),
        jni_trampoline,
    ) {
        Ok(addr) => addr,
        Err(msg) => return throw_internal_error(ctx, msg),
    };
    install_guard.set_replacement_addr(replacement_addr);

    let is_constructor = method_name == "<init>";
    let (per_method_hook_target, quick_trampoline, use_blr, _router_thunk_body, _original_entry_mutated) =
        match install_per_method_router_hook(
            true,
            original_entry_point,
            &bridge,
            ep_offset,
            env,
            art_method,
            (original_access_flags & K_ACC_NATIVE) != 0,
            is_constructor,
            false,
            false,
        ) {
            Ok(v) => v,
            Err(msg) => return throw_internal_error(ctx, msg),
        };

    set_quick_callback_method(art_method, replacement_addr as u64, Some(java_hook_dispatch_from_quick));
    install_guard.set_replacement_registered();

    let callback_bytes = dup_callback_to_bytes(ctx, callback_arg.raw());
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
                    declaring_class_source: art_method,
                },
                clone_addr,
                class_global_ref,
                return_type: get_return_type_from_sig(&actual_sig),
                return_type_sig: get_return_type_sig(&actual_sig),
                ctx: ctx as usize,
                callback_bytes,
                method_key: method_key(&class_name, &method_name, &actual_sig),
                is_static,
                param_count: count_jni_params(&actual_sig),
                param_types: parse_jni_param_types(&actual_sig),
                class_name: class_name.clone(),
                quick_trampoline,
                use_blr,
                native_entry_hook_target: 0,
                native_entry_trampoline: 0,
                native_entry_critical: false,
            },
        );
    });

    output_verbose(&format!(
        "[java hookQuick] 完成: {}.{}{} (ArtMethod={:#x}, trampoline={:#x})",
        class_name, method_name, actual_sig, art_method, quick_trampoline
    ));

    install_guard.commit();
    JSValue::bool(true).raw()
}
