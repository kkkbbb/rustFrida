// ============================================================================
// ART entrypoint classification helpers
// ============================================================================

/// Check if an address is an ART shared entrypoint (stub/bridge/nterp)
/// or resides inside libart.so.
///
/// Returns true if the address is:
/// - 0 (null)
/// - One of the known shared stubs (jni_trampoline, interpreter_bridge, resolution, nterp)
/// - Inside libart.so (e.g. other ART internal trampolines)
///
/// Compiled methods (AOT/JIT) that have independent code OUTSIDE libart.so return false.
pub(super) fn is_art_quick_entrypoint(addr: u64, bridge: &ArtBridgeFunctions) -> bool {
    if addr == 0 {
        return true;
    }
    // ClassLinker trampoline 地址比较（对标 Frida isArtQuickEntrypoint）
    if addr == bridge.quick_generic_jni_trampoline
        || addr == bridge.quick_to_interpreter_bridge
        || addr == bridge.quick_resolution_trampoline
        || addr == bridge.quick_imt_conflict_trampoline
        || addr == bridge.nterp_entry_point
        || addr == bridge.nterp_with_clinit_entry_point
    {
        return true;
    }
    // Thread TLS 中的真实 entrypoint 比较（trampoline 解析结果，0 表示无效跳过）
    if (bridge.resolved_jni_entrypoint != 0 && addr == bridge.resolved_jni_entrypoint)
        || (bridge.resolved_interpreter_bridge_entrypoint != 0
            && addr == bridge.resolved_interpreter_bridge_entrypoint)
        || (bridge.resolved_resolution_entrypoint != 0
            && addr == bridge.resolved_resolution_entrypoint)
    {
        return true;
    }
    // dladdr check: is this address in libart.so?
    is_in_libart(addr)
}

// ============================================================================
// ArtMethod resolution
// ============================================================================

/// Resolve a Java method to its ArtMethod* address.
/// Returns (art_method_ptr, is_static).
/// When `force_static` is true, skips GetMethodID and goes straight to GetStaticMethodID.
pub(crate) fn resolve_art_method(
    env: JniEnv,
    class_name: &str,
    method_name: &str,
    signature: &str,
    force_static: bool,
) -> Result<(u64, bool), String> {
    unsafe {
        if !env.is_null() && !crate::is_raw_clone_js_thread() && is_reflect_ids_ready() {
            let _ = get_art_method_spec(env, 0);
        }

        // For normal Java-worker calls, prefer ART's own class-loader aware
        // MethodID resolution. The raw dex resolver is still kept for raw-clone
        // contexts where JNI fallback is not safe.
        if !env.is_null() && !crate::is_raw_clone_js_thread() {
            match resolve_art_method_by_jni(env, class_name, method_name, signature, force_static) {
                Ok(resolved) => return Ok(resolved),
                Err(msg) => output_verbose(&format!(
                    "[resolve_art_method] JNI first pass failed for {}.{}{}: {}; trying dex resolver",
                    class_name, method_name, signature, msg
                )),
            }
        }

        if let Some(resolved) = resolve_art_method_by_dex(env, class_name, method_name, signature, force_static) {
            return Ok(resolved);
        }
        if crate::is_raw_clone_js_thread() && !raw_clone_executor_jni_scope_active() {
            let detail = last_dex_resolver_failure()
                .map(|reason| format!("; last resolver failure: {}", reason))
                .unwrap_or_default();
            return Err(format!(
                "dex self-resolver failed on raw clone thread; refusing JNI GetMethodID fallback for {}.{}{}{}",
                class_name, method_name, signature, detail
            ));
        }
        output_verbose(&format!(
            "[dex resolver] fallback to JNI GetMethodID for {}.{}{}",
            class_name, method_name, signature
        ));
    }

    unsafe { resolve_art_method_by_jni(env, class_name, method_name, signature, force_static) }
}

unsafe fn resolve_art_method_by_jni(
    env: JniEnv,
    class_name: &str,
    method_name: &str,
    signature: &str,
    force_static: bool,
) -> Result<(u64, bool), String> {
    let c_method = CString::new(method_name).map_err(|_| "invalid method name")?;
    let c_sig = CString::new(signature).map_err(|_| "invalid signature")?;

    let cls = find_class_safe(env, class_name);

    if cls.is_null() {
        // Defensive: ensure no pending exception leaks to caller
        jni_check_exc(env);
        return Err(format!("FindClass('{}') failed", class_name));
    }

    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);

    // Try GetMethodID (instance method first), unless force_static
    if !force_static {
        let get_method_id: GetMethodIdFn = jni_fn!(env, GetMethodIdFn, JNI_GET_METHOD_ID);

        let method_id = get_method_id(env, cls, c_method.as_ptr(), c_sig.as_ptr());
        output_verbose(&format!(
            "[resolve_art_method] cls={:#x}, GetMethodID({}.{}{})={:#x}",
            cls as u64, class_name, method_name, signature, method_id as u64
        ));

        if !jni_null_or_exc(env, method_id) {
            // Decode BEFORE deleting cls (ToReflectedMethod needs cls)
            let art_method = decode_method_id(env, cls, method_id as u64, false);
            delete_local_ref(env, cls);
            return Ok((art_method, false));
        }
    }

    // Try GetStaticMethodID
    let get_static_method_id: GetStaticMethodIdFn = jni_fn!(env, GetStaticMethodIdFn, JNI_GET_STATIC_METHOD_ID);

    let method_id = get_static_method_id(env, cls, c_method.as_ptr(), c_sig.as_ptr());

    if !jni_null_or_exc(env, method_id) {
        // Decode BEFORE deleting cls (ToReflectedMethod needs cls)
        let art_method = decode_method_id(env, cls, method_id as u64, true);
        delete_local_ref(env, cls);
        return Ok((art_method, true));
    }

    // Cleanup
    delete_local_ref(env, cls);

    Err(format!("method not found: {}.{}{}", class_name, method_name, signature))
}

/// Read the entry_point_from_quick_compiled_code_ from ArtMethod
pub(super) unsafe fn read_entry_point(art_method: u64, offset: usize) -> u64 {
    let ptr = (art_method as usize + offset) as *const u64;
    std::ptr::read_volatile(ptr)
}
