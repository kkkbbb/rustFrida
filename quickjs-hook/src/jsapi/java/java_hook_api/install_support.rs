use crate::ffi::hook as hook_ffi;
use crate::jsapi::console::{output_message, output_verbose};
use crate::jsapi::hook_api::StealthMode;

use super::super::art_controller::{ensure_shared_entry_router_hook, prepare_hook_target, stealth_mode};
use super::super::art_method::*;
use super::super::callback::delete_replacement_method;
use super::super::jni_core::*;
use super::super::reflect::find_class_safe;

pub(super) unsafe fn delete_global_ref_best_effort(class_global_ref: usize) {
    if class_global_ref == 0 {
        return;
    }
    if crate::is_raw_clone_js_thread() && !raw_clone_executor_jni_scope_active() {
        output_verbose("[java hook] raw clone: skip DeleteGlobalRef cleanup");
        return;
    }
    if let Ok(env) = get_thread_env() {
        let delete_global_ref: DeleteGlobalRefFn = jni_fn!(env, DeleteGlobalRefFn, JNI_DELETE_GLOBAL_REF);
        delete_global_ref(env, class_global_ref as *mut std::ffi::c_void);
    }
}

pub(super) struct JavaHookInstallGuard {
    art_method: u64,
    access_flags_offset: usize,
    data_offset: usize,
    entry_point_offset: usize,
    original_access_flags: u32,
    original_data: u64,
    original_entry_point: u64,
    replacement_addr: usize,
    class_global_ref: usize,
    redirect_installed: bool,
    replacement_registered: bool,
    original_method_mutated: bool,
    original_entry_mutated: bool,
    native_entry_hook_target: u64,
    committed: bool,
}

impl JavaHookInstallGuard {
    pub(super) fn new(
        art_method: u64,
        access_flags_offset: usize,
        data_offset: usize,
        entry_point_offset: usize,
        original_access_flags: u32,
        original_data: u64,
        original_entry_point: u64,
        class_global_ref: usize,
    ) -> Self {
        Self {
            art_method,
            access_flags_offset,
            data_offset,
            entry_point_offset,
            original_access_flags,
            original_data,
            original_entry_point,
            replacement_addr: 0,
            class_global_ref,
            redirect_installed: false,
            replacement_registered: false,
            original_method_mutated: false,
            original_entry_mutated: false,
            native_entry_hook_target: 0,
            committed: false,
        }
    }

    pub(super) fn set_redirect_installed(&mut self) {
        self.redirect_installed = true;
    }

    pub(super) fn set_replacement_addr(&mut self, replacement_addr: usize) {
        self.replacement_addr = replacement_addr;
    }

    pub(super) fn set_replacement_registered(&mut self) {
        self.replacement_registered = true;
    }

    pub(super) fn set_original_method_mutated(&mut self) {
        self.original_method_mutated = true;
    }

    pub(super) fn set_original_entry_mutated(&mut self) {
        self.original_entry_mutated = true;
    }

    pub(super) fn set_native_entry_hook_target(&mut self, target: u64) {
        self.native_entry_hook_target = target;
    }

    pub(super) fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for JavaHookInstallGuard {
    fn drop(&mut self) {
        if self.committed {
            return;
        }

        unsafe {
            if self.replacement_registered {
                delete_replacement_method(self.art_method);
            }

            if self.original_method_mutated {
                std::ptr::write_volatile(
                    (self.art_method as usize + self.access_flags_offset) as *mut u32,
                    self.original_access_flags,
                );
                hook_ffi::hook_flush_cache(
                    (self.art_method as usize + self.access_flags_offset) as *mut std::ffi::c_void,
                    4,
                );
            }

            if self.original_entry_mutated {
                std::ptr::write_volatile(
                    (self.art_method as usize + self.entry_point_offset) as *mut u64,
                    self.original_entry_point,
                );
                hook_ffi::hook_flush_cache(
                    (self.art_method as usize + self.entry_point_offset) as *mut std::ffi::c_void,
                    8,
                );
            }

            if self.redirect_installed {
                hook_ffi::hook_remove_redirect(self.art_method);
            }

            if self.native_entry_hook_target != 0 {
                crate::recomp::try_revert_slot_patch_by_slot(self.native_entry_hook_target as usize);
                hook_ffi::hook_remove(self.native_entry_hook_target as *mut std::ffi::c_void);
            }

            if self.replacement_addr != 0 {
                libc::free(self.replacement_addr as *mut std::ffi::c_void);
            }

            delete_global_ref_best_effort(self.class_global_ref);
        }
    }
}

#[allow(dead_code)]
pub(super) unsafe fn alloc_art_method_clone(art_method: u64, clone_size: usize) -> Result<u64, String> {
    let ptr = libc::malloc(clone_size);
    if ptr.is_null() {
        return Err("malloc failed for ArtMethod backup clone".to_string());
    }
    std::ptr::copy_nonoverlapping(art_method as *const u8, ptr as *mut u8, clone_size);
    Ok(ptr as u64)
}

pub(super) unsafe fn create_class_global_ref(env: JniEnv, class_name: &str) -> Result<usize, String> {
    if crate::is_raw_clone_js_thread() && !raw_clone_executor_jni_scope_active() {
        output_verbose(&format!(
            "[java hook] raw clone: skip class global ref for {}",
            class_name
        ));
        return Ok(0);
    }

    let cls = find_class_safe(env, class_name);
    if cls.is_null() {
        return Err(format!("FindClass('{}') failed for global ref", class_name));
    }
    let new_global_ref: NewGlobalRefFn = jni_fn!(env, NewGlobalRefFn, JNI_NEW_GLOBAL_REF);
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
    let gref = new_global_ref(env, cls);
    delete_local_ref(env, cls);
    Ok(gref as usize)
}

pub(super) unsafe fn create_replacement_art_method(
    art_method: u64,
    clone_size: usize,
    spec: &ArtMethodSpec,
    original_access_flags: u32,
    data_off: usize,
    ep_offset: usize,
    thunk: *mut std::ffi::c_void,
    jni_trampoline: u64,
) -> Result<usize, String> {
    let ptr = libc::malloc(clone_size);
    if ptr.is_null() {
        return Err("malloc failed for replacement ArtMethod".to_string());
    }
    std::ptr::copy_nonoverlapping(art_method as *const u8, ptr as *mut u8, clone_size);

    let repl = ptr as usize;
    let repl_flags = (original_access_flags
        & !(K_ACC_CRITICAL_NATIVE | K_ACC_FAST_NATIVE | K_ACC_NTERP_ENTRY_POINT_FAST_PATH))
        | K_ACC_NATIVE
        | k_acc_compile_dont_bother();
    std::ptr::write_volatile((repl + spec.access_flags_offset) as *mut u32, repl_flags);
    std::ptr::write_volatile((repl + data_off) as *mut u64, thunk as u64);
    std::ptr::write_volatile((repl + ep_offset) as *mut u64, jni_trampoline);
    hook_ffi::hook_flush_cache(ptr, clone_size);

    output_verbose(&format!(
        "[java hook] Step 4 replacement: addr={:#x}, flags={:#x}, data_={:#x}, ep={:#x}",
        repl, repl_flags, thunk as u64, jni_trampoline
    ));

    Ok(repl)
}

pub(super) unsafe fn create_quick_stack_sentinel_art_method(
    source_art_method: u64,
    clone_size: usize,
    spec: &ArtMethodSpec,
    data_off: usize,
    ep_offset: usize,
    stack_entry_point: u64,
) -> Result<(usize, u64), String> {
    const K_ACC_STATIC: u32 = 0x0008;

    if (source_art_method & 0x3) != 0 {
        return Err(format!(
            "quick stack sentinel source ArtMethod is tagged/opaque: {:#x}",
            source_art_method
        ));
    }
    let ptr = libc::malloc(clone_size);
    if ptr.is_null() {
        return Err("malloc failed for quick stack sentinel ArtMethod".to_string());
    }
    std::ptr::copy_nonoverlapping(source_art_method as *const u8, ptr as *mut u8, clone_size);

    let repl = ptr as usize;
    let src_declaring_class = std::ptr::read_volatile(source_art_method as *const u32);
    let src_dex_method_index = std::ptr::read_volatile((source_art_method as usize + 12) as *const u32);
    let src_flags = std::ptr::read_volatile((source_art_method as usize + spec.access_flags_offset) as *const u32);
    if src_declaring_class == 0 || src_declaring_class == 1 {
        libc::free(ptr);
        return Err(format!(
            "invalid quick stack sentinel declaring_class={:#x}, src={:#x}",
            src_declaring_class, source_art_method
        ));
    }
    let repl_flags = (src_flags & !(K_ACC_CRITICAL_NATIVE | K_ACC_FAST_NATIVE | K_ACC_NTERP_ENTRY_POINT_FAST_PATH))
        | K_ACC_NATIVE
        | K_ACC_STATIC
        | k_acc_compile_dont_bother();
    std::ptr::write_volatile((repl + spec.access_flags_offset) as *mut u32, repl_flags);
    std::ptr::write_volatile((repl + data_off) as *mut u64, 0);
    std::ptr::write_volatile((repl + ep_offset) as *mut u64, stack_entry_point);
    hook_ffi::hook_flush_cache(ptr, clone_size);

    let repl_declaring_class = std::ptr::read_volatile(repl as *const u32);
    let repl_dex_method_index = std::ptr::read_volatile((repl + 12) as *const u32);
    let repl_data = std::ptr::read_volatile((repl + data_off) as *const u64);
    let repl_ep = std::ptr::read_volatile((repl + ep_offset) as *const u64);
    output_message(&format!(
        "[java hook] quick stack sentinel: src={:#x}, addr={:#x}, decl={:#x}->{:#x}, dex_idx={:#x}->{:#x}, flags={:#x}->{:#x}, data_off={}, ep_off={}, data={:#x}, ep={:#x}",
        source_art_method, repl,
        src_declaring_class, repl_declaring_class,
        src_dex_method_index, repl_dex_method_index,
        src_flags, repl_flags,
        data_off, ep_offset, repl_data, repl_ep
    ));

    Ok((repl, source_art_method))
}

pub(super) unsafe fn update_original_method_flags_for_hook(
    art_method: u64,
    access_flags_offset: usize,
    original_access_flags: u32,
) {
    let mut removed_flags =
        K_ACC_FAST_INTERP_TO_INTERP | K_ACC_SINGLE_IMPLEMENTATION | K_ACC_NTERP_ENTRY_POINT_FAST_PATH;
    if (original_access_flags & K_ACC_NATIVE) == 0 {
        removed_flags |= K_ACC_SKIP_ACCESS_CHECKS;
    }
    let new_flags = (original_access_flags & !removed_flags) | k_acc_compile_dont_bother();
    std::ptr::write_volatile((art_method as usize + access_flags_offset) as *mut u32, new_flags);
    output_verbose(&format!(
        "[java hook] Step 5 original flags: {:#x} → {:#x}",
        original_access_flags, new_flags
    ));
}

/// 返回 (per_method_hook_target, quick_trampoline, use_blr)
/// quick_trampoline: Layer 3 的 art_router trampoline 地址（用于 callback skip fallback）
/// use_blr: true = thunk 用 BLR，$orig 可走 fast path（不调 JNI）
pub(super) unsafe fn install_per_method_router_hook(
    has_independent_code: bool,
    original_entry_point: u64,
    bridge: &ArtBridgeFunctions,
    ep_offset: usize,
    env: JniEnv,
    art_method: u64,
    is_native_method: bool,
    shared_native_art_entry: bool,
    enable_fast_orig: bool,
    allow_internal_entry_downgrade: bool,
) -> Result<(Option<u64>, u64, bool, Option<u64>, bool), String> {
    if has_independent_code {
        // Layer 3: inline hook quickCode 作为快速路径 (直接调用场景)
        // Do not modify target ArtMethod.entry_point_ for compiled app/framework
        // methods. Even ART-internal bridge downgrades are observable by some
        // shells. The quick router patches only the actual quick entry code.
        let use_fast_orig = enable_fast_orig && !is_native_method;
        let mut hooked_target: *mut std::ffi::c_void = std::ptr::null_mut();
        let (hook_addr, sflag, real_addr) =
            prepare_hook_target(original_entry_point as u64, env as *mut std::ffi::c_void)
                .map_err(|e| format!("prepare_hook_target: {}", e))?;
        // current_pc_hint = 0: 不需要 LR/x20 swap，让 JNI 正常走 epilogue
        let trampoline = hook_ffi::hook_install_art_router(
            hook_addr as *mut std::ffi::c_void,
            ep_offset as u32,
            sflag,
            env as *mut std::ffi::c_void,
            &mut hooked_target,
            1, // skip_resolve
            0, // no hint — replacement is kAccNative, ART handles it
            if use_fast_orig { 1 } else { 0 },
            0,
        );

        if trampoline.is_null() {
            return Err("hook_install_art_router failed".to_string());
        }

        // stealth2: 修复 trampoline（hook engine 从 slot 读到的是清零字节）
        super::super::art_controller::try_fixup_trampoline_pub(trampoline, real_addr);

        // 2-ArtMethod 模型: 不再设置 clone entry_point，callOriginal 直接用原始 ArtMethod

        let actual_hook_target = if !hooked_target.is_null() {
            hooked_target as u64
        } else {
            hook_addr
        };
        let router_thunk_body =
            hook_ffi::hook_art_router_get_thunk_body(actual_hook_target as *mut std::ffi::c_void) as u64;
        let router_thunk_body = (router_thunk_body != 0).then_some(router_thunk_body);

        // 诊断: 验证 inline hook 的 patch 是否真正写入
        let current_ep = std::ptr::read_volatile((art_method as usize + ep_offset) as *const u64);
        let hooked_bytes: [u8; 4] = std::ptr::read(actual_hook_target as *const [u8; 4]);
        output_verbose(&format!(
            "[java hook] Step 9: Layer 3 installed: ep={:#x} (hooked={:#x}), trampoline={:#x}, current_ep={:#x}, first_bytes={:02x}{:02x}{:02x}{:02x}",
            original_entry_point, actual_hook_target, trampoline as u64,
            current_ep,
            hooked_bytes[0], hooked_bytes[1], hooked_bytes[2], hooked_bytes[3]
        ));

        Ok((
            Some(actual_hook_target),
            trampoline as u64,
            use_fast_orig,
            router_thunk_body,
            false,
        ))
    } else {
        // 非 compiled 方法: entry_point 是共享 stub (nterp/interpreter_bridge/resolution)
        // 或 libart 内未归类的解释器入口。不能把 ArtMethod.entry_point_ 改到外部
        // thunk；这里只补全 libart/shared entry 自身的全局 router。
        // Only exact bridge/trampoline entries are considered router-safe for
        // default Java callbacks. Managed DSL passes allow_internal_entry_downgrade=false
        // because it is the high-frequency path: preserve exact nterp shared
        // entries in stealth modes and route them directly instead of degrading
        // the target ArtMethod to quick_to_interpreter_bridge.
        let preserve_exact_nterp = !allow_internal_entry_downgrade
            && stealth_mode() != StealthMode::Normal
            && ((bridge.nterp_entry_point != 0 && original_entry_point == bridge.nterp_entry_point)
                || (bridge.nterp_with_clinit_entry_point != 0
                    && original_entry_point == bridge.nterp_with_clinit_entry_point));
        let is_already_routed = original_entry_point == bridge.quick_to_interpreter_bridge
            || original_entry_point == bridge.quick_resolution_trampoline
            || preserve_exact_nterp;

        if shared_native_art_entry || !is_already_routed {
            if is_native_method {
                output_verbose(&format!(
                    "[java hook] Step 9: native/shared ART entry kept: ep={:#x}; external ArtMethod entry stub disabled",
                    original_entry_point
                ));
                return Ok((None, 0, false, None, false));
            }
            let mut original_entry_mutated = false;
            let shared_router_entry;
            if allow_internal_entry_downgrade && !is_already_routed && bridge.quick_to_interpreter_bridge != 0 {
                std::ptr::write_volatile(
                    (art_method as usize + ep_offset) as *mut u64,
                    bridge.quick_to_interpreter_bridge,
                );
                hook_ffi::hook_flush_cache((art_method as usize + ep_offset) as *mut std::ffi::c_void, 8);
                original_entry_mutated = true;
                output_verbose(&format!(
                    "[java hook] Step 9: libart shared entry {:#x} downgraded to interpreter bridge {:#x} (internal entry only)",
                    original_entry_point, bridge.quick_to_interpreter_bridge
                ));
                shared_router_entry = bridge.quick_to_interpreter_bridge;
            } else if is_already_routed {
                shared_router_entry = original_entry_point;
            } else {
                output_verbose(&format!(
                    "[java hook] Step 9: non-routed shared ART entry kept without dynamic external entry hook: ep={:#x}",
                    original_entry_point
                ));
                return Ok((None, 0, false, None, false));
            }
            ensure_shared_entry_router_hook(
                "method-shared-entry",
                shared_router_entry,
                ep_offset,
                env,
                preserve_exact_nterp,
            )?;
            output_verbose(&format!(
                "[java hook] Step 9: dynamic shared ART router active: ep={:#x}; target ArtMethod entry_external=false",
                shared_router_entry
            ));
            return Ok((None, 0, false, None, original_entry_mutated));
        }

        if preserve_exact_nterp {
            output_verbose(&format!(
                "[java hook] Step 9: exact nterp shared entry preserved for high-frequency DSL routing: ep={:#x}",
                original_entry_point
            ));
        } else {
            output_verbose(&format!(
                "[java hook] Step 9: 共享 stub, 依赖 Layer 1+2 路由: ep={:#x}",
                original_entry_point
            ));
        }
        Ok((None, 0, false, None, false))
    }
}
