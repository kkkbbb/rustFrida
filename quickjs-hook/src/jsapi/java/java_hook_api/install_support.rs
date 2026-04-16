use crate::ffi::hook as hook_ffi;
use crate::jsapi::console::output_verbose;

use super::super::art_controller::prepare_hook_target;
use super::super::art_method::*;
use super::super::callback::delete_replacement_method;
use super::super::jni_core::*;
use super::super::reflect::find_class_safe;

pub(super) unsafe fn delete_global_ref_best_effort(class_global_ref: usize) {
    if class_global_ref == 0 {
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
                std::ptr::write_volatile(
                    (self.art_method as usize + self.data_offset) as *mut u64,
                    self.original_data,
                );
                std::ptr::write_volatile(
                    (self.art_method as usize + self.entry_point_offset) as *mut u64,
                    self.original_entry_point,
                );
                hook_ffi::hook_flush_cache(self.art_method as *mut std::ffi::c_void, self.entry_point_offset + 8);
            }

            if self.redirect_installed {
                hook_ffi::hook_remove_redirect(self.art_method);
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

/// 返回 (per_method_hook_target, quick_trampoline)
/// quick_trampoline: Layer 3 的 art_router trampoline 地址（用于 callback skip fallback）
pub(super) unsafe fn install_per_method_router_hook(
    has_independent_code: bool,
    original_entry_point: u64,
    bridge: &ArtBridgeFunctions,
    ep_offset: usize,
    env: JniEnv,
    art_method: u64,
    _force_interpreter_route: bool,
) -> Result<(Option<u64>, u64), String> {
    if has_independent_code {
        // Layer 3: inline hook quickCode 作为快速路径 (直接调用场景)
        let mut hooked_target: *mut std::ffi::c_void = std::ptr::null_mut();
        let (hook_addr, sflag) = prepare_hook_target(original_entry_point as u64, env as *mut std::ffi::c_void)
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
        );

        if trampoline.is_null() {
            return Err("hook_install_art_router failed".to_string());
        }

        // stealth2: 修复 trampoline（hook engine 从 slot 读到的是清零字节）
        super::super::art_controller::try_fixup_trampoline_pub(trampoline, original_entry_point);

        // 2-ArtMethod 模型: 不再设置 clone entry_point，callOriginal 直接用原始 ArtMethod

        let actual_hook_target = if !hooked_target.is_null() {
            hooked_target as u64
        } else {
            original_entry_point
        };

        // 诊断: 验证 inline hook 的 patch 是否真正写入
        let current_ep = std::ptr::read_volatile((art_method as usize + ep_offset) as *const u64);
        let hooked_bytes: [u8; 4] = std::ptr::read(actual_hook_target as *const [u8; 4]);
        output_verbose(&format!(
            "[java hook] Step 9: Layer 3 installed: ep={:#x} (hooked={:#x}), trampoline={:#x}, current_ep={:#x}, first_bytes={:02x}{:02x}{:02x}{:02x}",
            original_entry_point, actual_hook_target, trampoline as u64,
            current_ep,
            hooked_bytes[0], hooked_bytes[1], hooked_bytes[2], hooked_bytes[3]
        ));

        Ok((Some(actual_hook_target), trampoline as u64))
    } else {
        // 非 compiled 方法: entry_point 是共享 stub (nterp/interpreter_bridge/resolution)
        // 如果 entry_point 不是 Layer 1 已 hook 的 interpreter_bridge/resolution_trampoline,
        // 则降级为 interpreter_bridge (确保走 Layer 1 拦截).
        // 对标 Frida: nterp → quick_to_interpreter_bridge 降级.
        let interp_bridge = bridge.quick_to_interpreter_bridge;
        let resolved_interp = bridge.resolved_interpreter_bridge_entrypoint;
        let resolved_res = bridge.resolved_resolution_entrypoint;

        let is_already_routed = original_entry_point == bridge.quick_to_interpreter_bridge
            || original_entry_point == bridge.quick_resolution_trampoline
            || (resolved_interp != 0 && original_entry_point == resolved_interp)
            || (resolved_res != 0 && original_entry_point == resolved_res);

        if !is_already_routed && interp_bridge != 0 {
            // DeoptimizeBootImage + forced_interpret_only 已确保方法走 interpreter → DoCall (Layer 2)
            // 不需要强制改 ep 为 interpreter_bridge — 保留 ART 设置的 ep（可能是 nterp 或
            // deopt bridge），让 Layer 2 DoCall 拦截。强制改 ep 在 spawn 模式下可能导致
            // WalkStack 异常（entry_point 与 OAT 元数据不匹配）。
            output_verbose(&format!(
                "[java hook] Step 9: 非 Layer 1 路由 ep={:#x}, 依赖 Layer 2 DoCall 拦截",
                original_entry_point
            ));
        } else {
            output_verbose(&format!(
                "[java hook] Step 9: 共享 stub, 依赖 Layer 1+2 路由: ep={:#x}",
                original_entry_point
            ));
        }
        Ok((None, 0))
    }
}
