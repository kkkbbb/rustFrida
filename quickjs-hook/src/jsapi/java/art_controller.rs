//! ART Controller — 全局 ART 内部函数 hook 模块
//!
//! 三层拦截矩阵:
//!
//! Layer 1: 共享 stub 路由 (全局, hook 一次)
//!   hook_install_art_router(quick_generic_jni_trampoline)
//!   hook_install_art_router(quick_to_interpreter_bridge)
//!   hook_install_art_router(quick_resolution_trampoline)
//!
//! Layer 2: Interpreter DoCall (全局, hook 一次)
//!   hook_attach(DoCall[i], on_do_call_enter)
//!
//! Layer 3: 编译方法独立代码路由 (每个被hook的编译方法)
//!   hook_install_art_router(method.quickCode)
//!   在 java_hook_api.rs 中安装
//!
//! 所有路由通过 replacedMethods 映射查找 replacement ArtMethod。

use crate::ffi::hook as hook_ffi;
use crate::jsapi::console::output_verbose;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::Mutex;

use super::art_method::{
    get_instrumentation_spec, read_entry_point, ArtBridgeFunctions, ART_BRIDGE_FUNCTIONS,
};
use super::art_thread::{get_art_thread_spec, get_managed_stack_spec, ArtThreadSpec, ART_THREAD_SPEC};
use super::callback::{get_replacement_method, is_replacement_method};
use super::jni_core::{get_runtime_addr, JniEnv};
use super::PAC_STRIP_MASK;

// ============================================================================
// Stealth 全局开关（支持 Normal / WxShadow / Recomp 三种模式）
// ============================================================================

use crate::jsapi::hook_api::StealthMode;

/// 全局 stealth 模式。
/// Normal=0  无 stealth
/// WxShadow=1  内核 shadow page patch
/// Recomp=2  页级重编译，在重编译页上 hook
static STEALTH_MODE: AtomicU8 = AtomicU8::new(StealthMode::Normal as u8);

/// Recomp 翻译回调：供 C 层 oat_patch 使用
unsafe extern "C" fn recomp_translate_for_c(orig_addr: usize) -> usize {
    match crate::recomp::ensure_and_translate(orig_addr) {
        Ok(addr) => addr,
        Err(_) => 0,
    }
}

/// 设置 stealth 模式
pub(super) fn set_stealth_mode(mode: StealthMode) {
    STEALTH_MODE.store(mode as u8, Ordering::Relaxed);
    let label = match mode {
        StealthMode::Normal => "关闭",
        StealthMode::WxShadow => "wxshadow",
        StealthMode::Recomp => "recomp",
    };

    // 同步 C 层 stealth 模式
    unsafe {
        hook_ffi::hook_set_stealth_mode(mode as i32);
        match mode {
            StealthMode::Recomp => hook_ffi::hook_set_recomp_translate(Some(recomp_translate_for_c)),
            _ => hook_ffi::hook_set_recomp_translate(None),
        }
    }

    output_verbose(&format!("[stealth] Java hook 模式: {}", label));
}

/// 查询当前 stealth 模式
pub(super) fn stealth_mode() -> StealthMode {
    StealthMode::from_js_arg(STEALTH_MODE.load(Ordering::Relaxed) as i64)
}

/// stealth2 slot 模式 trampoline 修复：hook engine 从 slot 读到的是清零字节，
/// 自动生成的 trampoline 无法 call original。用 recomp 页被覆盖的真正原始指令重建。
/// 非 recomp 模式或无 slot 记录时静默返回。
/// 安全包装: install_support.rs 调用
pub(super) fn try_fixup_trampoline_pub(trampoline: *mut std::ffi::c_void, orig_addr: u64) {
    unsafe { try_fixup_trampoline(trampoline, orig_addr) };
}

unsafe fn try_fixup_trampoline(trampoline: *mut std::ffi::c_void, orig_addr: u64) {
    if trampoline.is_null() || stealth_mode() != StealthMode::Recomp {
        return;
    }
    // 1. 用真正的原始指令重建 trampoline
    if let Err(e) = crate::recomp::fixup_slot_trampoline(trampoline as *mut u8, orig_addr as usize) {
        output_verbose(&format!("[stealth2] fixup_trampoline {:#x}: {}", orig_addr, e));
        return;
    }
    // 2. thunk + trampoline 都就绪，原子写 B 指令激活 hook
    if let Err(e) = crate::recomp::commit_slot_patch(orig_addr as usize) {
        output_verbose(&format!("[stealth2] commit_slot_patch {:#x}: {}", orig_addr, e));
    }
}

/// 统一地址准备：resolve ART trampoline + stealth 翻译
///
/// 返回 (hook_addr, stealth_flag):
///   Normal:   (resolved_addr, 0)
///   WxShadow: (resolved_addr, 1)
///   Recomp:   (recomp(resolved_addr), 2)
///
/// jni_env 用于 resolve ART tiny trampoline (LDR+BR)，非 art_router 场景传 null
///
/// force_mprotect: 为 true 时跳过 recomp/wxshadow，强制使用 mprotect (sflag=0)。
/// 用于 libart 内部的大函数（DoCall / GC / FixupStaticTrampolines 等），
/// 这些函数代码极其复杂（数百个 PC-relative 指令），全页 recomp 容易因
/// 指令交互导致 SIGSEGV。只对 app OAT 代码的 per-method hook 使用 recomp。
pub(super) unsafe fn prepare_hook_target(
    addr: u64,
    jni_env: *mut std::ffi::c_void,
) -> Result<(u64, i32), String> {
    prepare_hook_target_inner(addr, jni_env, false)
}

/// 同 prepare_hook_target，但强制 mprotect 模式（忽略 stealth 设置）
pub(super) unsafe fn prepare_hook_target_mprotect(
    addr: u64,
    jni_env: *mut std::ffi::c_void,
) -> Result<(u64, i32), String> {
    prepare_hook_target_inner(addr, jni_env, true)
}

unsafe fn prepare_hook_target_inner(
    addr: u64,
    jni_env: *mut std::ffi::c_void,
    force_mprotect: bool,
) -> Result<(u64, i32), String> {
    // 1. Resolve ART trampoline（所有模式都先 resolve）
    let resolved = hook_ffi::resolve_art_trampoline(
        addr as *mut std::ffi::c_void, jni_env);
    let real_addr = if !resolved.is_null() { resolved as u64 } else { addr };

    // 2. 按 stealth 模式处理
    if force_mprotect {
        return Ok((real_addr, 0));
    }
    match stealth_mode() {
        StealthMode::Normal => Ok((real_addr, 0)),
        StealthMode::WxShadow => Ok((real_addr, 1)),
        StealthMode::Recomp => {
            // Recomp 模式: recomp 代码页上写 1 条 B→slot，slot 里由 hook engine 写 thunk。
            // sflag=0 让 hook engine 把 slot 当普通地址处理，无需知道 stealth2。
            crate::recomp::ensure_and_translate(real_addr as usize)
                .map_err(|e| format!("recomp translate {:#x}: {}", real_addr, e))?;
            let slot = crate::recomp::alloc_trampoline_slot(real_addr as usize)
                .map_err(|e| format!("recomp slot {:#x}: {}", real_addr, e))?;
            Ok((slot as u64, 0))
        }
    }
}

// ============================================================================
// DeoptimizeBootImage — 对标 Frida
// ============================================================================

/// 获取 Instrumentation* 地址（按 InstrumentationSpec 的指针/嵌入模式解析）
unsafe fn get_instrumentation_ptr() -> Result<u64, String> {
    let spec = get_instrumentation_spec().ok_or("InstrumentationSpec 不可用")?;
    let runtime = get_runtime_addr().ok_or("Runtime 地址不可用")?;

    if spec.is_pointer_mode {
        let ptr = *((runtime as usize + spec.runtime_instrumentation_offset) as *const u64);
        let stripped = ptr & PAC_STRIP_MASK;
        if stripped == 0 {
            return Err("Instrumentation 指针为空".into());
        }
        Ok(stripped)
    } else {
        Ok(runtime + spec.runtime_instrumentation_offset as u64)
    }
}

/// Java.deoptimizeBootImage() — 对标 Frida
/// 调用 art::Runtime::DeoptimizeBootImage()，将 boot image AOT 方法降级为 interpreter。
pub(super) unsafe fn deoptimize_boot_image() -> Result<(), String> {
    let sym = crate::jsapi::module::libart_dlsym("_ZN3art7Runtime19DeoptimizeBootImageEv");
    if sym.is_null() {
        return Err("DeoptimizeBootImage 符号未找到 (API < 26?)".into());
    }
    let runtime = get_runtime_addr().ok_or("Runtime 地址不可用")?;

    type DeoptFn = unsafe extern "C" fn(runtime: u64);
    let deopt: DeoptFn = std::mem::transmute(sym);
    deopt(runtime);
    Ok(())
}

/// Java.deoptimizeEverything() — 对标 Frida
/// 调用 art::Instrumentation::DeoptimizeEverything()，全局强制解释执行。
/// API 30+: 直接调用 Instrumentation::DeoptimizeEverything
/// API < 30: 需要 JDWP 会话（暂不支持，返回错误）
pub(super) unsafe fn deoptimize_everything() -> Result<(), String> {
    let instrumentation = get_instrumentation_ptr()?;

    // 先检查并启用 deoptimization (API < 33)
    let enable_sym = crate::jsapi::module::libart_dlsym(
        "_ZN3art15instrumentation15Instrumentation20EnableDeoptimizationEv",
    );
    if !enable_sym.is_null() {
        let spec = get_instrumentation_spec().unwrap();
        if let Some(deopt_enabled_off) = spec.deoptimization_enabled_offset {
            let enabled = *((instrumentation as usize + deopt_enabled_off) as *const u8);
            if enabled == 0 {
                type EnableFn = unsafe extern "C" fn(instrumentation: u64);
                let enable: EnableFn = std::mem::transmute(enable_sym);
                enable(instrumentation);
            }
        }
    }

    // 调用 DeoptimizeEverything(instrumentation, "rustfrida")
    let sym = crate::jsapi::module::libart_dlsym(
        "_ZN3art15instrumentation15Instrumentation20DeoptimizeEverythingEPKc",
    );
    if sym.is_null() {
        return Err("Instrumentation::DeoptimizeEverything 符号未找到".into());
    }

    type DeoptFn = unsafe extern "C" fn(instrumentation: u64, key: *const u8);
    let deopt: DeoptFn = std::mem::transmute(sym);
    deopt(instrumentation, b"rustfrida\0".as_ptr());
    Ok(())
}

/// Java.deoptimizeMethod(artMethod) — 对标 Frida
/// 调用 art::Instrumentation::Deoptimize(ArtMethod*)，单个方法降级。
pub(super) unsafe fn deoptimize_method(art_method: u64) -> Result<(), String> {
    let instrumentation = get_instrumentation_ptr()?;

    // 先检查并启用 deoptimization (API < 33)
    let enable_sym = crate::jsapi::module::libart_dlsym(
        "_ZN3art15instrumentation15Instrumentation20EnableDeoptimizationEv",
    );
    if !enable_sym.is_null() {
        let spec = get_instrumentation_spec().unwrap();
        if let Some(deopt_enabled_off) = spec.deoptimization_enabled_offset {
            let enabled = *((instrumentation as usize + deopt_enabled_off) as *const u8);
            if enabled == 0 {
                type EnableFn = unsafe extern "C" fn(instrumentation: u64);
                let enable: EnableFn = std::mem::transmute(enable_sym);
                enable(instrumentation);
            }
        }
    }

    let sym = crate::jsapi::module::libart_dlsym(
        "_ZN3art15instrumentation15Instrumentation10DeoptimizeEPNS_9ArtMethodE",
    );
    if sym.is_null() {
        return Err("Instrumentation::Deoptimize 符号未找到".into());
    }

    type DeoptFn = unsafe extern "C" fn(instrumentation: u64, method: u64);
    let deopt: DeoptFn = std::mem::transmute(sym);
    deopt(instrumentation, art_method);
    Ok(())
}

// ============================================================================
// forced_interpret_only — 阻止 JIT 重编译被 hook 方法 (已弃用)
// ============================================================================

/// 原始 forced_interpret_only_ 值 (0=未设置, 1=原始为0已设为1, 2=原始已为1)
static FORCED_INTERPRET_SAVED: AtomicU8 = AtomicU8::new(0);

/// 设置 Runtime.Instrumentation.forced_interpret_only_ = 1，阻止 JIT 重编译
///
/// 通过 InstrumentationSpec 获取偏移，从 JavaVM → Runtime → Instrumentation → field。
/// 指针模式: Runtime[offset] 是 Instrumentation*，需先解引用
/// 嵌入模式: Runtime + offset 就是 Instrumentation 结构体的起始地址
unsafe fn set_forced_interpret_only() {
    let spec = match get_instrumentation_spec() {
        Some(s) => s,
        None => {
            output_verbose("[instrumentation] InstrumentationSpec 不可用，跳过 forced_interpret_only");
            return;
        }
    };

    let runtime = match get_runtime_addr() {
        Some(r) => r,
        None => {
            output_verbose("[instrumentation] 无法获取 Runtime 地址，跳过 forced_interpret_only");
            return;
        }
    };

    let instrumentation_base = if spec.is_pointer_mode {
        // 指针模式: Runtime[offset] 是 Instrumentation*
        let ptr = *((runtime as usize + spec.runtime_instrumentation_offset) as *const u64);
        let stripped = ptr & PAC_STRIP_MASK;
        if stripped == 0 {
            output_verbose("[instrumentation] Instrumentation 指针为空");
            return;
        }
        stripped as usize
    } else {
        // 嵌入模式: Runtime + offset 直接是 Instrumentation
        runtime as usize + spec.runtime_instrumentation_offset
    };

    let field_addr = (instrumentation_base + spec.force_interpret_only_offset) as *mut u8;
    let old_val = std::ptr::read_volatile(field_addr);

    if old_val == 0 {
        std::ptr::write_volatile(field_addr, 1);
        FORCED_INTERPRET_SAVED.store(1, Ordering::Relaxed);
        output_verbose(&format!(
            "[instrumentation] forced_interpret_only_ 已设置 (Instrumentation={:#x}, offset={})",
            instrumentation_base, spec.force_interpret_only_offset
        ));
    } else {
        FORCED_INTERPRET_SAVED.store(2, Ordering::Relaxed);
        output_verbose("[instrumentation] forced_interpret_only_ 已为1，无需修改");
    }
}

/// 恢复 forced_interpret_only_ 为原始值
unsafe fn restore_forced_interpret_only() {
    let saved = FORCED_INTERPRET_SAVED.load(Ordering::Relaxed);
    if saved != 1 {
        // 0=从未设置, 2=原始就是1 → 不需要恢复
        return;
    }

    let spec = match get_instrumentation_spec() {
        Some(s) => s,
        None => return,
    };

    let runtime = match get_runtime_addr() {
        Some(r) => r,
        None => return,
    };

    let instrumentation_base = if spec.is_pointer_mode {
        let ptr = *((runtime as usize + spec.runtime_instrumentation_offset) as *const u64);
        let stripped = ptr & PAC_STRIP_MASK;
        if stripped == 0 {
            return;
        }
        stripped as usize
    } else {
        runtime as usize + spec.runtime_instrumentation_offset
    };

    let field_addr = (instrumentation_base + spec.force_interpret_only_offset) as *mut u8;
    std::ptr::write_volatile(field_addr, 0);
    FORCED_INTERPRET_SAVED.store(0, Ordering::Relaxed);
    output_verbose("[instrumentation] forced_interpret_only_ 已恢复为 0");
}

// ============================================================================
// ArtController 状态
// ============================================================================

/// Layer 1 jni_trampoline 的 bypass 地址 (trampoline, 包含原始代码副本)
#[allow(dead_code)]
static JNI_TRAMPOLINE_BYPASS: AtomicU64 = AtomicU64::new(0);

/// 记录已安装的 artController 全局 hook 信息
struct ArtControllerState {
    /// Layer 1: 已 hook 的共享 stub 地址 (jni_trampoline, interpreter_bridge, resolution)
    shared_stub_targets: Vec<u64>,
    /// Layer 2: 已 hook 的 DoCall 函数地址
    do_call_targets: Vec<u64>,
    /// GC 同步 hook 地址 (CopyingPhase, CollectGarbageInternal, RunFlipFunction)
    gc_hook_targets: Vec<u64>,
    /// GetOatQuickMethodHeader hook 地址 (hook_replace, 0 表示未安装)
    oat_header_hook_target: u64,
    /// FixupStaticTrampolines hook 地址 (0 表示未安装)
    fixup_hook_target: u64,
    /// PrettyMethod hook 地址 (0 表示未安装)
    pretty_method_hook_target: u64,
}

unsafe impl Send for ArtControllerState {}
unsafe impl Sync for ArtControllerState {}

/// 全局 artController 状态。
///
/// 使用 Mutex<Option<_>> 而不是 OnceLock，这样 cleanup 后可以在新的 JS 引擎生命周期中重新初始化。
static ART_CONTROLLER: Mutex<Option<ArtControllerState>> = Mutex::new(None);

// ============================================================================
// 初始化
// ============================================================================

/// 惰性初始化 artController: 安装 Layer 1 (共享 stub 路由) + Layer 2 (DoCall hook)。
///
/// 每个 JS 引擎生命周期内最多初始化一次；cleanup 后允许重新初始化。
///
/// Layer 1: 对 3 个共享 stub 安装 hook_install_art_router，路由 hook 方法到 replacement
/// Layer 2: 对 DoCall 安装 hook_attach，拦截解释器路径
pub(super) fn ensure_art_controller_initialized(
    bridge: &ArtBridgeFunctions,
    ep_offset: usize,
    env: *mut std::ffi::c_void,
) {
    let mut controller = ART_CONTROLLER.lock().unwrap_or_else(|e| e.into_inner());
    if controller.is_some() {
        return;
    }

    output_verbose("[artController] 开始安装三层拦截矩阵...");

    // 提前探测 ArtThreadSpec (递归防护 stack check 需要)
    let _ = get_art_thread_spec(env as JniEnv);
    let _ = get_managed_stack_spec();

    // 注意: DeoptimizeBootImage / forced_interpret_only / InvalidateAllMethods 都不自动调用。
    // Frida 中这些是可选功能 (Java.deopt())，不是 hook 安装的前置条件。
    // 自动调用会:
    //   - DeoptimizeBootImage + forced_interpret: 全局走 interpreter → 进程启动极慢 → ActivityManager kill
    //   - InvalidateAllMethods: 清空所有 JIT 代码 → 热点方法集体重编译 → 瞬时性能降级
    // stealth=0 的 rw-sibling 直写 + stealth=1 的 KPM + stealth=2 的 recomp PTE 重定向
    // 已能直接 patch JIT cache ep, 不再需要提前 invalidate。
    // 副作用: 调用者已 inline 的 hook 方法 body 不会被拦截 (Frida 同样限制),
    // 需要完整拦截时用户显式调 Java.deopt()。
    // Hook 路由依靠:
    //   - Layer 1 (shared stub hooks) + Layer 2 (DoCall) 覆盖 interpreter 路径
    //   - Layer 3 (per-method quickCode hook) 覆盖 compiled 路径 (含 JIT cache)
    //   - install.rs 中 nterp → interpreter_bridge 降级确保 nterp 方法走 Layer 1

    let mut shared_stub_targets = Vec::new();
    let mut do_call_targets = Vec::new();

    // --- Layer 1: 共享 stub 路由 hook ---
    // 跳过 jni_trampoline: spawn 模式下 resume_child 之后才安装 hooks，
    // 子进程主线程正在高频调用 JNI。inline hook jni_trampoline 的 prologue
    // 覆写与执行存在竞态 → SIGSEGV。Frida 用 Memory.patchCode() 暂停所有
    // 线程后 patch，我们目前没有这个机制。
    // replacement 方法的 quickCode 仍指向 jni_trampoline（不经过 Layer 1），
    // 路由通过 Layer 2 (DoCall) 和 Layer 3 (per-method hook) 覆盖。
    let stubs = [
        ("quick_to_interpreter_bridge", bridge.quick_to_interpreter_bridge),
        ("quick_resolution_trampoline", bridge.quick_resolution_trampoline),
    ];

    for (name, addr) in &stubs {
        if *addr == 0 {
            output_verbose(&format!("[artController] Layer 1: {} 地址为0，跳过", name));
            continue;
        }
        let mut hooked_target: *mut std::ffi::c_void = std::ptr::null_mut();
        let (hook_addr, sflag) = match unsafe { prepare_hook_target(*addr, env) } {
            Ok(v) => v,
            Err(e) => {
                output_verbose(&format!("[artController] Layer 1: {} prepare failed: {}", name, e));
                continue;
            }
        };
        let trampoline = unsafe {
            hook_ffi::hook_install_art_router(
                hook_addr as *mut std::ffi::c_void,
                ep_offset as u32,
                sflag,
                env,
                &mut hooked_target,
                1, // skip_resolve: 已在 prepare_hook_target 中 resolve
                0, // no hint — replacement is kAccNative, ART handles it
            )
        };
        if !trampoline.is_null() {
            // stealth2: 修复 trampoline（hook engine 从 slot 读到的是清零字节）
            unsafe { try_fixup_trampoline(trampoline, *addr) };
            // 使用实际被 hook 的地址 (可能经过 resolve_art_trampoline 解析)
            let actual_target = if !hooked_target.is_null() {
                hooked_target as u64
            } else {
                *addr
            };
            shared_stub_targets.push(actual_target);

            // 保存 jni_trampoline 的 bypass (trampoline) 地址
            if *name == "quick_generic_jni_trampoline" {
                JNI_TRAMPOLINE_BYPASS.store(trampoline as u64, Ordering::Release);
            }

            output_verbose(&format!(
                "[artController] Layer 1: {} hook 安装成功: {:#x} (hooked={:#x}), trampoline={:#x}",
                name, addr, actual_target, trampoline as u64
            ));
            // 验证 inline hook 是否真的写入
            unsafe {
                hook_ffi::hook_dump_code(actual_target as *mut std::ffi::c_void, 20);
            }
        } else {
            output_verbose(&format!("[artController] Layer 1: {} hook 安装失败: {:#x}", name, addr));
        }
    }

    // --- Layer 2: DoCall hook (解释器路径) ---
    for (i, &addr) in bridge.do_call_addrs.iter().enumerate() {
        if addr == 0 {
            continue;
        }
        let (ha, sf) = unsafe { prepare_hook_target(addr, std::ptr::null_mut()) }.unwrap_or((addr, 0));
        let ret = unsafe {
            hook_ffi::hook_attach(ha as *mut std::ffi::c_void, Some(on_do_call_enter), None, std::ptr::null_mut(), sf)
        };
        if ret == 0 {
            unsafe { try_fixup_trampoline(hook_ffi::hook_get_trampoline(ha as *mut std::ffi::c_void), addr) };
            do_call_targets.push(addr);
            output_verbose(&format!(
                "[artController] Layer 2: DoCall[{}] hook 安装成功: {:#x}",
                i, addr
            ));
        } else {
            output_verbose(&format!(
                "[artController] Layer 2: DoCall[{}] hook 安装失败: {:#x} (ret={})",
                i, addr, ret
            ));
        }
    }

    // --- GC 同步 hooks ---
    // GC 可能移动 ArtMethod 的 entry_point / declaring_class_，需要在多个 GC 点同步
    let mut gc_hook_targets = Vec::new();

    // Fix 3: hook CopyingPhase/MarkingPhase on_leave
    if bridge.gc_copying_phase != 0 {
        let (ha, sf) = unsafe { prepare_hook_target(bridge.gc_copying_phase, std::ptr::null_mut()) }.unwrap_or((bridge.gc_copying_phase, 0));
        let ret = unsafe {
            hook_ffi::hook_attach(ha as *mut std::ffi::c_void, None, Some(on_gc_sync_leave), std::ptr::null_mut(), sf)
        };
        if ret == 0 {
            unsafe { try_fixup_trampoline(hook_ffi::hook_get_trampoline(ha as *mut std::ffi::c_void), bridge.gc_copying_phase) };
            gc_hook_targets.push(bridge.gc_copying_phase);
            output_verbose(&format!(
                "[artController] GC CopyingPhase hook 安装成功: {:#x}",
                bridge.gc_copying_phase
            ));
        } else {
            output_verbose(&format!(
                "[artController] GC CopyingPhase hook 安装失败: {:#x} (ret={})",
                bridge.gc_copying_phase, ret
            ));
        }
    }

    // Fix 3: hook CollectGarbageInternal on_leave (主 GC 入口)
    if bridge.gc_collect_internal != 0 {
        let (ha, sf) = unsafe { prepare_hook_target(bridge.gc_collect_internal, std::ptr::null_mut()) }.unwrap_or((bridge.gc_collect_internal, 0));
        let ret = unsafe {
            hook_ffi::hook_attach(ha as *mut std::ffi::c_void, None, Some(on_gc_sync_leave), std::ptr::null_mut(), sf)
        };
        if ret == 0 {
            unsafe { try_fixup_trampoline(hook_ffi::hook_get_trampoline(ha as *mut std::ffi::c_void), bridge.gc_collect_internal) };
            gc_hook_targets.push(bridge.gc_collect_internal);
            output_verbose(&format!(
                "[artController] GC CollectGarbageInternal hook 安装成功: {:#x}",
                bridge.gc_collect_internal
            ));
        } else {
            output_verbose(&format!(
                "[artController] GC CollectGarbageInternal hook 安装失败: {:#x} (ret={})",
                bridge.gc_collect_internal, ret
            ));
        }
    }

    // Fix 3: hook RunFlipFunction on_enter (线程翻转期间同步)
    if bridge.run_flip_function != 0 {
        let (ha, sf) = unsafe { prepare_hook_target(bridge.run_flip_function, std::ptr::null_mut()) }.unwrap_or((bridge.run_flip_function, 0));
        let ret = unsafe {
            hook_ffi::hook_attach(ha as *mut std::ffi::c_void, Some(on_gc_sync_enter), None, std::ptr::null_mut(), sf)
        };
        if ret == 0 {
            unsafe { try_fixup_trampoline(hook_ffi::hook_get_trampoline(ha as *mut std::ffi::c_void), bridge.run_flip_function) };
            gc_hook_targets.push(bridge.run_flip_function);
            output_verbose(&format!(
                "[artController] GC RunFlipFunction hook 安装成功: {:#x}",
                bridge.run_flip_function
            ));
        } else {
            output_verbose(&format!(
                "[artController] GC RunFlipFunction hook 安装失败: {:#x} (ret={})",
                bridge.run_flip_function, ret
            ));
        }
    }

    // --- Fix 4: hook GetOatQuickMethodHeader (replace mode) ---
    // replacement 的 data_ = thunk 地址, WalkStack → GetDexPc 查 CodeInfo 会 abort。
    // 对 replacement method 返回 NULL, 防止 ART 查找堆分配方法的 OAT 代码头。
    let mut oat_header_hook_target: u64 = 0;
    if bridge.get_oat_quick_method_header != 0 {
        let (ha, sf) = unsafe { prepare_hook_target(bridge.get_oat_quick_method_header, std::ptr::null_mut()) }.unwrap_or((bridge.get_oat_quick_method_header, 0));
        let trampoline = unsafe {
            hook_ffi::hook_replace(ha as *mut std::ffi::c_void, Some(on_get_oat_quick_method_header), std::ptr::null_mut(), sf)
        };
        if !trampoline.is_null() {
            unsafe { try_fixup_trampoline(trampoline, bridge.get_oat_quick_method_header) };
            oat_header_hook_target = bridge.get_oat_quick_method_header;
            output_verbose(&format!(
                "[artController] GetOatQuickMethodHeader hook 安装成功: {:#x}, trampoline={:#x}",
                bridge.get_oat_quick_method_header, trampoline as u64
            ));
        } else {
            output_verbose(&format!(
                "[artController] GetOatQuickMethodHeader hook 安装失败: {:#x}",
                bridge.get_oat_quick_method_header
            ));
        }
    }

    // --- Fix 5: hook FixupStaticTrampolines on_leave ---
    // 类初始化完成后同步 replacement 方法，防止 quickCode 被更新绕过 hook
    let mut fixup_hook_target: u64 = 0;
    if bridge.fixup_static_trampolines != 0 {
        let (ha, sf) = unsafe { prepare_hook_target(bridge.fixup_static_trampolines, std::ptr::null_mut()) }.unwrap_or((bridge.fixup_static_trampolines, 0));
        let ret = unsafe {
            hook_ffi::hook_attach(ha as *mut std::ffi::c_void, None, Some(on_gc_sync_leave), std::ptr::null_mut(), sf)
        };
        if ret == 0 {
            unsafe { try_fixup_trampoline(hook_ffi::hook_get_trampoline(ha as *mut std::ffi::c_void), bridge.fixup_static_trampolines) };
            fixup_hook_target = bridge.fixup_static_trampolines;
            output_verbose(&format!(
                "[artController] FixupStaticTrampolines hook 安装成功: {:#x}",
                bridge.fixup_static_trampolines
            ));
        } else {
            output_verbose(&format!(
                "[artController] FixupStaticTrampolines hook 安装失败: {:#x} (ret={})",
                bridge.fixup_static_trampolines, ret
            ));
        }
    }

    // --- Fix: hook PrettyMethod (NULL 指针崩溃防护) ---
    let mut pretty_method_hook_target: u64 = 0;
    if bridge.pretty_method != 0 {
        let (ha, sf) = unsafe { prepare_hook_target(bridge.pretty_method, std::ptr::null_mut()) }.unwrap_or((bridge.pretty_method, 0));
        let ret = unsafe {
            hook_ffi::hook_attach(ha as *mut std::ffi::c_void, Some(on_pretty_method_enter), None, std::ptr::null_mut(), sf)
        };
        if ret == 0 {
            unsafe { try_fixup_trampoline(hook_ffi::hook_get_trampoline(ha as *mut std::ffi::c_void), bridge.pretty_method) };
            pretty_method_hook_target = bridge.pretty_method;
            output_verbose(&format!(
                "[artController] PrettyMethod hook 安装成功: {:#x}",
                bridge.pretty_method
            ));
        } else {
            output_verbose(&format!(
                "[artController] PrettyMethod hook 安装失败: {:#x} (ret={})",
                bridge.pretty_method, ret
            ));
        }
    }

    // --- Fix 8: patch 内联 GetOatQuickMethodHeader ---
    // libart.so 内联了 GetOatQuickMethodHeader 的 data_!=-1 检查,
    // hook_replace 只拦截非内联调用。内联点需要单独 patch。
    let oat_inline_patched: i32 = unsafe {
        hook_ffi::hook_patch_inlined_oat_header_checks()
    };

    // SIGSEGV guard 作为 fallback
    unsafe {
        install_walkstack_sigsegv_guard();
    }

    output_verbose(&format!(
        "[artController] 初始化完成: Layer1={}, Layer2={}, GC={}, OatHeader={}, Fixup={}, PrettyMethod={}, InlinePatch={}",
        shared_stub_targets.len(),
        do_call_targets.len(),
        gc_hook_targets.len(),
        if oat_header_hook_target != 0 { "active" } else { "none" },
        if fixup_hook_target != 0 { "active" } else { "none" },
        if pretty_method_hook_target != 0 {
            "active"
        } else {
            "none"
        },
        if oat_inline_patched > 0 { oat_inline_patched } else { 0 },
    ));

    *controller = Some(ArtControllerState {
        shared_stub_targets,
        do_call_targets,
        gc_hook_targets,
        oat_header_hook_target,
        fixup_hook_target,
        pretty_method_hook_target,
    });
}

// ============================================================================
// 回调函数
// ============================================================================

/// 获取已缓存的 ArtThreadSpec（不需要 JNIEnv，仅从 OnceLock 读取）
fn get_art_thread_spec_cached() -> Option<&'static ArtThreadSpec> {
    match ART_THREAD_SPEC.get() {
        Some(Some(spec)) => Some(spec),
        _ => None,
    }
}

pub(super) static DO_CALL_COUNT: AtomicU64 = AtomicU64::new(0);
pub(super) static DO_CALL_HIT_COUNT: AtomicU64 = AtomicU64::new(0);
/// DoCall on_enter: 检查 x0 (ArtMethod*) 是否在 replacedMethods 中，有则替换。
/// 包含递归防护: 如果当前栈帧来自 callOriginal (managedStack 中已有 replacement)，
/// 则跳过替换，让 original method 正常执行，防止无限递归。
unsafe extern "C" fn on_do_call_enter(ctx_ptr: *mut hook_ffi::HookContext, _user_data: *mut std::ffi::c_void) {
    if ctx_ptr.is_null() {
        return;
    }
    let ctx = &mut *ctx_ptr;
    let method = ctx.x[0];
    DO_CALL_COUNT.fetch_add(1, Ordering::Relaxed);
    if let Some(replacement) = get_replacement_method(method) {
        DO_CALL_HIT_COUNT.fetch_add(1, Ordering::Relaxed);
        // 递归防护: TLS bypass (callOriginal) + managed stack check
        ensure_bypass_key();
        let bypass = libc::pthread_getspecific(BYPASS_KEY) as u64;
        if bypass == method {
            return; // callOriginal bypass
        }
        if !should_replace_for_stack(replacement) {
            return; // managed stack 递归
        }
        // 同步 declaring_class_: replacement (malloc'd) 不被 GC 追踪，
        // GC 移动 declaring class 后 replacement 的 declaring_class_ 可能 stale。
        // 每次替换前从 original 拷贝到 replacement，消除竞态。
        let dc = std::ptr::read_volatile(method as *const u32);
        std::ptr::write_volatile(replacement as *mut u32, dc);
        ctx.x[0] = replacement;
    }
}

/// 递归防护: 检查当前线程的 ManagedStack 判断是否应该进行替换。
///
/// 对标 Frida find_replacement_method_from_quick_code():
/// 1. 获取 Thread* via Thread::Current()
/// 2. 读取 managed_stack.top_quick_frame
/// 3. 如果 top_quick_frame != NULL → 正常调用，返回 true
/// 4. 读取 managed_stack.link
/// 5. 读取 link.top_quick_frame，解引用得到 ArtMethod*
/// 6. 如果该 ArtMethod* == replacement → 递归，返回 false
/// 7. 否则返回 true
unsafe fn should_replace_for_stack(replacement: u64) -> bool {
    // 获取 Thread::Current 函数指针
    let bridge = match ART_BRIDGE_FUNCTIONS.get() {
        Some(b) => b,
        None => return true,
    };
    if bridge.thread_current == 0 {
        return true; // 无法获取 Thread*，保守返回 true
    }

    // 调用 Thread::Current() 获取当前线程
    type ThreadCurrentFn = unsafe extern "C" fn() -> u64;
    let thread_current: ThreadCurrentFn = std::mem::transmute(bridge.thread_current);
    let thread = thread_current();
    let thread = thread & PAC_STRIP_MASK;
    if thread == 0 {
        return true;
    }

    // 获取 Thread 和 ManagedStack 布局偏移
    // 注意: get_art_thread_spec 需要 JNIEnv，但此处已经在 hook 回调中，
    // 且 spec 应该已经在初始化时被探测过。使用 OnceLock 缓存值。
    let thread_spec = match get_art_thread_spec_cached() {
        Some(spec) => spec,
        None => return true,
    };
    let ms_spec = get_managed_stack_spec();

    // 读取 managed_stack (嵌入在 Thread 结构体中)
    let managed_stack = thread as usize + thread_spec.managed_stack_offset;

    // 读取 top_quick_frame
    let top_qf = std::ptr::read_volatile((managed_stack + ms_spec.top_quick_frame_offset) as *const u64);

    if top_qf != 0 {
        // top_quick_frame != NULL → 正常调用 (有 compiled frame)，执行替换
        return true;
    }

    // top_quick_frame == NULL → 可能是从解释器进入的
    // 读取 link_ (上一个 ManagedStack)
    let link = std::ptr::read_volatile((managed_stack + ms_spec.link_offset) as *const u64);
    let link = link & PAC_STRIP_MASK;
    if link == 0 {
        return true;
    }

    // 读取 link.top_quick_frame (可能有 TaggedQuickFrame 的 tag bit)
    let link_tqf = std::ptr::read_volatile((link as usize + ms_spec.top_quick_frame_offset) as *const u64);
    // Strip tag bit (bit 0): ART uses it as a tag for managed/JNI frames
    let frame_ptr = (link_tqf & !1u64) & PAC_STRIP_MASK;
    if frame_ptr == 0 {
        return true;
    }

    // Dereference: top_quick_frame 指向栈上的 ArtMethod*
    let art_method_on_stack = std::ptr::read_volatile(frame_ptr as *const u64);
    let art_method_on_stack = art_method_on_stack & PAC_STRIP_MASK;

    if art_method_on_stack == replacement {
        // 栈上的方法就是 replacement → 这是 callOriginal 触发的递归调用
        false
    } else {
        true
    }
}

// ============================================================================
// callOriginal bypass — TLS 标记防止 art_router 递归
// ============================================================================

static BYPASS_KEY_INIT: std::sync::Once = std::sync::Once::new();
static mut BYPASS_KEY: libc::pthread_key_t = 0;

/// TLS bypass 栈析构函数：释放 Vec<u64> 堆内存
unsafe extern "C" fn bypass_stack_destructor(ptr: *mut std::ffi::c_void) {
    if !ptr.is_null() {
        let _ = Box::from_raw(ptr as *mut Vec<u64>);
    }
}

fn ensure_bypass_key() {
    BYPASS_KEY_INIT.call_once(|| unsafe {
        libc::pthread_key_create(&mut BYPASS_KEY as *mut _, Some(bypass_stack_destructor));
    });
}

/// 获取当前线程的 bypass 栈（惰性创建）
unsafe fn get_bypass_stack() -> &'static mut Vec<u64> {
    ensure_bypass_key();
    let ptr = libc::pthread_getspecific(BYPASS_KEY) as *mut Vec<u64>;
    if ptr.is_null() {
        let stack = Box::new(Vec::<u64>::with_capacity(4));
        let raw = Box::into_raw(stack);
        libc::pthread_setspecific(BYPASS_KEY, raw as *const _);
        &mut *raw
    } else {
        &mut *ptr
    }
}

/// callOriginal 前调用：将 original ArtMethod 地址 push 到 bypass 栈
/// 支持嵌套：callback skip fallback 期间内层方法也可能 skip 并调用 invoke_original_jni
pub(crate) fn set_call_original_bypass(art_method: u64) {
    unsafe { get_bypass_stack().push(art_method); }
}

/// callOriginal 后调用：从 bypass 栈 pop（恢复外层 bypass）
pub(crate) fn clear_call_original_bypass() {
    unsafe { get_bypass_stack().pop(); }
}

/// C-callable：art_router thunk + DoCall hook 调用，判断是否应该路由。
/// 返回 1 = 正常路由到 replacement，返回 0 = 跳过（callOriginal bypass 或 stack 递归 或 JS engine 繁忙）。
#[no_mangle]
pub unsafe extern "C" fn art_router_stack_check(replacement: u64) -> i32 {
    // TLS bypass 栈: 检查栈中是否有任何一个 entry 匹配当前 replacement 的 original
    let stack = get_bypass_stack();
    if !stack.is_empty() {
        let original = hook_ffi::hook_art_router_table_lookup_original(replacement);
        if original != 0 {
            for &bypassed in stack.iter() {
                if bypassed == original {
                    return 0; // callOriginal bypass
                }
            }
        }
    }


    // Fallback: managed stack check (对标 Frida, 覆盖其他递归场景)
    if should_replace_for_stack(replacement) { 1 } else { 0 }
}

/// 上次见到的非空 ArtMethod* (PrettyMethod 防护用)
static LAST_SEEN_ART_METHOD: AtomicU64 = AtomicU64::new(0);

/// PrettyMethod on_enter 回调: 当 method (x0/this) 为 NULL 时替换为上次见到的非空 method。
/// 对标 Frida fixupArtQuickDeliverExceptionBug: QuickDeliverException 中
/// native 线程无 Java frame 时 method==NULL → PrettyMethod(NULL) → SIGSEGV。
unsafe extern "C" fn on_pretty_method_enter(ctx_ptr: *mut hook_ffi::HookContext, _user_data: *mut std::ffi::c_void) {
    if ctx_ptr.is_null() {
        return;
    }
    let ctx = &mut *ctx_ptr;
    let method = ctx.x[0]; // ARM64: this (ArtMethod*) 在 x0
    if method == 0 {
        // NULL method → 替换为上次见到的非空 method 防止崩溃
        let last = LAST_SEEN_ART_METHOD.load(Ordering::Relaxed);
        if last != 0 {
            ctx.x[0] = last;
        }
    } else {
        LAST_SEEN_ART_METHOD.store(method, Ordering::Relaxed);
    }
}

/// GC / FixupStaticTrampolines on_leave 回调: 调用同步函数
unsafe extern "C" fn on_gc_sync_leave(_ctx_ptr: *mut hook_ffi::HookContext, _user_data: *mut std::ffi::c_void) {
    synchronize_replacement_methods();
}

/// RunFlipFunction on_enter 回调: 线程翻转期间同步
unsafe extern "C" fn on_gc_sync_enter(_ctx_ptr: *mut hook_ffi::HookContext, _user_data: *mut std::ffi::c_void) {
    synchronize_replacement_methods();
}

/// Fix 4: GetOatQuickMethodHeader replace-mode 回调
///
/// 对 replacement ArtMethod 返回 dummy header，防止 ART 查找堆分配方法的 OAT 代码头。
/// 返回 NULL 会导致 API 36 的 WalkStack 空指针崩溃（offset 0x18 解引用），
/// 所以改为返回一个全零的静态 dummy header，让 WalkStack 安全跳过。
/// 对其他方法调用原始实现。
///
/// dummy header 全零意味着 code_size=0，WalkStack 的 PC 范围检查不通过，
/// 会跳过该帧继续遍历，不会崩溃。
unsafe extern "C" fn on_get_oat_quick_method_header(
    ctx_ptr: *mut hook_ffi::HookContext,
    _user_data: *mut std::ffi::c_void,
) {
    // 64 字节全零 dummy header — 足够覆盖 OatQuickMethodHeader 各版本的字段
    static DUMMY_OAT_HEADER: [u8; 64] = [0u8; 64];

    if ctx_ptr.is_null() {
        return;
    }
    let ctx = &mut *ctx_ptr;
    let method = ctx.x[0]; // ArtMethod* this

    if is_replacement_method(method) {
        // replacement method → 返回 dummy header（非 NULL，但所有字段为 0）
        ctx.x[0] = DUMMY_OAT_HEADER.as_ptr() as u64;
    } else {
        // 非 replacement → 调用原始实现
        let trampoline = ctx.trampoline;
        if !trampoline.is_null() {
            let result = hook_ffi::hook_invoke_trampoline(ctx_ptr, trampoline);
            (*ctx_ptr).x[0] = result;
        }
    }
}

// ============================================================================
// Fix 6: synchronize_replacement_methods — 统一同步函数
// ============================================================================

/// 同步所有被 hook 方法的关键字段。
///
/// 在多个 ART 内部事件（GC、类初始化等）后调用，确保 hook 仍然生效。
///
/// 同步内容:
/// 1. declaring_class_ 同步: original → replacement (Fix 1)
/// 2. accessFlags 修复: kAccCompileDontBother + clear kAccFastInterpreterToInterpreterInvoke
/// 3. entry_point 验证与恢复 (Fix 2 + existing)
unsafe fn synchronize_replacement_methods() {
    use super::art_method::ART_BRIDGE_FUNCTIONS;
    use super::callback::{HookType, JAVA_HOOK_REGISTRY};
    use super::jni_core::{k_acc_compile_dont_bother, ART_METHOD_SPEC, K_ACC_FAST_INTERP_TO_INTERP};

    let guard = match JAVA_HOOK_REGISTRY.lock() {
        Ok(g) => g,
        Err(_) => return,
    };
    let registry = match guard.as_ref() {
        Some(r) => r,
        None => return,
    };

    let spec = match ART_METHOD_SPEC.get() {
        Some(s) => s,
        None => return,
    };
    let ep_offset = spec.entry_point_offset;

    // 获取 nterp 和 interpreter_bridge 地址 (共享 stub 方法的 GC 同步用)
    let (nterp, interp_bridge) = match ART_BRIDGE_FUNCTIONS.get() {
        Some(b) => (b.nterp_entry_point, b.quick_to_interpreter_bridge),
        None => (0, 0),
    };

    for (_, data) in registry.iter() {
        let art_method = data.art_method as usize;

        // --- Fix 1: declaring_class_ 同步 ---
        // 移动 GC 会更新原始 ArtMethod 的 declaring_class_ (offset 0, 4 bytes GcRoot)，
        // 堆分配的 replacement 不会被 GC 追踪，需要同步以防悬空引用。
        // 2-ArtMethod 模型: clone 已去掉，只同步 replacement。
        {
            let declaring_class = std::ptr::read_volatile(art_method as *const u32);
            // 同步 replacement 的 declaring_class_ (对标 Frida synchronize_replacement_methods)
            let HookType::Replaced { replacement_addr, .. } = &data.hook_type;
            if *replacement_addr != 0 {
                std::ptr::write_volatile(*replacement_addr as *mut u32, declaring_class);
            }
        }

        // --- flags 修复: 确保 kAccCompileDontBother 在 + kAccFastInterpreterToInterpreterInvoke 不在 ---
        let cdontbother = k_acc_compile_dont_bother();
        let flags = std::ptr::read_volatile((art_method + spec.access_flags_offset) as *const u32);
        let need_fix = (cdontbother != 0 && (flags & cdontbother) == 0) || (flags & K_ACC_FAST_INTERP_TO_INTERP) != 0;
        if need_fix {
            let fixed = (flags | cdontbother) & !K_ACC_FAST_INTERP_TO_INTERP;
            std::ptr::write_volatile((art_method + spec.access_flags_offset) as *mut u32, fixed);
        }

        // --- Fix 2 + existing: entry_point 验证与恢复 ---
        // 对标 Frida synchronize_replacement_methods: nterp → quick_to_interpreter_bridge
        let HookType::Replaced { per_method_hook_target, .. } = &data.hook_type;
        if per_method_hook_target.is_none() {
            // 共享 stub 方法: 如果 GC 重置 entry_point 为 nterp，再降级为 interpreter_bridge
            if nterp != 0 && interp_bridge != 0 {
                let current_ep = read_entry_point(data.art_method, ep_offset);
                if current_ep == nterp {
                    std::ptr::write_volatile((art_method + ep_offset) as *mut u64, interp_bridge);
                    hook_ffi::hook_flush_cache((art_method + ep_offset) as *mut std::ffi::c_void, 8);
                }
            }
        } else {
            // 编译方法: entry_point 应为 original_entry_point (已被 inline hook 修改)
            // 但 GC/类初始化可能将 ep 重置为 nterp → 降级为 interpreter_bridge
            let current_ep = read_entry_point(data.art_method, ep_offset);
            if current_ep != data.original_entry_point {
                if nterp != 0 && current_ep == nterp && interp_bridge != 0 {
                    std::ptr::write_volatile((art_method + ep_offset) as *mut u64, interp_bridge);
                } else {
                    std::ptr::write_volatile((art_method + ep_offset) as *mut u64, data.original_entry_point);
                }
                hook_ffi::hook_flush_cache((art_method + ep_offset) as *mut std::ffi::c_void, 8);
            }
        }
    }
}

// ============================================================================
// Fix 8: WalkStack NULL OatQuickMethodHeader SIGSEGV guard
// ============================================================================
//
// API 36 的 WalkStack 内联了 GetOatQuickMethodHeader 逻辑。对被 hook 的方法，
// 内联查找返回 NULL 后直接执行 LDR W9, [X10, #0x18] (X10=NULL) → SIGSEGV。
// 注册 SIGSEGV handler: 当 fault_addr==0x18 时，将 X10 指向全零 dummy buffer，
// 跳过无效访问恢复执行。

/// 64 字节全零 dummy — 足够覆盖 OatQuickMethodHeader 各版本的字段
static DUMMY_OAT_HEADER_BUF: [u8; 64] = [0u8; 64];

/// 旧的 SIGSEGV handler (chain 用)
static mut PREV_SIGSEGV_ACTION: libc::sigaction = unsafe { std::mem::zeroed() };
static WALKSTACK_GUARD_INSTALLED: AtomicBool = AtomicBool::new(false);

unsafe extern "C" fn walkstack_sigsegv_handler(
    sig: libc::c_int,
    info: *mut libc::siginfo_t,
    context: *mut libc::c_void,
) {
    if !info.is_null() && !context.is_null() {
        let fault_addr = (*info).si_addr() as u64;
        // 精准匹配: fault_addr == 0x18 说明是 NULL+0x18 解引用 (OAT header 字段访问)
        if fault_addr == 0x18 {
            let uc = context as *mut libc::ucontext_t;
            let regs = &mut (*uc).uc_mcontext.regs;
            // X10 = regs[10], 如果 X10 == 0 说明是我们关心的 WalkStack NULL header 场景
            if regs[10] == 0 {
                // 修复: X10 指向 dummy buffer，让后续 LDR 读到 0 而不是崩溃
                regs[10] = DUMMY_OAT_HEADER_BUF.as_ptr() as u64;
                // 不需要修改 PC — 返回后重新执行同一条 LDR 指令，这次 X10 有效
                return;
            }
        }
    }

    // 不是我们关心的场景 → chain 到旧 handler
    let prev = &PREV_SIGSEGV_ACTION;
    let prev_handler = prev.sa_sigaction;
    if prev.sa_flags & libc::SA_SIGINFO != 0 {
        let handler: unsafe extern "C" fn(libc::c_int, *mut libc::siginfo_t, *mut libc::c_void) =
            std::mem::transmute(prev_handler);
        handler(sig, info, context);
    } else if prev_handler == libc::SIG_DFL {
        libc::signal(sig, libc::SIG_DFL);
        libc::raise(sig);
    } else if prev_handler != libc::SIG_IGN {
        let simple: unsafe extern "C" fn(libc::c_int) = std::mem::transmute(prev_handler);
        simple(sig);
    }
}

unsafe fn install_walkstack_sigsegv_guard() {
    if WALKSTACK_GUARD_INSTALLED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut sa: libc::sigaction = std::mem::zeroed();
    sa.sa_sigaction = walkstack_sigsegv_handler as usize;
    sa.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK;
    libc::sigemptyset(&mut sa.sa_mask);

    let ret = libc::sigaction(libc::SIGSEGV, &sa, &mut PREV_SIGSEGV_ACTION);
    if ret == 0 {
        output_verbose("[artController] WalkStack SIGSEGV guard 已安装");
    } else {
        output_verbose(&format!(
            "[artController] WalkStack SIGSEGV guard 安装失败: {}",
            std::io::Error::last_os_error()
        ));
        WALKSTACK_GUARD_INSTALLED.store(false, Ordering::SeqCst);
    }
}

// ============================================================================
// 清理
// ============================================================================

/// 清理所有 artController 全局 hook
///
/// 移除 Layer 1 (共享 stub 路由 hook) 和 Layer 2 (DoCall hook)。
pub(super) fn cleanup_art_controller() {
    // 恢复 instrumentation 状态 (在移除 hooks 之前)
    unsafe {
        restore_forced_interpret_only();
    }

    let state = {
        let mut guard = ART_CONTROLLER.lock().unwrap_or_else(|e| e.into_inner());
        guard.take()
    };
    let state = match state {
        Some(s) => s,
        None => return, // 从未初始化，无需清理
    };

    output_verbose("[artController] 开始清理全局 ART hook...");

    // 收集所有需要移除的地址，统一移除
    let mut all_targets: Vec<(&str, u64)> = Vec::new();
    for &addr in &state.shared_stub_targets {
        all_targets.push(("Layer1", addr));
    }
    for &addr in &state.do_call_targets {
        all_targets.push(("Layer2", addr));
    }
    for &addr in &state.gc_hook_targets {
        all_targets.push(("GC", addr));
    }
    if state.oat_header_hook_target != 0 {
        all_targets.push(("OatHeader", state.oat_header_hook_target));
    }
    if state.fixup_hook_target != 0 {
        all_targets.push(("Fixup", state.fixup_hook_target));
    }
    if state.pretty_method_hook_target != 0 {
        all_targets.push(("PrettyMethod", state.pretty_method_hook_target));
    }

    for (_label, addr) in &all_targets {
        unsafe {
            hook_ffi::hook_remove(*addr as *mut std::ffi::c_void);
        }
    }

    // 恢复内联 OAT header patch
    unsafe {
        let restored = hook_ffi::hook_restore_inlined_oat_header_patches();
        if restored > 0 {
            output_verbose(&format!("[artController] 恢复了 {} 个内联 OAT patch", restored));
        }
    }

    LAST_SEEN_ART_METHOD.store(0, Ordering::Relaxed);
    output_verbose("[artController] 全局 ART hook 清理完成");
}
