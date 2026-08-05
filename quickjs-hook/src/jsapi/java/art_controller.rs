//! ART Controller — 全局 ART 内部函数 hook 模块
//!
//! 三层拦截矩阵:
//!
//! Layer 1: 共享 stub 路由 (全局, hook 一次)
//!   hook_install_art_router(quick_generic_jni_trampoline)
//!   hook_install_art_router(nterp_entry_point)
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
use crate::jsapi::module::{libart_dlsym, libart_find_symbol_contains, module_dlsym};
use crate::jsapi::util::{proc_maps_entries, read_proc_self_maps};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::Mutex;

use super::art_method::{get_instrumentation_spec, ArtBridgeFunctions, ART_BRIDGE_FUNCTIONS};
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
    let suspend_entry = resolve_recomp_suspend_poll_entrypoint();
    match crate::recomp::ensure_and_translate(orig_addr) {
        Ok(addr) => {
            register_recomp_signal_range(orig_addr, addr);
            if let Some(entry) = suspend_entry {
                let _ = crate::recomp::patch_suspend_polls(orig_addr, entry);
            }
            addr
        }
        Err(_) => 0,
    }
}

unsafe extern "C" fn recomp_existing_translate_for_c(orig_addr: usize) -> usize {
    crate::recomp::translate_existing(orig_addr).unwrap_or(0)
}

unsafe extern "C" fn recomp_reverse_translate_for_c(recomp_addr: usize) -> usize {
    crate::recomp::translate_recomp_to_orig(recomp_addr).unwrap_or(0)
}

const MAX_SIGNAL_RECOMP_RANGES: usize = 128;
const ART_FAULT_MANAGER_GENERATED_RANGES_OFFSET: usize = 0x28;
static SIGNAL_RECOMP_RANGE_COUNT: AtomicUsize = AtomicUsize::new(0);
static SIGNAL_RECOMP_ORIG_BASES: [AtomicUsize; MAX_SIGNAL_RECOMP_RANGES] =
    [const { AtomicUsize::new(0) }; MAX_SIGNAL_RECOMP_RANGES];
static SIGNAL_RECOMP_BASES: [AtomicUsize; MAX_SIGNAL_RECOMP_RANGES] =
    [const { AtomicUsize::new(0) }; MAX_SIGNAL_RECOMP_RANGES];

#[repr(C)]
struct ArtGeneratedCodeRangeNode {
    next: AtomicUsize,
    start: AtomicUsize,
    size: AtomicUsize,
}

static ART_RECOMP_RANGE_NODES: [ArtGeneratedCodeRangeNode; MAX_SIGNAL_RECOMP_RANGES] = [const {
    ArtGeneratedCodeRangeNode {
        next: AtomicUsize::new(0),
        start: AtomicUsize::new(0),
        size: AtomicUsize::new(0),
    }
}; MAX_SIGNAL_RECOMP_RANGES];

fn register_recomp_signal_range(orig_addr: usize, recomp_addr: usize) {
    const PAGE_SIZE: usize = 0x1000;
    let orig_base = orig_addr & !(PAGE_SIZE - 1);
    let recomp_base = recomp_addr & !(PAGE_SIZE - 1);
    let count = SIGNAL_RECOMP_RANGE_COUNT.load(Ordering::Acquire);
    let limit = count.min(MAX_SIGNAL_RECOMP_RANGES);
    for i in 0..limit {
        if SIGNAL_RECOMP_BASES[i].load(Ordering::Acquire) == recomp_base {
            return;
        }
    }
    if count >= MAX_SIGNAL_RECOMP_RANGES {
        return;
    }
    SIGNAL_RECOMP_ORIG_BASES[count].store(orig_base, Ordering::Release);
    SIGNAL_RECOMP_BASES[count].store(recomp_base, Ordering::Release);
    // Do not insert the recomp page into ART FaultManager's generated-code
    // list. If ART handles the suspend-poll fault itself, it saves the
    // anonymous recomp PC as the callee-save return PC; later GC root scanning
    // pairs that PC with the original OAT stack map and can crash in
    // ReferenceMapVisitor. Keep the range only in our signal-safe side table so
    // the front SIGSEGV guard can translate LR to the original OAT PC.
    SIGNAL_RECOMP_RANGE_COUNT.store(count + 1, Ordering::Release);
}

unsafe fn register_recomp_art_fault_range(index: usize, recomp_base: usize, size: usize) {
    let fault_manager = libart_dlsym("_ZN3art13fault_managerE");
    if fault_manager.is_null() {
        return;
    }

    let node = &ART_RECOMP_RANGE_NODES[index];
    node.start.store(recomp_base, Ordering::Release);
    node.size.store(size, Ordering::Release);

    let head_addr = (fault_manager as usize + ART_FAULT_MANAGER_GENERATED_RANGES_OFFSET) as *const AtomicUsize;
    let head = &*head_addr;
    let node_ptr = node as *const ArtGeneratedCodeRangeNode as usize;
    loop {
        let old_head = head.load(Ordering::Acquire);
        node.next.store(old_head, Ordering::Relaxed);
        if head
            .compare_exchange(old_head, node_ptr, Ordering::Release, Ordering::Relaxed)
            .is_ok()
        {
            break;
        }
    }
}

fn translate_recomp_to_orig_signal_safe(addr: usize) -> Option<usize> {
    const PAGE_SIZE: usize = 0x1000;
    let count = SIGNAL_RECOMP_RANGE_COUNT.load(Ordering::Acquire);
    let limit = count.min(MAX_SIGNAL_RECOMP_RANGES);
    for i in 0..limit {
        let recomp_base = SIGNAL_RECOMP_BASES[i].load(Ordering::Acquire);
        if recomp_base == 0 {
            continue;
        }
        if addr.wrapping_sub(recomp_base) < PAGE_SIZE {
            let orig_base = SIGNAL_RECOMP_ORIG_BASES[i].load(Ordering::Acquire);
            if orig_base != 0 {
                return Some(orig_base + (addr - recomp_base));
            }
        }
    }
    None
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
            StealthMode::Recomp => {
                hook_ffi::hook_set_recomp_translate(Some(recomp_translate_for_c));
                hook_ffi::hook_set_recomp_existing_translate(Some(recomp_existing_translate_for_c));
                hook_ffi::hook_set_recomp_reverse_translate(Some(recomp_reverse_translate_for_c));
            }
            _ => {
                hook_ffi::hook_set_recomp_translate(None);
                hook_ffi::hook_set_recomp_existing_translate(None);
                hook_ffi::hook_set_recomp_reverse_translate(None);
            }
        }
    }

    output_verbose(&format!("[stealth] Java hook 模式: {}", label));
}

/// 查询当前 stealth 模式
pub(super) fn stealth_mode() -> StealthMode {
    StealthMode::from_js_arg(STEALTH_MODE.load(Ordering::Relaxed) as i64)
}

pub(super) fn art_controller_initialized() -> bool {
    ART_CONTROLLER.lock().unwrap_or_else(|e| e.into_inner()).is_some()
}

fn maybe_install_raw_clone_executor_loop_hook(env: *mut std::ffi::c_void) {
    if !crate::is_raw_clone_js_thread() {
        return;
    }

    let installed = unsafe { super::callback::install_raw_clone_executor_loop_hook(env as JniEnv) };
    if installed {
        output_verbose("[artController] raw clone executor MessageQueue hook ready");
    }
}

/// stealth2 slot 模式 trampoline 修复：hook engine 从 slot 读到的是清零字节，
/// 自动生成的 trampoline 无法 call original。用 recomp 页被覆盖的真正原始指令重建。
/// 非 recomp 模式或无 slot 记录时静默返回。
/// 安全包装: install_support.rs 调用
pub(super) fn try_fixup_trampoline_pub(trampoline: *mut std::ffi::c_void, orig_addr: u64) -> bool {
    unsafe { try_fixup_trampoline(trampoline, orig_addr) }
}

unsafe fn try_fixup_trampoline(trampoline: *mut std::ffi::c_void, orig_addr: u64) -> bool {
    if stealth_mode() != StealthMode::Recomp {
        return true;
    }
    if trampoline.is_null() {
        output_verbose(&format!(
            "[stealth2] fixup_trampoline {:#x}: trampoline is null",
            orig_addr
        ));
        let _ = crate::recomp::try_revert_slot_patch(orig_addr as usize);
        return false;
    }
    // 1. 用真正的原始指令重建 trampoline
    if let Err(e) = crate::recomp::fixup_slot_trampoline(trampoline as *mut u8, orig_addr as usize) {
        output_verbose(&format!("[stealth2] fixup_trampoline {:#x}: {}", orig_addr, e));
        let _ = crate::recomp::try_revert_slot_patch(orig_addr as usize);
        return false;
    }
    let ret = hook_ffi::hook_mark_recomp_hook_by_trampoline(trampoline);
    if ret != 0 {
        output_verbose(&format!("[stealth2] mark_recomp_hook {:#x}: {}", orig_addr, ret));
        let _ = crate::recomp::try_revert_slot_patch(orig_addr as usize);
        return false;
    }
    // 2. thunk + trampoline 都就绪，原子写 B 指令激活 hook
    if let Err(e) = crate::recomp::commit_slot_patch(orig_addr as usize) {
        output_verbose(&format!("[stealth2] commit_slot_patch {:#x}: {}", orig_addr, e));
        let _ = crate::recomp::try_revert_slot_patch(orig_addr as usize);
        return false;
    }
    true
}

/// 统一地址准备：resolve ART trampoline + stealth 翻译。
/// Java.setStealth(1/2) 是严格模式；准备失败时调用方必须放弃该 hook，
/// 不能回退到原始地址 + sflag=0，否则会暴露普通 inline/mprotect 特征。
///
/// 返回 (hook_addr, stealth_flag, real_addr):
///   Normal:   (resolved_addr, 0, resolved_addr)
///   WxShadow: (resolved_addr, 1, resolved_addr)
///   Recomp:   (recomp slot, 0, resolved_addr)
///
/// real_addr 是真正分配/提交 recomp slot 的原始代码地址。调用方在
/// try_fixup_trampoline/commit_slot_patch 时必须使用 real_addr，不能使用
/// resolve 前的逻辑入口地址，否则 ART trampoline 入口会显示安装成功但不生效。
///
/// jni_env 用于 resolve ART tiny trampoline (LDR+BR)，非 art_router 场景传 null
pub(super) unsafe fn prepare_hook_target(addr: u64, jni_env: *mut std::ffi::c_void) -> Result<(u64, i32, u64), String> {
    // 1. Resolve ART trampoline（所有模式都先 resolve）
    let resolved = hook_ffi::resolve_art_trampoline(addr as *mut std::ffi::c_void, jni_env);
    let real_addr = if !resolved.is_null() { resolved as u64 } else { addr };

    // 2. 按 stealth 模式处理
    match stealth_mode() {
        StealthMode::Normal => Ok((real_addr, 0, real_addr)),
        StealthMode::WxShadow => Ok((real_addr, 1, real_addr)),
        StealthMode::Recomp => {
            // Recomp 模式: recomp 代码页上写 1 条 B→slot，slot 里由 hook engine 写 thunk。
            // sflag=0 让 hook engine 把 slot 当普通地址处理，无需知道 stealth2。
            let suspend_entry = resolve_recomp_suspend_poll_entrypoint();
            let recomp_addr = crate::recomp::ensure_and_translate(real_addr as usize)
                .map_err(|e| format!("recomp translate {:#x}: {}", real_addr, e))?;
            register_recomp_signal_range(real_addr as usize, recomp_addr);
            if let Some(entry) = suspend_entry {
                crate::recomp::patch_suspend_polls(real_addr as usize, entry)
                    .map_err(|e| format!("recomp suspend patch {:#x}: {}", real_addr, e))?;
            }
            let slot = crate::recomp::alloc_trampoline_slot(real_addr as usize)
                .map_err(|e| format!("recomp slot {:#x}: {}", real_addr, e))?;
            Ok((slot as u64, 0, real_addr))
        }
    }
}

unsafe fn prepare_hook_target_strict(
    label: &str,
    addr: u64,
    jni_env: *mut std::ffi::c_void,
) -> Option<(u64, i32, u64)> {
    match prepare_hook_target(addr, jni_env) {
        Ok(v) => Some(v),
        Err(e) => {
            output_verbose(&format!(
                "[artController] {} prepare failed: target={:#x}, {}; Java.setStealth({}) strict: skip hook, no mprotect fallback",
                label,
                addr,
                e,
                stealth_mode() as u8
            ));
            None
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
    let enable_sym =
        crate::jsapi::module::libart_dlsym("_ZN3art15instrumentation15Instrumentation20EnableDeoptimizationEv");
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
    let sym = crate::jsapi::module::libart_dlsym("_ZN3art15instrumentation15Instrumentation20DeoptimizeEverythingEPKc");
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
    let enable_sym =
        crate::jsapi::module::libart_dlsym("_ZN3art15instrumentation15Instrumentation20EnableDeoptimizationEv");
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

    let sym =
        crate::jsapi::module::libart_dlsym("_ZN3art15instrumentation15Instrumentation10DeoptimizeEPNS_9ArtMethodE");
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

pub(super) fn jni_trampoline_router_installed() -> bool {
    JNI_TRAMPOLINE_BYPASS.load(Ordering::Acquire) != 0
}

/// 记录已安装的 artController 全局 hook 信息
struct ArtControllerState {
    /// Layer 1 源入口地址，用于 stealth2 下按逻辑入口去重。
    shared_stub_sources: Vec<u64>,
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
    /// DecodeGcMasksOnly NULL header guard hook 地址 (0 表示未安装)
    decode_gc_masks_hook_target: u64,
}

unsafe impl Send for ArtControllerState {}
unsafe impl Sync for ArtControllerState {}

/// 全局 artController 状态。
///
/// 使用 Mutex<Option<_>> 而不是 OnceLock，这样 cleanup 后可以在新的 JS 引擎生命周期中重新初始化。
static ART_CONTROLLER: Mutex<Option<ArtControllerState>> = Mutex::new(None);
static ART_CONTROLLER_RELOAD_PAUSED: AtomicBool = AtomicBool::new(false);

pub fn set_art_controller_reload_paused(paused: bool) {
    ART_CONTROLLER_RELOAD_PAUSED.store(paused, Ordering::Release);
}

fn art_controller_reload_paused() -> bool {
    ART_CONTROLLER_RELOAD_PAUSED.load(Ordering::Acquire)
}

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
        drop(controller);
        maybe_install_raw_clone_executor_loop_hook(env);
        return;
    }

    output_verbose("[artController] 开始安装三层拦截矩阵...");

    // 提前探测 ArtThreadSpec (递归防护 stack check 需要)
    if !env.is_null() {
        if let Some(spec) = get_art_thread_spec(env as JniEnv) {
            unsafe {
                install_managed_implicit_suspend_guard(spec);
            }
        }
    } else {
        output_verbose("[artController] raw/no-env init: skip ArtThreadSpec probe");
    }
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
    //   - stealth=1/2 时 Layer 1 直接覆盖 nterp / interpreter / generic JNI entrypoints

    let mut shared_stub_targets = Vec::new();
    let mut shared_stub_sources = Vec::new();
    let mut do_call_targets = Vec::new();

    // --- Layer 1: 共享 stub 路由 hook ---
    //
    // quick_generic_jni_trampoline 覆盖 native/shared-JNI 方法。normal 模式下仍跳过:
    // spawn resume 后主线程会高频进 JNI，直接 mprotect/写原 libart prologue 有竞态。
    // Java.setStealth(1/2) 时才启用，底层走 wxshadow/recomp，不修改目标 ArtMethod
    // entry_point_/data_ 到外部地址。
    //
    // nterp/interpreter/resolution stub 覆盖解释执行、deopt、GC FixupStaticTrampolines
    // 把 entry_point 保持/改回 libart trampoline 的 edge case。
    let mut stubs = Vec::new();
    if stealth_mode() == StealthMode::Normal {
        output_verbose(
            "[artController] Layer 1: quick_generic_jni_trampoline skipped in normal mode; enable Java.setStealth(1/2) for shared JNI native routing",
        );
    } else {
        stubs.push((
            "quick_generic_jni_trampoline",
            bridge.quick_generic_jni_trampoline,
            false,
        ));
    }
    if bridge.nterp_entry_point != 0 && stealth_mode() != StealthMode::Normal {
        stubs.push(("nterp_entry_point", bridge.nterp_entry_point, true));
    }
    if bridge.nterp_with_clinit_entry_point != 0 && stealth_mode() != StealthMode::Normal {
        stubs.push((
            "nterp_with_clinit_entry_point",
            bridge.nterp_with_clinit_entry_point,
            true,
        ));
    }
    stubs.push(("quick_to_interpreter_bridge", bridge.quick_to_interpreter_bridge, false));
    stubs.push(("quick_resolution_trampoline", bridge.quick_resolution_trampoline, false));

    for (name, addr, pre_scan) in &stubs {
        if *addr == 0 {
            output_verbose(&format!("[artController] Layer 1: {} 地址为0，跳过", name));
            continue;
        }
        let mut hooked_target: *mut std::ffi::c_void = std::ptr::null_mut();
        let (hook_addr, sflag, real_addr) = match unsafe { prepare_hook_target(*addr, env) } {
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
                0, // use_blr=0: Layer 1 shared stubs 不用 BLR
                if *pre_scan { 1 } else { 0 },
            )
        };
        if !trampoline.is_null() {
            // stealth2: 修复 trampoline（hook engine 从 slot 读到的是清零字节）
            unsafe { try_fixup_trampoline(trampoline, real_addr) };
            // 使用实际被 hook 的地址 (可能经过 resolve_art_trampoline 解析)
            let actual_target = if !hooked_target.is_null() {
                hooked_target as u64
            } else {
                hook_addr
            };
            shared_stub_sources.push(*addr);
            shared_stub_targets.push(actual_target);

            // 保存 jni_trampoline 的 bypass (trampoline) 地址
            if *name == "quick_generic_jni_trampoline" {
                JNI_TRAMPOLINE_BYPASS.store(trampoline as u64, Ordering::Release);
            }

            output_verbose(&format!(
                "[artController] Layer 1: {} hook 安装成功: source={:#x}, real={:#x}, hooked={:#x}, trampoline={:#x}",
                name, addr, real_addr, actual_target, trampoline as u64
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
    // 覆盖 interpreter-only 调用链 (纯 interpreter caller 调 interpreter callee,
    // 不经任何 stub → Layer 1/3 漏掉). 命中率实测 0.05%, 但 deopt 后全量 interpreter
    // 模式下这条路径变主力.
    //
    // 历史问题: DoCall 通过 hook_attach 包裹原函数, 任何 Java 阻塞 (wait/IO) 会
    // 把 thunk 栈帧钉在 BLR 之后, 全局 g_thunk_in_flight 永不归零. 已通过把
    // 计数点改到 Rust java_hook_callback 解决 (阻塞在原 DoCall 不影响新计数).
    let skip_do_call = false;
    if !skip_do_call {
        for (i, &addr) in bridge.do_call_addrs.iter().enumerate() {
            if addr == 0 {
                continue;
            }
            let label = format!("Layer 2: DoCall[{}]", i);
            let Some((ha, sf, real_addr)) = (unsafe { prepare_hook_target_strict(&label, addr, std::ptr::null_mut()) })
            else {
                continue;
            };
            let ret = unsafe {
                let is_range = (i & 1) as usize as *mut std::ffi::c_void;
                hook_ffi::hook_attach(ha as *mut std::ffi::c_void, Some(on_do_call_enter), None, is_range, sf)
            };
            if ret == 0 {
                unsafe { try_fixup_trampoline(hook_ffi::hook_get_trampoline(ha as *mut std::ffi::c_void), real_addr) };
                do_call_targets.push(ha);
                output_verbose(&format!(
                    "[artController] Layer 2: DoCall[{}] hook 安装成功: {:#x} (hooked={:#x})",
                    i, addr, ha
                ));
            } else {
                output_verbose(&format!(
                    "[artController] Layer 2: DoCall[{}] hook 安装失败: {:#x} (ret={})",
                    i, addr, ret
                ));
            }
        }
    } else {
        output_verbose("[artController] Layer 2: DoCall hook 已跳过 (skip_do_call=true)");
    }

    // --- GC 同步 hooks ---
    // GC 可能移动 ArtMethod 的 entry_point / declaring_class_，需要在多个 GC 点同步
    let mut gc_hook_targets = Vec::new();

    // Fix 3: hook CopyingPhase/MarkingPhase on_leave
    if bridge.gc_copying_phase != 0 {
        if let Some((ha, sf, real_addr)) =
            unsafe { prepare_hook_target_strict("GC CopyingPhase", bridge.gc_copying_phase, std::ptr::null_mut()) }
        {
            let ret = unsafe {
                hook_ffi::hook_attach(
                    ha as *mut std::ffi::c_void,
                    None,
                    Some(on_gc_sync_leave),
                    std::ptr::null_mut(),
                    sf,
                )
            };
            if ret == 0 {
                unsafe { try_fixup_trampoline(hook_ffi::hook_get_trampoline(ha as *mut std::ffi::c_void), real_addr) };
                gc_hook_targets.push(ha);
                output_verbose(&format!(
                    "[artController] GC CopyingPhase hook 安装成功: {:#x} (hooked={:#x})",
                    bridge.gc_copying_phase, ha
                ));
            } else {
                output_verbose(&format!(
                    "[artController] GC CopyingPhase hook 安装失败: {:#x} (ret={})",
                    bridge.gc_copying_phase, ret
                ));
            }
        }
    }

    // Fix 3: hook CollectGarbageInternal on_leave (主 GC 入口)
    if bridge.gc_collect_internal != 0 {
        if let Some((ha, sf, real_addr)) = unsafe {
            prepare_hook_target_strict(
                "GC CollectGarbageInternal",
                bridge.gc_collect_internal,
                std::ptr::null_mut(),
            )
        } {
            let ret = unsafe {
                hook_ffi::hook_attach(
                    ha as *mut std::ffi::c_void,
                    None,
                    Some(on_gc_sync_leave),
                    std::ptr::null_mut(),
                    sf,
                )
            };
            if ret == 0 {
                unsafe { try_fixup_trampoline(hook_ffi::hook_get_trampoline(ha as *mut std::ffi::c_void), real_addr) };
                gc_hook_targets.push(ha);
                output_verbose(&format!(
                    "[artController] GC CollectGarbageInternal hook 安装成功: {:#x} (hooked={:#x})",
                    bridge.gc_collect_internal, ha
                ));
            } else {
                output_verbose(&format!(
                    "[artController] GC CollectGarbageInternal hook 安装失败: {:#x} (ret={})",
                    bridge.gc_collect_internal, ret
                ));
            }
        }
    }

    // Fix 3: hook RunFlipFunction on_enter (线程翻转期间同步)
    if bridge.run_flip_function != 0 {
        if let Some((ha, sf, real_addr)) =
            unsafe { prepare_hook_target_strict("GC RunFlipFunction", bridge.run_flip_function, std::ptr::null_mut()) }
        {
            let ret = unsafe {
                hook_ffi::hook_attach(
                    ha as *mut std::ffi::c_void,
                    Some(on_gc_sync_enter),
                    None,
                    std::ptr::null_mut(),
                    sf,
                )
            };
            if ret == 0 {
                unsafe { try_fixup_trampoline(hook_ffi::hook_get_trampoline(ha as *mut std::ffi::c_void), real_addr) };
                gc_hook_targets.push(ha);
                output_verbose(&format!(
                    "[artController] GC RunFlipFunction hook 安装成功: {:#x} (hooked={:#x})",
                    bridge.run_flip_function, ha
                ));
            } else {
                output_verbose(&format!(
                    "[artController] GC RunFlipFunction hook 安装失败: {:#x} (ret={})",
                    bridge.run_flip_function, ret
                ));
            }
        }
    }

    // --- Fix 4: hook GetOatQuickMethodHeader (replace mode) ---
    // replacement 的 data_ = thunk 地址, WalkStack → GetDexPc 查 CodeInfo 会 abort。
    // 对 replacement method 返回 NULL, 防止 ART 查找堆分配方法的 OAT 代码头。
    let mut oat_header_hook_target: u64 = 0;
    if bridge.get_oat_quick_method_header != 0 {
        if let Some((ha, sf, real_addr)) = unsafe {
            prepare_hook_target_strict(
                "GetOatQuickMethodHeader",
                bridge.get_oat_quick_method_header,
                std::ptr::null_mut(),
            )
        } {
            let trampoline = unsafe {
                hook_ffi::hook_replace(
                    ha as *mut std::ffi::c_void,
                    Some(on_get_oat_quick_method_header),
                    std::ptr::null_mut(),
                    sf,
                )
            };
            if !trampoline.is_null() {
                unsafe { try_fixup_trampoline(trampoline, real_addr) };
                oat_header_hook_target = ha;
                output_verbose(&format!(
                    "[artController] GetOatQuickMethodHeader hook 安装成功: {:#x} (hooked={:#x}), trampoline={:#x}",
                    bridge.get_oat_quick_method_header, ha, trampoline as u64
                ));
            } else {
                output_verbose(&format!(
                    "[artController] GetOatQuickMethodHeader hook 安装失败: {:#x}",
                    bridge.get_oat_quick_method_header
                ));
            }
        }
    }

    // --- Fix 5: hook FixupStaticTrampolines on_leave ---
    // 类初始化完成后同步 replacement 方法，防止 quickCode 被更新绕过 hook
    let mut fixup_hook_target: u64 = 0;
    if bridge.fixup_static_trampolines != 0 {
        if let Some((ha, sf, real_addr)) = unsafe {
            prepare_hook_target_strict(
                "FixupStaticTrampolines",
                bridge.fixup_static_trampolines,
                std::ptr::null_mut(),
            )
        } {
            let ret = unsafe {
                hook_ffi::hook_attach(
                    ha as *mut std::ffi::c_void,
                    None,
                    Some(on_gc_sync_leave),
                    std::ptr::null_mut(),
                    sf,
                )
            };
            if ret == 0 {
                unsafe { try_fixup_trampoline(hook_ffi::hook_get_trampoline(ha as *mut std::ffi::c_void), real_addr) };
                fixup_hook_target = ha;
                output_verbose(&format!(
                    "[artController] FixupStaticTrampolines hook 安装成功: {:#x} (hooked={:#x})",
                    bridge.fixup_static_trampolines, ha
                ));
            } else {
                output_verbose(&format!(
                    "[artController] FixupStaticTrampolines hook 安装失败: {:#x} (ret={})",
                    bridge.fixup_static_trampolines, ret
                ));
            }
        }
    }

    // PrettyMethod can run from ART/JD crash and signal paths. Routing it
    // through our hook pool can leave a thread unsuspendable if a signal handler
    // blocks there, so keep this guard disabled and rely on the OAT-header and
    // SIGSEGV walkstack guards below.
    let mut pretty_method_hook_target: u64 = 0;
    if false && bridge.pretty_method != 0 {
        if let Some((ha, sf, real_addr)) =
            unsafe { prepare_hook_target_strict("PrettyMethod", bridge.pretty_method, std::ptr::null_mut()) }
        {
            let ret = unsafe {
                hook_ffi::hook_attach(
                    ha as *mut std::ffi::c_void,
                    Some(on_pretty_method_enter),
                    None,
                    std::ptr::null_mut(),
                    sf,
                )
            };
            if ret == 0 {
                unsafe { try_fixup_trampoline(hook_ffi::hook_get_trampoline(ha as *mut std::ffi::c_void), real_addr) };
                pretty_method_hook_target = ha;
                output_verbose(&format!(
                    "[artController] PrettyMethod hook 安装成功: {:#x} (hooked={:#x})",
                    bridge.pretty_method, ha
                ));
            } else {
                output_verbose(&format!(
                    "[artController] PrettyMethod hook 安装失败: {:#x} (ret={})",
                    bridge.pretty_method, ret
                ));
            }
        }
    }

    // --- Fix 8: patch 内联 GetOatQuickMethodHeader ---
    // libart.so 内联了 GetOatQuickMethodHeader 的 data_!=-1 检查,
    // hook_replace 只拦截非内联调用。内联点需要单独 patch。
    // 传入 GetOatQuickMethodHeader 本体地址，避免模式扫描把本体当作内联副本 patch。
    let oat_inline_patched: i32 =
        unsafe { hook_ffi::hook_patch_inlined_oat_header_checks(bridge.get_oat_quick_method_header) };

    // API 36 的 GC WalkStack 可直接调用 DecodeGcMasksOnly(NULL)。信号 fallback
    // 容易被 app 后装的 crash handler 挤掉，所以主动在 DecodeGcMasksOnly 的
    // 首个 header load 前把 NULL x0 改成 dummy header。
    let decode_gc_masks_hook_target = unsafe { install_decode_gc_masks_only_null_guard() };

    // SIGSEGV guard 作为 fallback
    unsafe {
        install_walkstack_sigsegv_guard();
    }

    output_verbose(&format!(
        "[artController] 初始化完成: Layer1={}, Layer2={}, GC={}, OatHeader={}, Fixup={}, PrettyMethod={}, DecodeGcMasks={}, InlinePatch={}",
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
        if decode_gc_masks_hook_target != 0 { "active" } else { "none" },
        if oat_inline_patched > 0 { oat_inline_patched } else { 0 },
    ));

    *controller = Some(ArtControllerState {
        shared_stub_sources,
        shared_stub_targets,
        do_call_targets,
        gc_hook_targets,
        oat_header_hook_target,
        fixup_hook_target,
        pretty_method_hook_target,
        decode_gc_masks_hook_target,
    });
    drop(controller);
    maybe_install_raw_clone_executor_loop_hook(env);
}

/// 动态补充 shared ART entry 的全局 router。
///
/// 某些 Android 构建拿不到 nterp entrypoint，或者目标方法的 entry_point_
/// 指向 libart 内未归类的解释器入口。这里不修改 ArtMethod.entry_point_，
/// 只在该 libart 入口上安装共享 router，再由 router table 按 ArtMethod 分发。
pub(super) unsafe fn ensure_shared_entry_router_hook(
    label: &str,
    entry_point: u64,
    ep_offset: usize,
    env: JniEnv,
    pre_scan: bool,
) -> Result<(), String> {
    if entry_point == 0 {
        return Err(format!("{} entry_point is null", label));
    }

    let mut controller = ART_CONTROLLER.lock().unwrap_or_else(|e| e.into_inner());
    let state = controller
        .as_mut()
        .ok_or_else(|| format!("{} requested before artController initialized", label))?;

    if state.shared_stub_sources.contains(&entry_point) {
        output_verbose(&format!(
            "[artController] Layer 1 dynamic: {} already routed: source={:#x}",
            label, entry_point
        ));
        return Ok(());
    }

    let mut hooked_target: *mut std::ffi::c_void = std::ptr::null_mut();
    let (hook_addr, sflag, real_addr) =
        prepare_hook_target(entry_point, env as *mut std::ffi::c_void).map_err(|e| {
            format!(
                "Layer 1 dynamic {} prepare failed: source={:#x}, {}",
                label, entry_point, e
            )
        })?;

    let trampoline = hook_ffi::hook_install_art_router(
        hook_addr as *mut std::ffi::c_void,
        ep_offset as u32,
        sflag,
        env as *mut std::ffi::c_void,
        &mut hooked_target,
        1,
        0,
        0,
        if pre_scan { 1 } else { 0 },
    );
    if trampoline.is_null() {
        return Err(format!(
            "Layer 1 dynamic {} hook_install_art_router failed: source={:#x}, hook={:#x}",
            label, entry_point, hook_addr
        ));
    }

    try_fixup_trampoline(trampoline, real_addr);

    let actual_target = if !hooked_target.is_null() {
        hooked_target as u64
    } else {
        hook_addr
    };
    state.shared_stub_sources.push(entry_point);
    if !state.shared_stub_targets.contains(&actual_target) {
        state.shared_stub_targets.push(actual_target);
    }

    output_verbose(&format!(
        "[artController] Layer 1 dynamic: {} hook 安装成功: source={:#x}, real={:#x}, hooked={:#x}, trampoline={:#x}",
        label, entry_point, real_addr, actual_target, trampoline as u64
    ));
    hook_ffi::hook_dump_code(actual_target as *mut std::ffi::c_void, 20);
    Ok(())
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

pub(crate) fn cached_thread_top_quick_frame_offset() -> Option<usize> {
    let thread_spec = get_art_thread_spec_cached()?;
    let ms_spec = get_managed_stack_spec();
    Some(thread_spec.managed_stack_offset + ms_spec.top_quick_frame_offset)
}

/// Callback gate: 只允许一个线程进入完整 JNI trampoline → callback 路径。
/// 在 art_router_stack_check 中 CAS 获取，在 java_hook_callback 末尾（guard drop）释放。
pub(crate) static JAVA_CALLBACK_GATE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Gate 冷却计数器：释放后 N 次调用全部 bypass，避免主线程频繁走 $orig JNI 路径
static GATE_COOLDOWN: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
static GATE_COOLDOWN_CALLS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

const HOT_METHOD_SAMPLER_SLOTS: usize = 16;
static HOT_METHOD_SAMPLER_ORIGINALS: [std::sync::atomic::AtomicU64; HOT_METHOD_SAMPLER_SLOTS] =
    [const { std::sync::atomic::AtomicU64::new(0) }; HOT_METHOD_SAMPLER_SLOTS];
static HOT_METHOD_SAMPLER_EVERY_N: [std::sync::atomic::AtomicU32; HOT_METHOD_SAMPLER_SLOTS] =
    [const { std::sync::atomic::AtomicU32::new(0) }; HOT_METHOD_SAMPLER_SLOTS];
static HOT_METHOD_SAMPLER_COUNTERS: [std::sync::atomic::AtomicU64; HOT_METHOD_SAMPLER_SLOTS] =
    [const { std::sync::atomic::AtomicU64::new(0) }; HOT_METHOD_SAMPLER_SLOTS];

pub(crate) fn register_hot_method_sampler(original: u64, every_n: u32) {
    if original == 0 || every_n <= 1 {
        return;
    }
    for i in 0..HOT_METHOD_SAMPLER_SLOTS {
        let existing = HOT_METHOD_SAMPLER_ORIGINALS[i].load(std::sync::atomic::Ordering::Acquire);
        if existing == original {
            HOT_METHOD_SAMPLER_EVERY_N[i].store(every_n, std::sync::atomic::Ordering::Release);
            return;
        }
        if existing == 0
            && HOT_METHOD_SAMPLER_ORIGINALS[i]
                .compare_exchange(
                    0,
                    original,
                    std::sync::atomic::Ordering::AcqRel,
                    std::sync::atomic::Ordering::Relaxed,
                )
                .is_ok()
        {
            HOT_METHOD_SAMPLER_EVERY_N[i].store(every_n, std::sync::atomic::Ordering::Release);
            HOT_METHOD_SAMPLER_COUNTERS[i].store(0, std::sync::atomic::Ordering::Release);
            output_verbose(&format!("[hot-sampler] original={:#x}, every_n={}", original, every_n));
            return;
        }
    }
}

#[inline]
fn should_sample_original_method(original: u64) -> bool {
    if original == 0 {
        return true;
    }
    for i in 0..HOT_METHOD_SAMPLER_SLOTS {
        let sampled_original = HOT_METHOD_SAMPLER_ORIGINALS[i].load(std::sync::atomic::Ordering::Acquire);
        if sampled_original == 0 {
            continue;
        }
        if sampled_original != original {
            continue;
        }
        let every_n = HOT_METHOD_SAMPLER_EVERY_N[i].load(std::sync::atomic::Ordering::Relaxed);
        if every_n <= 1 {
            return true;
        }
        let count = HOT_METHOD_SAMPLER_COUNTERS[i]
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            .wrapping_add(1);
        return count % every_n as u64 == 0;
    }
    true
}

pub(crate) struct CallbackGateGuard;
impl Drop for CallbackGateGuard {
    fn drop(&mut self) {
        GATE_COOLDOWN.store(
            GATE_COOLDOWN_CALLS.load(std::sync::atomic::Ordering::Relaxed),
            std::sync::atomic::Ordering::Release,
        );
        JAVA_CALLBACK_GATE.store(false, std::sync::atomic::Ordering::Release);
    }
}

pub(super) static DO_CALL_COUNT: AtomicU64 = AtomicU64::new(0);
pub(super) static DO_CALL_HIT_COUNT: AtomicU64 = AtomicU64::new(0);
pub(super) static DO_CALL_QUICK_CALLBACK_COUNT: AtomicU64 = AtomicU64::new(0);
pub(super) static GET_OAT_HOOK_POOL_ORIGINAL_COUNT: AtomicU64 = AtomicU64::new(0);
pub(super) static GET_OAT_HOOK_POOL_REPLACEMENT_COUNT: AtomicU64 = AtomicU64::new(0);
pub(super) static GET_OAT_HOOK_POOL_LAST_METHOD: AtomicU64 = AtomicU64::new(0);
pub(super) static GET_OAT_HOOK_POOL_LAST_PC: AtomicU64 = AtomicU64::new(0);
/// DoCall on_enter: 检查 x0 (ArtMethod*) 是否在 replacedMethods 中，有则替换。
/// 包含递归防护: 如果当前栈帧来自 callOriginal (managedStack 中已有 replacement)，
/// 则跳过替换，让 original method 正常执行，防止无限递归。
unsafe extern "C" fn on_do_call_enter(ctx_ptr: *mut hook_ffi::HookContext, _user_data: *mut std::ffi::c_void) {
    if art_controller_reload_paused() {
        return;
    }
    if ctx_ptr.is_null() {
        return;
    }
    let ctx = &mut *ctx_ptr;
    let method = ctx.x[0];
    DO_CALL_COUNT.fetch_add(1, Ordering::Relaxed);
    if let Ok(env) = super::jni_core::get_thread_env() {
        let drained = super::callback::drain_raw_clone_executor(env);
        if drained != 0 {
            output_verbose(&format!("[java executor] DoCall drained {} raw-clone task(s)", drained));
        }
    }
    if hook_ffi::hook_managed_reentry_guard_active() != 0 {
        ctx.intercept_leave = 0;
        return;
    }
    let route_mode = hook_ffi::hook_art_router_record_do_call(method);

    // 默认: miss → tail-jump (原函数跑完不回 thunk, 无栈帧残留)
    ctx.intercept_leave = 0;

    if let Some(replacement) = get_replacement_method(method) {
        DO_CALL_HIT_COUNT.fetch_add(1, Ordering::Relaxed);
        // 递归防护: per-thread bypass (callOriginal) + managed stack check
        if hook_ffi::orig_bypass_consume_current_thread(method) != 0 {
            return; // managed helper orig() bypass — one-shot, let original DoCall run
        }
        let bypass = current_call_original_bypass();
        if bypass == method {
            return; // callOriginal bypass — 仍走 tail-jump (intercept_leave=0)
        }
        if !should_replace_for_stack(replacement) {
            return; // managed stack 递归 — 走 tail-jump
        }
        if route_mode < 4 {
            // 同步 declaring_class_: replacement (malloc'd) 不被 GC 追踪，
            // GC 移动 declaring class 后 replacement 的 declaring_class_ 可能 stale。
            // Managed DSL 的 replacement 是真实 dex 方法，declaring_class_ 必须保持 helper 类。
            let dc = std::ptr::read_volatile(method as *const u32);
            std::ptr::write_volatile(replacement as *mut u32, dc);
        }
        ctx.x[0] = replacement;
        // hit → 需要 wrap, 这样 thunk counter / java_hook_callback 能覆盖
        // replacement 整个执行期, drain 才能保证 "所有 replacement 退出".
        ctx.intercept_leave = 1;
    }
    // else: miss, intercept_leave 保持 0 → tail-jump, 不回 thunk
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
        // Compiled helper -> orig() 递归时，top_quick_frame 指向 helper frame。
        // 直接识别 replacement frame 并放行原方法，避免 helper 调 orig 再次被替换。
        let frame_ptr = (top_qf & !1u64) & PAC_STRIP_MASK;
        if frame_ptr != 0 {
            let art_method_on_stack = std::ptr::read_volatile(frame_ptr as *const u64) & PAC_STRIP_MASK;
            if art_method_on_stack == replacement {
                return false;
            }
        }
        // top_quick_frame != NULL 且不是 replacement → 正常调用，执行替换
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
// callOriginal bypass — per-thread atomic stack, no libc pthread TLS
// ============================================================================

const BYPASS_THREAD_SLOTS: usize = 64;
const BYPASS_STACK_DEPTH: usize = 8;

static BYPASS_THREAD_IDS: [AtomicU64; BYPASS_THREAD_SLOTS] = [const { AtomicU64::new(0) }; BYPASS_THREAD_SLOTS];
static BYPASS_DEPTHS: [AtomicUsize; BYPASS_THREAD_SLOTS] = [const { AtomicUsize::new(0) }; BYPASS_THREAD_SLOTS];
static BYPASS_VALUES: [[AtomicU64; BYPASS_STACK_DEPTH]; BYPASS_THREAD_SLOTS] =
    [const { [const { AtomicU64::new(0) }; BYPASS_STACK_DEPTH] }; BYPASS_THREAD_SLOTS];

fn bypass_slot_for_current_thread(allocate: bool) -> Option<usize> {
    let id = crate::current_thread_id_u64();
    for i in 0..BYPASS_THREAD_SLOTS {
        if BYPASS_THREAD_IDS[i].load(Ordering::Acquire) == id {
            return Some(i);
        }
    }
    if !allocate {
        return None;
    }
    for i in 0..BYPASS_THREAD_SLOTS {
        if BYPASS_THREAD_IDS[i]
            .compare_exchange(0, id, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            BYPASS_DEPTHS[i].store(0, Ordering::Release);
            return Some(i);
        }
    }
    None
}

fn current_call_original_bypass() -> u64 {
    let Some(slot) = bypass_slot_for_current_thread(false) else {
        return 0;
    };
    let depth = BYPASS_DEPTHS[slot].load(Ordering::Acquire);
    if depth == 0 {
        return 0;
    }
    let idx = (depth - 1).min(BYPASS_STACK_DEPTH - 1);
    BYPASS_VALUES[slot][idx].load(Ordering::Acquire)
}

fn call_original_bypass_contains(method: u64) -> bool {
    if method == 0 {
        return false;
    }
    let Some(slot) = bypass_slot_for_current_thread(false) else {
        return false;
    };
    let depth = BYPASS_DEPTHS[slot].load(Ordering::Acquire).min(BYPASS_STACK_DEPTH);
    for i in 0..depth {
        if BYPASS_VALUES[slot][i].load(Ordering::Acquire) == method {
            return true;
        }
    }
    false
}

/// callOriginal 前调用：将 original ArtMethod 地址 push 到 bypass 栈
/// 支持嵌套：callback skip fallback 期间内层方法也可能 skip 并调用 invoke_original_jni
pub(crate) fn set_call_original_bypass(art_method: u64) {
    let Some(slot) = bypass_slot_for_current_thread(true) else {
        return;
    };
    let depth = BYPASS_DEPTHS[slot].load(Ordering::Acquire);
    let idx = depth.min(BYPASS_STACK_DEPTH - 1);
    BYPASS_VALUES[slot][idx].store(art_method, Ordering::Release);
    if depth < BYPASS_STACK_DEPTH {
        BYPASS_DEPTHS[slot].store(depth + 1, Ordering::Release);
    }
}

/// callOriginal 后调用：从 bypass 栈 pop（恢复外层 bypass）
pub(crate) fn clear_call_original_bypass() {
    let Some(slot) = bypass_slot_for_current_thread(false) else {
        return;
    };
    let depth = BYPASS_DEPTHS[slot].load(Ordering::Acquire);
    if depth == 0 {
        return;
    }
    let next = depth - 1;
    BYPASS_VALUES[slot][next.min(BYPASS_STACK_DEPTH - 1)].store(0, Ordering::Release);
    BYPASS_DEPTHS[slot].store(next, Ordering::Release);
    if next == 0 {
        BYPASS_THREAD_IDS[slot].store(0, Ordering::Release);
    }
}

pub(crate) fn get_interpreter_bridge() -> u64 {
    use super::art_method::ART_BRIDGE_FUNCTIONS;
    match ART_BRIDGE_FUNCTIONS.get() {
        Some(b) => b.quick_to_interpreter_bridge,
        None => 0,
    }
}

/// C-callable：art_router thunk + DoCall hook 调用，判断是否应该路由。
/// 返回 1 = 正常路由到 replacement，返回 0 = 跳过（callOriginal bypass 或 stack 递归 或 JS engine 繁忙）。
#[no_mangle]
pub unsafe extern "C" fn art_router_stack_check(replacement: u64) -> i32 {
    if art_controller_reload_paused() {
        return 0;
    }
    if hook_ffi::hook_managed_reentry_guard_active() != 0 {
        return 0;
    }
    let original_for_quick = hook_ffi::hook_art_router_table_lookup_original(replacement);
    if original_for_quick != 0 && crate::fast_hook::is_fast_hook(original_for_quick) {
        if call_original_bypass_contains(original_for_quick) {
            return 0;
        }
        return if should_replace_for_stack(replacement) { 1 } else { 0 };
    }

    let original_for_js = hook_ffi::hook_art_router_table_lookup_original(replacement);
    if hook_ffi::hook_art_router_table_lookup_mode_by_replacement(replacement) >= 4 {
        if original_for_js != 0 && call_original_bypass_contains(original_for_js) {
            return 0;
        }
        return if should_replace_for_stack(replacement) { 1 } else { 0 };
    }
    if !should_sample_original_method(original_for_js) {
        return 0;
    }

    // JS hook: JS engine busy 检测 + cooldown gate
    let current_thread = crate::current_thread_id_u64();
    let owner = crate::JS_ENGINE_OWNER_THREAD.load(std::sync::atomic::Ordering::Acquire);
    if owner == current_thread {
        // reentrant ($orig path)
    } else if owner != 0 {
        return 0; // JS 被别人占用
    } else {
        // 冷却期：gate 释放后 N 次调用全部 bypass，避免主线程频繁走 $orig JNI
        if GATE_COOLDOWN.load(std::sync::atomic::Ordering::Relaxed) > 0 {
            GATE_COOLDOWN.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            return 0;
        }
        // CAS gate: 只允许一个线程进入完整路径
        if JAVA_CALLBACK_GATE
            .compare_exchange(
                false,
                true,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Relaxed,
            )
            .is_err()
        {
            return 0;
        }
    }

    // Per-thread bypass stack: 检查栈中是否有 entry 匹配当前 replacement 的 original
    let original = hook_ffi::hook_art_router_table_lookup_original(replacement);
    if call_original_bypass_contains(original) {
        return 0; // callOriginal bypass
    }

    // Fallback: managed stack check (对标 Frida, 覆盖其他递归场景)
    if should_replace_for_stack(replacement) {
        1
    } else {
        0
    }
}

/// 上次见到的非空 ArtMethod* (PrettyMethod 防护用)
static LAST_SEEN_ART_METHOD: AtomicU64 = AtomicU64::new(0);

fn stack_replacement_source(method: u64) -> Option<u64> {
    if method == 0 {
        return None;
    }
    let guard = super::callback::JAVA_HOOK_REGISTRY.lock().ok()?;
    let registry = guard.as_ref()?;
    for data in registry.values() {
        match &data.hook_type {
            super::callback::HookType::NativeEntry => {}
            super::callback::HookType::Replaced { replacement_addr, .. } if *replacement_addr as u64 == method => {
                return Some(data.art_method)
            }
            super::callback::HookType::Quick {
                replacement_addr,
                declaring_class_source,
                ..
            } if *replacement_addr as u64 == method => {
                return Some(if *declaring_class_source != 0 {
                    *declaring_class_source
                } else {
                    data.art_method
                });
            }
            super::callback::HookType::Managed {
                replacement_art_method, ..
            } if *replacement_art_method == method => {
                return Some(data.art_method);
            }
            _ => {}
        }
    }
    None
}

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
        if let Some(source) = stack_replacement_source(method) {
            // Heap replacement/sentinel ArtMethods are not GC roots. PrettyMethod
            // must parse the real source method so it never follows stale clone metadata.
            ctx.x[0] = source;
            LAST_SEEN_ART_METHOD.store(source, Ordering::Relaxed);
        } else {
            let original = hook_ffi::hook_art_router_table_lookup_original(method);
            if original != 0 {
                ctx.x[0] = original;
                LAST_SEEN_ART_METHOD.store(original, Ordering::Relaxed);
            } else {
                LAST_SEEN_ART_METHOD.store(method, Ordering::Relaxed);
            }
        }
    }
}

/// GC / FixupStaticTrampolines on_leave 回调: 调用同步函数
unsafe extern "C" fn on_gc_sync_leave(_ctx_ptr: *mut hook_ffi::HookContext, _user_data: *mut std::ffi::c_void) {
    if art_controller_reload_paused() {
        return;
    }
    synchronize_replacement_methods();
}

/// RunFlipFunction on_enter 回调: 线程翻转期间同步
unsafe extern "C" fn on_gc_sync_enter(_ctx_ptr: *mut hook_ffi::HookContext, _user_data: *mut std::ffi::c_void) {
    if art_controller_reload_paused() {
        return;
    }
    synchronize_replacement_methods();
}

/// Fix 4: GetOatQuickMethodHeader replace-mode 回调
///
/// 对标 Frida (android.js:1981): **对 replacement ArtMethod 返回 NULL**。
/// NULL 让 ART StackVisitor 走 `IsNative()` 兜底路径，把 frame 标记为 native method,
/// Thread.getStackTrace() / Throwable.printStackTrace() 能显示
/// `className.methodName(Native method)`，和 Frida 行为一致。
///
/// 之前用全零 dummy header 规避 NULL deref, 副作用是 WalkStack 认为 header 有效
/// 但 code_size=0 → 整帧被 skip → 栈里看不到 replacement。
///
/// NULL deref 的兜底在 `walkstack_sigsegv_handler`：精准匹配 fault_addr == 0x18 的
/// OAT header 字段访问, 把寄存器指向 dummy buffer 重执行。Frida 用等价的
/// `fixupArtQuickDeliverExceptionBug` 做同样的事。
unsafe extern "C" fn on_get_oat_quick_method_header(
    ctx_ptr: *mut hook_ffi::HookContext,
    _user_data: *mut std::ffi::c_void,
) {
    if ctx_ptr.is_null() {
        return;
    }
    let ctx = &mut *ctx_ptr;
    let method = ctx.x[0]; // ArtMethod* this
    let pc = ctx.x[1];

    if hook_ffi::hook_is_in_exec_pool(pc) != 0 {
        if get_replacement_method(method).is_some() {
            GET_OAT_HOOK_POOL_ORIGINAL_COUNT.fetch_add(1, Ordering::Relaxed);
            GET_OAT_HOOK_POOL_LAST_METHOD.store(method, Ordering::Relaxed);
            GET_OAT_HOOK_POOL_LAST_PC.store(pc, Ordering::Relaxed);
        } else if is_replacement_method(method) {
            GET_OAT_HOOK_POOL_REPLACEMENT_COUNT.fetch_add(1, Ordering::Relaxed);
            GET_OAT_HOOK_POOL_LAST_METHOD.store(method, Ordering::Relaxed);
            GET_OAT_HOOK_POOL_LAST_PC.store(pc, Ordering::Relaxed);
        }

        // Any PC inside rustfrida's exec pool belongs to a trampoline/router,
        // not to ART-owned quick code. Let StackVisitor treat it as a native
        // frame; asking the real ArtMethod for an OAT header with a pool PC can
        // pair unrelated method metadata with our trampoline and crash in
        // PrettyMethod during SIGQUIT/ANR stack dumping.
        ctx.x[0] = 0;
        return;
    }

    if let Some(orig_pc) = crate::recomp::translate_recomp_to_orig(pc as usize) {
        let trampoline = ctx.trampoline;
        if !trampoline.is_null() {
            ctx.x[1] = orig_pc as u64;
            let result = hook_ffi::hook_invoke_trampoline(ctx_ptr, trampoline);
            (*ctx_ptr).x[0] = result;
        }
        return;
    }

    if is_replacement_method(method) || stack_replacement_source(method).is_some() {
        // replacement method → NULL (让 StackVisitor 走 IsNative 兜底)
        ctx.x[0] = 0;
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
unsafe fn synchronize_replacement_methods() {
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
    for (_, data) in registry.iter() {
        if matches!(data.hook_type, HookType::NativeEntry) {
            continue;
        }

        let art_method = data.art_method as usize;

        // --- Fix 1: declaring_class_ 同步 ---
        // 移动 GC 会更新原始 ArtMethod 的 declaring_class_ (offset 0, 4 bytes GcRoot)，
        // 堆分配的 replacement 不会被 GC 追踪，需要同步以防悬空引用。
        // Quick hooks use a Process.getElapsedCpuTime() sentinel as the stack-walk
        // method, so its declaring_class_/dex metadata must not be overwritten with
        // the hooked method's class.
        {
            let (replacement_addr, declaring_class_source) = match &data.hook_type {
                HookType::NativeEntry => (0, 0),
                HookType::Replaced { replacement_addr, .. } => (*replacement_addr, data.art_method),
                HookType::Quick {
                    replacement_addr,
                    declaring_class_source,
                    ..
                } => (
                    *replacement_addr,
                    if *declaring_class_source != 0 {
                        *declaring_class_source
                    } else {
                        data.art_method
                    },
                ),
                HookType::Managed { .. } => (0, 0),
            };
            if replacement_addr != 0 && declaring_class_source != 0 {
                let declaring_class = std::ptr::read_volatile(declaring_class_source as *const u32);
                std::ptr::write_volatile(replacement_addr as *mut u32, declaring_class);
            }
        }

        if data.hook_type.original_flags_mutated() {
            // --- flags 修复: 确保 kAccCompileDontBother 在 + kAccFastInterpreterToInterpreterInvoke 不在 ---
            let cdontbother = k_acc_compile_dont_bother();
            let flags = std::ptr::read_volatile((art_method + spec.access_flags_offset) as *const u32);
            let need_fix =
                (cdontbother != 0 && (flags & cdontbother) == 0) || (flags & K_ACC_FAST_INTERP_TO_INTERP) != 0;
            if need_fix {
                let fixed = (flags | cdontbother) & !K_ACC_FAST_INTERP_TO_INTERP;
                std::ptr::write_volatile((art_method + spec.access_flags_offset) as *mut u32, fixed);
            }
        }

        // Target ArtMethod.entry_point_/data_ are intentionally left untouched.
        // Shared ART entrypoints are covered by Layer 1/2 hooks; compiled entries
        // are covered by Layer 3 code hooks.
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
static WALKSTACK_GUARD_USING_SIGCHAIN: AtomicBool = AtomicBool::new(false);

fn arm64_load_unsigned_base_reg(inst: u32) -> Option<usize> {
    // LDR{B,H,W,X} unsigned immediate:
    //   size  opc  fixed
    //   xx    01   111001
    // Match all element sizes and only loads, then return Rn.
    if (inst & 0x3b40_0000) == 0x3940_0000 {
        let rn = ((inst >> 5) & 0x1f) as usize;
        if rn < 31 {
            return Some(rn);
        }
    }
    None
}

unsafe fn bionic_sigaction(sig: libc::c_int, act: *const libc::sigaction, oldact: *mut libc::sigaction) -> libc::c_int {
    let sym = module_dlsym("libc.so", "sigaction");
    if !sym.is_null() {
        type SigactionFn =
            unsafe extern "C" fn(libc::c_int, *const libc::sigaction, *mut libc::sigaction) -> libc::c_int;
        let sigaction_fn: SigactionFn = std::mem::transmute(sym);
        return sigaction_fn(sig, act, oldact);
    }
    libc::sigaction(sig, act, oldact)
}

// ============================================================================
// Managed DSL implicit suspend SIGSEGV fallback
// ============================================================================
//
// ART arm64 quick code implements implicit suspend checks with:
//   ldr x21, [x21]   // encoding 0xf94002b5
// The normal ART fault handler rewrites PC to art_quick_implicit_suspend and
// clears Thread::tlsPtr_.suspend_trigger. On JD, some JIT helper frames can
// fall through libsigchain to the app crash handler; that handler blocks, so
// SuspendAll eventually times out. Register as a libsigchain special handler
// and consume only this exact instruction as a fallback after ART's handler.

const INVALID_THREAD_OFFSET: u64 = u64::MAX;

#[repr(C)]
struct SigchainAction {
    sc_sigaction: Option<unsafe extern "C" fn(libc::c_int, *mut libc::siginfo_t, *mut libc::c_void) -> bool>,
    sc_mask: libc::sigset_t,
    sc_flags: u64,
}

static IMPLICIT_SUSPEND_ENTRYPOINT: AtomicU64 = AtomicU64::new(0);
static IMPLICIT_SUSPEND_TRIGGER_OFFSET: AtomicU64 = AtomicU64::new(INVALID_THREAD_OFFSET);
static IMPLICIT_SUSPEND_THREAD_CURRENT: AtomicU64 = AtomicU64::new(0);

fn resolve_suspend_poll_entrypoint() -> Option<usize> {
    let cached = IMPLICIT_SUSPEND_ENTRYPOINT.load(Ordering::Relaxed) as usize;
    if cached != 0 {
        return Some(cached);
    }

    let implicit = unsafe { libart_dlsym("art_quick_implicit_suspend") as usize };
    if implicit != 0 {
        IMPLICIT_SUSPEND_ENTRYPOINT.store(implicit as u64, Ordering::Relaxed);
        return Some(implicit);
    }

    let test_suspend = unsafe { super::java_fast_api::art_quick_test_suspend_entrypoint() as usize };
    if test_suspend != 0 {
        output_verbose(&format!(
            "[artController] art_quick_implicit_suspend 未导出，使用 quick test-suspend entrypoint={:#x}",
            test_suspend
        ));
        IMPLICIT_SUSPEND_ENTRYPOINT.store(test_suspend as u64, Ordering::Relaxed);
        return Some(test_suspend);
    }

    None
}

fn resolve_recomp_suspend_poll_entrypoint() -> Option<usize> {
    let test_suspend = unsafe { super::java_fast_api::art_quick_test_suspend_entrypoint() as usize };
    if test_suspend != 0 {
        let _ = crate::recomp::patch_suspend_polls(0, test_suspend);
        return Some(test_suspend);
    }
    let entry = resolve_suspend_poll_entrypoint()?;
    let _ = crate::recomp::patch_suspend_polls(0, entry);
    Some(entry)
}

fn arm64_self_ldr_reg(inst: u32) -> Option<usize> {
    // LDR Xt, [Xn, #0]. ART normally uses `ldr x21, [x21]` for implicit
    // suspend checks, but some generated helper code has shown up outside
    // ART's generated-code range accounting. Match the instruction shape and
    // then validate against Thread::tlsPtr_.suspend_trigger before handling.
    if (inst & 0xffc0_0000) != 0xf940_0000 {
        return None;
    }
    if ((inst >> 10) & 0x0fff) != 0 {
        return None;
    }
    let rn = ((inst >> 5) & 0x1f) as usize;
    let rt = (inst & 0x1f) as usize;
    if rn == rt {
        Some(rt)
    } else {
        None
    }
}

unsafe fn try_handle_managed_implicit_suspend(
    sig: libc::c_int,
    info: *mut libc::siginfo_t,
    context: *mut libc::c_void,
) -> bool {
    if sig != libc::SIGSEGV || info.is_null() || context.is_null() {
        return false;
    }

    let entry = IMPLICIT_SUSPEND_ENTRYPOINT.load(Ordering::Relaxed);
    let offset = IMPLICIT_SUSPEND_TRIGGER_OFFSET.load(Ordering::Relaxed);
    if entry == 0 || offset == INVALID_THREAD_OFFSET {
        return false;
    }

    let uc = context as *mut libc::ucontext_t;
    let mc = &mut (*uc).uc_mcontext;
    let pc = mc.pc & PAC_STRIP_MASK;
    if pc == 0 || (pc & 0x3) != 0 {
        return false;
    }

    let translated_pc = translate_recomp_to_orig_signal_safe(pc as usize);
    let instr_pc = translated_pc.unwrap_or(pc as usize);
    let inst = core::ptr::read_unaligned(instr_pc as *const u32);
    let poll_pc = if inst == 0xf940_02b5 {
        instr_pc
    } else {
        let next_instr_pc = instr_pc.wrapping_add(4);
        let next_inst = core::ptr::read_unaligned(next_instr_pc as *const u32);
        if next_inst == 0xf940_02b5 {
            next_instr_pc
        } else {
            return false;
        }
    };
    // AOSP arm64 SuspensionHandler matches this exact poll instruction:
    //   ldr x21, [x21]
    // Do not require extra Thread/suspend_trigger validation here. In boot/JIT
    // quick frames reached through recomp, that validation can be stale while
    // the instruction match is still definitive.
    let current_fn = IMPLICIT_SUSPEND_THREAD_CURRENT.load(Ordering::Relaxed);
    let thread = if current_fn != 0 {
        let thread_current: unsafe extern "C" fn() -> u64 = core::mem::transmute(current_fn as usize);
        thread_current() & PAC_STRIP_MASK
    } else {
        mc.regs[19] & PAC_STRIP_MASK
    };
    if thread != 0 && (thread & 0x7) == 0 {
        let suspend_trigger_addr = thread.wrapping_add(offset);
        core::ptr::write(suspend_trigger_addr as *mut u64, suspend_trigger_addr);
        mc.regs[19] = thread;
    }

    // ART saves LR in the implicit-suspend callee-save frame and later uses it
    // as the quick frame PC while visiting GC roots. If this stays as the
    // anonymous recomp PC, StackVisitor can pair the original OAT header with a
    // recomp PC and decode the wrong stack-map offset. Keep execution semantics
    // equivalent by resuming at the original OAT instruction after the poll.
    mc.regs[30] = (poll_pc as u64).wrapping_add(4);
    mc.pc = entry;
    true
}

unsafe fn install_managed_implicit_suspend_guard(spec: &ArtThreadSpec) {
    let entry = libart_dlsym("art_quick_implicit_suspend") as u64;
    let thread_current = libart_dlsym("_ZN3art6Thread7CurrentEv") as u64;
    if entry == 0 {
        output_verbose(&format!(
            "[artController] implicit suspend guard 跳过: art_quick_implicit_suspend={:#x}",
            entry
        ));
        return;
    }

    IMPLICIT_SUSPEND_ENTRYPOINT.store(entry, Ordering::Relaxed);
    IMPLICIT_SUSPEND_TRIGGER_OFFSET.store(spec.suspend_trigger_offset as u64, Ordering::Relaxed);
    IMPLICIT_SUSPEND_THREAD_CURRENT.store(thread_current, Ordering::Relaxed);

    output_verbose(&format!(
        "[artController] implicit suspend guard 已配置: entry={:#x}, thread_current={:#x}, suspend_trigger_offset={} (复用 WalkStack SIGSEGV guard)",
        entry, thread_current, spec.suspend_trigger_offset
    ));
}

unsafe fn uninstall_managed_implicit_suspend_guard() {
    IMPLICIT_SUSPEND_ENTRYPOINT.store(0, Ordering::Relaxed);
    IMPLICIT_SUSPEND_TRIGGER_OFFSET.store(INVALID_THREAD_OFFSET, Ordering::Relaxed);
    IMPLICIT_SUSPEND_THREAD_CURRENT.store(0, Ordering::Relaxed);
}

unsafe extern "C" fn walkstack_sigsegv_handler(
    sig: libc::c_int,
    info: *mut libc::siginfo_t,
    context: *mut libc::c_void,
) {
    unsafe fn chain_prev_sigsegv(sig: libc::c_int, info: *mut libc::siginfo_t, context: *mut libc::c_void) {
        let prev = std::ptr::addr_of!(PREV_SIGSEGV_ACTION);
        let prev_handler = std::ptr::addr_of!((*prev).sa_sigaction).read();
        if std::ptr::addr_of!((*prev).sa_flags).read() & libc::SA_SIGINFO != 0 {
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

    if try_handle_managed_implicit_suspend(sig, info, context) {
        return;
    }

    if sig == libc::SIGSEGV && !context.is_null() {
        let uc = context as *mut libc::ucontext_t;
        let mc = &mut (*uc).uc_mcontext;
        let pc = mc.pc & PAC_STRIP_MASK;
        if let Some(orig_pc) = translate_recomp_to_orig_signal_safe(pc as usize) {
            // Let ART's real FaultManager see the original OAT PC for all
            // implicit checks/exceptions. This preserves its native handling
            // for suspend, null checks, stack overflow, etc., while avoiding
            // recomp PCs in stack-map calculations.
            mc.pc = orig_pc as u64;
            chain_prev_sigsegv(sig, info, context);
            if mc.pc == orig_pc as u64 {
                mc.pc = pc;
            }
            return;
        }
    }

    if try_handle_walkstack_null_oat_header(sig, info, context) {
        return;
    }

    // 不是我们关心的场景 → chain 到旧 handler
    chain_prev_sigsegv(sig, info, context);
}

unsafe fn try_handle_walkstack_null_oat_header(
    sig: libc::c_int,
    info: *mut libc::siginfo_t,
    context: *mut libc::c_void,
) -> bool {
    if sig != libc::SIGSEGV || info.is_null() || context.is_null() {
        return false;
    }

    let fault_addr = (*info).si_addr() as u64;
    // 精准匹配 NULL OatQuickMethodHeader 前 64 字节访问。旧路径只见过
    // NULL+0x18 且 base 固定为 X10；API 36 的 DecodeGcMasksOnly 也会从
    // NULL+0x0 读取。按当前 LDR 指令解码 base 寄存器，确认其值为 0 后
    // 指向全零 dummy header，返回后重执行同一条 load。
    if fault_addr >= DUMMY_OAT_HEADER_BUF.len() as u64 {
        return false;
    }

    let uc = context as *mut libc::ucontext_t;
    let mc = &mut (*uc).uc_mcontext;
    let pc = mc.pc & PAC_STRIP_MASK;
    if pc != 0 && (pc & 0x3) == 0 {
        let inst = core::ptr::read_unaligned(pc as *const u32);
        if let Some(rn) = arm64_load_unsigned_base_reg(inst) {
            let regs = &mut mc.regs;
            if regs[rn] == 0 {
                regs[rn] = DUMMY_OAT_HEADER_BUF.as_ptr() as u64;
                return true;
            }
        }
    }

    // Fallback for the original known pattern, in case the compiler used a
    // load form not covered by the unsigned-immediate decoder above.
    if fault_addr == 0x18 {
        let regs = &mut mc.regs;
        if regs[10] == 0 {
            regs[10] = DUMMY_OAT_HEADER_BUF.as_ptr() as u64;
            return true;
        }
    }

    false
}

unsafe extern "C" fn walkstack_sigchain_handler(
    sig: libc::c_int,
    info: *mut libc::siginfo_t,
    context: *mut libc::c_void,
) -> bool {
    try_handle_managed_implicit_suspend(sig, info, context) || try_handle_walkstack_null_oat_header(sig, info, context)
}

unsafe extern "C" fn on_decode_gc_masks_only_enter(ctx: *mut hook_ffi::HookContext, _user_data: *mut std::ffi::c_void) {
    if !ctx.is_null() && (*ctx).x[0] == 0 {
        (*ctx).x[0] = DUMMY_OAT_HEADER_BUF.as_ptr() as u64;
    }
}

unsafe fn find_decode_gc_masks_only_entry() -> u64 {
    if let Some((name, addr)) = libart_find_symbol_contains("DecodeGcMasksOnly") {
        output_verbose(&format!(
            "[artController] DecodeGcMasksOnly symbol wildcard hit: {} @ {:#x}",
            name, addr
        ));
        return addr;
    }

    0
}

unsafe fn find_decode_gc_masks_only_header_load() -> u64 {
    // Android 16 / API 36 libart DecodeGcMasksOnly prologue through the first
    // OatQuickMethodHeader load. Keep the prologue in the signature; the tail
    // alone also appears in GetOatQuickMethodHeader and would patch the wrong
    // site.
    const PATTERN: &[u8] = &[
        0xff, 0x43, 0x07, 0xd1, 0xfd, 0x7b, 0x1a, 0xa9, 0xfc, 0x57, 0x1b, 0xa9, 0xf4, 0x4f, 0x1c, 0xa9, 0xfd, 0x83,
        0x06, 0x91, 0x54, 0xd0, 0x3b, 0xd5, 0xf3, 0x03, 0x08, 0xaa, 0x00, 0xe4, 0x00, 0x6f, 0x88, 0x16, 0x40, 0xf9,
        0xe2, 0x03, 0x1f, 0xaa, 0xf5, 0x03, 0x00, 0x91, 0xa8, 0x83, 0x1f, 0xf8, 0x08, 0x00, 0x40, 0xb9,
    ];

    let Some(maps) = read_proc_self_maps() else {
        return 0;
    };

    let mut best = 0u64;
    for entry in proc_maps_entries(&maps) {
        let Some(path) = entry.path else {
            continue;
        };
        if !path.ends_with("/libart.so") || !entry.perms.starts_with("r-x") {
            continue;
        }
        let len = entry.end.saturating_sub(entry.start) as usize;
        if len < PATTERN.len() {
            continue;
        }
        let bytes = core::slice::from_raw_parts(entry.start as *const u8, len);
        for (off, window) in bytes.windows(PATTERN.len()).enumerate() {
            if window == PATTERN {
                best = entry.start + off as u64 + (PATTERN.len() as u64 - 4);
            }
        }
    }

    best
}

unsafe fn install_decode_gc_masks_only_null_guard() -> u64 {
    let load_target = find_decode_gc_masks_only_header_load();
    if load_target == 0 {
        output_verbose("[artController] DecodeGcMasksOnly NULL guard 跳过: pattern not found");
        return 0;
    }

    let Some((ha, sf, real_addr)) =
        prepare_hook_target_strict("DecodeGcMasksOnly NULL guard", load_target, std::ptr::null_mut())
    else {
        return 0;
    };
    let ret = hook_ffi::hook_attach(
        ha as *mut std::ffi::c_void,
        Some(on_decode_gc_masks_only_enter),
        None,
        std::ptr::null_mut(),
        sf,
    );
    if ret == 0 {
        if !try_fixup_trampoline(hook_ffi::hook_get_trampoline(ha as *mut std::ffi::c_void), real_addr) {
            let _ = hook_ffi::hook_remove(ha as *mut std::ffi::c_void);
            return 0;
        }
        output_verbose(&format!(
            "[artController] DecodeGcMasksOnly NULL guard 安装成功: load={:#x} (hooked={:#x})",
            load_target, ha
        ));
        ha
    } else {
        output_verbose(&format!(
            "[artController] DecodeGcMasksOnly NULL guard 安装失败: load={:#x}, ret={}",
            load_target, ret
        ));
        0
    }
}

unsafe fn install_walkstack_sigsegv_guard() {
    if WALKSTACK_GUARD_INSTALLED.swap(true, Ordering::SeqCst) {
        return;
    }

    let add = module_dlsym("libsigchain.so", "AddSpecialSignalHandlerFn");
    let ensure_front = module_dlsym("libsigchain.so", "EnsureFrontOfChain");
    if !add.is_null() {
        let mut action: SigchainAction = std::mem::zeroed();
        action.sc_sigaction = Some(walkstack_sigchain_handler);
        libc::sigemptyset(&mut action.sc_mask);
        action.sc_flags = 0;

        type AddSpecialSignalHandlerFn = unsafe extern "C" fn(libc::c_int, *mut SigchainAction);
        let add_fn: AddSpecialSignalHandlerFn = std::mem::transmute(add);
        add_fn(libc::SIGSEGV, &mut action as *mut SigchainAction);

        if !ensure_front.is_null() {
            type EnsureFrontOfChainFn = unsafe extern "C" fn(libc::c_int);
            let ensure_front_fn: EnsureFrontOfChainFn = std::mem::transmute(ensure_front);
            ensure_front_fn(libc::SIGSEGV);
        }

        WALKSTACK_GUARD_USING_SIGCHAIN.store(true, Ordering::SeqCst);
        output_verbose("[artController] WalkStack SIGSEGV guard 已安装 (libsigchain)");
        return;
    }

    let mut sa: libc::sigaction = std::mem::zeroed();
    sa.sa_sigaction = walkstack_sigsegv_handler as *const () as usize;
    sa.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK;
    libc::sigemptyset(&mut sa.sa_mask);

    let ret = bionic_sigaction(libc::SIGSEGV, &sa, std::ptr::addr_of_mut!(PREV_SIGSEGV_ACTION));
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

unsafe fn uninstall_walkstack_sigsegv_guard() {
    let installed = WALKSTACK_GUARD_INSTALLED.swap(false, Ordering::SeqCst);
    let using_sigchain = WALKSTACK_GUARD_USING_SIGCHAIN.swap(false, Ordering::SeqCst);

    if using_sigchain {
        let remove = module_dlsym("libsigchain.so", "RemoveSpecialSignalHandlerFn");
        if !remove.is_null() {
            type RemoveSpecialSignalHandlerFn = unsafe extern "C" fn(
                libc::c_int,
                unsafe extern "C" fn(libc::c_int, *mut libc::siginfo_t, *mut libc::c_void) -> bool,
            );
            let remove_fn: RemoveSpecialSignalHandlerFn = std::mem::transmute(remove);
            remove_fn(libc::SIGSEGV, walkstack_sigchain_handler);
            output_verbose("[artController] WalkStack SIGSEGV guard 已卸载 (libsigchain)");
        } else {
            output_verbose("[artController] WalkStack SIGSEGV guard 卸载失败: RemoveSpecialSignalHandlerFn not found");
        }
        return;
    }

    if !installed {
        return;
    }

    let ret = bionic_sigaction(libc::SIGSEGV, std::ptr::addr_of!(PREV_SIGSEGV_ACTION), std::ptr::null_mut());
    if ret == 0 {
        std::ptr::addr_of_mut!(PREV_SIGSEGV_ACTION).write(std::mem::zeroed());
        output_verbose("[artController] WalkStack SIGSEGV guard 已卸载");
    } else {
        output_verbose(&format!(
            "[artController] WalkStack SIGSEGV guard 卸载失败: {}",
            std::io::Error::last_os_error()
        ));
    }
}

pub(crate) unsafe fn refresh_walkstack_sigsegv_guard() {
    if WALKSTACK_GUARD_USING_SIGCHAIN.load(Ordering::SeqCst) {
        let ensure_front = module_dlsym("libsigchain.so", "EnsureFrontOfChain");
        if !ensure_front.is_null() {
            type EnsureFrontOfChainFn = unsafe extern "C" fn(libc::c_int);
            let ensure_front_fn: EnsureFrontOfChainFn = std::mem::transmute(ensure_front);
            ensure_front_fn(libc::SIGSEGV);
        }
        return;
    }

    let mut current: libc::sigaction = std::mem::zeroed();
    if bionic_sigaction(libc::SIGSEGV, std::ptr::null(), &mut current) != 0 {
        return;
    }
    if current.sa_sigaction == walkstack_sigsegv_handler as *const () as usize {
        return;
    }

    let mut sa: libc::sigaction = std::mem::zeroed();
    sa.sa_sigaction = walkstack_sigsegv_handler as *const () as usize;
    sa.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK;
    libc::sigemptyset(&mut sa.sa_mask);

    let mut previous: libc::sigaction = std::mem::zeroed();
    if bionic_sigaction(libc::SIGSEGV, &sa, &mut previous) == 0 {
        PREV_SIGSEGV_ACTION = previous;
        WALKSTACK_GUARD_INSTALLED.store(true, Ordering::SeqCst);
    }
}

// ============================================================================
// 清理
// ============================================================================

/// Phase 1 - 切断所有 "路由入口" 类 hook，阻止新 thunk 进入。
///
/// 包含 Layer1 (shared stub) / Layer2 (DoCall) / GC 同步 / FixupStaticTrampolines。
/// 这些 hook 要么把调用 route 进 thunk，要么在 GC/class-init 里把 entry_point
/// 重写回 thunk —— 不切掉它们，drain 永远追不上 inflow。
///
/// 刻意不动 OAT header / PrettyMethod / 内联 OAT patch 等 walkstack 防护 ——
/// 它们要在 drain=0 之后、pool munmap 之前才 cut (见 cut_art_controller_walkstack_guards)。
pub fn cut_art_controller_routing_hooks() {
    super::callback::cut_raw_clone_executor_loop_hook();

    let targets: Vec<(&'static str, u64)> = {
        let guard = ART_CONTROLLER.lock().unwrap_or_else(|e| e.into_inner());
        let state = match guard.as_ref() {
            Some(s) => s,
            None => return,
        };
        let mut all: Vec<(&str, u64)> = Vec::new();
        for &addr in &state.shared_stub_targets {
            all.push(("Layer1", addr));
        }
        for &addr in &state.do_call_targets {
            all.push(("Layer2", addr));
        }
        for &addr in &state.gc_hook_targets {
            all.push(("GC", addr));
        }
        if state.fixup_hook_target != 0 {
            all.push(("Fixup", state.fixup_hook_target));
        }
        all
    };

    if targets.is_empty() {
        return;
    }

    output_verbose(&format!(
        "[artController] cut routing: {} 个 hook_remove (Layer1/2/GC/Fixup)",
        targets.len()
    ));

    for (label, addr) in &targets {
        unsafe {
            remove_art_controller_hook(label, *addr);
        }
    }
}

unsafe fn remove_art_controller_hook(label: &str, addr: u64) {
    let reverted = crate::recomp::try_revert_slot_patch_by_slot(addr as usize);
    if reverted {
        output_verbose(&format!(
            "[artController] {} reverted recomp slot branch for target={:#x}",
            label, addr
        ));
    }
    let ret = hook_ffi::hook_remove(addr as *mut std::ffi::c_void);
    if ret != 0 {
        output_verbose(&format!(
            "[artController] {} hook_remove failed target={:#x} ret={}",
            label, addr, ret
        ));
    }
}

/// Phase 3 - 切断 walkstack 防护类 hook (drain=0 之后才安全)。
///
/// 包含 OAT header replace / PrettyMethod / 内联 OAT header patch。
/// 这些 hook 本身不路由进 thunk，只是让 ART WalkStack 在看到 thunk frame 时不 abort。
/// 在 drain 归零 (栈上无任何 thunk PC) 之后才能 cut。
pub fn cut_art_controller_walkstack_guards() {
    let targets: Vec<(&'static str, u64)> = {
        let guard = ART_CONTROLLER.lock().unwrap_or_else(|e| e.into_inner());
        let mut all: Vec<(&str, u64)> = Vec::new();
        if let Some(state) = guard.as_ref() {
            if state.oat_header_hook_target != 0 {
                all.push(("OatHeader", state.oat_header_hook_target));
            }
            if state.pretty_method_hook_target != 0 {
                all.push(("PrettyMethod", state.pretty_method_hook_target));
            }
            if state.decode_gc_masks_hook_target != 0 {
                all.push(("DecodeGcMasks", state.decode_gc_masks_hook_target));
            }
        }
        all
    };

    if !targets.is_empty() {
        output_verbose(&format!(
            "[artController] cut walkstack guards: {} 个 hook_remove",
            targets.len()
        ));
        for (label, addr) in &targets {
            unsafe {
                remove_art_controller_hook(label, *addr);
            }
        }
    }

    // 恢复内联 OAT header patch (直写的内联检查代码)
    unsafe {
        let restored = hook_ffi::hook_restore_inlined_oat_header_patches();
        if restored > 0 {
            output_verbose(&format!("[artController] 恢复 {} 个内联 OAT patch", restored));
        }
        uninstall_walkstack_sigsegv_guard();
        uninstall_managed_implicit_suspend_guard();
    }
}

/// 兼容旧调用：路由 + walkstack 防护一起 cut。
/// 新代码请分阶段调用 cut_art_controller_routing_hooks / cut_art_controller_walkstack_guards。
pub fn cut_art_controller_hooks() {
    cut_art_controller_routing_hooks();
    cut_art_controller_walkstack_guards();
}

/// Phase 3 - 释放 art_controller 状态 + 恢复 instrumentation (drain 之后)。
pub fn free_art_controller_state() {
    unsafe {
        restore_forced_interpret_only();
    }

    let taken = {
        let mut guard = ART_CONTROLLER.lock().unwrap_or_else(|e| e.into_inner());
        guard.take()
    };
    if taken.is_some() {
        JNI_TRAMPOLINE_BYPASS.store(0, Ordering::Release);
        LAST_SEEN_ART_METHOD.store(0, Ordering::Relaxed);
        output_verbose("[artController] 全局 ART hook 状态已释放");
    }
}

/// 兼容旧调用：cut → free 一次性做完。新代码请按 phase 排程。
pub(super) fn cleanup_art_controller() {
    cut_art_controller_hooks();
    free_art_controller_state();
}
