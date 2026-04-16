// ============================================================================
// ART bridge functions — ART internal trampoline addresses
// ============================================================================

/// ART 内部桥接函数地址集合
/// 当前仅使用 quick_generic_jni_trampoline，其余保留以备后用
#[allow(dead_code)]
pub(super) struct ArtBridgeFunctions {
    /// art_quick_generic_jni_trampoline — JNI native method 分发入口
    pub(super) quick_generic_jni_trampoline: u64,
    /// art_quick_to_interpreter_bridge — 编译代码到解释器的桥接
    pub(super) quick_to_interpreter_bridge: u64,
    /// art_quick_resolution_trampoline — 方法解析 trampoline
    pub(super) quick_resolution_trampoline: u64,
    /// art_quick_imt_conflict_trampoline — 接口方法分发冲突 trampoline
    pub(super) quick_imt_conflict_trampoline: u64,
    /// Nterp 解释器入口点（Android 12+），0 表示不可用
    pub(super) nterp_entry_point: u64,
    /// art::interpreter::DoCall<> 模板实例地址（最多4个）
    pub(super) do_call_addrs: Vec<u64>,
    /// GC 同步: ConcurrentCopying::CopyingPhase 地址，0 表示不可用
    pub(super) gc_copying_phase: u64,
    /// GC 同步: Heap::CollectGarbageInternal 地址，0 表示不可用
    pub(super) gc_collect_internal: u64,
    /// GC 同步: Thread::RunFlipFunction 地址，0 表示不可用
    pub(super) run_flip_function: u64,
    /// ArtMethod::GetOatQuickMethodHeader 地址，0 表示不可用
    pub(super) get_oat_quick_method_header: u64,
    /// ClassLinker::FixupStaticTrampolines / MakeInitializedClassesVisiblyInitialized 地址，0 表示不可用
    pub(super) fixup_static_trampolines: u64,
    /// art::Thread::Current() 函数地址，用于递归防护中获取当前线程
    pub(super) thread_current: u64,
    /// ArtMethod::PrettyMethod 函数地址，用于 NULL 指针崩溃防护
    pub(super) pretty_method: u64,
    /// 从 trampoline 解析出的真实 quick entrypoint（用于 entrypoint 比较）
    /// trampoline 通常是一条 LDR Xn, [Thread, #offset] 指令，实际入口在 Thread TLS 中
    pub(super) resolved_jni_entrypoint: u64,
    pub(super) resolved_interpreter_bridge_entrypoint: u64,
    pub(super) resolved_resolution_entrypoint: u64,
}

unsafe impl Send for ArtBridgeFunctions {}
unsafe impl Sync for ArtBridgeFunctions {}

/// 全局缓存的 ART bridge 函数地址
pub(super) static ART_BRIDGE_FUNCTIONS: std::sync::OnceLock<ArtBridgeFunctions> =
    std::sync::OnceLock::new();

/// 从 trampoline 地址解析真实的 quick entrypoint。
///
/// ART trampoline 的第一条指令通常是 `LDR Xn, [Xm, #offset]`，
/// 从 Thread TLS 中加载真实入口点地址。本函数读取该指令，提取 offset，
/// 然后通过 JNIEnv → Thread* 读取实际入口点。
///
/// 如果第一条指令不是 LDR 格式或 trampoline 为 0，则返回 trampoline 本身（fallback）。
unsafe fn resolve_quick_entrypoint_from_trampoline(trampoline: u64, env: JniEnv) -> u64 {
    if trampoline == 0 {
        return 0;
    }

    // 读取 trampoline 地址处的第一条 ARM64 指令
    let insn = *(trampoline as *const u32);

    // 检查是否是 LDR Xn, [Xm, #imm] 格式 (unsigned offset)
    // 编码: 1111 1001 01xx xxxx xxxx xxxx xxxx xxxx
    // mask: FFC0_0000, expected: F940_0000
    if (insn & 0xFFC0_0000) != 0xF940_0000 {
        // 不是 LDR 指令，返回 trampoline 本身
        return trampoline;
    }

    // 提取 imm12 (bits [21:10])，单位为 8 字节（64 位 LDR 的 scale）
    let imm12 = ((insn >> 10) & 0xFFF) as u64;
    let offset = imm12 * 8;

    // 从 JNIEnv 获取 Thread*: *(env + 8) 即 JNIEnvExt.self_
    let thread = *((env as usize + 8) as *const u64) & PAC_STRIP_MASK;
    if thread == 0 {
        return trampoline;
    }

    // 读取 *(thread + offset) 作为 resolved entrypoint
    let resolved = *((thread as usize + offset as usize) as *const u64) & PAC_STRIP_MASK;
    if resolved != 0 {
        output_verbose(&format!(
            "[art bridge] 解析 trampoline {:#x} → Thread+{:#x} → entrypoint {:#x}",
            trampoline, offset, resolved
        ));
        resolved
    } else {
        trampoline
    }
}

/// 发现并缓存所有 ART 内部桥接函数地址。
///
/// 策略:
/// 1. ClassLinker 扫描: 一次扫描提取 quick_generic_jni_trampoline、
///    quick_to_interpreter_bridge、quick_resolution_trampoline
/// 2. dlsym: GetNterpEntryPoint（调用它获取 nterp 入口）、DoCall 模板实例、
///    ConcurrentCopying::CopyingPhase
pub(super) unsafe fn find_art_bridge_functions(
    env: JniEnv,
    _ep_offset: usize,
) -> &'static ArtBridgeFunctions {
    ART_BRIDGE_FUNCTIONS.get_or_init(|| {
        output_verbose("[art bridge] 开始发现 ART 内部桥接函数...");

        // --- ClassLinker 扫描: 一次提取 4 个 trampoline ---
        let (jni_tramp, interp_bridge, resolution_tramp, imt_conflict) = find_classlinker_trampolines(env);

        output_verbose(&format!(
            "[art bridge] ClassLinker 结果: jni_tramp={:#x}, interp_bridge={:#x}, resolution_tramp={:#x}, imt_conflict={:#x}",
            jni_tramp, interp_bridge, resolution_tramp, imt_conflict
        ));

        // --- dlsym: Nterp 入口点 ---
        let nterp = find_nterp_entry_point();
        output_verbose(&format!("[art bridge] nterp_entry_point={:#x}", nterp));

        // --- dlsym: DoCall 模板实例 ---
        let do_calls = find_do_call_symbols();
        output_verbose(&format!("[art bridge] DoCall 实例数={}", do_calls.len()));
        for (i, addr) in do_calls.iter().enumerate() {
            output_verbose(&format!("[art bridge]   DoCall[{}]={:#x}", i, addr));
        }

        // --- dlsym: GC ConcurrentCopying::CopyingPhase ---
        let gc_phase = find_gc_copying_phase();
        output_verbose(&format!("[art bridge] gc_copying_phase={:#x}", gc_phase));

        // --- dlsym: Heap::CollectGarbageInternal ---
        let gc_collect = find_gc_collect_internal();
        output_verbose(&format!("[art bridge] gc_collect_internal={:#x}", gc_collect));

        // --- dlsym: Thread::RunFlipFunction ---
        let run_flip = find_run_flip_function();
        output_verbose(&format!("[art bridge] run_flip_function={:#x}", run_flip));

        // --- dlsym: ArtMethod::GetOatQuickMethodHeader ---
        let get_oat_header = find_get_oat_quick_method_header();
        output_verbose(&format!("[art bridge] get_oat_quick_method_header={:#x}", get_oat_header));

        // --- dlsym: FixupStaticTrampolines / MakeInitializedClassesVisiblyInitialized ---
        let fixup_static = find_fixup_static_trampolines();
        output_verbose(&format!("[art bridge] fixup_static_trampolines={:#x}", fixup_static));

        // --- dlsym: Thread::Current() (递归防护用) ---
        let thread_current = find_thread_current();
        output_verbose(&format!("[art bridge] thread_current={:#x}", thread_current));

        // --- dlsym: ArtMethod::PrettyMethod (NULL 指针崩溃防护) ---
        let pretty_method = find_pretty_method();
        output_verbose(&format!("[art bridge] pretty_method={:#x}", pretty_method));

        // --- 解析 trampoline → 真实 quick entrypoint ---
        let resolved_jni = resolve_quick_entrypoint_from_trampoline(jni_tramp, env);
        let resolved_interp = resolve_quick_entrypoint_from_trampoline(interp_bridge, env);
        let resolved_resolution = resolve_quick_entrypoint_from_trampoline(resolution_tramp, env);

        output_verbose(&format!(
            "[art bridge] resolved entrypoints: jni={:#x}, interp={:#x}, resolution={:#x}",
            resolved_jni, resolved_interp, resolved_resolution
        ));

        output_verbose("[art bridge] ART 桥接函数发现完成");

        ArtBridgeFunctions {
            quick_generic_jni_trampoline: jni_tramp,
            quick_to_interpreter_bridge: interp_bridge,
            quick_resolution_trampoline: resolution_tramp,
            quick_imt_conflict_trampoline: imt_conflict,
            nterp_entry_point: nterp,
            do_call_addrs: do_calls,
            gc_copying_phase: gc_phase,
            gc_collect_internal: gc_collect,
            run_flip_function: run_flip,
            get_oat_quick_method_header: get_oat_header,
            fixup_static_trampolines: fixup_static,
            thread_current,
            pretty_method,
            resolved_jni_entrypoint: resolved_jni,
            resolved_interpreter_bridge_entrypoint: resolved_interp,
            resolved_resolution_entrypoint: resolved_resolution,
        }
    })
}

/// 通过 ClassLinker 结构体扫描提取 3 个 ART trampoline 地址。
///
/// ClassLinker 布局 (Android 6+, 以 intern_table_ 为锚点):
///   intern_table_
///   quick_resolution_trampoline_            +1*8
///   quick_imt_conflict_trampoline_          +2*8
///   ... (delta 变量取决于 API 级别)
///   quick_generic_jni_trampoline_           +(delta)*8
///   quick_to_interpreter_bridge_trampoline_ +(delta+1)*8
///
/// 返回 (quick_generic_jni_trampoline, quick_to_interpreter_bridge, quick_resolution_trampoline, quick_imt_conflict_trampoline)
unsafe fn find_classlinker_trampolines(_env: JniEnv) -> (u64, u64, u64, u64) {
    // --- Strategy 1: dlsym (可能在某些 Android 构建中可用) ---
    // 注意: art_quick_* 符号通常是 LOCAL HIDDEN，dlsym 一般找不到
    // 通过 unrestricted API 查找（soinfo 摘除后 libc::dlsym 会崩溃）
    let jni_sym = crate::jsapi::module::libart_dlsym("art_quick_generic_jni_trampoline");
    let interp_sym = crate::jsapi::module::libart_dlsym("art_quick_to_interpreter_bridge");
    let resolution_sym = crate::jsapi::module::libart_dlsym("art_quick_resolution_trampoline");
    let imt_sym = crate::jsapi::module::libart_dlsym("art_quick_imt_conflict_trampoline");

    if !jni_sym.is_null() && !interp_sym.is_null() && !resolution_sym.is_null() {
        output_verbose("[art bridge] 全部通过 dlsym 发现");
        return (
            jni_sym as u64,
            interp_sym as u64,
            resolution_sym as u64,
            imt_sym as u64,
        );
    }

    // --- Strategy 2: ClassLinker 扫描 (主要策略) ---
    // art_quick_* 是 LOCAL HIDDEN 符号，APEX namespace 限制下 dlsym 找不到
    // 必须通过 ClassLinker 结构体内存扫描获取
    output_verbose("[art bridge] dlsym 未能获取全部地址，尝试 ClassLinker 扫描...");

    let (runtime, java_vm_off) = match find_runtime_java_vm() {
        Some(v) => v,
        None => {
            output_verbose("[art bridge] ClassLinker 扫描: 无法获取 Runtime/java_vm_ 偏移");
            return (
                jni_sym as u64,
                interp_sym as u64,
                resolution_sym as u64,
                imt_sym as u64,
            );
        }
    };

    output_verbose(&format!(
        "[art bridge] Runtime={:#x}, java_vm_ 在 Runtime+{:#x}",
        runtime, java_vm_off
    ));

    let api_level = get_android_api_level();
    let codename = get_android_codename();
    output_verbose(&format!(
        "[art bridge] Android API level: {}, codename: '{}'",
        api_level, codename
    ));

    let class_linker_candidates = compute_classlinker_candidates(java_vm_off);

    // find_runtime_java_vm 已经调用了 refresh_mem_regions()

    for &cl_off in &class_linker_candidates {
        let class_linker = safe_read_u64(runtime + cl_off as u64) & PAC_STRIP_MASK;
        if class_linker == 0 {
            continue;
        }

        let intern_table_off = cl_off - 8;
        let intern_table = safe_read_u64(runtime + intern_table_off as u64) & PAC_STRIP_MASK;
        if intern_table == 0 {
            continue;
        }

        output_verbose(&format!(
            "[art bridge] 候选: classLinker={:#x} (Runtime+{:#x}), internTable={:#x} (Runtime+{:#x})",
            class_linker, cl_off, intern_table, intern_table_off
        ));

        // 在 ClassLinker 中扫描 intern_table_ 指针作为锚点
        let cl_scan_start = 200usize;
        let cl_scan_end = cl_scan_start + 800;

        let mut intern_table_cl_offset: Option<usize> = None;
        for offset in (cl_scan_start..cl_scan_end).step_by(8) {
            let val = safe_read_u64(class_linker + offset as u64);
            let val_stripped = val & PAC_STRIP_MASK;
            if val_stripped == intern_table {
                intern_table_cl_offset = Some(offset);
                output_verbose(&format!(
                    "[art bridge] 找到 intern_table_ 在 ClassLinker+{:#x}",
                    offset
                ));
                break;
            }
        }

        let it_off = match intern_table_cl_offset {
            Some(o) => o,
            None => {
                output_verbose("[art bridge] 此候选 ClassLinker 中未找到 intern_table_");
                continue;
            }
        };

        // 根据 API 级别计算 delta (intern_table_ 到 quick_generic_jni_trampoline_ 的字段数)
        let delta: usize = if api_level >= 30 || codename == "R" {
            6
        } else if api_level >= 29 {
            4
        } else if api_level >= 23 {
            3
        } else {
            5 // Android 5.x: portable_resolution/imt_conflict/to_interpreter trampolines
        };

        // 提取四个 trampoline 地址
        let jni_tramp_off = it_off + delta * 8;
        let interp_bridge_off = jni_tramp_off + 8;
        // imt_conflict trampoline: genericJni 前一个指针位置
        let imt_conflict_off = jni_tramp_off - 8;
        // resolution trampoline: 从 jni_tramp 反推（API 29+ 有额外字段，不再紧跟 intern_table）
        // API >= 23: resolution 在 jni_tramp 前 2 个位置
        // API < 23: resolution 在 jni_tramp 前 3 个位置（有 portable_resolution_trampoline_）
        let resolution_tramp_off = if api_level >= 23 {
            jni_tramp_off - 2 * 8
        } else {
            jni_tramp_off - 3 * 8
        };

        let jni_tramp = safe_read_u64(class_linker + jni_tramp_off as u64) & PAC_STRIP_MASK;
        let interp_bridge = safe_read_u64(class_linker + interp_bridge_off as u64) & PAC_STRIP_MASK;
        let resolution_tramp =
            safe_read_u64(class_linker + resolution_tramp_off as u64) & PAC_STRIP_MASK;
        let imt_conflict = safe_read_u64(class_linker + imt_conflict_off as u64) & PAC_STRIP_MASK;

        output_verbose(&format!(
            "[art bridge] ClassLinker: jni_tramp=ClassLinker+{:#x}={:#x}, interp=ClassLinker+{:#x}={:#x}, resolution=ClassLinker+{:#x}={:#x}, imt_conflict=ClassLinker+{:#x}={:#x}",
            jni_tramp_off, jni_tramp, interp_bridge_off, interp_bridge, resolution_tramp_off, resolution_tramp, imt_conflict_off, imt_conflict
        ));

        // 验证: 应为 libart.so 中的代码指针
        if jni_tramp != 0 && is_code_pointer(jni_tramp) {
            // 对可能通过 dlsym 找到的地址使用 dlsym 值，否则用 ClassLinker 值
            let final_jni = if jni_sym.is_null() {
                jni_tramp
            } else {
                jni_sym as u64
            };
            let final_interp = if interp_bridge != 0 && is_code_pointer(interp_bridge) {
                interp_bridge
            } else if !interp_sym.is_null() {
                interp_sym as u64
            } else {
                0
            };
            let final_resolution = if resolution_tramp != 0 && is_code_pointer(resolution_tramp) {
                resolution_tramp
            } else if !resolution_sym.is_null() {
                resolution_sym as u64
            } else {
                0
            };
            let final_imt = if imt_conflict != 0 && is_code_pointer(imt_conflict) {
                imt_conflict
            } else if !imt_sym.is_null() {
                imt_sym as u64
            } else {
                0
            };

            return (final_jni, final_interp, final_resolution, final_imt);
        }
    }

    output_verbose("[art bridge] ClassLinker 扫描失败，返回 dlsym 结果（部分可能为0）");
    (
        jni_sym as u64,
        interp_sym as u64,
        resolution_sym as u64,
        imt_sym as u64,
    )
}

/// 查找 Nterp 解释器入口点（Android 12+ / API 31+）
///
/// 策略 1: dlsym("art::interpreter::GetNterpEntryPoint") → 调用它获取入口点
/// 策略 2: dlsym("ExecuteNterpImpl") — 直接查找（通常 LOCAL HIDDEN，可能失败）
/// 返回 0 表示不可用（Android 11 及以下无 Nterp）
unsafe fn find_nterp_entry_point() -> u64 {
    // 策略 1: GetNterpEntryPoint 是一个返回入口点地址的函数
    let func_ptr = libart_dlsym("_ZN3art11interpreter18GetNterpEntryPointEv");
    if !func_ptr.is_null() {
        let get_nterp: unsafe extern "C" fn() -> u64 = std::mem::transmute(func_ptr);
        let ep = get_nterp();
        if ep != 0 {
            output_verbose(&format!(
                "[art bridge] Nterp 入口点通过 GetNterpEntryPoint() 获取: {:#x}",
                ep
            ));
            return ep;
        }
    }

    // 策略 2: ExecuteNterpImpl（LOCAL HIDDEN，通常无法通过 dlsym 访问）
    let func_ptr2 = libart_dlsym("ExecuteNterpImpl");
    if !func_ptr2.is_null() {
        output_verbose(&format!(
            "[art bridge] Nterp 入口点通过 ExecuteNterpImpl 获取: {:#x}",
            func_ptr2 as u64
        ));
        return func_ptr2 as u64;
    }

    output_verbose("[art bridge] Nterp 入口点不可用（Android 11 及以下）");
    0
}

/// 查找 art::interpreter::DoCall<> 模板实例（4个：bool×bool 组合）
///
/// Android 12 (API 23-33) 使用:
///   _ZN3art11interpreter6DoCallILb{0,1}ELb{0,1}EEEbPNS_9ArtMethodEPNS_6ThreadERNS_11ShadowFrameEPKNS_11InstructionEtPNS_6JValueE
unsafe fn find_do_call_symbols() -> Vec<u64> {
    let api_level = get_android_api_level();

    // 根据 API 级别构建符号名模式
    let symbols: Vec<String> = if api_level <= 22 {
        // Android 5.x: ArtMethod 在 mirror 命名空间
        let mut syms = Vec::new();
        for b0 in &["0", "1"] {
            for b1 in &["0", "1"] {
                syms.push(format!(
                    "_ZN3art11interpreter6DoCallILb{}ELb{}EEEbPNS_6mirror9ArtMethodEPNS_6ThreadERNS_11ShadowFrameEPKNS_11InstructionEtPNS_6JValueE",
                    b0, b1
                ));
            }
        }
        syms
    } else if api_level <= 33 {
        // Android 6-13: 标准签名
        let mut syms = Vec::new();
        for b0 in &["0", "1"] {
            for b1 in &["0", "1"] {
                syms.push(format!(
                    "_ZN3art11interpreter6DoCallILb{}ELb{}EEEbPNS_9ArtMethodEPNS_6ThreadERNS_11ShadowFrameEPKNS_11InstructionEtPNS_6JValueE",
                    b0, b1
                ));
            }
        }
        syms
    } else {
        // Android 14+: 单 bool 模板参数
        let mut syms = Vec::new();
        for b0 in &["0", "1"] {
            syms.push(format!(
                "_ZN3art11interpreter6DoCallILb{}EEEbPNS_9ArtMethodEPNS_6ThreadERNS_11ShadowFrameEPKNS_11InstructionEtbPNS_6JValueE",
                b0
            ));
        }
        syms
    };

    let mut addrs = Vec::new();
    for sym_str in &symbols {
        let addr = libart_dlsym(sym_str);
        if !addr.is_null() {
            addrs.push(addr as u64);
        }
    }

    addrs
}

/// 清空 JIT 代码缓存: 调用 JitCodeCache::InvalidateAllMethods()
///
/// 首次 hook 时调用一次，使所有已 JIT 编译的代码失效:
/// - 已内联被 hook 方法的调用者代码失效 → 退回解释器
/// - 重新 JIT 时不再内联被 hook 方法 (kAccSingleImplementation 已清除)
///
/// best-effort: 符号未找到或指针无效时仅 log 警告，不阻断 hook 流程。
pub(super) unsafe fn try_invalidate_jit_cache() {
    // 查找 InvalidateAllMethods 符号
    let func_ptr = libart_dlsym("_ZN3art3jit12JitCodeCache21InvalidateAllMethodsEv");

    if func_ptr.is_null() {
        output_verbose("[jit cache] InvalidateAllMethods 符号未找到，跳过 JIT 缓存清空");
        return;
    }

    // 从 JavaVM → Runtime → jit_code_cache_ 导航获取 JitCodeCache*
    let runtime = match get_runtime_addr() {
        Some(r) => r,
        None => {
            output_verbose("[jit cache] 无法获取 Runtime 地址，跳过 JIT 缓存清空");
            return;
        }
    };

    // 从 Runtime 获取 jit_code_cache_:
    // 尝试 dlsym Runtime::instance_ 获取更可靠的路径
    let instance_ptr = crate::jsapi::module::libart_dlsym("_ZN3art7Runtime9instance_E");

    let runtime_addr = if !instance_ptr.is_null() {
        let rt = *(instance_ptr as *const u64);
        let rt_stripped = rt & PAC_STRIP_MASK;
        if rt_stripped != 0 {
            rt_stripped
        } else {
            runtime
        }
    } else {
        runtime
    };

    // 扫描 Runtime 查找 jit_ (Jit*) 指针
    // jit_ 通常在 Runtime 布局的后半部分
    // 策略: 通过 dlsym 查找 Jit::code_cache_ 的偏移
    // 简化方案: 直接用 dlsym 查找 jit_code_cache_ 全局或从 Runtime 扫描

    // 方案 A: 尝试 Runtime::jit_code_cache_ 直接访问
    // Runtime 的 jit_code_cache_ 字段可以通过扫描找到
    // 但更可靠的方式是: 扫描 Runtime 找到 Jit* (非空且是合理的堆指针)
    // 然后从 Jit 中取 code_cache_ (通常在 Jit+8 或 Jit+16)

    // 方案 B (更简单): 通过 dlsym 获取 jit_code_cache_ 成员偏移
    // 实际上最简单的方案: 扫描 Runtime 寻找指向合法 JitCodeCache 的指针

    // 使用 Jit::GetCodeCache() 如果可用
    let get_code_cache_ptr = crate::jsapi::module::libart_dlsym("_ZNK3art3jit3Jit12GetCodeCacheEv");

    if !get_code_cache_ptr.is_null() {
        // 需要 Jit* this — 从 Runtime 获取
        // Runtime::jit_ 指针扫描
        // jit_ 通常在 Runtime 中较后的位置 (offset 600-900)
        refresh_mem_regions();
        let scan_start = 500usize;
        let scan_end = 1200usize;

        for offset in (scan_start..scan_end).step_by(8) {
            let candidate = safe_read_u64(runtime_addr + offset as u64);
            let candidate_stripped = candidate & PAC_STRIP_MASK;

            // 跳过空指针和非堆地址
            if candidate_stripped == 0 || candidate_stripped < 0x7000_0000 {
                continue;
            }

            // 尝试作为 Jit* 调用 GetCodeCache()
            // GetCodeCache 是 const 方法: JitCodeCache* GetCodeCache() const
            type GetCodeCacheFn = unsafe extern "C" fn(this: u64) -> u64;
            let get_code_cache: GetCodeCacheFn = std::mem::transmute(get_code_cache_ptr);

            // 安全检查: 确保 candidate 看起来像合理的对象指针
            // 读取前 8 字节看是否为合理值
            let first_word = safe_read_u64(candidate_stripped);
            if first_word == 0 {
                continue;
            }

            let code_cache = get_code_cache(candidate_stripped);
            let code_cache_stripped = code_cache & PAC_STRIP_MASK;
            if code_cache_stripped != 0 && code_cache_stripped > 0x7000_0000 {
                // 找到了 JitCodeCache*，调用 InvalidateAllMethods
                type InvalidateAllFn = unsafe extern "C" fn(this: u64);
                let invalidate: InvalidateAllFn = std::mem::transmute(func_ptr);
                invalidate(code_cache_stripped);
                output_verbose(&format!(
                    "[jit cache] InvalidateAllMethods 调用成功: JitCodeCache={:#x} (Runtime+{:#x})",
                    code_cache_stripped, offset
                ));
                return;
            }
        }

        output_verbose("[jit cache] 未找到 Jit* 指针，尝试直接扫描 JitCodeCache...");
    }

    // 方案 C: 直接扫描 Runtime 找 jit_code_cache_ 指针
    // jit_code_cache_ 是一个独立字段，通常紧跟 jit_ 之后
    // 这里我们放弃精确查找，仅记录警告
    output_verbose("[jit cache] JIT 缓存清空跳过: 无法定位 JitCodeCache 指针");
}

/// 查找 GC ConcurrentCopying::CopyingPhase 或 MarkingPhase 符号
///
/// API > 28: CopyingPhase
/// API 23-28: MarkingPhase
unsafe fn find_gc_copying_phase() -> u64 {
    let api_level = get_android_api_level();

    let sym_name = if api_level > 28 {
        "_ZN3art2gc9collector17ConcurrentCopying12CopyingPhaseEv"
    } else if api_level > 22 {
        "_ZN3art2gc9collector17ConcurrentCopying12MarkingPhaseEv"
    } else {
        return 0; // Android 5.x 不使用 ConcurrentCopying
    };

    libart_dlsym(sym_name) as u64
}

/// 查找 Heap::CollectGarbageInternal 符号
///
/// 主 GC 入口点，GC 完成后需要同步 replacement 方法。
/// 符号签名因 Android 版本不同而异。
unsafe fn find_gc_collect_internal() -> u64 {
    let candidates = [
        // Android 12+ (API 31+): 5-arg overload (extra uint32_t param)
        "_ZN3art2gc4Heap22CollectGarbageInternalENS0_9collector6GcTypeENS0_7GcCauseEbj",
        // Android 12+ (API 31+): 4-arg overload
        "_ZN3art2gc4Heap22CollectGarbageInternalENS0_9collector6GcTypeENS0_7GcCauseEb",
        // Android 10-11 (API 29-30)
        "_ZN3art2gc4Heap22CollectGarbageInternalENS0_9collector6GcTypeENS0_7GcCauseEbPKNS0_9collector14GarbageCollectorE",
        // Older variants
        "_ZN3art2gc4Heap22CollectGarbageInternalENS0_13GcCauseEb",
    ];

    dlsym_first_match(&candidates)
}

/// 查找 Thread::RunFlipFunction 符号
///
/// 线程翻转期间需要同步 replacement 方法（moving GC 相关）。
unsafe fn find_run_flip_function() -> u64 {
    let candidates = [
        // Android 12+ (API 31+): 带 bool 参数
        "_ZN3art6Thread15RunFlipFunctionEPS0_b",
        // Android 10-11 (API 29-30)
        "_ZN3art6Thread15RunFlipFunctionEPS0_",
    ];

    dlsym_first_match(&candidates)
}

/// 查找 ArtMethod::GetOatQuickMethodHeader 符号
///
/// ART 通过此函数查找方法的 OAT 编译代码头。对 replacement method（堆分配），
/// 此调用可能返回错误结果或崩溃。需要拦截并对 replacement 返回 NULL。
unsafe fn find_get_oat_quick_method_header() -> u64 {
    let candidates = [
        "_ZN3art9ArtMethod23GetOatQuickMethodHeaderEm",
        // 某些 Android 版本使用 uintptr_t
        "_ZN3art9ArtMethod23GetOatQuickMethodHeaderEj",
    ];

    dlsym_first_match(&candidates)
}

/// 查找 FixupStaticTrampolines 或 MakeInitializedClassesVisiblyInitialized 符号
///
/// 当类完成延迟初始化时，ART 可能更新静态方法的 quickCode，
/// 从 resolution_trampoline 变为编译代码，绕过 hook。
unsafe fn find_fixup_static_trampolines() -> u64 {
    let candidates = [
        // Android 12+ (API 31+): MakeInitializedClassesVisiblyInitialized (40 chars)
        "_ZN3art11ClassLinker40MakeInitializedClassesVisiblyInitializedEPNS_6ThreadEb",
        // Android 8-11: FixupStaticTrampolines with Thread* param (ObjPtr 版本)
        "_ZN3art11ClassLinker22FixupStaticTrampolinesEPNS_6ThreadENS_6ObjPtrINS_6mirror5ClassEEE",
        // Android 8-11: FixupStaticTrampolines (ObjPtr 版本, no Thread*)
        "_ZN3art11ClassLinker22FixupStaticTrampolinesEPNS_6ObjPtrINS_6mirror5ClassEEE",
        // Android 7: FixupStaticTrampolines (raw pointer 版本)
        "_ZN3art11ClassLinker22FixupStaticTrampolinesEPNS_6mirror5ClassE",
    ];

    dlsym_first_match(&candidates)
}

/// 查找 art::Thread::Current() 函数地址
///
/// 用于递归防护: 在 on_do_call_enter 中获取当前线程的 Thread*,
/// 读取 ManagedStack 判断是否处于 callOriginal 递归中。
unsafe fn find_thread_current() -> u64 {
    libart_dlsym("_ZN3art6Thread7CurrentEv") as u64
}

/// 查找 ArtMethod::PrettyMethod 函数地址
///
/// 对标 Frida fixupArtQuickDeliverExceptionBug: 当 method==NULL 时
/// PrettyMethod 会崩溃。Hook 此函数替换 NULL 为上次见到的非空 method。
/// 优先成员函数版本，fallback 到静态函数版本。
unsafe fn find_pretty_method() -> u64 {
    // 成员函数版本: ArtMethod::PrettyMethod(bool)
    let addr = libart_dlsym("_ZN3art9ArtMethod12PrettyMethodEb");
    if !addr.is_null() {
        return addr as u64;
    }
    // 静态函数版本: PrettyMethod(ArtMethod*, bool)
    let addr = libart_dlsym("_ZN3art12PrettyMethodEPNS_9ArtMethodEb");
    addr as u64
}
