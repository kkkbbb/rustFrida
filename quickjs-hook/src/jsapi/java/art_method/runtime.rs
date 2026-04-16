// ============================================================================
// Runtime/JavaVM 共享辅助函数
// ============================================================================

/// 从 JNI_STATE 获取 Runtime* 和 java_vm_ 在 Runtime 中的偏移。
///
/// 扫描 Runtime 结构体查找 JavaVM* 指针位置。
/// 返回 (runtime_addr, java_vm_offset)，如果获取失败返回 None。
pub(super) unsafe fn find_runtime_java_vm() -> Option<(u64, usize)> {
    let vm_ptr = {
        let guard = JNI_STATE.lock().unwrap_or_else(|e| e.into_inner());
        match guard.as_ref() {
            Some(state) => state.vm,
            None => return None,
        }
    };

    let runtime = get_runtime_addr()?;

    refresh_mem_regions();

    let vm_addr_stripped = (vm_ptr as u64) & PAC_STRIP_MASK;
    let scan_start = 384usize;
    let scan_end = scan_start + 800;

    for offset in (scan_start..scan_end).step_by(8) {
        let val = safe_read_u64(runtime + offset as u64);
        let val_stripped = val & PAC_STRIP_MASK;
        if val_stripped == vm_addr_stripped {
            return Some((runtime, offset));
        }
    }

    None
}

// ============================================================================
// ArtRuntimeSpec — Runtime 内部偏移 (对标 Frida getArtRuntimeSpec)
// ============================================================================

/// ART Runtime 内部关键偏移
#[allow(dead_code)]
pub(super) struct ArtRuntimeSpec {
    /// Heap* 偏移
    pub heap_offset: usize,
    /// ThreadList* 偏移
    pub thread_list_offset: usize,
    /// InternTable* 偏移
    pub intern_table_offset: usize,
    /// ClassLinker* 偏移
    pub class_linker_offset: usize,
    /// JniIdManager* 偏移 (API 30+, None for older)
    pub jni_id_manager_offset: Option<usize>,
    /// Runtime 地址
    pub runtime_addr: u64,
}

static ART_RUNTIME_SPEC: OnceLock<Option<ArtRuntimeSpec>> = OnceLock::new();

/// 获取缓存的 ArtRuntimeSpec（首次调用时探测）
pub(super) fn get_art_runtime_spec() -> Option<&'static ArtRuntimeSpec> {
    ART_RUNTIME_SPEC
        .get_or_init(|| unsafe { probe_art_runtime_spec() })
        .as_ref()
}

/// 验证 classLinker 偏移是否正确（对标 Frida tryGetArtClassLinkerSpec）
///
/// 在 ClassLinker 结构体内部扫描 InternTable* 指针。
/// 如果找到匹配，说明 classLinkerOffset 正确。
unsafe fn verify_class_linker_offset(
    runtime: u64,
    class_linker_offset: usize,
    intern_table_offset: usize,
) -> bool {
    const PTR_SIZE: usize = 8;

    let cl_ptr = safe_read_u64(runtime + class_linker_offset as u64) & PAC_STRIP_MASK;
    let it_ptr = safe_read_u64(runtime + intern_table_offset as u64) & PAC_STRIP_MASK;

    if cl_ptr == 0 || it_ptr == 0 {
        output_verbose(&format!(
            "[art runtime] 交叉验证跳过: classLinker*={:#x}, internTable*={:#x}",
            cl_ptr, it_ptr
        ));
        return false;
    }

    // 在 ClassLinker 内部扫描 InternTable* 指针（对标 Frida: startOffset=200, range=100*PTR_SIZE）
    let scan_start = 200usize;
    let scan_end = scan_start + 800;

    for offset in (scan_start..scan_end).step_by(PTR_SIZE) {
        let val = safe_read_u64(cl_ptr + offset as u64) & PAC_STRIP_MASK;
        if val == it_ptr {
            output_verbose(&format!(
                "[art runtime] 交叉验证通过: 在 ClassLinker+{:#x} 找到 InternTable*={:#x}",
                offset, it_ptr
            ));
            return true;
        }
    }

    output_verbose(&format!(
        "[art runtime] 交叉验证失败: ClassLinker({:#x}) 中未找到 InternTable*({:#x})",
        cl_ptr, it_ptr
    ));
    false
}

/// 探测 ART Runtime 内部偏移（对标 Frida getArtRuntimeSpec / android.js:649-676）
///
/// 复用 find_runtime_java_vm 获取 Runtime 地址和 java_vm_ 偏移，
/// 然后根据 API level 计算 classLinker_, internTable_, threadList_, heap_ 偏移。
unsafe fn probe_art_runtime_spec() -> Option<ArtRuntimeSpec> {
    let (runtime, java_vm_off) = match find_runtime_java_vm() {
        Some(v) => v,
        None => {
            output_verbose("[art runtime] 无法获取 Runtime/java_vm_ 偏移");
            return None;
        }
    };

    let api_level = get_android_api_level();
    let is_34_equiv = is_api_level_34_or_apex_equivalent();

    const PTR_SIZE: usize = 8;

    let candidates = compute_classlinker_candidates(java_vm_off);

    // 对标 Frida tryGetArtClassLinkerSpec: 对每个候选进行 ClassLinker 内部结构验证
    let mut class_linker_offset: Option<usize> = None;
    for &candidate in &candidates {
        let intern_table_candidate = candidate - PTR_SIZE;
        if verify_class_linker_offset(runtime, candidate, intern_table_candidate) {
            class_linker_offset = Some(candidate);
            output_verbose(&format!(
                "[art runtime] classLinker 候选 Runtime+{:#x} 验证通过",
                candidate
            ));
            break;
        }
        output_verbose(&format!(
            "[art runtime] classLinker 候选 Runtime+{:#x} 验证失败，尝试下一个",
            candidate
        ));
    }

    // fallback: 如果所有候选都验证失败，取第一个非空指针
    let class_linker_offset = match class_linker_offset {
        Some(off) => off,
        None => {
            output_verbose("[art runtime] 所有候选交叉验证失败，退回首个非空候选");
            match candidates.iter().find(|&&off| {
                let ptr = safe_read_u64(runtime + off as u64) & PAC_STRIP_MASK;
                ptr != 0
            }) {
                Some(&off) => off,
                None => {
                    output_verbose("[art runtime] 无有效 classLinker 候选");
                    return None;
                }
            }
        }
    };

    // internTable_ = classLinker_ - 8 (对标 Frida android.js:663)
    let intern_table_offset = class_linker_offset - PTR_SIZE;

    // threadList_ = internTable_ - 8 (对标 Frida android.js:664)
    let thread_list_offset = intern_table_offset - PTR_SIZE;

    // heap_ 偏移 (对标 Frida android.js:666-676)
    let heap_offset = if is_34_equiv {
        // API 34+ / APEX equivalent: threadList - 9*8
        thread_list_offset - 9 * PTR_SIZE
    } else if api_level >= 24 {
        thread_list_offset - 8 * PTR_SIZE
    } else if api_level >= 23 {
        thread_list_offset - 7 * PTR_SIZE
    } else {
        thread_list_offset - 4 * PTR_SIZE
    };

    // jniIdManager_ (API 30+): java_vm_ - 8 (对标 Frida)
    let jni_id_manager_offset = if api_level >= 30 {
        Some(java_vm_off - PTR_SIZE)
    } else {
        None
    };

    // 验证: classLinker 和 internTable 指针非空
    let cl_ptr = safe_read_u64(runtime + class_linker_offset as u64) & PAC_STRIP_MASK;
    let it_ptr = safe_read_u64(runtime + intern_table_offset as u64) & PAC_STRIP_MASK;

    if cl_ptr == 0 {
        output_verbose("[art runtime] classLinker 指针为空，探测失败");
        return None;
    }

    output_verbose(&format!(
        "[art runtime] 探测成功: heap={:#x}, threadList={:#x}, internTable={:#x}, classLinker={:#x}{}",
        heap_offset, thread_list_offset, intern_table_offset, class_linker_offset,
        if let Some(jni_off) = jni_id_manager_offset {
            format!(", jniIdManager={:#x}", jni_off)
        } else {
            String::new()
        }
    ));
    output_verbose(&format!(
        "[art runtime] 验证: classLinker*={:#x}, internTable*={:#x}, Runtime={:#x}",
        cl_ptr, it_ptr, runtime
    ));

    Some(ArtRuntimeSpec {
        heap_offset,
        thread_list_offset,
        intern_table_offset,
        class_linker_offset,
        jni_id_manager_offset,
        runtime_addr: runtime,
    })
}

// ============================================================================
// jniIdsIndirection 偏移探测 — 对标 Frida tryDetectJniIdsIndirectionOffset
// ============================================================================

/// 缓存的 jniIdsIndirection 偏移探测结果
static JNI_IDS_INDIRECTION_OFFSET: OnceLock<Option<usize>> = OnceLock::new();

/// 获取缓存的 jniIdsIndirection 偏移（首次调用时探测）
pub(super) fn get_jni_ids_indirection_offset() -> Option<usize> {
    *JNI_IDS_INDIRECTION_OFFSET.get_or_init(|| probe_jni_ids_indirection_offset())
}

/// 反汇编 art::Runtime::SetJniIdType 提取 Runtime.jni_ids_indirection_ 的偏移。
///
/// 对标 Frida tryDetectJniIdsIndirectionOffset:
/// 扫描前 20 条指令，匹配以下模式之一:
/// - LDR + CMP: LDR 读取 jni_ids_indirection_ 后跟 CMP 比较 → 取 LDR 的位移
/// - STR + BL: STR 写入 jni_ids_indirection_ 后跟 BL 函数调用 → 取 STR 的位移
pub(super) fn probe_jni_ids_indirection_offset() -> Option<usize> {
    // dlsym 查找 art::Runtime::SetJniIdType
    // 注意: 该符号在 Android 12+ 为 PROTECTED visibility，RTLD_DEFAULT 无法找到
    // 必须使用 unrestricted dlsym (对标 Frida 的 linker API)
    let sym = unsafe {
        crate::jsapi::module::libart_dlsym("_ZN3art7Runtime12SetJniIdTypeENS_9JniIdTypeE")
    };
    if sym.is_null() {
        output_verbose("[jniIds] SetJniIdType 符号未找到");
        return None;
    }

    output_verbose(&format!("[jniIds] SetJniIdType={:#x}", sym as u64));

    // 扫描前 20 条指令，查找 (LDR + CMP) 或 (STR + BL) 指令对
    let func_addr = sym as u64;
    let mut prev_insn: u32 = 0;
    for i in 0..20u64 {
        let insn = unsafe { *((func_addr + i * 4) as *const u32) };

        if i > 0 {
            // 当前是 CMP 且前一条是 LDR → 取 LDR 的 displacement
            // CMP immediate: SF 11 10001 → mask 0x7F80_0000, Rd=11111 (XZR/WZR)
            let is_cmp_imm = (insn & 0x7F80_0000) == 0x7100_0000 && ((insn & 0x1F) == 0x1F);
            // CMP shifted register: SF 11 01011 → mask 0x7F20_0000 = 0x6B00_0000, Rd=11111
            let is_cmp_reg = (insn & 0x7F20_0000) == 0x6B00_0000 && ((insn & 0x1F) == 0x1F);
            let is_cmp = is_cmp_imm || is_cmp_reg;

            // LDR (unsigned offset): 匹配 32-bit 和 64-bit
            // jni_ids_indirection_ 是 C++ enum (通常 32-bit)，某些编译器生成 LDR W
            // 64-bit: 0xFFC0_0000 == 0xF940_0000, scale=8
            // 32-bit: 0xFFC0_0000 == 0xB940_0000, scale=4
            let prev_is_ldr64 = (prev_insn & 0xFFC0_0000) == 0xF940_0000;
            let prev_is_ldr32 = (prev_insn & 0xFFC0_0000) == 0xB940_0000;

            if is_cmp && (prev_is_ldr64 || prev_is_ldr32) {
                let imm12 = ((prev_insn >> 10) & 0xFFF) as usize;
                let scale = if prev_is_ldr64 { 8 } else { 4 };
                let offset = imm12 * scale;
                output_verbose(&format!(
                    "[jniIds] LDR+CMP 模式: offset={} ({}bit LDR)",
                    offset,
                    if prev_is_ldr64 { 64 } else { 32 }
                ));
                return Some(offset);
            }

            // 当前是 BL 且前一条是 STR → 取 STR 的 displacement
            let is_bl = (insn & 0xFC00_0000) == 0x9400_0000;
            // STR (unsigned offset): 匹配 32-bit 和 64-bit
            let prev_is_str64 = (prev_insn & 0xFFC0_0000) == 0xF900_0000;
            let prev_is_str32 = (prev_insn & 0xFFC0_0000) == 0xB900_0000;

            if is_bl && (prev_is_str64 || prev_is_str32) {
                let imm12 = ((prev_insn >> 10) & 0xFFF) as usize;
                let scale = if prev_is_str64 { 8 } else { 4 };
                let offset = imm12 * scale;
                output_verbose(&format!(
                    "[jniIds] STR+BL 模式: offset={} ({}bit STR)",
                    offset,
                    if prev_is_str64 { 64 } else { 32 }
                ));
                return Some(offset);
            }
        }

        prev_insn = insn;
    }

    output_verbose("[jniIds] 未找到 jniIdsIndirection 偏移");
    None
}
