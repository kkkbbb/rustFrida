// ============================================================================
// Instrumentation 偏移探测 — 对标 Frida tryDetectInstrumentationOffset/Pointer
// ============================================================================

/// Instrumentation 偏移规格
#[allow(dead_code)]
pub(super) struct InstrumentationSpec {
    /// Runtime.instrumentation_ 在 Runtime 结构体中的偏移
    pub runtime_instrumentation_offset: usize,
    /// Instrumentation.force_interpret_only_ 在 Instrumentation 结构体中的偏移 (固定=4)
    pub force_interpret_only_offset: usize,
    /// Instrumentation.deoptimization_enabled_ 偏移 (按 API level 查表, 可能不可用)
    pub deoptimization_enabled_offset: Option<usize>,
    /// true = 指针模式 (APEX >= 360_000_000), false = 嵌入模式
    pub is_pointer_mode: bool,
}

/// 缓存的 Instrumentation 偏移探测结果
static INSTRUMENTATION_SPEC: OnceLock<Option<InstrumentationSpec>> = OnceLock::new();

/// 获取缓存的 Instrumentation 偏移规格（首次调用时探测）
pub(super) fn get_instrumentation_spec() -> Option<&'static InstrumentationSpec> {
    INSTRUMENTATION_SPEC
        .get_or_init(|| probe_instrumentation_spec())
        .as_ref()
}

/// 按 API level 返回 Instrumentation.deoptimization_enabled_ 偏移 (64-bit ARM64)
/// 对标 Frida android.js 中的 deoptimizationEnabled 查找表 (pointerSize=8)
///
/// - API 21-31: 与 Frida 表一致的硬编码值
/// - API 32 (Android 12L): Instrumentation 结构体与 API 31 相同，偏移不变
/// - API 33+ (Android 13+): AOSP commit ba8600819d 将 EnableDeoptimization 变为 nop，
///   deoptimization_enabled_ 字段已无实际作用。Frida 在 API 32+ 也没有提供偏移，
///   而是通过检查 EnableDeoptimization 符号是否存在来决定是否使用该字段。
///   这里对 API 33+ 返回 None，调用方应检查 EnableDeoptimization 符号可用性。
fn get_deoptimization_enabled_offset() -> Option<usize> {
    match get_android_api_level() {
        21 | 22 => Some(224),
        23 => Some(296),
        24 | 25 => Some(344),
        26 | 27 => Some(352),
        28 => Some(392),
        29 => Some(328),
        30 | 31 | 32 => Some(336),
        // API 33+: deoptimization_enabled_ 已无实际作用，返回 None
        _ => None,
    }
}

/// 反汇编 art::Runtime::DeoptimizeBootImage 提取 Runtime.instrumentation_ 的偏移。
///
/// 对标 Frida tryDetectInstrumentationOffset / tryDetectInstrumentationPointer:
/// - 嵌入模式 (APEX < 360_000_000): 查找 ADD Xd, Xn, #imm 指令
/// - 指针模式 (APEX >= 360_000_000): 查找 LDR Xt, [Xn, #imm] 指令
///
/// 仅支持 ARM64。
pub(super) fn probe_instrumentation_spec() -> Option<InstrumentationSpec> {
    // Step 1: dlsym 查找 art::Runtime::DeoptimizeBootImage
    let sym =
        unsafe { crate::jsapi::module::libart_dlsym("_ZN3art7Runtime19DeoptimizeBootImageEv") };
    if sym.is_null() {
        output_verbose("[instrumentation] DeoptimizeBootImage 符号未找到");
        return None;
    }

    // Step 2: 根据 APEX 版本判断解析模式
    let apex_version = get_art_apex_version();
    let is_pointer_mode = apex_version >= 360_000_000;
    let deopt_offset = get_deoptimization_enabled_offset();

    output_verbose(&format!(
        "[instrumentation] DeoptimizeBootImage={:#x}, APEX={}, 模式={}",
        sym as u64,
        apex_version,
        if is_pointer_mode { "指针" } else { "嵌入" }
    ));

    // Step 3: 扫描前 30 条 ARM64 指令（每条 4 字节）
    let func_addr = sym as u64;
    for i in 0..30u64 {
        let insn_addr = func_addr + i * 4;
        let insn = unsafe { *(insn_addr as *const u32) };

        if is_pointer_mode {
            // 指针模式: 查找 LDR Xt, [Xn, #imm] (64-bit unsigned offset)
            // 编码: 1111 1001 01ii iiii iiii iinn nnnt tttt = 0xF940_0000
            // mask: 0xFFC0_0000
            if (insn & 0xFFC0_0000) == 0xF940_0000 {
                let rt = insn & 0x1F;
                let rn = (insn >> 5) & 0x1F;
                let imm12 = ((insn >> 10) & 0xFFF) as usize;
                let offset = imm12 * 8; // LDR X 的 imm12 按 8 缩放

                // 排除 x0 作为目标（Frida: ops[0].value === 'x0' → skip）
                // 基址必须是 x0（this 指针）
                if rt == 0 || rn != 0 {
                    continue;
                }

                if offset >= 0x100 && offset <= 0x400 {
                    output_verbose(&format!(
                        "[instrumentation] 指针模式: LDR x{}, [x{}, #{}]",
                        rt, rn, offset
                    ));
                    return Some(InstrumentationSpec {
                        runtime_instrumentation_offset: offset,
                        force_interpret_only_offset: 4,
                        deoptimization_enabled_offset: deopt_offset,
                        is_pointer_mode: true,
                    });
                }
            }
        } else {
            // 嵌入模式: 查找 ADD Xd, Xn, #imm (64-bit)
            // SF=1, op=0, S=0 → 1001 0001
            // shift=00: mask 0xFF80_0000, value 0x9100_0000
            // shift=01: mask 0xFF80_0000, value 0x9140_0000
            let masked = insn & 0xFF80_0000;
            if masked == 0x9100_0000 || masked == 0x9140_0000 {
                let rd = insn & 0x1F;
                let rn = (insn >> 5) & 0x1F;
                let imm12 = ((insn >> 10) & 0xFFF) as usize;
                let shift = ((insn >> 22) & 0x3) as usize;
                let offset = if shift == 1 { imm12 << 12 } else { imm12 };

                // 排除 sp (x31) 操作
                if rd == 31 || rn == 31 {
                    continue;
                }

                if offset >= 0x100 && offset <= 0x400 {
                    output_verbose(&format!(
                        "[instrumentation] 嵌入模式: ADD x{}, x{}, #{}",
                        rd, rn, offset
                    ));
                    return Some(InstrumentationSpec {
                        runtime_instrumentation_offset: offset,
                        force_interpret_only_offset: 4,
                        deoptimization_enabled_offset: deopt_offset,
                        is_pointer_mode: false,
                    });
                }
            }
        }
    }

    output_verbose("[instrumentation] 未找到 Instrumentation 偏移");
    None
}
