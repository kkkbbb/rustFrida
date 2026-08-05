//! Java.fastMethod() backend used by fast callbacks.
//!
//! This is intentionally fast-only: registration rejects methods that do not
//! currently have an independent quick-code entrypoint. Slow/reflection/JNI
//! calls stay in the JS callback path.

use crate::ffi;
use crate::jsapi::callback_util::{
    extract_string_arg, js_u64_to_js_number_or_bigint, set_js_u64_property, throw_internal_error, throw_type_error,
};
use crate::jsapi::console::output_verbose;
use crate::value::JSValue;
use std::cell::Cell;
use std::ffi::CString;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};

use super::art_method::*;
use super::callback::{get_return_type_from_sig, parse_jni_param_types};
use super::jni_core::*;
use super::reflect::{decode_field_id, decode_method_id, find_class_safe};
use super::safe_mem::{refresh_mem_regions, safe_read_u32};

#[derive(Clone, Debug)]
pub(crate) struct FastMethod {
    pub(crate) art_method: u64,
    #[allow(dead_code)]
    class_global_ref: u64,
    class_mirror: u64,
    pub(crate) is_static: bool,
    pub(crate) param_types: Vec<String>,
    shorty: CString,
}

#[derive(Clone, Debug)]
pub(crate) struct FastConstructor {
    #[allow(dead_code)]
    pub(crate) class_global_ref: u64,
    pub(crate) class_mirror: u64,
    pub(crate) art_method: u64,
    pub(crate) param_types: Vec<String>,
    shorty: CString,
}

#[derive(Clone, Debug)]
pub(crate) struct FastField {
    #[allow(dead_code)]
    pub(crate) art_field: u64,
    pub(crate) offset: u32,
    pub(crate) is_static: bool,
    pub(crate) value_type: u8,
    #[allow(dead_code)]
    pub(crate) jni_sig: String,
    #[allow(dead_code)]
    pub(crate) class_name: String,
    #[allow(dead_code)]
    pub(crate) field_name: String,
}

static FAST_METHODS: OnceLock<Mutex<Vec<FastMethod>>> = OnceLock::new();
static FAST_CONSTRUCTORS: OnceLock<Mutex<Vec<FastConstructor>>> = OnceLock::new();
static FAST_FIELDS: OnceLock<Mutex<Vec<FastField>>> = OnceLock::new();
static FAST_ART_EXCEPTION_SEEN: AtomicU64 = AtomicU64::new(0);
static FAST_ART_EXCEPTION_CLEARED: AtomicU64 = AtomicU64::new(0);
static FAST_ART_HANDLE_SCOPE_ENTER: AtomicU64 = AtomicU64::new(0);
static FAST_ART_HANDLE_SCOPE_UNAVAILABLE: AtomicU64 = AtomicU64::new(0);
static FAST_ART_HANDLE_SCOPE_LEAKED: AtomicU64 = AtomicU64::new(0);
static FAST_ART_HANDLE_SCOPE_MAX_ROOTS: AtomicU64 = AtomicU64::new(0);
static FAST_ART_HANDLE_SCOPE_ROOT_FAILED: AtomicU64 = AtomicU64::new(0);
static FAST_ART_HANDLE_SCOPE_CAPACITY_EXCEEDED: AtomicU64 = AtomicU64::new(0);
static QUICK_ENTRYPOINTS_OFFSET: AtomicUsize = AtomicUsize::new(0);
static FAST_TLAB_ALLOC_HIT: AtomicU64 = AtomicU64::new(0);
static FAST_TLAB_ALLOC_MISS: AtomicU64 = AtomicU64::new(0);
static FAST_QUICK_ALLOC_SLOW_PATH: AtomicU64 = AtomicU64::new(0);
static ART_CALLEE_SAVE_SUSPEND_METHOD: OnceLock<u64> = OnceLock::new();
static ART_QUICK_TEST_SUSPEND_ENTRYPOINT: OnceLock<u64> = OnceLock::new();

struct ArtSymbolCandidate {
    label: &'static str,
    name: &'static str,
    kind: &'static str,
}

struct ArtCalleeSaveProfile {
    label: &'static str,
    min_sdk: i32,
    max_sdk: i32,
    suspend_method_offset: u64,
}

#[derive(Clone, Copy)]
struct ArtCalleeSaveDynamicResolution {
    label: &'static str,
    method: u64,
    suspend_method_offset: u64,
    set_base_offset: Option<u64>,
    init_sequence_offset: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RuntimeRegExpr {
    Unknown,
    RuntimePlus(u64),
    RuntimePlusTypeIndex(u64),
}

const ART_CALLEE_SAVE_SYMBOLS: &[ArtSymbolCandidate] = &[
    ArtSymbolCandidate {
        label: "getCalleeSaveMethod",
        name: "_ZN3art7Runtime19GetCalleeSaveMethodENS_14CalleeSaveTypeE",
        kind: "art::CalleeSaveType",
    },
    ArtSymbolCandidate {
        label: "getCalleeSaveMethodUnchecked",
        name: "_ZN3art7Runtime28GetCalleeSaveMethodUncheckedENS_14CalleeSaveTypeE",
        kind: "art::CalleeSaveType",
    },
    ArtSymbolCandidate {
        label: "getCalleeSaveMethodConst",
        name: "_ZNK3art7Runtime19GetCalleeSaveMethodENS_14CalleeSaveTypeE",
        kind: "art::CalleeSaveType const",
    },
    ArtSymbolCandidate {
        label: "getCalleeSaveMethodUncheckedConst",
        name: "_ZNK3art7Runtime28GetCalleeSaveMethodUncheckedENS_14CalleeSaveTypeE",
        kind: "art::CalleeSaveType const",
    },
    ArtSymbolCandidate {
        label: "getCalleeSaveMethodRuntimeNested",
        name: "_ZN3art7Runtime19GetCalleeSaveMethodENS0_14CalleeSaveTypeE",
        kind: "art::Runtime::CalleeSaveType",
    },
    ArtSymbolCandidate {
        label: "getCalleeSaveMethodRuntimeNestedConst",
        name: "_ZNK3art7Runtime19GetCalleeSaveMethodENS0_14CalleeSaveTypeE",
        kind: "art::Runtime::CalleeSaveType const",
    },
];

const ART_CALLEE_SAVE_PROFILES: &[ArtCalleeSaveProfile] = &[ArtCalleeSaveProfile {
    label: "aosp-api31-36-callee-save-offsets",
    min_sdk: 31,
    max_sdk: 36,
    suspend_method_offset: 0x28,
}];

const ART_SET_CALLEE_SAVE_METHOD_SYMBOL: &str =
    "_ZN3art7Runtime19SetCalleeSaveMethodEPNS_9ArtMethodENS_14CalleeSaveTypeE";
const ART_CREATE_CALLEE_SAVE_METHOD_SYMBOL: &str = "_ZN3art7Runtime22CreateCalleeSaveMethodEv";
const CALLEE_SAVE_EVERYTHING_FOR_SUSPEND_CHECK: u32 = 5;
const CALLEE_SAVE_METHOD_COUNT: u64 = 6;
const CALLEE_SAVE_SLOT_SIZE: u64 = 8;
const CALLEE_SAVE_MAX_RUNTIME_OFFSET: u64 = 0x400;
const SET_CALLEE_SAVE_SCAN_BYTES: usize = 192;
const INIT_CALLEE_SAVE_VERIFY_WINDOW: u64 = 0x140;
const INIT_CALLEE_SAVE_BLOCK_BACK_INSNS: u64 = 12;

const QUICK_ENTRYPOINTS_OFFSET_FAILED: usize = usize::MAX;
const QUICK_ENTRYPOINT_COUNT: usize = 174;
const QUICK_ALLOC_OBJECT_INITIALIZED_INDEX: usize = 6;
const QUICK_TEST_SUSPEND_INDEX: usize = 105;
const QUICK_JNI_METHOD_START_INDEX: usize = 45;
const QUICK_JNI_METHOD_END_INDEX: usize = 46;
const QUICK_SCAN_LIMIT: usize = 16384;
const QUICK_MIN_LIBART_POINTERS: usize = 40;
const THREAD_CARD_TABLE_OFFSET: usize = 0x90;
const THREAD_EXCEPTION_OFFSET: usize = THREAD_CARD_TABLE_OFFSET + std::mem::size_of::<usize>();
const THREAD_LOCAL_POS_OFFSET: usize = THREAD_CARD_TABLE_OFFSET + 26 * std::mem::size_of::<usize>();
const THREAD_LOCAL_END_OFFSET: usize = THREAD_LOCAL_POS_OFFSET + std::mem::size_of::<usize>();
const MIRROR_OBJECT_CLASS_OFFSET: usize = 0;
const MIRROR_OBJECT_LOCK_WORD_OFFSET: usize = 4;
const MAX_TLAB_FAST_OBJECT_SIZE: u32 = 1 << 20;
const FAST_ART_HANDLE_SCOPE_CAPACITY: usize = 256;
const FAST_ART_STACK_INVOKE_WORDS: usize = 64;

#[repr(C)]
struct FastArtHandleScope {
    link: u64,
    capacity: i32,
    size: u32,
    refs: [u32; FAST_ART_HANDLE_SCOPE_CAPACITY],
}

impl FastArtHandleScope {
    fn new(link: u64) -> Self {
        Self {
            link,
            capacity: FAST_ART_HANDLE_SCOPE_CAPACITY as i32,
            size: 0,
            refs: [0; FAST_ART_HANDLE_SCOPE_CAPACITY],
        }
    }
}

#[inline]
fn update_fast_max(target: &AtomicU64, value: u64) {
    let mut observed = target.load(Ordering::Acquire);
    while value > observed {
        match target.compare_exchange(observed, value, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => break,
            Err(v) => observed = v,
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct FastArtRoot {
    slot: u32,
}

thread_local! {
    static CURRENT_FAST_ART_HANDLE_SCOPE: Cell<*mut FastArtHandleScope> = const { Cell::new(std::ptr::null_mut()) };
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum RequestedCompileKind {
    Auto,
    Fast,
    Baseline,
    Optimized,
}

impl RequestedCompileKind {
    fn from_str(s: &str) -> Option<Self> {
        match s {
            "auto" => Some(Self::Auto),
            "fast" => Some(Self::Fast),
            "baseline" => Some(Self::Baseline),
            "optimized" | "opt" => Some(Self::Optimized),
            _ => None,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Fast => "fast",
            Self::Baseline => "baseline",
            Self::Optimized => "optimized",
        }
    }

    fn sequence(self) -> &'static [u32] {
        match self {
            // Mirrors ART's JitAtFirstUse behavior: fast first, then baseline.
            Self::Auto => &[1, 2, 3],
            Self::Fast => &[1],
            Self::Baseline => &[2],
            Self::Optimized => &[3],
        }
    }
}

pub(crate) struct CompileResult {
    pub(crate) before: u64,
    pub(crate) after: u64,
    pub(crate) success: bool,
    pub(crate) compiled: bool,
    pub(crate) kind: &'static str,
    pub(crate) message: String,
}

#[no_mangle]
pub unsafe extern "C" fn art_quick_callee_save_suspend_method() -> *mut std::ffi::c_void {
    *ART_CALLEE_SAVE_SUSPEND_METHOD.get_or_init(|| unsafe { resolve_callee_save_suspend_method().unwrap_or(0) })
        as *mut std::ffi::c_void
}

#[no_mangle]
pub unsafe extern "C" fn art_quick_test_suspend_entrypoint() -> *mut std::ffi::c_void {
    if crate::is_raw_clone_js_thread() {
        return std::ptr::null_mut();
    }
    *ART_QUICK_TEST_SUSPEND_ENTRYPOINT.get_or_init(|| unsafe {
        let env = get_thread_env().unwrap_or(std::ptr::null_mut());
        current_art_thread(env)
            .and_then(|thread| quick_entrypoint(thread as usize, QUICK_TEST_SUSPEND_INDEX))
            .unwrap_or(0)
    }) as *mut std::ffi::c_void
}

#[no_mangle]
pub unsafe extern "C" fn art_quick_top_quick_frame_offset() -> u64 {
    super::art_controller::cached_thread_top_quick_frame_offset()
        .map(|v| v as u64)
        .unwrap_or(u64::MAX)
}

unsafe fn resolve_callee_save_suspend_method() -> Option<u64> {
    let runtime = resolve_art_runtime_instance()?;

    type GetCalleeSaveMethodFn = unsafe extern "C" fn(*mut std::ffi::c_void, u32) -> *mut std::ffi::c_void;
    for candidate in ART_CALLEE_SAVE_SYMBOLS {
        let sym = crate::jsapi::module::libart_dlsym(candidate.name);
        if sym.is_null() {
            continue;
        }
        let get_method: GetCalleeSaveMethodFn = std::mem::transmute(sym);
        let method = get_method(runtime, CALLEE_SAVE_EVERYTHING_FOR_SUSPEND_CHECK);
        if !method.is_null() {
            crate::jsapi::console::output_message(&format!(
                "[fast] ART callee-save suspend method via {} ({}): {:?}",
                candidate.label, candidate.kind, method
            ));
            return Some(method as u64);
        }
    }

    output_verbose("[fast] ART Runtime::GetCalleeSaveMethod not exported; trying dynamic callee-save anchors");

    if let Some(anchor) = probe_callee_save_dynamic_anchor(runtime) {
        crate::jsapi::console::output_message(&format!(
            "[fast] ART callee-save suspend method via {}: method={:#x}, runtime_off=0x{:x}, set_base={}, init_seq={}",
            anchor.label,
            anchor.method,
            anchor.suspend_method_offset,
            fmt_optional_hex(anchor.set_base_offset),
            fmt_optional_hex(anchor.init_sequence_offset)
        ));
        return Some(anchor.method);
    }

    output_verbose("[fast] ART callee-save dynamic anchors unavailable; trying profile fallback");

    if let Some(method) = resolve_callee_save_suspend_method_from_profile(runtime) {
        return Some(method);
    }

    crate::jsapi::console::output_message("[fast] ART callee-save suspend method unavailable");
    None
}

unsafe fn probe_callee_save_dynamic_anchor(runtime: *mut std::ffi::c_void) -> Option<ArtCalleeSaveDynamicResolution> {
    let runtime_addr = runtime as u64;
    let set_base_offset = decode_callee_save_base_offset_from_setter();
    let init_sequence_offset = scan_callee_save_suspend_offset_from_runtime_init();

    if let Some(base_offset) = set_base_offset {
        let suspend_method_offset =
            base_offset + CALLEE_SAVE_EVERYTHING_FOR_SUSPEND_CHECK as u64 * CALLEE_SAVE_SLOT_SIZE;
        if suspend_method_offset <= CALLEE_SAVE_MAX_RUNTIME_OFFSET
            && looks_like_callee_save_method_array(runtime_addr, suspend_method_offset)
        {
            let method = read_runtime_callee_save_method(runtime_addr, suspend_method_offset);
            if method != 0 {
                let label = if init_sequence_offset == Some(suspend_method_offset) {
                    "setCalleeSaveMethod+runtimeInitSequence"
                } else {
                    if let Some(init_offset) = init_sequence_offset {
                        output_verbose(&format!(
                            "[fast] ART callee-save init sequence offset 0x{:x} differs from setter offset 0x{:x}",
                            init_offset, suspend_method_offset
                        ));
                    }
                    "setCalleeSaveMethod"
                };
                return Some(ArtCalleeSaveDynamicResolution {
                    label,
                    method,
                    suspend_method_offset,
                    set_base_offset,
                    init_sequence_offset,
                });
            }
        } else {
            output_verbose(&format!(
                "[fast] ART SetCalleeSaveMethod decoded base offset 0x{:x}, but runtime array validation failed",
                base_offset
            ));
        }
    }

    if let Some(suspend_method_offset) = init_sequence_offset {
        if suspend_method_offset <= CALLEE_SAVE_MAX_RUNTIME_OFFSET
            && looks_like_callee_save_method_array(runtime_addr, suspend_method_offset)
        {
            let method = read_runtime_callee_save_method(runtime_addr, suspend_method_offset);
            if method != 0 {
                return Some(ArtCalleeSaveDynamicResolution {
                    label: "runtimeInitSequence",
                    method,
                    suspend_method_offset,
                    set_base_offset,
                    init_sequence_offset,
                });
            }
        } else {
            output_verbose(&format!(
                "[fast] ART callee-save runtime init sequence offset 0x{:x}, but runtime array validation failed",
                suspend_method_offset
            ));
        }
    }

    None
}

unsafe fn decode_callee_save_base_offset_from_setter() -> Option<u64> {
    let setter = crate::jsapi::module::libart_dlsym(ART_SET_CALLEE_SAVE_METHOD_SYMBOL) as u64;
    if setter == 0 || !crate::jsapi::module::is_in_libart(setter) {
        return None;
    }

    let mut regs = [RuntimeRegExpr::Unknown; 32];
    regs[0] = RuntimeRegExpr::RuntimePlus(0);

    for off in (0..SET_CALLEE_SAVE_SCAN_BYTES).step_by(4) {
        let instr = std::ptr::read_unaligned((setter + off as u64) as *const u32);
        if let Some(base_offset) = decode_callee_save_setter_store(instr, &regs) {
            if base_offset <= CALLEE_SAVE_MAX_RUNTIME_OFFSET {
                return Some(base_offset);
            }
        }
        update_runtime_reg_exprs(instr, &mut regs);
    }

    None
}

fn decode_callee_save_setter_store(instr: u32, regs: &[RuntimeRegExpr; 32]) -> Option<u64> {
    if let Some((rt, rn, rm, option, scaled)) = decode_str64_register_offset(instr) {
        if rt == 1 && rm == 2 && scaled && matches!(option, 0b010 | 0b011) {
            if let RuntimeRegExpr::RuntimePlus(base_offset) = regs[rn as usize] {
                return Some(base_offset);
            }
        }
    }

    if let Some((rt, rn, imm)) = decode_str64_unsigned_imm(instr) {
        if rt == 1 {
            if let RuntimeRegExpr::RuntimePlusTypeIndex(base_offset) = regs[rn as usize] {
                return base_offset.checked_add(imm);
            }
        }
    }

    None
}

fn update_runtime_reg_exprs(instr: u32, regs: &mut [RuntimeRegExpr; 32]) {
    if let Some((rd, rn, imm)) = decode_add64_immediate(instr) {
        regs[rd as usize] = match regs[rn as usize] {
            RuntimeRegExpr::RuntimePlus(base) => base
                .checked_add(imm)
                .map(RuntimeRegExpr::RuntimePlus)
                .unwrap_or(RuntimeRegExpr::Unknown),
            RuntimeRegExpr::RuntimePlusTypeIndex(base) => base
                .checked_add(imm)
                .map(RuntimeRegExpr::RuntimePlusTypeIndex)
                .unwrap_or(RuntimeRegExpr::Unknown),
            RuntimeRegExpr::Unknown => RuntimeRegExpr::Unknown,
        };
        return;
    }

    if let Some((rd, rn, rm, shift)) = decode_add64_shifted_register(instr) {
        regs[rd as usize] = if rm == 2 && shift == 3 {
            match regs[rn as usize] {
                RuntimeRegExpr::RuntimePlus(base) => RuntimeRegExpr::RuntimePlusTypeIndex(base),
                _ => RuntimeRegExpr::Unknown,
            }
        } else {
            RuntimeRegExpr::Unknown
        };
        return;
    }

    if let Some((rd, rm)) = decode_mov64_register(instr) {
        regs[rd as usize] = regs[rm as usize];
    }
}

unsafe fn scan_callee_save_suspend_offset_from_runtime_init() -> Option<u64> {
    for (start, end) in libart_executable_ranges() {
        if let Some(offset) = scan_callee_save_suspend_offset_in_range(start, end) {
            return Some(offset);
        }
    }
    None
}

unsafe fn scan_callee_save_suspend_offset_in_range(start: u64, end: u64) -> Option<u64> {
    let mut addr = start;
    while addr + 4 <= end {
        if decode_callee_save_type_mov(addr).is_some_and(|imm| imm == CALLEE_SAVE_EVERYTHING_FOR_SUSPEND_CHECK) {
            if let Some((base_reg, suspend_offset)) =
                decode_callee_save_init_block(addr, CALLEE_SAVE_EVERYTHING_FOR_SUSPEND_CHECK, start, end)
            {
                if suspend_offset >= CALLEE_SAVE_EVERYTHING_FOR_SUSPEND_CHECK as u64 * CALLEE_SAVE_SLOT_SIZE
                    && suspend_offset <= CALLEE_SAVE_MAX_RUNTIME_OFFSET
                {
                    let base_offset =
                        suspend_offset - CALLEE_SAVE_EVERYTHING_FOR_SUSPEND_CHECK as u64 * CALLEE_SAVE_SLOT_SIZE;
                    if verify_callee_save_init_sequence(addr, base_reg, base_offset, start, end) {
                        return Some(suspend_offset);
                    }
                }
            }
        }
        addr += 4;
    }
    None
}

unsafe fn verify_callee_save_init_sequence(
    type5_mov_addr: u64,
    base_reg: u32,
    base_offset: u64,
    range_start: u64,
    range_end: u64,
) -> bool {
    let window_start = type5_mov_addr
        .saturating_sub(INIT_CALLEE_SAVE_VERIFY_WINDOW)
        .max(range_start);
    let window_end = type5_mov_addr.saturating_add(16).min(range_end);
    let mut seen_mask = 0u32;
    let mut addr = window_start;

    while addr + 4 <= window_end {
        if let Some(ty) = decode_callee_save_type_mov(addr) {
            if ty < CALLEE_SAVE_METHOD_COUNT as u32 {
                if let Some((candidate_base_reg, slot_offset)) =
                    decode_callee_save_init_block(addr, ty, range_start, range_end)
                {
                    if candidate_base_reg == base_reg && slot_offset == base_offset + ty as u64 * CALLEE_SAVE_SLOT_SIZE
                    {
                        seen_mask |= 1u32 << ty;
                    }
                }
            }
        }
        addr += 4;
    }

    seen_mask & ((1u32 << CALLEE_SAVE_METHOD_COUNT) - 1) == (1u32 << CALLEE_SAVE_METHOD_COUNT) - 1
}

unsafe fn decode_callee_save_init_block(
    mov_w2_addr: u64,
    expected_type: u32,
    range_start: u64,
    range_end: u64,
) -> Option<(u32, u64)> {
    if decode_callee_save_type_mov(mov_w2_addr) != Some(expected_type) {
        return None;
    }
    if !has_following_bl(mov_w2_addr, range_end) {
        return None;
    }

    let search_start = mov_w2_addr
        .saturating_sub(INIT_CALLEE_SAVE_BLOCK_BACK_INSNS * 4)
        .max(range_start);
    let mut addr = mov_w2_addr;
    while addr >= search_start + 4 {
        addr -= 4;
        let instr = std::ptr::read_unaligned(addr as *const u32);
        if let Some((_rt, rn, imm)) = decode_ldr64_unsigned_imm(instr) {
            if rn != 31 && imm % CALLEE_SAVE_SLOT_SIZE == 0 && imm <= CALLEE_SAVE_MAX_RUNTIME_OFFSET {
                return Some((rn, imm));
            }
        }
    }
    None
}

unsafe fn has_following_bl(mov_w2_addr: u64, range_end: u64) -> bool {
    let mut addr = mov_w2_addr + 4;
    let end = mov_w2_addr.saturating_add(12).min(range_end);
    while addr + 4 <= end {
        let instr = std::ptr::read_unaligned(addr as *const u32);
        if is_bl_immediate(instr) {
            return true;
        }
        addr += 4;
    }
    false
}

fn libart_executable_ranges() -> Vec<(u64, u64)> {
    let maps = match crate::jsapi::util::read_proc_self_maps() {
        Some(maps) => maps,
        None => return Vec::new(),
    };

    crate::jsapi::util::proc_maps_entries(&maps)
        .filter_map(|entry| {
            let path = entry.path?;
            let prot = entry.prot_flags();
            if prot & libc::PROT_READ == 0 || prot & libc::PROT_EXEC == 0 {
                return None;
            }
            if !path.ends_with("/libart.so") {
                return None;
            }
            if !(path.starts_with("/apex/") || path.starts_with("/system/") || path.starts_with("/system_ext/")) {
                return None;
            }
            Some((entry.start, entry.end))
        })
        .collect()
}

fn decode_str64_register_offset(instr: u32) -> Option<(u32, u32, u32, u32, bool)> {
    if instr & 0x3b60_0c00 != 0x3820_0800 {
        return None;
    }
    let rt = instr & 0x1f;
    let rn = (instr >> 5) & 0x1f;
    let scaled = ((instr >> 12) & 1) != 0;
    let option = (instr >> 13) & 0x7;
    let rm = (instr >> 16) & 0x1f;
    Some((rt, rn, rm, option, scaled))
}

fn decode_str64_unsigned_imm(instr: u32) -> Option<(u32, u32, u64)> {
    if instr & 0xffc0_0000 != 0xf900_0000 {
        return None;
    }
    let rt = instr & 0x1f;
    let rn = (instr >> 5) & 0x1f;
    let imm = ((instr >> 10) & 0xfff) as u64 * 8;
    Some((rt, rn, imm))
}

fn decode_ldr64_unsigned_imm(instr: u32) -> Option<(u32, u32, u64)> {
    if instr & 0xffc0_0000 != 0xf940_0000 {
        return None;
    }
    let rt = instr & 0x1f;
    let rn = (instr >> 5) & 0x1f;
    let imm = ((instr >> 10) & 0xfff) as u64 * 8;
    Some((rt, rn, imm))
}

fn decode_add64_immediate(instr: u32) -> Option<(u32, u32, u64)> {
    if instr & 0xffc0_0000 != 0x9100_0000 {
        return None;
    }
    let rd = instr & 0x1f;
    let rn = (instr >> 5) & 0x1f;
    let shift = (instr >> 22) & 0x3;
    if shift > 1 {
        return None;
    }
    let mut imm = ((instr >> 10) & 0xfff) as u64;
    if shift == 1 {
        imm <<= 12;
    }
    Some((rd, rn, imm))
}

fn decode_add64_shifted_register(instr: u32) -> Option<(u32, u32, u32, u32)> {
    if instr & 0xff20_0000 != 0x8b00_0000 {
        return None;
    }
    if (instr >> 22) & 0x3 != 0 {
        return None;
    }
    let rd = instr & 0x1f;
    let rn = (instr >> 5) & 0x1f;
    let shift = (instr >> 10) & 0x3f;
    let rm = (instr >> 16) & 0x1f;
    Some((rd, rn, rm, shift))
}

fn decode_mov64_register(instr: u32) -> Option<(u32, u32)> {
    if instr & 0xffe0_ffe0 != 0xaa00_03e0 {
        return None;
    }
    let rd = instr & 0x1f;
    let rm = (instr >> 16) & 0x1f;
    if rd == 31 || rm == 31 {
        return None;
    }
    Some((rd, rm))
}

unsafe fn decode_callee_save_type_mov(addr: u64) -> Option<u32> {
    let instr = std::ptr::read_unaligned(addr as *const u32);
    if instr == 0x2a1f_03e2 {
        return Some(0);
    }
    if instr & 0xffe0_001f != 0x5280_0002 {
        return None;
    }
    if ((instr >> 21) & 0x3) != 0 {
        return None;
    }
    Some((instr >> 5) & 0xffff)
}

fn is_bl_immediate(instr: u32) -> bool {
    instr & 0xfc00_0000 == 0x9400_0000
}

unsafe fn read_runtime_callee_save_method(runtime_addr: u64, suspend_method_offset: u64) -> u64 {
    std::ptr::read_volatile((runtime_addr + suspend_method_offset) as *const u64) & super::PAC_STRIP_MASK
}

fn fmt_optional_hex(value: Option<u64>) -> String {
    value
        .map(|v| format!("0x{:x}", v))
        .unwrap_or_else(|| "none".to_string())
}

unsafe fn resolve_callee_save_suspend_method_from_profile(runtime: *mut std::ffi::c_void) -> Option<u64> {
    let sdk = get_android_api_level();
    let runtime_addr = runtime as u64;

    for profile in ART_CALLEE_SAVE_PROFILES {
        if sdk < profile.min_sdk || sdk > profile.max_sdk {
            continue;
        }

        let method = read_runtime_callee_save_method(runtime_addr, profile.suspend_method_offset);
        if method == 0 || !looks_like_callee_save_method_array(runtime_addr, profile.suspend_method_offset) {
            continue;
        }

        crate::jsapi::console::output_message(&format!(
            "[fast] ART callee-save suspend method via profile {}: method={:#x}, runtime_off=0x{:x}, sdk={}",
            profile.label, method, profile.suspend_method_offset, sdk
        ));
        return Some(method);
    }

    None
}

unsafe fn probe_callee_save_profile_fallback(
    runtime: *mut std::ffi::c_void,
) -> Option<(&'static ArtCalleeSaveProfile, u64)> {
    let sdk = get_android_api_level();
    let runtime_addr = runtime as u64;

    for profile in ART_CALLEE_SAVE_PROFILES {
        if sdk < profile.min_sdk || sdk > profile.max_sdk {
            continue;
        }

        let method = read_runtime_callee_save_method(runtime_addr, profile.suspend_method_offset);
        if method != 0 && looks_like_callee_save_method_array(runtime_addr, profile.suspend_method_offset) {
            return Some((profile, method));
        }
    }

    None
}

unsafe fn looks_like_callee_save_method_array(runtime: u64, suspend_method_offset: u64) -> bool {
    let first = runtime + suspend_method_offset - 5 * 8;
    let mut previous = 0u64;
    for i in 0..6u64 {
        let method = std::ptr::read_volatile((first + i * 8) as *const u64) & super::PAC_STRIP_MASK;
        if method == 0 || (method & 0x3) != 0 {
            return false;
        }
        if previous != 0 && method == previous {
            return false;
        }
        previous = method;
    }
    true
}

pub(super) unsafe extern "C" fn js_art_symbol_probe(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let obj = JSValue(ffi::JS_NewObject(ctx));
    let sdk = get_android_api_level();
    obj.set_property(ctx, "sdk", JSValue::int(sdk));
    obj.set_property(ctx, "codename", JSValue::string(ctx, get_android_codename()));
    obj.set_property(ctx, "targetRange", JSValue::string(ctx, "Android 12-16 / API 31-36"));
    obj.set_property(ctx, "inTargetRange", JSValue::bool((31..=36).contains(&sdk)));

    let runtime_instance = crate::jsapi::module::libart_dlsym("_ZN3art7Runtime9instance_E") as u64;
    let runtime_current = crate::jsapi::module::libart_dlsym("_ZN3art7Runtime7CurrentEv") as u64;
    let set_callee_save = crate::jsapi::module::libart_dlsym(ART_SET_CALLEE_SAVE_METHOD_SYMBOL) as u64;
    let create_callee_save = crate::jsapi::module::libart_dlsym(ART_CREATE_CALLEE_SAVE_METHOD_SYMBOL) as u64;
    obj.set_property(
        ctx,
        "runtimeInstanceSymbol",
        JSValue(ffi::JS_NewBigUint64(ctx, runtime_instance)),
    );
    obj.set_property(
        ctx,
        "runtimeCurrentSymbol",
        JSValue(ffi::JS_NewBigUint64(ctx, runtime_current)),
    );
    obj.set_property(
        ctx,
        "setCalleeSaveMethodSymbol",
        JSValue(ffi::JS_NewBigUint64(ctx, set_callee_save)),
    );
    obj.set_property(
        ctx,
        "createCalleeSaveMethodSymbol",
        JSValue(ffi::JS_NewBigUint64(ctx, create_callee_save)),
    );

    let symbols = JSValue(ffi::JS_NewObject(ctx));
    let mut selected_label = "";
    let mut selected_name = "";
    let mut selected_kind = "";
    let mut selected_addr = 0u64;

    for candidate in ART_CALLEE_SAVE_SYMBOLS {
        let addr = crate::jsapi::module::libart_dlsym(candidate.name) as u64;
        let item = JSValue(ffi::JS_NewObject(ctx));
        item.set_property(ctx, "name", JSValue::string(ctx, candidate.name));
        item.set_property(ctx, "kind", JSValue::string(ctx, candidate.kind));
        item.set_property(ctx, "found", JSValue::bool(addr != 0));
        item.set_property(ctx, "address", JSValue(ffi::JS_NewBigUint64(ctx, addr)));
        symbols.set_property(ctx, candidate.label, item);

        if selected_addr == 0 && addr != 0 {
            selected_label = candidate.label;
            selected_name = candidate.name;
            selected_kind = candidate.kind;
            selected_addr = addr;
        }
    }

    obj.set_property(ctx, "calleeSaveSymbols", symbols);
    obj.set_property(ctx, "selectedLabel", JSValue::string(ctx, selected_label));
    obj.set_property(ctx, "selectedName", JSValue::string(ctx, selected_name));
    obj.set_property(ctx, "selectedKind", JSValue::string(ctx, selected_kind));
    obj.set_property(
        ctx,
        "selectedAddress",
        JSValue(ffi::JS_NewBigUint64(ctx, selected_addr)),
    );

    let dynamic = JSValue(ffi::JS_NewObject(ctx));
    let mut dynamic_valid = false;
    if let Some(runtime) = resolve_art_runtime_instance() {
        let runtime_addr = runtime as u64;
        dynamic.set_property(ctx, "runtime", JSValue(ffi::JS_NewBigUint64(ctx, runtime_addr)));
        dynamic.set_property(
            ctx,
            "setBaseOffset",
            JSValue(ffi::JS_NewBigUint64(
                ctx,
                decode_callee_save_base_offset_from_setter().unwrap_or(u64::MAX),
            )),
        );
        dynamic.set_property(
            ctx,
            "initSequenceOffset",
            JSValue(ffi::JS_NewBigUint64(
                ctx,
                scan_callee_save_suspend_offset_from_runtime_init().unwrap_or(u64::MAX),
            )),
        );
        if let Some(anchor) = probe_callee_save_dynamic_anchor(runtime) {
            dynamic_valid = true;
            dynamic.set_property(ctx, "valid", JSValue::bool(true));
            dynamic.set_property(ctx, "source", JSValue::string(ctx, anchor.label));
            dynamic.set_property(
                ctx,
                "runtimeOffset",
                JSValue(ffi::JS_NewBigUint64(ctx, anchor.suspend_method_offset)),
            );
            dynamic.set_property(
                ctx,
                "candidateMethod",
                JSValue(ffi::JS_NewBigUint64(ctx, anchor.method)),
            );
        } else {
            dynamic.set_property(ctx, "valid", JSValue::bool(false));
        }
    } else {
        dynamic.set_property(ctx, "valid", JSValue::bool(false));
        dynamic.set_property(ctx, "runtime", JSValue(ffi::JS_NewBigUint64(ctx, 0)));
        dynamic.set_property(ctx, "setBaseOffset", JSValue(ffi::JS_NewBigUint64(ctx, u64::MAX)));
        dynamic.set_property(ctx, "initSequenceOffset", JSValue(ffi::JS_NewBigUint64(ctx, u64::MAX)));
    }
    obj.set_property(ctx, "calleeSaveDynamicAnchor", dynamic);

    let fallback = JSValue(ffi::JS_NewObject(ctx));
    let mut fallback_valid = false;
    if let Some(runtime) = resolve_art_runtime_instance() {
        let runtime_addr = runtime as u64;
        fallback.set_property(ctx, "runtime", JSValue(ffi::JS_NewBigUint64(ctx, runtime_addr)));
        if let Some((profile, method)) = probe_callee_save_profile_fallback(runtime) {
            fallback_valid = true;
            fallback.set_property(ctx, "valid", JSValue::bool(true));
            fallback.set_property(ctx, "profile", JSValue::string(ctx, profile.label));
            fallback.set_property(ctx, "minSdk", JSValue::int(profile.min_sdk));
            fallback.set_property(ctx, "maxSdk", JSValue::int(profile.max_sdk));
            fallback.set_property(
                ctx,
                "runtimeOffset",
                JSValue(ffi::JS_NewBigUint64(ctx, profile.suspend_method_offset)),
            );
            fallback.set_property(ctx, "candidateMethod", JSValue(ffi::JS_NewBigUint64(ctx, method)));
        } else {
            fallback.set_property(ctx, "valid", JSValue::bool(false));
        }
    } else {
        fallback.set_property(ctx, "valid", JSValue::bool(false));
        fallback.set_property(ctx, "runtime", JSValue(ffi::JS_NewBigUint64(ctx, 0)));
    }
    obj.set_property(ctx, "calleeSaveProfileFallback", fallback);

    obj.set_property(
        ctx,
        "quickCalleeSaveFrameSupported",
        JSValue::bool(selected_addr != 0 || dynamic_valid || fallback_valid),
    );
    obj.0
}

unsafe fn resolve_art_runtime_instance() -> Option<*mut std::ffi::c_void> {
    let instance_ptr = crate::jsapi::module::libart_dlsym("_ZN3art7Runtime9instance_E");
    if !instance_ptr.is_null() {
        let raw = std::ptr::read_volatile(instance_ptr as *const u64) & super::PAC_STRIP_MASK;
        if raw != 0 {
            return Some(raw as *mut std::ffi::c_void);
        }
    }

    let current_sym = crate::jsapi::module::libart_dlsym("_ZN3art7Runtime7CurrentEv");
    if !current_sym.is_null() {
        let current: unsafe extern "C" fn() -> *mut std::ffi::c_void = std::mem::transmute(current_sym);
        let runtime = current();
        if !runtime.is_null() {
            return Some(runtime);
        }
    }

    crate::jsapi::console::output_message("[fast] ART Runtime::instance_ unavailable");
    None
}

fn fast_methods() -> &'static Mutex<Vec<FastMethod>> {
    FAST_METHODS.get_or_init(|| Mutex::new(Vec::new()))
}

fn fast_constructors() -> &'static Mutex<Vec<FastConstructor>> {
    FAST_CONSTRUCTORS.get_or_init(|| Mutex::new(Vec::new()))
}

fn fast_fields() -> &'static Mutex<Vec<FastField>> {
    FAST_FIELDS.get_or_init(|| Mutex::new(Vec::new()))
}

fn make_shorty(sig: &str) -> CString {
    let return_sig = sig
        .rsplit_once(')')
        .map(|(_, ret)| ret)
        .filter(|ret| !ret.is_empty())
        .unwrap_or("V");
    let mut shorty = Vec::with_capacity(sig.len() + 1);
    shorty.push(shorty_char(return_sig));
    for param in parse_jni_param_types(sig) {
        shorty.push(shorty_char(param.as_str()));
    }
    CString::new(shorty).unwrap_or_else(|_| CString::new("V").unwrap())
}

fn shorty_char(type_sig: &str) -> u8 {
    match type_sig.as_bytes().first().copied().unwrap_or(b'V') {
        b'L' | b'[' => b'L',
        ch => ch,
    }
}

pub(in crate::jsapi::java) unsafe fn resolve_fast_method(
    env: JniEnv,
    class_name: &str,
    method_name: &str,
    signature: &str,
    force_static: bool,
) -> Result<(u64, u64, u64, bool), String> {
    let c_method = CString::new(method_name).map_err(|_| "invalid method name")?;
    let c_sig = CString::new(signature).map_err(|_| "invalid signature")?;
    let cls = find_class_safe(env, class_name);
    if cls.is_null() {
        jni_check_exc(env);
        return Err(format!("FindClass('{}') failed", class_name));
    }

    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
    let delete_global_ref: DeleteGlobalRefFn = jni_fn!(env, DeleteGlobalRefFn, JNI_DELETE_GLOBAL_REF);
    let new_global_ref: NewGlobalRefFn = jni_fn!(env, NewGlobalRefFn, JNI_NEW_GLOBAL_REF);
    let class_global = new_global_ref(env, cls);
    if jni_null_or_exc(env, class_global) {
        delete_local_ref(env, cls);
        return Err(format!("NewGlobalRef failed for {}", class_name));
    }

    if !force_static {
        let get_method_id: GetMethodIdFn = jni_fn!(env, GetMethodIdFn, JNI_GET_METHOD_ID);
        let method_id = get_method_id(env, cls, c_method.as_ptr(), c_sig.as_ptr());
        if !jni_null_or_exc(env, method_id) {
            let art_method = decode_method_id(env, cls, method_id as u64, false);
            delete_local_ref(env, cls);
            return Ok((art_method, method_id as u64, class_global as u64, false));
        }
    }

    let get_static_method_id: GetStaticMethodIdFn = jni_fn!(env, GetStaticMethodIdFn, JNI_GET_STATIC_METHOD_ID);
    let method_id = get_static_method_id(env, cls, c_method.as_ptr(), c_sig.as_ptr());
    if !jni_null_or_exc(env, method_id) {
        let art_method = decode_method_id(env, cls, method_id as u64, true);
        delete_local_ref(env, cls);
        return Ok((art_method, method_id as u64, class_global as u64, true));
    }
    delete_local_ref(env, cls);
    delete_global_ref(env, class_global);

    Err(format!("method not found: {}.{}{}", class_name, method_name, signature))
}

pub(in crate::jsapi::java) unsafe fn resolve_fast_field(
    env: JniEnv,
    class_name: String,
    field_name: String,
    requested_sig: Option<String>,
) -> Result<FastField, String> {
    let Some(spec) = get_art_field_spec() else {
        return Err("unsupported ArtField layout".to_string());
    };

    cache_fields_for_class(env, &class_name);
    let (jni_sig, field_id, is_static) = {
        let guard = FIELD_CACHE.lock().unwrap_or_else(|e| e.into_inner());
        let cached = guard
            .as_ref()
            .and_then(|cache| cache.get(&class_name))
            .and_then(|fields| fields.get(&field_name))
            .map(|info| (info.jni_sig.clone(), info.field_id, info.is_static));
        match cached {
            Some(v) => v,
            None => {
                let Some(sig) = requested_sig.clone() else {
                    return Err(format!("field not found: {}.{}", class_name, field_name));
                };
                let cls = find_class_safe(env, &class_name);
                if cls.is_null() {
                    return Err(format!("class not found: {}", class_name));
                }
                let c_name = CString::new(field_name.as_str()).map_err(|_| "invalid field name".to_string())?;
                let c_sig = CString::new(sig.as_str()).map_err(|_| "invalid field signature".to_string())?;
                jni_check_exc(env);
                let get_field_id: GetFieldIdFn = jni_fn!(env, GetFieldIdFn, JNI_GET_FIELD_ID);
                let field_id = get_field_id(env, cls, c_name.as_ptr(), c_sig.as_ptr());
                if !jni_null_or_exc(env, field_id) {
                    (sig, field_id, false)
                } else {
                    let get_static_field_id: GetStaticFieldIdFn =
                        jni_fn!(env, GetStaticFieldIdFn, JNI_GET_STATIC_FIELD_ID);
                    let field_id = get_static_field_id(env, cls, c_name.as_ptr(), c_sig.as_ptr());
                    if !jni_null_or_exc(env, field_id) {
                        (sig, field_id, true)
                    } else {
                        return Err(format!("field not found: {}.{}{}", class_name, field_name, sig));
                    }
                }
            }
        }
    };

    if let Some(sig) = requested_sig.as_ref() {
        if sig != &jni_sig {
            return Err("field signature mismatch".to_string());
        }
    }
    if is_static {
        return Err("fastField only supports instance fields".to_string());
    }
    if !is_fast_field_type(&jni_sig) {
        return Err("fastField only supports primitive/object instance fields".to_string());
    }

    let cls = find_class_safe(env, &class_name);
    if cls.is_null() {
        return Err(format!("class not found: {}", class_name));
    }
    let art_field = decode_field_id(env, cls, field_id as u64, is_static);
    jni_check_exc(env);
    if art_field == 0 {
        return Err(format!("failed to decode field id: {}.{}", class_name, field_name));
    }
    refresh_mem_regions();
    let offset = safe_read_u32(art_field + spec.offset_offset as u64);
    if offset == 0 {
        return Err(format!("invalid field offset: {}.{}", class_name, field_name));
    }

    Ok(FastField {
        art_field,
        offset,
        is_static,
        value_type: jni_sig.as_bytes()[0],
        jni_sig,
        class_name,
        field_name,
    })
}

pub(crate) fn get_fast_method(handle: u64) -> Option<FastMethod> {
    if handle == 0 {
        return None;
    }
    let methods = fast_methods().lock().unwrap_or_else(|e| e.into_inner());
    methods.get((handle - 1) as usize).cloned()
}

pub(crate) fn get_fast_constructor(handle: u64) -> Option<FastConstructor> {
    if handle == 0 {
        return None;
    }
    let constructors = fast_constructors().lock().unwrap_or_else(|e| e.into_inner());
    constructors.get((handle - 1) as usize).cloned()
}

pub(crate) fn get_fast_field(handle: u64) -> Option<FastField> {
    if handle == 0 {
        return None;
    }
    let fields = fast_fields().lock().unwrap_or_else(|e| e.into_inner());
    fields.get((handle - 1) as usize).cloned()
}

unsafe fn is_fast_field_type(sig: &str) -> bool {
    matches!(
        sig.as_bytes().first().copied(),
        Some(b'Z' | b'B' | b'C' | b'S' | b'I' | b'J' | b'F' | b'D' | b'L' | b'[')
    )
}

unsafe fn parse_fast_options(
    ctx: *mut ffi::JSContext,
    argc: i32,
    argv: *mut ffi::JSValue,
    opt_index: i32,
) -> Result<(bool, RequestedCompileKind), ffi::JSValue> {
    if argc <= opt_index {
        return Ok((false, RequestedCompileKind::Auto));
    }
    let opt = JSValue(*argv.add(opt_index as usize));
    if opt.is_bool() {
        return Ok((opt.to_bool().unwrap_or(false), RequestedCompileKind::Auto));
    }
    if opt.is_string() {
        let Some(kind_s) = opt.to_string(ctx) else {
            return Ok((false, RequestedCompileKind::Auto));
        };
        let Some(kind) = RequestedCompileKind::from_str(kind_s.as_str()) else {
            return Err(throw_type_error(ctx, b"invalid compile kind\0"));
        };
        return Ok((true, kind));
    }
    if opt.is_object() {
        let compile_val = opt.get_property(ctx, "compile");
        let should_compile = compile_val.to_bool().unwrap_or(false);
        compile_val.free(ctx);

        let kind_val = opt.get_property(ctx, "kind");
        let kind = if kind_val.is_string() {
            let kind_s = kind_val.to_string(ctx).unwrap_or_else(|| "auto".to_string());
            let Some(kind) = RequestedCompileKind::from_str(kind_s.as_str()) else {
                kind_val.free(ctx);
                return Err(throw_type_error(ctx, b"invalid compile kind\0"));
            };
            kind
        } else {
            RequestedCompileKind::Auto
        };
        kind_val.free(ctx);
        return Ok((should_compile, kind));
    }
    Ok((false, RequestedCompileKind::Auto))
}

pub(crate) unsafe extern "C" fn js_java_fast_method(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 3 {
        return throw_type_error(
            ctx,
            b"fastMethod(class, method, sig[, options]) requires at least 3 arguments\0",
        );
    }

    let class_name = match extract_string_arg(ctx, JSValue(*argv), b"arg 0 must be string\0") {
        Ok(s) => s,
        Err(e) => return e,
    };
    let method_name = match extract_string_arg(ctx, JSValue(*argv.add(1)), b"arg 1 must be string\0") {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_str = match extract_string_arg(ctx, JSValue(*argv.add(2)), b"arg 2 must be string\0") {
        Ok(s) => s,
        Err(e) => return e,
    };
    let (actual_sig, force_static) = if let Some(stripped) = sig_str.strip_prefix("static:") {
        (stripped.to_string(), true)
    } else {
        (sig_str, false)
    };

    let (should_compile, compile_kind) = match parse_fast_options(ctx, argc, argv, 3) {
        Ok(v) => v,
        Err(e) => return e,
    };

    let raw_clone = crate::is_raw_clone_js_thread();
    let (art_method, class_global_ref, class_mirror, is_static) = if raw_clone {
        match super::callback::resolve_fast_method_via_executor(
            class_name.clone(),
            method_name.clone(),
            actual_sig.clone(),
            force_static,
            should_compile,
            compile_kind,
        ) {
            Ok((art_method, class_global_ref, class_mirror, is_static)) => {
                (art_method, class_global_ref, class_mirror, is_static)
            }
            Err(msg) => return throw_internal_error(ctx, msg),
        }
    } else {
        let env = match ensure_jni_initialized() {
            Ok(e) => e,
            Err(msg) => return throw_internal_error(ctx, msg),
        };

        let (art_method, _method_id, class_global_ref, is_static) =
            match resolve_fast_method(env, &class_name, &method_name, &actual_sig, force_static) {
                Ok(v) => v,
                Err(msg) => return throw_internal_error(ctx, msg),
            };

        let spec = get_art_method_spec(env, art_method);
        let bridge = find_art_bridge_functions(env, spec.entry_point_offset);
        let mut entry_point = read_entry_point(art_method, spec.entry_point_offset);
        if is_art_quick_entrypoint(entry_point, bridge) && should_compile {
            let compile = compile_art_method_to_quick(env, art_method, spec.entry_point_offset, bridge, compile_kind);
            entry_point = compile.after;
            crate::jsapi::console::output_verbose(&format!(
                "[fastMethod] compile {}.{}{} kind={} success={} before={:#x} after={:#x} msg={}",
                class_name,
                method_name,
                actual_sig,
                compile.kind,
                compile.success,
                compile.before,
                compile.after,
                compile.message
            ));
        }
        if is_art_quick_entrypoint(entry_point, bridge) {
            return throw_internal_error(
                ctx,
                format!(
                    "fastMethod rejected {}.{}{}: no independent quick entrypoint (entry={:#x})",
                    class_name, method_name, actual_sig, entry_point
                ),
            );
        }
        (
            art_method,
            class_global_ref,
            super::decode_global_jobject_raw(env, class_global_ref as *mut std::ffi::c_void).unwrap_or(0),
            is_static,
        )
    };

    let method = FastMethod {
        art_method,
        class_global_ref,
        class_mirror,
        is_static,
        param_types: parse_jni_param_types(&actual_sig),
        shorty: make_shorty(&actual_sig),
    };
    let mut methods = fast_methods().lock().unwrap_or_else(|e| e.into_inner());
    methods.push(method);
    js_u64_to_js_number_or_bigint(ctx, methods.len() as u64)
}

pub(crate) unsafe extern "C" fn js_java_fast_constructor(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return throw_type_error(
            ctx,
            b"fastConstructor(class, sig[, options]) requires at least 2 arguments\0",
        );
    }

    let class_name = match extract_string_arg(ctx, JSValue(*argv), b"arg 0 must be string\0") {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_str = match extract_string_arg(ctx, JSValue(*argv.add(1)), b"arg 1 must be string\0") {
        Ok(s) => s,
        Err(e) => return e,
    };
    if get_return_type_from_sig(&sig_str) != b'V' {
        return throw_type_error(ctx, b"constructor signature must return void\0");
    }

    let (should_compile, compile_kind) = match parse_fast_options(ctx, argc, argv, 2) {
        Ok(v) => v,
        Err(e) => return e,
    };

    let raw_clone = crate::is_raw_clone_js_thread();
    let (art_method, class_global_ref, class_mirror, is_static) = if raw_clone {
        match super::callback::resolve_fast_method_via_executor(
            class_name.clone(),
            "<init>".to_string(),
            sig_str.clone(),
            false,
            should_compile,
            compile_kind,
        ) {
            Ok((art_method, class_global_ref, class_mirror, is_static)) => {
                (art_method, class_global_ref, class_mirror, is_static)
            }
            Err(msg) => return throw_internal_error(ctx, msg),
        }
    } else {
        let env = match ensure_jni_initialized() {
            Ok(e) => e,
            Err(msg) => return throw_internal_error(ctx, msg),
        };

        let (art_method, _method_id, class_global_ref, is_static) =
            match resolve_fast_method(env, &class_name, "<init>", &sig_str, false) {
                Ok(v) => v,
                Err(msg) => return throw_internal_error(ctx, msg),
            };

        let spec = get_art_method_spec(env, art_method);
        let bridge = find_art_bridge_functions(env, spec.entry_point_offset);
        let mut entry_point = read_entry_point(art_method, spec.entry_point_offset);
        if is_art_quick_entrypoint(entry_point, bridge) && should_compile {
            let compile = compile_art_method_to_quick(env, art_method, spec.entry_point_offset, bridge, compile_kind);
            entry_point = compile.after;
            crate::jsapi::console::output_verbose(&format!(
                "[fastConstructor] compile {}.<init>{} kind={} success={} before={:#x} after={:#x} msg={}",
                class_name, sig_str, compile.kind, compile.success, compile.before, compile.after, compile.message
            ));
        }
        if is_art_quick_entrypoint(entry_point, bridge) {
            return throw_internal_error(
                ctx,
                format!(
                    "fastConstructor rejected {}.<init>{}: no independent quick entrypoint (entry={:#x})",
                    class_name, sig_str, entry_point
                ),
            );
        }
        (
            art_method,
            class_global_ref,
            super::decode_global_jobject_raw(env, class_global_ref as *mut std::ffi::c_void).unwrap_or(0),
            is_static,
        )
    };

    if is_static {
        return throw_internal_error(
            ctx,
            format!("constructor resolved as static: {}{}", class_name, sig_str),
        );
    }

    output_verbose(&format!(
        "[fastConstructor] {}.<init>{} class_global={:#x} class_mirror={:#x}",
        class_name, sig_str, class_global_ref as usize, class_mirror
    ));
    let constructor = FastConstructor {
        class_global_ref: class_global_ref as u64,
        class_mirror,
        art_method,
        param_types: parse_jni_param_types(&sig_str),
        shorty: make_shorty(&sig_str),
    };
    let mut constructors = fast_constructors().lock().unwrap_or_else(|e| e.into_inner());
    constructors.push(constructor);
    js_u64_to_js_number_or_bigint(ctx, constructors.len() as u64)
}

pub(crate) unsafe extern "C" fn js_java_fast_field(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return throw_type_error(ctx, b"fastField(class, field[, sig]) requires at least 2 arguments\0");
    }

    let class_name = match extract_string_arg(ctx, JSValue(*argv), b"arg 0 must be string\0") {
        Ok(s) => s,
        Err(e) => return e,
    };
    let field_name = match extract_string_arg(ctx, JSValue(*argv.add(1)), b"arg 1 must be string\0") {
        Ok(s) => s,
        Err(e) => return e,
    };
    let requested_sig = if argc >= 3 {
        let sig_arg = JSValue(*argv.add(2));
        if !sig_arg.is_undefined() && !sig_arg.is_null() {
            match extract_string_arg(ctx, sig_arg, b"arg 2 must be string\0") {
                Ok(s) => Some(s),
                Err(e) => return e,
            }
        } else {
            None
        }
    } else {
        None
    };

    let field = if crate::is_raw_clone_js_thread() {
        match super::callback::resolve_fast_field_via_executor(class_name, field_name, requested_sig) {
            Ok(field) => field,
            Err(msg) => return throw_internal_error(ctx, msg),
        }
    } else {
        let env = match ensure_jni_initialized() {
            Ok(e) => e,
            Err(msg) => return throw_internal_error(ctx, msg),
        };
        match resolve_fast_field(env, class_name, field_name, requested_sig) {
            Ok(field) => field,
            Err(msg) if msg == "field signature mismatch" => {
                return throw_type_error(ctx, b"field signature mismatch\0")
            }
            Err(msg) if msg == "fastField only supports instance fields" => {
                return throw_type_error(ctx, b"fastField only supports instance fields\0")
            }
            Err(msg) if msg == "fastField only supports primitive/object instance fields" => {
                return throw_type_error(ctx, b"fastField only supports primitive/object instance fields\0")
            }
            Err(msg) => return throw_internal_error(ctx, msg),
        }
    };
    let mut fields = fast_fields().lock().unwrap_or_else(|e| e.into_inner());
    fields.push(field);
    js_u64_to_js_number_or_bigint(ctx, fields.len() as u64)
}

pub(crate) unsafe extern "C" fn js_java_compile_method(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 3 {
        return throw_type_error(
            ctx,
            b"compileMethod(class, method, sig[, kind]) requires at least 3 arguments\0",
        );
    }

    let class_name = match extract_string_arg(ctx, JSValue(*argv), b"arg 0 must be string\0") {
        Ok(s) => s,
        Err(e) => return e,
    };
    let method_name = match extract_string_arg(ctx, JSValue(*argv.add(1)), b"arg 1 must be string\0") {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_str = match extract_string_arg(ctx, JSValue(*argv.add(2)), b"arg 2 must be string\0") {
        Ok(s) => s,
        Err(e) => return e,
    };
    let (actual_sig, force_static) = if let Some(stripped) = sig_str.strip_prefix("static:") {
        (stripped.to_string(), true)
    } else {
        (sig_str, false)
    };
    let kind = if argc >= 4 {
        if let Some(s) = JSValue(*argv.add(3)).to_string(ctx) {
            match RequestedCompileKind::from_str(s.as_str()) {
                Some(k) => k,
                None => return throw_type_error(ctx, b"invalid compile kind\0"),
            }
        } else {
            RequestedCompileKind::Auto
        }
    } else {
        RequestedCompileKind::Auto
    };

    let (art_method, result) = if crate::is_raw_clone_js_thread() {
        match super::callback::compile_method_via_executor(class_name, method_name, actual_sig, force_static, kind) {
            Ok(v) => v,
            Err(msg) => return throw_internal_error(ctx, msg),
        }
    } else {
        let env = match ensure_jni_initialized() {
            Ok(e) => e,
            Err(msg) => return throw_internal_error(ctx, msg),
        };
        let (art_method, _is_static) =
            match resolve_art_method(env, &class_name, &method_name, &actual_sig, force_static) {
                Ok(v) => v,
                Err(msg) => return throw_internal_error(ctx, msg),
            };
        let spec = get_art_method_spec(env, art_method);
        let bridge = find_art_bridge_functions(env, spec.entry_point_offset);
        (
            art_method,
            compile_art_method_to_quick(env, art_method, spec.entry_point_offset, bridge, kind),
        )
    };

    let obj = ffi::JS_NewObject(ctx);
    let obj_v = JSValue(obj);
    obj_v.set_property(ctx, "success", JSValue::bool(result.success));
    obj_v.set_property(ctx, "compiled", JSValue::bool(result.compiled));
    obj_v.set_property(ctx, "kind", JSValue::string(ctx, result.kind));
    obj_v.set_property(ctx, "message", JSValue::string(ctx, &result.message));
    set_js_u64_property(ctx, obj, "artMethod", art_method);
    set_js_u64_property(ctx, obj, "before", result.before);
    set_js_u64_property(ctx, obj, "after", result.after);
    obj
}

pub(crate) unsafe extern "C" fn js_java_jit_info(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if crate::is_raw_clone_js_thread() {
        return super::callback::jit_info_via_executor(ctx);
    }
    let _env = match ensure_jni_initialized() {
        Ok(e) => e,
        Err(msg) => return throw_internal_error(ctx, msg),
    };
    let Some(info) = probe_jit_runtime_info() else {
        return throw_internal_error(ctx, "JIT runtime info unavailable".to_string());
    };

    let obj = ffi::JS_NewObject(ctx);
    let obj_v = JSValue(obj);
    set_js_u64_property(ctx, obj, "runtime", info.runtime);
    set_js_u64_property(ctx, obj, "javaVmOffset", info.java_vm_offset as u64);
    set_js_u64_property(ctx, obj, "jitOffset", info.jit_offset as u64);
    set_js_u64_property(ctx, obj, "jitCodeCacheOffset", info.jit_code_cache_offset as u64);
    set_js_u64_property(ctx, obj, "directJit", info.direct_jit);
    set_js_u64_property(ctx, obj, "runtimeJitCodeCache", info.runtime_jit_code_cache);
    set_js_u64_property(ctx, obj, "directGetCodeCache", info.direct_get_code_cache);
    set_js_u64_property(ctx, obj, "foundJit", info.found_jit);
    obj_v.set_property(ctx, "message", JSValue::string(ctx, &info.message));
    obj
}

pub(crate) unsafe fn compile_art_method_to_quick(
    env: JniEnv,
    art_method: u64,
    entry_point_offset: usize,
    bridge: &ArtBridgeFunctions,
    kind: RequestedCompileKind,
) -> CompileResult {
    let before = read_entry_point(art_method, entry_point_offset);
    if !is_art_quick_entrypoint(before, bridge) {
        return CompileResult {
            before,
            after: before,
            success: true,
            compiled: false,
            kind: "already-quick",
            message: "method already has independent quick code".to_string(),
        };
    }

    let Some(jit) = find_jit_instance() else {
        return CompileResult {
            before,
            after: before,
            success: false,
            compiled: false,
            kind: kind.label(),
            message: "Jit* not found".to_string(),
        };
    };
    let Some(thread) = current_art_thread(env) else {
        return CompileResult {
            before,
            after: before,
            success: false,
            compiled: false,
            kind: kind.label(),
            message: "Thread::Current() unavailable".to_string(),
        };
    };
    let Some((compile_method, compile_symbol)) = find_jit_compile_method() else {
        return CompileResult {
            before,
            after: before,
            success: false,
            compiled: false,
            kind: kind.label(),
            message: "Jit::CompileMethod symbol not found".to_string(),
        };
    };

    let mut last_kind = kind.label();
    let mut saw_compile_success = false;
    for k in kind.sequence() {
        last_kind = compile_method.label(*k);
        let ok = compile_method.call(jit, art_method, thread, *k) != 0;
        let after = read_entry_point(art_method, entry_point_offset);
        if ok {
            saw_compile_success = true;
        }
        if !is_art_quick_entrypoint(after, bridge) {
            return CompileResult {
                before,
                after,
                success: true,
                compiled: true,
                kind: last_kind,
                message: format!("{}({}) succeeded", compile_symbol, last_kind),
            };
        }
    }

    let after = read_entry_point(art_method, entry_point_offset);
    CompileResult {
        before,
        after,
        success: false,
        compiled: saw_compile_success,
        kind: last_kind,
        message: if saw_compile_success {
            "JIT reported success but entrypoint is still a shared ART bridge".to_string()
        } else {
            "Jit::CompileMethod returned false".to_string()
        },
    }
}

enum JitCompileMethod {
    OsrOnly(unsafe extern "C" fn(this: u64, method: u64, thread: u64, osr: u8) -> u8),
    BaselineOsr(unsafe extern "C" fn(this: u64, method: u64, thread: u64, baseline: u8, osr: u8) -> u8),
    BaselineOsrPrejit(
        unsafe extern "C" fn(this: u64, method: u64, thread: u64, baseline: u8, osr: u8, prejit: u8) -> u8,
    ),
    KindPrejit(unsafe extern "C" fn(this: u64, method: u64, thread: u64, compilation_kind: u32, prejit: u8) -> u8),
    KindPrejitOsr(
        unsafe extern "C" fn(this: u64, method: u64, thread: u64, compilation_kind: u32, prejit: u8, osr: u8) -> u8,
    ),
}

impl JitCompileMethod {
    unsafe fn call(&self, jit: u64, method: u64, thread: u64, compilation_kind: u32) -> u8 {
        match self {
            Self::OsrOnly(f) => f(jit, method, thread, 0),
            Self::BaselineOsr(f) => f(jit, method, thread, Self::old_baseline_flag(compilation_kind), 0),
            Self::BaselineOsrPrejit(f) => f(jit, method, thread, Self::old_baseline_flag(compilation_kind), 0, 0),
            Self::KindPrejit(f) => f(jit, method, thread, compilation_kind, 0),
            Self::KindPrejitOsr(f) => f(jit, method, thread, compilation_kind, 0, 0),
        }
    }

    fn label(&self, compilation_kind: u32) -> &'static str {
        match self {
            Self::OsrOnly(_) => "jit",
            Self::BaselineOsr(_) | Self::BaselineOsrPrejit(_) => {
                if compilation_kind == 3 {
                    "optimized"
                } else {
                    "baseline"
                }
            }
            Self::KindPrejit(_) | Self::KindPrejitOsr(_) => match compilation_kind {
                1 => "fast",
                2 => "baseline",
                3 => "optimized",
                _ => "unknown",
            },
        }
    }

    fn old_baseline_flag(compilation_kind: u32) -> u8 {
        if compilation_kind == 3 {
            0
        } else {
            1
        }
    }
}

unsafe fn find_jit_compile_method() -> Option<(JitCompileMethod, &'static str)> {
    let kind_prejit_osr_symbol = "_ZN3art3jit3Jit13CompileMethodEPNS_9ArtMethodEPNS_6ThreadENS_15CompilationKindEbb";
    let kind_prejit_osr = crate::jsapi::module::libart_dlsym(kind_prejit_osr_symbol);
    if !kind_prejit_osr.is_null() {
        type CompileMethodFn =
            unsafe extern "C" fn(this: u64, method: u64, thread: u64, compilation_kind: u32, prejit: u8, osr: u8) -> u8;
        let compile_method: CompileMethodFn = std::mem::transmute(kind_prejit_osr);
        return Some((JitCompileMethod::KindPrejitOsr(compile_method), kind_prejit_osr_symbol));
    }

    let kind_prejit_symbol = "_ZN3art3jit3Jit13CompileMethodEPNS_9ArtMethodEPNS_6ThreadENS_15CompilationKindEb";
    let kind_prejit = crate::jsapi::module::libart_dlsym(kind_prejit_symbol);
    if !kind_prejit.is_null() {
        type CompileMethodFn =
            unsafe extern "C" fn(this: u64, method: u64, thread: u64, compilation_kind: u32, prejit: u8) -> u8;
        let compile_method: CompileMethodFn = std::mem::transmute(kind_prejit);
        return Some((JitCompileMethod::KindPrejit(compile_method), kind_prejit_symbol));
    }

    let baseline_osr_prejit_symbol = "_ZN3art3jit3Jit13CompileMethodEPNS_9ArtMethodEPNS_6ThreadEbbb";
    let baseline_osr_prejit = crate::jsapi::module::libart_dlsym(baseline_osr_prejit_symbol);
    if !baseline_osr_prejit.is_null() {
        type CompileMethodFn =
            unsafe extern "C" fn(this: u64, method: u64, thread: u64, baseline: u8, osr: u8, prejit: u8) -> u8;
        let compile_method: CompileMethodFn = std::mem::transmute(baseline_osr_prejit);
        return Some((
            JitCompileMethod::BaselineOsrPrejit(compile_method),
            baseline_osr_prejit_symbol,
        ));
    }

    let baseline_osr_symbol = "_ZN3art3jit3Jit13CompileMethodEPNS_9ArtMethodEPNS_6ThreadEbb";
    let baseline_osr = crate::jsapi::module::libart_dlsym(baseline_osr_symbol);
    if !baseline_osr.is_null() {
        type CompileMethodFn = unsafe extern "C" fn(this: u64, method: u64, thread: u64, baseline: u8, osr: u8) -> u8;
        let compile_method: CompileMethodFn = std::mem::transmute(baseline_osr);
        return Some((JitCompileMethod::BaselineOsr(compile_method), baseline_osr_symbol));
    }

    let osr_only_symbol = "_ZN3art3jit3Jit13CompileMethodEPNS_9ArtMethodEPNS_6ThreadEb";
    let osr_only = crate::jsapi::module::libart_dlsym(osr_only_symbol);
    if !osr_only.is_null() {
        type CompileMethodFn = unsafe extern "C" fn(this: u64, method: u64, thread: u64, osr: u8) -> u8;
        let compile_method: CompileMethodFn = std::mem::transmute(osr_only);
        return Some((JitCompileMethod::OsrOnly(compile_method), osr_only_symbol));
    }

    None
}

unsafe fn current_art_thread(env: JniEnv) -> Option<u64> {
    let sym = crate::jsapi::module::libart_dlsym("_ZN3art6Thread7CurrentEv");
    if !sym.is_null() {
        type ThreadCurrentFn = unsafe extern "C" fn() -> u64;
        let thread_current: ThreadCurrentFn = std::mem::transmute(sym);
        let thread = thread_current() & super::PAC_STRIP_MASK;
        if thread != 0 {
            return Some(thread);
        }
    }
    if !env.is_null() {
        let thread = *((env as usize + 8) as *const u64) & super::PAC_STRIP_MASK;
        if thread != 0 {
            return Some(thread);
        }
    }
    None
}

type ArtMethodInvokeFn = unsafe extern "C" fn(
    method: *mut std::ffi::c_void,
    thread: *mut std::ffi::c_void,
    args: *mut u32,
    args_size: u32,
    result: *mut u64,
    shorty: *const std::os::raw::c_char,
);

static ART_METHOD_INVOKE: OnceLock<Option<ArtMethodInvokeFn>> = OnceLock::new();

pub(crate) unsafe fn invoke_fast_method_raw_on_thread(
    method: &FastMethod,
    thread: u64,
    receiver: u64,
    args: &[u64],
) -> Result<u64, String> {
    if thread == 0 {
        return Err("current ART Thread is null".to_string());
    }
    if !method.is_static && receiver == 0 {
        return Err("jcall instance receiver is null".to_string());
    }
    if args.len() != method.param_types.len() {
        return Err(format!(
            "jcall argument count mismatch: expected {}, got {}",
            method.param_types.len(),
            args.len()
        ));
    }

    let mut invoke_args = StackArtInvokeArgs::new();
    if !method.is_static {
        invoke_args.push("L", receiver)?;
    }
    for (i, type_sig) in method.param_types.iter().enumerate() {
        invoke_args.push(type_sig.as_str(), args[i])?;
    }
    let before_exception = thread_exception(thread);
    let ret = invoke_fast_method_art_ready_raw(method, thread, invoke_args.as_mut_ptr(), invoke_args.size_bytes())?;
    if clear_new_thread_exception(thread, before_exception) {
        return Err("ArtMethod::Invoke method raised exception".to_string());
    }
    Ok(ret)
}

pub(crate) unsafe fn fast_method_receiver_is_exact(method: &FastMethod, receiver: u64) -> bool {
    method.is_static || object_class_matches(receiver, method.class_mirror)
}

unsafe fn object_class_matches(obj: u64, class_mirror: u64) -> bool {
    if obj == 0 || class_mirror == 0 {
        return false;
    }
    let compressed_class = std::ptr::read_volatile(obj as *const u32) as u64;
    compressed_class == (class_mirror & 0xffff_ffff)
}

unsafe fn invoke_fast_method_art_ready_raw(
    method: &FastMethod,
    thread: u64,
    args: *mut u32,
    args_size: u32,
) -> Result<u64, String> {
    let Some(invoke) = art_method_invoke() else {
        return Err("ArtMethod::Invoke symbol not found".to_string());
    };
    let mut result = 0u64;
    invoke(
        method.art_method as *mut std::ffi::c_void,
        thread as *mut std::ffi::c_void,
        args,
        args_size,
        &mut result as *mut u64,
        method.shorty.as_ptr(),
    );
    Ok(result)
}

pub(crate) unsafe fn invoke_fast_constructor_raw_on_thread(
    ctor: &FastConstructor,
    thread: u64,
    receiver: u64,
    args: &[u64],
) -> Result<(), String> {
    if thread == 0 {
        return Err("current ART Thread is null".to_string());
    }
    if receiver == 0 {
        return Err("jnew receiver allocation returned null".to_string());
    }
    if args.len() != ctor.param_types.len() {
        return Err(format!(
            "jnew argument count mismatch: expected {}, got {}",
            ctor.param_types.len(),
            args.len()
        ));
    }

    let mut invoke_args = StackArtInvokeArgs::new();
    invoke_args.push("L", receiver)?;
    for (i, type_sig) in ctor.param_types.iter().enumerate() {
        invoke_args.push(type_sig.as_str(), args[i])?;
    }
    let before_exception = thread_exception(thread);
    invoke_fast_constructor_art_ready_raw(ctor, thread, invoke_args.as_mut_ptr(), invoke_args.size_bytes())?;
    if clear_new_thread_exception(thread, before_exception) {
        return Err("ArtMethod::Invoke constructor raised exception".to_string());
    }
    Ok(())
}

unsafe fn invoke_fast_constructor_art_ready_raw(
    ctor: &FastConstructor,
    thread: u64,
    args: *mut u32,
    args_size: u32,
) -> Result<(), String> {
    let Some(invoke) = art_method_invoke() else {
        return Err("ArtMethod::Invoke symbol not found".to_string());
    };
    let mut result = 0u64;
    invoke(
        ctor.art_method as *mut std::ffi::c_void,
        thread as *mut std::ffi::c_void,
        args,
        args_size,
        &mut result as *mut u64,
        ctor.shorty.as_ptr(),
    );
    Ok(())
}

pub(crate) unsafe fn with_fast_art_handle_scope<R>(thread: u64, f: impl FnOnce() -> R) -> R {
    FAST_ART_HANDLE_SCOPE_ENTER.fetch_add(1, Ordering::Relaxed);
    if crate::is_raw_clone_js_thread() {
        FAST_ART_HANDLE_SCOPE_UNAVAILABLE.fetch_add(1, Ordering::Relaxed);
        return f();
    }
    let env = get_thread_env().unwrap_or(std::ptr::null_mut());
    if env.is_null() {
        FAST_ART_HANDLE_SCOPE_UNAVAILABLE.fetch_add(1, Ordering::Relaxed);
        return f();
    }
    let Some(spec) = super::art_thread::get_art_thread_spec(env) else {
        FAST_ART_HANDLE_SCOPE_UNAVAILABLE.fetch_add(1, Ordering::Relaxed);
        return f();
    };
    if thread == 0 {
        FAST_ART_HANDLE_SCOPE_UNAVAILABLE.fetch_add(1, Ordering::Relaxed);
        return f();
    }

    let top_addr = (thread as usize + spec.top_handle_scope_offset) as *mut u64;
    let previous_top = std::ptr::read_volatile(top_addr);
    let mut scope = FastArtHandleScope::new(previous_top);
    let scope_ptr = &mut scope as *mut FastArtHandleScope;
    std::ptr::write_volatile(top_addr, scope_ptr as u64);
    let previous_tls = CURRENT_FAST_ART_HANDLE_SCOPE.with(|current| {
        let previous = current.get();
        current.set(scope_ptr);
        previous
    });

    let result = f();

    let used_roots = (*scope_ptr).size as u64;
    update_fast_max(&FAST_ART_HANDLE_SCOPE_MAX_ROOTS, used_roots);
    CURRENT_FAST_ART_HANDLE_SCOPE.with(|current| current.set(previous_tls));
    let current_top = std::ptr::read_volatile(top_addr);
    if current_top == scope_ptr as u64 {
        std::ptr::write_volatile(top_addr, previous_top);
    } else {
        FAST_ART_HANDLE_SCOPE_LEAKED.fetch_add(1, Ordering::Relaxed);
        std::ptr::write_volatile(top_addr, previous_top);
        return result;
    }
    result
}

pub(crate) unsafe fn root_fast_raw_object_for_callback(raw: u64) -> Result<FastArtRoot, String> {
    if raw == 0 {
        return Err("cannot root null raw object".to_string());
    }
    if raw > u32::MAX as u64 {
        return Err(format!("raw object is not a compressed ART reference: {:#x}", raw));
    }
    CURRENT_FAST_ART_HANDLE_SCOPE.with(|current| {
        let scope = current.get();
        if scope.is_null() {
            FAST_ART_HANDLE_SCOPE_ROOT_FAILED.fetch_add(1, Ordering::Relaxed);
            return Err("fast ART handle scope unavailable".to_string());
        }
        let scope = &mut *scope;
        let slot = scope.size as usize;
        if slot >= FAST_ART_HANDLE_SCOPE_CAPACITY {
            FAST_ART_HANDLE_SCOPE_ROOT_FAILED.fetch_add(1, Ordering::Relaxed);
            FAST_ART_HANDLE_SCOPE_CAPACITY_EXCEEDED.fetch_add(1, Ordering::Relaxed);
            return Err("fast ART handle scope capacity exceeded".to_string());
        }
        scope.refs[slot] = raw as u32;
        scope.size += 1;
        Ok(FastArtRoot { slot: slot as u32 })
    })
}

pub(crate) unsafe fn read_fast_art_root(root: FastArtRoot) -> Option<u64> {
    CURRENT_FAST_ART_HANDLE_SCOPE.with(|current| {
        let scope = current.get();
        if scope.is_null() {
            return None;
        }
        let scope = &*scope;
        let slot = root.slot as usize;
        if slot >= scope.size as usize || slot >= FAST_ART_HANDLE_SCOPE_CAPACITY {
            None
        } else {
            Some(scope.refs[slot] as u64)
        }
    })
}

unsafe fn art_method_invoke() -> Option<ArtMethodInvokeFn> {
    *ART_METHOD_INVOKE.get_or_init(|| {
        let sym = crate::jsapi::module::libart_dlsym("_ZN3art9ArtMethod6InvokeEPNS_6ThreadEPjjPNS_6JValueEPKc");
        if sym.is_null() {
            None
        } else {
            Some(std::mem::transmute(sym))
        }
    })
}

struct StackArtInvokeArgs {
    words: [u32; FAST_ART_STACK_INVOKE_WORDS],
    len: usize,
}

impl StackArtInvokeArgs {
    fn new() -> Self {
        Self {
            words: [0; FAST_ART_STACK_INVOKE_WORDS],
            len: 0,
        }
    }

    fn push(&mut self, type_sig: &str, raw: u64) -> Result<(), String> {
        match type_sig.as_bytes().first().copied() {
            Some(b'J' | b'D') => {
                self.push_word(raw as u32)?;
                self.push_word((raw >> 32) as u32)
            }
            Some(b'F') => self.push_word(raw as u32),
            Some(b'L' | b'[') => self.push_word(raw as u32),
            _ => self.push_word(raw as u32),
        }
    }

    fn push_word(&mut self, word: u32) -> Result<(), String> {
        if self.len >= self.words.len() {
            return Err("ArtMethod::Invoke argument buffer exceeded fast stack capacity".to_string());
        }
        self.words[self.len] = word;
        self.len += 1;
        Ok(())
    }

    fn as_mut_ptr(&mut self) -> *mut u32 {
        self.words.as_mut_ptr()
    }

    fn size_bytes(&self) -> u32 {
        (self.len * std::mem::size_of::<u32>()) as u32
    }
}

pub(crate) unsafe fn alloc_fast_object_quick_on_thread(thread: u64, class_mirror: u64) -> Option<u64> {
    if thread == 0 || class_mirror == 0 {
        FAST_TLAB_ALLOC_MISS.fetch_add(1, Ordering::Relaxed);
        return None;
    }
    let size_offset = super::heap_scan::resolve_class_object_size_offset();
    let object_size = std::ptr::read_volatile((class_mirror as usize + size_offset) as *const u32);
    if object_size == 0 || object_size > MAX_TLAB_FAST_OBJECT_SIZE || object_size % 8 != 0 {
        FAST_TLAB_ALLOC_MISS.fetch_add(1, Ordering::Relaxed);
        return None;
    }
    let pos_addr = (thread as usize + THREAD_LOCAL_POS_OFFSET) as *mut u64;
    let end_addr = (thread as usize + THREAD_LOCAL_END_OFFSET) as *const u64;
    let pos = std::ptr::read_volatile(pos_addr);
    let end = std::ptr::read_volatile(end_addr);
    let Some(next) = pos.checked_add(object_size as u64) else {
        FAST_TLAB_ALLOC_MISS.fetch_add(1, Ordering::Relaxed);
        return alloc_fast_object_quick_slow_on_thread(thread, class_mirror);
    };
    if pos == 0 || next > end {
        FAST_TLAB_ALLOC_MISS.fetch_add(1, Ordering::Relaxed);
        return alloc_fast_object_quick_slow_on_thread(thread, class_mirror);
    }
    std::ptr::write_volatile(pos_addr, next);
    std::ptr::write_bytes(pos as *mut u8, 0, object_size as usize);
    std::ptr::write_volatile(
        (pos as usize + MIRROR_OBJECT_CLASS_OFFSET) as *mut u32,
        class_mirror as u32,
    );
    std::ptr::write_volatile((pos as usize + MIRROR_OBJECT_LOCK_WORD_OFFSET) as *mut u32, 0);
    std::sync::atomic::fence(Ordering::Release);
    FAST_TLAB_ALLOC_HIT.fetch_add(1, Ordering::Relaxed);
    Some(pos)
}

unsafe fn alloc_fast_object_quick_slow_on_thread(thread: u64, class_mirror: u64) -> Option<u64> {
    if thread == 0 || class_mirror == 0 {
        return None;
    }
    let entry = quick_entrypoint(thread as usize, QUICK_ALLOC_OBJECT_INITIALIZED_INDEX)?;
    FAST_QUICK_ALLOC_SLOW_PATH.fetch_add(1, Ordering::Relaxed);
    let before_exception = thread_exception(thread);
    let raw = call_quick_alloc_object(entry as usize, thread as usize, class_mirror as usize) as u64;
    if clear_new_thread_exception(thread, before_exception) {
        return None;
    }
    (raw != 0).then_some(raw)
}

#[inline]
pub(crate) unsafe fn fast_art_exception_stats() -> (u64, u64) {
    (
        FAST_ART_EXCEPTION_SEEN.load(Ordering::Acquire),
        FAST_ART_EXCEPTION_CLEARED.load(Ordering::Acquire),
    )
}

#[inline]
pub(crate) unsafe fn fast_art_handle_scope_stats() -> (u64, u64, u64, u64, u64, u64) {
    (
        FAST_ART_HANDLE_SCOPE_ENTER.load(Ordering::Acquire),
        FAST_ART_HANDLE_SCOPE_UNAVAILABLE.load(Ordering::Acquire),
        FAST_ART_HANDLE_SCOPE_LEAKED.load(Ordering::Acquire),
        FAST_ART_HANDLE_SCOPE_MAX_ROOTS.load(Ordering::Acquire),
        FAST_ART_HANDLE_SCOPE_ROOT_FAILED.load(Ordering::Acquire),
        FAST_ART_HANDLE_SCOPE_CAPACITY_EXCEEDED.load(Ordering::Acquire),
    )
}

#[inline]
pub(crate) unsafe fn fast_tlab_alloc_stats() -> (u64, u64, u64) {
    (
        FAST_TLAB_ALLOC_HIT.load(Ordering::Acquire),
        FAST_TLAB_ALLOC_MISS.load(Ordering::Acquire),
        FAST_QUICK_ALLOC_SLOW_PATH.load(Ordering::Acquire),
    )
}

#[inline]
unsafe fn thread_exception(thread: u64) -> u64 {
    if thread == 0 {
        return 0;
    }
    std::ptr::read_volatile((thread as usize + THREAD_EXCEPTION_OFFSET) as *const u64)
}

#[inline]
unsafe fn clear_new_thread_exception(thread: u64, before_exception: u64) -> bool {
    if thread == 0 {
        return false;
    }
    let exception_addr = (thread as usize + THREAD_EXCEPTION_OFFSET) as *mut u64;
    let after_exception = std::ptr::read_volatile(exception_addr);
    if after_exception == 0 || after_exception == before_exception {
        return false;
    }
    FAST_ART_EXCEPTION_SEEN.fetch_add(1, Ordering::Relaxed);
    if before_exception == 0 {
        std::ptr::write_volatile(exception_addr, 0);
        FAST_ART_EXCEPTION_CLEARED.fetch_add(1, Ordering::Relaxed);
        return true;
    }
    false
}

unsafe fn quick_entrypoint(thread: usize, index: usize) -> Option<u64> {
    if thread == 0 || index >= QUICK_ENTRYPOINT_COUNT {
        return None;
    }
    let cached = QUICK_ENTRYPOINTS_OFFSET.load(Ordering::Acquire);
    if cached == QUICK_ENTRYPOINTS_OFFSET_FAILED {
        return None;
    }
    if cached != 0 {
        let off = cached - 1;
        let entry = std::ptr::read_volatile((thread + off + index * 8) as *const u64);
        return crate::jsapi::module::is_in_libart(entry).then_some(entry);
    }

    let max_off = QUICK_SCAN_LIMIT.saturating_sub(QUICK_ENTRYPOINT_COUNT * 8);
    for off in (0..=max_off).step_by(8) {
        let base = (thread + off) as *const u64;
        let start = std::ptr::read_volatile(base.add(QUICK_JNI_METHOD_START_INDEX));
        let end = std::ptr::read_volatile(base.add(QUICK_JNI_METHOD_END_INDEX));
        if !crate::jsapi::module::is_in_libart(start) || !crate::jsapi::module::is_in_libart(end) {
            continue;
        }
        if off < 16 {
            continue;
        }
        let prev0 = std::ptr::read_volatile((thread + off - 16) as *const u64);
        let prev1 = std::ptr::read_volatile((thread + off - 8) as *const u64);
        if !crate::jsapi::module::is_in_libart(prev0) || !crate::jsapi::module::is_in_libart(prev1) {
            continue;
        }

        let mut libart_ptrs = 0usize;
        for i in 0..QUICK_ENTRYPOINT_COUNT {
            if crate::jsapi::module::is_in_libart(std::ptr::read_volatile(base.add(i))) {
                libart_ptrs += 1;
            }
        }
        if libart_ptrs < QUICK_MIN_LIBART_POINTERS {
            continue;
        }

        QUICK_ENTRYPOINTS_OFFSET.store(off + 1, Ordering::Release);
        let entry = std::ptr::read_volatile(base.add(index));
        return crate::jsapi::module::is_in_libart(entry).then_some(entry);
    }

    QUICK_ENTRYPOINTS_OFFSET.store(QUICK_ENTRYPOINTS_OFFSET_FAILED, Ordering::Release);
    None
}

#[cfg(target_arch = "aarch64")]
unsafe fn call_quick_alloc_object(entry: usize, thread: usize, klass: usize) -> usize {
    let mut ret = klass;
    core::arch::asm!(
        "str x19, [sp, #-16]!",
        "mov x19, x10",
        "blr x11",
        "ldr x19, [sp], #16",
        in("x10") thread,
        in("x11") entry,
        inlateout("x0") ret,
        clobber_abi("C"),
    );
    ret
}

#[cfg(not(target_arch = "aarch64"))]
unsafe fn call_quick_alloc_object(entry: usize, _thread: usize, klass: usize) -> usize {
    let f: unsafe extern "C" fn(usize) -> usize = std::mem::transmute(entry);
    f(klass)
}
