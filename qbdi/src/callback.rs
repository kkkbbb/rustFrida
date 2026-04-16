//! Callback types and helpers for QBDI

use crate::ffi;
use crate::ffi::*;
use crate::state::{FPRState, GPRState, RWord};
use std::ffi::CStr;

/// Re-export types from ffi
pub use ffi::{
    AnalysisType, ConditionType, InstPosition, MemoryAccess, MemoryAccessFlags, MemoryAccessType, OperandFlag,
    OperandType, RegisterAccessType, VMAction, VMEvent, VMState,
};

/// Callback ID
pub type CallbackId = u32;

/// Invalid callback ID constant
pub const INVALID_EVENTID: CallbackId = ffi::INVALID_EVENTID;

/// Default callback priority
pub const PRIORITY_DEFAULT: i32 = CallbackPriority_QBDI_PRIORITY_DEFAULT as i32;

/// Maximum priority for callbacks using memory access API
pub const PRIORITY_MEMACCESS_LIMIT: i32 = CallbackPriority_QBDI_PRIORITY_MEMACCESS_LIMIT as i32;

/// Operand analysis result with Rust-friendly accessors
pub struct OperandAnalysis<'a> {
    raw: &'a ffi::OperandAnalysis,
}

impl<'a> OperandAnalysis<'a> {
    pub(crate) fn from_raw(raw: &'a ffi::OperandAnalysis) -> Self {
        Self { raw }
    }

    /// Get operand type
    pub fn operand_type(&self) -> OperandType {
        self.raw.type_
    }

    /// Get operand flags
    pub fn flags(&self) -> OperandFlag {
        self.raw.flag
    }

    /// Get operand value (immediate value or register ID)
    pub fn value(&self) -> i64 {
        self.raw.value
    }

    /// Get operand size in bytes
    pub fn size(&self) -> u8 {
        self.raw.size
    }

    /// Get sub-register offset in bits
    pub fn reg_offset(&self) -> u8 {
        self.raw.regOff
    }

    /// Get register index in VM state (-1 if unknown)
    pub fn reg_ctx_index(&self) -> i16 {
        self.raw.regCtxIdx
    }

    /// Get register name
    pub fn reg_name(&self) -> Option<&str> {
        if self.raw.regName.is_null() {
            None
        } else {
            unsafe { CStr::from_ptr(self.raw.regName).to_str().ok() }
        }
    }

    /// Get register access type
    pub fn reg_access(&self) -> RegisterAccessType {
        self.raw.regAccess
    }

    /// Check if operand is an immediate
    pub fn is_immediate(&self) -> bool {
        self.raw.type_ == OperandType_QBDI_OPERAND_IMM
    }

    /// Check if operand is a GPR
    pub fn is_gpr(&self) -> bool {
        self.raw.type_ == OperandType_QBDI_OPERAND_GPR
    }

    /// Check if operand is a FPR
    pub fn is_fpr(&self) -> bool {
        self.raw.type_ == OperandType_QBDI_OPERAND_FPR
    }

    /// Check if operand is used for address computation
    pub fn is_address(&self) -> bool {
        (self.raw.flag) & OperandFlag_QBDI_OPERANDFLAG_ADDR != 0
    }

    /// Check if operand is PC-relative
    pub fn is_pc_relative(&self) -> bool {
        (self.raw.flag) & OperandFlag_QBDI_OPERANDFLAG_PCREL != 0
    }

    /// Check if operand is implicit
    pub fn is_implicit(&self) -> bool {
        (self.raw.flag) & OperandFlag_QBDI_OPERANDFLAG_IMPLICIT != 0
    }
}

/// Instruction analysis result with Rust-friendly accessors
pub struct InstAnalysis<'a> {
    raw: &'a ffi::InstAnalysis,
}

impl<'a> InstAnalysis<'a> {
    pub(crate) fn from_raw(raw: &'a ffi::InstAnalysis) -> Self {
        Self { raw }
    }

    /// Get instruction mnemonic
    pub fn mnemonic(&self) -> Option<&str> {
        if self.raw.mnemonic.is_null() {
            None
        } else {
            unsafe { CStr::from_ptr(self.raw.mnemonic).to_str().ok() }
        }
    }

    /// Get instruction address
    pub fn address(&self) -> RWord {
        self.raw.address
    }

    /// Get instruction size in bytes
    pub fn size(&self) -> u32 {
        self.raw.instSize
    }

    /// Check if instruction affects control flow
    pub fn affects_control_flow(&self) -> bool {
        self.raw.affectControlFlow
    }

    /// Check if instruction is a branch
    pub fn is_branch(&self) -> bool {
        self.raw.isBranch
    }

    /// Check if instruction is a call
    pub fn is_call(&self) -> bool {
        self.raw.isCall
    }

    /// Check if instruction is a return
    pub fn is_return(&self) -> bool {
        self.raw.isReturn
    }

    /// Check if instruction is a comparison
    pub fn is_compare(&self) -> bool {
        self.raw.isCompare
    }

    /// Check if instruction is predicable (conditional)
    pub fn is_predicable(&self) -> bool {
        self.raw.isPredicable
    }

    /// Check if instruction is a move immediate
    pub fn is_move_imm(&self) -> bool {
        self.raw.isMoveImm
    }

    /// Check if instruction may load from memory
    pub fn may_load(&self) -> bool {
        self.raw.mayLoad
    }

    /// Check if instruction may store to memory
    pub fn may_store(&self) -> bool {
        self.raw.mayStore
    }

    /// Get expected load size (0 if undetermined)
    pub fn load_size(&self) -> u32 {
        self.raw.loadSize
    }

    /// Get expected store size (0 if undetermined)
    pub fn store_size(&self) -> u32 {
        self.raw.storeSize
    }

    /// Get instruction condition
    pub fn condition(&self) -> ConditionType {
        self.raw.condition
    }

    /// Get disassembly string
    pub fn disassembly(&self) -> Option<&str> {
        if self.raw.disassembly.is_null() {
            None
        } else {
            unsafe { CStr::from_ptr(self.raw.disassembly).to_str().ok() }
        }
    }

    /// Get flags access type
    pub fn flags_access(&self) -> RegisterAccessType {
        self.raw.flagsAccess
    }

    /// Get number of operands
    pub fn num_operands(&self) -> usize {
        self.raw.numOperands as usize
    }

    /// Get operand by index
    pub fn operand(&self, index: usize) -> Option<OperandAnalysis<'a>> {
        if index >= self.num_operands() || self.raw.operands.is_null() {
            None
        } else {
            unsafe {
                let operand = &*self.raw.operands.add(index);
                Some(OperandAnalysis::from_raw(operand))
            }
        }
    }

    /// Iterate over all operands
    pub fn operands(&'a self) -> impl Iterator<Item = OperandAnalysis<'a>> + 'a {
        (0..self.num_operands()).filter_map(move |i| self.operand(i))
    }

    /// Get symbol name
    pub fn symbol_name(&self) -> Option<&str> {
        if self.raw.symbolName.is_null() {
            None
        } else {
            unsafe { CStr::from_ptr(self.raw.symbolName).to_str().ok() }
        }
    }

    /// Get symbol offset
    pub fn symbol_offset(&self) -> u32 {
        self.raw.symbolOffset
    }

    /// Get module name
    pub fn module_name(&self) -> Option<&str> {
        if self.raw.moduleName.is_null() {
            None
        } else {
            unsafe { CStr::from_ptr(self.raw.moduleName).to_str().ok() }
        }
    }

    /// Get JIT patch address
    pub fn patch_address(&self) -> RWord {
        self.raw.patchAddress
    }

    /// Get JIT patch size
    pub fn patch_size(&self) -> u16 {
        self.raw.patchSize
    }

    /// Get LLVM opcode
    pub fn opcode(&self) -> u32 {
        self.raw.opcode_LLVM
    }
}

/// VM State with Rust-friendly accessors
impl VMState {
    /// Get the event type
    pub fn event(&self) -> VMEvent {
        self.event
    }

    /// Check if a specific event is set
    pub fn has_event(&self, event: VMEvent) -> bool {
        (self.event & event) != 0
    }

    /// Get basic block start address
    pub fn basic_block_start(&self) -> RWord {
        self.basicBlockStart
    }

    /// Get basic block end address
    pub fn basic_block_end(&self) -> RWord {
        self.basicBlockEnd
    }

    /// Get sequence start address
    pub fn sequence_start(&self) -> RWord {
        self.sequenceStart
    }

    /// Get sequence end address
    pub fn sequence_end(&self) -> RWord {
        self.sequenceEnd
    }
}

/// Callback context passed to instruction callbacks
pub struct InstCallbackContext<'a> {
    pub vm: crate::vm::VMRef<'a>,
    pub gpr: &'a mut GPRState,
    pub fpr: &'a mut FPRState,
}

/// Callback context passed to VM event callbacks
pub struct VMCallbackContext<'a> {
    pub vm: crate::vm::VMRef<'a>,
    pub state: &'a VMState,
    pub gpr: &'a mut GPRState,
    pub fpr: &'a mut FPRState,
}

/// Memory access information helper
impl MemoryAccess {
    /// Get the instruction address that made this access
    pub fn inst_address(&self) -> RWord {
        self.instAddress
    }

    /// Get the accessed memory address
    pub fn access_address(&self) -> RWord {
        self.accessAddress
    }

    /// Get the value read/written
    pub fn value(&self) -> RWord {
        self.value
    }

    /// Get access size in bytes
    pub fn size(&self) -> u16 {
        self.size
    }

    /// Get access type (read/write)
    pub fn access_type(&self) -> MemoryAccessType {
        self.type_
    }

    /// Check if this is a read access
    pub fn is_read(&self) -> bool {
        (self.type_) & MemoryAccessType_QBDI_MEMORY_READ != 0
    }

    /// Check if this is a write access
    pub fn is_write(&self) -> bool {
        (self.type_) & MemoryAccessType_QBDI_MEMORY_WRITE != 0
    }

    /// Check if size is unknown
    pub fn is_size_unknown(&self) -> bool {
        (self.flags) & MemoryAccessFlags_QBDI_MEMORY_UNKNOWN_SIZE != 0
    }

    /// Check if value is unknown
    pub fn is_value_unknown(&self) -> bool {
        (self.flags) & MemoryAccessFlags_QBDI_MEMORY_UNKNOWN_VALUE != 0
    }
}
