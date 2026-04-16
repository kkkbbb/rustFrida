use {
    crate::instruction_writer::{Aarch64BranchCondition, Aarch64Register, Argument, IndexMode, InstructionWriter},
    core::{convert::TryInto, ffi::c_void},
    frida_gum_sys as gum_sys,
    gum_sys::GumArgument,
};

#[cfg(not(any(feature = "module-names", feature = "backtrace", feature = "memory-access-monitor")))]
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// The Aarch64 instruction writer.
pub struct Aarch64InstructionWriter {
    pub(crate) writer: *mut gum_sys::_GumArm64Writer,
    is_from_new: bool,
}

impl InstructionWriter for Aarch64InstructionWriter {
    fn new(code_address: u64) -> Self {
        Self {
            writer: unsafe { gum_sys::gum_arm64_writer_new(code_address as *mut c_void) },
            is_from_new: true,
        }
    }

    fn code_offset(&self) -> u64 {
        unsafe { (*self.writer).code as u64 }
    }

    fn pc(&self) -> u64 {
        unsafe { (*self.writer).pc }
    }

    fn can_branch_directly_between(&self, source: u64, target: u64) -> bool {
        unsafe { gum_sys::gum_arm64_writer_can_branch_directly_between(self.writer, source, target) != 0 }
    }

    fn put_bytes(&self, bytes: &[u8]) -> bool {
        unsafe { gum_sys::gum_arm64_writer_put_bytes(self.writer, bytes.as_ptr(), bytes.len() as u32) != 0 }
    }

    fn put_label(&self, id: u64) -> bool {
        unsafe { gum_sys::gum_arm64_writer_put_label(self.writer, id as *const c_void) != 0 }
    }

    fn reset(&self, code_address: u64) {
        unsafe { gum_sys::gum_arm64_writer_reset(self.writer, code_address as *mut c_void) }
    }

    fn put_branch_address(&self, address: u64) -> bool {
        unsafe { gum_sys::gum_arm64_writer_put_b_imm(self.writer, address) != 0 }
    }

    fn put_nop(&self) {
        unsafe { gum_sys::gum_arm64_writer_put_nop(self.writer) }
    }

    fn flush(&self) -> bool {
        unsafe { gum_sys::gum_arm64_writer_flush(self.writer) != 0 }
    }
}

impl Aarch64InstructionWriter {
    pub(crate) fn from_raw(writer: *mut gum_sys::_GumArm64Writer) -> Self {
        Self {
            writer,
            is_from_new: false,
        }
    }

    /// Get the underlying frida gum writer object
    pub fn raw_writer(&self) -> *mut gum_sys::_GumArm64Writer {
        self.writer
    }

    /// Insert a `b` to a label. The label is specified by `id`.
    pub fn put_b_label(&self, id: u64) {
        unsafe { gum_sys::gum_arm64_writer_put_b_label(self.writer, id as *const c_void) }
    }

    /// Insert a `brk #i` instruction.
    pub fn put_brk_imm(&self, imm: u16) {
        unsafe { gum_sys::gum_arm64_writer_put_brk_imm(self.writer, imm) }
    }

    /// Insert a `sub d, l, r` instruction.
    pub fn put_sub_reg_reg_imm(&self, dst_reg: Aarch64Register, left_reg: Aarch64Register, right_value: u64) -> bool {
        unsafe {
            gum_sys::gum_arm64_writer_put_sub_reg_reg_imm(self.writer, dst_reg as u32, left_reg as u32, right_value)
                != 0
        }
    }

    /// Insert a `add d, l, r` instruction.
    pub fn put_add_reg_reg_imm(&self, dst_reg: Aarch64Register, left_reg: Aarch64Register, right_value: u64) -> bool {
        unsafe {
            gum_sys::gum_arm64_writer_put_add_reg_reg_imm(self.writer, dst_reg as u32, left_reg as u32, right_value)
                != 0
        }
    }

    /// Insert a `add d, l, r` instruction.
    pub fn put_add_reg_reg_reg(
        &self,
        dst_reg: Aarch64Register,
        left_reg: Aarch64Register,
        right_reg: Aarch64Register,
    ) -> bool {
        unsafe {
            gum_sys::gum_arm64_writer_put_add_reg_reg_reg(
                self.writer,
                dst_reg as u32,
                left_reg as u32,
                right_reg as u32,
            ) != 0
        }
    }

    /// Insert a `mov d, s` instruction.
    pub fn put_mov_reg_reg(&self, dst_reg: Aarch64Register, src_reg: Aarch64Register) -> bool {
        unsafe { gum_sys::gum_arm64_writer_put_mov_reg_reg(self.writer, dst_reg as u32, src_reg as u32) != 0 }
    }

    /// Insert a `stp reg, reg, [reg + o]` instruction.
    pub fn put_stp_reg_reg_reg_offset(
        &self,
        reg_a: Aarch64Register,
        reg_b: Aarch64Register,
        reg_dst: Aarch64Register,
        offset: i64,
        mode: IndexMode,
    ) -> bool {
        unsafe {
            gum_sys::gum_arm64_writer_put_stp_reg_reg_reg_offset(
                self.writer,
                reg_a as u32,
                reg_b as u32,
                reg_dst as u32,
                offset,
                mode as u32,
            ) != 0
        }
    }

    /// Insert a `ldr reg, [reg + o]` instruction.
    pub fn put_ldr_reg_reg_offset(&self, reg_a: Aarch64Register, reg_src: Aarch64Register, offset: u64) -> bool {
        unsafe {
            gum_sys::gum_arm64_writer_put_ldr_reg_reg_offset(self.writer, reg_a as u32, reg_src as u32, offset) != 0
        }
    }

    pub fn put_str_reg_reg_offset(&self, reg_src: Aarch64Register, reg_dst: Aarch64Register, offset: u64) -> bool {
        unsafe {
            gum_sys::gum_arm64_writer_put_str_reg_reg_offset(self.writer, reg_src as u32, reg_dst as u32, offset) != 0
        }
    }

    pub fn put_cmp_reg_reg(&self, reg_a: Aarch64Register, reg_b: Aarch64Register) -> bool {
        unsafe { gum_sys::gum_arm64_writer_put_cmp_reg_reg(self.writer, reg_a as u32, reg_b as u32) != 0 }
    }

    /// Insert a `ldp reg, reg, [reg + o]` instruction.
    pub fn put_ldp_reg_reg_reg_offset(
        &self,
        reg_a: Aarch64Register,
        reg_b: Aarch64Register,
        reg_src: Aarch64Register,
        offset: i64,
        mode: IndexMode,
    ) -> bool {
        unsafe {
            gum_sys::gum_arm64_writer_put_ldp_reg_reg_reg_offset(
                self.writer,
                reg_a as u32,
                reg_b as u32,
                reg_src as u32,
                offset,
                mode as u32,
            ) != 0
        }
    }

    /// Insert a `mov reg, u64` instruction.
    pub fn put_ldr_reg_u64(&self, reg: Aarch64Register, address: u64) -> bool {
        unsafe { gum_sys::gum_arm64_writer_put_ldr_reg_u64(self.writer, reg as u32, address) != 0 }
    }

    pub fn put_push_reg_reg(&self, reg_a: Aarch64Register, reg_b: Aarch64Register) -> bool {
        unsafe { gum_sys::gum_arm64_writer_put_push_reg_reg(self.writer, reg_a as u32, reg_b as u32) != 0 }
    }
    pub fn put_pop_reg_reg(&self, reg_a: Aarch64Register, reg_b: Aarch64Register) -> bool {
        unsafe { gum_sys::gum_arm64_writer_put_pop_reg_reg(self.writer, reg_a as u32, reg_b as u32) != 0 }
    }

    pub fn put_br_reg(&self, reg: Aarch64Register) -> bool {
        unsafe { gum_sys::gum_arm64_writer_put_br_reg(self.writer, reg as u32) != 0 }
    }
    pub fn put_ldr_reg_address(&self, reg: Aarch64Register, address: u64) -> bool {
        unsafe { gum_sys::gum_arm64_writer_put_ldr_reg_address(self.writer, reg as u32, address) != 0 }
    }
    pub fn put_adrp_reg_address(&self, reg: Aarch64Register, address: u64) -> bool {
        unsafe { gum_sys::gum_arm64_writer_put_adrp_reg_address(self.writer, reg as u32, address) != 0 }
    }

    pub fn put_bcond_label(&self, branch_condition: Aarch64BranchCondition, label_id: u64) {
        unsafe {
            gum_sys::gum_arm64_writer_put_b_cond_label(self.writer, branch_condition as u32, label_id as *const c_void)
        }
    }

    #[allow(clippy::useless_conversion)]
    pub fn put_call_address_with_arguments(&self, address: u64, arguments: &[Argument]) -> bool {
        unsafe {
            let arguments: Vec<GumArgument> = arguments
                .iter()
                .map(|argument| match argument {
                    Argument::Register(register) => GumArgument {
                        type_: gum_sys::_GumArgType_GUM_ARG_REGISTER.try_into().unwrap(),
                        value: gum_sys::_GumArgument__bindgen_ty_1 { reg: *register as i32 },
                    },
                    Argument::Address(address) => GumArgument {
                        type_: gum_sys::_GumArgType_GUM_ARG_ADDRESS.try_into().unwrap(),
                        value: gum_sys::_GumArgument__bindgen_ty_1 { address: *address },
                    },
                })
                .collect();

            gum_sys::gum_arm64_writer_put_call_address_with_arguments_array(
                self.writer,
                address,
                arguments.len() as u32,
                arguments.as_ptr(),
            );
            true
        }
    }

    /// Insert a `bl imm` instruction.
    pub fn put_bl_imm(&self, address: u64) -> bool {
        unsafe { gum_sys::gum_arm64_writer_put_bl_imm(self.writer, address) != 0 }
    }
}

impl Drop for Aarch64InstructionWriter {
    fn drop(&mut self) {
        if self.is_from_new {
            unsafe { gum_sys::gum_arm64_writer_unref(self.writer) }
        }
    }
}
