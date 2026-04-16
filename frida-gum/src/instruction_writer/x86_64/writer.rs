use {
    crate::instruction_writer::{Argument, InstructionWriter, X86BranchCondition, X86Register},
    core::ffi::c_void,
    frida_gum_sys as gum_sys,
    gum_sys::{gssize, GumArgument, GumBranchHint},
};

#[cfg(not(any(feature = "module-names", feature = "backtrace", feature = "memory-access-monitor")))]
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// The x86/x86_64 instruction writer.
pub struct X86InstructionWriter {
    pub(crate) writer: *mut gum_sys::_GumX86Writer,
    is_from_new: bool,
}

impl InstructionWriter for X86InstructionWriter {
    fn new(code_address: u64) -> Self {
        Self {
            writer: unsafe { gum_sys::gum_x86_writer_new(code_address as *mut c_void) },
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
        unsafe { gum_sys::gum_x86_writer_can_branch_directly_between(source, target) != 0 }
    }

    fn put_bytes(&self, bytes: &[u8]) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_bytes(self.writer, bytes.as_ptr(), bytes.len() as u32);
            true
        }
    }

    fn put_label(&self, id: u64) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_label(self.writer, id as *const c_void) != 0 }
    }

    fn reset(&self, code_address: u64) {
        unsafe { gum_sys::gum_x86_writer_reset(self.writer, code_address as *mut c_void) }
    }

    fn put_branch_address(&self, address: u64) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_jmp_address(self.writer, address) != 0 }
    }

    fn put_nop(&self) {
        unsafe { gum_sys::gum_x86_writer_put_nop(self.writer) }
    }

    fn flush(&self) -> bool {
        unsafe { gum_sys::gum_x86_writer_flush(self.writer) != 0 }
    }
}

impl X86InstructionWriter {
    pub(crate) fn from_raw(writer: *mut gum_sys::_GumX86Writer) -> Self {
        Self {
            writer,
            is_from_new: false,
        }
    }

    /// Get the underlying frida gum writer object
    pub fn raw_writer(&self) -> *mut gum_sys::_GumX86Writer {
        self.writer
    }

    pub fn put_leave(&self) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_leave(self.writer);
        }
        true
    }

    pub fn put_ret(&self) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_ret(self.writer);
        }
        true
    }

    pub fn put_ret_imm(&self, imm: u16) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_ret_imm(self.writer, imm);
        }
        true
    }

    pub fn put_jmp_address(&self, address: u64) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_jmp_address(self.writer, address) != 0 }
    }

    pub fn put_jmp_short_label(&self, id: u64) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_jmp_short_label(self.writer, id as *const c_void);
        }
        true
    }

    /// Insert a `jmp` near to a label. The label is specified by `id`.
    pub fn put_jmp_near_label(&self, id: u64) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_jmp_near_label(self.writer, id as *const c_void);
        }
        true
    }

    pub fn put_jmp_reg(&self, reg: X86Register) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_jmp_reg(self.writer, reg as u32) != 0 }
    }

    pub fn put_jmp_reg_ptr(&self, reg: X86Register) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_jmp_reg_ptr(self.writer, reg as u32) != 0 }
    }

    pub fn put_jmp_reg_offset_ptr(&self, reg: X86Register, offset: isize) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_jmp_reg_offset_ptr(self.writer, reg as u32, offset as gssize) != 0 }
    }

    pub fn put_jmp_near_ptr(&self, address: u64) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_jmp_near_ptr(self.writer, address) != 0 }
    }

    pub fn put_jcc_short_label(&self, condition: X86BranchCondition, label_id: u64, hint: GumBranchHint) {
        unsafe {
            gum_sys::gum_x86_writer_put_jcc_short_label(
                self.writer,
                #[allow(clippy::useless_conversion)]
                (condition as u32).try_into().unwrap(),
                label_id as *const c_void,
                hint,
            )
        }
    }

    pub fn put_jcc_near_label(&self, condition: X86BranchCondition, label_id: u64, hint: GumBranchHint) {
        unsafe {
            gum_sys::gum_x86_writer_put_jcc_near_label(
                self.writer,
                #[allow(clippy::useless_conversion)]
                (condition as u32).try_into().unwrap(),
                label_id as *const c_void,
                hint,
            )
        }
    }

    pub fn put_mov_reg_gs_u32_ptr(&self, reg: X86Register, imm: u32) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_mov_reg_gs_u32_ptr(self.writer, reg as u32, imm) != 0 }
    }

    pub fn put_add_reg_imm(&self, reg: X86Register, imm: isize) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_add_reg_imm(self.writer, reg as u32, imm as gssize) != 0 }
    }

    pub fn put_add_reg_reg(&self, dst_reg: X86Register, src_reg: X86Register) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_add_reg_reg(self.writer, dst_reg as u32, src_reg as u32) != 0 }
    }

    pub fn put_add_reg_near_ptr(&self, dst_reg: X86Register, address: u64) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_add_reg_near_ptr(self.writer, dst_reg as u32, address) != 0 }
    }

    pub fn put_sub_reg_imm(&self, dst_reg: X86Register, imm: isize) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_sub_reg_imm(self.writer, dst_reg as u32, imm as gssize) != 0 }
    }

    pub fn put_sub_reg_reg(&self, dst_reg: X86Register, src_reg: X86Register) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_sub_reg_reg(self.writer, dst_reg as u32, src_reg as u32) != 0 }
    }

    pub fn put_sub_reg_near_ptr(&self, dst_reg: X86Register, address: u64) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_sub_reg_near_ptr(self.writer, dst_reg as u32, address) != 0 }
    }

    pub fn put_inc_reg(&self, reg: X86Register) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_inc_reg(self.writer, reg as u32) != 0 }
    }

    pub fn put_dec_reg(&self, reg: X86Register) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_dec_reg(self.writer, reg as u32) != 0 }
    }

    pub fn put_and_reg_reg(&self, dst_reg: X86Register, src_reg: X86Register) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_and_reg_reg(self.writer, dst_reg as u32, src_reg as u32) != 0 }
    }

    pub fn put_and_reg_u32(&self, reg: X86Register, imm: u32) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_and_reg_u32(self.writer, reg as u32, imm) != 0 }
    }

    pub fn put_shl_reg_u8(&self, dst_reg: X86Register, imm: u8) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_shl_reg_u8(self.writer, dst_reg as u32, imm) != 0 }
    }

    pub fn put_shr_reg_u8(&self, dst_reg: X86Register, imm: u8) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_shr_reg_u8(self.writer, dst_reg as u32, imm) != 0 }
    }

    pub fn put_xor_reg_reg(&self, dst_reg: X86Register, src_reg: X86Register) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_xor_reg_reg(self.writer, dst_reg as u32, src_reg as u32) != 0 }
    }

    pub fn put_mov_reg_reg(&self, dst_reg: X86Register, src_reg: X86Register) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_mov_reg_reg(self.writer, dst_reg as u32, src_reg as u32) != 0 }
    }

    pub fn put_mov_reg_u32(&self, dst_reg: X86Register, imm: u32) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_mov_reg_u32(self.writer, dst_reg as u32, imm) != 0 }
    }

    pub fn put_mov_reg_u64(&self, dst_reg: X86Register, imm: u64) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_mov_reg_u64(self.writer, dst_reg as u32, imm) != 0 }
    }

    pub fn put_mov_reg_address(&self, dst_reg: X86Register, address: u64) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_mov_reg_address(self.writer, dst_reg as u32, address);
        }
        true
    }

    pub fn put_mov_reg_ptr_u32(&self, dst_reg: X86Register, imm: u32) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_mov_reg_ptr_u32(self.writer, dst_reg as u32, imm);
        }
        true
    }

    pub fn put_mov_reg_offset_ptr_u32(&self, dst_reg: X86Register, offset: isize, imm: u32) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_mov_reg_offset_ptr_u32(self.writer, dst_reg as u32, offset as gssize, imm) != 0
        }
    }

    pub fn put_mov_reg_ptr_reg(&self, dst_reg: X86Register, src_reg: X86Register) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_mov_reg_ptr_reg(self.writer, dst_reg as u32, src_reg as u32);
        }
        true
    }

    pub fn put_mov_reg_offset_ptr_reg(&self, dst_reg: X86Register, offset: isize, src_reg: X86Register) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_mov_reg_offset_ptr_reg(
                self.writer,
                dst_reg as u32,
                offset as gssize,
                src_reg as u32,
            ) != 0
        }
    }

    pub fn put_mov_reg_reg_ptr(&self, dst_reg: X86Register, src_reg: X86Register) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_mov_reg_reg_ptr(self.writer, dst_reg as u32, src_reg as u32) }
        true
    }

    pub fn put_mov_reg_reg_offset_ptr(&self, dst_reg: X86Register, src_reg: X86Register, offset: isize) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_mov_reg_reg_offset_ptr(
                self.writer,
                dst_reg as u32,
                src_reg as u32,
                offset as gssize,
            ) != 0
        }
    }

    pub fn put_mov_reg_base_index_scale_offset_ptr(
        &self,
        dst_reg: X86Register,
        base_reg: X86Register,
        index_reg: X86Register,
        scale: u8,
        offset: isize,
    ) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_mov_reg_base_index_scale_offset_ptr(
                self.writer,
                dst_reg as u32,
                base_reg as u32,
                index_reg as u32,
                scale,
                offset as gssize,
            ) != 0
        }
    }

    /// Insert a `lea d, [s + o]` instruction.
    pub fn put_lea_reg_reg_offset(&self, dst_reg: X86Register, src_reg: X86Register, src_offset: isize) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_lea_reg_reg_offset(
                self.writer,
                dst_reg as u32,
                src_reg as u32,
                src_offset as gssize,
            ) != 0
        }
    }

    pub fn put_push_u32(&self, imm: u32) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_push_u32(self.writer, imm);
        }
        true
    }

    pub fn put_push_near_ptr(&self, address: u64) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_push_near_ptr(self.writer, address) != 0 }
    }

    /// Insert a `push R` instruction.
    pub fn put_push_reg(&self, reg: X86Register) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_push_reg(self.writer, reg as u32) != 0 }
    }

    /// Insert a `pop R` instruction.
    pub fn put_pop_reg(&self, reg: X86Register) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_pop_reg(self.writer, reg as u32) != 0 }
    }

    /// Insert a call address instruction.
    pub fn put_call_address(&self, address: u64) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_call_address(self.writer, address) != 0 }
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

            gum_sys::gum_x86_writer_put_call_address_with_arguments_array(
                self.writer,
                gum_sys::_GumCallingConvention_GUM_CALL_CAPI.try_into().unwrap(),
                address,
                arguments.len() as u32,
                arguments.as_ptr(),
            ) != 0
        }
    }

    #[allow(clippy::useless_conversion)]
    pub fn put_call_address_with_aligned_arguments(&self, address: u64, arguments: &[Argument]) -> bool {
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

            gum_sys::gum_x86_writer_put_call_address_with_aligned_arguments_array(
                self.writer,
                gum_sys::_GumCallingConvention_GUM_CALL_CAPI.try_into().unwrap(),
                address,
                arguments.len() as u32,
                arguments.as_ptr(),
            ) != 0
        }
    }

    pub fn put_test_reg_reg(&self, reg_a: X86Register, reg_b: X86Register) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_test_reg_reg(self.writer, reg_a as u32, reg_b as u32) != 0 }
    }
    pub fn put_nop(&self) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_nop(self.writer);
        }
        true
    }

    pub fn put_pushfx(&self) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_pushfx(self.writer);
        }
        true
    }

    pub fn put_popfx(&self) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_popfx(self.writer);
        }
        true
    }

    pub fn put_pushax(&self) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_pushax(self.writer);
        }
        true
    }

    pub fn put_popax(&self) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_popax(self.writer);
        }
        true
    }
}

impl Drop for X86InstructionWriter {
    fn drop(&mut self) {
        if self.is_from_new {
            unsafe { gum_sys::gum_x86_writer_unref(self.writer) }
        }
    }
}
