use {crate::instruction_writer::InstructionWriter, core::ffi::c_void, frida_gum_sys as gum_sys};

pub struct ArmInstructionWriter {
    pub(crate) writer: *mut gum_sys::_GumArmWriter,
    is_from_new: bool,
}

impl InstructionWriter for ArmInstructionWriter {
    fn new(code_address: u64) -> Self {
        Self {
            writer: unsafe { gum_sys::gum_arm_writer_new(code_address as *mut c_void) },
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
        unsafe { gum_sys::gum_arm_writer_can_branch_directly_between(self.writer, source, target) != 0 }
    }

    fn put_bytes(&self, bytes: &[u8]) -> bool {
        unsafe { gum_sys::gum_arm_writer_put_bytes(self.writer, bytes.as_ptr(), bytes.len() as u32) != 0 }
    }

    fn put_label(&self, id: u64) -> bool {
        unsafe { gum_sys::gum_arm_writer_put_label(self.writer, id as *const c_void) != 0 }
    }

    fn reset(&self, code_address: u64) {
        unsafe { gum_sys::gum_arm_writer_reset(self.writer, code_address as *mut c_void) }
    }

    fn put_branch_address(&self, address: u64) -> bool {
        unsafe { gum_sys::gum_arm_writer_put_b_imm(self.writer, address) != 0 }
    }

    fn put_nop(&self) {
        unsafe { gum_sys::gum_arm_writer_put_nop(self.writer) }
    }

    fn flush(&self) -> bool {
        unsafe { gum_sys::gum_arm_writer_flush(self.writer) != 0 }
    }
}

impl ArmInstructionWriter {
    pub(crate) fn from_raw(writer: *mut gum_sys::_GumArmWriter) -> Self {
        Self {
            writer,
            is_from_new: false,
        }
    }

    /// Get the underlying frida gum writer object
    pub fn raw_writer(&self) -> *mut gum_sys::_GumArmWriter {
        self.writer
    }
}

impl Drop for ArmInstructionWriter {
    fn drop(&mut self) {
        if self.is_from_new {
            unsafe { gum_sys::gum_arm_writer_unref(self.writer) }
        }
    }
}
