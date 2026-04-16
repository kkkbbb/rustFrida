use {
    crate::instruction_writer::{Relocator, X86InstructionWriter},
    core::ffi::c_void,
    frida_gum_sys::{cs_insn, Insn},
};

pub struct X86Relocator {
    inner: *mut c_void,
}

impl Relocator for X86Relocator {
    fn new(input_code: u64, output: &mut X86InstructionWriter) -> Self {
        extern "C" {
            fn gum_x86_relocator_new(input_code: *const c_void, output: *mut c_void) -> *mut c_void;
        }
        Self {
            inner: unsafe { gum_x86_relocator_new(input_code as *const c_void, output.writer as *mut c_void) },
        }
    }

    fn read_one(&mut self) -> (u32, Insn) {
        extern "C" {
            fn gum_x86_relocator_read_one(relocator: *mut c_void, instruction: *mut *const cs_insn) -> u32;
        }

        let mut insn_addr: *const cs_insn = core::ptr::null_mut();
        let ret = unsafe { gum_x86_relocator_read_one(self.inner, &mut insn_addr as *mut _) };
        (ret, unsafe { Insn::from_raw(insn_addr) })
    }

    fn eoi(&mut self) -> bool {
        extern "C" {
            fn gum_x86_relocator_eoi(relocator: *mut c_void) -> u32;
        }

        unsafe { gum_x86_relocator_eoi(self.inner) != 0 }
    }

    fn write_all(&mut self) {
        extern "C" {
            fn gum_x86_relocator_write_all(relocator: *mut c_void);
        }

        unsafe { gum_x86_relocator_write_all(self.inner) }
    }

    fn write_one(&mut self) -> bool {
        extern "C" {
            fn gum_x86_relocator_write_one(relocator: *mut c_void) -> i32;
        }

        unsafe { gum_x86_relocator_write_one(self.inner) != 0 }
    }

    fn skip_one(&mut self) -> bool {
        extern "C" {
            fn gum_x86_relocator_skip_one(relocator: *mut c_void) -> i32;
        }

        unsafe { gum_x86_relocator_skip_one(self.inner) != 0 }
    }
}

impl Drop for X86Relocator {
    fn drop(&mut self) {
        extern "C" {
            fn gum_x86_relocator_unref(relocator: *mut c_void);
        }

        unsafe { gum_x86_relocator_unref(self.inner) }
    }
}
