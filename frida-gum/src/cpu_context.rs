/*
 * Copyright © 2020-2021 Keegan Saunders
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */
use {
    core::{ffi::c_void, marker::PhantomData},
    frida_gum_sys as gum_sys,
    gum_sys::GumCpuContext,
    paste::paste,
};

macro_rules! cpu_accesors {
    ($reg:ty,$($name:ident),*) => {
        $(
            pub fn $name(&self) -> $reg {
                unsafe { (*self.cpu_context).$name }
            }

            paste! {
                pub fn [<set_ $name>](&mut self, $name: $reg) {
                    unsafe { (*self.cpu_context).$name = $name }
                }
            }
        )*
    }
}

/// Platform-dependent access to processor state.
pub struct CpuContext<'a> {
    pub cpu_context: *mut GumCpuContext,
    phantom: PhantomData<&'a GumCpuContext>,
}

impl<'a> CpuContext<'a> {
    pub(crate) fn from_raw(cpu_context: *mut GumCpuContext) -> CpuContext<'a> {
        CpuContext {
            cpu_context,
            phantom: PhantomData,
        }
    }

    /// Get a numbered argument from the processor context, determined by the platform calling convention.
    pub fn arg(&self, n: u32) -> usize {
        unsafe { gum_sys::gum_cpu_context_get_nth_argument(self.cpu_context, n) as usize }
    }

    /// Set a numbered argument in the processor context, determined by the platform calling convention.
    pub fn set_arg(&mut self, n: u32, value: usize) {
        unsafe { gum_sys::gum_cpu_context_replace_nth_argument(self.cpu_context, n, value as *mut c_void) }
    }

    /// Get the value of the register used for the platform calling convention's return value.
    pub fn return_value(&self) -> usize {
        unsafe { gum_sys::gum_cpu_context_get_return_value(self.cpu_context) as usize }
    }

    /// Set the value of the register used for the platform calling convention's return value.
    pub fn set_return_value(&mut self, value: usize) {
        unsafe { gum_sys::gum_cpu_context_replace_return_value(self.cpu_context, value as *mut c_void) }
    }

    #[cfg(target_arch = "x86_64")]
    cpu_accesors!(u64, rip, r15, r14, r13, r12, r11, r10, r9, r8, rdi, rsi, rbp, rsp, rbx, rdx, rcx, rax);

    #[cfg(target_arch = "x86")]
    cpu_accesors!(u32, eip, edi, esi, ebp, esp, ebx, edx, ecx, eax);

    #[cfg(target_arch = "arm")]
    cpu_accesors!(u32, cpsr, pc, sp, r8, r9, r10, r11, r12, lr);
    // TODO(meme) uint32_t r[8];

    #[cfg(target_arch = "aarch64")]
    cpu_accesors!(u64, pc, sp, fp, lr);
    // TODO(meme) uint8_t q[128]; uint64_t x[29];

    #[cfg(target_arch = "aarch64")]
    /// Get the value of the specified general purpose register.
    pub fn reg(&self, index: usize) -> u64 {
        assert!(index < 29);
        unsafe { (*self.cpu_context).x[index] }
    }

    #[cfg(target_arch = "aarch64")]
    /// Set the value of the specified general purpose register.
    pub fn set_reg(&mut self, index: usize, value: u64) {
        assert!(index < 29);
        unsafe { (*self.cpu_context).x[index] = value };
    }

    #[cfg(feature = "backtrace")]
    #[cfg_attr(docsrs, doc(cfg(feature = "backtrace")))]
    /// Get an accurate backtrace from this CPU context.
    pub fn backtrace_accurate(&self) -> Vec<usize> {
        crate::Backtracer::accurate_with_context(unsafe { &*self.cpu_context })
    }

    #[cfg(feature = "backtrace")]
    #[cfg_attr(docsrs, doc(cfg(feature = "backtrace")))]
    /// Get a fuzzy backtrace from this CPU context.
    pub fn backtrace_fuzzy(&self) -> Vec<usize> {
        crate::Backtracer::fuzzy_with_context(unsafe { &*self.cpu_context })
    }
}
