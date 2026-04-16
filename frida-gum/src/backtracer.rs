/*
 * Copyright © 2020-2021 Keegan Saunders
 * Copyright © 2021 S Rubenstein
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! Backtracer helpers.
//!

use {core::mem::MaybeUninit, frida_gum_sys as gum_sys};

// The following function is not exposed through the `frida-gum.h` header, so we don't have an
// auto-generated binding for it. This may change in a future version.
#[cfg(not(target_os = "windows"))]
extern "C" {
    // On some platforms `ucontext` contains a u128 which does not have a defined ABI. In this case,
    // we disable the error as we assume the behaviour is correct (all other platforms are unaffected).
    #[allow(improper_ctypes)]
    fn gum_linux_parse_ucontext(context: *const libc::ucontext_t, cpu_context: *mut gum_sys::GumCpuContext);
}

pub struct Backtracer;

impl Backtracer {
    /// Generate a backtrace
    fn generate(backtracer: *mut gum_sys::GumBacktracer, context: *const gum_sys::GumCpuContext) -> Vec<usize> {
        let mut return_address_array = MaybeUninit::<gum_sys::_GumReturnAddressArray>::uninit();

        unsafe {
            gum_sys::gum_backtracer_generate(backtracer, context, return_address_array.as_mut_ptr());
            let return_address_array = return_address_array.assume_init();
            let mut result = vec![];
            for i in 0..return_address_array.len {
                result.push(*return_address_array.items.get(i as usize).unwrap() as usize);
            }
            result
        }
    }

    /// Generate an accurate backtrace as a list of return addresses from the current context
    pub fn accurate() -> Vec<usize> {
        Self::generate(unsafe { gum_sys::gum_backtracer_make_accurate() }, core::ptr::null())
    }

    /// Generate a fuzzy backtrace as a list of return addresses from the current context
    pub fn fuzzy() -> Vec<usize> {
        Self::generate(unsafe { gum_sys::gum_backtracer_make_fuzzy() }, core::ptr::null())
    }

    /// Generate an accurate backtrace as a list of return addresses for the supplied cpu
    /// context.
    pub fn accurate_with_context(context: &gum_sys::GumCpuContext) -> Vec<usize> {
        Self::generate(
            unsafe { gum_sys::gum_backtracer_make_accurate() },
            context as *const gum_sys::GumCpuContext,
        )
    }

    /// Generate a fuzzy backtrace as a list of return addresses for the supplied cpu
    /// context.
    pub fn fuzzy_with_context(context: &gum_sys::GumCpuContext) -> Vec<usize> {
        Self::generate(
            unsafe { gum_sys::gum_backtracer_make_fuzzy() },
            context as *const gum_sys::GumCpuContext,
        )
    }

    /// Generate an accurate backtrace as a list of return addresses for the supplied signal
    /// context.
    #[cfg(not(target_os = "windows"))]
    pub fn accurate_with_signal_context(context: &libc::ucontext_t) -> Vec<usize> {
        let mut cpu_context = MaybeUninit::<gum_sys::GumCpuContext>::uninit();

        unsafe {
            gum_linux_parse_ucontext(context as *const libc::ucontext_t, cpu_context.as_mut_ptr());
            Self::accurate_with_context(&cpu_context.assume_init())
        }
    }

    /// Generate a fuzzy backtrace as a list of return addresses for the supplied signal
    /// context.
    #[cfg(not(target_os = "windows"))]
    pub fn fuzzy_with_signal_context(context: &libc::ucontext_t) -> Vec<usize> {
        let mut cpu_context = MaybeUninit::<gum_sys::GumCpuContext>::uninit();

        unsafe {
            gum_linux_parse_ucontext(context as *const libc::ucontext_t, cpu_context.as_mut_ptr());
            Self::fuzzy_with_context(&cpu_context.assume_init())
        }
    }
}
