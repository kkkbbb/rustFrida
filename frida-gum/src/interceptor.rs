/*
 * Copyright © 2020-2021 Keegan Saunders
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! Function hooking engine.
//!
use {
    crate::{Error, Gum, NativePointer, Result},
    core::ptr,
    frida_gum_sys as gum_sys,
};

#[cfg(feature = "invocation-listener")]
use core::ffi::c_void;
#[cfg(feature = "invocation-listener")]
mod invocation_listener;
#[cfg(feature = "invocation-listener")]
#[cfg_attr(docsrs, doc(cfg(feature = "invocation-listener")))]
pub use invocation_listener::*;

/// Function hooking engine interface.
pub struct Interceptor {
    interceptor: *mut gum_sys::GumInterceptor,
    _gum: Gum,
}

impl Clone for Interceptor {
    fn clone(&self) -> Self {
        Interceptor {
            interceptor: unsafe { frida_gum_sys::g_object_ref(self.interceptor as *mut _) as *mut _ },
            _gum: self._gum.clone(),
        }
    }
}

impl Drop for Interceptor {
    fn drop(&mut self) {
        unsafe { frida_gum_sys::g_object_unref(self.interceptor as *mut _) }
    }
}

impl Interceptor {
    /// Obtain an Interceptor handle, ensuring that the runtime is properly initialized. This may
    /// be called as many times as needed, and results in a no-op if the Interceptor is
    /// already initialized.
    pub fn obtain(gum: &Gum) -> Interceptor {
        Interceptor {
            interceptor: unsafe { gum_sys::gum_interceptor_obtain() },
            _gum: gum.clone(),
        }
    }

    /// Attach a listener to the beginning of a function address.
    ///
    /// # Safety
    ///
    /// The provided address *must* point to the start of a function in a valid
    /// memory region.
    #[cfg(feature = "invocation-listener")]
    #[cfg_attr(docsrs, doc(cfg(feature = "invocation-listener")))]
    pub fn attach<I: InvocationListener>(&mut self, f: NativePointer, listener: &mut I) -> Result<Listener> {
        let listener = invocation_listener_transform(listener);
        match unsafe { gum_sys::gum_interceptor_attach(self.interceptor, f.0, listener, ptr::null_mut(), 0) } {
            gum_sys::GumAttachReturn_GUM_ATTACH_OK => Ok(Listener(NativePointer(listener as *mut c_void))),
            gum_sys::GumAttachReturn_GUM_ATTACH_WRONG_SIGNATURE => Err(Error::InterceptorBadSignature),
            gum_sys::GumAttachReturn_GUM_ATTACH_ALREADY_ATTACHED => Err(Error::InterceptorAlreadyAttached),
            gum_sys::GumAttachReturn_GUM_ATTACH_POLICY_VIOLATION => Err(Error::PolicyViolation),
            gum_sys::GumAttachReturn_GUM_ATTACH_WRONG_TYPE => Err(Error::WrongType),
            _ => Err(Error::InterceptorError),
        }
    }

    /// Attach a listener to an instruction address.
    ///
    /// # Safety
    ///
    /// The provided address *must* point to a valid instruction.
    #[cfg(feature = "invocation-listener")]
    #[cfg_attr(docsrs, doc(cfg(feature = "invocation-listener")))]
    pub fn attach_instruction<I: ProbeListener>(&mut self, instr: NativePointer, listener: &mut I) -> Result<Listener> {
        let listener = probe_listener_transform(listener);
        match unsafe { gum_sys::gum_interceptor_attach(self.interceptor, instr.0, listener, ptr::null_mut(), 0) } {
            gum_sys::GumAttachReturn_GUM_ATTACH_OK => Ok(Listener(NativePointer(listener as *mut c_void))),
            gum_sys::GumAttachReturn_GUM_ATTACH_WRONG_SIGNATURE => Err(Error::InterceptorBadSignature),
            gum_sys::GumAttachReturn_GUM_ATTACH_ALREADY_ATTACHED => Err(Error::InterceptorAlreadyAttached),
            gum_sys::GumAttachReturn_GUM_ATTACH_POLICY_VIOLATION => Err(Error::PolicyViolation),
            gum_sys::GumAttachReturn_GUM_ATTACH_WRONG_TYPE => Err(Error::WrongType),
            _ => Err(Error::InterceptorError),
        }
    }

    /// Detach an attached listener.
    ///
    /// # Safety
    ///
    /// The listener *must* have been attached with [`Interceptor::attach()`].
    #[cfg(feature = "invocation-listener")]
    #[cfg_attr(docsrs, doc(cfg(feature = "invocation-listener")))]
    pub fn detach(&mut self, listener: Listener) {
        let Listener(NativePointer(ptr)) = listener;
        unsafe { gum_sys::gum_interceptor_detach(self.interceptor, ptr as *mut gum_sys::GumInvocationListener) };
    }

    /// Replace a function with another function. The new function should have the same signature
    /// as the old one.
    ///
    /// # Safety
    ///
    /// Assumes that the provided function and replacement addresses are valid and point to the
    /// start of valid functions
    pub fn replace(
        &mut self,
        function: NativePointer,
        replacement: NativePointer,
        replacement_data: NativePointer,
    ) -> Result<NativePointer> {
        let mut original_function = NativePointer(ptr::null_mut());
        unsafe {
            match gum_sys::gum_interceptor_replace(
                self.interceptor,
                function.0,
                replacement.0,
                replacement_data.0,
                &mut original_function.0,
            ) {
                gum_sys::GumReplaceReturn_GUM_REPLACE_OK => Ok(original_function),
                gum_sys::GumReplaceReturn_GUM_REPLACE_WRONG_SIGNATURE => Err(Error::InterceptorBadSignature),
                gum_sys::GumReplaceReturn_GUM_REPLACE_ALREADY_REPLACED => Err(Error::InterceptorAlreadyReplaced),
                gum_sys::GumReplaceReturn_GUM_REPLACE_POLICY_VIOLATION => Err(Error::PolicyViolation),
                gum_sys::GumReplaceReturn_GUM_REPLACE_WRONG_TYPE => Err(Error::WrongType),
                _ => Err(Error::InterceptorError),
            }
        }
    }

    /// Replace a function with another function. The new function should have the same signature
    /// as the old one. This implementation avoids the overhead of the re-entrancy checking and
    /// context push/pop of conventional interceptors returning the address of a simple trampoline
    /// and patching the original function with the provided replacement. This type is not
    /// interoperable with `attach` and requires the caller to pass any required data to the hook
    /// function themselves.
    ///
    /// # Safety
    ///
    /// Assumes that the provided function and replacement addresses are valid and point to the
    /// start of valid functions
    pub fn replace_fast(&mut self, function: NativePointer, replacement: NativePointer) -> Result<NativePointer> {
        let mut original_function = NativePointer(ptr::null_mut());
        unsafe {
            match gum_sys::gum_interceptor_replace_fast(
                self.interceptor,
                function.0,
                replacement.0,
                &mut original_function.0,
            ) {
                gum_sys::GumReplaceReturn_GUM_REPLACE_OK => Ok(original_function),
                gum_sys::GumReplaceReturn_GUM_REPLACE_WRONG_SIGNATURE => Err(Error::InterceptorBadSignature),
                gum_sys::GumReplaceReturn_GUM_REPLACE_ALREADY_REPLACED => Err(Error::InterceptorAlreadyReplaced),
                gum_sys::GumReplaceReturn_GUM_REPLACE_POLICY_VIOLATION => Err(Error::PolicyViolation),
                gum_sys::GumReplaceReturn_GUM_REPLACE_WRONG_TYPE => Err(Error::WrongType),
                _ => Err(Error::InterceptorError),
            }
        }
    }

    /// Reverts a function replacement for the given function, such that the implementation is the
    /// original function.
    ///
    /// # Safety
    ///
    /// Assumes that function is the start of a real function previously replaced uisng
    /// [`Interceptor::replace`].
    pub fn revert(&mut self, function: NativePointer) {
        unsafe {
            gum_sys::gum_interceptor_revert(self.interceptor, function.0);
        }
    }

    /// Retrieve the current [`InvocationContext`].
    ///
    /// # Safety
    ///
    /// Should only be called from within a hook or replacement function.
    #[cfg(feature = "invocation-listener")]
    #[cfg_attr(docsrs, doc(cfg(feature = "invocation-listener")))]
    pub fn current_invocation<'a>() -> InvocationContext<'a> {
        InvocationContext::from_raw(unsafe { gum_sys::gum_interceptor_get_current_invocation() })
    }

    /// Begin an [`Interceptor`] transaction. This may improve performance if
    /// applying many hooks.
    ///
    /// # Safety
    ///
    /// After placing hooks, the transaction must be ended with [`Interceptor::end_transaction()`].
    pub fn begin_transaction(&mut self) {
        unsafe { gum_sys::gum_interceptor_begin_transaction(self.interceptor) };
    }

    /// End an [`Interceptor`] transaction. This must be called after placing hooks
    /// if in a transaction started with [`Interceptor::begin_transaction()`].
    pub fn end_transaction(&mut self) {
        unsafe { gum_sys::gum_interceptor_end_transaction(self.interceptor) };
    }
}

/// An instance of a listener attached to an instruction or function.
#[allow(dead_code)]
pub struct Listener(NativePointer);

impl Drop for Listener {
    fn drop(&mut self) {
        let Self(NativePointer(ptr)) = self;
        unsafe { frida_gum_sys::g_object_unref(*ptr) }
    }
}

impl Clone for Listener {
    fn clone(&self) -> Self {
        let Self(NativePointer(ptr)) = self;
        Self(NativePointer(unsafe { frida_gum_sys::g_object_ref(*ptr) }))
    }
}
