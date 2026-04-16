use {
    crate::{
        error::GumResult,
        script::{Script, ScriptData},
        Gum,
    },
    core::{ffi::c_void, pin::Pin, ptr::null_mut},
    frida_gum_sys::{
        gum_script_backend_create, gum_script_backend_obtain_qjs, gum_script_backend_obtain_v8, GBytes, GCancellable,
        GumScriptBackend,
    },
};

#[cfg(feature = "std")]
use std::ffi::CString;

#[cfg(not(feature = "std"))]
use alloc::ffi::CString;

#[derive(Clone)]
pub struct Backend {
    internal: *mut GumScriptBackend,
    _gum: Gum,
}

impl Backend {
    pub(crate) fn from_raw(gum: &Gum, backend: *mut GumScriptBackend) -> Self {
        Self {
            _gum: gum.clone(),
            internal: backend,
        }
    }

    pub fn obtain_qjs(gum: &Gum) -> Self {
        Self::from_raw(gum, unsafe { gum_script_backend_obtain_qjs() })
    }

    pub fn obtain_v8(gum: &Gum) -> Self {
        Self::from_raw(gum, unsafe { gum_script_backend_obtain_v8() })
    }

    pub(crate) fn load_script<F: Fn(&str, &[u8])>(&self, script: &mut Script<F>) -> GumResult<()> {
        let cname = CString::new(script.name.as_str()).unwrap();
        let cpayload = CString::new(script.payload.as_str()).unwrap();
        let snapshot: *mut GBytes = null_mut();
        let cancellable: *mut GCancellable = null_mut();
        let script_data = unsafe { Pin::into_inner_unchecked(script.data.as_mut()) };
        script_data.set_backend(self.internal);
        unsafe {
            gum_script_backend_create(
                self.internal,
                cname.as_ptr(),
                cpayload.as_ptr(),
                snapshot,
                cancellable,
                Some(ScriptData::<F>::create_cb),
                script_data as *mut ScriptData<F> as *mut c_void,
            );
        }
        Ok(())
    }
}
