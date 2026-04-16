use {
    crate::error::{Error, GumResult},
    core::{
        ffi::{c_void, CStr},
        ptr::null_mut,
        slice::from_raw_parts,
    },
    frida_gum_sys::{
        gchar, gpointer, gsize, gum_script_backend_create_finish, gum_script_load, gum_script_load_finish,
        gum_script_set_message_handler, GAsyncResult, GBytes, GCancellable, GError, GObject, GumScript,
        GumScriptBackend,
    },
};

/* glib exports are aliased in frida devkit for Linux and Android */
#[cfg(any(target_os = "linux", target_os = "android"))]
use frida_gum_sys::_frida_g_bytes_get_data as g_bytes_get_data;

#[cfg(not(any(target_os = "linux", target_os = "android")))]
use frida_gum_sys::g_bytes_get_data;

pub(crate) struct ScriptData<F>
where
    F: Fn(&str, &[u8]),
{
    backend: *mut GumScriptBackend,
    script: *mut GumScript,
    result: GumResult<()>,
    callback: Option<F>,
}

impl<F> ScriptData<F>
where
    F: Fn(&str, &[u8]),
{
    pub fn new(callback: Option<F>) -> Self {
        ScriptData {
            backend: null_mut(),
            script: null_mut(),
            result: Err(Error::LoadScriptNotStarted),
            callback,
        }
    }

    pub(crate) unsafe extern "C" fn create_cb(
        _source_object: *mut GObject,
        result: *mut GAsyncResult,
        user_data: gpointer,
    ) {
        let data = &mut *(user_data as *mut ScriptData<F>);
        let mut error: *mut GError = null_mut();

        data.script = gum_script_backend_create_finish(data.backend, result, &mut error);
        if data.script.is_null() || !error.is_null() {
            data.result = Err(Error::FailedToCreateScript);
            return;
        }

        gum_script_set_message_handler(data.script, Some(ScriptData::<F>::js_msg), user_data, None);

        let cancellable: *mut GCancellable = null_mut();
        gum_script_load(
            data.script,
            cancellable,
            Some(ScriptData::<F>::load_cb),
            data as *mut ScriptData<F> as *mut c_void,
        );
    }

    fn get_bytes(gdata: &mut GBytes) -> GumResult<&[u8]> {
        let mut size: gsize = 0;
        let data = unsafe { g_bytes_get_data(gdata, &mut size) } as *const u8;
        if data.is_null() || size == 0 {
            return Ok(&[]);
        }

        let bytes = unsafe { from_raw_parts(data, size.try_into().map_err(|_e| Error::FailedToReadBytes)?) };
        Ok(bytes)
    }

    unsafe extern "C" fn js_msg(gmessage: *const gchar, gbytes: *mut GBytes, user_data: gpointer) {
        let data = &mut *(user_data as *mut ScriptData<F>);
        let message = CStr::from_ptr(gmessage).to_str().unwrap_or_default();
        let bytes = if gbytes.is_null() {
            &[]
        } else {
            Self::get_bytes(&mut *gbytes).unwrap_or_default()
        };
        if let Some(callback) = &mut data.callback {
            callback(message, bytes);
        }
    }

    unsafe extern "C" fn load_cb(_source_object: *mut GObject, result: *mut GAsyncResult, user_data: gpointer) {
        let data = &mut *(user_data as *mut ScriptData<F>);
        gum_script_load_finish(data.script, result);
        data.result = Ok(());
    }

    pub fn loaded(&self) -> GumResult<()> {
        self.result.clone()
    }

    pub fn set_backend(&mut self, backend: *mut GumScriptBackend) {
        self.backend = backend;
    }
}
