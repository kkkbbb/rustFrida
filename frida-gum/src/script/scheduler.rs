use {
    crate::script::{backend::Backend, context::Context},
    frida_gum_sys::{
        gum_script_backend_get_scheduler, gum_script_scheduler_disable_background_thread,
        gum_script_scheduler_get_js_context, GumScriptScheduler,
    },
};

#[derive(Clone)]
pub(crate) struct Scheduler {
    internal: *mut GumScriptScheduler,
    _backend: Backend,
}

impl Scheduler {
    pub fn from_raw(backend: &Backend, scheduler: *mut GumScriptScheduler) -> Self {
        Self {
            _backend: backend.clone(),
            internal: scheduler,
        }
    }

    pub fn obtain(backend: &Backend) -> Self {
        Self::from_raw(backend, unsafe { gum_script_backend_get_scheduler() })
    }

    pub fn disable_background_thread(&self) {
        unsafe { gum_script_scheduler_disable_background_thread(self.internal) }
    }

    pub fn get_context(&self) -> Context {
        Context::from_raw(&self, unsafe { gum_script_scheduler_get_js_context(self.internal) })
    }
}
