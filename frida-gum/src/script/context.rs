use {
    crate::script::scheduler::Scheduler,
    frida_gum_sys::{GMainContext, GMainLoop},
};

#[cfg(any(target_os = "linux", target_os = "android"))]
use frida_gum_sys::{
    _frida_g_main_context_iteration as g_main_context_iteration,
    _frida_g_main_context_pending as g_main_context_pending,
    _frida_g_main_context_push_thread_default as g_main_context_push_thread_default,
    _frida_g_main_loop_new as g_main_loop_new,
};

#[cfg(not(any(target_os = "linux", target_os = "android")))]
use frida_gum_sys::{
    g_main_context_iteration, g_main_context_pending, g_main_context_push_thread_default, g_main_loop_new,
};

#[derive(Clone)]
pub(crate) struct Context {
    internal: *mut GMainContext,
    _scheduler: Scheduler,
}

impl Context {
    pub fn from_raw(scheduler: &Scheduler, context: *mut GMainContext) -> Self {
        Self {
            _scheduler: scheduler.clone(),
            internal: context,
        }
    }

    pub fn create_main_loop(&self, is_running: bool) -> *mut GMainLoop {
        unsafe { g_main_loop_new(self.internal, if is_running { 1 } else { 0 }) }
    }

    pub fn set_as_thread_default(&self) {
        unsafe { g_main_context_push_thread_default(self.internal) }
    }

    pub fn run(&self, may_block: bool) {
        unsafe {
            while g_main_context_pending(self.internal) != 0 {
                g_main_context_iteration(self.internal, if may_block { 1 } else { 0 });
            }
        }
    }
}
