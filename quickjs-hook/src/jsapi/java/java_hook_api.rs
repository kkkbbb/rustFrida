//! JS API: Java.hook / Java.unhook
//!
//! 安装、卸载与安装期资源回滚拆分到子模块，降低单文件复杂度。

mod fast_install;
mod install;
mod install_support;
mod managed_dex_builder;
mod managed_install;
mod uninstall;

pub(in crate::jsapi::java) use fast_install::install_fast_hook_with_env;
pub(super) use fast_install::{js_fast_hook, js_fast_hook_check, js_fast_hook_signature, js_fast_hook_stats};
pub(super) use install::{js_java_hook, js_java_hook_quick};
pub use managed_install::managed_native_counter_value;
pub(in crate::jsapi::java) use managed_install::{
    drain_managed_messages_inner, install_managed_dsl_with_env, read_managed_counter_inner, ManagedDrainResult,
    ManagedDslInstallResult,
};
pub(crate) use managed_install::{finish_java_worker_thread_from_native, start_java_worker_thread};
pub(super) use managed_install::{js_managed_drain_messages, js_managed_hook_dsl, js_managed_read_counter};
pub(super) use uninstall::js_java_unhook;
