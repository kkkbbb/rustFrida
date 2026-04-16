//! JavaScript API implementations

pub(crate) mod callback_util;
pub mod console;
pub mod hook_api;
pub mod java;
pub mod jni;
pub mod memory;
pub mod module;
pub mod ptr;
pub mod rpc;
pub(crate) mod util;

pub use console::register_console;
pub use hook_api::register_hook_api;
pub use java::deferred_java_init;
pub use java::register_java_api;
pub use jni::register_jni_api;
pub use memory::register_memory_api;
pub use module::register_module_api;
pub use ptr::register_ptr;
pub use rpc::register_rpc;

use crate::context::JSContext;

/// Register all JavaScript APIs
pub fn register_all_apis(ctx: &JSContext) {
    register_console(ctx);
    register_ptr(ctx);
    register_hook_api(ctx);
    register_jni_api(ctx);
    register_memory_api(ctx);
    register_module_api(ctx);
    register_java_api(ctx);
    register_rpc(ctx);
}
