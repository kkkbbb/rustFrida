//! Console API implementation

use crate::context::JSContext;
use crate::ffi;
use crate::jsapi::util::add_cfunction_to_object;
use crate::value::JSValue;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

/// Callback type for console output
pub type ConsoleCallback = Box<dyn Fn(&str) + Send + 'static>;

/// Global console output callback
static CONSOLE_CALLBACK: Mutex<Option<ConsoleCallback>> = Mutex::new(None);

/// 全局 verbose 开关（由 host 端 --verbose 传入）
static VERBOSE: AtomicBool = AtomicBool::new(false);

/// 设置 verbose 模式
pub fn set_verbose(on: bool) {
    VERBOSE.store(on, Ordering::Relaxed);
}

/// 查询 verbose 模式
pub fn is_verbose() -> bool {
    VERBOSE.load(Ordering::Relaxed)
}

/// Set the console output callback
pub fn set_console_callback<F>(callback: F)
where
    F: Fn(&str) + Send + 'static,
{
    let mut guard = CONSOLE_CALLBACK.lock().unwrap_or_else(|e| e.into_inner());
    *guard = Some(Box::new(callback));
}

/// Clear the console callback
pub fn clear_console_callback() {
    let mut guard = CONSOLE_CALLBACK.lock().unwrap_or_else(|e| e.into_inner());
    *guard = None;
}

/// Internal function to output console message
pub(crate) fn output_message(msg: &str) {
    let guard = CONSOLE_CALLBACK.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(callback) = guard.as_ref() {
        callback(msg);
    } else {
        // Default: print to stderr (for Android logcat)
        eprintln!("[JS] {}", msg);
    }
}

/// 仅 verbose 模式时输出的诊断信息
pub(crate) fn output_verbose(msg: &str) {
    if VERBOSE.load(Ordering::Relaxed) {
        output_message(msg);
    }
}

/// Format JS values for console output
fn format_args(ctx: *mut ffi::JSContext, argc: i32, argv: *mut ffi::JSValue) -> String {
    let mut parts = Vec::new();

    for i in 0..argc {
        let val = JSValue(unsafe { *argv.add(i as usize) });
        let s = val.to_string(ctx).unwrap_or_else(|| "[object]".to_string());
        parts.push(s);
    }

    parts.join(" ")
}

/// console.log implementation
unsafe extern "C" fn console_log(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let msg = format_args(ctx, argc, argv);
    output_message(&msg);
    JSValue::undefined().raw()
}

/// console.warn implementation
unsafe extern "C" fn console_warn(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let msg = format_args(ctx, argc, argv);
    output_message(&format!("[WARN] {}", msg));
    JSValue::undefined().raw()
}

/// console.error implementation
unsafe extern "C" fn console_error(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let msg = format_args(ctx, argc, argv);
    output_message(&format!("[ERROR] {}", msg));
    JSValue::undefined().raw()
}

/// console.info implementation
unsafe extern "C" fn console_info(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let msg = format_args(ctx, argc, argv);
    output_message(&format!("[INFO] {}", msg));
    JSValue::undefined().raw()
}

/// console.debug implementation
unsafe extern "C" fn console_debug(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let msg = format_args(ctx, argc, argv);
    output_message(&format!("[DEBUG] {}", msg));
    JSValue::undefined().raw()
}

/// Register console API on the context
pub fn register_console(ctx: &JSContext) {
    let global = ctx.global_object();
    let console = ctx.new_object();

    unsafe {
        let ctx_ptr = ctx.as_ptr();
        let obj = console.raw();
        add_cfunction_to_object(ctx_ptr, obj, "log", console_log, 0);
        add_cfunction_to_object(ctx_ptr, obj, "warn", console_warn, 0);
        add_cfunction_to_object(ctx_ptr, obj, "error", console_error, 0);
        add_cfunction_to_object(ctx_ptr, obj, "info", console_info, 0);
        add_cfunction_to_object(ctx_ptr, obj, "debug", console_debug, 0);
    }

    // Set console on global object
    global.set_property(ctx.as_ptr(), "console", console);
    global.free(ctx.as_ptr());
}
