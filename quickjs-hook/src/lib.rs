#![allow(dead_code)]
//! quickjs-hook - QuickJS JavaScript engine with inline hook support for ARM64 Android
//!
//! This crate provides:
//! - QuickJS JavaScript engine bindings
//! - ARM64 inline hook engine
//! - Frida-style JavaScript API for hooking
//!
//! # Example
//!
//! ```rust,ignore
//! use quickjs_hook::{JSEngine, init_hook_engine};
//!
//! // Initialize hook engine with executable memory
//! init_hook_engine(exec_mem, size).unwrap();
//!
//! // Create JS engine and run script
//! let engine = JSEngine::new().unwrap();
//! engine.eval(r#"
//!     console.log("Hello from QuickJS!");
//!     hook(ptr("0x12345678"), function(ctx) {
//!         console.log("Hooked! x0=" + ctx.x0);
//!     });
//! "#).unwrap();
//! ```

#![allow(clippy::missing_safety_doc)]

mod completion;
pub mod context;
pub mod fast_hook;
pub mod ffi;
pub mod jsapi;
mod raw_thread;
pub mod recomp;
pub mod runtime;
pub mod value;

pub use completion::complete_script;
pub use context::JSContext;
pub use jsapi::console::{set_console_callback, set_verbose};
pub use jsapi::deferred_java_init;
pub use jsapi::hook_api::cleanup_hooks;
#[cfg(feature = "qbdi")]
pub use jsapi::hook_api::preload_qbdi_helper;
#[cfg(feature = "qbdi")]
pub use jsapi::hook_api::shutdown_qbdi_helper;
pub use jsapi::hook_api::{cut_native_hooks, free_native_hooks};
pub use jsapi::java::abort_raw_clone_java_executor_for_unload;
pub use jsapi::java::art_controller::{
    cut_art_controller_hooks, cut_art_controller_routing_hooks, cut_art_controller_walkstack_guards,
    free_art_controller_state, set_art_controller_reload_paused,
};
pub use jsapi::java::cleanup_java_hooks;
pub use jsapi::java::detach_current_jni_thread;
pub use jsapi::java::finish_java_worker_thread_from_native;
pub use jsapi::java::java_subsystem_active_for_cleanup;
pub use jsapi::java::raw_clone_java_executor_hook_active;
pub use jsapi::java::start_java_worker_thread;
pub use jsapi::java::{cut_java_hooks, drain_thunk_in_flight, free_java_hooks};
pub use jsapi::memory::cleanup_wxshadow_patches;
pub use runtime::JSRuntime;
pub use value::JSValue;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

const JS_TOP_LEVEL_EXECUTION_TIMEOUT_MS: u64 = 6_500;

static QBDI_OUTPUT_DIR: OnceLock<String> = OnceLock::new();
static QBDI_HELPER_BLOB: Mutex<Option<Vec<u8>>> = Mutex::new(None);
static JS_EXECUTION_DEADLINE_MS: AtomicU64 = AtomicU64::new(0);

pub fn set_qbdi_output_dir(output_dir: impl Into<String>) {
    let _ = QBDI_OUTPUT_DIR.set(output_dir.into());
}

pub fn set_qbdi_helper_blob(blob: Vec<u8>) {
    *QBDI_HELPER_BLOB.lock().unwrap_or_else(|e| e.into_inner()) = Some(blob);
}

pub(crate) fn qbdi_output_dir() -> Option<&'static str> {
    QBDI_OUTPUT_DIR.get().map(|s| s.as_str())
}

pub(crate) fn qbdi_helper_blob() -> Option<Vec<u8>> {
    QBDI_HELPER_BLOB.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// Global JS engine instance (protected by Mutex).
/// pub(crate) so hook_callback_wrapper can serialize concurrent JS_Call invocations.
pub(crate) static JS_ENGINE: Mutex<Option<JSEngine>> = Mutex::new(None);
/// Best-effort owner tracking for the thread currently executing inside the global JS engine.
/// Used by hook callbacks to distinguish same-thread reentrancy from ordinary contention.
pub(crate) static JS_ENGINE_OWNER_THREAD: AtomicU64 = AtomicU64::new(0);

static RAW_CLONE_JS_THREAD_0: AtomicU64 = AtomicU64::new(0);
static RAW_CLONE_JS_THREAD_1: AtomicU64 = AtomicU64::new(0);
static RAW_CLONE_JS_THREAD_2: AtomicU64 = AtomicU64::new(0);
static RAW_CLONE_JS_THREAD_3: AtomicU64 = AtomicU64::new(0);
static RAW_CLONE_JS_THREAD_4: AtomicU64 = AtomicU64::new(0);
static RAW_CLONE_JS_THREAD_5: AtomicU64 = AtomicU64::new(0);
static RAW_CLONE_JS_THREAD_6: AtomicU64 = AtomicU64::new(0);
static RAW_CLONE_JS_THREAD_7: AtomicU64 = AtomicU64::new(0);

fn raw_clone_js_thread_slots() -> [&'static AtomicU64; 8] {
    [
        &RAW_CLONE_JS_THREAD_0,
        &RAW_CLONE_JS_THREAD_1,
        &RAW_CLONE_JS_THREAD_2,
        &RAW_CLONE_JS_THREAD_3,
        &RAW_CLONE_JS_THREAD_4,
        &RAW_CLONE_JS_THREAD_5,
        &RAW_CLONE_JS_THREAD_6,
        &RAW_CLONE_JS_THREAD_7,
    ]
}

pub struct RawCloneJsThreadGuard {
    id: u64,
}

impl Drop for RawCloneJsThreadGuard {
    fn drop(&mut self) {
        for slot in raw_clone_js_thread_slots() {
            if slot.load(Ordering::Acquire) == self.id {
                let _ = slot.compare_exchange(self.id, 0, Ordering::AcqRel, Ordering::Acquire);
                break;
            }
        }
    }
}

pub fn mark_raw_clone_js_thread() -> RawCloneJsThreadGuard {
    let id = current_thread_id_u64();
    for slot in raw_clone_js_thread_slots() {
        if slot.load(Ordering::Acquire) == id
            || slot
                .compare_exchange(0, id, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            return RawCloneJsThreadGuard { id };
        }
    }
    RawCloneJsThreadGuard { id }
}

pub(crate) fn is_raw_clone_js_thread() -> bool {
    let id = current_thread_id_u64();
    raw_clone_js_thread_slots()
        .iter()
        .any(|slot| slot.load(Ordering::Acquire) == id)
}

#[inline]
pub(crate) fn current_thread_id_u64() -> u64 {
    // Must use TPIDR_EL0 directly — on API 36, pthread_self() != TPIDR_EL0.
    // The thunk bypass uses MRS TPIDR_EL0 for thread matching.
    let tpidr: u64;
    unsafe { std::arch::asm!("mrs {}, tpidr_el0", out(reg) tpidr) };
    tpidr
}

#[inline]
pub(crate) fn mark_js_engine_owner_current_thread() {
    JS_ENGINE_OWNER_THREAD.store(current_thread_id_u64(), Ordering::Release);
}

#[inline]
pub(crate) fn clear_js_engine_owner_current_thread() {
    let current = current_thread_id_u64();
    let _ = JS_ENGINE_OWNER_THREAD.compare_exchange(current, 0, Ordering::AcqRel, Ordering::Relaxed);
}

struct JsEngineOwnerGuard;

impl JsEngineOwnerGuard {
    fn acquire() -> Self {
        mark_js_engine_owner_current_thread();
        JsEngineOwnerGuard
    }
}

impl Drop for JsEngineOwnerGuard {
    fn drop(&mut self) {
        clear_js_engine_owner_current_thread();
    }
}

struct JsExecutionDeadlineGuard {
    previous_deadline_ms: u64,
}

impl JsExecutionDeadlineGuard {
    fn begin(timeout_ms: u64) -> Self {
        let previous_deadline_ms = JS_EXECUTION_DEADLINE_MS.load(Ordering::Acquire);
        let deadline_ms = if timeout_ms == 0 {
            0
        } else {
            monotonic_ms().saturating_add(timeout_ms)
        };
        JS_EXECUTION_DEADLINE_MS.store(deadline_ms, Ordering::Release);
        Self { previous_deadline_ms }
    }
}

impl Drop for JsExecutionDeadlineGuard {
    fn drop(&mut self) {
        JS_EXECUTION_DEADLINE_MS.store(self.previous_deadline_ms, Ordering::Release);
    }
}

fn monotonic_ms() -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    let ret = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    if ret != 0 {
        return 0;
    }
    (ts.tv_sec as u64)
        .saturating_mul(1_000)
        .saturating_add((ts.tv_nsec as u64) / 1_000_000)
}

pub(crate) fn js_execution_deadline_expired() -> bool {
    let deadline_ms = JS_EXECUTION_DEADLINE_MS.load(Ordering::Acquire);
    deadline_ms != 0 && monotonic_ms() >= deadline_ms
}

/// Log callback registered with the C hook engine.
/// Routes hook_engine diagnostic messages through the JS console callback
/// so they appear in the REPL output alongside normal [JS] messages.
unsafe extern "C" fn hook_engine_log_impl(msg: *const std::os::raw::c_char) {
    if msg.is_null() {
        return;
    }
    let s = std::ffi::CStr::from_ptr(msg).to_string_lossy();
    let formatted = format!("[hook_engine] {}", s);
    // 错误/警告永远输出（失败类消息对排错重要），其余全部 verbose 静默
    // 识别关键字: FAILED/failed/失败/ERROR/WARN/\033[31m 红/\033[33m 黄
    let is_error = s.contains("FAILED")
        || s.contains("failed")
        || s.contains("失败")
        || s.contains("ERROR")
        || s.contains("WARN")
        || s.contains("\x1b[31m")
        || s.contains("\x1b[33m");
    if is_error {
        crate::jsapi::console::output_message(&formatted);
    } else {
        crate::jsapi::console::output_verbose(&formatted);
    }
}

/// Initialize the hook engine with executable memory
///
/// # Arguments
/// * `exec_mem` - Pointer to executable memory region (must be RWX)
/// * `size` - Size of the memory region in bytes
///
/// # Returns
/// * `Ok(())` on success
/// * `Err(String)` on failure
pub fn init_hook_engine(exec_mem: *mut u8, size: usize) -> Result<(), String> {
    let result = unsafe { ffi::hook::hook_engine_init(exec_mem as *mut _, size) };

    if result == 0 {
        // Register log callback so wxshadow/prctl diagnostics appear in REPL
        unsafe { ffi::hook::hook_engine_set_log_fn(Some(hook_engine_log_impl)) };
        Ok(())
    } else {
        Err("Failed to initialize hook engine".to_string())
    }
}

/// Cleanup the hook engine
///
/// 对标 Frida: 只 reset 内部状态, 不 munmap 扩展 pool (见 hook_engine.c 注释).
/// 线程若还在 thunk 里执行, 代码页保留直到进程退出, 避免 SIGSEGV。
pub fn cleanup_hook_engine() {
    unsafe {
        ffi::hook::hook_engine_cleanup();
    }
}

/// High-level JS engine wrapper
/// Note: Field order matters for drop order - context must be dropped before runtime
pub struct JSEngine {
    context: JSContext,
    runtime: JSRuntime,
}

impl JSEngine {
    /// Create a new JS engine with all APIs registered
    pub fn new() -> Option<Self> {
        let runtime = JSRuntime::new()?;
        let context = runtime.new_context()?;

        // Register all JavaScript APIs
        jsapi::register_all_apis(&context);

        // 预缓存 hook callback 热路径用到的 atom（x0..x30 / sp / pc / lr / returnAddress /
        // trampoline / __hookCtxPtr / __hookTrampoline），消除每次回调的 CString+JS_NewAtom 开销。
        unsafe {
            jsapi::callback_util::init_hot_atoms(context.as_ptr());
        }

        Some(JSEngine { runtime, context })
    }

    /// Evaluate a JavaScript script
    pub fn eval(&self, script: &str) -> Result<JSValue, String> {
        self.context.eval(script, "<eval>")
    }

    /// Evaluate a script with a specific filename
    pub fn eval_file(&self, script: &str, filename: &str) -> Result<JSValue, String> {
        self.context.eval(script, filename)
    }

    /// Get the JS context
    pub fn context(&self) -> &JSContext {
        &self.context
    }

    /// Get the JS runtime
    pub fn runtime(&self) -> &JSRuntime {
        &self.runtime
    }

    /// Execute pending jobs (for promises)
    pub fn run_pending_jobs(&self) {
        while self.context.execute_pending_job() {}
    }

    /// Run callbacks queued by Java.ready() after the current top-level script
    /// has finished, so callbacks can reference helpers declared later in the
    /// same loadjs payload.
    pub fn flush_java_ready_callbacks(&self) -> Result<(), String> {
        if is_raw_clone_js_thread() {
            return Ok(());
        }
        let value = self.context.eval(
            "if (globalThis.Java && typeof Java._flushReadyCallbacks === 'function') Java._flushReadyCallbacks();",
            "<java_ready_flush>",
        )?;
        value.free(self.context.as_ptr());
        Ok(())
    }
}

impl Drop for JSEngine {
    fn drop(&mut self) {
        // 外部编排器 (agent::quickjs_loader::cleanup) 在调用 cleanup_engine 之前
        // 已按 cut → drain → free 完成所有 hook 清理。此处不再重复调用 cleanup_java_hooks
        // / cleanup_hooks — 否则 drain 会再跑一次 30s 上限（hook registry 已空，
        // 但 g_thunk_in_flight 可能仍 > 0，纯粹浪费时间）。
        //
        // 若 JSEngine 被独立 drop（非经 orchestrator），调用方负责先 cut/drain/free。
        //
        // Drop 顺序（字段声明顺序）：先 context（这里访问仍有效）→ 再 runtime。
        // 在 context drop 前释放热路径 atom，让 JS_FreeAtom 有合法上下文。
        unsafe {
            jsapi::callback_util::free_hot_atoms(self.context.as_ptr());
        }
    }
}

// Safety: JSEngine is protected by Mutex, ensuring single-threaded access
unsafe impl Send for JSEngine {}
unsafe impl Sync for JSEngine {}

/// Get or initialize the global JS engine
pub fn get_or_init_engine() -> Result<(), String> {
    let mut engine = JS_ENGINE
        .lock()
        .map_err(|e| format!("Failed to lock JS engine: {}", e))?;
    if engine.is_none() {
        *engine = Some(JSEngine::new().ok_or_else(|| "Failed to create JS engine".to_string())?);
    }
    Ok(())
}

/// Load and execute a JavaScript script using the global engine.
/// Returns the string representation of the result, or an empty string for `undefined`.
///
/// 等价于 `load_script_with_filename(script, "<eval>")`。
pub fn load_script(script: &str) -> Result<String, String> {
    load_script_with_filename(script, "<eval>")
}

/// Load + execute with an explicit filename (用于 QuickJS 报错时显示 `filename:line:col`)。
pub fn load_script_with_filename(script: &str, filename: &str) -> Result<String, String> {
    let mut engine = JS_ENGINE
        .lock()
        .map_err(|e| format!("Failed to lock JS engine: {}", e))?;
    if engine.is_none() {
        *engine = Some(JSEngine::new().ok_or_else(|| "Failed to create JS engine".to_string())?);
    }
    let engine = engine.as_ref().ok_or("JS engine not initialized")?;
    let _owner_guard = JsEngineOwnerGuard::acquire();
    let _deadline_guard = JsExecutionDeadlineGuard::begin(JS_TOP_LEVEL_EXECUTION_TIMEOUT_MS);
    let value = engine.eval_file(script, filename)?;
    engine.flush_java_ready_callbacks()?;
    engine.run_pending_jobs();
    let result = if value.is_undefined() {
        "undefined".to_string()
    } else {
        value.to_string(engine.context().as_ptr()).unwrap_or_default()
    };
    value.free(engine.context().as_ptr());
    Ok(result)
}

/// 将任意字符串编码成 JS 字符串字面量（带双引号），可直接拼入 JS 源码。
fn js_string_literal(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// 调用 `rpc.exports[method]` 并返回 JSON 字符串化后的结果。
///
/// 使用全局 JS 引擎锁，与 REPL eval 互斥。HTTP RPC 调用应在外层用 Mutex 串行化，
/// 防止多个并发请求竞争同一把 JS 引擎锁。
///
/// # 参数
/// * `method` - 注册在 `rpc.exports` 上的方法名
/// * `args_json` - JSON array 字符串（如 `"[1, 2, 3]"`），空字符串等价于 `"[]"`
///
/// # 返回
/// * `Ok(json)` - 返回值的 JSON 字符串表示；`undefined` 返回 `"null"`
/// * `Err(msg)` - 引擎未初始化 / 方法不存在 / JS 异常
pub fn dispatch_rpc(method: &str, args_json: &str) -> Result<String, String> {
    let engine = JS_ENGINE
        .lock()
        .map_err(|e| format!("Failed to lock JS engine: {}", e))?;
    let engine = engine.as_ref().ok_or("JS engine not initialized")?;
    let _owner_guard = JsEngineOwnerGuard::acquire();
    let _deadline_guard = JsExecutionDeadlineGuard::begin(JS_TOP_LEVEL_EXECUTION_TIMEOUT_MS);

    // 构造 `__rpc_dispatch("method", "args_json")` 表达式。
    let script = format!(
        "__rpc_dispatch({}, {})",
        js_string_literal(method),
        js_string_literal(args_json),
    );

    let value = engine.eval(&script)?;
    engine.run_pending_jobs();
    let result = value
        .to_string(engine.context().as_ptr())
        .unwrap_or_else(|| "null".to_string());
    value.free(engine.context().as_ptr());
    Ok(result)
}

/// Cleanup the global JS engine
pub fn cleanup_engine() {
    if let Ok(mut engine) = JS_ENGINE.lock() {
        *engine = None;
    }
}
