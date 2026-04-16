//! Shared callback utilities for hook and java hook callbacks
//!
//! Contains: JS engine lock acquisition, JS exception handling,
//! and registry initialization helpers.

use crate::ffi;
use crate::jsapi::console::output_message;
use crate::jsapi::ptr::get_native_pointer_addr;
use crate::jsapi::util::JSCFn;
use crate::value::JSValue;
use crate::JSEngine;
use std::ffi::CString;
use std::sync::MutexGuard;
use std::time::{Duration, Instant};

const CALLBACK_LOCK_WAIT_SPIN_LIMIT: usize = 32;
const CALLBACK_LOCK_WAIT_TIMEOUT: Duration = Duration::from_millis(20);
const JS_MAX_SAFE_INTEGER: u64 = 1u64 << 53;

pub(crate) enum JsEngineCallbackGuard {
    Locked {
        _guard: MutexGuard<'static, Option<JSEngine>>,
    },
    Reentrant,
}

impl Drop for JsEngineCallbackGuard {
    fn drop(&mut self) {
        if matches!(self, JsEngineCallbackGuard::Locked { .. }) {
            crate::clear_js_engine_owner_current_thread();
        }
    }
}

/// Acquire JS_ENGINE lock for a hook callback (try_lock to avoid deadlock).
///
/// Same-thread reentrant callbacks are allowed without re-locking the mutex,
/// because the current thread already owns the global engine.
///
/// Returns None if another thread holds the engine past the wait timeout.
/// On success, calls qjs_update_stack_top for cross-thread safety.
pub(crate) unsafe fn acquire_js_engine_for_callback(
    ctx: *mut ffi::JSContext,
    context_name: &str,
    target_id: u64,
) -> Option<JsEngineCallbackGuard> {
    let current_thread = crate::current_thread_id_u64();

    if crate::JS_ENGINE_OWNER_THREAD.load(std::sync::atomic::Ordering::Acquire) == current_thread {
        ffi::qjs_update_stack_top(ctx);
        return Some(JsEngineCallbackGuard::Reentrant);
    }

    let start = Instant::now();
    let mut spins = 0usize;

    loop {
        match crate::JS_ENGINE.try_lock() {
            Ok(g) => {
                crate::mark_js_engine_owner_current_thread();
                ffi::qjs_update_stack_top(ctx);
                return Some(JsEngineCallbackGuard::Locked { _guard: g });
            }
            Err(std::sync::TryLockError::WouldBlock) => {
                if crate::JS_ENGINE_OWNER_THREAD.load(std::sync::atomic::Ordering::Acquire) == current_thread {
                    ffi::qjs_update_stack_top(ctx);
                    return Some(JsEngineCallbackGuard::Reentrant);
                }

                if start.elapsed() >= CALLBACK_LOCK_WAIT_TIMEOUT {
                    output_message(&format!(
                        "[{}] callback skipped (JS engine busy > {} ms), target={:#x}",
                        context_name,
                        CALLBACK_LOCK_WAIT_TIMEOUT.as_millis(),
                        target_id
                    ));
                    return None;
                }

                if spins < CALLBACK_LOCK_WAIT_SPIN_LIMIT {
                    spins += 1;
                    std::hint::spin_loop();
                } else {
                    std::thread::yield_now();
                }
            }
            Err(std::sync::TryLockError::Poisoned(e)) => {
                crate::mark_js_engine_owner_current_thread();
                ffi::qjs_update_stack_top(ctx);
                return Some(JsEngineCallbackGuard::Locked { _guard: e.into_inner() });
            }
        }
    }
}

/// Check for JS exception, extract message, and output error.
///
/// Returns true if an exception was found (caller should do cleanup and return).
/// Handles secondary exceptions from toString gracefully.
pub(crate) unsafe fn handle_js_exception(ctx: *mut ffi::JSContext, result: ffi::JSValue, context_name: &str) -> bool {
    if ffi::qjs_is_exception(result) == 0 {
        return false;
    }
    let exc = ffi::JS_GetException(ctx);
    let exc_val = JSValue(exc);
    let msg_prop = exc_val.get_property(ctx, "message");
    let msg = if let Some(s) = msg_prop.to_string(ctx) {
        msg_prop.free(ctx);
        s
    } else {
        msg_prop.free(ctx);
        let fallback = exc_val
            .to_string(ctx)
            .unwrap_or_else(|| "[unknown exception]".to_string());
        // Consume any secondary exception from toString
        let secondary = ffi::JS_GetException(ctx);
        let secondary_val = JSValue(secondary);
        if !secondary_val.is_null() && !secondary_val.is_undefined() {
            secondary_val.free(ctx);
        }
        fallback
    };
    output_message(&format!("[{} error] {}", context_name, msg));
    exc_val.free(ctx);
    true
}

/// Initialize a Mutex<Option<HashMap>> registry if not already initialized (idempotent).
pub(crate) fn ensure_registry_initialized<K: std::hash::Hash + Eq, V>(
    registry: &std::sync::Mutex<Option<std::collections::HashMap<K, V>>>,
) {
    let mut guard = registry.lock().unwrap_or_else(|e| e.into_inner());
    if guard.is_none() {
        *guard = Some(std::collections::HashMap::new());
    }
}

/// Acquire registry lock and call f with immutable reference to the HashMap.
/// Returns None if the registry is not initialized.
pub(crate) fn with_registry<K, V, R>(
    registry: &std::sync::Mutex<Option<std::collections::HashMap<K, V>>>,
    f: impl FnOnce(&std::collections::HashMap<K, V>) -> R,
) -> Option<R>
where
    K: std::hash::Hash + Eq,
{
    let guard = registry.lock().unwrap_or_else(|e| e.into_inner());
    guard.as_ref().map(f)
}

/// Acquire registry lock and call f with mutable reference to the HashMap.
/// Returns None if the registry is not initialized.
pub(crate) fn with_registry_mut<K, V, R>(
    registry: &std::sync::Mutex<Option<std::collections::HashMap<K, V>>>,
    f: impl FnOnce(&mut std::collections::HashMap<K, V>) -> R,
) -> Option<R>
where
    K: std::hash::Hash + Eq,
{
    let mut guard = registry.lock().unwrap_or_else(|e| e.into_inner());
    guard.as_mut().map(f)
}

/// Bidirectional map backed by two Mutex<Option<HashMap<u64, u64>>>.
/// Provides synchronized forward and reverse lookups.
pub(crate) struct BiMap {
    forward: std::sync::Mutex<Option<std::collections::HashMap<u64, u64>>>,
    reverse: std::sync::Mutex<Option<std::collections::HashMap<u64, u64>>>,
}

impl BiMap {
    pub(crate) const fn new() -> Self {
        Self {
            forward: std::sync::Mutex::new(None),
            reverse: std::sync::Mutex::new(None),
        }
    }

    /// 初始化双向映射（幂等）
    pub(crate) fn init(&self) {
        ensure_registry_initialized(&self.forward);
        ensure_registry_initialized(&self.reverse);
    }

    /// 插入 forward(left → right) + reverse(right → left)
    pub(crate) fn insert(&self, left: u64, right: u64) {
        with_registry_mut(&self.forward, |map| {
            map.insert(left, right);
        });
        with_registry_mut(&self.reverse, |map| {
            map.insert(right, left);
        });
    }

    /// 通过 forward key 查找 value
    pub(crate) fn get_forward(&self, left: u64) -> Option<u64> {
        with_registry(&self.forward, |map| map.get(&left).copied()).flatten()
    }

    /// 通过 reverse key 查找是否存在
    pub(crate) fn contains_reverse(&self, right: u64) -> bool {
        with_registry(&self.reverse, |map| map.contains_key(&right)).unwrap_or(false)
    }

    /// 删除 forward(left) 及对应的 reverse 条目，返回被删除的 right 值
    pub(crate) fn remove_by_forward(&self, left: u64) -> Option<u64> {
        let right = with_registry_mut(&self.forward, |map| map.remove(&left)).flatten();
        if let Some(r) = right {
            with_registry_mut(&self.reverse, |map| {
                map.remove(&r);
            });
        }
        right
    }
}

/// Extract a u64 address from a JSValue that is either a NativePointer or a numeric value.
///
/// Returns Ok(addr) on success, Err(js_exception) on failure (exception already thrown).
pub(crate) unsafe fn extract_pointer_address(
    ctx: *mut ffi::JSContext,
    arg: JSValue,
    func_name: &str,
) -> Result<u64, ffi::JSValue> {
    if let Some(a) = get_native_pointer_addr(ctx, arg) {
        return Ok(a);
    }
    if let Some(a) = arg.to_u64(ctx) {
        return Ok(a);
    }
    let msg = std::ffi::CString::new(format!("{}() argument must be a pointer", func_name)).unwrap_or_default();
    Err(ffi::JS_ThrowTypeError(ctx, msg.as_ptr()))
}

/// Extract a string argument from JSValue.
pub(crate) unsafe fn extract_string_arg(
    ctx: *mut ffi::JSContext,
    arg: JSValue,
    error_msg: &[u8],
) -> Result<String, ffi::JSValue> {
    arg.to_string(ctx)
        .ok_or_else(|| ffi::JS_ThrowTypeError(ctx, error_msg.as_ptr() as *const _))
}

/// Ensure a JSValue is a function.
pub(crate) unsafe fn ensure_function_arg(
    ctx: *mut ffi::JSContext,
    arg: JSValue,
    error_msg: &[u8],
) -> Result<(), ffi::JSValue> {
    if arg.is_function(ctx) {
        Ok(())
    } else {
        Err(ffi::JS_ThrowTypeError(ctx, error_msg.as_ptr() as *const _))
    }
}

/// Throw a type error from a static byte string.
pub(crate) unsafe fn throw_type_error(ctx: *mut ffi::JSContext, error_msg: &[u8]) -> ffi::JSValue {
    // error_msg 是 &[u8] 常量短字符串（不超 256 字节），继续用内置路径
    ffi::JS_ThrowTypeError(ctx, error_msg.as_ptr() as *const _)
}

/// Throw an internal error from an owned Rust string.
///
/// 绕开 QuickJS `JS_ThrowInternalError` 内部 `char buf[256]` + vsnprintf 的双重坑:
///   1. 256 字节硬截断 (Java 异常 + cause 链容易超过)
///   2. 消息被当 printf 格式字符串 (含 % 会被误解析/崩溃)
///
/// 使用 `qjs_throw_error_with_message` 直接 `new InternalError(msg)` 走 JS 构造器路径，
/// 消息长度无限制，`%` 原样保留。
pub(crate) unsafe fn throw_internal_error(ctx: *mut ffi::JSContext, message: impl AsRef<str>) -> ffi::JSValue {
    let msg = message.as_ref();
    let bytes = msg.as_bytes();
    let class_name = b"InternalError\0";
    ffi::qjs_throw_error_with_message(
        ctx,
        class_name.as_ptr() as *const std::os::raw::c_char,
        bytes.as_ptr() as *const std::os::raw::c_char,
        bytes.len(),
    )
}

/// Set a u64 property on a JS object as BigUint64.
/// 封装 CString → JS_NewAtom → JS_NewBigUint64 → qjs_set_property → JS_FreeAtom 模式。
pub(crate) unsafe fn set_js_u64_property(ctx: *mut ffi::JSContext, obj: ffi::JSValue, name: &str, value: u64) {
    let cname = std::ffi::CString::new(name).unwrap();
    let atom = ffi::JS_NewAtom(ctx, cname.as_ptr());
    let val = ffi::JS_NewBigUint64(ctx, value);
    ffi::qjs_set_property(ctx, obj, atom, val);
    ffi::JS_FreeAtom(ctx, atom);
}

/// Set a CFunction property on a JS object.
pub(crate) unsafe fn set_js_cfunction_property(
    ctx: *mut ffi::JSContext,
    obj: ffi::JSValue,
    name: &str,
    func: JSCFn,
    argc: i32,
) {
    let cname = CString::new(name).unwrap();
    let func_val = ffi::qjs_new_cfunction(ctx, Some(func), cname.as_ptr(), argc);
    JSValue(obj).set_property(ctx, name, JSValue(func_val));
}

/// Read a u64-like property from a JS object. Non-numeric values fall back to 0.
pub(crate) unsafe fn get_js_u64_property(ctx: *mut ffi::JSContext, obj: ffi::JSValue, name: &str) -> u64 {
    let prop = JSValue(obj).get_property(ctx, name);
    let value = prop.to_u64(ctx).unwrap_or(0);
    prop.free(ctx);
    value
}

/// Convert a JS numeric/BigInt value to u64, defaulting to 0 on conversion failure.
pub(crate) unsafe fn js_value_to_u64_or_zero(ctx: *mut ffi::JSContext, value: JSValue) -> u64 {
    value.to_u64(ctx).unwrap_or(0)
}

/// Encode a u64 as Number when it fits JS safe integer range, otherwise BigUint64.
pub(crate) unsafe fn js_u64_to_js_number_or_bigint(ctx: *mut ffi::JSContext, value: u64) -> ffi::JSValue {
    if value <= JS_MAX_SAFE_INTEGER {
        ffi::qjs_new_int64(ctx, value as i64)
    } else {
        ffi::JS_NewBigUint64(ctx, value)
    }
}

/// Encode an i64 as Number when it fits JS safe integer range, otherwise BigInt64.
pub(crate) unsafe fn js_i64_to_js_number_or_bigint(ctx: *mut ffi::JSContext, value: i64) -> ffi::JSValue {
    if value.unsigned_abs() <= JS_MAX_SAFE_INTEGER {
        ffi::qjs_new_int64(ctx, value)
    } else {
        ffi::JS_NewBigInt64(ctx, value)
    }
}

/// Duplicate a JS callback value and return its raw bytes for Send/Sync-safe storage.
///
/// The caller is responsible for eventually freeing the duplicated value via qjs_free_value.
pub(crate) unsafe fn dup_callback_to_bytes(ctx: *mut ffi::JSContext, callback: ffi::JSValue) -> [u8; 16] {
    let callback_dup = ffi::qjs_dup_value(ctx, callback);
    let mut bytes = [0u8; 16];
    std::ptr::copy_nonoverlapping(
        &callback_dup as *const ffi::JSValue as *const u8,
        bytes.as_mut_ptr(),
        16,
    );
    bytes
}

/// 统一的 hook 回调骨架：获取 JS 锁 → 提取 callback → 构建上下文对象 → JS_Call → 异常处理 → 清理。
///
/// 将 native hook 和 Java hook 回调的公共流程提取为一个函数。
/// 调用方负责：锁 registry 复制数据、设置/清除 atomics。
///
/// - `ctx_raw`: QuickJS context 指针（usize）
/// - `callback_bytes`: 16 字节 JS callback value（由 dup_callback_to_bytes 生成）
/// - `context_name`: 日志标识（"hook" / "java hook"）
/// - `target_id`: 目标地址（用于日志）
/// - `build_context`: 闭包，构建传给 JS 回调的上下文对象（返回 JSValue）
/// - `handle_result`: 闭包，处理 JS 回调返回值（仅无异常时调用）；
///   参数为 (ctx, js_ctx_obj, call_result)，可同时访问上下文对象和调用结果
pub(crate) unsafe fn invoke_hook_callback_common(
    ctx_raw: usize,
    callback_bytes: &[u8; 16],
    context_name: &str,
    target_id: u64,
    build_context: impl FnOnce(*mut ffi::JSContext) -> ffi::JSValue,
    handle_result: impl FnOnce(*mut ffi::JSContext, ffi::JSValue, ffi::JSValue),
) {
    let ctx = ctx_raw as *mut ffi::JSContext;

    // 获取 JS 引擎锁（try_lock 避免死锁）
    let _js_guard = match acquire_js_engine_for_callback(ctx, context_name, target_id) {
        Some(g) => g,
        None => return,
    };

    // 从 bytes 提取 JS callback value，dup 增加引用计数。
    // 回调执行期间 re-hook 可能替换并释放 registry 中的旧回调，
    // dup 确保 JS_Call 期间函数不会被释放（防止 UAF）。
    let callback: ffi::JSValue = std::ptr::read(callback_bytes.as_ptr() as *const ffi::JSValue);
    let callback_dup = ffi::qjs_dup_value(ctx, callback);

    // 构建 JS 上下文对象（hook 类型相关）
    let js_ctx = build_context(ctx);

    let global = ffi::JS_GetGlobalObject(ctx);
    let result = ffi::JS_Call(ctx, callback_dup, global, 1, &js_ctx as *const _ as *mut _);

    // 异常检查 — 无异常时才处理返回值
    if !handle_js_exception(ctx, result, context_name) {
        handle_result(ctx, js_ctx, result);
    }

    // 清理 JS 值
    ffi::qjs_free_value(ctx, js_ctx);
    ffi::qjs_free_value(ctx, result);
    ffi::qjs_free_value(ctx, global);
    ffi::qjs_free_value(ctx, callback_dup);
}
