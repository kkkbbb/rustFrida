//! Hook callback wrapper (cross-thread safety, context building) — replace mode
//!
//! The thunk saves context and calls on_enter, then restores x0 and returns.
//! The callback can optionally call the original function via orig().

use crate::ffi;
use crate::ffi::hook as hook_ffi;
use crate::jsapi::callback_util::{
    get_js_u64_property, invoke_hook_callback_common, js_u64_to_js_number_or_bigint, js_value_to_u64_or_zero,
    set_js_cfunction_property, set_js_u64_property,
};
use std::sync::{Condvar, Mutex};

use super::registry::HOOK_REGISTRY;

#[derive(Clone, Copy)]
struct NativeHookFrame {
    ctx_ptr: usize,
    trampoline: u64,
    orig_called: bool,
}

// JS 回调在全局引擎锁下串行执行，因此用一个栈保存 native hook 回调状态即可支持嵌套 hook。
static NATIVE_HOOK_STACK: Mutex<Vec<NativeHookFrame>> = Mutex::new(Vec::new());
static IN_FLIGHT_NATIVE_HOOK_CALLBACKS: Mutex<usize> = Mutex::new(0);
static IN_FLIGHT_NATIVE_HOOK_CALLBACKS_CV: Condvar = Condvar::new();

struct InFlightNativeHookGuard;

impl InFlightNativeHookGuard {
    fn enter() -> Self {
        let mut in_flight = IN_FLIGHT_NATIVE_HOOK_CALLBACKS
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *in_flight += 1;
        Self
    }
}

impl Drop for InFlightNativeHookGuard {
    fn drop(&mut self) {
        let mut in_flight = IN_FLIGHT_NATIVE_HOOK_CALLBACKS
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *in_flight = in_flight.saturating_sub(1);
        if *in_flight == 0 {
            IN_FLIGHT_NATIVE_HOOK_CALLBACKS_CV.notify_all();
        }
    }
}

fn push_native_hook_frame(ctx_ptr: *mut hook_ffi::HookContext, trampoline: u64) {
    let mut stack = NATIVE_HOOK_STACK.lock().unwrap_or_else(|e| e.into_inner());
    stack.push(NativeHookFrame {
        ctx_ptr: ctx_ptr as usize,
        trampoline,
        orig_called: false,
    });
}

fn pop_native_hook_frame(ctx_ptr: *mut hook_ffi::HookContext, trampoline: u64) -> bool {
    let mut stack = NATIVE_HOOK_STACK.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(frame) = stack.pop() {
        debug_assert_eq!(frame.ctx_ptr, ctx_ptr as usize);
        debug_assert_eq!(frame.trampoline, trampoline);
        frame.orig_called
    } else {
        false
    }
}

fn mark_native_hook_frame_orig_called(ctx_ptr: *mut hook_ffi::HookContext, trampoline: u64) -> bool {
    let mut stack = NATIVE_HOOK_STACK.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(frame) = stack
        .iter_mut()
        .rfind(|frame| frame.ctx_ptr == ctx_ptr as usize && frame.trampoline == trampoline)
    {
        frame.orig_called = true;
        true
    } else {
        false
    }
}

fn current_native_hook_frame() -> Option<(*mut hook_ffi::HookContext, u64)> {
    let stack = NATIVE_HOOK_STACK.lock().unwrap_or_else(|e| e.into_inner());
    stack
        .last()
        .map(|frame| (frame.ctx_ptr as *mut hook_ffi::HookContext, frame.trampoline))
}

pub(crate) fn wait_for_in_flight_native_hook_callbacks(timeout: std::time::Duration) -> bool {
    let start = std::time::Instant::now();
    let mut in_flight = IN_FLIGHT_NATIVE_HOOK_CALLBACKS
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    while *in_flight != 0 {
        let Some(remaining) = timeout.checked_sub(start.elapsed()) else {
            return false;
        };
        let (guard, wait_result) = IN_FLIGHT_NATIVE_HOOK_CALLBACKS_CV
            .wait_timeout(in_flight, remaining)
            .unwrap_or_else(|e| e.into_inner());
        in_flight = guard;
        if wait_result.timed_out() && *in_flight != 0 {
            return false;
        }
    }
    true
}

pub(super) fn in_flight_native_hook_callbacks() -> usize {
    *IN_FLIGHT_NATIVE_HOOK_CALLBACKS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

/// Hook callback that calls the JS function (replace mode)
pub(crate) unsafe extern "C" fn hook_callback_wrapper(
    ctx_ptr: *mut hook_ffi::HookContext,
    user_data: *mut std::ffi::c_void,
) {
    if ctx_ptr.is_null() || user_data.is_null() {
        return;
    }
    let _in_flight_guard = InFlightNativeHookGuard::enter();

    let target_addr = user_data as u64;

    // Copy callback data then release the lock before QuickJS operations.
    let (ctx_usize, callback_bytes, trampoline) = {
        let guard = match HOOK_REGISTRY.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        let registry = match guard.as_ref() {
            Some(r) => r,
            None => return,
        };
        let hook_data = match registry.get(&target_addr) {
            Some(d) => d,
            None => return,
        };
        (hook_data.ctx, hook_data.callback_bytes, hook_data.trampoline)
    }; // HOOK_REGISTRY lock released here

    push_native_hook_frame(ctx_ptr, trampoline);

    // Track whether the JS callback completed without exception and wrote back x0.
    let mut result_was_set = false;

    invoke_hook_callback_common(
        ctx_usize,
        &callback_bytes,
        "hook",
        target_addr,
        // 构建 JS 上下文对象：x0-x30, sp, pc, trampoline, orig()
        |ctx| {
            let js_ctx = ffi::JS_NewObject(ctx);
            let hook_ctx = &*ctx_ptr;

            for i in 0..31 {
                let prop_name = format!("x{}", i);
                set_js_u64_property(ctx, js_ctx, &prop_name, hook_ctx.x[i]);
            }
            set_js_u64_property(ctx, js_ctx, "sp", hook_ctx.sp);
            set_js_u64_property(ctx, js_ctx, "pc", hook_ctx.pc);
            set_js_u64_property(ctx, js_ctx, "trampoline", trampoline);
            // Bind callback-local state to the context object so ctx.orig() remains stable
            // even if nested hooks temporarily overwrite the global fallback state.
            set_js_u64_property(ctx, js_ctx, "__hookCtxPtr", ctx_ptr as usize as u64);
            set_js_u64_property(ctx, js_ctx, "__hookTrampoline", trampoline);
            set_js_cfunction_property(ctx, js_ctx, "orig", js_native_call_original, 0);

            js_ctx
        },
        // 处理返回值：
        // 1. 先同步 JS ctx 上所有被修改的寄存器到 C HookContext
        // 2. 显式 return 值 → 覆盖 x0
        // 3. 不 return（undefined）→ 保持 ctx.x0 的值（可能被 JS 修改或被 orig() 写入）
        |ctx, js_ctx, result| {
            result_was_set = true;
            // 同步 JS ctx 属性 → C HookContext（用户可能修改了 ctx.x0 等）
            for i in 0..31u32 {
                let prop_name = format!("x{}", i);
                (*ctx_ptr).x[i as usize] = get_js_u64_property(ctx, js_ctx, &prop_name);
            }
            // 显式 return 值覆盖 x0
            let result_val = ffi::JSValue {
                u: result.u,
                tag: result.tag,
            };
            if ffi::qjs_is_undefined(result_val) == 0 {
                (*ctx_ptr).x[0] = js_value_to_u64_or_zero(ctx, crate::value::JSValue(result_val));
            }
            // undefined 时保持 ctx.x0 (可能是 orig() 写入的返回值或 JS 修改的值)
        },
    );

    let orig_called = pop_native_hook_frame(ctx_ptr, trampoline);

    // Fallback: if the JS callback was skipped (engine busy) or threw an exception,
    // treat the hook as transparent and invoke the original function.
    if !result_was_set && trampoline != 0 && !orig_called {
        (*ctx_ptr).x[0] = hook_ffi::hook_invoke_trampoline(ctx_ptr, trampoline as *mut std::ffi::c_void);
    }
}

/// JS CFunction: ctx.orig(...args?)
///
/// 无参数: 先同步 JS ctx 对象上被修改的寄存器到 C HookContext，再调用 trampoline。
/// 有参数: 用传入的参数覆盖 x0-xN（最多 6 个），其余寄存器同步自 JS ctx。
///
/// 返回原函数的返回值 (BigUint64 或 Number)，同时写入 ctx.x[0]。
unsafe extern "C" fn js_native_call_original(
    ctx: *mut ffi::JSContext,
    this_val: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let ctx_ptr = {
        let value = get_js_u64_property(ctx, this_val, "__hookCtxPtr") as *mut hook_ffi::HookContext;
        if !value.is_null() {
            value
        } else {
            current_native_hook_frame()
                .map(|(ctx_ptr, _)| ctx_ptr)
                .unwrap_or(std::ptr::null_mut())
        }
    };
    let trampoline = {
        let value = get_js_u64_property(ctx, this_val, "__hookTrampoline");
        if value != 0 {
            value
        } else {
            current_native_hook_frame()
                .map(|(_, trampoline)| trampoline)
                .unwrap_or(0)
        }
    };

    if ctx_ptr.is_null() || trampoline == 0 {
        return ffi::JS_ThrowInternalError(
            ctx,
            b"orig() can only be called inside a hook callback\0".as_ptr() as *const _,
        );
    }

    // 同步 JS ctx 属性到 C HookContext（用户可能修改了 ctx.x0 等）
    let hook_ctx = &mut *ctx_ptr;
    for i in 0..31 {
        let prop_name = format!("x{}", i);
        hook_ctx.x[i] = get_js_u64_property(ctx, this_val, &prop_name);
    }
    hook_ctx.sp = get_js_u64_property(ctx, this_val, "sp");

    // 如果 orig() 传了参数，按顺序覆盖 x0-xN (最多 x0-x30)
    let max_args = (argc as usize).min(31);
    for i in 0..max_args {
        let val = crate::value::JSValue(*argv.add(i));
        hook_ctx.x[i] = js_value_to_u64_or_zero(ctx, val);
    }

    let _ = mark_native_hook_frame_orig_called(ctx_ptr, trampoline);
    let result = hook_ffi::hook_invoke_trampoline(ctx_ptr, trampoline as *mut std::ffi::c_void);

    // Write result back to HookContext.x[0] so the thunk's final RET returns this value
    (*ctx_ptr).x[0] = result;

    // 同步返回值到 JS ctx.x0 属性，使 ctx.orig() 后读 ctx.x0 能拿到返回值
    set_js_u64_property(ctx, this_val, "x0", result);

    // Return value: Number (≤2^53) or BigUint64
    js_u64_to_js_number_or_bigint(ctx, result)
}
