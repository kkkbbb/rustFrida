//! Java.use() API — Frida-style Java method hooking
//!
//! 统一 Clone+Replace 策略:
//! 所有方法统一走 clone → replacement → artController 三层拦截矩阵。
//! 编译方法额外安装 per-method 路由 hook (Layer 3)。
//!
//! On ARM64 Android, jmethodID == ArtMethod*. All methods use a replacement
//! ArtMethod (native, jniCode=thunk) routed through the three-layer interception
//! matrix. All callbacks use unified JNI calling convention.
//!
//! ## JS API
//!
//! ```javascript
//! var Activity = Java.use("android.app.Activity");
//! Activity.onResume.impl = function(ctx) { console.log("hit"); };
//! Activity.onResume.impl = null; // unhook
//! // For overloaded methods:
//! Activity.foo.overload("(II)V").impl = function(ctx) { ... };
//! ```

/// Transmute a JNI function pointer from the function table by index.
macro_rules! jni_fn {
    ($env:expr, $ty:ty, $idx:expr) => {
        std::mem::transmute::<*const std::ffi::c_void, $ty>($crate::jsapi::java::jni_core::jni_fn_ptr($env, $idx))
    };
}

/// ARM64 PAC/TBI 位剥离掩码 — 保留 48-bit 规范虚拟地址
/// MTE 设备上 bit 48-55 可能非零，必须用 48-bit 而非 56-bit 掩码
pub(crate) const PAC_STRIP_MASK: u64 = 0x0000_FFFF_FFFF_FFFF;

mod art_class;
pub mod art_controller;
mod art_method;
mod art_thread;
pub(crate) mod callback;
#[allow(dead_code)]
mod heap_scan;
mod java_array_api;
mod java_choose_api;
pub(crate) mod java_fast_api;
mod java_field_api;
pub(crate) mod java_hook_api;
mod java_inspect_api;
mod java_method_list_api;
pub(crate) mod jni_core;
mod jvmti;
pub(crate) mod reflect;

mod safe_mem;

pub use java_hook_api::managed_native_counter_value;
pub(crate) use jni_core::ensure_jni_initialized;
pub(crate) use reflect::get_class_name_unchecked;

pub fn detach_current_jni_thread() {
    jni_core::detach_current_thread_if_owned();
}

pub fn start_java_worker_thread(native_loop: *mut std::ffi::c_void) -> Result<(), String> {
    if crate::is_raw_clone_js_thread() {
        unsafe { callback::start_java_worker_thread_via_executor(native_loop) }
    } else {
        unsafe { java_hook_api::start_java_worker_thread(native_loop) }
    }
}

pub unsafe fn finish_java_worker_thread_from_native(
    env: *mut *const *const std::ffi::c_void,
    worker_cls: *mut std::ffi::c_void,
) -> Result<(), String> {
    java_hook_api::finish_java_worker_thread_from_native(env, worker_cls)
}

pub(crate) unsafe fn decode_jobject_raw(env: jni_core::JniEnv, obj: *mut std::ffi::c_void) -> Option<u64> {
    art_class::decode_jobject(env, obj)
}

pub(crate) unsafe fn decode_global_jobject_raw(env: jni_core::JniEnv, obj: *mut std::ffi::c_void) -> Option<u64> {
    art_class::decode_global_jobject(env, obj)
}

use crate::context::JSContext;
use crate::ffi;
use crate::ffi::hook as hook_ffi;
use crate::jsapi::callback_util::{set_js_u64_property, throw_internal_error, throw_type_error};
use crate::jsapi::console::output_verbose;
use crate::jsapi::util::add_cfunction_to_object;
use crate::value::JSValue;

use crate::jsapi::hook_api::StealthMode;
use art_controller::{art_controller_initialized, set_stealth_mode, stealth_mode};
use art_method::{resolve_art_method, try_invalidate_jit_cache};
use callback::*;
use java_choose_api::*;
use java_fast_api::*;
use java_field_api::*;
use java_hook_api::*;
use java_inspect_api::*;
use java_method_list_api::*;
use jni_core::*;
use reflect::*;

// DecodeJObject 前置验证在 hook 回调拿到的 indirect JNI ref 上会误判失败。
// 这批 JNI 包装函数统一不做前置验证——JNI 自身能安全处理无效引用
// （返回 null 或抛异常），调用后 jni_check_exc 清一下异常兜底。

pub(crate) unsafe fn try_read_jstring(env_ptr: u64, obj_ptr: u64) -> Option<String> {
    let env = env_ptr as JniEnv;
    let obj = obj_ptr as *mut std::ffi::c_void;
    if env.is_null() || obj.is_null() {
        return None;
    }

    let new_local_ref: NewLocalRefFn = jni_fn!(env, NewLocalRefFn, JNI_NEW_LOCAL_REF);
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
    let is_instance_of: IsInstanceOfFn = jni_fn!(env, IsInstanceOfFn, JNI_IS_INSTANCE_OF);
    let get_str: GetStringUtfCharsFn = jni_fn!(env, GetStringUtfCharsFn, JNI_GET_STRING_UTF_CHARS);
    let rel_str: ReleaseStringUtfCharsFn = jni_fn!(env, ReleaseStringUtfCharsFn, JNI_RELEASE_STRING_UTF_CHARS);

    let local_obj = new_local_ref(env, obj);
    if jni_null_or_exc(env, local_obj) {
        return None;
    }

    let mut chars: *const std::os::raw::c_char = std::ptr::null();
    let result = (|| {
        if let Some(reflect) = REFLECT_IDS.get() {
            if !reflect.string_class.is_null() {
                let is_string = is_instance_of(env, local_obj, reflect.string_class) != 0;
                let had_exc = jni_check_exc(env);
                if !is_string || had_exc {
                    return None;
                }
            }
        }

        chars = get_str(env, local_obj, std::ptr::null_mut());
        if chars.is_null() {
            jni_check_exc(env);
            return None;
        }

        Some(std::ffi::CStr::from_ptr(chars).to_string_lossy().into_owned())
    })();

    if !chars.is_null() {
        rel_str(env, local_obj, chars);
    }
    delete_local_ref(env, local_obj);
    result
}

pub(crate) unsafe fn try_get_class_name(env_ptr: u64, cls_ptr: u64) -> Option<String> {
    let env = env_ptr as JniEnv;
    if env.is_null() || cls_ptr == 0 {
        return None;
    }

    // 直接尝试 JNI 调用 Class.getName()，不做 DecodeJObject 前置验证。
    // 前置验证对 indirect JNI reference (如 hook 回调中的 jclass) 可能误判失败。
    // JNI 自身能安全处理无效引用（返回 null 或抛异常）。
    let result = crate::jsapi::java::get_class_name_unchecked(env_ptr, cls_ptr);
    // 清除 JNI 调用可能产生的异常
    if result.is_none() {
        jni_check_exc(env);
    }
    result
}

pub(crate) unsafe fn try_get_object_class(env_ptr: u64, obj_ptr: u64) -> Option<u64> {
    let env = env_ptr as JniEnv;
    let obj = obj_ptr as *mut std::ffi::c_void;
    if env.is_null() || obj.is_null() {
        return None;
    }

    let get_object_class: GetObjectClassFn = jni_fn!(env, GetObjectClassFn, JNI_GET_OBJECT_CLASS);
    let cls = get_object_class(env, obj);
    // 注意: 用 let 提前 eager 求值 jni_check_exc，防止 `|| ` 短路漏清待定异常
    let exc = jni_check_exc(env);
    if cls.is_null() || exc {
        None
    } else {
        Some(cls as u64)
    }
}

pub(crate) unsafe fn try_get_superclass(env_ptr: u64, cls_ptr: u64) -> Option<u64> {
    let env = env_ptr as JniEnv;
    let cls = cls_ptr as *mut std::ffi::c_void;
    if env.is_null() || cls.is_null() {
        return None;
    }

    let get_superclass: GetSuperclassFn = jni_fn!(env, GetSuperclassFn, JNI_GET_SUPERCLASS);
    let super_cls = get_superclass(env, cls);
    let exc = jni_check_exc(env);
    if super_cls.is_null() || exc {
        // Object / interface 的 superclass 就是 null，不是错误；清异常兜底
        None
    } else {
        Some(super_cls as u64)
    }
}

pub(crate) unsafe fn try_is_same_object(env_ptr: u64, a_ptr: u64, b_ptr: u64) -> bool {
    let env = env_ptr as JniEnv;
    let a = a_ptr as *mut std::ffi::c_void;
    let b = b_ptr as *mut std::ffi::c_void;
    if env.is_null() {
        return false;
    }

    let is_same_object: IsSameObjectFn = jni_fn!(env, IsSameObjectFn, JNI_IS_SAME_OBJECT);
    let same = is_same_object(env, a, b) != 0;
    let had_exc = jni_check_exc(env);
    same && !had_exc
}

pub(crate) unsafe fn try_is_instance_of(env_ptr: u64, obj_ptr: u64, cls_ptr: u64) -> bool {
    let env = env_ptr as JniEnv;
    let obj = obj_ptr as *mut std::ffi::c_void;
    let cls = cls_ptr as *mut std::ffi::c_void;
    if env.is_null() || obj.is_null() || cls.is_null() {
        return false;
    }

    let is_instance_of: IsInstanceOfFn = jni_fn!(env, IsInstanceOfFn, JNI_IS_INSTANCE_OF);
    let is_instance = is_instance_of(env, obj, cls) != 0;
    let had_exc = jni_check_exc(env);
    is_instance && !had_exc
}

pub(crate) unsafe fn try_get_object_class_name(env_ptr: u64, obj_ptr: u64) -> Option<String> {
    let env = env_ptr as JniEnv;
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);

    let cls = try_get_object_class(env_ptr, obj_ptr)? as *mut std::ffi::c_void;
    let name = try_get_class_name(env_ptr, cls as u64);
    delete_local_ref(env, cls);
    name
}

pub(crate) unsafe fn try_exception_check(env_ptr: u64) -> bool {
    let env = env_ptr as JniEnv;
    if env.is_null() {
        return false;
    }
    let check: ExcCheckFn = jni_fn!(env, ExcCheckFn, JNI_EXCEPTION_CHECK);
    check(env) != 0
}

pub(crate) unsafe fn try_exception_clear(env_ptr: u64) {
    let env = env_ptr as JniEnv;
    if env.is_null() {
        return;
    }
    let clear: ExcClearFn = jni_fn!(env, ExcClearFn, JNI_EXCEPTION_CLEAR);
    clear(env);
}

pub(crate) unsafe fn try_exception_occurred(env_ptr: u64) -> Option<u64> {
    let env = env_ptr as JniEnv;
    if env.is_null() {
        return None;
    }
    let occurred: ExcOccurredFn = jni_fn!(env, ExcOccurredFn, JNI_EXCEPTION_OCCURRED);
    let exc = occurred(env);
    if exc.is_null() {
        None
    } else {
        Some(exc as u64)
    }
}

pub(crate) unsafe fn try_new_string_utf(env_ptr: u64, s: &str) -> Option<u64> {
    let env = env_ptr as JniEnv;
    if env.is_null() {
        return None;
    }
    let cstr = match std::ffi::CString::new(s) {
        Ok(c) => c,
        Err(_) => return None, // 嵌入 NUL 字节非法
    };
    let new_string_utf: NewStringUtfFn = jni_fn!(env, NewStringUtfFn, JNI_NEW_STRING_UTF);
    let jstr = new_string_utf(env, cstr.as_ptr());
    let exc = jni_check_exc(env);
    if jstr.is_null() || exc {
        None
    } else {
        Some(jstr as u64)
    }
}

pub(crate) unsafe fn try_new_local_ref(env_ptr: u64, obj_ptr: u64) -> Option<u64> {
    let env = env_ptr as JniEnv;
    let obj = obj_ptr as *mut std::ffi::c_void;
    if env.is_null() || obj.is_null() {
        return None;
    }
    let new_local_ref: NewLocalRefFn = jni_fn!(env, NewLocalRefFn, JNI_NEW_LOCAL_REF);
    let local = new_local_ref(env, obj);
    let exc = jni_check_exc(env);
    if local.is_null() || exc {
        None
    } else {
        Some(local as u64)
    }
}

pub(crate) unsafe fn try_delete_local_ref(env_ptr: u64, obj_ptr: u64) {
    let env = env_ptr as JniEnv;
    let obj = obj_ptr as *mut std::ffi::c_void;
    if env.is_null() || obj.is_null() {
        return;
    }
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
    delete_local_ref(env, obj);
}

pub(crate) unsafe fn try_find_class(env_ptr: u64, name: &str) -> Option<u64> {
    let env = env_ptr as JniEnv;
    if env.is_null() {
        return None;
    }
    let cls = reflect::find_class_safe(env, name);
    if cls.is_null() {
        None
    } else {
        Some(cls as u64)
    }
}

/// JS CFunction: Java.deopt() — 清空 JIT 缓存 (InvalidateAllMethods)
/// 返回 true/false 表示操作是否成功
unsafe extern "C" fn js_java_deopt(
    _ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    output_verbose("[java deopt] 清空 JIT 缓存...");
    try_invalidate_jit_cache();
    output_verbose("[java deopt] JIT 缓存清空完成");
    JSValue::bool(true).raw()
}

/// JS CFunction: Java.deoptimizeBootImage() — 对标 Frida Java.deoptimizeBootImage()
/// Boot image AOT 方法降级为 interpreter (API >= 26)
unsafe extern "C" fn js_java_deoptimize_boot_image(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    match art_controller::deoptimize_boot_image() {
        Ok(()) => JSValue::bool(true).raw(),
        Err(e) => {
            let msg = std::ffi::CString::new(e).unwrap_or_default();
            ffi::JS_ThrowInternalError(ctx, msg.as_ptr())
        }
    }
}

/// JS CFunction: Java.deoptimizeEverything() — 对标 Frida Java.deoptimizeEverything()
/// 全局强制解释执行
unsafe extern "C" fn js_java_deoptimize_everything(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    match art_controller::deoptimize_everything() {
        Ok(()) => JSValue::bool(true).raw(),
        Err(e) => {
            let msg = std::ffi::CString::new(e).unwrap_or_default();
            ffi::JS_ThrowInternalError(ctx, msg.as_ptr())
        }
    }
}

/// JS CFunction: Java.deoptimizeMethod(class, method, sig) — 对标 Frida Java.deoptimizeMethod()
/// 单个方法降级为 interpreter
unsafe extern "C" fn js_java_deoptimize_method(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 3 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"deoptimizeMethod(class, method, sig) requires 3 arguments\0".as_ptr() as *const _,
        );
    }

    let class_name =
        match crate::jsapi::callback_util::extract_string_arg(ctx, JSValue(*argv), b"class must be a string\0") {
            Ok(v) => v,
            Err(e) => return e,
        };
    let method_name =
        match crate::jsapi::callback_util::extract_string_arg(ctx, JSValue(*argv.add(1)), b"method must be a string\0")
        {
            Ok(v) => v,
            Err(e) => return e,
        };
    let sig =
        match crate::jsapi::callback_util::extract_string_arg(ctx, JSValue(*argv.add(2)), b"sig must be a string\0") {
            Ok(v) => v,
            Err(e) => return e,
        };
    let (actual_sig, force_static) = if let Some(stripped) = sig.strip_prefix("static:") {
        (stripped.to_string(), true)
    } else {
        (sig, false)
    };

    if crate::is_raw_clone_js_thread() {
        return match callback::deoptimize_method_via_executor(class_name, method_name, actual_sig, force_static) {
            Ok(()) => JSValue::bool(true).raw(),
            Err(msg) => crate::jsapi::callback_util::throw_internal_error(ctx, msg),
        };
    }

    let env = match ensure_jni_initialized() {
        Ok(e) => e,
        Err(msg) => return crate::jsapi::callback_util::throw_internal_error(ctx, msg),
    };

    let (art_method, _is_static) = match resolve_art_method(env, &class_name, &method_name, &actual_sig, force_static) {
        Ok(r) => r,
        Err(msg) => return crate::jsapi::callback_util::throw_internal_error(ctx, msg),
    };

    match art_controller::deoptimize_method(art_method) {
        Ok(()) => JSValue::bool(true).raw(),
        Err(e) => {
            let msg = std::ffi::CString::new(e).unwrap_or_default();
            ffi::JS_ThrowInternalError(ctx, msg.as_ptr())
        }
    }
}

/// JS CFunction: Java._artRouterDebug() — dump ART router not_found capture
/// Shows the last X0 (ArtMethod*) seen in the thunk's not_found path and the
/// total miss count. Also reads back entry_point of all hooked methods to check
/// if our writes persisted.
unsafe extern "C" fn js_art_router_debug(
    _ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let mut last_x0: u64 = 0;
    let mut miss_count: u64 = 0;
    hook_ffi::hook_art_router_get_debug(&mut last_x0, &mut miss_count);
    output_verbose(&format!(
        "[art_router_debug] last_x0={:#x}, miss_count={}",
        last_x0, miss_count
    ));

    // Also dump the table for reference
    hook_ffi::hook_art_router_table_dump();

    // Read back entry_point of all hooked methods to check persistence
    {
        let guard = JAVA_HOOK_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(ref registry) = *guard {
            for (art_method, data) in registry.iter() {
                if let Some(spec) = ART_METHOD_SPEC.get() {
                    let current_ep =
                        std::ptr::read_volatile((*art_method as usize + spec.entry_point_offset) as *const u64);
                    let current_flags =
                        std::ptr::read_volatile((*art_method as usize + spec.access_flags_offset) as *const u32);
                    output_verbose(&format!(
                        "[art_router_debug] ArtMethod={:#x}: current_ep={:#x} (original={:#x}), flags={:#x} (original={:#x})",
                        art_method, current_ep, data.original_entry_point,
                        current_flags, data.original_access_flags
                    ));
                }
            }
        }
    }

    // Reset counters for next check
    hook_ffi::hook_art_router_reset_debug();
    JSValue::bool(true).raw()
}

unsafe extern "C" fn js_art_route_stats(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let mut miss_last_x0: u64 = 0;
    let mut miss_count: u64 = 0;
    let mut router_hits: u64 = 0;
    let mut router_last_x0: u64 = 0;
    let mut quick_hits: u64 = 0;
    let mut replacement_hits: u64 = 0;
    let mut do_call_table_hits: u64 = 0;
    let mut do_call_last_x0: u64 = 0;
    let mut do_call_raw_last_x0: u64 = 0;
    let mut quick_pass_hits: u64 = 0;
    let mut quick_callback_calls: u64 = 0;
    let mut quick_skip_hits: u64 = 0;
    let mut quick_callee_save_frames: u64 = 0;
    let mut quick_callee_save_method: u64 = 0;
    let mut quick_top_quick_frame_offset: u64 = 0;
    let mut quick_test_suspend_calls: u64 = 0;
    let mut quick_test_suspend_entrypoint: u64 = 0;

    hook_ffi::hook_art_router_get_debug(&mut miss_last_x0, &mut miss_count);
    hook_ffi::hook_art_router_get_hit_debug(&mut router_hits, &mut router_last_x0);
    hook_ffi::hook_art_router_get_route_stats(
        &mut quick_hits,
        &mut replacement_hits,
        &mut do_call_table_hits,
        &mut do_call_last_x0,
        &mut do_call_raw_last_x0,
        &mut quick_pass_hits,
        &mut quick_callback_calls,
        &mut quick_skip_hits,
        &mut quick_callee_save_frames,
        &mut quick_callee_save_method,
        &mut quick_top_quick_frame_offset,
        &mut quick_test_suspend_calls,
        &mut quick_test_suspend_entrypoint,
    );

    let obj = ffi::JS_NewObject(ctx);
    let obj_val = JSValue(obj);
    obj_val.set_property(ctx, "routerHits", JSValue(ffi::JS_NewBigUint64(ctx, router_hits)));
    obj_val.set_property(ctx, "routerQuickHits", JSValue(ffi::JS_NewBigUint64(ctx, quick_hits)));
    obj_val.set_property(
        ctx,
        "routerQuickPassHits",
        JSValue(ffi::JS_NewBigUint64(ctx, quick_pass_hits)),
    );
    obj_val.set_property(
        ctx,
        "routerQuickCallbackCalls",
        JSValue(ffi::JS_NewBigUint64(ctx, quick_callback_calls)),
    );
    obj_val.set_property(
        ctx,
        "routerQuickSkipHits",
        JSValue(ffi::JS_NewBigUint64(ctx, quick_skip_hits)),
    );
    obj_val.set_property(
        ctx,
        "routerQuickCalleeSaveFrames",
        JSValue(ffi::JS_NewBigUint64(ctx, quick_callee_save_frames)),
    );
    obj_val.set_property(
        ctx,
        "routerQuickCalleeSaveMethod",
        JSValue(ffi::JS_NewBigUint64(ctx, quick_callee_save_method)),
    );
    obj_val.set_property(
        ctx,
        "routerQuickTopQuickFrameOffset",
        JSValue(ffi::JS_NewBigUint64(ctx, quick_top_quick_frame_offset)),
    );
    obj_val.set_property(
        ctx,
        "routerQuickTestSuspendCalls",
        JSValue(ffi::JS_NewBigUint64(ctx, quick_test_suspend_calls)),
    );
    obj_val.set_property(
        ctx,
        "routerQuickTestSuspendEntrypoint",
        JSValue(ffi::JS_NewBigUint64(ctx, quick_test_suspend_entrypoint)),
    );
    obj_val.set_property(
        ctx,
        "routerReplacementHits",
        JSValue(ffi::JS_NewBigUint64(ctx, replacement_hits)),
    );
    obj_val.set_property(ctx, "routerLastX0", JSValue(ffi::JS_NewBigUint64(ctx, router_last_x0)));
    obj_val.set_property(ctx, "routerMisses", JSValue(ffi::JS_NewBigUint64(ctx, miss_count)));
    obj_val.set_property(
        ctx,
        "routerMissLastX0",
        JSValue(ffi::JS_NewBigUint64(ctx, miss_last_x0)),
    );
    obj_val.set_property(
        ctx,
        "doCallTotal",
        JSValue(ffi::JS_NewBigUint64(
            ctx,
            art_controller::DO_CALL_COUNT.load(std::sync::atomic::Ordering::Relaxed),
        )),
    );
    obj_val.set_property(
        ctx,
        "doCallReplacementHits",
        JSValue(ffi::JS_NewBigUint64(
            ctx,
            art_controller::DO_CALL_HIT_COUNT.load(std::sync::atomic::Ordering::Relaxed),
        )),
    );
    obj_val.set_property(
        ctx,
        "doCallQuickCallbackCalls",
        JSValue(ffi::JS_NewBigUint64(
            ctx,
            art_controller::DO_CALL_QUICK_CALLBACK_COUNT.load(std::sync::atomic::Ordering::Relaxed),
        )),
    );
    obj_val.set_property(
        ctx,
        "doCallRouterTableHits",
        JSValue(ffi::JS_NewBigUint64(ctx, do_call_table_hits)),
    );
    obj_val.set_property(
        ctx,
        "doCallRouterLastX0",
        JSValue(ffi::JS_NewBigUint64(ctx, do_call_last_x0)),
    );
    obj_val.set_property(
        ctx,
        "doCallRawLastX0",
        JSValue(ffi::JS_NewBigUint64(ctx, do_call_raw_last_x0)),
    );
    obj_val.set_property(
        ctx,
        "managedBackupStubHits",
        JSValue(ffi::JS_NewBigUint64(ctx, hook_ffi::hook_managed_backup_stub_hits())),
    );
    obj_val.set_property(
        ctx,
        "managedDirectHits",
        JSValue(ffi::JS_NewBigUint64(ctx, hook_ffi::hook_managed_direct_hits())),
    );
    obj_val.set_property(
        ctx,
        "managedReentryGuardEnabled",
        JSValue::bool(hook_ffi::hook_managed_reentry_guard_enabled() != 0),
    );
    obj_val.set_property(
        ctx,
        "managedReentryGuardDepth",
        JSValue(ffi::JS_NewBigUint64(
            ctx,
            hook_ffi::hook_managed_reentry_guard_depth() as u64,
        )),
    );
    obj_val.set_property(
        ctx,
        "managedReentryGuardEnters",
        JSValue(ffi::JS_NewBigUint64(ctx, hook_ffi::hook_managed_reentry_guard_enters())),
    );
    obj_val.set_property(
        ctx,
        "managedReentryGuardBypassHits",
        JSValue(ffi::JS_NewBigUint64(
            ctx,
            hook_ffi::hook_managed_reentry_guard_bypass_hits(),
        )),
    );
    obj_val.set_property(
        ctx,
        "origBypassHits",
        JSValue(ffi::JS_NewBigUint64(ctx, hook_ffi::hook_orig_bypass_hits())),
    );
    obj_val.set_property(
        ctx,
        "origBypassSetSuccesses",
        JSValue(ffi::JS_NewBigUint64(ctx, hook_ffi::hook_orig_bypass_set_successes())),
    );
    obj_val.set_property(
        ctx,
        "origBypassSetFailures",
        JSValue(ffi::JS_NewBigUint64(ctx, hook_ffi::hook_orig_bypass_set_failures())),
    );
    obj_val.set_property(
        ctx,
        "origBypassActive",
        JSValue(ffi::JS_NewBigUint64(ctx, hook_ffi::hook_orig_bypass_active_count())),
    );
    obj_val.set_property(
        ctx,
        "oatInlinePatchCount",
        JSValue(ffi::JS_NewBigUint64(ctx, hook_ffi::hook_oat_inline_patch_count())),
    );
    obj_val.set_property(
        ctx,
        "oatPcPoolBypassHits",
        JSValue(ffi::JS_NewBigUint64(ctx, hook_ffi::hook_oat_pc_pool_bypass_hits())),
    );
    obj_val.set_property(
        ctx,
        "oatReplacementBypassHits",
        JSValue(ffi::JS_NewBigUint64(ctx, hook_ffi::hook_oat_replacement_bypass_hits())),
    );
    obj_val.set_property(
        ctx,
        "getOatHookPoolOriginal",
        JSValue(ffi::JS_NewBigUint64(
            ctx,
            art_controller::GET_OAT_HOOK_POOL_ORIGINAL_COUNT.load(std::sync::atomic::Ordering::Relaxed),
        )),
    );
    obj_val.set_property(
        ctx,
        "getOatHookPoolReplacement",
        JSValue(ffi::JS_NewBigUint64(
            ctx,
            art_controller::GET_OAT_HOOK_POOL_REPLACEMENT_COUNT.load(std::sync::atomic::Ordering::Relaxed),
        )),
    );
    obj_val.set_property(
        ctx,
        "getOatHookPoolLastMethod",
        JSValue(ffi::JS_NewBigUint64(
            ctx,
            art_controller::GET_OAT_HOOK_POOL_LAST_METHOD.load(std::sync::atomic::Ordering::Relaxed),
        )),
    );
    obj_val.set_property(
        ctx,
        "getOatHookPoolLastPc",
        JSValue(ffi::JS_NewBigUint64(
            ctx,
            art_controller::GET_OAT_HOOK_POOL_LAST_PC.load(std::sync::atomic::Ordering::Relaxed),
        )),
    );
    obj
}

unsafe extern "C" fn js_reset_art_route_stats(
    _ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    hook_ffi::hook_art_router_reset_debug();
    art_controller::DO_CALL_COUNT.store(0, std::sync::atomic::Ordering::Relaxed);
    art_controller::DO_CALL_HIT_COUNT.store(0, std::sync::atomic::Ordering::Relaxed);
    art_controller::DO_CALL_QUICK_CALLBACK_COUNT.store(0, std::sync::atomic::Ordering::Relaxed);
    art_controller::GET_OAT_HOOK_POOL_ORIGINAL_COUNT.store(0, std::sync::atomic::Ordering::Relaxed);
    art_controller::GET_OAT_HOOK_POOL_REPLACEMENT_COUNT.store(0, std::sync::atomic::Ordering::Relaxed);
    art_controller::GET_OAT_HOOK_POOL_LAST_METHOD.store(0, std::sync::atomic::Ordering::Relaxed);
    art_controller::GET_OAT_HOOK_POOL_LAST_PC.store(0, std::sync::atomic::Ordering::Relaxed);
    JSValue::bool(true).raw()
}

unsafe extern "C" fn js_set_managed_reentry_guard(
    _ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let enabled = if argc >= 1 {
        JSValue(*argv).to_bool().unwrap_or(true)
    } else {
        true
    };
    hook_ffi::hook_set_managed_reentry_guard_enabled(enabled as i32);
    JSValue::bool(enabled).raw()
}

unsafe extern "C" fn js_managed_reentry_guard_stats(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let obj = ffi::JS_NewObject(ctx);
    let obj_val = JSValue(obj);
    obj_val.set_property(
        ctx,
        "enabled",
        JSValue::bool(hook_ffi::hook_managed_reentry_guard_enabled() != 0),
    );
    obj_val.set_property(
        ctx,
        "depth",
        JSValue(ffi::JS_NewBigUint64(
            ctx,
            hook_ffi::hook_managed_reentry_guard_depth() as u64,
        )),
    );
    obj_val.set_property(
        ctx,
        "enters",
        JSValue(ffi::JS_NewBigUint64(ctx, hook_ffi::hook_managed_reentry_guard_enters())),
    );
    obj_val.set_property(
        ctx,
        "bypassHits",
        JSValue(ffi::JS_NewBigUint64(
            ctx,
            hook_ffi::hook_managed_reentry_guard_bypass_hits(),
        )),
    );
    obj
}

/// JS CFunction: Java.setStealth(mode) — 设置 stealth 模式
///
/// mode: Hook.NORMAL (0) / false, Hook.WXSHADOW (1) / true, Hook.RECOMP (2)
/// 建议在首次 Java.hook() 之前调用，否则已安装的 Layer 1/2 hook 不受影响。
unsafe extern "C" fn js_java_set_stealth(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Java.setStealth() requires 1 argument: Hook.NORMAL/WXSHADOW/RECOMP or bool\0".as_ptr() as *const _,
        );
    }
    let arg = JSValue(*argv);
    // 向后兼容: true → WxShadow, false → Normal
    // 数字: 0=Normal, 1=WxShadow, 2=Recomp
    let mode = match arg.to_i64(ctx) {
        Some(v) => StealthMode::from_js_arg(v),
        None => {
            if arg.to_bool() == Some(true) {
                StealthMode::WxShadow
            } else {
                StealthMode::Normal
            }
        }
    };
    if art_controller_initialized() && mode != stealth_mode() {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Java.setStealth() must be called before ART hooks are installed; use host pre-stealth/script pre-scan so all install paths use one mode\0".as_ptr() as *const _,
        );
    }
    set_stealth_mode(mode);
    ffi::JS_NewBigUint64(ctx, mode as u64)
}

/// JS CFunction: Java.getStealth() — 查询当前 stealth 模式
unsafe extern "C" fn js_java_get_stealth(
    _ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    ffi::JS_NewBigUint64(_ctx, stealth_mode() as u64)
}

/// JS CFunction: Java._updateClassLoader(ptr) — 更新缓存的 app ClassLoader
/// 由 Java.ready() gate hook 在 Instrumentation.newApplication 回调中调用，
/// 传入 ClassLoader 的 jobject 指针。
unsafe extern "C" fn js_update_classloader(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if crate::is_raw_clone_js_thread() {
        return throw_internal_error(
            ctx,
            "Java._updateClassLoader is disabled on raw clone JS threads because it stores JNI references",
        );
    }
    if argc < 1 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Java._updateClassLoader() requires 1 argument: ClassLoader jobject ptr\0".as_ptr() as *const _,
        );
    }
    let arg = JSValue(*argv);
    let cl_ptr = match arg.to_u64(ctx) {
        Some(v) => v as *mut std::ffi::c_void,
        None => {
            return ffi::JS_ThrowTypeError(
                ctx,
                b"Java._updateClassLoader() argument must be a pointer (BigInt)\0".as_ptr() as *const _,
            )
        }
    };

    match ensure_jni_initialized() {
        Ok(env) => {
            let updated = update_app_classloader(env, cl_ptr);
            if updated {
                output_verbose("[java.ready] ClassLoader 已更新");
            } else {
                output_verbose("[java.ready] ClassLoader 更新失败");
            }
            JSValue::bool(updated).raw()
        }
        Err(_) => {
            output_verbose("[java.ready] 获取 JNIEnv 失败，ClassLoader 更新失败");
            JSValue::bool(false).raw()
        }
    }
}

/// JS CFunction: Java._isClassLoaderReady() — 检查 app ClassLoader 是否已就绪
unsafe extern "C" fn js_is_classloader_ready(
    _ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    JSValue::bool(is_classloader_ready()).raw()
}

/// JS CFunction: Java._isRawCloneJsThread() — 当前 JS 是否运行在 raw clone TLS worker。
unsafe extern "C" fn js_is_raw_clone_js_thread(
    _ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    JSValue::bool(crate::is_raw_clone_js_thread()).raw()
}

/// JS CFunction: Java._cutRawCloneExecutorHook() — pre-resume 失败路径切掉 executor hook。
unsafe extern "C" fn js_cut_raw_clone_executor_hook(
    _ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    JSValue::bool(callback::cut_raw_clone_executor_loop_hook()).raw()
}

/// JS CFunction: Java._reprobeClassLoader() — 主动重新探测 ClassLoader
unsafe extern "C" fn js_reprobe_classloader(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if crate::is_raw_clone_js_thread() {
        return callback::reprobe_classloader_via_executor(ctx, false);
    }
    JSValue::bool(reflect::reprobe_classloader()).raw()
}

/// JS CFunction: Java._reprobeClassLoaderOnce() — 单次轻量探测 ClassLoader。
unsafe extern "C" fn js_reprobe_classloader_once(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if crate::is_raw_clone_js_thread() {
        return callback::reprobe_classloader_via_executor(ctx, true);
    }
    JSValue::bool(reflect::reprobe_classloader_once()).raw()
}

unsafe fn js_loader_arg_to_ptr(ctx: *mut ffi::JSContext, arg: JSValue) -> u64 {
    if let Some(v) = arg.to_u64(ctx) {
        return v;
    }

    if arg.is_object() {
        let jptr = arg.get_property(ctx, "__jptr");
        let jptr_val = jptr.to_u64(ctx).unwrap_or(0);
        jptr.free(ctx);
        if jptr_val != 0 {
            return jptr_val;
        }

        let ptr_prop = arg.get_property(ctx, "ptr");
        let ptr_val = ptr_prop.to_u64(ctx).unwrap_or(0);
        ptr_prop.free(ctx);
        if ptr_val != 0 {
            return ptr_val;
        }
    }

    0
}

unsafe extern "C" fn js_java_classloaders(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if crate::is_raw_clone_js_thread() {
        return callback::classloaders_via_executor(ctx);
    }
    let env = match ensure_jni_initialized() {
        Ok(env) => env,
        Err(msg) => return throw_internal_error(ctx, msg),
    };

    let loaders = enumerate_classloaders(env);
    let arr = ffi::JS_NewArray(ctx);
    for (index, loader) in loaders.iter().enumerate() {
        let obj = ffi::JS_NewObject(ctx);
        set_js_u64_property(ctx, obj, "ptr", loader.ptr);
        JSValue(obj).set_property(ctx, "source", JSValue::string(ctx, &loader.source));
        JSValue(obj).set_property(ctx, "loaderClassName", JSValue::string(ctx, &loader.loader_class_name));
        JSValue(obj).set_property(ctx, "description", JSValue::string(ctx, &loader.description));
        ffi::JS_SetPropertyUint32(ctx, arr, index as u32, obj);
    }

    arr
}

unsafe extern "C" fn js_java_find_class_with_loader(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if crate::is_raw_clone_js_thread() {
        if argc < 2 {
            return throw_type_error(
                ctx,
                b"Java._findClassWithLoader() requires 2 arguments: loader, className\0",
            );
        }

        let loader_ptr = js_loader_arg_to_ptr(ctx, JSValue(*argv));
        if loader_ptr == 0 {
            return throw_type_error(
                ctx,
                b"Java._findClassWithLoader() loader must be a loader object or pointer\0",
            );
        }

        let class_name = match JSValue(*argv.add(1)).to_string(ctx) {
            Some(v) => v,
            None => return throw_type_error(ctx, b"Java._findClassWithLoader() className must be a string\0"),
        };

        return callback::find_class_with_loader_via_executor(ctx, loader_ptr, class_name);
    }
    if argc < 2 {
        return throw_type_error(
            ctx,
            b"Java._findClassWithLoader() requires 2 arguments: loader, className\0",
        );
    }

    let loader_ptr = js_loader_arg_to_ptr(ctx, JSValue(*argv));
    if loader_ptr == 0 {
        return throw_type_error(
            ctx,
            b"Java._findClassWithLoader() loader must be a loader object or pointer\0",
        );
    }

    let class_name = match JSValue(*argv.add(1)).to_string(ctx) {
        Some(v) => v,
        None => return throw_type_error(ctx, b"Java._findClassWithLoader() className must be a string\0"),
    };

    let env = match ensure_jni_initialized() {
        Ok(env) => env,
        Err(msg) => return throw_internal_error(ctx, msg),
    };

    let result = ffi::JS_NewObject(ctx);
    let via = find_class_with_loader(env, loader_ptr as *mut std::ffi::c_void, &class_name);
    JSValue(result).set_property(ctx, "ok", JSValue::bool(via.is_some()));
    JSValue(result).set_property(ctx, "className", JSValue::string(ctx, &class_name));
    set_js_u64_property(ctx, result, "loaderPtr", loader_ptr);
    if let Some(via) = via {
        JSValue(result).set_property(ctx, "via", JSValue::string(ctx, via));
    } else {
        JSValue(result).set_property(ctx, "via", JSValue::null());
    }
    result
}

/// Java._findClassObject(name) — 返回指定类名对应的 java.lang.Class 实例（JS wrapper）。
///
/// 与 Java.use 不同的是: 这里返回的是**真正的** java.lang.Class 对象 Proxy，
/// 可以作为参数传递给需要 Class<?> 的 Java 方法（等价于 Java 源码里的 Foo.class）。
///
/// 使用 find_class_safe 内部路径: 先尝试缓存的 app ClassLoader.loadClass，
/// fallback 到 JNI FindClass。对 app 私有类 / bundle 动态加载类都能命中，
/// 比 Class.forName(String) 的 caller-ClassLoader 单参版本更可靠。
unsafe extern "C" fn js_java_find_class_object(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if crate::is_raw_clone_js_thread() {
        if argc < 1 {
            return throw_type_error(ctx, b"Java._findClassObject() requires 1 argument: className\0");
        }
        let class_name = match JSValue(*argv).to_string(ctx) {
            Some(v) => v,
            None => return throw_type_error(ctx, b"Java._findClassObject() className must be a string\0"),
        };

        return callback::find_class_object_via_executor(ctx, class_name);
    }
    if argc < 1 {
        return throw_type_error(ctx, b"Java._findClassObject() requires 1 argument: className\0");
    }
    let class_name = match JSValue(*argv).to_string(ctx) {
        Some(v) => v,
        None => return throw_type_error(ctx, b"Java._findClassObject() className must be a string\0"),
    };

    let env = match ensure_jni_initialized() {
        Ok(env) => env,
        Err(msg) => return throw_internal_error(ctx, msg),
    };

    let cls = reflect::find_class_safe(env, &class_name);
    if cls.is_null() {
        return throw_internal_error(ctx, format!("class not found: {}", class_name));
    }

    // Wrap jclass（本身就是 java.lang.Class 实例）为 JS Proxy
    // marshal_local_java_object_to_js 会做 NewGlobalRef + 释放 local ref
    marshal_local_java_object_to_js(ctx, env, cls, Some("java.lang.Class"))
}

unsafe extern "C" fn js_java_set_classloader(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if crate::is_raw_clone_js_thread() {
        if argc < 1 {
            return throw_type_error(ctx, b"Java._setClassLoader() requires 1 argument: loader\0");
        }

        let loader_ptr = js_loader_arg_to_ptr(ctx, JSValue(*argv));
        if loader_ptr == 0 {
            return throw_type_error(
                ctx,
                b"Java._setClassLoader() loader must be a loader object or pointer\0",
            );
        }

        return callback::set_classloader_via_executor(ctx, loader_ptr);
    }
    if argc < 1 {
        return throw_type_error(ctx, b"Java._setClassLoader() requires 1 argument: loader\0");
    }

    let loader_ptr = js_loader_arg_to_ptr(ctx, JSValue(*argv));
    if loader_ptr == 0 {
        return throw_type_error(
            ctx,
            b"Java._setClassLoader() loader must be a loader object or pointer\0",
        );
    }

    let env = match ensure_jni_initialized() {
        Ok(env) => env,
        Err(msg) => return throw_internal_error(ctx, msg),
    };
    if env.is_null() {
        return throw_internal_error(ctx, "JNI env unavailable for Java._setClassLoader");
    }

    JSValue::bool(set_classloader_override(env, loader_ptr as *mut std::ffi::c_void)).raw()
}

/// 预初始化 artController Layer 1+2 (在进程暂停时调用)。
/// spawn 模式下必须在 resume_child 之前调用,确保 inline hooks 在所有
/// 线程暂停时安装,避免代码覆写与执行的竞态条件。
pub fn pre_init_art_controller() -> Result<(), String> {
    JAVA_SUBSYSTEM_TOUCHED.store(true, Ordering::Release);
    let env = ensure_jni_initialized().map_err(|e| format!("JNI init failed: {}", e))?;
    unsafe {
        // 探测 ArtMethodSpec (需要一个已知的 native 方法来校准偏移)
        // 传 0 会使用内部探测逻辑
        let spec = jni_core::get_art_method_spec(env, 0);
        let ep_offset = spec.entry_point_offset;
        // 发现 ART bridge 函数
        let bridge = art_method::find_art_bridge_functions(env, ep_offset);
        // 初始化 artController (安装 Layer 1+2 全局 hooks)
        art_controller::ensure_art_controller_initialized(&bridge, ep_offset, env as *mut std::ffi::c_void);
    }
    Ok(())
}

/// Host-side preconfiguration used before spawn-time ART initialization.
pub fn set_host_stealth_mode(mode: i64) -> Result<u8, String> {
    let mode = StealthMode::from_js_arg(mode);
    if art_controller_initialized() && mode != stealth_mode() {
        return Err(format!(
            "Java stealth mode already locked by installed ART hooks: current={}, requested={}",
            stealth_mode() as u8,
            mode as u8
        ));
    }
    set_stealth_mode(mode);
    Ok(mode as u8)
}

/// Register Java API: hook/unhook (C-level) + _methods, then eval boot script
/// to set up the Proxy-based Java.use() API.
/// Spawn 模式延迟 JNI 初始化：AttachCurrentThread + cache reflect IDs + 触发 gate hook。
/// 在 resume 之后调用（ART 已完成 post-fork 初始化）。
pub fn deferred_java_init() -> Result<(), String> {
    JAVA_SUBSYSTEM_TOUCHED.store(true, Ordering::Release);
    let env = ensure_jni_initialized().map_err(|e| format!("deferred_java_init: {}", e))?;
    unsafe {
        cache_reflect_ids(env);
    }

    crate::jsapi::console::output_verbose("[java] deferred_java_init: JNI 已就绪");

    // 兜底：resume 前 Java.ready 里的 gate hook 安装可能因 JNI 未就绪而失败
    if let Err(e) = crate::load_script("Java._installGateHook && Java._installGateHook()") {
        crate::jsapi::console::output_verbose(&format!("[java] gate hook retry: {}", e));
    }

    Ok(())
}

use std::sync::atomic::{AtomicBool, Ordering};
static REFLECT_CACHE_INITED: AtomicBool = AtomicBool::new(false);
static JAVA_SUBSYSTEM_TOUCHED: AtomicBool = AtomicBool::new(false);

fn java_cleanup_needed() -> bool {
    if JAVA_SUBSYSTEM_TOUCHED.load(Ordering::Acquire) || art_controller_initialized() {
        return true;
    }

    let guard = JAVA_HOOK_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    guard.as_ref().is_some_and(|registry| !registry.is_empty())
}

pub fn java_subsystem_active_for_cleanup() -> bool {
    java_cleanup_needed()
}

pub fn abort_raw_clone_java_executor_for_unload() -> bool {
    callback::cut_raw_clone_executor_loop_hook()
}

pub fn raw_clone_java_executor_hook_active() -> bool {
    callback::raw_clone_executor_hook_active()
}

/// 延迟初始化 Java reflection 缓存（PID 注入模式下首次调用 Java API 时触发）
pub(crate) fn lazy_init_reflect_cache() {
    JAVA_SUBSYSTEM_TOUCHED.store(true, Ordering::Release);
    if crate::is_raw_clone_js_thread() {
        crate::jsapi::console::output_verbose("[java] lazy_init_reflect_cache: skip on raw clone JS thread");
        return;
    }
    if REFLECT_CACHE_INITED.load(Ordering::Acquire) {
        return;
    }
    crate::jsapi::console::output_verbose("[java] lazy_init_reflect_cache: probing JVM...");
    if let Ok(env) = ensure_jni_initialized() {
        crate::jsapi::console::output_verbose("[java] lazy_init_reflect_cache: JVM found, caching...");
        unsafe {
            cache_reflect_ids(env);
        }
        REFLECT_CACHE_INITED.store(true, Ordering::Release);
        crate::jsapi::console::output_verbose("[java] lazy_init_reflect_cache: done");
    } else {
        crate::jsapi::console::output_verbose("[java] lazy_init_reflect_cache: JVM not ready, skip");
    }
}

unsafe extern "C" fn js_java_ensure_initialized(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    match install_java_api(ctx) {
        Ok(java) => java,
        Err(err) => throw_internal_error(ctx, err),
    }
}

pub fn register_lazy_java_api(ctx: &JSContext) {
    let global = ctx.global_object();

    unsafe {
        let ctx_ptr = ctx.as_ptr();
        let java_obj = ffi::JS_NewObject(ctx_ptr);
        add_cfunction_to_object(ctx_ptr, java_obj, "_ensureInitialized", js_java_ensure_initialized, 0);
        global.set_property(ctx_ptr, "Java", JSValue(java_obj));
    }

    global.free(ctx.as_ptr());

    let boot = r#"
(function() {
    "use strict";
    var lazy = Java;
    var ensure = lazy._ensureInitialized;
    var initialized = false;
    var real = null;
    delete lazy._ensureInitialized;

    function getReal() {
        if (!initialized) {
            real = ensure();
            initialized = true;
        }
        return real;
    }

    globalThis.Java = new Proxy(lazy, {
        get: function(_, prop) {
            if (prop === "toString") return function() { return initialized ? "[object Java]" : "[object LazyJava]"; };
            var target = getReal();
            return target[prop];
        },
        set: function(_, prop, value) {
            var target = getReal();
            target[prop] = value;
            return true;
        },
        has: function(_, prop) {
            var target = getReal();
            return prop in target;
        },
        ownKeys: function(_) {
            return Reflect.ownKeys(getReal());
        },
        getOwnPropertyDescriptor: function(_, prop) {
            return Object.getOwnPropertyDescriptor(getReal(), prop);
        }
    });
})();
"#;
    match ctx.eval(boot, "<java_lazy_boot>") {
        Ok(val) => val.free(ctx.as_ptr()),
        Err(e) => output_verbose(&format!("[java_api] lazy boot script error: {}", e)),
    }
}

/// Install full Java API: hook/unhook (C-level) + _methods, then eval boot script
/// to set up the Proxy-based Java.use() API.
unsafe fn install_java_api(ctx_ptr: *mut ffi::JSContext) -> Result<ffi::JSValue, String> {
    if ctx_ptr.is_null() {
        return Err("Java lazy init: JSContext is null".to_string());
    }
    JAVA_SUBSYSTEM_TOUCHED.store(true, Ordering::Release);

    let global_raw = ffi::JS_GetGlobalObject(ctx_ptr);
    let global = JSValue(global_raw);

    // Create the "Java" namespace object
    let java_obj = ffi::JS_NewObject(ctx_ptr);

    add_cfunction_to_object(ctx_ptr, java_obj, "hook", js_java_hook, 4);
    add_cfunction_to_object(ctx_ptr, java_obj, "hookQuick", js_java_hook_quick, 4);
    add_cfunction_to_object(ctx_ptr, java_obj, "fastHook", js_fast_hook, 4);
    add_cfunction_to_object(ctx_ptr, java_obj, "managedHookDsl", js_managed_hook_dsl, 4);
    add_cfunction_to_object(ctx_ptr, java_obj, "managedReadCounter", js_managed_read_counter, 2);
    add_cfunction_to_object(ctx_ptr, java_obj, "managedDrainMessages", js_managed_drain_messages, 2);
    add_cfunction_to_object(ctx_ptr, java_obj, "fastHookSig", js_fast_hook_signature, 1);
    add_cfunction_to_object(ctx_ptr, java_obj, "fastHookCheck", js_fast_hook_check, 2);
    add_cfunction_to_object(ctx_ptr, java_obj, "unhook", js_java_unhook, 3);
    add_cfunction_to_object(ctx_ptr, java_obj, "deopt", js_java_deopt, 0);
    add_cfunction_to_object(
        ctx_ptr,
        java_obj,
        "deoptimizeBootImage",
        js_java_deoptimize_boot_image,
        0,
    );
    add_cfunction_to_object(
        ctx_ptr,
        java_obj,
        "deoptimizeEverything",
        js_java_deoptimize_everything,
        0,
    );
    add_cfunction_to_object(ctx_ptr, java_obj, "deoptimizeMethod", js_java_deoptimize_method, 3);
    add_cfunction_to_object(ctx_ptr, java_obj, "setStealth", js_java_set_stealth, 1);
    add_cfunction_to_object(ctx_ptr, java_obj, "getStealth", js_java_get_stealth, 0);
    add_cfunction_to_object(
        ctx_ptr,
        java_obj,
        "setManagedHookGuard",
        js_set_managed_reentry_guard,
        1,
    );
    add_cfunction_to_object(
        ctx_ptr,
        java_obj,
        "managedHookGuardStats",
        js_managed_reentry_guard_stats,
        0,
    );
    add_cfunction_to_object(ctx_ptr, java_obj, "_artRouterDebug", js_art_router_debug, 0);
    add_cfunction_to_object(ctx_ptr, java_obj, "_artRouteStats", js_art_route_stats, 0);
    add_cfunction_to_object(ctx_ptr, java_obj, "_resetArtRouteStats", js_reset_art_route_stats, 0);
    add_cfunction_to_object(ctx_ptr, java_obj, "_fastHookStats", js_fast_hook_stats, 0);
    add_cfunction_to_object(
        ctx_ptr,
        java_obj,
        "_artSymbolProbe",
        java_fast_api::js_art_symbol_probe,
        0,
    );
    add_cfunction_to_object(ctx_ptr, java_obj, "_methods", js_java_methods, 1);
    // Instance method invocation helper used by Java object proxies
    add_cfunction_to_object(ctx_ptr, java_obj, "_invokeMethod", js_java_invoke_method, 4);
    add_cfunction_to_object(
        ctx_ptr,
        java_obj,
        "_invokeStaticMethod",
        js_java_invoke_static_method,
        4,
    );
    add_cfunction_to_object(ctx_ptr, java_obj, "_newObject", js_java_new_object, 2);
    add_cfunction_to_object(ctx_ptr, java_obj, "getField", js_java_get_field, 4);
    // Frida-style FieldWrapper 后端（无 FIELD_CACHE 锁）
    add_cfunction_to_object(ctx_ptr, java_obj, "_fieldMeta", js_java_field_meta, 3);
    add_cfunction_to_object(ctx_ptr, java_obj, "_readField", js_java_read_field, 5);
    add_cfunction_to_object(ctx_ptr, java_obj, "_writeField", js_java_write_field, 6);

    // Java 数组访问 (arr.length / arr[i])
    add_cfunction_to_object(
        ctx_ptr,
        java_obj,
        "_arrayLength",
        java_array_api::js_java_array_length,
        1,
    );
    add_cfunction_to_object(ctx_ptr, java_obj, "_arrayGet", java_array_api::js_java_array_get, 3);

    // 检测面测试 API
    add_cfunction_to_object(ctx_ptr, java_obj, "_inspectArtMethod", js_java_inspect_art_method, 3);
    add_cfunction_to_object(ctx_ptr, java_obj, "_jitInfo", js_java_jit_info, 0);
    add_cfunction_to_object(ctx_ptr, java_obj, "compileMethod", js_java_compile_method, 4);
    add_cfunction_to_object(ctx_ptr, java_obj, "optMethod", js_java_compile_method, 4);
    add_cfunction_to_object(ctx_ptr, java_obj, "optimizeMethod", js_java_compile_method, 4);
    add_cfunction_to_object(ctx_ptr, java_obj, "fastMethod", js_java_fast_method, 3);
    add_cfunction_to_object(ctx_ptr, java_obj, "fastConstructor", js_java_fast_constructor, 3);
    add_cfunction_to_object(ctx_ptr, java_obj, "fastField", js_java_fast_field, 3);
    add_cfunction_to_object(
        ctx_ptr,
        java_obj,
        "_setForcedInterpretOnly",
        js_java_set_forced_interpret_only,
        1,
    );
    add_cfunction_to_object(ctx_ptr, java_obj, "_initArtController", js_java_init_art_controller, 0);
    add_cfunction_to_object(
        ctx_ptr,
        java_obj,
        "_installExecutorHook",
        callback::js_install_raw_clone_executor_hook,
        0,
    );
    add_cfunction_to_object(
        ctx_ptr,
        java_obj,
        "_cutRawCloneExecutorHook",
        js_cut_raw_clone_executor_hook,
        0,
    );
    add_cfunction_to_object(ctx_ptr, java_obj, "_updateClassLoader", js_update_classloader, 1);
    add_cfunction_to_object(ctx_ptr, java_obj, "_isClassLoaderReady", js_is_classloader_ready, 0);
    add_cfunction_to_object(ctx_ptr, java_obj, "_isRawCloneJsThread", js_is_raw_clone_js_thread, 0);
    add_cfunction_to_object(ctx_ptr, java_obj, "_reprobeClassLoader", js_reprobe_classloader, 0);
    add_cfunction_to_object(
        ctx_ptr,
        java_obj,
        "_reprobeClassLoaderOnce",
        js_reprobe_classloader_once,
        0,
    );
    add_cfunction_to_object(ctx_ptr, java_obj, "_classLoaders", js_java_classloaders, 0);
    add_cfunction_to_object(
        ctx_ptr,
        java_obj,
        "_findClassWithLoader",
        js_java_find_class_with_loader,
        2,
    );
    add_cfunction_to_object(ctx_ptr, java_obj, "_findClassObject", js_java_find_class_object, 1);
    add_cfunction_to_object(ctx_ptr, java_obj, "_setClassLoader", js_java_set_classloader, 1);
    // Java.choose() backend: VMDebug/JVMTI reliable live-object enumeration
    add_cfunction_to_object(ctx_ptr, java_obj, "_enumerateInstances", js_java_enumerate_instances, 3);
    // Java.choose() 配套：批量释放 wrapper 持有的 JNI global refs
    add_cfunction_to_object(
        ctx_ptr,
        java_obj,
        "_releaseInstanceRefs",
        js_java_release_instance_refs,
        1,
    );

    // Set Java object on global before evaluating java_boot; boot captures these C
    // functions into closures and then hides the raw methods from the public API.
    global.set_property(ctx_ptr, "Java", JSValue(java_obj));

    let boot = include_str!("java_boot.js");
    let cscript = std::ffi::CString::new(boot).map_err(|e| format!("Invalid java boot script: {}", e))?;
    let cfilename = std::ffi::CString::new("<java_boot>").unwrap();
    ffi::qjs_update_stack_top(ctx_ptr);
    let val = ffi::JS_Eval(
        ctx_ptr,
        cscript.as_ptr(),
        boot.len(),
        cfilename.as_ptr(),
        ffi::JS_EVAL_TYPE_GLOBAL as i32,
    );
    let val = JSValue(val);
    if val.is_exception() {
        let exc = JSValue(ffi::JS_GetException(ctx_ptr));
        let message = exc
            .to_string(ctx_ptr)
            .unwrap_or_else(|| "Java boot script failed".to_string());
        exc.free(ctx_ptr);
        global.free(ctx_ptr);
        return Err(message);
    }
    val.free(ctx_ptr);

    let java_name = std::ffi::CString::new("Java").unwrap();
    let installed = ffi::JS_GetPropertyStr(ctx_ptr, global.raw(), java_name.as_ptr());
    global.free(ctx_ptr);
    Ok(installed)
}

pub fn register_java_api(ctx: &JSContext) {
    unsafe {
        match install_java_api(ctx.as_ptr()) {
            Ok(java) => JSValue(java).free(ctx.as_ptr()),
            Err(e) => output_verbose(&format!("[java_api] boot script error: {}", e)),
        }
    }
}

// ============================================================================
// Java hook 拆卸原子操作 — 供 js_java_unhook 和 cleanup_java_hooks 复用
// ============================================================================

/// 恢复 ArtMethod 原始 flags，以及 hook 安装时主动改写过的内部 entry。
///
/// 目标 app/framework ArtMethod 的 entry_point_/data_ 不写外部地址，也不在
/// cleanup 时用旧快照覆盖 ART 自己后续做出的更新。路由切断通过 code hook /
/// ART shared entry hook 完成。
pub(super) unsafe fn restore_art_method_fields(data: &JavaHookData) {
    if !data.hook_type.original_flags_mutated() && !data.hook_type.original_entry_mutated() {
        return;
    }
    if let Some(spec) = ART_METHOD_SPEC.get() {
        if data.hook_type.original_flags_mutated() {
            std::ptr::write_volatile(
                (data.art_method as usize + spec.access_flags_offset) as *mut u32,
                data.original_access_flags,
            );
            hook_ffi::hook_flush_cache(
                (data.art_method as usize + spec.access_flags_offset) as *mut std::ffi::c_void,
                4,
            );
        }
        if data.hook_type.original_entry_mutated() {
            std::ptr::write_volatile(
                (data.art_method as usize + spec.entry_point_offset) as *mut u64,
                data.original_entry_point,
            );
            hook_ffi::hook_flush_cache(
                (data.art_method as usize + spec.entry_point_offset) as *mut std::ffi::c_void,
                8,
            );
        }
    }
}

/// 移除 Layer 3 per-method inline hook + stealth2 revert_slot_patch。
pub(super) unsafe fn remove_per_method_hook(data: &JavaHookData) {
    if data.quick_trampoline == 0 {
        // No inline per-method hook was installed. Shared/early-entry methods are
        // routed through ART trampolines only; restore_art_method_fields() only
        // restores the access flags.
        return;
    }

    match &data.hook_type {
        callback::HookType::NativeEntry => {}
        callback::HookType::Replaced {
            per_method_hook_target, ..
        }
        | callback::HookType::Quick {
            per_method_hook_target, ..
        }
        | callback::HookType::Managed {
            per_method_hook_target, ..
        } => {
            if let Some(target) = per_method_hook_target {
                let _ = crate::recomp::revert_slot_patch(data.original_entry_point as usize);
                hook_ffi::hook_remove(*target as *mut std::ffi::c_void);
            }
        }
    }
}

/// 移除 registered native fnPtr inline hook。
pub(super) unsafe fn remove_native_entry_hook(data: &JavaHookData) {
    if data.native_entry_hook_target != 0 {
        crate::recomp::try_revert_slot_patch_by_slot(data.native_entry_hook_target as usize);
        hook_ffi::hook_remove(data.native_entry_hook_target as *mut std::ffi::c_void);
    }
}

/// 移除 native trampoline (hook_remove_redirect)。
pub(super) unsafe fn remove_native_trampoline(data: &JavaHookData) {
    if matches!(data.hook_type, callback::HookType::NativeEntry) {
        return;
    }
    hook_ffi::hook_remove_redirect(data.art_method);
}

/// 释放 replacement/clone ArtMethod 堆内存 + JNI global ref + JS callback。
pub(super) unsafe fn free_java_hook_resources(data: &JavaHookData, env_opt: Option<JniEnv>) {
    let replacement_addr = match &data.hook_type {
        callback::HookType::NativeEntry => 0,
        callback::HookType::Replaced { replacement_addr, .. } | callback::HookType::Quick { replacement_addr, .. } => {
            *replacement_addr
        }
        callback::HookType::Managed { sentinel_addr, .. } => *sentinel_addr,
    };
    if replacement_addr != 0 {
        libc::free(replacement_addr as *mut std::ffi::c_void);
    }
    if data.clone_addr != 0 {
        libc::free(data.clone_addr as *mut std::ffi::c_void);
    }

    if data.class_global_ref != 0 {
        if let Some(env) = env_opt {
            let delete_global_ref: DeleteGlobalRefFn = jni_fn!(env, DeleteGlobalRefFn, JNI_DELETE_GLOBAL_REF);
            delete_global_ref(env, data.class_global_ref as *mut std::ffi::c_void);
        }
    }

    if data.ctx != 0 {
        let ctx = data.ctx as *mut ffi::JSContext;
        let callback: ffi::JSValue = std::ptr::read(data.callback_bytes.as_ptr() as *const ffi::JSValue);
        ffi::qjs_free_value(ctx, callback);
    }
}

/// Cleanup all Java hooks (call before dropping context)
///
/// Frida revert() 风格: 恢复全部 ArtMethod 字段，清理 replacedMethods 映射。
///
/// 调用路径: JSEngine::drop() → cleanup_java_hooks()
/// 此时 JS_ENGINE 锁已被当前线程持有（cleanup_engine() 中 `*engine = None` 触发 drop），
/// 因此不能再次 lock()（非重入锁会死锁）。使用 try_lock() 安全处理两种情况：
/// - WouldBlock: 当前线程已持有锁（正常路径），JS callback 释放安全
/// - Ok: 意外的非锁定路径调用，获取锁后释放 JS callback
/// Phase 1 - 切断 Java hook 入口 (不释放资源)。
///
/// 新 caller 立即走原方法，不再进入 thunk；in-flight counter 之后只减不增。
/// 必须与 `cut_native_hooks` / `cut_art_controller_hooks` 一起在 drain 之前完成，
/// 否则 g_thunk_in_flight 永远 ≠ 0。
pub fn cut_java_hooks() {
    if !java_cleanup_needed() {
        return;
    }

    if !crate::is_raw_clone_js_thread() {
        if let Ok(env) = ensure_jni_initialized() {
            unsafe {
                cleanup_enumerated_classloader_refs(env);
                cleanup_cached_class_refs(env);
            }
        }
    }

    let guard = JAVA_HOOK_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(registry) = guard.as_ref() {
        for (_art_method, data) in registry.iter() {
            unsafe {
                // unpatch per-method hook 首字节 → 新 caller 立即走原方法
                remove_per_method_hook(data);
                // registered native 直接 fnPtr hook 也要先切断，避免新调用进 callback
                remove_native_entry_hook(data);
                // 恢复 ArtMethod flags (Layer 1/2 路由也切断)
                restore_art_method_fields(data);
                // router 表条目保留 → OAT bypass 对 in-flight 仍生效
                // router 表清空放到 free 阶段
            }
        }
    }
}

/// Phase 2 - Drain g_thunk_in_flight → 0。返回 true 表示真的归零，false 超时。
///
/// 调用方必须保证所有 hook 入口（Java + native + OAT inline）已在此之前切断，
/// 否则 counter 可能永不归 0 → 走到短预算超时。
///
/// **超时处理很重要**：超时意味着有线程阻塞在 callback 深处的 JNI/Java monitor，
/// 它们未来可能醒来返回 thunk。**false 时调用方必须跳过 free 资源和 munmap**，
/// 否则线程醒来会访问已释放内存 → 崩溃。安全做法：让资源 leak 到进程退出。
///
/// 循环 100ms 粒度轮询，2.5s 总上限兜底。
/// 诊断走 `output_message` 保证始终可见（不依赖 VERBOSE 开关）。
pub fn drain_thunk_in_flight() -> bool {
    use crate::jsapi::console::output_message;
    // callback 归零后可释放 JS 资源；exec 归零后才可 munmap pool/recomp。
    // Phase 1 已 cut 全部 routing 入口，counter 只减不增。若线程 parked 在 hooked 深处
    // (Looper.pollOnce / JNI monitor 等)，短等后放弃 free，让资源 leak 到进程退出。
    const DRAIN_BUDGET: std::time::Duration = std::time::Duration::from_millis(2500);
    let start = std::time::Instant::now();
    let initial_callback = in_flight_java_hook_callbacks();
    let initial_exec = unsafe { hook_ffi::hook_thunk_in_flight_count() };
    output_message(&format!(
        "[drain] start, callback_in_flight={}, exec_in_flight={}",
        initial_callback, initial_exec
    ));
    let mut rounds = 0u32;
    loop {
        let callbacks_done = wait_for_in_flight_java_hook_callbacks(std::time::Duration::from_millis(100));
        let exec_remaining = unsafe { hook_ffi::hook_thunk_in_flight_count() };
        if callbacks_done && exec_remaining == 0 {
            output_message(&format!(
                "[drain] done, callback_in_flight=0, exec_in_flight=0 after {}ms ({} rounds)",
                start.elapsed().as_millis(),
                rounds + 1
            ));
            return true;
        }
        if callbacks_done {
            crate::raw_thread::sleep_ms(100);
        }
        rounds += 1;
        if start.elapsed() >= DRAIN_BUDGET {
            let callback_remaining = in_flight_java_hook_callbacks();
            let exec_remaining = unsafe { hook_ffi::hook_thunk_in_flight_count() };
            output_message(&format!(
                "[drain] timeout after {}ms, callback_in_flight={}, exec_in_flight={} (skip free, keep resources)",
                DRAIN_BUDGET.as_millis(),
                callback_remaining,
                exec_remaining
            ));
            return false;
        }
        if rounds % 10 == 0 {
            let callback_remaining = in_flight_java_hook_callbacks();
            let exec_remaining = unsafe { hook_ffi::hook_thunk_in_flight_count() };
            output_message(&format!(
                "[drain] round {}, {}ms, callback_in_flight={}, exec_in_flight={}",
                rounds,
                start.elapsed().as_millis(),
                callback_remaining,
                exec_remaining
            ));
        }
    }
}

/// Phase 3 - 释放 Java hook 资源（clone/replacement ArtMethod、JNI global ref、JS callback）。
///
/// 必须在 `drain_thunk_in_flight` 之后调用。此时无任何线程在 thunk 或其 callee 中，
/// 释放 ArtMethod 堆内存 + JNI ref 安全。router 表最后清空。
pub fn free_java_hooks() {
    if !java_cleanup_needed() {
        return;
    }

    // router 表清空 (art_controller 的 OAT patch 已由 cut_art_controller_hooks revert)
    unsafe {
        hook_ffi::hook_art_router_table_clear();
    }

    // delete_replacement_method (先批量做，避免后面 drop guard 释放)
    {
        let guard = JAVA_HOOK_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(registry) = guard.as_ref() {
            for (_art_method, data) in registry.iter() {
                unsafe {
                    callback::delete_replacement_method(data.art_method);
                }
            }
        }
    }

    let env_opt = if crate::is_raw_clone_js_thread() {
        None
    } else {
        unsafe { get_thread_env().ok() }
    };
    let _js_guard = crate::JS_ENGINE.try_lock();

    let mut guard = JAVA_HOOK_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(registry) = guard.take() {
        for (_art_method, data) in registry {
            unsafe {
                remove_native_entry_hook(&data);
                remove_native_trampoline(&data);
                free_java_hook_resources(&data, env_opt);
            }
        }
    }
}

/// 兼容旧调用: 依次执行 cut → drain → art_controller cleanup → free。
/// drain 超时则跳过 free（避免线程苏醒踩已释放资源）。
/// 新代码应该用编排器模式 (cut_* → drain → free_*) 以便与 native/OAT 并行切断。
pub fn cleanup_java_hooks() {
    if !java_cleanup_needed() {
        return;
    }

    cut_java_hooks();
    let drained = drain_thunk_in_flight();
    if !drained {
        return;
    }
    art_controller::cleanup_art_controller();
    free_java_hooks();
}
