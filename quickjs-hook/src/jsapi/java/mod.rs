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
mod art_controller;
mod art_method;
mod art_thread;
mod callback;
mod heap_scan;
mod java_choose_api;
mod java_field_api;
mod java_hook_api;
mod java_inspect_api;
mod java_method_list_api;
mod jni_core;
mod reflect;
mod safe_mem;

pub(crate) use jni_core::ensure_jni_initialized;
pub(crate) use reflect::get_class_name_unchecked;

use crate::context::JSContext;
use crate::ffi;
use crate::ffi::hook as hook_ffi;
use crate::jsapi::callback_util::{set_js_u64_property, throw_internal_error, throw_type_error};
use crate::jsapi::console::output_verbose;
use crate::jsapi::util::add_cfunction_to_object;
use crate::value::JSValue;

use crate::jsapi::hook_api::StealthMode;
use art_controller::{set_stealth_mode, stealth_mode};
use art_method::{resolve_art_method, try_invalidate_jit_cache};
use callback::*;
use java_choose_api::*;
use java_field_api::*;
use java_hook_api::*;
use java_inspect_api::*;
use java_method_list_api::*;
use jni_core::*;
use reflect::*;

#[inline]
unsafe fn validate_jni_ref(env: JniEnv, obj: *mut std::ffi::c_void) -> bool {
    !obj.is_null() && art_class::is_valid_jni_ref(env, obj)
}

pub(crate) unsafe fn try_read_jstring(env_ptr: u64, obj_ptr: u64) -> Option<String> {
    let env = env_ptr as JniEnv;
    let obj = obj_ptr as *mut std::ffi::c_void;
    if env.is_null() || obj.is_null() {
        return None;
    }

    if !validate_jni_ref(env, obj) {
        return None;
    }

    let new_local_ref: NewLocalRefFn = jni_fn!(env, NewLocalRefFn, JNI_NEW_LOCAL_REF);
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
    let is_instance_of: IsInstanceOfFn = jni_fn!(env, IsInstanceOfFn, JNI_IS_INSTANCE_OF);
    let get_str: GetStringUtfCharsFn = jni_fn!(env, GetStringUtfCharsFn, JNI_GET_STRING_UTF_CHARS);
    let rel_str: ReleaseStringUtfCharsFn = jni_fn!(env, ReleaseStringUtfCharsFn, JNI_RELEASE_STRING_UTF_CHARS);

    let local_obj = new_local_ref(env, obj);
    if local_obj.is_null() || jni_check_exc(env) {
        return None;
    }

    let mut chars: *const std::os::raw::c_char = std::ptr::null();
    let result = (|| {
        if let Some(reflect) = REFLECT_IDS.get() {
            if !reflect.string_class.is_null()
                && (is_instance_of(env, local_obj, reflect.string_class) == 0 || jni_check_exc(env))
            {
                return None;
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
    if env.is_null() || !validate_jni_ref(env, obj) {
        return None;
    }

    let get_object_class: GetObjectClassFn = jni_fn!(env, GetObjectClassFn, JNI_GET_OBJECT_CLASS);
    let cls = get_object_class(env, obj);
    if cls.is_null() || jni_check_exc(env) {
        None
    } else {
        Some(cls as u64)
    }
}

pub(crate) unsafe fn try_get_superclass(env_ptr: u64, cls_ptr: u64) -> Option<u64> {
    let env = env_ptr as JniEnv;
    let cls = cls_ptr as *mut std::ffi::c_void;
    if env.is_null() || !validate_jni_ref(env, cls) {
        return None;
    }

    let get_superclass: GetSuperclassFn = jni_fn!(env, GetSuperclassFn, JNI_GET_SUPERCLASS);
    let super_cls = get_superclass(env, cls);
    if super_cls.is_null() || jni_check_exc(env) {
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
    if (!a.is_null() && !validate_jni_ref(env, a)) || (!b.is_null() && !validate_jni_ref(env, b)) {
        return false;
    }

    let is_same_object: IsSameObjectFn = jni_fn!(env, IsSameObjectFn, JNI_IS_SAME_OBJECT);
    is_same_object(env, a, b) != 0 && !jni_check_exc(env)
}

pub(crate) unsafe fn try_is_instance_of(env_ptr: u64, obj_ptr: u64, cls_ptr: u64) -> bool {
    let env = env_ptr as JniEnv;
    let obj = obj_ptr as *mut std::ffi::c_void;
    let cls = cls_ptr as *mut std::ffi::c_void;
    if env.is_null() || !validate_jni_ref(env, obj) || !validate_jni_ref(env, cls) {
        return false;
    }

    let is_instance_of: IsInstanceOfFn = jni_fn!(env, IsInstanceOfFn, JNI_IS_INSTANCE_OF);
    is_instance_of(env, obj, cls) != 0 && !jni_check_exc(env)
}

pub(crate) unsafe fn try_get_object_class_name(env_ptr: u64, obj_ptr: u64) -> Option<String> {
    let env = env_ptr as JniEnv;
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);

    let cls = try_get_object_class(env_ptr, obj_ptr)? as *mut std::ffi::c_void;
    let name = try_get_class_name(env_ptr, cls as u64);
    delete_local_ref(env, cls);
    name
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

    let class_name = match crate::jsapi::callback_util::extract_string_arg(
        ctx, JSValue(*argv), b"class must be a string\0",
    ) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let method_name = match crate::jsapi::callback_util::extract_string_arg(
        ctx, JSValue(*argv.add(1)), b"method must be a string\0",
    ) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let sig = match crate::jsapi::callback_util::extract_string_arg(
        ctx, JSValue(*argv.add(2)), b"sig must be a string\0",
    ) {
        Ok(v) => v,
        Err(e) => return e,
    };

    let env = match ensure_jni_initialized() {
        Ok(e) => e,
        Err(msg) => return crate::jsapi::callback_util::throw_internal_error(ctx, msg),
    };

    let (art_method, _is_static) = match resolve_art_method(env, &class_name, &method_name, &sig, false) {
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
            update_app_classloader(env, cl_ptr);
            output_verbose("[java.ready] ClassLoader 已更新");
            JSValue::bool(true).raw()
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

/// JS CFunction: Java._reprobeClassLoader() — 主动重新探测 ClassLoader
unsafe extern "C" fn js_reprobe_classloader(
    _ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    JSValue::bool(reflect::reprobe_classloader()).raw()
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

    JSValue::bool(set_classloader_override(env, loader_ptr as *mut std::ffi::c_void)).raw()
}

/// 预初始化 artController Layer 1+2 (在进程暂停时调用)。
/// spawn 模式下必须在 resume_child 之前调用,确保 inline hooks 在所有
/// 线程暂停时安装,避免代码覆写与执行的竞态条件。
pub fn pre_init_art_controller() -> Result<(), String> {
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

/// Register Java API: hook/unhook (C-level) + _methods, then eval boot script
/// to set up the Proxy-based Java.use() API.
/// Spawn 模式延迟 JNI 初始化：AttachCurrentThread + cache reflect IDs + 触发 gate hook。
/// 在 resume 之后调用（ART 已完成 post-fork 初始化）。
pub fn deferred_java_init() -> Result<(), String> {
    let env = ensure_jni_initialized().map_err(|e| format!("deferred_java_init: {}", e))?;
    unsafe {
        cache_reflect_ids(env);
    }

    crate::jsapi::console::output_verbose("[java] deferred_java_init: JNI 已就绪");

    // 触发 Java.ready gate hook 安装：调用 Java._installGateHook()
    // loadjs 在 resume 前运行时 Java.ready(fn) 注册了回调但 gate hook 安装失败（无 JNI）
    // 现在 JNI 就绪，重新安装 gate hook
    if let Err(e) = crate::load_script("Java._installGateHook && Java._installGateHook()") {
        crate::jsapi::console::output_verbose(&format!("[java] gate hook eval 失败: {}", e));
    }

    Ok(())
}

pub fn register_java_api(ctx: &JSContext) {
    // Spawn 模式: 跳过 JNI 初始化（由 deferred_java_init 在 resume 后完成）
    // PID 注入模式: 立刻初始化
    if let Ok(env) = ensure_jni_initialized() {
        unsafe {
            cache_reflect_ids(env);
        }
    }

    let global = ctx.global_object();

    unsafe {
        // Create the "Java" namespace object
        let java_obj = ffi::JS_NewObject(ctx.as_ptr());

        let ctx_ptr = ctx.as_ptr();
        add_cfunction_to_object(ctx_ptr, java_obj, "hook", js_java_hook, 4);
        add_cfunction_to_object(ctx_ptr, java_obj, "unhook", js_java_unhook, 3);
        add_cfunction_to_object(ctx_ptr, java_obj, "deopt", js_java_deopt, 0);
        add_cfunction_to_object(ctx_ptr, java_obj, "deoptimizeBootImage", js_java_deoptimize_boot_image, 0);
        add_cfunction_to_object(ctx_ptr, java_obj, "deoptimizeEverything", js_java_deoptimize_everything, 0);
        add_cfunction_to_object(ctx_ptr, java_obj, "deoptimizeMethod", js_java_deoptimize_method, 3);
        add_cfunction_to_object(ctx_ptr, java_obj, "setStealth", js_java_set_stealth, 1);
        add_cfunction_to_object(ctx_ptr, java_obj, "getStealth", js_java_get_stealth, 0);
        add_cfunction_to_object(ctx_ptr, java_obj, "_artRouterDebug", js_art_router_debug, 0);
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

        // 检测面测试 API
        add_cfunction_to_object(ctx_ptr, java_obj, "_inspectArtMethod", js_java_inspect_art_method, 3);
        add_cfunction_to_object(
            ctx_ptr,
            java_obj,
            "_setForcedInterpretOnly",
            js_java_set_forced_interpret_only,
            1,
        );
        add_cfunction_to_object(ctx_ptr, java_obj, "_initArtController", js_java_init_art_controller, 0);
        add_cfunction_to_object(ctx_ptr, java_obj, "_updateClassLoader", js_update_classloader, 1);
        add_cfunction_to_object(ctx_ptr, java_obj, "_isClassLoaderReady", js_is_classloader_ready, 0);
        add_cfunction_to_object(ctx_ptr, java_obj, "_reprobeClassLoader", js_reprobe_classloader, 0);
        add_cfunction_to_object(ctx_ptr, java_obj, "_classLoaders", js_java_classloaders, 0);
        add_cfunction_to_object(
            ctx_ptr,
            java_obj,
            "_findClassWithLoader",
            js_java_find_class_with_loader,
            2,
        );
        add_cfunction_to_object(
            ctx_ptr,
            java_obj,
            "_findClassObject",
            js_java_find_class_object,
            1,
        );
        add_cfunction_to_object(ctx_ptr, java_obj, "_setClassLoader", js_java_set_classloader, 1);
        // Java.choose() backend: 走 VMDebug.getInstancesOfClasses 枚举堆上实例
        add_cfunction_to_object(
            ctx_ptr,
            java_obj,
            "_enumerateInstances",
            js_java_enumerate_instances,
            3,
        );
        // Java.choose() 配套：批量释放 wrapper 持有的 JNI global refs
        add_cfunction_to_object(
            ctx_ptr,
            java_obj,
            "_releaseInstanceRefs",
            js_java_release_instance_refs,
            1,
        );

        // Set Java object on global
        global.set_property(ctx.as_ptr(), "Java", JSValue(java_obj));
    }

    global.free(ctx.as_ptr());

    // Load boot script: sets up Java.use() Proxy API, captures hook/unhook/
    // _methods in closures, then removes them from the Java object.
    let boot = include_str!("java_boot.js");
    match ctx.eval(boot, "<java_boot>") {
        Ok(val) => val.free(ctx.as_ptr()),
        Err(e) => output_verbose(&format!("[java_api] boot script error: {}", e)),
    }
}

// ============================================================================
// Java hook 拆卸原子操作 — 供 js_java_unhook 和 cleanup_java_hooks 复用
// ============================================================================

/// 恢复 ArtMethod 原始字段 (access_flags, data_, entry_point) + flush icache。
pub(super) unsafe fn restore_art_method_fields(data: &JavaHookData) {
    if let Some(spec) = ART_METHOD_SPEC.get() {
        std::ptr::write_volatile(
            (data.art_method as usize + spec.access_flags_offset) as *mut u32,
            data.original_access_flags,
        );
        std::ptr::write_volatile(
            (data.art_method as usize + spec.data_offset) as *mut u64,
            data.original_data,
        );
        std::ptr::write_volatile(
            (data.art_method as usize + spec.entry_point_offset) as *mut u64,
            data.original_entry_point,
        );
        hook_ffi::hook_flush_cache(
            data.art_method as usize as *mut std::ffi::c_void,
            spec.entry_point_offset + 8,
        );
    }
}

/// 移除 Layer 3 per-method inline hook + stealth2 revert_slot_patch。
pub(super) unsafe fn remove_per_method_hook(data: &JavaHookData) {
    if let callback::HookType::Replaced { per_method_hook_target, .. } = &data.hook_type {
        if let Some(target) = per_method_hook_target {
            hook_ffi::hook_remove(*target as *mut std::ffi::c_void);
            let _ = crate::recomp::revert_slot_patch(data.original_entry_point as usize);
        }
    }
}

/// 移除 native trampoline (hook_remove_redirect)。
pub(super) unsafe fn remove_native_trampoline(data: &JavaHookData) {
    hook_ffi::hook_remove_redirect(data.art_method);
}

/// 释放 replacement ArtMethod 堆内存 + JNI global ref + JS callback。
pub(super) unsafe fn free_java_hook_resources(data: &JavaHookData, env_opt: Option<JniEnv>) {
    if let callback::HookType::Replaced { replacement_addr, .. } = &data.hook_type {
        if *replacement_addr != 0 {
            libc::free(*replacement_addr as *mut std::ffi::c_void);
        }
    }

    if data.class_global_ref != 0 {
        if let Some(env) = env_opt {
            let delete_global_ref: DeleteGlobalRefFn = jni_fn!(env, DeleteGlobalRefFn, JNI_DELETE_GLOBAL_REF);
            delete_global_ref(env, data.class_global_ref as *mut std::ffi::c_void);
        }
    }

    let ctx = data.ctx as *mut ffi::JSContext;
    let callback: ffi::JSValue = std::ptr::read(data.callback_bytes.as_ptr() as *const ffi::JSValue);
    ffi::qjs_free_value(ctx, callback);
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
pub fn cleanup_java_hooks() {
    if let Ok(env) = ensure_jni_initialized() {
        unsafe {
            cleanup_enumerated_classloader_refs(env);
            cleanup_cached_class_refs(env);
        }
    }

    // DEBUG: cleanup 前打印 art_router hit/miss 计数
    unsafe {
        let mut last_x0: u64 = 0;
        let mut miss_count: u64 = 0;
        let mut hit_count: u64 = 0;
        hook_ffi::hook_art_router_get_debug(&mut last_x0, &mut miss_count);
        hook_ffi::hook_art_router_get_hit_debug(&mut hit_count, std::ptr::null_mut());
        let do_call_total = art_controller::DO_CALL_COUNT.load(std::sync::atomic::Ordering::Relaxed);
        let do_call_hits = art_controller::DO_CALL_HIT_COUNT.load(std::sync::atomic::Ordering::Relaxed);
        output_verbose(&format!(
            "[art_router_debug] cleanup: router_hit={}, router_miss={}, last_x0={:#x}, docall_total={}, docall_hit={}",
            hit_count, miss_count, last_x0, do_call_total, do_call_hits
        ));
        hook_ffi::hook_art_router_table_dump();
    }

    // 【关键】先清空 C 侧 ART router 查表，切断路由 → 防止并发线程通过
    unsafe {
        hook_ffi::hook_art_router_table_clear();
    }

    // ============================================================
    // Pass 1: 恢复所有 ArtMethod 字段 + 删除 replacedMethods 映射
    //
    // 【必须在移除 Layer 1 hooks 之前完成】
    // 否则: Layer 1 hook 移除后原始 trampoline 恢复，但 ArtMethod 仍然是
    // native+data_=our_thunk → 其他线程调用 → jni_trampoline → 我们的 thunk
    // → callback 找不到 registry → 返回 x0=JNIEnv* 作为返回值 → 崩溃
    // ============================================================
    {
        let guard = JAVA_HOOK_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(registry) = guard.as_ref() {
            for (_art_method, data) in registry.iter() {
                unsafe {
                    restore_art_method_fields(data);
                    callback::delete_replacement_method(data.art_method);
                }
            }
        }
    } // guard dropped — 释放锁让 in-flight callback 能获取锁并安全退出

    // 等待已进入 thunk 的回调自然退出。
    // ArtMethod 已恢复后不会再有新回调进入，因此这里等待 in-flight 计数清零即可。
    if !wait_for_in_flight_java_hook_callbacks(std::time::Duration::from_millis(200)) {
        output_verbose(&format!(
            "[java cleanup] 等待 in-flight callbacks 超时，remaining={}",
            in_flight_java_hook_callbacks()
        ));
    }

    // 移除 artController 全局 hook (Layer 1/2/GC)
    // 此时 ArtMethod 已全部恢复，移除 Layer 1 hook 后不会有线程进入 thunk
    art_controller::cleanup_art_controller();

    // ============================================================
    // Pass 2: 移除 per-method hooks + 释放资源
    // ============================================================

    let env_opt = unsafe { get_thread_env().ok() };
    let _js_guard = crate::JS_ENGINE.try_lock();

    let mut guard = JAVA_HOOK_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(registry) = guard.take() {
        for (_art_method, data) in registry {
            unsafe {
                remove_per_method_hook(&data);
                remove_native_trampoline(&data);
                free_java_hook_resources(&data, env_opt);
            }
        }
    }
}
