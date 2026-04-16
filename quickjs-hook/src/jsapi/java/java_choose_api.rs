//! JS API: `Java.choose(className, {onMatch, onComplete})` — Frida 兼容。
//!
//! Native backend: `Java._enumerateInstances(className, includeSubtypes?) → Array<{__jptr, __jclass}>`
//! JS 侧 (`java_boot.js`) 把返回的裸 wrapper 列表喂进 onMatch / onComplete 回调。
//!
//! 两条后端，按设备能力自动选择：
//!   (A) `dalvik.system.VMDebug.getInstancesOfClasses` —— Android ≤13 有效。
//!       在 API 34+ 被从 Java 层删除，API 36 同样不可用。
//!   (B) 直接扫描 ART 堆 `[anon:dalvik-*]` VMA ——  对标 Frida 的 VisitObjects 但走本地
//!       实现，不依赖已被 strip 的 `art::gc::Heap::VisitObjects/GetInstances`。见
//!       `heap_scan.rs`。
//!
//! JNI 初始化阶段的 `bypass_hidden_api_restrictions` 会放行 reflect 级 hidden-API。

use crate::ffi;
use crate::jsapi::callback_util::{
    extract_string_arg, set_js_u64_property, throw_internal_error, throw_type_error,
};
use crate::jsapi::console::output_verbose;
use crate::value::JSValue;
use std::ffi::CString;

use super::heap_scan::heap_scan_enumerate_instances;
use super::jni_core::*;
use super::reflect::find_class_safe;

/// JS CFunction: `Java._enumerateInstances(className, includeSubtypes?, maxCount?) → Array<{__jptr,__jclass}>`
///
/// 每个 instance 都 `NewGlobalRef` 一次（或 `art::JavaVMExt::AddGlobalRef`），由 JS 侧持有。
/// 调用方**必须**通过 `Java._releaseInstanceRefs(arr)` 释放，否则 JNI global ref table 会爆。
pub(super) unsafe extern "C" fn js_java_enumerate_instances(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return throw_type_error(
            ctx,
            b"Java._enumerateInstances(className, includeSubtypes?, maxCount?) requires className\0",
        );
    }

    // 兼容 Frida：className 用 . 或 / 分隔都接受
    let class_name_raw = match extract_string_arg(
        ctx,
        JSValue(*argv),
        b"Java._enumerateInstances: className must be a string\0",
    ) {
        Ok(s) => s,
        Err(e) => return e,
    };
    if class_name_raw.is_empty() {
        return throw_type_error(ctx, b"Java._enumerateInstances: className must be non-empty\0");
    }
    let class_name = class_name_raw.replace('/', ".");

    let include_subtypes = if argc >= 2 {
        JSValue(*argv.add(1)).to_bool().unwrap_or(false)
    } else {
        false
    };
    let max_count = if argc >= 3 {
        JSValue(*argv.add(2))
            .to_i64(ctx)
            .map(|v| if v < 0 { 0usize } else { v as usize })
            .unwrap_or(0usize)
    } else {
        0
    };

    let env = match ensure_jni_initialized() {
        Ok(env) => env,
        Err(msg) => return throw_internal_error(ctx, msg),
    };

    // 1) 先试 VMDebug 路径（Android 10~13）
    match vmdebug_enumerate(ctx, env, &class_name, include_subtypes, max_count) {
        Ok(arr) => arr,
        Err(vmdebug_err) => {
            // 2) VMDebug 不可用 —— 降到 heap-scan 路径（Android 14+/API 36 适用）
            output_verbose(&format!("[java.choose] VMDebug 后端失败: {}", vmdebug_err));
            output_verbose("[java.choose] 降级到 heap-scan 后端");
            match heap_scan_enumerate_js(ctx, env, &class_name, include_subtypes, max_count) {
                Ok(arr) => arr,
                Err(scan_err) => throw_internal_error(
                    ctx,
                    format!(
                        "Java.choose: both backends failed.\n  VMDebug: {}\n  heap-scan: {}",
                        vmdebug_err, scan_err
                    ),
                ),
            }
        }
    }
}

/// JS CFunction: `Java._releaseInstanceRefs(arr_of_wrappers)` — 批量释放
/// `Java._enumerateInstances` 返回的所有 `__jptr` global refs。
///
/// arr 元素结构：`{__jptr: BigInt, __jclass: string}`。__jptr 为 null/undefined 跳过。
pub(super) unsafe extern "C" fn js_java_release_instance_refs(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return throw_type_error(ctx, b"Java._releaseInstanceRefs(arr) requires array arg\0");
    }
    let arr_val = JSValue(*argv);
    if !arr_val.is_object() {
        return throw_type_error(ctx, b"Java._releaseInstanceRefs(arr): arg must be array\0");
    }

    let env = match ensure_jni_initialized() {
        Ok(env) => env,
        Err(msg) => return throw_internal_error(ctx, msg),
    };
    let delete_global_ref: DeleteGlobalRefFn =
        jni_fn!(env, DeleteGlobalRefFn, JNI_DELETE_GLOBAL_REF);

    // 读 length
    let length_val = arr_val.get_property(ctx, "length");
    let length = length_val.to_u64(ctx).unwrap_or(0);
    length_val.free(ctx);

    let mut released = 0u64;
    for i in 0..length {
        let elem = ffi::JS_GetPropertyUint32(ctx, arr_val.0, i as u32);
        let elem_val = JSValue(elem);
        if elem_val.is_object() {
            let jptr_prop = elem_val.get_property(ctx, "__jptr");
            if let Some(jptr) = jptr_prop.to_u64(ctx) {
                if jptr != 0 {
                    delete_global_ref(env, jptr as *mut std::ffi::c_void);
                    // 把 __jptr 置 0，防止用户再用同一 wrapper 调方法
                    crate::jsapi::callback_util::set_js_u64_property(ctx, elem, "__jptr", 0);
                    released += 1;
                }
            }
            jptr_prop.free(ctx);
        }
        elem_val.free(ctx);
    }

    ffi::JS_NewBigUint64(ctx, released)
}

// ============================================================================
// 后端 A：VMDebug.getInstancesOfClasses
// ============================================================================

unsafe fn vmdebug_enumerate(
    ctx: *mut ffi::JSContext,
    env: JniEnv,
    class_name: &str,
    include_subtypes: bool,
    max_count: usize,
) -> Result<ffi::JSValue, String> {
    jni_check_exc(env);

    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);

    let target_cls = find_class_safe(env, class_name);
    if target_cls.is_null() {
        return Err(format!("class not found: {}", class_name));
    }
    let class_cls = find_class_safe(env, "java.lang.Class");
    if class_cls.is_null() {
        delete_local_ref(env, target_cls);
        return Err("java.lang.Class not resolvable".to_string());
    }
    let vmdebug_cls = find_class_safe(env, "dalvik.system.VMDebug");
    if vmdebug_cls.is_null() {
        delete_local_ref(env, target_cls);
        delete_local_ref(env, class_cls);
        return Err("dalvik.system.VMDebug not found".to_string());
    }

    // 三种历史签名按稳定顺序尝试：
    //   (a) Android 10~12 Java wrapper:   `([Ljava/lang/Class;Z)[[Ljava/lang/Object;` (2D)
    //   (b) Android 13 @FastNative:        `([Ljava/lang/Class;Z)[Ljava/lang/Object;`  (1D)
    //   (c) Legacy native backing:         `getInstancesOfClassesNative(...)` (1D)
    let get_static_mid: GetStaticMethodIdFn =
        jni_fn!(env, GetStaticMethodIdFn, JNI_GET_STATIC_METHOD_ID);

    let c_name_main = CString::new("getInstancesOfClasses").unwrap();
    let c_sig_2d = CString::new("([Ljava/lang/Class;Z)[[Ljava/lang/Object;").unwrap();
    let c_sig_1d = CString::new("([Ljava/lang/Class;Z)[Ljava/lang/Object;").unwrap();
    let c_name_native = CString::new("getInstancesOfClassesNative").unwrap();

    let mut mid = get_static_mid(env, vmdebug_cls, c_name_main.as_ptr(), c_sig_2d.as_ptr());
    let mut is_2d = true;
    if mid.is_null() {
        jni_check_exc(env);
        mid = get_static_mid(env, vmdebug_cls, c_name_main.as_ptr(), c_sig_1d.as_ptr());
        is_2d = false;
    }
    if mid.is_null() {
        jni_check_exc(env);
        mid = get_static_mid(env, vmdebug_cls, c_name_native.as_ptr(), c_sig_1d.as_ptr());
        is_2d = false;
    }
    if mid.is_null() {
        jni_check_exc(env);
        delete_local_ref(env, target_cls);
        delete_local_ref(env, class_cls);
        delete_local_ref(env, vmdebug_cls);
        return Err(
            "VMDebug.getInstancesOfClasses[Native] unavailable on this build".to_string(),
        );
    }

    // 构造 Class[]{target_cls}
    let new_obj_array: NewObjectArrayFn = jni_fn!(env, NewObjectArrayFn, JNI_NEW_OBJECT_ARRAY);
    let set_obj_array_elem: SetObjectArrayElementFn =
        jni_fn!(env, SetObjectArrayElementFn, JNI_SET_OBJECT_ARRAY_ELEMENT);

    let classes_arr = new_obj_array(env, 1, class_cls, std::ptr::null_mut());
    if classes_arr.is_null() || jni_check_exc(env) {
        delete_local_ref(env, target_cls);
        delete_local_ref(env, class_cls);
        delete_local_ref(env, vmdebug_cls);
        return Err("NewObjectArray(Class[1]) failed".to_string());
    }
    set_obj_array_elem(env, classes_arr, 0, target_cls);
    if jni_check_exc(env) {
        delete_local_ref(env, classes_arr);
        delete_local_ref(env, target_cls);
        delete_local_ref(env, class_cls);
        delete_local_ref(env, vmdebug_cls);
        return Err("SetObjectArrayElement failed".to_string());
    }

    let call_static_obj: CallStaticObjectMethodAFn =
        jni_fn!(env, CallStaticObjectMethodAFn, JNI_CALL_STATIC_OBJECT_METHOD_A);
    let args: [u64; 2] = [classes_arr as u64, if include_subtypes { 1 } else { 0 }];
    let raw_result = call_static_obj(
        env,
        vmdebug_cls,
        mid,
        args.as_ptr() as *const std::ffi::c_void,
    );

    delete_local_ref(env, classes_arr);
    delete_local_ref(env, class_cls);
    delete_local_ref(env, vmdebug_cls);

    if let Some(msg) = jni_take_exception(env) {
        delete_local_ref(env, target_cls);
        if !raw_result.is_null() {
            delete_local_ref(env, raw_result);
        }
        return Err(format!("VMDebug.getInstancesOfClasses threw: {}", msg));
    }
    if raw_result.is_null() {
        delete_local_ref(env, target_cls);
        return Err("VMDebug.getInstancesOfClasses returned null".to_string());
    }

    let get_arr_len: GetArrayLengthFn = jni_fn!(env, GetArrayLengthFn, JNI_GET_ARRAY_LENGTH);
    let get_arr_elem: GetObjectArrayElementFn =
        jni_fn!(env, GetObjectArrayElementFn, JNI_GET_OBJECT_ARRAY_ELEMENT);

    let instances_arr = if is_2d {
        let inner = get_arr_elem(env, raw_result, 0);
        delete_local_ref(env, raw_result);
        if inner.is_null() || jni_check_exc(env) {
            delete_local_ref(env, target_cls);
            return Err("result[0] is null".to_string());
        }
        inner
    } else {
        raw_result
    };

    let len = get_arr_len(env, instances_arr);
    if jni_check_exc(env) || len < 0 {
        delete_local_ref(env, instances_arr);
        delete_local_ref(env, target_cls);
        return Err("GetArrayLength failed".to_string());
    }

    let new_global_ref: NewGlobalRefFn = jni_fn!(env, NewGlobalRefFn, JNI_NEW_GLOBAL_REF);

    let cap = if max_count == 0 { i32::MAX } else { max_count as i32 };
    let arr = ffi::JS_NewArray(ctx);
    let mut out_idx: u32 = 0;
    for i in 0..len.min(cap) {
        let inst = get_arr_elem(env, instances_arr, i);
        if inst.is_null() {
            jni_check_exc(env);
            continue;
        }
        let g = new_global_ref(env, inst);
        delete_local_ref(env, inst);
        if g.is_null() {
            jni_check_exc(env);
            continue;
        }
        let wrapper = ffi::JS_NewObject(ctx);
        set_js_u64_property(ctx, wrapper, "__jptr", g as u64);
        JSValue(wrapper).set_property(ctx, "__jclass", JSValue::string(ctx, class_name));
        ffi::JS_SetPropertyUint32(ctx, arr, out_idx, wrapper);
        out_idx += 1;
    }
    // 已经截断到 cap 的话，剩余 local refs 也释掉
    for i in len.min(cap)..len {
        let inst = get_arr_elem(env, instances_arr, i);
        if !inst.is_null() {
            delete_local_ref(env, inst);
        }
    }

    delete_local_ref(env, instances_arr);
    delete_local_ref(env, target_cls);

    Ok(arr)
}

// ============================================================================
// 后端 B：直接扫描 ART 堆（Android 14+/API 36）
// ============================================================================

unsafe fn heap_scan_enumerate_js(
    ctx: *mut ffi::JSContext,
    env: JniEnv,
    class_name: &str,
    include_subtypes: bool,
    max_count: usize,
) -> Result<ffi::JSValue, String> {
    jni_check_exc(env);

    // 目标 class —— 必须用 global ref（find_class_safe 的 cache 即为 global）
    let target_cls = find_class_safe(env, class_name);
    if target_cls.is_null() {
        return Err(format!("class not found: {}", class_name));
    }

    // 把 local ref 升成真 global ref：heap_scan 的 DecodeGlobalJObject 会检查 IndirectRef tag
    let new_global_ref: NewGlobalRefFn = jni_fn!(env, NewGlobalRefFn, JNI_NEW_GLOBAL_REF);
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
    let delete_global_ref: DeleteGlobalRefFn =
        jni_fn!(env, DeleteGlobalRefFn, JNI_DELETE_GLOBAL_REF);

    let class_global = new_global_ref(env, target_cls);
    delete_local_ref(env, target_cls);
    if class_global.is_null() {
        return Err("NewGlobalRef(target_cls) failed".to_string());
    }

    let hits_result = heap_scan_enumerate_instances(env, class_global, include_subtypes, max_count);
    delete_global_ref(env, class_global);

    let hits = hits_result?;
    output_verbose(&format!(
        "[java.choose] heap-scan hits={} for {} (subtypes={})",
        hits.len(),
        class_name,
        include_subtypes
    ));

    // subtypes 模式下，命中的对象实际类可能是 needle 的某个子类。__jclass 字段需要回填
    // 真实类名而非 needle 名，否则 JS 侧 wrapper 会以为它是 needle 类型，调用子类特有方法时
    // 走错 method id。简化处理：subtypes 模式下用 needle 名（用户在 onMatch 里可以
    // `obj.getClass().getName()` 拿真实类）。Frida 行为也是用 needle wrapper。
    let arr = ffi::JS_NewArray(ctx);
    for (idx, jobj) in hits.iter().enumerate() {
        if jobj.is_null() {
            continue;
        }
        let wrapper = ffi::JS_NewObject(ctx);
        set_js_u64_property(ctx, wrapper, "__jptr", *jobj as u64);
        JSValue(wrapper).set_property(ctx, "__jclass", JSValue::string(ctx, class_name));
        ffi::JS_SetPropertyUint32(ctx, arr, idx as u32, wrapper);
    }

    Ok(arr)
}
