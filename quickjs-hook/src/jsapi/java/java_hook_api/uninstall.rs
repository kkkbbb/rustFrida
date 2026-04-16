use crate::ffi;
use crate::jsapi::callback_util::{extract_string_arg, with_registry, with_registry_mut};
use crate::jsapi::console::output_verbose;
use crate::value::JSValue;

use super::super::callback::*;
use super::super::jni_core::*;

pub(in crate::jsapi::java) unsafe extern "C" fn js_java_unhook(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 3 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Java.unhook() requires 3 arguments: class, method, signature\0".as_ptr() as *const _,
        );
    }

    let class_arg = JSValue(*argv);
    let method_arg = JSValue(*argv.add(1));
    let sig_arg = JSValue(*argv.add(2));

    let class_name = match extract_string_arg(ctx, class_arg, b"Java.unhook() first argument must be a string\0") {
        Ok(value) => value,
        Err(err) => return err,
    };

    let method_name = match extract_string_arg(ctx, method_arg, b"Java.unhook() second argument must be a string\0") {
        Ok(value) => value,
        Err(err) => return err,
    };

    let sig_str = match extract_string_arg(ctx, sig_arg, b"Java.unhook() third argument must be a string\0") {
        Ok(value) => value,
        Err(err) => return err,
    };

    let actual_sig = if let Some(stripped) = sig_str.strip_prefix("static:") {
        stripped.to_string()
    } else {
        sig_str
    };

    let key = method_key(&class_name, &method_name, &actual_sig);
    let art_method_addr = with_registry(&JAVA_HOOK_REGISTRY, |registry| {
        registry.iter().find(|(_, v)| v.method_key == key).map(|(k, _)| *k)
    })
    .flatten();

    let art_method_addr = match art_method_addr {
        Some(am) => am,
        None => {
            return ffi::JS_ThrowInternalError(ctx, b"method not hooked\0".as_ptr() as *const _);
        }
    };

    let hook_data = with_registry_mut(&JAVA_HOOK_REGISTRY, |registry| registry.remove(&art_method_addr)).flatten();

    let hook_data = match hook_data {
        Some(d) => d,
        None => {
            return ffi::JS_ThrowInternalError(ctx, b"method not hooked\0".as_ptr() as *const _);
        }
    };

    output_verbose(&format!(
        "[java unhook] 开始: art_method={:#x}, type={:?}",
        hook_data.art_method, hook_data.hook_type
    ));

    // Step 1: 删除 art_router 映射，切断路由
    delete_replacement_method(hook_data.art_method);

    // Step 2: 移除 Layer 3 per-method hook + stealth2 revert
    super::super::remove_per_method_hook(&hook_data);

    // Step 3: 恢复 ArtMethod 原始字段
    super::super::restore_art_method_fields(&hook_data);

    // Step 4: 移除 native trampoline
    super::super::remove_native_trampoline(&hook_data);

    // Step 5: 等待 in-flight callbacks 自然退出
    if !wait_for_in_flight_java_hook_callbacks(std::time::Duration::from_millis(200)) {
        output_verbose(&format!(
            "[java unhook] 等待 in-flight callbacks 超时，remaining={}",
            in_flight_java_hook_callbacks()
        ));
    }

    // Step 6: 释放资源
    let env_opt = get_thread_env().ok();
    super::super::free_java_hook_resources(&hook_data, env_opt);

    output_verbose(&format!(
        "[java unhook] 完成: {}.{}{}",
        class_name, method_name, actual_sig
    ));

    JSValue::bool(true).raw()
}
