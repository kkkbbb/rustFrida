use crate::ffi;
use crate::jsapi::callback_util::{throw_internal_error, with_registry_mut};
use crate::jsapi::console::output_message;
use crate::value::JSValue;
use std::collections::HashMap;
use std::ffi::{c_void, CString};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use super::super::art_controller::refresh_walkstack_sigsegv_guard;
use super::super::art_method::*;
use super::super::callback::*;
use super::super::java_fast_api::{compile_art_method_to_quick, RequestedCompileKind};
use super::super::jni_core::*;
use super::super::reflect::{decode_method_id, find_class_safe, get_app_classloader_local_ref};
use super::install_support::{create_class_global_ref, update_original_method_flags_for_hook, JavaHookInstallGuard};
use super::managed_dex_builder::{
    build_java_worker_dex, build_managed_dsl_dex, GeneratedCounter, GeneratedMessageChannel, GeneratedStringLiteral,
    MANAGED_MESSAGE_CAPACITY, MANAGED_MESSAGE_CODES_FIELD, MANAGED_MESSAGE_DROPPED_FIELD, MANAGED_MESSAGE_HEAD_FIELD,
    MANAGED_MESSAGE_TAIL_FIELD, MANAGED_MESSAGE_TEXTS_FIELD, MANAGED_MESSAGE_VALUES_FIELD,
};

struct DynamicManagedHelperRefs {
    class_name: String,
    class_global_ref: u64,
    loader_global_ref: u64,
    dex_bytes: Vec<u8>,
    natives_registered: bool,
}

static DYNAMIC_MANAGED_HELPER_REFS: Mutex<Vec<DynamicManagedHelperRefs>> = Mutex::new(Vec::new());
static DYNAMIC_MANAGED_CLASS_ID: AtomicU64 = AtomicU64::new(1);
static JAVA_WORKER_STARTED: AtomicBool = AtomicBool::new(false);
static JAVA_WORKER_THREAD_GLOBAL: Mutex<Option<u64>> = Mutex::new(None);
static NATIVE_MANAGED_COUNTERS: OnceLock<Mutex<HashMap<(String, String), Box<AtomicU64>>>> = OnceLock::new();

fn shared_entrypoint_name(entry_point: u64, bridge: &ArtBridgeFunctions) -> &'static str {
    if entry_point == bridge.nterp_entry_point {
        "nterp_entry_point"
    } else if entry_point == bridge.nterp_with_clinit_entry_point {
        "nterp_with_clinit_entry_point"
    } else if entry_point == bridge.resolved_interpreter_bridge_entrypoint
        || entry_point == bridge.quick_to_interpreter_bridge
    {
        "quick_to_interpreter_bridge"
    } else if entry_point == bridge.resolved_resolution_entrypoint || entry_point == bridge.quick_resolution_trampoline
    {
        "quick_resolution_trampoline"
    } else if entry_point == bridge.resolved_jni_entrypoint || entry_point == bridge.quick_generic_jni_trampoline {
        "quick_generic_jni_trampoline"
    } else if entry_point == bridge.quick_imt_conflict_trampoline {
        "quick_imt_conflict_trampoline"
    } else {
        "shared ART entrypoint"
    }
}

unsafe fn ensure_dsl_target_has_independent_quick_code(
    env: JniEnv,
    class_name: &str,
    method_name: &str,
    sig: &str,
    art_method: u64,
) -> Result<(), String> {
    let spec = get_art_method_spec(env, art_method);
    let entry_point = read_entry_point(art_method, spec.entry_point_offset);
    let bridge = find_art_bridge_functions(env, spec.entry_point_offset);
    if !is_code_pointer(entry_point) {
        return Err(format!(
            "DSL hook requires compiled/JIT quick code for {}.{}{}, but entry_point is not executable (ArtMethod={:#x}, entry={:#x}). Try Java.compileMethod(\"{}\", \"{}\", \"{}\", \"auto\") first.",
            class_name, method_name, sig, art_method, entry_point, class_name, method_name, sig
        ));
    }
    if is_art_quick_entrypoint(entry_point, bridge) {
        return Err(format!(
            "DSL hook only supports compiled/JIT quick entrypoints. {}.{}{} currently uses {} ({:#x}); not installing the nterp/shared-entry router. Call Java.compileMethod(\"{}\", \"{}\", \"{}\", \"auto\") or Java.use(\"{}\").{}.overload(\"{}\").opt() first, then install dslImpl again.",
            class_name,
            method_name,
            sig,
            shared_entrypoint_name(entry_point, bridge),
            entry_point,
            class_name,
            method_name,
            sig,
            class_name,
            method_name,
            sig
        ));
    }
    Ok(())
}

unsafe fn jni_failure_with_exception(env: JniEnv, context: &str) -> String {
    match jni_take_exception(env) {
        Some(exc) if !exc.is_empty() => format!("{}: {}", context, exc),
        _ => context.to_string(),
    }
}

fn native_counter_registry() -> &'static Mutex<HashMap<(String, String), Box<AtomicU64>>> {
    NATIVE_MANAGED_COUNTERS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn install_native_counter_ptrs(helper_class: &str, counter_fields: &[String]) -> Vec<*mut u64> {
    let mut registry = native_counter_registry().lock().unwrap_or_else(|e| e.into_inner());
    let mut ptrs = Vec::with_capacity(counter_fields.len());
    for field_name in counter_fields {
        let counter = registry
            .entry((helper_class.to_string(), field_name.clone()))
            .or_insert_with(|| Box::new(AtomicU64::new(0)));
        ptrs.push(counter.as_ref() as *const AtomicU64 as *mut u64);
    }
    ptrs
}

fn read_native_counter(helper_class: &str, field_name: &str) -> Option<u64> {
    let registry = NATIVE_MANAGED_COUNTERS.get()?;
    let registry = registry.lock().unwrap_or_else(|e| e.into_inner());
    registry.iter().find_map(|((class, field), counter)| {
        if class == helper_class && field == field_name {
            Some(counter.load(Ordering::Relaxed))
        } else {
            None
        }
    })
}

pub fn managed_native_counter_value(helper_class: &str, field_name: &str) -> Option<u64> {
    read_native_counter(helper_class, field_name)
}

unsafe fn load_dynamic_managed_helper_class(
    env: JniEnv,
    dex_bytes: Vec<u8>,
    helper_class_name: &str,
) -> Result<*mut std::ffi::c_void, String> {
    let slot_index = {
        let mut refs = DYNAMIC_MANAGED_HELPER_REFS.lock().unwrap_or_else(|e| e.into_inner());
        let idx = refs.len();
        refs.push(DynamicManagedHelperRefs {
            class_name: helper_class_name.to_string(),
            class_global_ref: 0,
            loader_global_ref: 0,
            dex_bytes,
            natives_registered: false,
        });
        idx
    };

    let (dex_ptr, dex_len) = {
        let refs = DYNAMIC_MANAGED_HELPER_REFS.lock().unwrap_or_else(|e| e.into_inner());
        let dex = &refs[slot_index].dex_bytes;
        (dex.as_ptr() as *mut std::ffi::c_void, dex.len() as i64)
    };

    let find_loader_cls = find_class_safe(env, "dalvik/system/InMemoryDexClassLoader");
    if find_loader_cls.is_null() {
        return Err("InMemoryDexClassLoader class not found".to_string());
    }

    let get_mid: GetMethodIdFn = jni_fn!(env, GetMethodIdFn, JNI_GET_METHOD_ID);
    let new_object: NewObjectAFn = jni_fn!(env, NewObjectAFn, JNI_NEW_OBJECT_A);
    let new_direct: NewDirectByteBufferFn = jni_fn!(env, NewDirectByteBufferFn, JNI_NEW_DIRECT_BYTE_BUFFER);
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
    let new_global_ref: NewGlobalRefFn = jni_fn!(env, NewGlobalRefFn, JNI_NEW_GLOBAL_REF);
    let call_obj: CallObjectMethodAFn = jni_fn!(env, CallObjectMethodAFn, JNI_CALL_OBJECT_METHOD_A);
    let new_string_utf: NewStringUtfFn = jni_fn!(env, NewStringUtfFn, JNI_NEW_STRING_UTF);

    let ctor_name = CString::new("<init>").unwrap();
    let ctor_sig = CString::new("(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V").unwrap();
    let ctor = get_mid(env, find_loader_cls, ctor_name.as_ptr(), ctor_sig.as_ptr());
    if ctor.is_null() {
        let err = jni_failure_with_exception(
            env,
            "InMemoryDexClassLoader(ByteBuffer, ClassLoader) constructor not found",
        );
        delete_local_ref(env, find_loader_cls);
        return Err(err);
    }
    if let Some(exc) = jni_take_exception(env) {
        delete_local_ref(env, find_loader_cls);
        return Err(format!(
            "InMemoryDexClassLoader(ByteBuffer, ClassLoader) constructor lookup failed: {}",
            exc
        ));
    }

    let dex_buf = new_direct(env, dex_ptr, dex_len);
    if dex_buf.is_null() {
        let err = jni_failure_with_exception(env, "NewDirectByteBuffer for dynamic managed dex failed");
        delete_local_ref(env, find_loader_cls);
        return Err(err);
    }
    if let Some(exc) = jni_take_exception(env) {
        delete_local_ref(env, find_loader_cls);
        return Err(format!("NewDirectByteBuffer for dynamic managed dex failed: {}", exc));
    }

    let parent_loader = get_app_classloader_local_ref(env);
    let args = [dex_buf as u64, parent_loader as u64];
    let loader = new_object(env, find_loader_cls, ctor, args.as_ptr() as *const std::ffi::c_void);
    if loader.is_null() {
        let err = jni_failure_with_exception(env, "new dynamic InMemoryDexClassLoader failed");
        if !parent_loader.is_null() {
            delete_local_ref(env, parent_loader);
        }
        delete_local_ref(env, dex_buf);
        delete_local_ref(env, find_loader_cls);
        return Err(err);
    }
    if let Some(exc) = jni_take_exception(env) {
        if !parent_loader.is_null() {
            delete_local_ref(env, parent_loader);
        }
        delete_local_ref(env, dex_buf);
        delete_local_ref(env, find_loader_cls);
        return Err(format!("new dynamic InMemoryDexClassLoader failed: {}", exc));
    }

    let class_loader_cls = find_class_safe(env, "java/lang/ClassLoader");
    if class_loader_cls.is_null() {
        delete_local_ref(env, loader);
        if !parent_loader.is_null() {
            delete_local_ref(env, parent_loader);
        }
        delete_local_ref(env, dex_buf);
        delete_local_ref(env, find_loader_cls);
        return Err("java.lang.ClassLoader class not found".to_string());
    }
    let load_name = CString::new("loadClass").unwrap();
    let load_sig = CString::new("(Ljava/lang/String;)Ljava/lang/Class;").unwrap();
    let load_mid = get_mid(env, class_loader_cls, load_name.as_ptr(), load_sig.as_ptr());
    if load_mid.is_null() {
        let err = jni_failure_with_exception(env, "ClassLoader.loadClass method not found");
        delete_local_ref(env, class_loader_cls);
        delete_local_ref(env, loader);
        if !parent_loader.is_null() {
            delete_local_ref(env, parent_loader);
        }
        delete_local_ref(env, dex_buf);
        delete_local_ref(env, find_loader_cls);
        return Err(err);
    }
    if let Some(exc) = jni_take_exception(env) {
        delete_local_ref(env, class_loader_cls);
        delete_local_ref(env, loader);
        if !parent_loader.is_null() {
            delete_local_ref(env, parent_loader);
        }
        delete_local_ref(env, dex_buf);
        delete_local_ref(env, find_loader_cls);
        return Err(format!("ClassLoader.loadClass lookup failed: {}", exc));
    }

    let helper_name = CString::new(helper_class_name).map_err(|_| "invalid helper class name".to_string())?;
    let helper_jstr = new_string_utf(env, helper_name.as_ptr());
    if helper_jstr.is_null() {
        let err = jni_failure_with_exception(env, "NewStringUTF for dynamic helper class failed");
        delete_local_ref(env, class_loader_cls);
        delete_local_ref(env, loader);
        if !parent_loader.is_null() {
            delete_local_ref(env, parent_loader);
        }
        delete_local_ref(env, dex_buf);
        delete_local_ref(env, find_loader_cls);
        return Err(err);
    }
    if let Some(exc) = jni_take_exception(env) {
        delete_local_ref(env, class_loader_cls);
        delete_local_ref(env, loader);
        if !parent_loader.is_null() {
            delete_local_ref(env, parent_loader);
        }
        delete_local_ref(env, dex_buf);
        delete_local_ref(env, find_loader_cls);
        return Err(format!("NewStringUTF for dynamic helper class failed: {}", exc));
    }
    let load_args = [helper_jstr as u64];
    let helper_cls = call_obj(env, loader, load_mid, load_args.as_ptr() as *const std::ffi::c_void);
    delete_local_ref(env, helper_jstr);
    if helper_cls.is_null() {
        let err = jni_failure_with_exception(env, "dynamic managed helper loadClass failed");
        delete_local_ref(env, class_loader_cls);
        delete_local_ref(env, loader);
        if !parent_loader.is_null() {
            delete_local_ref(env, parent_loader);
        }
        delete_local_ref(env, dex_buf);
        delete_local_ref(env, find_loader_cls);
        return Err(err);
    }
    if let Some(exc) = jni_take_exception(env) {
        delete_local_ref(env, class_loader_cls);
        delete_local_ref(env, loader);
        if !parent_loader.is_null() {
            delete_local_ref(env, parent_loader);
        }
        delete_local_ref(env, dex_buf);
        delete_local_ref(env, find_loader_cls);
        return Err(format!("dynamic managed helper loadClass failed: {}", exc));
    }

    let helper_global = new_global_ref(env, helper_cls);
    let loader_global = new_global_ref(env, loader);
    if helper_global.is_null() || loader_global.is_null() {
        let err = jni_failure_with_exception(env, "dynamic helper global ref creation failed");
        delete_local_ref(env, helper_cls);
        delete_local_ref(env, class_loader_cls);
        delete_local_ref(env, loader);
        if !parent_loader.is_null() {
            delete_local_ref(env, parent_loader);
        }
        delete_local_ref(env, dex_buf);
        delete_local_ref(env, find_loader_cls);
        return Err(err);
    }
    if let Some(exc) = jni_take_exception(env) {
        delete_local_ref(env, helper_cls);
        delete_local_ref(env, class_loader_cls);
        delete_local_ref(env, loader);
        if !parent_loader.is_null() {
            delete_local_ref(env, parent_loader);
        }
        delete_local_ref(env, dex_buf);
        delete_local_ref(env, find_loader_cls);
        return Err(format!("dynamic helper global ref creation failed: {}", exc));
    }

    {
        let mut refs = DYNAMIC_MANAGED_HELPER_REFS.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(slot) = refs.get_mut(slot_index) {
            slot.class_global_ref = helper_global as u64;
            slot.loader_global_ref = loader_global as u64;
        }
    }

    delete_local_ref(env, class_loader_cls);
    delete_local_ref(env, loader);
    if !parent_loader.is_null() {
        delete_local_ref(env, parent_loader);
    }
    delete_local_ref(env, dex_buf);
    delete_local_ref(env, find_loader_cls);

    Ok(helper_cls)
}

pub(crate) unsafe fn start_java_worker_thread(native_loop: *mut c_void) -> Result<(), String> {
    if native_loop.is_null() {
        return Err("java worker native loop pointer is null".to_string());
    }
    if JAVA_WORKER_STARTED.load(Ordering::Acquire) {
        return Ok(());
    }

    let env = ensure_jni_initialized()?;
    let class_id = DYNAMIC_MANAGED_CLASS_ID.fetch_add(1, Ordering::Relaxed);
    let generated = build_java_worker_dex(class_id)?;
    output_message(&format!(
        "[java worker] generated dex class={} size={}",
        generated.class_name,
        generated.dex.len()
    ));
    let worker_cls = load_dynamic_managed_helper_class(env, generated.dex, &generated.class_name)?;
    output_message("[java worker] helper class loaded");

    let register_natives: RegisterNativesFn = jni_fn!(env, RegisterNativesFn, JNI_REGISTER_NATIVES);
    let native_name = CString::new("nativeLoop").unwrap();
    let native_sig = CString::new("()Z").unwrap();
    let methods = [JniNativeMethod {
        name: native_name.as_ptr(),
        signature: native_sig.as_ptr(),
        fn_ptr: native_loop,
    }];
    if register_natives(env, worker_cls, methods.as_ptr(), methods.len() as i32) != 0 {
        return Err(jni_failure_with_exception(
            env,
            "RegisterNatives failed for Java worker nativeLoop",
        ));
    }
    if let Some(exc) = jni_take_exception(env) {
        return Err(format!("RegisterNatives failed for Java worker nativeLoop: {}", exc));
    }
    output_message("[java worker] nativeLoop registered");

    let get_mid: GetMethodIdFn = jni_fn!(env, GetMethodIdFn, JNI_GET_METHOD_ID);
    let new_object: NewObjectAFn = jni_fn!(env, NewObjectAFn, JNI_NEW_OBJECT_A);
    let call_void: CallVoidMethodAFn = jni_fn!(env, CallVoidMethodAFn, JNI_CALL_VOID_METHOD_A);
    let new_global_ref: NewGlobalRefFn = jni_fn!(env, NewGlobalRefFn, JNI_NEW_GLOBAL_REF);
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);

    let ctor_name = CString::new("<init>").unwrap();
    let ctor_sig = CString::new("()V").unwrap();
    let ctor = get_mid(env, worker_cls, ctor_name.as_ptr(), ctor_sig.as_ptr());
    if ctor.is_null() {
        return Err(jni_failure_with_exception(env, "Java worker constructor not found"));
    }
    if let Some(exc) = jni_take_exception(env) {
        return Err(format!("Java worker constructor lookup failed: {}", exc));
    }

    let worker = new_object(env, worker_cls, ctor, std::ptr::null());
    if worker.is_null() {
        return Err(jni_failure_with_exception(env, "new Java worker thread failed"));
    }
    if let Some(exc) = jni_take_exception(env) {
        return Err(format!("new Java worker thread failed: {}", exc));
    }
    output_message("[java worker] thread object created");

    let thread_cls = find_class_safe(env, "java/lang/Thread");
    if thread_cls.is_null() {
        delete_local_ref(env, worker);
        return Err("java.lang.Thread class not found".to_string());
    }
    let start_name = CString::new("start").unwrap();
    let start_sig = CString::new("()V").unwrap();
    let start_mid = get_mid(env, thread_cls, start_name.as_ptr(), start_sig.as_ptr());
    if start_mid.is_null() {
        let err = jni_failure_with_exception(env, "Thread.start method not found");
        delete_local_ref(env, thread_cls);
        delete_local_ref(env, worker);
        return Err(err);
    }
    if let Some(exc) = jni_take_exception(env) {
        delete_local_ref(env, thread_cls);
        delete_local_ref(env, worker);
        return Err(format!("Thread.start method lookup failed: {}", exc));
    }

    let worker_global = new_global_ref(env, worker);
    if worker_global.is_null() {
        let err = jni_failure_with_exception(env, "Java worker global ref creation failed");
        delete_local_ref(env, thread_cls);
        delete_local_ref(env, worker);
        return Err(err);
    }
    if let Some(exc) = jni_take_exception(env) {
        delete_local_ref(env, thread_cls);
        delete_local_ref(env, worker);
        return Err(format!("Java worker global ref creation failed: {}", exc));
    }

    output_message("[java worker] calling Thread.start");
    call_void(env, worker, start_mid, std::ptr::null());
    delete_local_ref(env, thread_cls);
    delete_local_ref(env, worker);
    if let Some(exc) = jni_take_exception(env) {
        return Err(format!("Thread.start failed for Java worker: {}", exc));
    }

    *JAVA_WORKER_THREAD_GLOBAL.lock().unwrap_or_else(|e| e.into_inner()) = Some(worker_global as u64);
    JAVA_WORKER_STARTED.store(true, Ordering::Release);
    output_message(&format!(
        "[java worker] started ART-managed worker class={}",
        generated.class_name
    ));
    Ok(())
}

pub(crate) unsafe fn finish_java_worker_thread_from_native(env: JniEnv, worker_cls: *mut c_void) -> Result<(), String> {
    if env.is_null() || worker_cls.is_null() {
        return Err("Java worker native release received null JNI arguments".to_string());
    }
    let worker = {
        let guard = JAVA_WORKER_THREAD_GLOBAL.lock().unwrap_or_else(|e| e.into_inner());
        match *guard {
            Some(worker) => worker as *mut c_void,
            None => {
                JAVA_WORKER_STARTED.store(false, Ordering::Release);
                return Ok(());
            }
        }
    };

    let delete_global_ref: DeleteGlobalRefFn = jni_fn!(env, DeleteGlobalRefFn, JNI_DELETE_GLOBAL_REF);
    let unregister_natives: UnregisterNativesFn = jni_fn!(env, UnregisterNativesFn, JNI_UNREGISTER_NATIVES);

    let managed_helpers: Vec<(String, u64)> = {
        let refs = DYNAMIC_MANAGED_HELPER_REFS.lock().unwrap_or_else(|e| e.into_inner());
        refs.iter()
            .filter(|slot| slot.natives_registered && slot.class_global_ref != 0)
            .map(|slot| (slot.class_name.clone(), slot.class_global_ref))
            .collect()
    };
    for (class_name, class_ref) in &managed_helpers {
        if unregister_natives(env, *class_ref as *mut c_void) != 0 {
            return Err(jni_failure_with_exception(
                env,
                &format!("UnregisterNatives failed for managed helper {}", class_name),
            ));
        }
        if let Some(exc) = jni_take_exception(env) {
            return Err(format!(
                "UnregisterNatives failed for managed helper {}: {}",
                class_name, exc
            ));
        }
    }
    if !managed_helpers.is_empty() {
        let mut refs = DYNAMIC_MANAGED_HELPER_REFS.lock().unwrap_or_else(|e| e.into_inner());
        for slot in refs.iter_mut() {
            if managed_helpers
                .iter()
                .any(|(_, class_ref)| *class_ref == slot.class_global_ref)
            {
                slot.natives_registered = false;
            }
        }
        output_message(&format!(
            "[java worker] removed native bindings from {} managed helper class(es)",
            managed_helpers.len()
        ));
    }

    if unregister_natives(env, worker_cls) != 0 {
        return Err(jni_failure_with_exception(
            env,
            "UnregisterNatives failed for Java worker",
        ));
    }
    if let Some(exc) = jni_take_exception(env) {
        return Err(format!("UnregisterNatives failed for Java worker: {}", exc));
    }

    delete_global_ref(env, worker);
    *JAVA_WORKER_THREAD_GLOBAL.lock().unwrap_or_else(|e| e.into_inner()) = None;
    JAVA_WORKER_STARTED.store(false, Ordering::Release);
    output_message("[java worker] stopped and native binding removed");
    Ok(())
}

fn find_dynamic_managed_helper_class(class_name: &str) -> Option<*mut std::ffi::c_void> {
    let refs = DYNAMIC_MANAGED_HELPER_REFS.lock().unwrap_or_else(|e| e.into_inner());
    refs.iter()
        .find(|slot| slot.class_name == class_name && slot.class_global_ref != 0)
        .map(|slot| slot.class_global_ref as *mut std::ffi::c_void)
}

unsafe fn initialize_generated_string_literals(
    env: JniEnv,
    helper_cls: *mut std::ffi::c_void,
    literals: &[GeneratedStringLiteral],
) -> Result<(), String> {
    if literals.is_empty() {
        return Ok(());
    }

    let get_static_field_id: GetStaticFieldIdFn = jni_fn!(env, GetStaticFieldIdFn, JNI_GET_STATIC_FIELD_ID);
    type SetStaticObjectFieldFn =
        unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, *mut std::ffi::c_void);
    let set_static_object_field: SetStaticObjectFieldFn =
        jni_fn!(env, SetStaticObjectFieldFn, JNI_SET_STATIC_OBJECT_FIELD);
    let new_string_utf: NewStringUtfFn = jni_fn!(env, NewStringUtfFn, JNI_NEW_STRING_UTF);
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
    let string_sig = CString::new("Ljava/lang/String;").unwrap();

    for lit in literals {
        let field_name = CString::new(lit.field_name.as_str())
            .map_err(|_| format!("invalid generated string field name {}", lit.field_name))?;
        let field_id = get_static_field_id(env, helper_cls, field_name.as_ptr(), string_sig.as_ptr());
        if jni_null_or_exc(env, field_id) {
            return Err(format!("generated string field {} not found", lit.field_name));
        }

        let value = CString::new(lit.value.as_str())
            .map_err(|_| format!("string literal for {} contains NUL byte", lit.field_name))?;
        let jstr = new_string_utf(env, value.as_ptr());
        if jni_null_or_exc(env, jstr) {
            return Err(format!(
                "NewStringUTF failed for generated string field {}",
                lit.field_name
            ));
        }
        set_static_object_field(env, helper_cls, field_id, jstr);
        delete_local_ref(env, jstr);
        if jni_check_exc(env) {
            return Err(format!(
                "SetStaticObjectField failed for generated string field {}",
                lit.field_name
            ));
        }
    }
    output_message(&format!(
        "[managedHook] initialized {} generated string literal field(s)",
        literals.len()
    ));
    Ok(())
}

unsafe fn initialize_generated_message_queue(
    env: JniEnv,
    helper_cls: *mut std::ffi::c_void,
    channels: &[GeneratedMessageChannel],
    capacity: i32,
) -> Result<(), String> {
    if channels.is_empty() {
        return Ok(());
    }

    let get_static_field_id: GetStaticFieldIdFn = jni_fn!(env, GetStaticFieldIdFn, JNI_GET_STATIC_FIELD_ID);
    type SetStaticObjectFieldFn =
        unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, *mut std::ffi::c_void);
    let set_static_object_field: SetStaticObjectFieldFn =
        jni_fn!(env, SetStaticObjectFieldFn, JNI_SET_STATIC_OBJECT_FIELD);
    let set_static_int_field: SetStaticIntFieldFn = jni_fn!(env, SetStaticIntFieldFn, JNI_SET_STATIC_INT_FIELD);
    let new_int_array: NewPrimitiveArrayFn = jni_fn!(env, NewPrimitiveArrayFn, JNI_NEW_INT_ARRAY);
    let new_object_array: NewObjectArrayFn = jni_fn!(env, NewObjectArrayFn, JNI_NEW_OBJECT_ARRAY);
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);

    let int_sig = CString::new("I").unwrap();
    for field in [
        MANAGED_MESSAGE_HEAD_FIELD,
        MANAGED_MESSAGE_TAIL_FIELD,
        MANAGED_MESSAGE_DROPPED_FIELD,
    ] {
        let name = CString::new(field).unwrap();
        let fid = get_static_field_id(env, helper_cls, name.as_ptr(), int_sig.as_ptr());
        if jni_null_or_exc(env, fid) {
            return Err(format!("generated message field {} not found", field));
        }
        set_static_int_field(env, helper_cls, fid, 0);
        if jni_check_exc(env) {
            return Err(format!(
                "SetStaticIntField failed for generated message field {}",
                field
            ));
        }
    }

    let int_array_sig = CString::new("[I").unwrap();
    for field in [MANAGED_MESSAGE_CODES_FIELD, MANAGED_MESSAGE_VALUES_FIELD] {
        let name = CString::new(field).unwrap();
        let fid = get_static_field_id(env, helper_cls, name.as_ptr(), int_array_sig.as_ptr());
        if jni_null_or_exc(env, fid) {
            return Err(format!("generated message array field {} not found", field));
        }
        let array = new_int_array(env, capacity);
        if jni_null_or_exc(env, array) {
            return Err(format!("NewIntArray failed for generated message array {}", field));
        }
        set_static_object_field(env, helper_cls, fid, array);
        delete_local_ref(env, array);
        if jni_check_exc(env) {
            return Err(format!(
                "SetStaticObjectField failed for generated message array {}",
                field
            ));
        }
    }

    let string_array_sig = CString::new("[Ljava/lang/String;").unwrap();
    let string_array_name = CString::new(MANAGED_MESSAGE_TEXTS_FIELD).unwrap();
    let string_array_fid = get_static_field_id(env, helper_cls, string_array_name.as_ptr(), string_array_sig.as_ptr());
    if jni_null_or_exc(env, string_array_fid) {
        return Err(format!(
            "generated message array field {} not found",
            MANAGED_MESSAGE_TEXTS_FIELD
        ));
    }
    let string_cls = find_class_safe(env, "java.lang.String");
    if jni_null_or_exc(env, string_cls) {
        return Err("java.lang.String class not found for generated message text array".to_string());
    }
    let string_array = new_object_array(env, capacity, string_cls, std::ptr::null_mut());
    delete_local_ref(env, string_cls);
    if jni_null_or_exc(env, string_array) {
        return Err(format!(
            "NewObjectArray failed for generated message array {}",
            MANAGED_MESSAGE_TEXTS_FIELD
        ));
    }
    set_static_object_field(env, helper_cls, string_array_fid, string_array);
    delete_local_ref(env, string_array);
    if jni_check_exc(env) {
        return Err(format!(
            "SetStaticObjectField failed for generated message array {}",
            MANAGED_MESSAGE_TEXTS_FIELD
        ));
    }

    output_message(&format!(
        "[managedHook] initialized message queue capacity={} channel(s)={}",
        capacity,
        channels.len(),
    ));
    Ok(())
}

unsafe fn direct_buffer_range(env: JniEnv, buffer: *mut c_void, offset: i32, length: i32) -> Option<(*mut u8, usize)> {
    if buffer.is_null() || offset < 0 || length <= 0 {
        return None;
    }
    let get_address: GetDirectBufferAddressFn = jni_fn!(env, GetDirectBufferAddressFn, JNI_GET_DIRECT_BUFFER_ADDRESS);
    let get_capacity: GetDirectBufferCapacityFn =
        jni_fn!(env, GetDirectBufferCapacityFn, JNI_GET_DIRECT_BUFFER_CAPACITY);
    let base = get_address(env, buffer) as *mut u8;
    let capacity = get_capacity(env, buffer);
    let range_failed = {
        let had_exc = jni_check_exc(env);
        base.is_null() || capacity <= 0 || had_exc
    };
    if range_failed {
        return None;
    }
    let offset = offset as i64;
    if offset >= capacity {
        return None;
    }
    let available = capacity - offset;
    let len = std::cmp::min(length as i64, available) as usize;
    if len == 0 {
        return None;
    }
    Some((base.add(offset as usize), len))
}

unsafe extern "C" fn managed_dbb_fill(
    env: JniEnv,
    _cls: *mut c_void,
    buffer: *mut c_void,
    offset: i32,
    length: i32,
    value: i32,
) -> i32 {
    let Some((dst, len)) = direct_buffer_range(env, buffer, offset, length) else {
        return 0;
    };
    std::ptr::write_bytes(dst, value as u8, len);
    len as i32
}

unsafe extern "C" fn managed_dbb_copy_from_byte_array(
    env: JniEnv,
    _cls: *mut c_void,
    buffer: *mut c_void,
    dst_offset: i32,
    src: *mut c_void,
    src_offset: i32,
    length: i32,
) -> i32 {
    if src.is_null() || src_offset < 0 || length <= 0 {
        return 0;
    }
    let get_array_length: GetArrayLengthFn = jni_fn!(env, GetArrayLengthFn, JNI_GET_ARRAY_LENGTH);
    let get_region: GetByteArrayRegionFn = jni_fn!(env, GetByteArrayRegionFn, JNI_GET_BYTE_ARRAY_REGION);
    let src_len = get_array_length(env, src);
    let src_len_failed = {
        let had_exc = jni_check_exc(env);
        src_len <= 0 || src_offset >= src_len || had_exc
    };
    if src_len_failed {
        return 0;
    }
    let Some((dst, dst_len)) = direct_buffer_range(env, buffer, dst_offset, length) else {
        return 0;
    };
    let src_available = src_len - src_offset;
    let len = std::cmp::min(dst_len, std::cmp::min(length, src_available) as usize);
    if len == 0 || len > i32::MAX as usize {
        return 0;
    }
    let mut tmp = vec![0i8; len];
    get_region(env, src, src_offset, len as i32, tmp.as_mut_ptr());
    if jni_check_exc(env) {
        return 0;
    }
    std::ptr::copy_nonoverlapping(tmp.as_ptr() as *const u8, dst, len);
    len as i32
}

unsafe extern "C" fn managed_dbb_copy_to_byte_array(
    env: JniEnv,
    _cls: *mut c_void,
    buffer: *mut c_void,
    src_offset: i32,
    dst: *mut c_void,
    dst_offset: i32,
    length: i32,
) -> i32 {
    if dst.is_null() || dst_offset < 0 || length <= 0 {
        return 0;
    }
    let get_array_length: GetArrayLengthFn = jni_fn!(env, GetArrayLengthFn, JNI_GET_ARRAY_LENGTH);
    let set_region: SetByteArrayRegionFn = jni_fn!(env, SetByteArrayRegionFn, JNI_SET_BYTE_ARRAY_REGION);
    let dst_len = get_array_length(env, dst);
    let dst_len_failed = {
        let had_exc = jni_check_exc(env);
        dst_len <= 0 || dst_offset >= dst_len || had_exc
    };
    if dst_len_failed {
        return 0;
    }
    let Some((src, src_len)) = direct_buffer_range(env, buffer, src_offset, length) else {
        return 0;
    };
    let dst_available = dst_len - dst_offset;
    let len = std::cmp::min(src_len, std::cmp::min(length, dst_available) as usize);
    if len == 0 || len > i32::MAX as usize {
        return 0;
    }
    set_region(env, dst, dst_offset, len as i32, src as *const i8);
    if jni_check_exc(env) {
        return 0;
    }
    len as i32
}

unsafe extern "C" fn managed_dbb_capacity(env: JniEnv, _cls: *mut c_void, buffer: *mut c_void) -> i32 {
    if buffer.is_null() {
        return -1;
    }
    let get_capacity: GetDirectBufferCapacityFn =
        jni_fn!(env, GetDirectBufferCapacityFn, JNI_GET_DIRECT_BUFFER_CAPACITY);
    let capacity = get_capacity(env, buffer);
    let capacity_failed = {
        let had_exc = jni_check_exc(env);
        capacity < 0 || had_exc
    };
    if capacity_failed {
        return -1;
    }
    std::cmp::min(capacity, i32::MAX as i64) as i32
}

unsafe extern "C" fn managed_dbb_get_u8(env: JniEnv, _cls: *mut c_void, buffer: *mut c_void, offset: i32) -> i32 {
    let Some((src, _len)) = direct_buffer_range(env, buffer, offset, 1) else {
        return -1;
    };
    *src as i32
}

unsafe extern "C" fn managed_reentry_guard_enter(_env: JniEnv, _cls: *mut c_void) {
    crate::ffi::hook::hook_managed_reentry_guard_enter();
}

unsafe extern "C" fn managed_reentry_guard_leave(_env: JniEnv, _cls: *mut c_void) {
    crate::ffi::hook::hook_managed_reentry_guard_leave();
}

unsafe fn register_managed_guard_helpers(env: JniEnv, helper_cls: *mut c_void) -> Result<(), String> {
    let register_natives: RegisterNativesFn = jni_fn!(env, RegisterNativesFn, JNI_REGISTER_NATIVES);
    let names = [
        CString::new("__rf_guard_enter").unwrap(),
        CString::new("__rf_guard_leave").unwrap(),
    ];
    let sigs = [CString::new("()V").unwrap(), CString::new("()V").unwrap()];
    let methods = [
        JniNativeMethod {
            name: names[0].as_ptr(),
            signature: sigs[0].as_ptr(),
            fn_ptr: managed_reentry_guard_enter as *mut c_void,
        },
        JniNativeMethod {
            name: names[1].as_ptr(),
            signature: sigs[1].as_ptr(),
            fn_ptr: managed_reentry_guard_leave as *mut c_void,
        },
    ];
    let register_result = register_natives(env, helper_cls, methods.as_ptr(), methods.len() as i32);
    let register_failed = {
        let had_exc = jni_check_exc(env);
        register_result != 0 || had_exc
    };
    if register_failed {
        return Err("RegisterNatives failed for managed reentrancy guard helpers".to_string());
    }
    Ok(())
}

fn mark_managed_helper_natives_registered(class_name: &str) {
    let mut refs = DYNAMIC_MANAGED_HELPER_REFS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(slot) = refs.iter_mut().find(|slot| slot.class_name == class_name) {
        slot.natives_registered = true;
    }
}

unsafe fn register_direct_buffer_helpers(env: JniEnv, helper_cls: *mut c_void) -> Result<(), String> {
    let register_natives: RegisterNativesFn = jni_fn!(env, RegisterNativesFn, JNI_REGISTER_NATIVES);
    let names = [
        CString::new("__rf_dbb_fill").unwrap(),
        CString::new("__rf_dbb_copy_from_byte_array").unwrap(),
        CString::new("__rf_dbb_copy_to_byte_array").unwrap(),
        CString::new("__rf_dbb_capacity").unwrap(),
        CString::new("__rf_dbb_get_u8").unwrap(),
    ];
    let sigs = [
        CString::new("(Ljava/nio/ByteBuffer;III)I").unwrap(),
        CString::new("(Ljava/nio/ByteBuffer;I[BII)I").unwrap(),
        CString::new("(Ljava/nio/ByteBuffer;I[BII)I").unwrap(),
        CString::new("(Ljava/nio/ByteBuffer;)I").unwrap(),
        CString::new("(Ljava/nio/ByteBuffer;I)I").unwrap(),
    ];
    let methods = [
        JniNativeMethod {
            name: names[0].as_ptr(),
            signature: sigs[0].as_ptr(),
            fn_ptr: managed_dbb_fill as *mut c_void,
        },
        JniNativeMethod {
            name: names[1].as_ptr(),
            signature: sigs[1].as_ptr(),
            fn_ptr: managed_dbb_copy_from_byte_array as *mut c_void,
        },
        JniNativeMethod {
            name: names[2].as_ptr(),
            signature: sigs[2].as_ptr(),
            fn_ptr: managed_dbb_copy_to_byte_array as *mut c_void,
        },
        JniNativeMethod {
            name: names[3].as_ptr(),
            signature: sigs[3].as_ptr(),
            fn_ptr: managed_dbb_capacity as *mut c_void,
        },
        JniNativeMethod {
            name: names[4].as_ptr(),
            signature: sigs[4].as_ptr(),
            fn_ptr: managed_dbb_get_u8 as *mut c_void,
        },
    ];
    let register_result = register_natives(env, helper_cls, methods.as_ptr(), methods.len() as i32);
    let register_failed = {
        let had_exc = jni_check_exc(env);
        register_result != 0 || had_exc
    };
    if register_failed {
        return Err("RegisterNatives failed for managed DirectByteBuffer helpers".to_string());
    }
    output_message("[managedHook] registered DirectByteBuffer native helpers");
    Ok(())
}

unsafe fn set_orig_backup_entrypoint(
    backup_art_method: u64,
    art_method_size: usize,
    access_flags_offset: usize,
    entry_point_offset: usize,
    entrypoint: u64,
) -> Result<(), String> {
    if backup_art_method == 0 || entrypoint == 0 {
        return Err("invalid managed orig backup entrypoint state".to_string());
    }
    if entry_point_offset + std::mem::size_of::<u64>() > art_method_size {
        return Err(format!(
            "invalid managed orig backup entrypoint layout: ep_offset={} size={}",
            entry_point_offset, art_method_size
        ));
    }
    if access_flags_offset + std::mem::size_of::<u32>() > art_method_size {
        return Err(format!(
            "invalid managed orig backup flags layout: flags_offset={} size={}",
            access_flags_offset, art_method_size
        ));
    }

    let flags = std::ptr::read_volatile((backup_art_method as usize + access_flags_offset) as *const u32);
    std::ptr::write_volatile(
        (backup_art_method as usize + access_flags_offset) as *mut u32,
        flags | k_acc_compile_dont_bother(),
    );
    std::ptr::write_volatile(
        (backup_art_method as usize + entry_point_offset) as *mut u64,
        entrypoint,
    );
    crate::ffi::hook::hook_flush_cache(backup_art_method as *mut std::ffi::c_void, art_method_size);
    output_message(&format!(
        "[managedHook] orig backup ArtMethod entrypoint -> stub {:#x}",
        entrypoint
    ));
    Ok(())
}

unsafe fn install_managed_method_helper(
    env: JniEnv,
    class_name: &str,
    method_name: &str,
    actual_sig: &str,
    resolved_art_method: Option<u64>,
    helper_cls: *mut std::ffi::c_void,
    helper_method_name_str: &str,
    helper_method_sig_str: &str,
    orig_backup_name_sig: Option<(&str, &str)>,
    label: &str,
    _uses_orig: bool,
) -> Result<(), String> {
    let art_method = if let Some(art_method) = resolved_art_method {
        art_method
    } else {
        resolve_art_method(env, class_name, method_name, actual_sig, false)?.0
    };

    init_java_registry();
    if crate::jsapi::callback_util::with_registry(&JAVA_HOOK_REGISTRY, |r| r.contains_key(&art_method)).unwrap_or(false)
    {
        return Err(format!(
            "{}.{}{} already hooked — unhook first",
            class_name, method_name, actual_sig
        ));
    }

    let get_static_mid: GetStaticMethodIdFn = jni_fn!(env, GetStaticMethodIdFn, JNI_GET_STATIC_METHOD_ID);
    let helper_method_sig = CString::new(helper_method_sig_str).unwrap();
    let helper_method_name = CString::new(helper_method_name_str).unwrap();
    let helper_method_id = get_static_mid(env, helper_cls, helper_method_name.as_ptr(), helper_method_sig.as_ptr());
    if jni_null_or_exc(env, helper_method_id) {
        let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
        delete_local_ref(env, helper_cls);
        return Err(format!("managed helper {} method not found", helper_method_name_str));
    }
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
    let helper_art_method = decode_method_id(env, helper_cls, helper_method_id as u64, true);
    if helper_art_method == 0 {
        delete_local_ref(env, helper_cls);
        return Err("managed helper ArtMethod decode failed".to_string());
    }
    let orig_backup_art_method = if let Some((backup_name_str, backup_sig_str)) = orig_backup_name_sig {
        let backup_name = CString::new(backup_name_str).unwrap();
        let backup_sig = CString::new(backup_sig_str).unwrap();
        let backup_method_id = get_static_mid(env, helper_cls, backup_name.as_ptr(), backup_sig.as_ptr());
        if jni_null_or_exc(env, backup_method_id) {
            delete_local_ref(env, helper_cls);
            return Err(format!("managed helper {} method not found", backup_name_str));
        }
        let art_method = decode_method_id(env, helper_cls, backup_method_id as u64, true);
        if art_method == 0 {
            delete_local_ref(env, helper_cls);
            return Err("managed helper orig backup ArtMethod decode failed".to_string());
        }
        Some(art_method)
    } else {
        None
    };
    let spec = get_art_method_spec(env, art_method);
    let ep_offset = spec.entry_point_offset;
    let data_off = spec.data_offset;
    let original_access_flags = std::ptr::read_volatile((art_method as usize + spec.access_flags_offset) as *const u32);
    let original_data = std::ptr::read_volatile((art_method as usize + data_off) as *const u64);
    let original_entry_point = read_entry_point(art_method, ep_offset);
    let bridge = find_art_bridge_functions(env, ep_offset);

    let original_is_shared_entrypoint = is_art_quick_entrypoint(original_entry_point, bridge);

    let helper_spec = get_art_method_spec(env, helper_art_method);
    let mut helper_entry_point = read_entry_point(helper_art_method, helper_spec.entry_point_offset);
    if is_art_quick_entrypoint(helper_entry_point, bridge) {
        let compile = compile_art_method_to_quick(
            env,
            helper_art_method,
            helper_spec.entry_point_offset,
            bridge,
            RequestedCompileKind::Auto,
        );
        output_message(&format!(
            "[managedHook] helper used shared ART entrypoint {:#x}; compile helper: success={} compiled={} kind={} message={}",
            helper_entry_point, compile.success, compile.compiled, compile.kind, compile.message
        ));
        helper_entry_point = read_entry_point(helper_art_method, helper_spec.entry_point_offset);
        if is_art_quick_entrypoint(helper_entry_point, bridge) {
            delete_local_ref(env, helper_cls);
            return Err(format!(
                "DSL helper did not compile to independent quick code: helper={}.{}{} entry={} ({:#x}); {}",
                label,
                helper_method_name_str,
                helper_method_sig_str,
                shared_entrypoint_name(helper_entry_point, bridge),
                helper_entry_point,
                compile.message
            ));
        }
    }
    let orig_bypass_art_method = art_method;
    let class_global_ref = create_class_global_ref(env, class_name)?;
    let mut install_guard = JavaHookInstallGuard::new(
        art_method,
        spec.access_flags_offset,
        data_off,
        ep_offset,
        original_access_flags,
        original_data,
        original_entry_point,
        class_global_ref,
    );

    if original_is_shared_entrypoint {
        delete_local_ref(env, helper_cls);
        return Err(format!(
            "DSL hook only supports compiled/JIT quick entrypoints. {}.{}{} currently uses {} ({:#x}); call Java.compileMethod(...) or MethodWrapper.opt() before installing dslImpl.",
            class_name,
            method_name,
            actual_sig,
            shared_entrypoint_name(original_entry_point, bridge),
            original_entry_point
        ));
    }

    update_original_method_flags_for_hook(art_method, spec.access_flags_offset, original_access_flags);
    install_guard.set_original_method_mutated();

    let (per_method_hook_target, quick_trampoline) = {
        let (hook_addr, stealth_flag, real_addr) =
            super::super::art_controller::prepare_hook_target(original_entry_point, env as *mut std::ffi::c_void)
                .map_err(|e| format!("prepare_hook_target: {}", e))?;
        let mut hooked_target: *mut std::ffi::c_void = std::ptr::null_mut();
        let quick_trampoline = crate::ffi::hook::hook_install_managed_direct_router(
            hook_addr as *mut std::ffi::c_void,
            stealth_flag,
            env as *mut std::ffi::c_void,
            &mut hooked_target,
            helper_art_method,
            helper_entry_point,
            orig_bypass_art_method,
            0,
        );
        if quick_trampoline.is_null() {
            delete_local_ref(env, helper_cls);
            return Err("hook_install_managed_direct_router failed".to_string());
        }
        super::super::art_controller::try_fixup_trampoline_pub(quick_trampoline, real_addr);
        if let Some(backup_art_method) = orig_backup_art_method {
            let orig_stub = crate::ffi::hook::hook_create_managed_orig_stub(art_method, quick_trampoline);
            if orig_stub.is_null() {
                delete_local_ref(env, helper_cls);
                return Err("hook_create_managed_orig_stub failed".to_string());
            }
            set_orig_backup_entrypoint(
                backup_art_method,
                spec.size,
                spec.access_flags_offset,
                ep_offset,
                orig_stub as u64,
            )?;
        }
        let per_method_hook_target = if !hooked_target.is_null() {
            Some(hooked_target as u64)
        } else {
            Some(hook_addr)
        };
        (per_method_hook_target, quick_trampoline as u64)
    };
    delete_local_ref(env, helper_cls);
    let use_blr = false;

    with_registry_mut(&JAVA_HOOK_REGISTRY, |registry| {
        registry.insert(
            art_method,
            JavaHookData {
                art_method,
                original_access_flags,
                original_entry_point,
                original_data,
                hook_type: HookType::Managed {
                    replacement_art_method: helper_art_method,
                    sentinel_addr: 0,
                    per_method_hook_target,
                },
                clone_addr: 0,
                class_global_ref,
                return_type: get_return_type_from_sig(actual_sig),
                return_type_sig: get_return_type_sig(actual_sig),
                ctx: 0,
                callback_bytes: [0u8; 16],
                method_key: method_key(class_name, method_name, actual_sig),
                is_static: false,
                param_count: count_jni_params(actual_sig),
                param_types: parse_jni_param_types(actual_sig),
                class_name: class_name.to_string(),
                quick_trampoline,
                use_blr,
                native_entry_hook_target: 0,
                native_entry_trampoline: 0,
                native_entry_critical: false,
            },
        );
    });

    cache_fields_for_class(env, class_name);
    output_message(&format!(
        "[managedHook] installed {} {}.{}{} -> helper ArtMethod={:#x}, original={:#x}, trampoline={:#x}",
        label, class_name, method_name, actual_sig, helper_art_method, art_method, quick_trampoline
    ));

    install_guard.commit();
    Ok(())
}

unsafe fn install_count_orig_fast_path(
    env: JniEnv,
    class_name: &str,
    method_name: &str,
    actual_sig: &str,
    art_method: u64,
    is_static: bool,
    helper_class: &str,
    counter_fields: &[String],
) -> Result<u64, String> {
    if counter_fields.is_empty() {
        return Err("count-orig fast path requires at least one counter".to_string());
    }

    let spec = get_art_method_spec(env, art_method);
    let ep_offset = spec.entry_point_offset;
    let data_off = spec.data_offset;
    let original_access_flags = std::ptr::read_volatile((art_method as usize + spec.access_flags_offset) as *const u32);
    let original_data = std::ptr::read_volatile((art_method as usize + data_off) as *const u64);
    let original_entry_point = read_entry_point(art_method, ep_offset);
    let bridge = find_art_bridge_functions(env, ep_offset);

    let original_is_shared_entrypoint = is_art_quick_entrypoint(original_entry_point, bridge);

    if original_is_shared_entrypoint {
        return Err(format!(
            "count-orig native fast path only supports compiled/JIT quick entrypoints. {}.{}{} currently uses {} ({:#x}); call Java.compileMethod(...) or MethodWrapper.opt() first.",
            class_name,
            method_name,
            actual_sig,
            shared_entrypoint_name(original_entry_point, bridge),
            original_entry_point
        ));
    }

    let class_global_ref = create_class_global_ref(env, class_name)?;
    let mut install_guard = JavaHookInstallGuard::new(
        art_method,
        spec.access_flags_offset,
        data_off,
        ep_offset,
        original_access_flags,
        original_data,
        original_entry_point,
        class_global_ref,
    );

    update_original_method_flags_for_hook(art_method, spec.access_flags_offset, original_access_flags);
    install_guard.set_original_method_mutated();

    let mut counter_ptrs = install_native_counter_ptrs(helper_class, counter_fields);

    let (per_method_hook_target, quick_trampoline) = {
        let (hook_addr, stealth_flag, real_addr) =
            super::super::art_controller::prepare_hook_target(original_entry_point, env as *mut std::ffi::c_void)
                .map_err(|e| format!("prepare_hook_target: {}", e))?;
        let mut hooked_target: *mut std::ffi::c_void = std::ptr::null_mut();
        let quick_trampoline = crate::ffi::hook::hook_install_count_orig_router(
            hook_addr as *mut std::ffi::c_void,
            stealth_flag,
            env as *mut std::ffi::c_void,
            &mut hooked_target,
            counter_ptrs.as_mut_ptr() as *mut *mut u64,
            counter_ptrs.len() as u32,
        );
        if quick_trampoline.is_null() {
            return Err("hook_install_count_orig_router failed".to_string());
        }
        super::super::art_controller::try_fixup_trampoline_pub(quick_trampoline, real_addr);

        let per_method_hook_target = if !hooked_target.is_null() {
            Some(hooked_target as u64)
        } else {
            Some(hook_addr)
        };
        (per_method_hook_target, quick_trampoline as u64)
    };
    with_registry_mut(&JAVA_HOOK_REGISTRY, |registry| {
        registry.insert(
            art_method,
            JavaHookData {
                art_method,
                original_access_flags,
                original_entry_point,
                original_data,
                hook_type: HookType::Managed {
                    replacement_art_method: 0,
                    sentinel_addr: 0,
                    per_method_hook_target,
                },
                clone_addr: 0,
                class_global_ref,
                return_type: get_return_type_from_sig(actual_sig),
                return_type_sig: get_return_type_sig(actual_sig),
                ctx: 0,
                callback_bytes: [0u8; 16],
                method_key: method_key(class_name, method_name, actual_sig),
                is_static,
                param_count: count_jni_params(actual_sig),
                param_types: parse_jni_param_types(actual_sig),
                class_name: class_name.to_string(),
                quick_trampoline,
                use_blr: false,
                native_entry_hook_target: 0,
                native_entry_trampoline: 0,
                native_entry_critical: false,
            },
        );
    });

    cache_fields_for_class(env, class_name);
    output_message(&format!(
        "[managedHook] installed count-orig fast path {}.{}{} counters={} original={:#x}, trampoline={:#x}",
        class_name,
        method_name,
        actual_sig,
        counter_fields.len(),
        art_method,
        quick_trampoline
    ));

    install_guard.commit();
    Ok(quick_trampoline)
}

pub(in crate::jsapi::java) struct ManagedDslInstallResult {
    helper_class: String,
    helper_method: String,
    helper_signature: String,
    uses_orig: bool,
    optimized_passthrough: bool,
    optimized_native_count_orig: bool,
    counters: Vec<GeneratedCounter>,
    message_channels: Vec<GeneratedMessageChannel>,
    message_capacity: i32,
}

#[derive(Clone, Debug)]
pub(in crate::jsapi::java) struct ManagedMessageItem {
    pub code: i32,
    pub value: i32,
    pub text: Option<String>,
}

#[derive(Clone, Debug)]
pub(in crate::jsapi::java) struct ManagedDrainResult {
    pub items: Vec<ManagedMessageItem>,
    pub head: i32,
    pub tail: i32,
    pub dropped: i32,
    pub capacity: i32,
}

unsafe fn install_managed_dsl_inner(
    class_name: &str,
    method_name: &str,
    sig: &str,
    dsl: &str,
    message_capacity: i32,
) -> Result<ManagedDslInstallResult, String> {
    let scoped_env = scoped_jni_env()?;
    install_managed_dsl_with_env(scoped_env.env(), class_name, method_name, sig, dsl, message_capacity)
}

pub(in crate::jsapi::java) unsafe fn install_managed_dsl_with_env(
    env: JniEnv,
    class_name: &str,
    method_name: &str,
    sig: &str,
    dsl: &str,
    message_capacity: i32,
) -> Result<ManagedDslInstallResult, String> {
    let (art_method, is_static) = resolve_art_method(env, class_name, method_name, sig, false)?;
    init_java_registry();
    if crate::jsapi::callback_util::with_registry(&JAVA_HOOK_REGISTRY, |r| r.contains_key(&art_method)).unwrap_or(false)
    {
        return Err(format!(
            "{}.{}{} already hooked — unhook first",
            class_name, method_name, sig
        ));
    }
    ensure_dsl_target_has_independent_quick_code(env, class_name, method_name, sig, art_method)?;
    let class_id = DYNAMIC_MANAGED_CLASS_ID.fetch_add(1, Ordering::Relaxed);
    let generated = build_managed_dsl_dex(
        env,
        class_id,
        class_name,
        method_name,
        sig,
        is_static,
        dsl,
        message_capacity,
    )?;
    let helper_class = generated.class_name.clone();
    let helper_method = generated.method_name.clone();
    let helper_signature = generated.method_sig.clone();
    let uses_orig = generated.uses_orig;
    let optimized_passthrough = generated.orig_only_passthrough;
    let optimized_native_count_orig = !generated.fast_tail_orig_counter_fields.is_empty();
    let counters = generated.counters.clone();
    let message_channels = generated.message_channels.clone();
    let message_capacity = generated.message_capacity;
    output_message(&format!(
        "[managedHook] generated generic DSL dex class={} target={}.{}{} static={} fastTailOrig={} origOnlyPassthrough={} nativeCountOrig={} dexSize={}",
        generated.class_name,
        class_name,
        method_name,
        sig,
        is_static,
        generated.fast_tail_orig,
        generated.orig_only_passthrough,
        optimized_native_count_orig,
        generated.dex.len()
    ));
    if generated.orig_only_passthrough {
        output_message(&format!(
            "[managedHook] optimized {}.{}{} return-orig DSL as pass-through; no method patch installed",
            class_name, method_name, sig
        ));
        return Ok(ManagedDslInstallResult {
            helper_class,
            helper_method,
            helper_signature,
            uses_orig,
            optimized_passthrough,
            optimized_native_count_orig: false,
            counters,
            message_channels,
            message_capacity,
        });
    }
    let mut optimized_native_count_orig_installed = false;
    if optimized_native_count_orig {
        match install_count_orig_fast_path(
            env,
            class_name,
            method_name,
            sig,
            art_method,
            is_static,
            &helper_class,
            &generated.fast_tail_orig_counter_fields,
        ) {
            Ok(_) => {
                optimized_native_count_orig_installed = true;
                refresh_walkstack_sigsegv_guard();
                return Ok(ManagedDslInstallResult {
                    helper_class,
                    helper_method,
                    helper_signature,
                    uses_orig,
                    optimized_passthrough,
                    optimized_native_count_orig: optimized_native_count_orig_installed,
                    counters,
                    message_channels,
                    message_capacity,
                });
            }
            Err(e) => {
                output_message(&format!(
                    "[managedHook] native count-orig fast path disabled for {}.{}{}: {}; falling back to generic DSL helper",
                    class_name, method_name, sig, e
                ));
            }
        }
    }
    let helper_cls = load_dynamic_managed_helper_class(env, generated.dex, &generated.class_name)?;
    register_managed_guard_helpers(env, helper_cls)?;
    mark_managed_helper_natives_registered(&generated.class_name);
    initialize_generated_string_literals(env, helper_cls, &generated.string_literals)?;
    initialize_generated_message_queue(env, helper_cls, &generated.message_channels, generated.message_capacity)?;
    if generated.uses_direct_buffer_helpers {
        register_direct_buffer_helpers(env, helper_cls)?;
    }
    install_managed_method_helper(
        env,
        class_name,
        method_name,
        sig,
        Some(art_method),
        helper_cls,
        &generated.method_name,
        &generated.method_sig,
        generated
            .orig_backup_name
            .as_deref()
            .zip(generated.orig_backup_sig.as_deref()),
        "generic-dsl",
        generated.uses_orig,
    )?;
    refresh_walkstack_sigsegv_guard();
    Ok(ManagedDslInstallResult {
        helper_class,
        helper_method,
        helper_signature,
        uses_orig,
        optimized_passthrough,
        optimized_native_count_orig: optimized_native_count_orig_installed,
        counters,
        message_channels,
        message_capacity,
    })
}

unsafe fn wrap_managed_dsl_install_result(ctx: *mut ffi::JSContext, result: ManagedDslInstallResult) -> ffi::JSValue {
    let obj = JSValue(ffi::JS_NewObject(ctx));
    obj.set_property(ctx, "success", JSValue::bool(true));
    obj.set_property(ctx, "helperClass", JSValue::string(ctx, &result.helper_class));
    obj.set_property(ctx, "helperMethod", JSValue::string(ctx, &result.helper_method));
    obj.set_property(ctx, "helperSignature", JSValue::string(ctx, &result.helper_signature));
    obj.set_property(ctx, "usesOrig", JSValue::bool(result.uses_orig));
    obj.set_property(ctx, "optimizedPassThrough", JSValue::bool(result.optimized_passthrough));
    obj.set_property(
        ctx,
        "optimizedNativeCountOrig",
        JSValue::bool(result.optimized_native_count_orig),
    );
    let counters = JSValue(ffi::JS_NewObject(ctx));
    for counter in result.counters {
        counters.set_property(ctx, &counter.name, JSValue::string(ctx, &counter.field_name));
    }
    obj.set_property(ctx, "counters", counters);
    let messages = JSValue(ffi::JS_NewObject(ctx));
    for channel in result.message_channels {
        messages.set_property(ctx, &channel.name, JSValue::int(channel.code));
    }
    obj.set_property(ctx, "messages", messages);
    obj.set_property(ctx, "buff", JSValue::int(result.message_capacity));
    obj.raw()
}

unsafe fn extract_string_prop(
    ctx: *mut ffi::JSContext,
    obj: JSValue,
    names: &[&str],
    api: &str,
) -> Result<String, ffi::JSValue> {
    for name in names {
        let value = obj.get_property(ctx, name);
        if !value.is_undefined() && !value.is_null() {
            let result = value.to_string(ctx);
            value.free(ctx);
            if let Some(result) = result {
                return Ok(result);
            }
            return Err(throw_internal_error(
                ctx,
                format!("{} option '{}' must be a string", api, name),
            ));
        }
        value.free(ctx);
    }
    Err(throw_internal_error(
        ctx,
        format!("{} option missing: {}", api, names.join("/")),
    ))
}

unsafe fn extract_optional_i32_prop(
    ctx: *mut ffi::JSContext,
    obj: JSValue,
    names: &[&str],
    api: &str,
) -> Result<Option<i32>, ffi::JSValue> {
    for name in names {
        let value = obj.get_property(ctx, name);
        if !value.is_undefined() && !value.is_null() {
            let Some(parsed) = value.to_i64(ctx) else {
                value.free(ctx);
                return Err(throw_internal_error(
                    ctx,
                    format!("{} option '{}' must be an integer", api, name),
                ));
            };
            value.free(ctx);
            if parsed < i32::MIN as i64 || parsed > i32::MAX as i64 {
                return Err(throw_internal_error(
                    ctx,
                    format!("{} option '{}' is out of i32 range: {}", api, name, parsed),
                ));
            }
            return Ok(Some(parsed as i32));
        }
        value.free(ctx);
    }
    Ok(None)
}

unsafe fn extract_managed_hook_dsl_args(
    ctx: *mut ffi::JSContext,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> Result<(String, String, String, String, i32), ffi::JSValue> {
    if argc == 1 {
        let opts = JSValue(*argv);
        if !opts.is_object() || ffi::JS_IsArray(ctx, opts.raw()) != 0 {
            return Err(ffi::JS_ThrowTypeError(
                ctx,
                b"Java.managedHookDsl(object) requires an options object\0".as_ptr() as *const _,
            ));
        }
        let class_name = extract_string_prop(ctx, opts, &["className", "class"], "managedHookDsl")?;
        let method_name = extract_string_prop(ctx, opts, &["methodName", "method"], "managedHookDsl")?;
        let sig = extract_string_prop(ctx, opts, &["signature", "sig"], "managedHookDsl")?;
        let dsl = extract_string_prop(ctx, opts, &["dsl", "script"], "managedHookDsl")?;
        let message_capacity =
            extract_optional_i32_prop(ctx, opts, &["buff"], "managedHookDsl")?.unwrap_or(MANAGED_MESSAGE_CAPACITY);
        return Ok((class_name, method_name, sig, dsl, message_capacity));
    }

    if argc >= 4 {
        let Some(class_name) = JSValue(*argv).to_string(ctx) else {
            return Err(throw_internal_error(
                ctx,
                "managedHookDsl arg1 className must be a string",
            ));
        };
        let Some(method_name) = JSValue(*argv.add(1)).to_string(ctx) else {
            return Err(throw_internal_error(
                ctx,
                "managedHookDsl arg2 methodName must be a string",
            ));
        };
        let Some(sig) = JSValue(*argv.add(2)).to_string(ctx) else {
            return Err(throw_internal_error(
                ctx,
                "managedHookDsl arg3 signature must be a string",
            ));
        };
        let Some(dsl) = JSValue(*argv.add(3)).to_string(ctx) else {
            return Err(throw_internal_error(ctx, "managedHookDsl arg4 dsl must be a string"));
        };
        let message_capacity = if argc >= 5 {
            match JSValue(*argv.add(4)).to_i64(ctx) {
                Some(value) => value,
                None => return Err(throw_internal_error(ctx, "managedHookDsl arg5 buff must be an integer")),
            }
        } else {
            MANAGED_MESSAGE_CAPACITY as i64
        };
        if message_capacity < i32::MIN as i64 || message_capacity > i32::MAX as i64 {
            return Err(throw_internal_error(
                ctx,
                format!("managedHookDsl arg5 buff is out of i32 range: {}", message_capacity),
            ));
        }
        return Ok((class_name, method_name, sig, dsl, message_capacity as i32));
    }

    Err(throw_internal_error(
        ctx,
        "managedHookDsl requires object or (className, methodName, signature, dsl)",
    ))
}

pub(in crate::jsapi::java) unsafe extern "C" fn js_managed_hook_dsl(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let (class_name, method_name, sig, dsl, message_capacity) = match extract_managed_hook_dsl_args(ctx, argc, argv) {
        Ok(v) => v,
        Err(e) => return e,
    };

    let result = if crate::is_raw_clone_js_thread() {
        match super::super::callback::managed_hook_dsl_via_executor(class_name, method_name, sig, dsl, message_capacity)
        {
            Ok(result) => result,
            Err(msg) => return throw_internal_error(ctx, msg),
        }
    } else {
        match install_managed_dsl_inner(&class_name, &method_name, &sig, &dsl, message_capacity) {
            Ok(result) => result,
            Err(msg) => return throw_internal_error(ctx, msg),
        }
    };

    wrap_managed_dsl_install_result(ctx, result)
}

unsafe fn extract_helper_class_arg(
    ctx: *mut ffi::JSContext,
    value: JSValue,
    api: &str,
) -> Result<String, ffi::JSValue> {
    if value.is_object() && ffi::JS_IsArray(ctx, value.raw()) == 0 {
        return extract_string_prop(ctx, value, &["helperClass", "className", "class"], api);
    }
    value
        .to_string(ctx)
        .ok_or_else(|| throw_internal_error(ctx, format!("{} helperClass must be a string or dslInfo object", api)))
}

unsafe fn managed_static_field_id(
    env: JniEnv,
    helper_cls: *mut std::ffi::c_void,
    name: &str,
    sig: &str,
) -> Result<*mut std::ffi::c_void, String> {
    let get_static_field_id: GetStaticFieldIdFn = jni_fn!(env, GetStaticFieldIdFn, JNI_GET_STATIC_FIELD_ID);
    let name = CString::new(name).map_err(|_| format!("invalid managed field name {}", name))?;
    let sig = CString::new(sig).map_err(|_| format!("invalid managed field sig {}", sig))?;
    let fid = get_static_field_id(env, helper_cls, name.as_ptr(), sig.as_ptr());
    if jni_null_or_exc(env, fid) {
        return Err("managed message field not found".to_string());
    }
    Ok(fid)
}

pub(in crate::jsapi::java) unsafe fn drain_managed_messages_inner(
    env: JniEnv,
    helper_class: &str,
    max_items_requested: Option<i64>,
) -> Result<ManagedDrainResult, String> {
    let Some(helper_cls) = find_dynamic_managed_helper_class(helper_class) else {
        return Err(format!("managed helper class not found: {}", helper_class));
    };
    let get_static_int_field: GetStaticIntFieldFn = jni_fn!(env, GetStaticIntFieldFn, JNI_GET_STATIC_INT_FIELD);
    let set_static_int_field: SetStaticIntFieldFn = jni_fn!(env, SetStaticIntFieldFn, JNI_SET_STATIC_INT_FIELD);
    let get_static_object_field: GetStaticObjectFieldFn =
        jni_fn!(env, GetStaticObjectFieldFn, JNI_GET_STATIC_OBJECT_FIELD);
    let get_array_length: GetArrayLengthFn = jni_fn!(env, GetArrayLengthFn, JNI_GET_ARRAY_LENGTH);
    let get_int_array_region: GetIntArrayRegionFn = jni_fn!(env, GetIntArrayRegionFn, JNI_GET_INT_ARRAY_REGION);
    let get_object_array_element: GetObjectArrayElementFn =
        jni_fn!(env, GetObjectArrayElementFn, JNI_GET_OBJECT_ARRAY_ELEMENT);
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);

    let head_fid = managed_static_field_id(env, helper_cls, MANAGED_MESSAGE_HEAD_FIELD, "I")?;
    let tail_fid = managed_static_field_id(env, helper_cls, MANAGED_MESSAGE_TAIL_FIELD, "I")?;
    let dropped_fid = managed_static_field_id(env, helper_cls, MANAGED_MESSAGE_DROPPED_FIELD, "I")?;
    let codes_fid = managed_static_field_id(env, helper_cls, MANAGED_MESSAGE_CODES_FIELD, "[I")?;
    let values_fid = managed_static_field_id(env, helper_cls, MANAGED_MESSAGE_VALUES_FIELD, "[I")?;
    let texts_fid = managed_static_field_id(env, helper_cls, MANAGED_MESSAGE_TEXTS_FIELD, "[Ljava/lang/String;")?;

    let head = get_static_int_field(env, helper_cls, head_fid);
    let tail = get_static_int_field(env, helper_cls, tail_fid);
    let dropped = get_static_int_field(env, helper_cls, dropped_fid);
    if jni_check_exc(env) {
        return Err("managedDrainMessages failed to read queue counters".to_string());
    }
    let codes_array = get_static_object_field(env, helper_cls, codes_fid);
    let values_array = get_static_object_field(env, helper_cls, values_fid);
    let texts_array = get_static_object_field(env, helper_cls, texts_fid);
    let arrays_failed = {
        let had_exc = jni_check_exc(env);
        codes_array.is_null() || values_array.is_null() || texts_array.is_null() || had_exc
    };
    if arrays_failed {
        return Err("managedDrainMessages message arrays are not initialized".to_string());
    }

    struct LocalArrayRefs {
        env: JniEnv,
        delete_local_ref: DeleteLocalRefFn,
        codes: *mut std::ffi::c_void,
        values: *mut std::ffi::c_void,
        texts: *mut std::ffi::c_void,
    }
    impl Drop for LocalArrayRefs {
        fn drop(&mut self) {
            unsafe {
                if !self.codes.is_null() {
                    (self.delete_local_ref)(self.env, self.codes);
                }
                if !self.values.is_null() {
                    (self.delete_local_ref)(self.env, self.values);
                }
                if !self.texts.is_null() {
                    (self.delete_local_ref)(self.env, self.texts);
                }
            }
        }
    }
    let _array_refs = LocalArrayRefs {
        env,
        delete_local_ref,
        codes: codes_array,
        values: values_array,
        texts: texts_array,
    };

    let capacity = get_array_length(env, codes_array)
        .min(get_array_length(env, values_array))
        .min(get_array_length(env, texts_array));
    let capacity_failed = {
        let had_exc = jni_check_exc(env);
        capacity <= 0 || had_exc
    };
    if capacity_failed {
        return Err("managedDrainMessages message arrays have invalid capacity".to_string());
    }
    let available = (head as i64 - tail as i64).clamp(0, capacity as i64) as i32;
    let max_items = max_items_requested
        .map(|value| value.clamp(0, capacity as i64) as i32)
        .unwrap_or(capacity);
    let count = available.min(max_items);

    let mut items = Vec::with_capacity(count.max(0) as usize);
    if count > 0 {
        let mut codes = vec![0i32; capacity as usize];
        let mut values = vec![0i32; capacity as usize];
        get_int_array_region(env, codes_array, 0, capacity, codes.as_mut_ptr());
        get_int_array_region(env, values_array, 0, capacity, values.as_mut_ptr());
        if jni_check_exc(env) {
            return Err("managedDrainMessages failed to read message arrays".to_string());
        }
        let mask = capacity - 1;
        for i in 0..count {
            let slot = ((tail + i) & mask) as usize;
            let text_obj = get_object_array_element(env, texts_array, slot as i32);
            let text_failed = jni_null_or_exc(env, text_obj);
            let text = if !text_failed {
                let text = super::super::try_read_jstring(env as u64, text_obj as u64);
                delete_local_ref(env, text_obj);
                text
            } else {
                None
            };
            items.push(ManagedMessageItem {
                code: codes[slot],
                value: values[slot],
                text,
            });
        }
    }

    let new_tail = tail.wrapping_add(count);
    set_static_int_field(env, helper_cls, tail_fid, new_tail);
    if jni_check_exc(env) {
        return Err("managedDrainMessages failed to update queue tail".to_string());
    }

    Ok(ManagedDrainResult {
        items,
        head,
        tail: new_tail,
        dropped,
        capacity,
    })
}

pub(in crate::jsapi::java) unsafe fn read_managed_counter_inner(
    env: JniEnv,
    helper_class: &str,
    field_name: &str,
) -> Result<u64, String> {
    if let Some(value) = read_native_counter(helper_class, field_name) {
        return Ok(value);
    }
    let Some(helper_cls) = find_dynamic_managed_helper_class(helper_class) else {
        return Err(format!("managed helper class not found: {}", helper_class));
    };
    let get_static_field_id: GetStaticFieldIdFn = jni_fn!(env, GetStaticFieldIdFn, JNI_GET_STATIC_FIELD_ID);
    let get_static_int_field: GetStaticIntFieldFn = jni_fn!(env, GetStaticIntFieldFn, JNI_GET_STATIC_INT_FIELD);
    let field_name =
        CString::new(field_name).map_err(|_| "managedReadCounter fieldName contains NUL byte".to_string())?;
    let int_sig = CString::new("I").unwrap();
    let field_id = get_static_field_id(env, helper_cls, field_name.as_ptr(), int_sig.as_ptr());
    if jni_null_or_exc(env, field_id) {
        return Err("managedReadCounter counter field not found".to_string());
    }
    let value = get_static_int_field(env, helper_cls, field_id);
    if jni_check_exc(env) {
        return Err("managedReadCounter GetStaticIntField failed".to_string());
    }
    Ok(value as u32 as u64)
}

unsafe fn wrap_managed_drain_result(ctx: *mut ffi::JSContext, result: ManagedDrainResult) -> ffi::JSValue {
    let arr = ffi::JS_NewArray(ctx);
    for (i, message) in result.items.into_iter().enumerate() {
        let item = JSValue(ffi::JS_NewObject(ctx));
        item.set_property(ctx, "code", JSValue::int(message.code));
        if let Some(text) = message.text {
            let value = JSValue::string(ctx, &text);
            item.set_property(ctx, "value", value);
            item.set_property(ctx, "text", JSValue::string(ctx, &text));
        } else {
            item.set_property(ctx, "value", JSValue::int(message.value));
        }
        ffi::JS_SetPropertyUint32(ctx, arr, i as u32, item.raw());
    }
    let out = JSValue(arr);
    out.set_property(ctx, "head", JSValue::int(result.head));
    out.set_property(ctx, "tail", JSValue::int(result.tail));
    out.set_property(ctx, "dropped", JSValue::int(result.dropped));
    out.set_property(ctx, "capacity", JSValue::int(result.capacity));
    out.raw()
}

pub(in crate::jsapi::java) unsafe extern "C" fn js_managed_drain_messages(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return throw_internal_error(ctx, "managedDrainMessages requires (dslInfoOrHelperClass[, max])");
    }
    let helper_class = match extract_helper_class_arg(ctx, JSValue(*argv), "managedDrainMessages") {
        Ok(value) => value,
        Err(err) => return err,
    };
    let max_items_requested = if argc >= 2 {
        match JSValue(*argv.add(1)).to_i64(ctx) {
            Some(value) => Some(value),
            None => return throw_internal_error(ctx, "managedDrainMessages max must be an integer"),
        }
    } else {
        None
    };
    let result = if crate::is_raw_clone_js_thread() {
        match super::super::callback::managed_drain_messages_via_executor(helper_class, max_items_requested) {
            Ok(value) => value,
            Err(msg) => return throw_internal_error(ctx, msg),
        }
    } else {
        let scoped_env = match scoped_jni_env() {
            Ok(env) => env,
            Err(msg) => return throw_internal_error(ctx, msg),
        };
        match drain_managed_messages_inner(scoped_env.env(), &helper_class, max_items_requested) {
            Ok(value) => value,
            Err(msg) => return throw_internal_error(ctx, msg),
        }
    };
    wrap_managed_drain_result(ctx, result)
}

pub(in crate::jsapi::java) unsafe extern "C" fn js_managed_read_counter(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return throw_internal_error(ctx, "managedReadCounter requires (helperClass, fieldName)");
    }
    let Some(helper_class) = JSValue(*argv).to_string(ctx) else {
        return throw_internal_error(ctx, "managedReadCounter helperClass must be a string");
    };
    let Some(field_name) = JSValue(*argv.add(1)).to_string(ctx) else {
        return throw_internal_error(ctx, "managedReadCounter fieldName must be a string");
    };
    if let Some(value) = read_native_counter(&helper_class, &field_name) {
        return ffi::JS_NewBigUint64(ctx, value);
    }
    let value = if crate::is_raw_clone_js_thread() {
        match super::super::callback::managed_read_counter_via_executor(helper_class, field_name) {
            Ok(value) => value,
            Err(msg) => return throw_internal_error(ctx, msg),
        }
    } else {
        let scoped_env = match scoped_jni_env() {
            Ok(env) => env,
            Err(msg) => return throw_internal_error(ctx, msg),
        };
        match read_managed_counter_inner(scoped_env.env(), &helper_class, &field_name) {
            Ok(value) => value,
            Err(msg) => return throw_internal_error(ctx, msg),
        }
    };
    ffi::JS_NewBigUint64(ctx, value)
}
