//! JNI core types, constants, and initialization
//!
//! Contains: ArtMethod layout constants, JNI type aliases, function table helpers,
//! entry_point offset probing, JNI state management.

use crate::jsapi::console::output_verbose;
use crate::jsapi::module::probe_module_range;
use std::ffi::CString;
use std::os::raw::c_char;
use std::sync::Mutex;

use super::reflect::decode_method_id;
use super::safe_mem::{refresh_mem_regions, safe_read_u32, safe_read_u64};
use super::PAC_STRIP_MASK;

// ============================================================================
// ArtMethod layout — dynamic probing (Frida-style)
// ============================================================================

/// 动态探测的 ArtMethod 布局规格（Frida-style）
///
/// 通过扫描已知 native 方法 (Process.getElapsedCpuTime) 的 ArtMethod 内存，
/// 动态发现 access_flags、data_ (jniCode)、entry_point_ 偏移。
/// 兼容厂商魔改 ArtMethod 布局。
pub(super) struct ArtMethodSpec {
    pub(super) access_flags_offset: usize,
    pub(super) data_offset: usize,        // jniCode / data_
    pub(super) entry_point_offset: usize, // quickCode / entry_point_
    pub(super) size: usize,               // ArtMethod 总大小
}

pub(super) static ART_METHOD_SPEC: std::sync::OnceLock<ArtMethodSpec> = std::sync::OnceLock::new();

/// kAccNative — marks method as native (ART uses JNI trampoline to call data_)
pub(super) const K_ACC_NATIVE: u32 = 0x0100;
/// kAccFastInterpreterToInterpreterInvoke — fast interpreter dispatch (must clear for native)
pub(super) const K_ACC_FAST_INTERP_TO_INTERP: u32 = 0x40000000;
/// kAccSingleImplementation — devirtualization optimization (must clear for hooked methods)
pub(super) const K_ACC_SINGLE_IMPLEMENTATION: u32 = 0x08000000;
/// kAccFastNative — fast JNI (@FastNative annotation, must clear for our hook)
/// NOTE: same bit as kAccSkipAccessChecks (mutually exclusive: native vs non-native methods)
pub(super) const K_ACC_FAST_NATIVE: u32 = 0x00080000;
/// kAccCriticalNative — critical JNI (@CriticalNative, must clear)
pub(super) const K_ACC_CRITICAL_NATIVE: u32 = 0x00200000;
/// kAccSkipAccessChecks — skip access checks optimization (must clear)
/// Same bit as kAccFastNative (0x00080000) — they share the bit, different interpretation
pub(super) const K_ACC_SKIP_ACCESS_CHECKS: u32 = 0x00080000;
/// kAccNterpEntryPointFastPath — nterp fast path (must clear for native conversion)
pub(super) const K_ACC_NTERP_ENTRY_POINT_FAST_PATH: u32 = 0x00100000;
/// kAccXposedHookedMethod — Xposed framework hooked method marker
pub(super) const K_ACC_XPOSED_HOOKED_METHOD: u32 = 0x10000000;
/// kAccNterpInvokeFastPathFlag — nterp invoke fast path (noise bit, may be set on probed method)
pub(super) const K_ACC_NTERP_INVOKE_FAST_PATH_FLAG: u32 = 0x00200000;
/// kAccPublicApi — public API whitelist marker (noise bit, may be set on probed method)
pub(super) const K_ACC_PUBLIC_API: u32 = 0x10000000;

/// 缓存的 kAccCompileDontBother 位值
static K_ACC_COMPILE_DONT_BOTHER_CACHED: std::sync::OnceLock<u32> = std::sync::OnceLock::new();

/// 按 API 级别返回 kAccCompileDontBother 的正确位值 (cached)。
/// API >= 27: 0x02000000, API 24-26: 0x01000000, API < 24: 0
pub(super) fn k_acc_compile_dont_bother() -> u32 {
    *K_ACC_COMPILE_DONT_BOTHER_CACHED.get_or_init(|| {
        let api = get_android_api_level();
        if api >= 27 {
            0x02000000
        } else if api >= 24 {
            0x01000000
        } else {
            0
        }
    })
}

// ============================================================================
// JNI type aliases + helpers (module-level, shared across all functions)
// ============================================================================

pub(crate) type JniEnv = *mut *const *const std::ffi::c_void;

pub(super) type FindClassFn = unsafe extern "C" fn(JniEnv, *const c_char) -> *mut std::ffi::c_void;
pub(super) type GetMethodIdFn =
    unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *const c_char, *const c_char) -> *mut std::ffi::c_void;
pub(super) type GetStaticMethodIdFn =
    unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *const c_char, *const c_char) -> *mut std::ffi::c_void;
pub(super) type ExcCheckFn = unsafe extern "C" fn(JniEnv) -> u8;
pub(super) type ExcClearFn = unsafe extern "C" fn(JniEnv);
pub(super) type ExcOccurredFn = unsafe extern "C" fn(JniEnv) -> *mut std::ffi::c_void;
pub(super) type DeleteLocalRefFn = unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void);
pub(super) type NewLocalRefFn = unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void) -> *mut std::ffi::c_void;
pub(super) type NewGlobalRefFn = unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void) -> *mut std::ffi::c_void;
pub(super) type DeleteGlobalRefFn = unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void);
pub(super) type MonitorEnterFn = unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void) -> i32;
pub(super) type MonitorExitFn = unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void) -> i32;
pub(super) type GetObjectClassFn = unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void) -> *mut std::ffi::c_void;
pub(super) type GetSuperclassFn = unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void) -> *mut std::ffi::c_void;
pub(super) type IsSameObjectFn = unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void) -> u8;
pub(super) type NewObjectAFn = unsafe extern "C" fn(
    JniEnv,
    *mut std::ffi::c_void,
    *mut std::ffi::c_void,
    *const std::ffi::c_void,
) -> *mut std::ffi::c_void;
pub(super) type IsInstanceOfFn = unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void) -> u8;
pub(super) type GetFieldIdFn =
    unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *const c_char, *const c_char) -> *mut std::ffi::c_void;
pub(super) type NewStringUtfFn = unsafe extern "C" fn(JniEnv, *const c_char) -> *mut std::ffi::c_void;
pub(super) type GetStringUtfCharsFn = unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut u8) -> *const c_char;
pub(super) type ReleaseStringUtfCharsFn = unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *const c_char);
pub(super) type PushLocalFrameFn = unsafe extern "C" fn(JniEnv, i32) -> i32;
pub(super) type PopLocalFrameFn = unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void) -> *mut std::ffi::c_void;
pub(super) type GetArrayLengthFn = unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void) -> i32;
pub(super) type GetObjectArrayElementFn =
    unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, i32) -> *mut std::ffi::c_void;
pub(super) type GetBooleanArrayRegionFn =
    unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, i32, i32, *mut u8);
pub(super) type GetByteArrayRegionFn =
    unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, i32, i32, *mut i8);
pub(super) type GetCharArrayRegionFn =
    unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, i32, i32, *mut u16);
pub(super) type GetShortArrayRegionFn =
    unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, i32, i32, *mut i16);
pub(super) type GetIntArrayRegionFn =
    unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, i32, i32, *mut i32);
pub(super) type GetLongArrayRegionFn =
    unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, i32, i32, *mut i64);
pub(super) type GetFloatArrayRegionFn =
    unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, i32, i32, *mut f32);
pub(super) type GetDoubleArrayRegionFn =
    unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, i32, i32, *mut f64);
pub(super) type CallObjectMethodAFn = unsafe extern "C" fn(
    JniEnv,
    *mut std::ffi::c_void,
    *mut std::ffi::c_void,
    *const std::ffi::c_void,
) -> *mut std::ffi::c_void;
pub(super) type CallBooleanMethodAFn =
    unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, *const std::ffi::c_void) -> u8;
pub(super) type CallByteMethodAFn =
    unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, *const std::ffi::c_void) -> i8;
pub(super) type CallCharMethodAFn =
    unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, *const std::ffi::c_void) -> u16;
pub(super) type CallShortMethodAFn =
    unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, *const std::ffi::c_void) -> i16;
pub(super) type CallStaticObjectMethodAFn = unsafe extern "C" fn(
    JniEnv,
    *mut std::ffi::c_void,
    *mut std::ffi::c_void,
    *const std::ffi::c_void,
) -> *mut std::ffi::c_void;
pub(super) type CallStaticIntMethodAFn =
    unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, *const std::ffi::c_void) -> i32;
pub(super) type CallIntMethodAFn =
    unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, *const std::ffi::c_void) -> i32;
pub(super) type CallLongMethodAFn =
    unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, *const std::ffi::c_void) -> i64;
pub(super) type CallFloatMethodAFn =
    unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, *const std::ffi::c_void) -> f32;
pub(super) type CallDoubleMethodAFn =
    unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, *const std::ffi::c_void) -> f64;
pub(super) type ToReflectedMethodFn =
    unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, u8) -> *mut std::ffi::c_void;
#[allow(dead_code)]
pub(super) type ToReflectedFieldFn =
    unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, u8) -> *mut std::ffi::c_void;
pub(super) type GetLongFieldFn = unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void) -> i64;
pub(super) type GetBooleanFieldFn = unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void) -> u8;
pub(super) type GetByteFieldFn = unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void) -> i8;
pub(super) type GetCharFieldFn = unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void) -> u16;
pub(super) type GetShortFieldFn = unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void) -> i16;
pub(super) type GetIntFieldFn = unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void) -> i32;
pub(super) type GetFloatFieldFn = unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void) -> f32;
pub(super) type GetDoubleFieldFn = unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void) -> f64;
pub(super) type GetObjectFieldFn =
    unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void) -> *mut std::ffi::c_void;

// Void method call (instance)
pub(super) type CallVoidMethodAFn =
    unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, *const std::ffi::c_void);
// Object array creation/mutation
pub(super) type NewObjectArrayFn =
    unsafe extern "C" fn(JniEnv, i32, *mut std::ffi::c_void, *mut std::ffi::c_void) -> *mut std::ffi::c_void;
pub(super) type SetObjectArrayElementFn =
    unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, i32, *mut std::ffi::c_void);

// Static field getter types (signature: env, cls, fid → value)
pub(super) type GetStaticFieldIdFn =
    unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *const c_char, *const c_char) -> *mut std::ffi::c_void;
pub(super) type GetStaticBooleanFieldFn =
    unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void) -> u8;
pub(super) type GetStaticByteFieldFn = unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void) -> i8;
pub(super) type GetStaticCharFieldFn =
    unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void) -> u16;
pub(super) type GetStaticShortFieldFn =
    unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void) -> i16;
pub(super) type GetStaticIntFieldFn = unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void) -> i32;
pub(super) type GetStaticLongFieldFn =
    unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void) -> i64;
pub(super) type GetStaticFloatFieldFn =
    unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void) -> f32;
pub(super) type GetStaticDoubleFieldFn =
    unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void) -> f64;
pub(super) type GetStaticObjectFieldFn =
    unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void) -> *mut std::ffi::c_void;

/// Call a JNI function from the function table by index.
/// JNIEnv is `JNINativeInterface**` — (*env)[index] is the function pointer.
#[inline]
pub(crate) unsafe fn jni_fn_ptr(env: JniEnv, index: usize) -> *const std::ffi::c_void {
    let table = *env as *const *const std::ffi::c_void;
    *table.add(index)
}

/// Check for and clear any pending JNI exception. Returns true if there was one.
#[inline]
pub(super) unsafe fn jni_check_exc(env: JniEnv) -> bool {
    let check: ExcCheckFn = jni_fn!(env, ExcCheckFn, JNI_EXCEPTION_CHECK);
    if check(env) != 0 {
        let clear: ExcClearFn = jni_fn!(env, ExcClearFn, JNI_EXCEPTION_CLEAR);
        clear(env);
        true
    } else {
        false
    }
}

/// Check for a pending JNI exception and extract its toString() + cause chain
/// as a human-readable string. Always clears the exception on return.
///
/// Returns `Some(msg)` if there was an exception, `None` otherwise.
///
/// Format: `"<ClassName>: <message> [caused by: ...]"`
///
/// Safe to call during hook callbacks — only uses JNI FindClass/GetMethodID/
/// CallObjectMethod (no WalkStack). Bounded recursion depth (3 levels) on
/// cause chain to avoid infinite loops from self-referencing causes.
pub(super) unsafe fn jni_take_exception(env: JniEnv) -> Option<String> {
    let check: ExcCheckFn = jni_fn!(env, ExcCheckFn, JNI_EXCEPTION_CHECK);
    if check(env) == 0 {
        return None;
    }

    let occurred: ExcOccurredFn = jni_fn!(env, ExcOccurredFn, JNI_EXCEPTION_OCCURRED);
    let throwable = occurred(env);

    // 必须先 clear 才能对 throwable 调用其它 JNI 方法
    let clear: ExcClearFn = jni_fn!(env, ExcClearFn, JNI_EXCEPTION_CLEAR);
    clear(env);

    if throwable.is_null() {
        return Some("<null throwable>".to_string());
    }

    let msg = format_throwable_chain(env, throwable, 0);

    let delete: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
    delete(env, throwable);

    Some(msg)
}

/// 递归提取 throwable 的 toString() + cause 链。depth 上限 3 层。
unsafe fn format_throwable_chain(env: JniEnv, throwable: *mut std::ffi::c_void, depth: usize) -> String {
    if throwable.is_null() {
        return "<null>".to_string();
    }

    // 查找 java.lang.Throwable（缓存下来也行，但单次开销可接受）
    let find_class: FindClassFn = jni_fn!(env, FindClassFn, JNI_FIND_CLASS);
    let get_mid: GetMethodIdFn = jni_fn!(env, GetMethodIdFn, JNI_GET_METHOD_ID);
    let call_obj: CallObjectMethodAFn = jni_fn!(env, CallObjectMethodAFn, JNI_CALL_OBJECT_METHOD_A);
    let get_chars: GetStringUtfCharsFn = jni_fn!(env, GetStringUtfCharsFn, JNI_GET_STRING_UTF_CHARS);
    let rel_chars: ReleaseStringUtfCharsFn = jni_fn!(env, ReleaseStringUtfCharsFn, JNI_RELEASE_STRING_UTF_CHARS);
    let delete: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);

    let throwable_cls_name = CString::new("java/lang/Throwable").unwrap();
    let throwable_cls = find_class(env, throwable_cls_name.as_ptr());
    // 必须捕获 FindClass 可能的异常
    let check: ExcCheckFn = jni_fn!(env, ExcCheckFn, JNI_EXCEPTION_CHECK);
    if check(env) != 0 {
        clear_exc(env);
    }
    if throwable_cls.is_null() {
        return "<Throwable class not found>".to_string();
    }

    let to_string_name = CString::new("toString").unwrap();
    let to_string_sig = CString::new("()Ljava/lang/String;").unwrap();
    let to_string_mid = get_mid(env, throwable_cls, to_string_name.as_ptr(), to_string_sig.as_ptr());
    if check(env) != 0 {
        clear_exc(env);
    }

    let get_cause_name = CString::new("getCause").unwrap();
    let get_cause_sig = CString::new("()Ljava/lang/Throwable;").unwrap();
    let get_cause_mid = get_mid(env, throwable_cls, get_cause_name.as_ptr(), get_cause_sig.as_ptr());
    if check(env) != 0 {
        clear_exc(env);
    }

    let mut result = String::new();

    if !to_string_mid.is_null() {
        let jstr = call_obj(env, throwable, to_string_mid, std::ptr::null());
        if check(env) != 0 {
            clear_exc(env);
            result.push_str("<toString threw>");
        } else if !jstr.is_null() {
            let chars = get_chars(env, jstr, std::ptr::null_mut());
            if !chars.is_null() {
                result.push_str(&std::ffi::CStr::from_ptr(chars).to_string_lossy());
                rel_chars(env, jstr, chars);
            }
            delete(env, jstr);
        }
    } else {
        result.push_str("<toString mid not found>");
    }

    // 递归提取 cause（最多 3 层，防止循环引用）
    const MAX_CAUSE_DEPTH: usize = 3;
    if depth < MAX_CAUSE_DEPTH && !get_cause_mid.is_null() {
        let cause = call_obj(env, throwable, get_cause_mid, std::ptr::null());
        if check(env) != 0 {
            clear_exc(env);
        } else if !cause.is_null() {
            let cause_msg = format_throwable_chain(env, cause, depth + 1);
            result.push_str("\n  Caused by: ");
            result.push_str(&cause_msg);
            delete(env, cause);
        }
    } else if depth >= MAX_CAUSE_DEPTH {
        result.push_str("\n  Caused by: <truncated>");
    }

    delete(env, throwable_cls);
    result
}

#[inline]
unsafe fn clear_exc(env: JniEnv) {
    let clear: ExcClearFn = jni_fn!(env, ExcClearFn, JNI_EXCEPTION_CLEAR);
    clear(env);
}

/// Check if a 64-bit value looks like a valid ARM64 code pointer.
/// Strips PAC/TBI high bits (bits 48-63) before checking, since entry_point
/// values may carry PAC signatures or MTE tags on supported devices.
/// After stripping, verifies via dladdr that the address is in a mapped executable region.
pub(super) fn is_code_pointer(val: u64) -> bool {
    // Strip PAC/TBI bits to get the bare virtual address (48-bit canonical form)
    let stripped = val & PAC_STRIP_MASK;
    if stripped == 0 {
        return false;
    }
    // Verify it resolves via dladdr (mapped executable memory)
    unsafe {
        let mut info: libc::Dl_info = std::mem::zeroed();
        libc::dladdr(stripped as *const std::ffi::c_void, &mut info) != 0
    }
}

/// 缓存的 Android API level
static ANDROID_API_LEVEL: std::sync::OnceLock<i32> = std::sync::OnceLock::new();
/// 缓存的 Android codename
static ANDROID_CODENAME: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// 读取 Android 系统属性值
unsafe fn read_system_property(name: &str, buf: &mut [u8]) {
    let prop = CString::new(name).unwrap();
    // __system_property_get 在 libc.so 中，通过 module_dlsym 精确查找
    let sym = crate::jsapi::module::module_dlsym("libc.so", "__system_property_get");
    if sym.is_null() {
        return;
    }
    let get_prop: unsafe extern "C" fn(*const c_char, *mut c_char) -> i32 = std::mem::transmute(sym);
    get_prop(prop.as_ptr(), buf.as_mut_ptr() as *mut c_char);
}

/// Get Android API level from system property ro.build.version.sdk (cached).
pub(super) fn get_android_api_level() -> i32 {
    *ANDROID_API_LEVEL.get_or_init(|| {
        let mut buf = [0u8; 32];
        unsafe { read_system_property("ro.build.version.sdk", &mut buf) };
        let s = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr() as *const c_char) };
        s.to_str().unwrap_or("0").parse().unwrap_or(0)
    })
}

/// Get Android version codename from system property ro.build.version.codename (cached).
/// Returns "REL" for release builds, or a codename (e.g. "R", "S", "Tiramisu") for preview builds.
pub(super) fn get_android_codename() -> &'static str {
    ANDROID_CODENAME.get_or_init(|| {
        let mut buf = [0u8; 64];
        unsafe { read_system_property("ro.build.version.codename", &mut buf) };
        let s = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr() as *const c_char) };
        s.to_str().unwrap_or("").to_string()
    })
}

/// Get the ArtMethodSpec, probing on first use (Frida-style dynamic discovery).
pub(super) fn get_art_method_spec(env: JniEnv, art_method: u64) -> &'static ArtMethodSpec {
    ART_METHOD_SPEC.get_or_init(|| probe_art_method_spec(env, art_method))
}

/// Probe ArtMethod layout specification.
///
/// Strategy 1 (Frida-style): 扫描 Process.getElapsedCpuTime 的 ArtMethod 内存，
/// 动态发现 access_flags、data_ (jniCode)、entry_point_ 偏移。
///
/// Strategy 2 (fallback): 退回 code pointer 探测逻辑，access_flags 默认 4。
fn probe_art_method_spec(env: JniEnv, art_method: u64) -> ArtMethodSpec {
    // Strategy 1: Frida-style full scan using known native method
    if let Some(spec) = unsafe { probe_art_method_spec_frida(env) } {
        return spec;
    }

    output_verbose("[art spec] Frida-style probe 失败，退回 entry_point 探测...");

    // Strategy 2: Fallback — probe entry_point offset using code pointer heuristic
    let ep_offset = probe_entry_point_offset_legacy(env, art_method);
    let api_level = get_android_api_level();
    let size = if api_level <= 21 { ep_offset + 32 } else { ep_offset + 8 };
    ArtMethodSpec {
        access_flags_offset: 4,     // AOSP default
        data_offset: ep_offset - 8, // data_ precedes entry_point_
        entry_point_offset: ep_offset,
        size,
    }
}

/// Frida-style ArtMethod 布局全扫描。
///
/// 对标 Frida `_getArtMethodSpec()`: 通过 JNI 获取 Process.getElapsedCpuTime 的 ArtMethod*
/// （已知 public|static|final|native），在单循环中独立扫描 access_flags 和 jniCode (data_) 偏移，
/// 不假设两者的先后顺序（防御厂商魔改布局），推算 entry_point 偏移。
unsafe fn probe_art_method_spec_frida(env: JniEnv) -> Option<ArtMethodSpec> {
    // Step 1: 获取 Process.getElapsedCpuTime 的 ArtMethod*
    let probe_method = get_known_native_art_method(env)?;

    output_verbose(&format!(
        "[art spec] 探测方法: Process.getElapsedCpuTime ArtMethod*={:#x}",
        probe_method
    ));

    // Step 2: 获取 libandroid_runtime.so 地址范围（native 实现所在）
    let (rt_start, rt_end) = probe_module_range("libandroid_runtime.so");
    if rt_start == 0 {
        output_verbose("[art spec] libandroid_runtime.so 范围获取失败");
        return None;
    }

    output_verbose(&format!(
        "[art spec] libandroid_runtime.so range: {:#x}-{:#x}",
        rt_start, rt_end
    ));

    // 刷新内存映射缓存，保护后续扫描
    refresh_mem_regions();

    // Step 3: 单循环独立扫描 access_flags 和 jniCode（对标 Frida 的 remaining 计数器模式）
    // 不假设 access_flags 在 jniCode 之前 — 两者独立检测，兼容厂商魔改布局
    const EXPECTED_FLAGS: u32 = 0x0119; // kAccPublic|kAccStatic|kAccFinal|kAccNative
    const NOISE_MASK: u32 = K_ACC_FAST_INTERP_TO_INTERP | K_ACC_PUBLIC_API | K_ACC_NTERP_INVOKE_FAST_PATH_FLAG;
    const RELEVANT_MASK: u32 = !NOISE_MASK;
    const MAX_SCAN: usize = 64;

    let mut access_flags_offset: Option<usize> = None;
    let mut data_offset: Option<usize> = None;
    let mut remaining = 2u32;

    for offset in (0..MAX_SCAN).step_by(4) {
        if remaining == 0 {
            break;
        }

        // 检测 access_flags: 过滤噪声位后匹配 public|static|final|native = 0x0119
        if access_flags_offset.is_none() {
            let val = safe_read_u32(probe_method + offset as u64);
            if (val & RELEVANT_MASK) == EXPECTED_FLAGS {
                access_flags_offset = Some(offset);
                remaining -= 1;
                output_verbose(&format!(
                    "[art spec] access_flags 发现: offset={}, value={:#x}, masked={:#x}",
                    offset,
                    val,
                    val & RELEVANT_MASK
                ));
            }
        }

        // 检测 jniCode (data_): 指针落在 libandroid_runtime.so 范围内
        if data_offset.is_none() {
            let val = safe_read_u64(probe_method + offset as u64);
            // Strip PAC/TBI bits (bits 48-63)
            let stripped = val & PAC_STRIP_MASK;
            if stripped >= rt_start && stripped < rt_end {
                data_offset = Some(offset);
                remaining -= 1;
                output_verbose(&format!(
                    "[art spec] data_ (jniCode) 发现: offset={}, value={:#x}",
                    offset, val
                ));
            }
        }
    }

    let af_offset = match access_flags_offset {
        Some(o) => o,
        None => {
            output_verbose("[art spec] access_flags 未找到");
            return None;
        }
    };

    let d_offset = match data_offset {
        Some(o) => o,
        None => {
            output_verbose("[art spec] data_ (jniCode) 未找到 (expected in libandroid_runtime.so)");
            return None;
        }
    };

    // entry_point_ 紧跟 data_ 之后
    // API <= 21: entrypointFieldSize = 8 (interpreter_to_interpreter + interpreter_to_compiled 各 4 字节)
    // API >= 22: entrypointFieldSize = pointerSize (8 on ARM64)
    // ARM64 上两者都是 8，但 size 计算不同
    let api_level = get_android_api_level();
    let ep_offset = d_offset + 8;
    // size 必须覆盖所有会被读写的字段。
    // Frida 公式: quickCodeOffset + pointerSize，但 Android 16 (API 36) 的
    // access_flags 可能在 entry_point 之后 (offset 36 > quickCode+8=32)。
    // 取所有字段末尾的最大值。
    let frida_size = if api_level <= 21 { ep_offset + 32 } else { ep_offset + 8 };
    let access_flags_end = af_offset + 4; // access_flags is u32
    let size = frida_size.max(access_flags_end);

    output_verbose(&format!(
        "[art spec] Frida-style 探测成功: access_flags={}, data_={}, entry_point={}, size={} (API {})",
        af_offset, d_offset, ep_offset, size, api_level
    ));

    Some(ArtMethodSpec {
        access_flags_offset: af_offset,
        data_offset: d_offset,
        entry_point_offset: ep_offset,
        size,
    })
}

/// 获取已知 native 静态方法的 ArtMethod* (Process.getElapsedCpuTime)。
/// 该方法是 public static final native，flags 已知，用于 Frida-style 布局扫描。
///
/// 对标 Frida `unwrapMethodId(env.getStaticMethodId(...))`:
/// API 30+ 可能返回 opaque jmethodID（bit 0 = 1），需解码为真实 ArtMethod*。
unsafe fn get_known_native_art_method(env: JniEnv) -> Option<u64> {
    let c_class = CString::new("android/os/Process").unwrap();
    let c_method = CString::new("getElapsedCpuTime").unwrap();
    let c_sig = CString::new("()J").unwrap();

    let find_class: FindClassFn = jni_fn!(env, FindClassFn, JNI_FIND_CLASS);
    let get_static_mid: GetStaticMethodIdFn = jni_fn!(env, GetStaticMethodIdFn, JNI_GET_STATIC_METHOD_ID);
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);

    let cls = find_class(env, c_class.as_ptr());
    if cls.is_null() || jni_check_exc(env) {
        output_verbose("[art spec] FindClass(android/os/Process) 失败");
        return None;
    }

    let mid = get_static_mid(env, cls, c_method.as_ptr(), c_sig.as_ptr());
    if mid.is_null() || jni_check_exc(env) {
        delete_local_ref(env, cls);
        output_verbose("[art spec] GetStaticMethodID(getElapsedCpuTime) 失败");
        return None;
    }

    // 解码 opaque jmethodID → 真实 ArtMethod* (API 30+ 安全)
    // 对标 Frida 的 unwrapMethodId(): 如果 bit 0 = 0 则直接返回，否则通过反射解码
    let art_method = decode_method_id(env, cls, mid as u64, true);
    delete_local_ref(env, cls);

    if art_method != mid as u64 {
        output_verbose(&format!(
            "[art spec] jmethodID 已解码: {:#x} → ArtMethod*={:#x}",
            mid as u64, art_method
        ));
    }

    Some(art_method)
}

/// Legacy entry_point offset probing (fallback when Frida-style scan fails).
///
/// Strategy: read values at candidate offsets (24, 32) from a known method.
/// The entry_point is the one that looks like a valid code pointer.
fn probe_entry_point_offset_legacy(env: JniEnv, target_art_method: u64) -> usize {
    let val_24 = unsafe { *((target_art_method as usize + 24) as *const u64) };
    let val_32 = unsafe { *((target_art_method as usize + 32) as *const u64) };

    let is_24 = is_code_pointer(val_24);
    let is_32 = is_code_pointer(val_32);

    output_verbose(&format!(
        "[art spec] legacy probe: val_24={:#x} (code={}), val_32={:#x} (code={})",
        val_24, is_24, val_32, is_32
    ));

    let offset = if is_24 && !is_32 {
        24
    } else if is_32 && !is_24 {
        32
    } else if is_24 && is_32 {
        let cur_dex_idx = unsafe { *((target_art_method as usize + 12) as *const u32) };
        let next_32 = unsafe { *((target_art_method as usize + 32 + 12) as *const u32) };
        if next_32 == cur_dex_idx + 1 {
            24
        } else {
            32
        }
    } else {
        // Neither looks valid — try Object.hashCode as secondary probe
        probe_with_known_method_legacy(env).unwrap_or(24)
    };

    output_verbose(&format!("[art spec] legacy result: entry_point offset={}", offset));
    offset
}

/// Secondary legacy probe using Object.hashCode().
fn probe_with_known_method_legacy(env: JniEnv) -> Option<usize> {
    unsafe {
        let c_class = CString::new("java/lang/Object").unwrap();
        let c_method = CString::new("hashCode").unwrap();
        let c_sig = CString::new("()I").unwrap();

        let find_class: FindClassFn = jni_fn!(env, FindClassFn, JNI_FIND_CLASS);
        let get_mid: GetMethodIdFn = jni_fn!(env, GetMethodIdFn, JNI_GET_METHOD_ID);
        let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);

        let cls = find_class(env, c_class.as_ptr());
        if cls.is_null() || jni_check_exc(env) {
            return None;
        }

        let mid = get_mid(env, cls, c_method.as_ptr(), c_sig.as_ptr());
        delete_local_ref(env, cls);
        if mid.is_null() || jni_check_exc(env) {
            return None;
        }

        let am = mid as u64;
        let v24 = *((am as usize + 24) as *const u64);
        let v32 = *((am as usize + 32) as *const u64);
        let c24 = is_code_pointer(v24);
        let c32 = is_code_pointer(v32);

        if c24 && !c32 {
            Some(24)
        } else if c32 && !c24 {
            Some(32)
        } else {
            None
        }
    }
}

// ============================================================================
// JNI function table indices (stable across Android versions)
// ============================================================================

pub(super) const JNI_FIND_CLASS: usize = 6;
pub(super) const JNI_GET_SUPERCLASS: usize = 10;
pub(super) const JNI_TO_REFLECTED_METHOD: usize = 9;
#[allow(dead_code)]
pub(super) const JNI_TO_REFLECTED_FIELD: usize = 12;
pub(super) const JNI_EXCEPTION_OCCURRED: usize = 15;
pub(super) const JNI_EXCEPTION_CLEAR: usize = 17;
pub(super) const JNI_PUSH_LOCAL_FRAME: usize = 19;
pub(super) const JNI_POP_LOCAL_FRAME: usize = 20;
pub(super) const JNI_DELETE_LOCAL_REF: usize = 23;
pub(super) const JNI_IS_SAME_OBJECT: usize = 24;
pub(super) const JNI_GET_METHOD_ID: usize = 33;
pub(super) const JNI_CALL_OBJECT_METHOD_A: usize = 36;
pub(super) const JNI_CALL_BOOLEAN_METHOD_A: usize = 39;
pub(super) const JNI_CALL_BYTE_METHOD_A: usize = 42;
pub(super) const JNI_CALL_CHAR_METHOD_A: usize = 45;
pub(super) const JNI_CALL_SHORT_METHOD_A: usize = 48;
pub(super) const JNI_CALL_INT_METHOD_A: usize = 51;
pub(super) const JNI_CALL_LONG_METHOD_A: usize = 54;
pub(super) const JNI_CALL_FLOAT_METHOD_A: usize = 57;
pub(super) const JNI_CALL_DOUBLE_METHOD_A: usize = 60;
pub(super) const JNI_GET_STATIC_METHOD_ID: usize = 113;
pub(super) const JNI_GET_STRING_UTF_CHARS: usize = 169;
pub(super) const JNI_RELEASE_STRING_UTF_CHARS: usize = 170;
pub(super) const JNI_GET_ARRAY_LENGTH: usize = 171;
pub(super) const JNI_GET_OBJECT_ARRAY_ELEMENT: usize = 173;
pub(super) const JNI_GET_BOOLEAN_ARRAY_REGION: usize = 199;
pub(super) const JNI_GET_BYTE_ARRAY_REGION: usize = 200;
pub(super) const JNI_GET_CHAR_ARRAY_REGION: usize = 201;
pub(super) const JNI_GET_SHORT_ARRAY_REGION: usize = 202;
pub(super) const JNI_GET_INT_ARRAY_REGION: usize = 203;
pub(super) const JNI_GET_LONG_ARRAY_REGION: usize = 204;
pub(super) const JNI_GET_FLOAT_ARRAY_REGION: usize = 205;
pub(super) const JNI_GET_DOUBLE_ARRAY_REGION: usize = 206;
pub(super) const JNI_EXCEPTION_CHECK: usize = 228;
pub(super) const JNI_NEW_OBJECT_A: usize = 30;

pub(super) const JNI_CALL_STATIC_OBJECT_METHOD_A: usize = 116;
pub(super) const JNI_NEW_STRING_UTF: usize = 167;

// CallNonvirtual*MethodA indices (for callOriginal on instance methods)
pub(super) const JNI_CALL_NONVIRTUAL_OBJECT_METHOD_A: usize = 66;
pub(super) const JNI_CALL_NONVIRTUAL_BOOLEAN_METHOD_A: usize = 69;
pub(super) const JNI_CALL_NONVIRTUAL_INT_METHOD_A: usize = 81;
pub(super) const JNI_CALL_NONVIRTUAL_LONG_METHOD_A: usize = 84;
pub(super) const JNI_CALL_NONVIRTUAL_FLOAT_METHOD_A: usize = 87;
pub(super) const JNI_CALL_NONVIRTUAL_DOUBLE_METHOD_A: usize = 90;
pub(super) const JNI_CALL_NONVIRTUAL_VOID_METHOD_A: usize = 93;

// CallStatic*MethodA indices (for callOriginal on static methods)
pub(super) const JNI_CALL_STATIC_VOID_METHOD_A: usize = 143;
pub(super) const JNI_CALL_STATIC_BOOLEAN_METHOD_A: usize = 119;
pub(super) const JNI_CALL_STATIC_BYTE_METHOD_A: usize = 122;
pub(super) const JNI_CALL_STATIC_CHAR_METHOD_A: usize = 125;
pub(super) const JNI_CALL_STATIC_SHORT_METHOD_A: usize = 128;
pub(super) const JNI_CALL_STATIC_INT_METHOD_A: usize = 131;
pub(super) const JNI_CALL_STATIC_LONG_METHOD_A: usize = 134;
pub(super) const JNI_CALL_STATIC_FLOAT_METHOD_A: usize = 137;
pub(super) const JNI_CALL_STATIC_DOUBLE_METHOD_A: usize = 140;

// Void method call (instance)
pub(super) const JNI_CALL_VOID_METHOD_A: usize = 63;
// Object array
pub(super) const JNI_NEW_OBJECT_ARRAY: usize = 172;
pub(super) const JNI_SET_OBJECT_ARRAY_ELEMENT: usize = 174;

// Ref management
pub(super) const JNI_DELETE_GLOBAL_REF: usize = 22;

// Object class query
pub(super) const JNI_GET_OBJECT_CLASS: usize = 31;

// Field access & reflection
pub(super) const JNI_IS_INSTANCE_OF: usize = 32;
pub(super) const JNI_NEW_GLOBAL_REF: usize = 21;
pub(super) const JNI_NEW_LOCAL_REF: usize = 25;
pub(super) const JNI_MONITOR_ENTER: usize = 217;
pub(super) const JNI_MONITOR_EXIT: usize = 218;
pub(super) const JNI_GET_FIELD_ID: usize = 94;
pub(super) const JNI_GET_OBJECT_FIELD: usize = 95;
pub(super) const JNI_GET_BOOLEAN_FIELD: usize = 96;
pub(super) const JNI_GET_BYTE_FIELD: usize = 97;
pub(super) const JNI_GET_CHAR_FIELD: usize = 98;
pub(super) const JNI_GET_SHORT_FIELD: usize = 99;
pub(super) const JNI_GET_INT_FIELD: usize = 100;
pub(super) const JNI_GET_LONG_FIELD: usize = 101;
pub(super) const JNI_GET_FLOAT_FIELD: usize = 102;
pub(super) const JNI_GET_DOUBLE_FIELD: usize = 103;

// Static field access
pub(super) const JNI_GET_STATIC_FIELD_ID: usize = 144;
pub(super) const JNI_GET_STATIC_OBJECT_FIELD: usize = 145;
pub(super) const JNI_GET_STATIC_BOOLEAN_FIELD: usize = 146;
pub(super) const JNI_GET_STATIC_BYTE_FIELD: usize = 147;
pub(super) const JNI_GET_STATIC_CHAR_FIELD: usize = 148;
pub(super) const JNI_GET_STATIC_SHORT_FIELD: usize = 149;
pub(super) const JNI_GET_STATIC_INT_FIELD: usize = 150;
pub(super) const JNI_GET_STATIC_LONG_FIELD: usize = 151;
pub(super) const JNI_GET_STATIC_FLOAT_FIELD: usize = 152;
pub(super) const JNI_GET_STATIC_DOUBLE_FIELD: usize = 153;

// Static field write
pub(super) const JNI_SET_STATIC_OBJECT_FIELD: usize = 154;
pub(super) const JNI_SET_STATIC_BOOLEAN_FIELD: usize = 155;
pub(super) const JNI_SET_STATIC_BYTE_FIELD: usize = 156;
pub(super) const JNI_SET_STATIC_CHAR_FIELD: usize = 157;
pub(super) const JNI_SET_STATIC_SHORT_FIELD: usize = 158;
pub(super) const JNI_SET_STATIC_INT_FIELD: usize = 159;
pub(super) const JNI_SET_STATIC_LONG_FIELD: usize = 160;
pub(super) const JNI_SET_STATIC_FLOAT_FIELD: usize = 161;
pub(super) const JNI_SET_STATIC_DOUBLE_FIELD: usize = 162;

// Instance field write
pub(super) const JNI_SET_OBJECT_FIELD: usize = 104;
pub(super) const JNI_SET_BOOLEAN_FIELD: usize = 105;
pub(super) const JNI_SET_BYTE_FIELD: usize = 106;
pub(super) const JNI_SET_CHAR_FIELD: usize = 107;
pub(super) const JNI_SET_SHORT_FIELD: usize = 108;
pub(super) const JNI_SET_INT_FIELD: usize = 109;
pub(super) const JNI_SET_LONG_FIELD: usize = 110;
pub(super) const JNI_SET_FLOAT_FIELD: usize = 111;
pub(super) const JNI_SET_DOUBLE_FIELD: usize = 112;

// ============================================================================
// JNI state (lazy-initialized, cached)
// ============================================================================

pub(super) struct JniState {
    pub(super) vm: *mut std::ffi::c_void, // JavaVM*
}

unsafe impl Send for JniState {}
unsafe impl Sync for JniState {}

pub(super) static JNI_STATE: Mutex<Option<JniState>> = Mutex::new(None);

/// 从 JNI_STATE 获取 Runtime 地址 (JavaVMExt.runtime_ at offset 8)
pub(super) unsafe fn get_runtime_addr() -> Option<u64> {
    let vm_ptr = {
        let guard = JNI_STATE.lock().unwrap_or_else(|e| e.into_inner());
        match guard.as_ref() {
            Some(state) => state.vm,
            None => return None,
        }
    };
    let runtime_raw = *((vm_ptr as usize + 8) as *const u64);
    let runtime = runtime_raw & PAC_STRIP_MASK;
    if runtime == 0 {
        None
    } else {
        Some(runtime)
    }
}

/// Initialize JNI state by finding the existing JavaVM in the target process,
/// then return a JNIEnv* for the **current thread** via AttachCurrentThread.
///
/// JNIEnv is thread-local — each thread must use its own env pointer.
/// AttachCurrentThread is idempotent (cheap if already attached).
pub(crate) fn ensure_jni_initialized() -> Result<JniEnv, String> {
    // Fast path: VM already found, just attach current thread
    {
        let guard = JNI_STATE.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(ref state) = *guard {
            return unsafe { attach_current_thread(state.vm) };
        }
    }

    // Slow path: find JavaVM first
    unsafe {
        let sym = crate::jsapi::module::libart_dlsym("JNI_GetCreatedJavaVMs");
        if sym.is_null() {
            return Err("dlsym(JNI_GetCreatedJavaVMs) failed".to_string());
        }

        let get_vms: unsafe extern "C" fn(*mut *mut std::ffi::c_void, i32, *mut i32) -> i32 = std::mem::transmute(sym);

        let mut vm_ptr: *mut std::ffi::c_void = std::ptr::null_mut();
        let mut vm_count: i32 = 0;
        let ret = get_vms(&mut vm_ptr, 1, &mut vm_count);
        if ret != 0 || vm_count == 0 || vm_ptr.is_null() {
            return Err("JNI_GetCreatedJavaVMs failed".to_string());
        }

        // Cache VM pointer
        {
            let mut guard = JNI_STATE.lock().unwrap_or_else(|e| e.into_inner());
            *guard = Some(JniState { vm: vm_ptr });
        }

        // Attach current thread and return its env
        attach_current_thread(vm_ptr)
    }
}

/// Attach the current thread to the JavaVM and return its JNIEnv*.
/// Idempotent — returns existing env if thread is already attached.
unsafe fn attach_current_thread(vm_ptr: *mut std::ffi::c_void) -> Result<JniEnv, String> {
    // 先试 GetEnv — 如果当前线程已 attach，直接返回（不触发 Thread::Attach）
    let vm_table = *(vm_ptr as *const *const *const std::ffi::c_void);
    let get_env_fn: unsafe extern "C" fn(*mut std::ffi::c_void, *mut *mut std::ffi::c_void, i32) -> i32 =
        std::mem::transmute(*vm_table.add(6)); // GetEnv = index 6

    let mut env_ptr: *mut std::ffi::c_void = std::ptr::null_mut();
    let get_env_ret = get_env_fn(vm_ptr, &mut env_ptr, 0x00010006); // JNI_VERSION_1_6
    if get_env_ret == 0 && !env_ptr.is_null() {
        return Ok(env_ptr as JniEnv);
    }

    // GetEnv 失败 → 需要 AttachCurrentThread
    let attach_fn: unsafe extern "C" fn(
        *mut std::ffi::c_void,
        *mut *mut std::ffi::c_void,
        *mut std::ffi::c_void,
    ) -> i32 = std::mem::transmute(*vm_table.add(4));

    env_ptr = std::ptr::null_mut();
    let ret = attach_fn(vm_ptr, &mut env_ptr, std::ptr::null_mut());
    if ret != 0 || env_ptr.is_null() {
        return Err(format!("AttachCurrentThread failed (ret={})", ret));
    }

    Ok(env_ptr as JniEnv)
}

/// Get a valid JNIEnv* for the current thread via AttachCurrentThread.
/// Safe to call from any thread (hook callbacks run on the hooked thread).
/// AttachCurrentThread is idempotent — returns existing env if already attached.
pub(super) unsafe fn get_thread_env() -> Result<JniEnv, String> {
    // ensure_jni_initialized now always returns current thread's env
    ensure_jni_initialized()
}

// ============================================================================
// API 34+ APEX 版本检测（对标 Frida isApiLevel34OrApexEquivalent / getArtApexVersion）
// ============================================================================

/// 缓存的 ART APEX 版本号
static ART_APEX_VERSION: std::sync::OnceLock<u64> = std::sync::OnceLock::new();

/// 缓存的 API 34+ 等效判断结果
static IS_API_34_OR_APEX_EQUIV: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

/// 获取 ART APEX 模块版本号（对标 Frida getArtApexVersion）
///
/// 解析 /proc/self/mountinfo，查找 /apex/com.android.art 相关挂载行，
/// 提取版本号。如果挂载信息不可用，则 fallback 为 api_level * 10_000_000。
pub(super) fn get_art_apex_version() -> u64 {
    *ART_APEX_VERSION.get_or_init(|| {
        let version = parse_art_apex_version();
        output_verbose(&format!("[apex] ART APEX version: {}", version));
        version
    })
}

/// 判断当前环境是否等效于 API 34+（对标 Frida isApiLevel34OrApexEquivalent）
///
/// 通过 dlsym 检查 libart.so 是否导出 API 34 新增符号:
/// - AppInfo::GetPrimaryApkReferenceProfile
/// - Thread::RunFlipFunction(Thread*, bool)  (API 34 新增 bool 参数版本)
///
/// 任一存在即返回 true。用于处理 APEX 模块更新导致 ART 内部布局
/// 与 SDK API 级别不一致的情况（如 API 33 设备安装了 API 34 的 ART APEX）。
pub(super) fn is_api_level_34_or_apex_equivalent() -> bool {
    *IS_API_34_OR_APEX_EQUIV.get_or_init(|| {
        use crate::jsapi::module::libart_dlsym;

        let result = unsafe {
            // 检查 API 34 新增符号
            let sym1 = libart_dlsym("_ZN3art7AppInfo29GetPrimaryApkReferenceProfileEv");
            if !sym1.is_null() {
                output_verbose("[apex] API 34+ 等效: 发现 AppInfo::GetPrimaryApkReferenceProfile");
                return true;
            }

            // Thread::RunFlipFunction(Thread*, bool) — API 34 新增 bool 参数重载
            let sym2 = libart_dlsym("_ZN3art6Thread15RunFlipFunctionEPS0_b");
            if !sym2.is_null() {
                output_verbose("[apex] API 34+ 等效: 发现 Thread::RunFlipFunction(Thread*, bool)");
                return true;
            }

            false
        };

        if !result {
            output_verbose("[apex] API 34+ 等效检测: 未发现特征符号");
        }
        result
    })
}

// ============================================================================
// JNI IDs Indirection — Frida-style 读取+按需解码 (对标 Frida unwrapGenericId)
// ============================================================================

/// JNI ID 解码能力缓存
///
/// 对标 Frida: 读取 Runtime.jni_ids_indirection_ 判断模式，
/// 按需通过 JniIdManager::DecodeMethodId/DecodeFieldId 解码。
/// 仅当 dlsym 解码函数不可用时，才 fallback 强制写 kPointer。
struct JniIdDecoderState {
    /// Runtime.jni_ids_indirection_ 字段地址 (用于每次读取当前模式)
    indirection_field_addr: *const i32,
    /// JniIdManager::DecodeMethodId 函数指针 (可能为 null)
    decode_method_id_fn: Option<DecodeIdFn>,
    /// JniIdManager::DecodeFieldId 函数指针 (可能为 null)
    #[allow(dead_code)]
    decode_field_id_fn: Option<DecodeIdFn>,
    /// JniIdManager* 指针 (作为 DecodeMethodId/DecodeFieldId 的 this)
    jni_id_manager: u64,
    /// 是否已 fallback 强制写为 kPointer (当 decode 函数不可用时)
    forced_pointer_mode: bool,
}

unsafe impl Send for JniIdDecoderState {}
unsafe impl Sync for JniIdDecoderState {}

/// C++ 成员函数签名: ArtMethod*/ArtField* DecodeXxxId(JniIdManager* this, jxxxID id)
type DecodeIdFn = unsafe extern "C" fn(this: *mut std::ffi::c_void, id: *mut std::ffi::c_void) -> u64;

/// kPointer = 0 (jmethodID 直接是 ArtMethod*)
const K_POINTER: i32 = 0;

static JNI_ID_DECODER: std::sync::OnceLock<Option<JniIdDecoderState>> = std::sync::OnceLock::new();

/// 初始化 JNI ID 解码器（对标 Frida unwrapGenericId 的初始化部分）
///
/// Strategy:
/// 1. 探测 jni_ids_indirection_ 偏移 → 获取字段地址（用于运行时读取）
/// 2. dlsym DecodeMethodId / DecodeFieldId
/// 3. 从 ArtRuntimeSpec 获取 JniIdManager* 指针
/// 4. 如果 decode 函数可用 → 纯读取模式，不修改 ART 状态
/// 5. 如果 decode 函数不可用但 indirection != kPointer → fallback 强制写 kPointer
pub(super) fn init_jni_id_decoder() {
    JNI_ID_DECODER.get_or_init(|| {
        use super::art_method::{get_art_runtime_spec, get_jni_ids_indirection_offset};
        use super::PAC_STRIP_MASK;

        // Step 1: 探测 indirection offset
        let indirection_offset = match get_jni_ids_indirection_offset() {
            Some(o) => o,
            None => {
                output_verbose("[jniIds] indirection offset 不可用，ID 解码走 fallback 路径");
                return None;
            }
        };

        // Step 2: 获取 Runtime*
        let runtime = match unsafe { get_runtime_addr() } {
            Some(r) => r,
            None => {
                output_verbose("[jniIds] 无法获取 Runtime 地址");
                return None;
            }
        };

        let indirection_field_addr = (runtime as usize + indirection_offset) as *const i32;

        // Step 3: dlsym DecodeMethodId / DecodeFieldId (对标 Frida android.js:316-317)
        let decode_method_fn = unsafe {
            let sym = crate::jsapi::module::libart_dlsym("_ZN3art3jni12JniIdManager14DecodeMethodIdEP10_jmethodID");
            if !sym.is_null() {
                Some(std::mem::transmute::<*mut std::ffi::c_void, DecodeIdFn>(sym))
            } else {
                None
            }
        };

        let decode_field_fn = unsafe {
            let sym = crate::jsapi::module::libart_dlsym("_ZN3art3jni12JniIdManager13DecodeFieldIdEP9_jfieldID");
            if !sym.is_null() {
                Some(std::mem::transmute::<*mut std::ffi::c_void, DecodeIdFn>(sym))
            } else {
                None
            }
        };

        // Step 4: 获取 JniIdManager* (from ArtRuntimeSpec)
        let jni_id_manager = if decode_method_fn.is_some() || decode_field_fn.is_some() {
            match get_art_runtime_spec() {
                Some(spec) => match spec.jni_id_manager_offset {
                    Some(off) => {
                        let mgr = unsafe { super::safe_mem::safe_read_u64(runtime + off as u64) & PAC_STRIP_MASK };
                        if mgr != 0 {
                            output_verbose(&format!("[jniIds] JniIdManager*={:#x} (Runtime+{:#x})", mgr, off));
                        }
                        mgr
                    }
                    None => 0,
                },
                None => 0,
            }
        } else {
            0
        };

        let has_decode = (decode_method_fn.is_some() || decode_field_fn.is_some()) && jni_id_manager != 0;

        // Step 5: 如果 decode 函数可用 → Frida 风格纯读取，不修改 ART 状态
        // 如果 decode 函数不可用 → fallback 强制写 kPointer
        let current_mode = unsafe { std::ptr::read_volatile(indirection_field_addr) };
        let forced_pointer_mode = if has_decode {
            output_verbose(&format!(
                "[jniIds] Frida-style 解码器就绪: DecodeMethodId={}, DecodeFieldId={}, indirection={}",
                decode_method_fn.is_some(),
                decode_field_fn.is_some(),
                current_mode
            ));
            false // 不需要强制写
        } else if current_mode != K_POINTER {
            // 无 decode 函数但 indirection != kPointer → 必须强制写
            unsafe { std::ptr::write_volatile(indirection_field_addr as *mut i32, K_POINTER) };
            output_verbose(&format!(
                "[jniIds] decode 函数不可用，fallback 强制 indirection {} → 0 (kPointer), Runtime+{:#x}",
                current_mode, indirection_offset
            ));
            true
        } else {
            output_verbose("[jniIds] 已为 kPointer 模式，jmethodID 即 ArtMethod* 直接可用");
            false
        };

        Some(JniIdDecoderState {
            indirection_field_addr,
            decode_method_id_fn: decode_method_fn,
            decode_field_id_fn: decode_field_fn,
            jni_id_manager,
            forced_pointer_mode,
        })
    });
}

/// 读取当前 jni_ids_indirection_ 值，判断是否为指针模式
///
/// 对标 Frida: 每次读取 Runtime.jni_ids_indirection_，不假设其值不变。
pub(super) fn is_jni_pointer_mode() -> bool {
    match JNI_ID_DECODER.get() {
        Some(Some(state)) => {
            if state.forced_pointer_mode {
                return true; // 已强制写为 kPointer
            }
            let current = unsafe { std::ptr::read_volatile(state.indirection_field_addr) };
            current == K_POINTER
        }
        _ => false, // 未初始化或初始化失败 → 保守假设需要解码
    }
}

/// 通用 JNI ID 解码: 检查 indirection 模式，按需调用 decode 函数。
///
/// 对标 Frida unwrapGenericId: 读取 indirection 值，如果不是 kPointer
/// 则调用对应的 DecodeXxxId(jniIdManager, id)。
unsafe fn decode_id_via_manager(id: u64, get_fn: impl Fn(&JniIdDecoderState) -> Option<DecodeIdFn>) -> Option<u64> {
    let state = JNI_ID_DECODER.get()?.as_ref()?;

    if state.forced_pointer_mode {
        return Some(id);
    }

    let indirection = std::ptr::read_volatile(state.indirection_field_addr);
    if indirection == K_POINTER {
        return Some(id);
    }

    let decode_fn = get_fn(state)?;
    if state.jni_id_manager == 0 {
        return None;
    }

    let result = decode_fn(
        state.jni_id_manager as *mut std::ffi::c_void,
        id as *mut std::ffi::c_void,
    );
    if result != 0 {
        Some(result)
    } else {
        None
    }
}

/// 通过 JniIdManager::DecodeMethodId 解码 jmethodID → ArtMethod*
pub(super) unsafe fn decode_method_id_via_manager(method_id: u64) -> Option<u64> {
    decode_id_via_manager(method_id, |s| s.decode_method_id_fn)
}

/// 通过 JniIdManager::DecodeFieldId 解码 jfieldID → ArtField*
#[allow(dead_code)]
pub(super) unsafe fn decode_field_id_via_manager(field_id: u64) -> Option<u64> {
    decode_id_via_manager(field_id, |s| s.decode_field_id_fn)
}

/// 解析 /proc/self/mountinfo 提取 ART APEX 版本号
///
/// 对标 Frida getArtApexVersion 逻辑:
/// 遍历每行，第5列 (mountRoot) 以 /apex/com.android.art 开头时:
/// - 如果 mountRoot 包含 '@'，则 split('@') 取版本部分，记录到 sourceVersions[mountSource]
/// - 否则记录 artSource = mountSource (第11列)
/// 最终如果 sourceVersions 包含 artSource，返回对应版本；否则 fallback。
fn parse_art_apex_version() -> u64 {
    use std::collections::HashMap;

    let content = match std::fs::read_to_string("/proc/self/mountinfo") {
        Ok(c) => c,
        Err(_) => {
            output_verbose("[apex] /proc/self/mountinfo 读取失败，使用 fallback");
            let api = get_android_api_level() as u64;
            return api * 10_000_000;
        }
    };

    let mut source_versions: HashMap<String, u64> = HashMap::new();
    let mut art_source: Option<String> = None;

    for line in content.lines() {
        let elements: Vec<&str> = line.split(' ').collect();
        if elements.len() < 11 {
            continue;
        }

        let mount_root = elements[4]; // 第5列 (0-indexed)
        if !mount_root.starts_with("/apex/com.android.art") {
            continue;
        }

        let mount_source = elements[10]; // 第11列

        if mount_root.contains('@') {
            // 格式: /apex/com.android.art@341715org — '@' 后面是版本号
            if let Some(version_str) = mount_root.split('@').nth(1) {
                // 提取纯数字前缀作为版本号
                let version_digits: String = version_str.chars().take_while(|c| c.is_ascii_digit()).collect();
                if let Ok(version) = version_digits.parse::<u64>() {
                    source_versions.insert(mount_source.to_string(), version);
                }
            }
        } else {
            art_source = Some(mount_source.to_string());
        }
    }

    // 如果找到 artSource 且 sourceVersions 中有对应版本，返回它
    if let Some(ref src) = art_source {
        if let Some(&version) = source_versions.get(src) {
            return version;
        }
    }

    // Fallback: api_level * 10_000_000
    let api = get_android_api_level() as u64;
    api * 10_000_000
}
