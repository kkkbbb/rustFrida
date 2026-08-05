// ============================================================================
// Hook registry
// ============================================================================

/// Hook 类型：统一 Clone+Replace 策略
/// 所有回调统一 JNI 调用约定: x0=JNIEnv*, x1=this/jclass, x2+=args
#[derive(Debug, Clone)]
pub(super) enum HookType {
    /// Registered native fnPtr hook only.
    ///
    /// The original ArtMethod is not modified. The hook is installed by
    /// patching the native function body pointed to by ArtMethod::data_.
    NativeEntry,
    /// Unified replacement hook (art_router swaps ArtMethod*)
    /// - replacement_addr: heap-allocated replacement ArtMethod (native, jniCode=thunk)
    /// - per_method_hook_target: Some(quickCode) for compiled methods (Layer 3 router hook),
    ///   Some(standalone stub) for shared stubs not covered by Layer 1, and None for
    ///   shared stub methods routed via Layer 1/2.
    Replaced {
        replacement_addr: usize,
        per_method_hook_target: Option<u64>,
        original_flags_mutated: bool,
        original_entry_mutated: bool,
    },
    /// Experimental quick callback hook.
    /// Router calls Rust directly and only uses replacement_addr as a native
    /// stack-walk sentinel while the callback is active.
    Quick {
        replacement_addr: usize,
        per_method_hook_target: Option<u64>,
        declaring_class_source: u64,
    },
    /// Replacement is a real ART-managed Java method loaded from helper dex.
    /// It must not be freed or have declaring_class_ synchronized from the
    /// hooked method.
    Managed {
        replacement_art_method: u64,
        sentinel_addr: usize,
        per_method_hook_target: Option<u64>,
    },
}

impl HookType {
    pub(super) fn original_flags_mutated(&self) -> bool {
        match self {
            HookType::NativeEntry | HookType::Quick { .. } => false,
            HookType::Replaced {
                original_flags_mutated,
                ..
            } => *original_flags_mutated,
            HookType::Managed { .. } => true,
        }
    }

    pub(super) fn original_entry_mutated(&self) -> bool {
        match self {
            HookType::Replaced {
                original_entry_mutated,
                ..
            } => *original_entry_mutated,
            _ => false,
        }
    }
}

#[derive(Clone)]
pub(super) struct JavaHookData {
    pub(super) art_method: u64,
    // Frida-style original method state（unhook 时恢复全部字段）
    pub(super) original_access_flags: u32,
    pub(super) original_entry_point: u64, // quickCode / entry_point_
    pub(super) original_data: u64,        // data_ / jniCode
    // Hook 路径类型
    pub(super) hook_type: HookType,
    // Backup clone for callOriginal (heap, 原始状态副本)
    pub(super) clone_addr: u64,
    // JNI global ref to jclass (for JNI CallNonvirtual/Static calls).
    // Raw clone installs may store 0 and derive a temporary local class ref
    // from ArtMethod.declaring_class_ when needed.
    pub(super) class_global_ref: usize,
    // Return type char from JNI signature: b'V', b'I', b'J', b'Z', b'L', etc.
    pub(super) return_type: u8,
    // Full return type descriptor from signature (e.g. "V", "I", "Ljava/lang/String;", "[B")
    pub(super) return_type_sig: String,
    // JS callback info
    pub(super) ctx: usize,
    pub(super) callback_bytes: [u8; 16],
    pub(super) method_key: String, // "class.method.sig" for lookup
    pub(super) is_static: bool,
    pub(super) param_count: usize,
    // Per-parameter JNI type descriptors (e.g. ["I", "Ljava/lang/String;", "[B"])
    pub(super) param_types: Vec<String>,
    // Hooked class name (dot notation, for wrapping object args)
    #[allow(dead_code)]
    pub(super) class_name: String,
    /// Layer 3 art_router trampoline 地址 (quickCode 原始指令 + jump back)。
    /// callback skip fallback 用它直接调原始方法，避免走 JNI re-entry 路径。
    /// 0 = 无 trampoline（非 compiled 方法，走 Layer 1/2 路由）。
    pub(super) quick_trampoline: u64,
    /// true = thunk 用 BLR (post-callback dispatch), $orig 可设 fast_orig 标志。
    /// false = thunk 用 BR, $orig 必须走 JNI 路径。
    pub(super) use_blr: bool,
    /// Registered native method entry hook target passed to hook_engine.
    ///
    /// ART's generic JNI trampoline calls ArtMethod::data_ (the registered
    /// native fnPtr) directly, so shared-stub routing may never see the Java
    /// invocation. In recomp mode this is the anonymous slot, not the original
    /// native fnPtr. Non-zero means $orig must call this trampoline instead of
    /// re-entering the ArtMethod via JNI.
    pub(super) native_entry_hook_target: u64,
    pub(super) native_entry_trampoline: u64,
    /// true when the native entry uses @CriticalNative ABI:
    /// x0+ are Java primitive args directly, no JNIEnv*/jclass receiver.
    pub(super) native_entry_critical: bool,
}

unsafe impl Send for JavaHookData {}
unsafe impl Sync for JavaHookData {}

/// Global Java hook registry keyed by art_method address
pub(super) static JAVA_HOOK_REGISTRY: Mutex<Option<HashMap<u64, JavaHookData>>> = Mutex::new(None);

/// Java hook 在途计数 —— 只在"JS callback 实际执行中"时 ≠ 0。
///
/// 计数点 (Rust java_hook_callback 进出):
///   enter → IN_FLIGHT += 1   (JSEngine 获取前)
///   drop  → IN_FLIGHT -= 1   (JSEngine 返回后)
///
/// 与旧方案 (汇编 thunk 全局 g_thunk_in_flight) 的区别：
/// - 旧: art_router scan 进入就计, found/not_found 一视同仁, attach 包裹原函数 →
///        任何 Java 阻塞都把 counter 钉死不归零
/// - 新: 只计 "正在执行 JS callback 的线程", 只要 JS 回调链退出就减. 原函数
///        (DoCall 走 not_found 路径) 阻塞不影响计数
///
/// drain=0 语义: "没有任何 JS callback 在执行" → 安全 free callback JSValue /
/// JNI ref / replacement ArtMethod. 栈帧残留于 attach thunk BLR 之后 (callback 未
/// 触发, 线程在原函数内阻塞) 对软清理无影响 (不 munmap pool, 线程后续自然返回).
static IN_FLIGHT_JAVA_HOOK_CALLBACKS: std::sync::Mutex<usize> = std::sync::Mutex::new(0);
static IN_FLIGHT_JAVA_HOOK_CALLBACKS_CV: std::sync::Condvar = std::sync::Condvar::new();

pub(crate) struct InFlightJavaHookGuard;

impl InFlightJavaHookGuard {
    pub(crate) fn enter() -> Self {
        let mut c = IN_FLIGHT_JAVA_HOOK_CALLBACKS.lock().unwrap_or_else(|e| e.into_inner());
        *c += 1;
        Self
    }
}

impl Drop for InFlightJavaHookGuard {
    fn drop(&mut self) {
        let mut c = IN_FLIGHT_JAVA_HOOK_CALLBACKS.lock().unwrap_or_else(|e| e.into_inner());
        *c = c.saturating_sub(1);
        if *c == 0 {
            IN_FLIGHT_JAVA_HOOK_CALLBACKS_CV.notify_all();
        }
    }
}

pub(super) fn in_flight_java_hook_callbacks() -> usize {
    *IN_FLIGHT_JAVA_HOOK_CALLBACKS.lock().unwrap_or_else(|e| e.into_inner())
}

/// 条件变量等 IN_FLIGHT_JAVA_HOOK_CALLBACKS 归零 (callback drop 时 notify_all)
pub(super) fn wait_for_in_flight_java_hook_callbacks(timeout: std::time::Duration) -> bool {
    let start = std::time::Instant::now();
    let mut c = IN_FLIGHT_JAVA_HOOK_CALLBACKS.lock().unwrap_or_else(|e| e.into_inner());
    while *c != 0 {
        let Some(remaining) = timeout.checked_sub(start.elapsed()) else {
            return false;
        };
        let (guard, res) = IN_FLIGHT_JAVA_HOOK_CALLBACKS_CV
            .wait_timeout(c, remaining)
            .unwrap_or_else(|e| e.into_inner());
        c = guard;
        if res.timed_out() && *c != 0 {
            return false;
        }
    }
    true
}

/// Parse JNI signature to extract the return type character.
/// "(II)V" → b'V', "(Ljava/lang/String;)Ljava/lang/Object;" → b'L'
pub(crate) fn get_return_type_from_sig(sig: &str) -> u8 {
    if let Some(pos) = sig.rfind(')') {
        let ret = &sig[pos + 1..];
        match ret.as_bytes().first() {
            Some(&c) => c,
            None => b'V',
        }
    } else {
        b'V'
    }
}

/// Extract the full return type descriptor from a JNI method signature.
/// "(II)V" → "V", "(I)Ljava/lang/String;" → "Ljava/lang/String;", "()[B" → "[B"
pub(crate) fn get_return_type_sig(sig: &str) -> String {
    if let Some(pos) = sig.rfind(')') {
        sig[pos + 1..].to_string()
    } else {
        "V".to_string()
    }
}

pub(super) fn init_java_registry() {
    ensure_registry_initialized(&JAVA_HOOK_REGISTRY);
}

pub(super) fn fast_hook_invoke_meta(art_method: u64) -> Option<(u64, bool)> {
    let guard = JAVA_HOOK_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    let data = guard.as_ref()?.get(&art_method)?;
    match data.hook_type {
        HookType::Quick { .. } if crate::fast_hook::is_fast_hook(art_method) => {
            Some((data.quick_trampoline, data.use_blr))
        }
        _ => None,
    }
}

pub(crate) fn registered_methods_for_class(class_name: &str) -> Vec<MethodInfo> {
    let prefix = format!("{}.", class_name);
    let guard = JAVA_HOOK_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    let Some(registry) = guard.as_ref() else {
        return Vec::new();
    };

    registry
        .values()
        .filter_map(|data| {
            let rest = data.method_key.strip_prefix(&prefix)?;
            let sig_start = rest.find('(')?;
            let name = &rest[..sig_start];
            let sig = &rest[sig_start..];
            Some(MethodInfo {
                name: name.to_string(),
                sig: sig.to_string(),
                is_static: data.is_static,
                modifiers: 0,
            })
        })
        .collect()
}

pub(crate) unsafe fn registered_class_mirror_for_class(class_name: &str) -> Option<u64> {
    let prefix = format!("{}.", class_name);
    let guard = JAVA_HOOK_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    let registry = guard.as_ref()?;

    registry
        .values()
        .find(|data| data.method_key.starts_with(&prefix) || data.class_name == class_name)
        .map(|data| art_method_declaring_class_mirror(data.art_method))
        .filter(|mirror| *mirror != 0)
}

pub(super) fn registered_invoke_target_for_key(
    class_name: &str,
    method_name: &str,
    sig: &str,
    is_static: bool,
) -> Option<(u64, usize)> {
    let key = method_key(class_name, method_name, sig);
    let guard = JAVA_HOOK_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    let data = guard
        .as_ref()?
        .values()
        .find(|data| data.method_key == key && data.is_static == is_static)?;
    Some((data.art_method, data.class_global_ref))
}

static ART_MIRROR_NEW_LOCAL_REF: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
static ART_JNIENV_DELETE_LOCAL_REF: std::sync::OnceLock<usize> = std::sync::OnceLock::new();

pub(super) unsafe fn art_method_declaring_class_mirror(art_method_addr: u64) -> u64 {
    if art_method_addr < 0x1000 {
        return 0;
    }

    let compressed = std::ptr::read_volatile(art_method_addr as *const u32) as u64;
    if compressed > 0x10000 && crate::jsapi::util::is_addr_accessible(compressed, 4) {
        return compressed;
    }

    let raw = std::ptr::read_volatile(art_method_addr as *const u64) & super::PAC_STRIP_MASK;
    if raw > 0x10000 && crate::jsapi::util::is_addr_accessible(raw, 4) {
        return raw;
    }

    0
}

pub(super) unsafe fn raw_mirror_to_local_ref(env: JniEnv, raw: u64) -> *mut std::ffi::c_void {
    if env.is_null() || raw == 0 {
        return std::ptr::null_mut();
    }

    let sym = *ART_MIRROR_NEW_LOCAL_REF.get_or_init(|| {
        crate::jsapi::module::libart_dlsym("_ZN3art9JNIEnvExt11NewLocalRefEPNS_6mirror6ObjectE") as usize
    });
    if sym != 0 {
        type NewLocalFromMirrorFn = unsafe extern "C" fn(
            *mut std::ffi::c_void,
            *mut std::ffi::c_void,
        ) -> *mut std::ffi::c_void;
        let f: NewLocalFromMirrorFn = std::mem::transmute(sym);
        return f(env as *mut std::ffi::c_void, raw as *mut std::ffi::c_void);
    }

    if crate::is_raw_clone_js_thread() {
        crate::jsapi::console::output_verbose(
            "[raw mirror] JNIEnvExt::NewLocalRef unavailable on raw clone; refusing JNI fallback",
        );
        return std::ptr::null_mut();
    }

    let new_local_ref: NewLocalRefFn = jni_fn!(env, NewLocalRefFn, JNI_NEW_LOCAL_REF);
    new_local_ref(env, raw as *mut std::ffi::c_void)
}

pub(super) unsafe fn raw_delete_local_ref(env: JniEnv, obj: *mut std::ffi::c_void) {
    if env.is_null() || obj.is_null() {
        return;
    }

    let sym = *ART_JNIENV_DELETE_LOCAL_REF.get_or_init(|| {
        crate::jsapi::module::libart_dlsym("_ZN3art9JNIEnvExt14DeleteLocalRefEP8_jobject") as usize
    });
    if sym != 0 {
        type DeleteLocalRefFn =
            unsafe extern "C" fn(*mut std::ffi::c_void, *mut std::ffi::c_void);
        let f: DeleteLocalRefFn = std::mem::transmute(sym);
        f(env as *mut std::ffi::c_void, obj);
        return;
    }

    if crate::is_raw_clone_js_thread() {
        crate::jsapi::console::output_verbose(
            "[raw mirror] JNIEnvExt::DeleteLocalRef unavailable on raw clone; leaking local ref",
        );
        return;
    }

    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
    delete_local_ref(env, obj);
}

pub(super) unsafe fn local_class_ref_for_art_method(env: JniEnv, art_method_addr: u64) -> *mut std::ffi::c_void {
    raw_mirror_to_local_ref(env, art_method_declaring_class_mirror(art_method_addr))
}

/// Build a unique key string for method lookup
pub(super) fn method_key(class: &str, method: &str, sig: &str) -> String {
    format!("{}.{}{}", class, method, sig)
}
