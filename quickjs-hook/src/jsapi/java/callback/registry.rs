// ============================================================================
// Hook registry
// ============================================================================

/// Hook 类型：统一 Clone+Replace 策略
/// 所有回调统一 JNI 调用约定: x0=JNIEnv*, x1=this/jclass, x2+=args
#[derive(Debug)]
pub(super) enum HookType {
    /// Unified replacement hook (art_router swaps ArtMethod*)
    /// - replacement_addr: heap-allocated replacement ArtMethod (native, jniCode=thunk)
    /// - per_method_hook_target: Some(quickCode) for compiled methods (Layer 3 router hook),
    ///   None for shared stub methods (routed via Layer 1/2)
    Replaced {
        replacement_addr: usize,
        per_method_hook_target: Option<u64>,
    },
}

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
    // JNI global ref to jclass (for JNI CallNonvirtual/Static calls)
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
}

unsafe impl Send for JavaHookData {}
unsafe impl Sync for JavaHookData {}

/// Global Java hook registry keyed by art_method address
pub(super) static JAVA_HOOK_REGISTRY: Mutex<Option<HashMap<u64, JavaHookData>>> = Mutex::new(None);

pub(super) static IN_FLIGHT_JAVA_HOOK_CALLBACKS: Mutex<usize> = Mutex::new(0);
pub(super) static IN_FLIGHT_JAVA_HOOK_CALLBACKS_CV: Condvar = Condvar::new();

/// RAII guard for callbacks that already entered the Java hook trampoline path.
///
/// cleanup_java_hooks() waits on this counter instead of relying on a blind sleep.
pub(super) struct InFlightJavaHookGuard;

impl InFlightJavaHookGuard {
    pub(super) fn enter() -> Self {
        let mut in_flight = IN_FLIGHT_JAVA_HOOK_CALLBACKS
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *in_flight += 1;
        Self
    }
}

impl Drop for InFlightJavaHookGuard {
    fn drop(&mut self) {
        let mut in_flight = IN_FLIGHT_JAVA_HOOK_CALLBACKS
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *in_flight = in_flight.saturating_sub(1);
        if *in_flight == 0 {
            IN_FLIGHT_JAVA_HOOK_CALLBACKS_CV.notify_all();
        }
    }
}

pub(super) fn in_flight_java_hook_callbacks() -> usize {
    *IN_FLIGHT_JAVA_HOOK_CALLBACKS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

pub(super) fn wait_for_in_flight_java_hook_callbacks(timeout: std::time::Duration) -> bool {
    let start = std::time::Instant::now();
    let mut in_flight = IN_FLIGHT_JAVA_HOOK_CALLBACKS
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    while *in_flight != 0 {
        let Some(remaining) = timeout.checked_sub(start.elapsed()) else {
            return false;
        };
        let (guard, wait_result) = IN_FLIGHT_JAVA_HOOK_CALLBACKS_CV
            .wait_timeout(in_flight, remaining)
            .unwrap_or_else(|e| e.into_inner());
        in_flight = guard;
        if wait_result.timed_out() && *in_flight != 0 {
            return false;
        }
    }
    true
}

/// Parse JNI signature to extract the return type character.
/// "(II)V" → b'V', "(Ljava/lang/String;)Ljava/lang/Object;" → b'L'
pub(super) fn get_return_type_from_sig(sig: &str) -> u8 {
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
pub(super) fn get_return_type_sig(sig: &str) -> String {
    if let Some(pos) = sig.rfind(')') {
        sig[pos + 1..].to_string()
    } else {
        "V".to_string()
    }
}

pub(super) fn init_java_registry() {
    ensure_registry_initialized(&JAVA_HOOK_REGISTRY);
}

/// Build a unique key string for method lookup
pub(super) fn method_key(class: &str, method: &str, sig: &str) -> String {
    format!("{}.{}{}", class, method, sig)
}
