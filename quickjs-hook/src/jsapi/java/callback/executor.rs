// ============================================================================
// Raw-clone Java executor mailbox
// ============================================================================
//
// Raw clone JS threads must not enter ART's Call*MethodA/NewObjectA paths.
// Instead they enqueue a native task here and wait. A real Java thread drains
// the mailbox from java_hook_callback before acquiring the QuickJS engine lock.

#[derive(Clone)]
pub(crate) enum JniExecutorOp {
    ThreadEnv,
    ClassName {
        cls_ptr: u64,
    },
    ReadJString {
        obj_ptr: u64,
    },
    GetObjectClass {
        obj_ptr: u64,
    },
    GetSuperclass {
        cls_ptr: u64,
    },
    IsSameObject {
        a_ptr: u64,
        b_ptr: u64,
    },
    IsInstanceOf {
        obj_ptr: u64,
        cls_ptr: u64,
    },
    GetObjectClassName {
        obj_ptr: u64,
    },
    ExceptionCheck,
    ExceptionClear,
    ExceptionOccurred,
    FindClass {
        name: String,
    },
    NewStringUtf {
        value: String,
    },
    NewLocalRef {
        obj_ptr: u64,
    },
    DeleteLocalRef {
        obj_ptr: u64,
    },
}

#[derive(Clone)]
enum ExecutorTaskKind {
    StartJavaWorker {
        native_loop: u64,
    },
    Jni {
        op: JniExecutorOp,
    },
    Methods {
        class_name: String,
    },
    ResolveMethod {
        class_name: String,
        method_name: String,
        method_sig: String,
        force_static: bool,
    },
    Instance {
        obj_ptr: u64,
        obj_is_global: bool,
        class_name: String,
        method_name: String,
        method_sig: String,
    },
    Static {
        class_name: String,
        method_name: String,
        method_sig: String,
    },
    NewObject {
        class_name: String,
        ctor_sig: String,
    },
    CleanupGlobals {
        refs: Vec<u64>,
    },
    ArrayLength {
        array_ptr: u64,
        array_is_global: bool,
    },
    ArrayGet {
        array_ptr: u64,
        array_is_global: bool,
        index: i32,
        elem_sig: String,
    },
    FieldMeta {
        class_name: String,
        field_name: String,
    },
    FieldRead {
        obj_ptr: u64,
        obj_is_global: bool,
        class_name: String,
        field_id: u64,
        sig: String,
        is_static: bool,
    },
    FieldWrite {
        obj_ptr: u64,
        obj_is_global: bool,
        class_name: String,
        field_id: u64,
        sig: String,
        is_static: bool,
    },
    DirectGetField {
        obj_ptr: u64,
        class_name: String,
        field_name: String,
        field_sig: String,
    },
    EnumerateInstances {
        class_name: String,
        include_subtypes: bool,
        max_count: usize,
    },
    ClassLoaders,
    FindClassWithLoader {
        loader_ptr: u64,
        class_name: String,
    },
    FindClassObject {
        class_name: String,
    },
    SetClassLoader {
        loader_ptr: u64,
    },
    ResolveFastMethod {
        class_name: String,
        method_name: String,
        method_sig: String,
        force_static: bool,
        should_compile: bool,
        compile_kind: super::java_fast_api::RequestedCompileKind,
    },
    ResolveFastField {
        class_name: String,
        field_name: String,
        requested_sig: Option<String>,
    },
    ManagedHookDsl {
        class_name: String,
        method_name: String,
        method_sig: String,
        dsl: String,
        message_capacity: i32,
    },
    FastHook {
        class_name: String,
        method_name: String,
        method_sig: String,
        dsl: String,
    },
    DeoptimizeMethod {
        class_name: String,
        method_name: String,
        method_sig: String,
        force_static: bool,
    },
    CompileMethod {
        class_name: String,
        method_name: String,
        method_sig: String,
        force_static: bool,
        compile_kind: super::java_fast_api::RequestedCompileKind,
    },
    JitInfo,
    ReprobeClassLoader {
        once: bool,
    },
    ManagedDrainMessages {
        helper_class: String,
        max_items_requested: Option<i64>,
    },
    ManagedReadCounter {
        helper_class: String,
        field_name: String,
    },
}

#[derive(Clone)]
enum ExecutorArg {
    Raw(u64),
    String(String),
    Object(u64),
    GlobalRef(u64),
    Null,
}

enum ExecutorValue {
    Undefined,
    Null,
    Bool(bool),
    Int(i32),
    BigU64(u64),
    Pointer(u64),
    Float(f64),
    String(String),
    Object {
        ptr: u64,
        class_name: String,
        is_global: bool,
    },
    FieldMeta {
        field_id: u64,
        sig: String,
        is_static: bool,
        class_name: String,
        field_offset: u32,
    },
    InstanceRefs {
        refs: Vec<u64>,
        class_name: String,
    },
    Method {
        art_method: u64,
        is_static: bool,
    },
    Methods(Vec<MethodInfo>),
    ClassLoaders(Vec<ClassLoaderInfo>),
    FindClassWithLoader {
        loader_ptr: u64,
        class_name: String,
        via: Option<&'static str>,
    },
    FastMethod {
        art_method: u64,
        class_global_ref: u64,
        class_mirror: u64,
        is_static: bool,
    },
    FastField(super::java_fast_api::FastField),
    ManagedHookDsl(super::java_hook_api::ManagedDslInstallResult),
    ManagedDrain(super::java_hook_api::ManagedDrainResult),
    CompileResult {
        art_method: u64,
        result: super::java_fast_api::CompileResult,
    },
    JitInfo {
        runtime: u64,
        java_vm_offset: u64,
        jit_offset: u64,
        jit_code_cache_offset: u64,
        direct_jit: u64,
        runtime_jit_code_cache: u64,
        direct_get_code_cache: u64,
        found_jit: u64,
        message: String,
    },
}

type ExecutorResult = Result<ExecutorValue, String>;

type ExecCallStaticBooleanMethodAFn =
    unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, *const std::ffi::c_void) -> u8;
type ExecCallStaticByteMethodAFn =
    unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, *const std::ffi::c_void) -> i8;
type ExecCallStaticCharMethodAFn =
    unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, *const std::ffi::c_void) -> u16;
type ExecCallStaticShortMethodAFn =
    unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, *const std::ffi::c_void) -> i16;
type ExecCallStaticLongMethodAFn =
    unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, *const std::ffi::c_void) -> i64;
type ExecCallStaticFloatMethodAFn =
    unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, *const std::ffi::c_void) -> f32;
type ExecCallStaticDoubleMethodAFn =
    unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, *const std::ffi::c_void) -> f64;

struct ExecutorRequest {
    kind: ExecutorTaskKind,
    param_types: Vec<String>,
    args: Vec<ExecutorArg>,
    result: std::sync::Mutex<Option<ExecutorResult>>,
}

static EXECUTOR_QUEUE: std::sync::Mutex<std::collections::VecDeque<std::sync::Arc<ExecutorRequest>>> =
    std::sync::Mutex::new(std::collections::VecDeque::new());
static EXECUTOR_DRAINING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static EXECUTOR_LOOP_HOOK_TARGET: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static EXECUTOR_HANDLER_HOOK_TARGET: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static EXECUTOR_NATIVE_WAKE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static EXECUTOR_LOOPER_WAKE_FD_OFFSET: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
static EXECUTOR_MAIN_MESSAGE_QUEUE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static EXECUTOR_LAST_MESSAGE_QUEUE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static EXECUTOR_MAIN_EPOLL_WAKE_FD: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);
static EXECUTOR_INVALID_QUEUE_LOGS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
static EXECUTOR_EPOLL_WAKE_LOGS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
static EXECUTOR_ABORTING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static EXECUTOR_GLOBAL_REFS: std::sync::Mutex<Vec<u64>> = std::sync::Mutex::new(Vec::new());

const EXECUTOR_RAW_CLONE_WAIT_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(30_000);
const EXECUTOR_DEFAULT_WAIT_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(1200);
const EXECUTOR_START_WORKER_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(5000);
const EXECUTOR_HEAVY_WAIT_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(1800);
const EXECUTOR_NO_QUEUE_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(300);
const EXECUTOR_LIGHT_WAIT_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(600);
const EXECUTOR_DRAIN_LIMIT: usize = 32;

unsafe fn enqueue_executor_task(
    kind: ExecutorTaskKind,
    param_types: Vec<String>,
    args: Vec<ExecutorArg>,
) -> ExecutorResult {
    if EXECUTOR_ABORTING.load(std::sync::atomic::Ordering::Acquire) {
        return Err("Java executor is shutting down".to_string());
    }

    let wait_timeout = executor_wait_timeout(&kind);
    let req = std::sync::Arc::new(ExecutorRequest {
        kind,
        param_types,
        args,
        result: std::sync::Mutex::new(None),
    });

    {
        let mut queue = EXECUTOR_QUEUE.lock().unwrap_or_else(|e| e.into_inner());
        queue.push_back(req.clone());
    }

    let mut last_wake = std::time::Instant::now();
    let had_message_queue_at_enqueue = wake_executor_drain_trigger();

    let start = std::time::Instant::now();
    loop {
        if let Some(result) = req.result.lock().unwrap_or_else(|e| e.into_inner()).take() {
            return result;
        }
        if EXECUTOR_ABORTING.load(std::sync::atomic::Ordering::Acquire) && cancel_executor_task(&req) {
            return Err("Java executor is shutting down".to_string());
        }
        let last_message_queue = selected_executor_message_queue();
        if !crate::is_raw_clone_js_thread()
            && last_message_queue == 0
            && start.elapsed() >= EXECUTOR_NO_QUEUE_TIMEOUT
            && cancel_executor_task(&req)
        {
            crate::jsapi::console::output_verbose(
                "[java executor] no Java-thread drain observed; executing on current attached thread",
            );
            return execute_executor_task_on_current_thread(&req);
        }
        if !crate::is_raw_clone_js_thread()
            && last_message_queue != 0
            && start.elapsed() >= wait_timeout
            && cancel_executor_task(&req)
        {
            crate::jsapi::console::output_verbose(&format!(
                "[java executor] Java-thread drain stalled after {}ms; executing on current attached thread",
                wait_timeout.as_millis()
            ));
            return execute_executor_task_on_current_thread(&req);
        }
        if !executor_drain_trigger_installed()
            && !had_message_queue_at_enqueue
            && EXECUTOR_LAST_MESSAGE_QUEUE.load(std::sync::atomic::Ordering::Acquire) == 0
            && start.elapsed() >= EXECUTOR_NO_QUEUE_TIMEOUT
        {
            cancel_executor_task(&req);
            return Err(format!(
                "Java executor unavailable after {}ms: no Java-thread drain observed; raw-clone JNI fallback is disabled",
                EXECUTOR_NO_QUEUE_TIMEOUT.as_millis()
            ));
        }
        if start.elapsed() >= wait_timeout {
            cancel_executor_task(&req);
            return Err(format!(
                "Java executor timeout after {}ms waiting for ART Java-thread callback; raw-clone JNI fallback is disabled",
                wait_timeout.as_millis()
            ));
        }
        if last_wake.elapsed() >= std::time::Duration::from_millis(10) {
            wake_executor_message_queue();
            last_wake = std::time::Instant::now();
        }
        raw_executor_sleep_1ms();
    }
}

fn executor_wait_timeout(kind: &ExecutorTaskKind) -> std::time::Duration {
    if crate::is_raw_clone_js_thread() {
        return EXECUTOR_RAW_CLONE_WAIT_TIMEOUT;
    }
    match kind {
        ExecutorTaskKind::StartJavaWorker { .. } => EXECUTOR_START_WORKER_TIMEOUT,
        ExecutorTaskKind::Jni { .. } => EXECUTOR_LIGHT_WAIT_TIMEOUT,
        ExecutorTaskKind::EnumerateInstances { .. }
        | ExecutorTaskKind::ClassLoaders
        | ExecutorTaskKind::ManagedDrainMessages { .. } => EXECUTOR_HEAVY_WAIT_TIMEOUT,
        ExecutorTaskKind::SetClassLoader { .. } | ExecutorTaskKind::FindClassWithLoader { .. } => {
            EXECUTOR_LIGHT_WAIT_TIMEOUT
        }
        ExecutorTaskKind::ReprobeClassLoader { once: true } => EXECUTOR_LIGHT_WAIT_TIMEOUT,
        ExecutorTaskKind::ReprobeClassLoader { once: false } => EXECUTOR_DEFAULT_WAIT_TIMEOUT,
        _ => EXECUTOR_DEFAULT_WAIT_TIMEOUT,
    }
}

fn executor_queue_has_pending() -> bool {
    let queue = EXECUTOR_QUEUE.lock().unwrap_or_else(|e| e.into_inner());
    !queue.is_empty()
}

fn wake_executor_drain_trigger() -> bool {
    if wake_executor_message_queue() {
        return true;
    }
    if crate::is_raw_clone_js_thread() && selected_executor_message_queue() == 0 {
        return wake_main_epoll_eventfd();
    }
    false
}

fn wake_executor_message_queue() -> bool {
    let _wake_addr = EXECUTOR_NATIVE_WAKE.load(std::sync::atomic::Ordering::Acquire);
    let queue_ptr = selected_executor_message_queue();
    if queue_ptr == 0 {
        return false;
    }
    if !is_valid_native_message_queue(queue_ptr) {
        clear_executor_message_queue(queue_ptr);
        log_invalid_message_queue(queue_ptr, "wake");
        return false;
    }
    if let Some(woke) = safe_write_looper_wake_fd(queue_ptr) {
        if !woke {
            clear_executor_message_queue(queue_ptr);
            log_invalid_message_queue(queue_ptr, "wake-fd");
        }
        return woke;
    }
    false
}

fn wake_main_epoll_eventfd() -> bool {
    let cached = EXECUTOR_MAIN_EPOLL_WAKE_FD.load(std::sync::atomic::Ordering::Acquire);
    if cached >= 0 {
        if write_eventfd(cached) {
            return true;
        }
        EXECUTOR_MAIN_EPOLL_WAKE_FD.store(-1, std::sync::atomic::Ordering::Release);
    }

    let (epoll_fd, event_fd) = match discover_main_epoll_eventfd() {
        Ok(pair) => pair,
        Err(reason) => {
            log_main_epoll_wake_skip(&reason);
            return false;
        }
    };

    EXECUTOR_MAIN_EPOLL_WAKE_FD.store(event_fd, std::sync::atomic::Ordering::Release);
    if EXECUTOR_EPOLL_WAKE_LOGS.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 2 {
        crate::jsapi::console::output_verbose(&format!(
            "[java executor] main epoll wake fd observed: epoll={}, eventfd={}",
            epoll_fd, event_fd
        ));
    }
    write_eventfd(event_fd)
}

fn discover_main_epoll_eventfd() -> Result<(i32, i32), String> {
    let entries = std::fs::read_dir("/proc/self/fd").map_err(|e| format!("read /proc/self/fd failed: {}", e))?;
    let mut fds = Vec::new();
    for entry in entries.flatten() {
        let fd = entry.file_name().to_string_lossy().parse::<i32>().ok();
        if let Some(fd) = fd {
            fds.push(fd);
        }
    }
    fds.sort_unstable();

    let mut epoll_count = 0usize;
    let mut candidates = Vec::new();
    for fd in fds {
        let Ok(link) = std::fs::read_link(format!("/proc/self/fd/{}", fd)) else {
            continue;
        };
        if !link.to_string_lossy().contains("eventpoll") {
            continue;
        }
        epoll_count += 1;
        if let Some(candidate) = inspect_epoll_wake_candidate(fd) {
            candidates.push(candidate);
        }
    }

    if candidates.len() == 1 {
        let candidate = candidates[0];
        return Ok((candidate.epoll_fd, candidate.event_fd));
    }

    let socket_rich: Vec<EpollWakeCandidate> = unique_max_by(&candidates, |candidate| candidate.socket_entries)
        .into_iter()
        .filter(|candidate| candidate.socket_entries > 1)
        .collect();
    if socket_rich.len() == 1 {
        let candidate = socket_rich[0];
        return Ok((candidate.epoll_fd, candidate.event_fd));
    }

    let looper_like: Vec<EpollWakeCandidate> = candidates
        .iter()
        .copied()
        .filter(|candidate| candidate.socket_entries != 0 || candidate.binder_entries != 0)
        .collect();
    if looper_like.len() == 1 {
        let candidate = looper_like[0];
        return Ok((candidate.epoll_fd, candidate.event_fd));
    }

    Err(format!(
        "fd scan found {} eventpoll(s), {} eventfd candidate(s), {} looper-like candidate(s)",
        epoll_count,
        candidates.len(),
        looper_like.len()
    ))
}

fn unique_max_by<F>(candidates: &[EpollWakeCandidate], metric: F) -> Vec<EpollWakeCandidate>
where
    F: Fn(&EpollWakeCandidate) -> usize,
{
    let Some(max_value) = candidates.iter().map(|candidate| metric(candidate)).max() else {
        return Vec::new();
    };
    candidates
        .iter()
        .copied()
        .filter(|candidate| metric(candidate) == max_value)
        .collect()
}

#[derive(Clone, Copy)]
struct EpollWakeCandidate {
    epoll_fd: i32,
    event_fd: i32,
    socket_entries: usize,
    binder_entries: usize,
}

fn inspect_epoll_wake_candidate(epoll_fd: i32) -> Option<EpollWakeCandidate> {
    let fdinfo = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", epoll_fd)).ok()?;
    let mut event_fds = Vec::new();
    let mut socket_entries = 0usize;
    let mut binder_entries = 0usize;

    for line in fdinfo.lines() {
        let Some(tfd) = parse_epoll_tfd(line) else {
            continue;
        };
        let Ok(target) = std::fs::read_link(format!("/proc/self/fd/{}", tfd)) else {
            continue;
        };
        let target = target.to_string_lossy();
        if target.contains("anon_inode:[eventfd]") {
            event_fds.push(tfd);
            if event_fds.len() > 1 {
                return None;
            }
        } else if target.contains("socket:") {
            socket_entries += 1;
        } else if target.contains("/dev/binder")
            || target.contains("/dev/vndbinder")
            || target.contains("/dev/hwbinder")
        {
            binder_entries += 1;
        }
    }

    match event_fds.as_slice() {
        [event_fd] => Some(EpollWakeCandidate {
            epoll_fd,
            event_fd: *event_fd,
            socket_entries,
            binder_entries,
        }),
        _ => None,
    }
}

fn log_main_epoll_wake_skip(reason: &str) {
    if EXECUTOR_EPOLL_WAKE_LOGS.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 2 {
        crate::jsapi::console::output_verbose(&format!("[java executor] main epoll wake skipped: {}", reason));
    }
}

fn parse_epoll_tfd(line: &str) -> Option<i32> {
    let line = line.trim_start();
    if !line.starts_with("tfd:") {
        return None;
    }
    let mut parts = line.split_whitespace();
    let _label = parts.next()?;
    parse_i32_token(parts.next()?)
}

fn parse_i32_token(token: &str) -> Option<i32> {
    let token = token.trim();
    if let Some(hex) = token.strip_prefix("0x") {
        i32::from_str_radix(hex, 16).ok()
    } else {
        token.parse::<i32>().ok()
    }
}

fn write_eventfd(fd: i32) -> bool {
    if fd < 0 || unsafe { libc::fcntl(fd, libc::F_GETFD) < 0 } {
        return false;
    }
    let value: u64 = 1;
    loop {
        let ret = unsafe {
            libc::write(
                fd,
                &value as *const u64 as *const libc::c_void,
                std::mem::size_of::<u64>(),
            )
        };
        if ret == std::mem::size_of::<u64>() as isize {
            return true;
        }
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if errno == libc::EINTR {
            continue;
        }
        return errno == libc::EAGAIN;
    }
}

fn selected_executor_message_queue() -> u64 {
    let main_queue = EXECUTOR_MAIN_MESSAGE_QUEUE.load(std::sync::atomic::Ordering::Acquire);
    if main_queue != 0 {
        main_queue
    } else {
        EXECUTOR_LAST_MESSAGE_QUEUE.load(std::sync::atomic::Ordering::Acquire)
    }
}

fn clear_executor_message_queue(queue_ptr: u64) {
    let _ = EXECUTOR_MAIN_MESSAGE_QUEUE.compare_exchange(
        queue_ptr,
        0,
        std::sync::atomic::Ordering::AcqRel,
        std::sync::atomic::Ordering::Acquire,
    );
    let _ = EXECUTOR_LAST_MESSAGE_QUEUE.compare_exchange(
        queue_ptr,
        0,
        std::sync::atomic::Ordering::AcqRel,
        std::sync::atomic::Ordering::Acquire,
    );
}

fn log_invalid_message_queue(queue_ptr: u64, where_: &str) {
    if EXECUTOR_INVALID_QUEUE_LOGS.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 4 {
        crate::jsapi::console::output_verbose(&format!(
            "[java executor] skip invalid MessageQueue ptr at {}: {:#x}",
            where_, queue_ptr
        ));
    }
}

fn is_valid_native_message_queue(queue_ptr: u64) -> bool {
    if queue_ptr < 0x10000 || !crate::jsapi::util::is_addr_accessible(queue_ptr, 16) {
        return false;
    }
    let looper = unsafe { std::ptr::read_volatile(queue_ptr as *const u64) };
    if looper < 0x10000 || !crate::jsapi::util::is_addr_accessible(looper, 8) {
        return false;
    }
    let fd_offset = looper_wake_fd_offset();
    if fd_offset == 0 {
        return false;
    }
    if !crate::jsapi::util::is_addr_accessible(looper + fd_offset as u64, 4) {
        return false;
    }
    let fd = unsafe { std::ptr::read_volatile((looper + fd_offset as u64) as *const i32) };
    fd >= 0 && unsafe { libc::fcntl(fd, libc::F_GETFD) >= 0 }
}

fn safe_write_looper_wake_fd(queue_ptr: u64) -> Option<bool> {
    let fd_offset = looper_wake_fd_offset();
    if fd_offset == 0 {
        return None;
    }
    if queue_ptr < 0x10000 || !crate::jsapi::util::is_addr_accessible(queue_ptr, 8) {
        return Some(false);
    }
    let looper = unsafe { std::ptr::read_volatile(queue_ptr as *const u64) };
    if looper < 0x10000 || !crate::jsapi::util::is_addr_accessible(looper + fd_offset as u64, 4) {
        return Some(false);
    }
    let fd = unsafe { std::ptr::read_volatile((looper + fd_offset as u64) as *const i32) };
    if fd < 0 || unsafe { libc::fcntl(fd, libc::F_GETFD) < 0 } {
        return Some(false);
    }

    let value: u64 = 1;
    loop {
        let ret = unsafe {
            libc::write(
                fd,
                &value as *const u64 as *const libc::c_void,
                std::mem::size_of::<u64>(),
            )
        };
        if ret == std::mem::size_of::<u64>() as isize {
            return Some(true);
        }
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if errno == libc::EINTR {
            continue;
        }
        if errno == libc::EAGAIN {
            return Some(true);
        }
        return Some(false);
    }
}

fn looper_wake_fd_offset() -> u32 {
    let cached = EXECUTOR_LOOPER_WAKE_FD_OFFSET.load(std::sync::atomic::Ordering::Acquire);
    if cached != 0 {
        return cached;
    }
    let offset = unsafe { resolve_looper_wake_fd_offset() }.unwrap_or(0);
    if offset != 0 {
        EXECUTOR_LOOPER_WAKE_FD_OFFSET.store(offset, std::sync::atomic::Ordering::Release);
    }
    offset
}

unsafe fn resolve_looper_wake_fd_offset() -> Option<u32> {
    let wake = crate::jsapi::module::module_dlsym("libutils.so", "_ZN7android6Looper4wakeEv") as u64;
    if wake == 0 || !crate::jsapi::util::is_addr_accessible(wake, 64) {
        return None;
    }

    for off in (0..96usize).step_by(4) {
        let pc = wake + off as u64;
        let inst = std::ptr::read_volatile(pc as *const u32);
        // ldr w0, [x19, #imm] in Looper::wake before write(fd, ...).
        if (inst & 0xffff_fc00) == 0xb940_1660 {
            let imm12 = (inst >> 10) & 0x0fff;
            let byte_offset = imm12 << 2;
            if byte_offset > 0 && byte_offset < 0x400 {
                crate::jsapi::console::output_verbose(&format!(
                    "[java executor] Looper wake fd offset = 0x{:x}",
                    byte_offset
                ));
                return Some(byte_offset);
            }
        }
    }
    None
}

fn cancel_executor_task(req: &std::sync::Arc<ExecutorRequest>) -> bool {
    let mut queue = EXECUTOR_QUEUE.lock().unwrap_or_else(|e| e.into_inner());
    let before = queue.len();
    queue.retain(|item| !std::sync::Arc::ptr_eq(item, req));
    before != queue.len()
}

fn complete_executor_task(req: &ExecutorRequest, result: ExecutorResult) {
    let mut guard = req.result.lock().unwrap_or_else(|e| e.into_inner());
    *guard = Some(result);
}

pub(crate) fn reset_raw_clone_executor_abort() {
    EXECUTOR_ABORTING.store(false, std::sync::atomic::Ordering::Release);
}

pub(crate) fn abort_raw_clone_executor_for_unload() {
    EXECUTOR_ABORTING.store(true, std::sync::atomic::Ordering::Release);
    let pending = {
        let mut queue = EXECUTOR_QUEUE.lock().unwrap_or_else(|e| e.into_inner());
        queue.drain(..).collect::<Vec<_>>()
    };
    if !pending.is_empty() {
        crate::jsapi::console::output_verbose(&format!(
            "[java executor] aborting {} pending task(s) for unload",
            pending.len()
        ));
    }
    for req in pending {
        complete_executor_task(&req, Err("Java executor is shutting down".to_string()));
    }
    wake_executor_message_queue();
}

fn raw_executor_sleep_1ms() {
    let ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 1_000_000,
    };
    unsafe {
        let _ = libc::syscall(
            libc::SYS_nanosleep,
            &ts as *const libc::timespec,
            std::ptr::null_mut::<libc::timespec>(),
        );
    }
}

pub(crate) unsafe fn drain_raw_clone_executor(env: JniEnv) -> usize {
    if env.is_null() {
        return 0;
    }
    if EXECUTOR_DRAINING
        .compare_exchange(
            false,
            true,
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
        )
        .is_err()
    {
        return 0;
    }

    struct DrainGuard;
    impl Drop for DrainGuard {
        fn drop(&mut self) {
            EXECUTOR_DRAINING.store(false, std::sync::atomic::Ordering::Release);
        }
    }
    let _guard = DrainGuard;

    let mut count = 0usize;
    loop {
        if count >= EXECUTOR_DRAIN_LIMIT {
            break;
        }
        let req = {
            let mut queue = EXECUTOR_QUEUE.lock().unwrap_or_else(|e| e.into_inner());
            queue.pop_front()
        };
        let Some(req) = req else {
            break;
        };
        let result = execute_executor_task(env, &req);
        complete_executor_task(&req, result);
        count += 1;
    }
    count
}

pub(crate) unsafe fn install_raw_clone_executor_loop_hook(env: JniEnv) -> bool {
    if executor_drain_trigger_installed() {
        return true;
    }
    reset_raw_clone_executor_abort();
    if env.is_null() {
        crate::jsapi::console::output_verbose(
            "[java executor] installing Java-thread executor hooks without JNIEnv (symbol/self-parse)",
        );
    }

    let mut installed = install_message_queue_executor_hook(env);
    if !env.is_null() {
        installed |= install_handler_dispatch_executor_hook(env);
    }
    installed
}

pub(crate) unsafe fn start_java_worker_thread_via_executor(native_loop: *mut std::ffi::c_void) -> Result<(), String> {
    if native_loop.is_null() {
        return Err("java worker native loop pointer is null".to_string());
    }
    if !ensure_executor_loop_ready() {
        return Err("Java executor loop hook is not installed".to_string());
    }
    match enqueue_executor_task(
        ExecutorTaskKind::StartJavaWorker {
            native_loop: native_loop as u64,
        },
        Vec::new(),
        Vec::new(),
    ) {
        Ok(_) => Ok(()),
        Err(err) => Err(err),
    }
}

unsafe fn install_message_queue_executor_hook(env: JniEnv) -> bool {
    if EXECUTOR_LOOP_HOOK_TARGET.load(std::sync::atomic::Ordering::Acquire) != 0 {
        return true;
    }

    let (poll_addr, wake_addr) = match resolve_message_queue_native_symbols() {
        Some((poll_addr, wake_addr)) => (poll_addr, wake_addr),
        None => {
            let poll_method = match super::art_method::resolve_art_method(
                env,
                "android.os.MessageQueue",
                "nativePollOnce",
                "(JI)V",
                false,
            ) {
                Ok((method, _)) => method,
                Err(e) => {
                    crate::jsapi::console::output_verbose(&format!(
                        "[java executor] MessageQueue.nativePollOnce resolve failed: {}",
                        e
                    ));
                    return false;
                }
            };
            let wake_method =
                match super::art_method::resolve_art_method(env, "android.os.MessageQueue", "nativeWake", "(J)V", true)
                {
                    Ok((method, _)) => method,
                    Err(e) => {
                        crate::jsapi::console::output_verbose(&format!(
                            "[java executor] MessageQueue.nativeWake resolve failed: {}",
                            e
                        ));
                        return false;
                    }
                };

            let spec = super::jni_core::get_art_method_spec(env, poll_method);
            let poll_addr = std::ptr::read_volatile((poll_method as usize + spec.data_offset) as *const u64)
                & super::PAC_STRIP_MASK;
            let wake_addr = std::ptr::read_volatile((wake_method as usize + spec.data_offset) as *const u64)
                & super::PAC_STRIP_MASK;
            (poll_addr, wake_addr)
        }
    };
    if poll_addr == 0 || wake_addr == 0 {
        crate::jsapi::console::output_verbose(&format!(
            "[java executor] MessageQueue native ptr invalid: poll={:#x}, wake={:#x}",
            poll_addr, wake_addr
        ));
        return false;
    }

    let (hook_addr, sflag, real_addr) = match super::art_controller::prepare_hook_target(poll_addr, std::ptr::null_mut()) {
        Ok(v) => v,
        Err(e) => {
            crate::jsapi::console::output_verbose(&format!(
                "[java executor] MessageQueue.nativePollOnce prepare failed: target={:#x}, {}",
                poll_addr, e
            ));
            return false;
        }
    };

    let ret = hook_ffi::hook_attach(
        hook_addr as *mut std::ffi::c_void,
        Some(on_message_queue_native_poll_once_enter),
        None,
        std::ptr::null_mut(),
        sflag,
    );
    if ret != 0 {
        crate::jsapi::console::output_verbose(&format!(
            "[java executor] MessageQueue.nativePollOnce hook failed: target={:#x}, hook={:#x}, ret={}",
            poll_addr, hook_addr, ret
        ));
        return false;
    }
    if !super::art_controller::try_fixup_trampoline_pub(
        hook_ffi::hook_get_trampoline(hook_addr as *mut std::ffi::c_void),
        real_addr,
    ) {
        hook_ffi::hook_remove(hook_addr as *mut std::ffi::c_void);
        return false;
    }

    EXECUTOR_NATIVE_WAKE.store(wake_addr, std::sync::atomic::Ordering::Release);
    EXECUTOR_LOOP_HOOK_TARGET.store(hook_addr, std::sync::atomic::Ordering::Release);
    crate::jsapi::console::output_verbose(&format!(
        "[java executor] MessageQueue loop hook installed: poll={:#x}, hook={:#x}, wake={:#x}",
        poll_addr, hook_addr, wake_addr
    ));
    true
}

unsafe fn install_handler_dispatch_executor_hook(env: JniEnv) -> bool {
    if EXECUTOR_HANDLER_HOOK_TARGET.load(std::sync::atomic::Ordering::Acquire) != 0 {
        return true;
    }

    let (art_method, _) = match super::art_method::resolve_art_method(
        env,
        "android.os.Handler",
        "dispatchMessage",
        "(Landroid/os/Message;)V",
        false,
    ) {
        Ok(v) => v,
        Err(e) => {
            crate::jsapi::console::output_verbose(&format!(
                "[java executor] Handler.dispatchMessage resolve failed: {}",
                e
            ));
            return false;
        }
    };
    let spec = super::jni_core::get_art_method_spec(env, art_method);
    let entry_point = super::art_method::read_entry_point(art_method, spec.entry_point_offset) & super::PAC_STRIP_MASK;
    if entry_point == 0 || crate::jsapi::module::is_in_libart(entry_point) {
        crate::jsapi::console::output_verbose(&format!(
            "[java executor] Handler.dispatchMessage hook skipped: shared entry={:#x}",
            entry_point
        ));
        return false;
    }

    let (hook_addr, sflag, real_addr) = match super::art_controller::prepare_hook_target(entry_point, std::ptr::null_mut()) {
        Ok(v) => v,
        Err(e) => {
            crate::jsapi::console::output_verbose(&format!(
                "[java executor] Handler.dispatchMessage prepare failed: entry={:#x}, {}",
                entry_point, e
            ));
            return false;
        }
    };

    let ret = hook_ffi::hook_attach(
        hook_addr as *mut std::ffi::c_void,
        Some(on_handler_dispatch_message_enter),
        None,
        std::ptr::null_mut(),
        sflag,
    );
    if ret != 0 {
        crate::jsapi::console::output_verbose(&format!(
            "[java executor] Handler.dispatchMessage hook failed: target={:#x}, hook={:#x}, ret={}",
            entry_point, hook_addr, ret
        ));
        return false;
    }
    if !super::art_controller::try_fixup_trampoline_pub(
        hook_ffi::hook_get_trampoline(hook_addr as *mut std::ffi::c_void),
        real_addr,
    ) {
        hook_ffi::hook_remove(hook_addr as *mut std::ffi::c_void);
        return false;
    }

    EXECUTOR_HANDLER_HOOK_TARGET.store(hook_addr, std::sync::atomic::Ordering::Release);
    crate::jsapi::console::output_verbose(&format!(
        "[java executor] Handler.dispatchMessage drain hook installed: entry={:#x}, hook={:#x}",
        entry_point, hook_addr
    ));
    true
}

pub(super) unsafe fn enumerate_methods_via_executor(class_name: &str) -> Result<Vec<MethodInfo>, String> {
    if !ensure_executor_loop_ready() {
        return Err("Java executor loop hook is not installed".to_string());
    }

    match enqueue_executor_task(
        ExecutorTaskKind::Methods {
            class_name: class_name.to_string(),
        },
        Vec::new(),
        Vec::new(),
    ) {
        Ok(ExecutorValue::Methods(methods)) => Ok(methods),
        Ok(_) => Err("Java executor returned non-method result".to_string()),
        Err(err) => Err(err),
    }
}

fn ensure_executor_loop_ready() -> bool {
    executor_drain_trigger_installed() || unsafe { install_raw_clone_executor_loop_hook(std::ptr::null_mut()) }
}

fn executor_drain_trigger_installed() -> bool {
    EXECUTOR_LOOP_HOOK_TARGET.load(std::sync::atomic::Ordering::Acquire) != 0
        || EXECUTOR_HANDLER_HOOK_TARGET.load(std::sync::atomic::Ordering::Acquire) != 0
}

pub(super) unsafe extern "C" fn js_install_raw_clone_executor_hook(
    _ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    JSValue::bool(install_raw_clone_executor_loop_hook(std::ptr::null_mut())).raw()
}

fn resolve_message_queue_native_symbols() -> Option<(u64, u64)> {
    unsafe {
        let poll_by_table =
            crate::jsapi::module::module_find_jni_native_method("libandroid_runtime.so", "nativePollOnce", "(JI)V");
        let wake_by_table =
            crate::jsapi::module::module_find_jni_native_method("libandroid_runtime.so", "nativeWake", "(J)V");
        if let (Some(poll_addr), Some(wake_addr)) = (poll_by_table, wake_by_table) {
            crate::jsapi::console::output_verbose(&format!(
                "[java executor] MessageQueue JNI table: nativePollOnce={:#x}, nativeWake={:#x}",
                poll_addr, wake_addr
            ));
            return Some((poll_addr, wake_addr));
        }

        let poll = crate::jsapi::module::module_find_symbol_contains(
            "libandroid_runtime.so",
            "android_os_MessageQueue_nativePollOnce",
        );
        let wake = crate::jsapi::module::module_find_symbol_contains(
            "libandroid_runtime.so",
            "android_os_MessageQueue_nativeWake",
        );
        match (poll, wake) {
            (Some((poll_name, poll_addr)), Some((wake_name, wake_addr))) => {
                crate::jsapi::console::output_verbose(&format!(
                    "[java executor] MessageQueue native symbols: {}={:#x}, {}={:#x}",
                    poll_name, poll_addr, wake_name, wake_addr
                ));
                Some((poll_addr, wake_addr))
            }
            _ => {
                crate::jsapi::console::output_verbose(
                    "[java executor] MessageQueue native symbol lookup failed; falling back to ArtMethod resolve",
                );
                None
            }
        }
    }
}

pub(crate) fn cut_raw_clone_executor_loop_hook() -> bool {
    abort_raw_clone_executor_for_unload();
    release_executor_global_refs_via_executor();
    let mut removed_all = true;
    let target = EXECUTOR_LOOP_HOOK_TARGET.load(std::sync::atomic::Ordering::Acquire);
    if target != 0 {
        let reverted = crate::recomp::try_revert_slot_patch_by_slot(target as usize);
        if reverted {
            crate::jsapi::console::output_verbose(&format!(
                "[java executor] MessageQueue reverted recomp slot branch for target={:#x}",
                target
            ));
        }
        let ret = unsafe { hook_ffi::hook_remove(target as *mut std::ffi::c_void) };
        if ret == 0 {
            EXECUTOR_LOOP_HOOK_TARGET.store(0, std::sync::atomic::Ordering::Release);
            crate::jsapi::console::output_verbose(&format!(
                "[java executor] MessageQueue loop hook removed: {:#x}",
                target
            ));
        } else {
            removed_all = false;
            crate::jsapi::console::output_verbose(&format!(
                "[java executor] MessageQueue loop hook remove failed: {:#x}, ret={}",
                target, ret
            ));
        }
    }
    let handler_target = EXECUTOR_HANDLER_HOOK_TARGET.load(std::sync::atomic::Ordering::Acquire);
    if handler_target != 0 {
        let reverted = crate::recomp::try_revert_slot_patch_by_slot(handler_target as usize);
        if reverted {
            crate::jsapi::console::output_verbose(&format!(
                "[java executor] Handler.dispatchMessage reverted recomp slot branch for target={:#x}",
                handler_target
            ));
        }
        let ret = unsafe { hook_ffi::hook_remove(handler_target as *mut std::ffi::c_void) };
        if ret == 0 {
            EXECUTOR_HANDLER_HOOK_TARGET.store(0, std::sync::atomic::Ordering::Release);
            crate::jsapi::console::output_verbose(&format!(
                "[java executor] Handler.dispatchMessage hook removed: {:#x}",
                handler_target
            ));
        } else {
            removed_all = false;
            crate::jsapi::console::output_verbose(&format!(
                "[java executor] Handler.dispatchMessage hook remove failed: {:#x}, ret={}",
                handler_target, ret
            ));
        }
    }
    if removed_all {
        EXECUTOR_NATIVE_WAKE.store(0, std::sync::atomic::Ordering::Release);
        EXECUTOR_MAIN_MESSAGE_QUEUE.store(0, std::sync::atomic::Ordering::Release);
        EXECUTOR_LAST_MESSAGE_QUEUE.store(0, std::sync::atomic::Ordering::Release);
    }
    removed_all
}

pub(crate) fn raw_clone_executor_hook_active() -> bool {
    executor_drain_trigger_installed()
}

fn release_executor_global_refs_via_executor() {
    let refs = take_executor_global_refs();
    if refs.is_empty() {
        return;
    }
    if EXECUTOR_LOOP_HOOK_TARGET.load(std::sync::atomic::Ordering::Acquire) == 0
        || EXECUTOR_LAST_MESSAGE_QUEUE.load(std::sync::atomic::Ordering::Acquire) == 0
    {
        crate::jsapi::console::output_verbose(&format!(
            "[java executor] defer release of {} global ref(s): MessageQueue not ready",
            refs.len()
        ));
        let mut pending = EXECUTOR_GLOBAL_REFS.lock().unwrap_or_else(|e| e.into_inner());
        pending.extend(refs);
        return;
    }

    let count = refs.len();
    let result = unsafe { enqueue_executor_task(ExecutorTaskKind::CleanupGlobals { refs }, Vec::new(), Vec::new()) };
    match result {
        Ok(_) => {
            crate::jsapi::console::output_verbose(&format!("[java executor] released {} executor global ref(s)", count))
        }
        Err(err) => crate::jsapi::console::output_verbose(&format!(
            "[java executor] release executor global refs failed: {}",
            err
        )),
    }
}

unsafe extern "C" fn on_message_queue_native_poll_once_enter(
    ctx_ptr: *mut hook_ffi::HookContext,
    _user_data: *mut std::ffi::c_void,
) {
    if ctx_ptr.is_null() {
        return;
    }
    let ctx = &mut *ctx_ptr;
    ctx.intercept_leave = 0;

    let env = ctx.x[0] as JniEnv;
    let queue_ptr = ctx.x[2];
    if queue_ptr != 0 {
        if !is_valid_native_message_queue(queue_ptr) {
            log_invalid_message_queue(queue_ptr, "poll");
        } else {
            let tid = libc::syscall(libc::SYS_gettid) as i32;
            let pid = unsafe { libc::syscall(libc::SYS_getpid) as i32 };
            if tid == pid && EXECUTOR_MAIN_MESSAGE_QUEUE.swap(queue_ptr, std::sync::atomic::Ordering::AcqRel) == 0 {
                crate::jsapi::console::output_verbose(&format!(
                    "[java executor] main MessageQueue observed: {:#x}",
                    queue_ptr
                ));
            }
            EXECUTOR_LAST_MESSAGE_QUEUE.store(queue_ptr, std::sync::atomic::Ordering::Release);
        }
    }
    if env.is_null() || !executor_queue_has_pending() {
        return;
    }

    let drained = drain_raw_clone_executor(env);
    if drained != 0 {
        crate::jsapi::console::output_verbose(&format!(
            "[java executor] MessageQueue drained {} raw-clone task(s)",
            drained
        ));
    }
}

unsafe extern "C" fn on_handler_dispatch_message_enter(
    ctx_ptr: *mut hook_ffi::HookContext,
    _user_data: *mut std::ffi::c_void,
) {
    if ctx_ptr.is_null() {
        return;
    }
    let ctx = &mut *ctx_ptr;
    ctx.intercept_leave = 0;
    if !executor_queue_has_pending() {
        return;
    }

    let thread = ctx.x[19] & super::PAC_STRIP_MASK;
    let env = jni_env_from_quick_thread(thread);
    if env.is_null() {
        return;
    }

    let drained = drain_raw_clone_executor(env);
    if drained != 0 {
        crate::jsapi::console::output_verbose(&format!(
            "[java executor] Handler.dispatchMessage drained {} raw-clone task(s)",
            drained
        ));
    }
}

unsafe fn jni_env_from_quick_thread(thread: u64) -> JniEnv {
    if thread == 0 {
        return std::ptr::null_mut();
    }
    super::safe_mem::refresh_mem_regions();
    for offset in (144..384).step_by(8) {
        let candidate = super::safe_mem::safe_read_u64(thread + offset as u64) & super::PAC_STRIP_MASK;
        if candidate == 0 {
            continue;
        }
        let self_thread = super::safe_mem::safe_read_u64(candidate + 8) & super::PAC_STRIP_MASK;
        if self_thread != thread {
            continue;
        }
        let functions = super::safe_mem::safe_read_u64(candidate) & super::PAC_STRIP_MASK;
        if functions != 0 {
            return candidate as JniEnv;
        }
    }
    std::ptr::null_mut()
}

unsafe fn execute_executor_task_on_current_thread(req: &ExecutorRequest) -> ExecutorResult {
    let scope = match super::jni_core::scoped_jni_env() {
        Ok(scope) => scope,
        Err(err) => return Err(format!("Java executor current-thread fallback failed: {}", err)),
    };
    execute_executor_task(scope.env(), req)
}

unsafe fn execute_executor_task(env: JniEnv, req: &ExecutorRequest) -> ExecutorResult {
    match &req.kind {
        ExecutorTaskKind::StartJavaWorker { native_loop } => {
            super::java_hook_api::start_java_worker_thread(*native_loop as *mut std::ffi::c_void)?;
            Ok(ExecutorValue::Undefined)
        }
        ExecutorTaskKind::Jni { op } => execute_jni_executor_op(env, op),
        ExecutorTaskKind::Methods { class_name } => {
            super::reflect::enumerate_methods(env, class_name).map(ExecutorValue::Methods)
        }
        ExecutorTaskKind::ResolveMethod {
            class_name,
            method_name,
            method_sig,
            force_static,
        } => execute_resolve_method_task(env, class_name, method_name, method_sig, *force_static),
        ExecutorTaskKind::Instance {
            obj_ptr,
            obj_is_global,
            class_name,
            method_name,
            method_sig,
        } => execute_instance_task(
            env,
            *obj_ptr,
            *obj_is_global,
            class_name,
            method_name,
            method_sig,
            &req.param_types,
            &req.args,
        ),
        ExecutorTaskKind::Static {
            class_name,
            method_name,
            method_sig,
        } => execute_static_task(env, class_name, method_name, method_sig, &req.param_types, &req.args),
        ExecutorTaskKind::NewObject { class_name, ctor_sig } => {
            execute_new_object_task(env, class_name, ctor_sig, &req.param_types, &req.args)
        }
        ExecutorTaskKind::CleanupGlobals { refs } => {
            release_executor_global_refs_on_java_thread(env, refs);
            super::reflect::cleanup_enumerated_classloader_refs(env);
            super::reflect::cleanup_cached_class_refs(env);
            Ok(ExecutorValue::Undefined)
        }
        ExecutorTaskKind::ArrayLength {
            array_ptr,
            array_is_global,
        } => execute_array_length_task(env, *array_ptr, *array_is_global),
        ExecutorTaskKind::ArrayGet {
            array_ptr,
            array_is_global,
            index,
            elem_sig,
        } => execute_array_get_task(env, *array_ptr, *array_is_global, *index, elem_sig),
        ExecutorTaskKind::FieldMeta { class_name, field_name } => execute_field_meta_task(env, class_name, field_name),
        ExecutorTaskKind::FieldRead {
            obj_ptr,
            obj_is_global,
            class_name,
            field_id,
            sig,
            is_static,
        } => execute_field_read_task(env, *obj_ptr, *obj_is_global, class_name, *field_id, sig, *is_static),
        ExecutorTaskKind::FieldWrite {
            obj_ptr,
            obj_is_global,
            class_name,
            field_id,
            sig,
            is_static,
        } => execute_field_write_task(
            env,
            *obj_ptr,
            *obj_is_global,
            class_name,
            *field_id,
            sig,
            *is_static,
            req.args.first().unwrap_or(&ExecutorArg::Null),
        ),
        ExecutorTaskKind::DirectGetField {
            obj_ptr,
            class_name,
            field_name,
            field_sig,
        } => execute_direct_get_field_task(env, *obj_ptr, class_name, field_name, field_sig),
        ExecutorTaskKind::EnumerateInstances {
            class_name,
            include_subtypes,
            max_count,
        } => super::java_choose_api::enumerate_instance_refs_with_options(
            env,
            class_name,
            *include_subtypes,
            *max_count,
            false,
        )
        .map(|refs| ExecutorValue::InstanceRefs {
            refs,
            class_name: class_name.clone(),
        }),
        ExecutorTaskKind::ClassLoaders => Ok(ExecutorValue::ClassLoaders(super::reflect::enumerate_classloaders(env))),
        ExecutorTaskKind::FindClassWithLoader { loader_ptr, class_name } => Ok(ExecutorValue::FindClassWithLoader {
            loader_ptr: *loader_ptr,
            class_name: class_name.clone(),
            via: super::reflect::find_class_with_loader(env, *loader_ptr as *mut std::ffi::c_void, class_name),
        }),
        ExecutorTaskKind::FindClassObject { class_name } => execute_find_class_object_task(env, class_name),
        ExecutorTaskKind::SetClassLoader { loader_ptr } => Ok(ExecutorValue::Bool(
            super::reflect::set_classloader_override(env, *loader_ptr as *mut std::ffi::c_void),
        )),
        ExecutorTaskKind::ResolveFastMethod {
            class_name,
            method_name,
            method_sig,
            force_static,
            should_compile,
            compile_kind,
        } => execute_resolve_fast_method_task(
            env,
            class_name,
            method_name,
            method_sig,
            *force_static,
            *should_compile,
            *compile_kind,
        ),
        ExecutorTaskKind::ResolveFastField {
            class_name,
            field_name,
            requested_sig,
        } => {
            super::java_fast_api::resolve_fast_field(env, class_name.clone(), field_name.clone(), requested_sig.clone())
                .map(ExecutorValue::FastField)
        }
        ExecutorTaskKind::ManagedHookDsl {
            class_name,
            method_name,
            method_sig,
            dsl,
            message_capacity,
        } => super::java_hook_api::install_managed_dsl_with_env(
            env,
            class_name,
            method_name,
            method_sig,
            dsl,
            *message_capacity,
        )
        .map(ExecutorValue::ManagedHookDsl),
        ExecutorTaskKind::FastHook {
            class_name,
            method_name,
            method_sig,
            dsl,
        } => super::java_hook_api::install_fast_hook_with_env(env, class_name, method_name, method_sig, dsl)
            .map(|_| ExecutorValue::Bool(true)),
        ExecutorTaskKind::DeoptimizeMethod {
            class_name,
            method_name,
            method_sig,
            force_static,
        } => {
            let (art_method, _) =
                super::art_method::resolve_art_method(env, class_name, method_name, method_sig, *force_static)?;
            super::art_controller::deoptimize_method(art_method)?;
            Ok(ExecutorValue::Bool(true))
        }
        ExecutorTaskKind::CompileMethod {
            class_name,
            method_name,
            method_sig,
            force_static,
            compile_kind,
        } => {
            let (art_method, _) =
                super::art_method::resolve_art_method(env, class_name, method_name, method_sig, *force_static)?;
            let spec = super::jni_core::get_art_method_spec(env, art_method);
            let bridge = super::art_method::find_art_bridge_functions(env, spec.entry_point_offset);
            let result = super::java_fast_api::compile_art_method_to_quick(
                env,
                art_method,
                spec.entry_point_offset,
                bridge,
                *compile_kind,
            );
            Ok(ExecutorValue::CompileResult { art_method, result })
        }
        ExecutorTaskKind::JitInfo => {
            let Some(info) = super::art_method::probe_jit_runtime_info() else {
                return Err("JIT runtime info unavailable".to_string());
            };
            Ok(ExecutorValue::JitInfo {
                runtime: info.runtime,
                java_vm_offset: info.java_vm_offset as u64,
                jit_offset: info.jit_offset as u64,
                jit_code_cache_offset: info.jit_code_cache_offset as u64,
                direct_jit: info.direct_jit,
                runtime_jit_code_cache: info.runtime_jit_code_cache,
                direct_get_code_cache: info.direct_get_code_cache,
                found_jit: info.found_jit,
                message: info.message,
            })
        }
        ExecutorTaskKind::ReprobeClassLoader { once } => {
            if *once {
                Ok(ExecutorValue::Bool(super::reflect::reprobe_classloader_once_with_env(
                    env,
                )))
            } else {
                let mut ok = false;
                for attempt in 0..8 {
                    if attempt > 0 {
                        crate::raw_thread::sleep_ms(50);
                    }
                    if super::reflect::reprobe_classloader_once_with_env(env) {
                        ok = true;
                        break;
                    }
                }
                Ok(ExecutorValue::Bool(ok))
            }
        }
        ExecutorTaskKind::ManagedDrainMessages {
            helper_class,
            max_items_requested,
        } => super::java_hook_api::drain_managed_messages_inner(env, helper_class, *max_items_requested)
            .map(ExecutorValue::ManagedDrain),
        ExecutorTaskKind::ManagedReadCounter {
            helper_class,
            field_name,
        } => super::java_hook_api::read_managed_counter_inner(env, helper_class, field_name).map(ExecutorValue::BigU64),
    }
}

pub(crate) unsafe fn run_jni_executor_op_to_js(ctx: *mut ffi::JSContext, op: JniExecutorOp) -> ffi::JSValue {
    if !ensure_executor_loop_ready() {
        return js_throw_internal_error(ctx, "Java executor loop hook is not installed".to_string());
    }
    executor_value_to_js(
        ctx,
        enqueue_executor_task(ExecutorTaskKind::Jni { op }, Vec::new(), Vec::new()),
    )
}

unsafe fn execute_jni_executor_op(env: JniEnv, op: &JniExecutorOp) -> ExecutorResult {
    if env.is_null() {
        return Err("Java executor JNI task has null JNIEnv".to_string());
    }

    match op {
        JniExecutorOp::ThreadEnv => Ok(ExecutorValue::Pointer(env as usize as u64)),
        JniExecutorOp::ClassName { cls_ptr } => Ok(super::try_get_class_name(env as u64, *cls_ptr)
            .map(ExecutorValue::String)
            .unwrap_or(ExecutorValue::Null)),
        JniExecutorOp::ReadJString { obj_ptr } => Ok(super::try_read_jstring(env as u64, *obj_ptr)
            .map(ExecutorValue::String)
            .unwrap_or(ExecutorValue::Null)),
        JniExecutorOp::GetObjectClass { obj_ptr } => {
            let local = super::try_get_object_class(env as u64, *obj_ptr)
                .map(|p| p as *mut std::ffi::c_void)
                .unwrap_or(std::ptr::null_mut());
            jni_executor_pointer_from_local_ref(env, local, "GetObjectClass")
        }
        JniExecutorOp::GetSuperclass { cls_ptr } => {
            let local = super::try_get_superclass(env as u64, *cls_ptr)
                .map(|p| p as *mut std::ffi::c_void)
                .unwrap_or(std::ptr::null_mut());
            jni_executor_pointer_from_local_ref(env, local, "GetSuperclass")
        }
        JniExecutorOp::IsSameObject { a_ptr, b_ptr } => {
            Ok(ExecutorValue::Bool(super::try_is_same_object(env as u64, *a_ptr, *b_ptr)))
        }
        JniExecutorOp::IsInstanceOf { obj_ptr, cls_ptr } => Ok(ExecutorValue::Bool(super::try_is_instance_of(
            env as u64,
            *obj_ptr,
            *cls_ptr,
        ))),
        JniExecutorOp::GetObjectClassName { obj_ptr } => Ok(super::try_get_object_class_name(env as u64, *obj_ptr)
            .map(ExecutorValue::String)
            .unwrap_or(ExecutorValue::Null)),
        JniExecutorOp::ExceptionCheck => Ok(ExecutorValue::Bool(super::try_exception_check(env as u64))),
        JniExecutorOp::ExceptionClear => {
            super::try_exception_clear(env as u64);
            Ok(ExecutorValue::Bool(true))
        }
        JniExecutorOp::ExceptionOccurred => {
            let local = super::try_exception_occurred(env as u64)
                .map(|p| p as *mut std::ffi::c_void)
                .unwrap_or(std::ptr::null_mut());
            jni_executor_pointer_from_local_ref(env, local, "ExceptionOccurred")
        }
        JniExecutorOp::FindClass { name } => {
            let local = super::try_find_class(env as u64, name)
                .map(|p| p as *mut std::ffi::c_void)
                .unwrap_or(std::ptr::null_mut());
            jni_executor_pointer_from_local_ref(env, local, "FindClass")
        }
        JniExecutorOp::NewStringUtf { value } => {
            let local = super::try_new_string_utf(env as u64, value)
                .map(|p| p as *mut std::ffi::c_void)
                .unwrap_or(std::ptr::null_mut());
            jni_executor_pointer_from_local_ref(env, local, "NewStringUTF")
        }
        JniExecutorOp::NewLocalRef { obj_ptr } => {
            let local = super::try_new_local_ref(env as u64, *obj_ptr)
                .map(|p| p as *mut std::ffi::c_void)
                .unwrap_or(std::ptr::null_mut());
            jni_executor_pointer_from_local_ref(env, local, "NewLocalRef")
        }
        JniExecutorOp::DeleteLocalRef { obj_ptr } => {
            jni_executor_delete_ref(env, *obj_ptr);
            Ok(ExecutorValue::Bool(true))
        }
    }
}

unsafe fn jni_executor_pointer_from_local_ref(
    env: JniEnv,
    local: *mut std::ffi::c_void,
    label: &str,
) -> ExecutorResult {
    if local.is_null() {
        return Ok(ExecutorValue::Null);
    }

    let new_global_ref: NewGlobalRefFn = jni_fn!(env, NewGlobalRefFn, JNI_NEW_GLOBAL_REF);
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
    let global = new_global_ref(env, local);
    delete_local_ref(env, local);
    if jni_null_or_exc(env, global) {
        return Err(format!("Java executor {} NewGlobalRef failed", label));
    }

    remember_executor_global_ref(global as u64);
    Ok(ExecutorValue::Pointer(global as u64))
}

unsafe fn jni_executor_delete_ref(env: JniEnv, obj_ptr: u64) {
    if env.is_null() || obj_ptr == 0 {
        return;
    }

    let obj = obj_ptr as *mut std::ffi::c_void;
    if forget_executor_global_ref(obj_ptr) {
        let delete_global_ref: DeleteGlobalRefFn = jni_fn!(env, DeleteGlobalRefFn, JNI_DELETE_GLOBAL_REF);
        delete_global_ref(env, obj);
    } else {
        let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
        delete_local_ref(env, obj);
    }
}

unsafe fn execute_find_class_object_task(env: JniEnv, class_name: &str) -> ExecutorResult {
    let cls = find_class_safe(env, class_name);
    if jni_null_or_exc(env, cls) {
        return Err(format!("class not found: {}", class_name));
    }
    object_result_from_local_ref_for_new_object(env, cls, "Ljava/lang/Class;")
}

unsafe fn execute_resolve_fast_method_task(
    env: JniEnv,
    class_name: &str,
    method_name: &str,
    method_sig: &str,
    force_static: bool,
    should_compile: bool,
    compile_kind: super::java_fast_api::RequestedCompileKind,
) -> ExecutorResult {
    let (art_method, _method_id, class_global_ref, is_static) =
        super::java_fast_api::resolve_fast_method(env, class_name, method_name, method_sig, force_static)?;

    let spec = super::jni_core::get_art_method_spec(env, art_method);
    let bridge = super::art_method::find_art_bridge_functions(env, spec.entry_point_offset);
    let mut entry_point = super::art_method::read_entry_point(art_method, spec.entry_point_offset);
    if super::art_method::is_art_quick_entrypoint(entry_point, bridge) && should_compile {
        let compile = super::java_fast_api::compile_art_method_to_quick(
            env,
            art_method,
            spec.entry_point_offset,
            bridge,
            compile_kind,
        );
        entry_point = compile.after;
        crate::jsapi::console::output_verbose(&format!(
            "[fastMethod] executor compile {}.{}{} kind={} success={} before={:#x} after={:#x} msg={}",
            class_name,
            method_name,
            method_sig,
            compile.kind,
            compile.success,
            compile.before,
            compile.after,
            compile.message
        ));
    }
    if super::art_method::is_art_quick_entrypoint(entry_point, bridge) {
        return Err(format!(
            "fastMethod rejected {}.{}{}: no independent quick entrypoint (entry={:#x})",
            class_name, method_name, method_sig, entry_point
        ));
    }

    let class_mirror = super::decode_global_jobject_raw(env, class_global_ref as *mut std::ffi::c_void).unwrap_or(0);
    remember_executor_global_ref(class_global_ref);
    Ok(ExecutorValue::FastMethod {
        art_method,
        class_global_ref,
        class_mirror,
        is_static,
    })
}

unsafe fn execute_instance_task(
    env: JniEnv,
    obj_ptr: u64,
    obj_is_global: bool,
    class_name: &str,
    method_name: &str,
    method_sig: &str,
    param_types: &[String],
    args: &[ExecutorArg],
) -> ExecutorResult {
    if obj_ptr == 0 {
        return Err("Java executor instance call target is null".to_string());
    }

    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
    let get_mid: GetMethodIdFn = jni_fn!(env, GetMethodIdFn, JNI_GET_METHOD_ID);
    let new_local_ref: NewLocalRefFn = jni_fn!(env, NewLocalRefFn, JNI_NEW_LOCAL_REF);

    let cls = find_class_safe(env, class_name);
    if jni_null_or_exc(env, cls) {
        return Err(format!("Java executor FindClass('{}') failed", class_name));
    }

    let local_obj = if obj_is_global {
        new_local_ref(env, obj_ptr as *mut std::ffi::c_void)
    } else {
        raw_mirror_to_local_ref(env, obj_ptr)
    };
    if jni_null_or_exc(env, local_obj) {
        delete_local_ref(env, cls);
        return Err("Java executor NewLocalRef failed for receiver".to_string());
    }

    let c_name = match std::ffi::CString::new(method_name) {
        Ok(v) => v,
        Err(_) => {
            delete_local_ref(env, local_obj);
            delete_local_ref(env, cls);
            return Err("Java executor invalid method name".to_string());
        }
    };
    let c_sig = match std::ffi::CString::new(method_sig) {
        Ok(v) => v,
        Err(_) => {
            delete_local_ref(env, local_obj);
            delete_local_ref(env, cls);
            return Err("Java executor invalid method signature".to_string());
        }
    };
    let mid = get_mid(env, cls, c_name.as_ptr(), c_sig.as_ptr());
    if jni_null_or_exc(env, mid) {
        delete_local_ref(env, local_obj);
        delete_local_ref(env, cls);
        return Err(format!(
            "Java executor GetMethodID failed: {}.{}{}",
            class_name, method_name, method_sig
        ));
    }

    let mut locals = Vec::new();
    let jargs = build_executor_jargs(env, param_types, args, &mut locals)?;
    let result = call_executor_method(env, local_obj, mid, method_sig, false, jargs.as_ptr());
    for local in locals {
        if !local.is_null() {
            delete_local_ref(env, local);
        }
    }
    delete_local_ref(env, local_obj);
    delete_local_ref(env, cls);
    result
}

unsafe fn execute_resolve_method_task(
    env: JniEnv,
    class_name: &str,
    method_name: &str,
    method_sig: &str,
    force_static: bool,
) -> ExecutorResult {
    super::reflect::ensure_reflect_ids(env);
    let spec = super::jni_core::get_art_method_spec(env, 0);
    let bridge = super::art_method::find_art_bridge_functions(env, spec.entry_point_offset);
    if bridge.quick_generic_jni_trampoline == 0 {
        return Err("Java executor failed to initialize ART bridge functions".to_string());
    }
    match super::art_method::resolve_art_method(env, class_name, method_name, method_sig, force_static) {
        Ok((art_method, is_static)) => Ok(ExecutorValue::Method { art_method, is_static }),
        Err(err) => Err(err),
    }
}

unsafe fn execute_static_task(
    env: JniEnv,
    class_name: &str,
    method_name: &str,
    method_sig: &str,
    param_types: &[String],
    args: &[ExecutorArg],
) -> ExecutorResult {
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
    let get_mid: GetStaticMethodIdFn = jni_fn!(env, GetStaticMethodIdFn, JNI_GET_STATIC_METHOD_ID);

    let cls = find_class_safe(env, class_name);
    if jni_null_or_exc(env, cls) {
        return Err(format!("Java executor FindClass('{}') failed", class_name));
    }

    let c_name = match std::ffi::CString::new(method_name) {
        Ok(v) => v,
        Err(_) => {
            delete_local_ref(env, cls);
            return Err("Java executor invalid static method name".to_string());
        }
    };
    let c_sig = match std::ffi::CString::new(method_sig) {
        Ok(v) => v,
        Err(_) => {
            delete_local_ref(env, cls);
            return Err("Java executor invalid static method signature".to_string());
        }
    };
    let mid = get_mid(env, cls, c_name.as_ptr(), c_sig.as_ptr());
    if jni_null_or_exc(env, mid) {
        delete_local_ref(env, cls);
        return Err(format!(
            "Java executor GetStaticMethodID failed: {}.{}{}",
            class_name, method_name, method_sig
        ));
    }

    let mut locals = Vec::new();
    let jargs = build_executor_jargs(env, param_types, args, &mut locals)?;
    let result = call_executor_method(env, cls, mid, method_sig, true, jargs.as_ptr());
    for local in locals {
        if !local.is_null() {
            delete_local_ref(env, local);
        }
    }
    delete_local_ref(env, cls);
    result
}

unsafe fn execute_new_object_task(
    env: JniEnv,
    class_name: &str,
    ctor_sig: &str,
    param_types: &[String],
    args: &[ExecutorArg],
) -> ExecutorResult {
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
    let get_mid: GetMethodIdFn = jni_fn!(env, GetMethodIdFn, JNI_GET_METHOD_ID);
    let new_object: NewObjectAFn = jni_fn!(env, NewObjectAFn, JNI_NEW_OBJECT_A);

    let cls = find_class_safe(env, class_name);
    if jni_null_or_exc(env, cls) {
        return Err(format!("Java executor FindClass('{}') failed", class_name));
    }

    let c_name = std::ffi::CString::new("<init>").unwrap();
    let c_sig = match std::ffi::CString::new(ctor_sig) {
        Ok(v) => v,
        Err(_) => {
            delete_local_ref(env, cls);
            return Err("Java executor invalid constructor signature".to_string());
        }
    };
    let mid = get_mid(env, cls, c_name.as_ptr(), c_sig.as_ptr());
    if jni_null_or_exc(env, mid) {
        delete_local_ref(env, cls);
        return Err(format!(
            "Java executor GetMethodID failed: {}.<init>{}",
            class_name, ctor_sig
        ));
    }

    let mut locals = Vec::new();
    let jargs = build_executor_jargs(env, param_types, args, &mut locals)?;
    let obj = new_object(env, cls, mid, jargs.as_ptr() as *const std::ffi::c_void);
    for local in locals {
        if !local.is_null() {
            delete_local_ref(env, local);
        }
    }
    delete_local_ref(env, cls);

    if jni_null_or_exc(env, obj) {
        return Err(format!("Java executor exception in {}.<init>{}", class_name, ctor_sig));
    }
    object_result_from_local_ref_for_new_object(env, obj, &format!("L{};", class_name.replace('.', "/")))
}

unsafe fn local_ref_for_executor_object(
    env: JniEnv,
    obj_ptr: u64,
    obj_is_global: bool,
) -> Result<*mut std::ffi::c_void, String> {
    if obj_ptr == 0 {
        return Ok(std::ptr::null_mut());
    }
    if obj_is_global {
        let new_local_ref: NewLocalRefFn = jni_fn!(env, NewLocalRefFn, JNI_NEW_LOCAL_REF);
        let local = new_local_ref(env, obj_ptr as *mut std::ffi::c_void);
        if jni_null_or_exc(env, local) {
            return Err("Java executor NewLocalRef failed for global object".to_string());
        }
        Ok(local)
    } else {
        let local = raw_mirror_to_local_ref(env, obj_ptr);
        if jni_null_or_exc(env, local) {
            return Err("Java executor raw mirror local-ref conversion failed".to_string());
        }
        Ok(local)
    }
}

unsafe fn execute_array_length_task(env: JniEnv, array_ptr: u64, array_is_global: bool) -> ExecutorResult {
    let local = local_ref_for_executor_object(env, array_ptr, array_is_global)?;
    if local.is_null() {
        return Err("Java executor array target is null".to_string());
    }
    let get_len: GetArrayLengthFn = jni_fn!(env, GetArrayLengthFn, JNI_GET_ARRAY_LENGTH);
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
    let len = get_len(env, local);
    let failed = jni_check_exc(env);
    delete_local_ref(env, local);
    if failed {
        return Err("Java executor GetArrayLength failed".to_string());
    }
    Ok(ExecutorValue::Int(len))
}

unsafe fn execute_array_get_task(
    env: JniEnv,
    array_ptr: u64,
    array_is_global: bool,
    index: i32,
    elem_sig: &str,
) -> ExecutorResult {
    let local = local_ref_for_executor_object(env, array_ptr, array_is_global)?;
    if local.is_null() {
        return Err("Java executor array target is null".to_string());
    }
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
    if !elem_sig.starts_with('L') && !elem_sig.starts_with('[') {
        delete_local_ref(env, local);
        return Err(format!(
            "Java executor array get only supports object arrays, got {}",
            elem_sig
        ));
    }
    let get_elem: GetObjectArrayElementFn = jni_fn!(env, GetObjectArrayElementFn, JNI_GET_OBJECT_ARRAY_ELEMENT);
    let obj = get_elem(env, local, index);
    let failed = jni_check_exc(env);
    delete_local_ref(env, local);
    if failed {
        if !obj.is_null() {
            delete_local_ref(env, obj);
        }
        return Err("Java executor GetObjectArrayElement failed".to_string());
    }
    object_result_from_local_ref(env, obj, elem_sig)
}

unsafe fn lookup_executor_field_meta(class_name: &str, field_name: &str) -> Option<(String, u64, u32, bool)> {
    let guard = super::art_method::FIELD_CACHE.lock().unwrap_or_else(|e| e.into_inner());
    let cache = guard.as_ref()?;
    let class_fields = cache.get(class_name)?;
    let info = class_fields.get(field_name)?;
    Some((
        info.jni_sig.clone(),
        info.field_id as u64,
        info.field_offset,
        info.is_static,
    ))
}

unsafe fn execute_field_meta_task(env: JniEnv, class_name: &str, field_name: &str) -> ExecutorResult {
    super::reflect::ensure_reflect_ids(env);
    super::art_method::cache_fields_for_class(env, class_name);
    match lookup_executor_field_meta(class_name, field_name) {
        Some((sig, field_id, field_offset, is_static)) => Ok(ExecutorValue::FieldMeta {
            field_id,
            sig,
            is_static,
            class_name: class_name.to_string(),
            field_offset,
        }),
        None => Ok(ExecutorValue::Undefined),
    }
}

unsafe fn execute_field_read_task(
    env: JniEnv,
    obj_ptr: u64,
    obj_is_global: bool,
    class_name: &str,
    field_id: u64,
    sig: &str,
    is_static: bool,
) -> ExecutorResult {
    if field_id == 0 {
        return Err("Java executor field id is null".to_string());
    }
    let field_id = field_id as *mut std::ffi::c_void;
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
    let target = if is_static {
        let cls = find_class_safe(env, class_name);
        if jni_null_or_exc(env, cls) {
            return Err(format!(
                "Java executor FindClass('{}') failed for field read",
                class_name
            ));
        }
        cls
    } else {
        if obj_ptr == 0 {
            return Err("Java executor field read target is null".to_string());
        }
        local_ref_for_executor_object(env, obj_ptr, obj_is_global)?
    };
    let result = read_executor_field_value(env, target, field_id, sig, is_static);
    delete_local_ref(env, target);
    result
}

unsafe fn read_executor_field_value(
    env: JniEnv,
    target: *mut std::ffi::c_void,
    field_id: *mut std::ffi::c_void,
    sig: &str,
    is_static: bool,
) -> ExecutorResult {
    macro_rules! read_prim {
        ($static_ty:ty, $inst_ty:ty, $static_idx:expr, $inst_idx:expr, $convert:expr) => {{
            if is_static {
                let f: $static_ty = jni_fn!(env, $static_ty, $static_idx);
                let v = f(env, target, field_id);
                if jni_check_exc(env) {
                    return Err("Java executor exception during static field read".to_string());
                }
                $convert(v)
            } else {
                let f: $inst_ty = jni_fn!(env, $inst_ty, $inst_idx);
                let v = f(env, target, field_id);
                if jni_check_exc(env) {
                    return Err("Java executor exception during instance field read".to_string());
                }
                $convert(v)
            }
        }};
    }

    match sig.as_bytes().first().copied() {
        Some(b'Z') => read_prim!(
            GetStaticBooleanFieldFn,
            GetBooleanFieldFn,
            JNI_GET_STATIC_BOOLEAN_FIELD,
            JNI_GET_BOOLEAN_FIELD,
            |v: u8| Ok(ExecutorValue::Bool(v != 0))
        ),
        Some(b'B') => read_prim!(
            GetStaticByteFieldFn,
            GetByteFieldFn,
            JNI_GET_STATIC_BYTE_FIELD,
            JNI_GET_BYTE_FIELD,
            |v: i8| Ok(ExecutorValue::Int(v as i32))
        ),
        Some(b'C') => read_prim!(
            GetStaticCharFieldFn,
            GetCharFieldFn,
            JNI_GET_STATIC_CHAR_FIELD,
            JNI_GET_CHAR_FIELD,
            |v: u16| Ok(ExecutorValue::String(
                std::char::from_u32(v as u32).unwrap_or('\0').to_string()
            ))
        ),
        Some(b'S') => read_prim!(
            GetStaticShortFieldFn,
            GetShortFieldFn,
            JNI_GET_STATIC_SHORT_FIELD,
            JNI_GET_SHORT_FIELD,
            |v: i16| Ok(ExecutorValue::Int(v as i32))
        ),
        Some(b'I') => read_prim!(
            GetStaticIntFieldFn,
            GetIntFieldFn,
            JNI_GET_STATIC_INT_FIELD,
            JNI_GET_INT_FIELD,
            |v: i32| Ok(ExecutorValue::Int(v))
        ),
        Some(b'J') => read_prim!(
            GetStaticLongFieldFn,
            GetLongFieldFn,
            JNI_GET_STATIC_LONG_FIELD,
            JNI_GET_LONG_FIELD,
            |v: i64| Ok(ExecutorValue::BigU64(v as u64))
        ),
        Some(b'F') => read_prim!(
            GetStaticFloatFieldFn,
            GetFloatFieldFn,
            JNI_GET_STATIC_FLOAT_FIELD,
            JNI_GET_FLOAT_FIELD,
            |v: f32| Ok(ExecutorValue::Float(v as f64))
        ),
        Some(b'D') => read_prim!(
            GetStaticDoubleFieldFn,
            GetDoubleFieldFn,
            JNI_GET_STATIC_DOUBLE_FIELD,
            JNI_GET_DOUBLE_FIELD,
            |v: f64| Ok(ExecutorValue::Float(v))
        ),
        Some(b'L') | Some(b'[') => {
            let obj = if is_static {
                let f: GetStaticObjectFieldFn = jni_fn!(env, GetStaticObjectFieldFn, JNI_GET_STATIC_OBJECT_FIELD);
                f(env, target, field_id)
            } else {
                let f: GetObjectFieldFn = jni_fn!(env, GetObjectFieldFn, JNI_GET_OBJECT_FIELD);
                f(env, target, field_id)
            };
            if jni_check_exc(env) {
                if !obj.is_null() {
                    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
                    delete_local_ref(env, obj);
                }
                return Err("Java executor exception during object field read".to_string());
            }
            object_result_from_local_ref(env, obj, sig)
        }
        _ => Ok(ExecutorValue::Undefined),
    }
}

unsafe fn execute_field_write_task(
    env: JniEnv,
    obj_ptr: u64,
    obj_is_global: bool,
    class_name: &str,
    field_id: u64,
    sig: &str,
    is_static: bool,
    value: &ExecutorArg,
) -> ExecutorResult {
    if field_id == 0 {
        return Err("Java executor field id is null".to_string());
    }
    let field_id = field_id as *mut std::ffi::c_void;
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
    let target = if is_static {
        let cls = find_class_safe(env, class_name);
        if jni_null_or_exc(env, cls) {
            return Err(format!(
                "Java executor FindClass('{}') failed for field write",
                class_name
            ));
        }
        cls
    } else {
        if obj_ptr == 0 {
            return Err("Java executor field write target is null".to_string());
        }
        local_ref_for_executor_object(env, obj_ptr, obj_is_global)?
    };
    let result = write_executor_field_value(env, target, field_id, sig, is_static, value);
    delete_local_ref(env, target);
    result
}

unsafe fn execute_direct_get_field_task(
    env: JniEnv,
    obj_ptr: u64,
    class_name: &str,
    field_name: &str,
    field_sig: &str,
) -> ExecutorResult {
    if obj_ptr == 0 {
        return Err("Java executor direct getField target is null".to_string());
    }

    let sig_first = field_sig.as_bytes().first().copied();
    if !matches!(
        sig_first,
        Some(b'Z' | b'B' | b'C' | b'S' | b'I' | b'J' | b'F' | b'D' | b'L' | b'[')
    ) {
        return Err(format!("unsupported field signature: {}", field_sig));
    }

    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
    let get_field_id: GetFieldIdFn = jni_fn!(env, GetFieldIdFn, JNI_GET_FIELD_ID);
    let new_local_ref: NewLocalRefFn = jni_fn!(env, NewLocalRefFn, JNI_NEW_LOCAL_REF);

    let cls = find_class_safe(env, class_name);
    if jni_null_or_exc(env, cls) {
        return Err(format!("Java executor FindClass('{}') failed for getField", class_name));
    }

    let local_obj = new_local_ref(env, obj_ptr as *mut std::ffi::c_void);
    if jni_null_or_exc(env, local_obj) {
        delete_local_ref(env, cls);
        return Err("Java executor NewLocalRef failed for getField target".to_string());
    }

    let c_field = match std::ffi::CString::new(field_name) {
        Ok(v) => v,
        Err(_) => {
            delete_local_ref(env, local_obj);
            delete_local_ref(env, cls);
            return Err("invalid field name".to_string());
        }
    };
    let c_sig = match std::ffi::CString::new(field_sig) {
        Ok(v) => v,
        Err(_) => {
            delete_local_ref(env, local_obj);
            delete_local_ref(env, cls);
            return Err("invalid field signature".to_string());
        }
    };

    let field_id = get_field_id(env, cls, c_field.as_ptr(), c_sig.as_ptr());
    if jni_null_or_exc(env, field_id) {
        delete_local_ref(env, local_obj);
        delete_local_ref(env, cls);
        return Err(format!(
            "Java executor GetFieldID failed: {}.{}{}",
            class_name, field_name, field_sig
        ));
    }

    let result = read_executor_field_value(env, local_obj, field_id, field_sig, false);
    delete_local_ref(env, local_obj);
    delete_local_ref(env, cls);
    result
}

unsafe fn write_executor_field_value(
    env: JniEnv,
    target: *mut std::ffi::c_void,
    field_id: *mut std::ffi::c_void,
    sig: &str,
    is_static: bool,
    value: &ExecutorArg,
) -> ExecutorResult {
    macro_rules! raw_arg {
        () => {
            match value {
                ExecutorArg::Raw(v) => *v,
                _ => 0,
            }
        };
    }
    macro_rules! write_prim {
        ($static_ty:ty, $inst_ty:ty, $static_idx:expr, $inst_idx:expr, $val:expr) => {{
            if is_static {
                let f: $static_ty = jni_fn!(env, $static_ty, $static_idx);
                f(env, target, field_id, $val);
            } else {
                let f: $inst_ty = jni_fn!(env, $inst_ty, $inst_idx);
                f(env, target, field_id, $val);
            }
            if jni_check_exc(env) {
                Err("Java executor exception during field write".to_string())
            } else {
                Ok(ExecutorValue::Undefined)
            }
        }};
    }

    match sig.as_bytes().first().copied() {
        Some(b'Z') => write_prim!(
            unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, u8),
            unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, u8),
            JNI_SET_STATIC_BOOLEAN_FIELD,
            JNI_SET_BOOLEAN_FIELD,
            (raw_arg!() != 0) as u8
        ),
        Some(b'B') => write_prim!(
            unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, i8),
            unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, i8),
            JNI_SET_STATIC_BYTE_FIELD,
            JNI_SET_BYTE_FIELD,
            raw_arg!() as i8
        ),
        Some(b'C') => write_prim!(
            unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, u16),
            unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, u16),
            JNI_SET_STATIC_CHAR_FIELD,
            JNI_SET_CHAR_FIELD,
            raw_arg!() as u16
        ),
        Some(b'S') => write_prim!(
            unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, i16),
            unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, i16),
            JNI_SET_STATIC_SHORT_FIELD,
            JNI_SET_SHORT_FIELD,
            raw_arg!() as i16
        ),
        Some(b'I') => write_prim!(
            SetStaticIntFieldFn,
            unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, i32),
            JNI_SET_STATIC_INT_FIELD,
            JNI_SET_INT_FIELD,
            raw_arg!() as i32
        ),
        Some(b'J') => write_prim!(
            unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, i64),
            unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, i64),
            JNI_SET_STATIC_LONG_FIELD,
            JNI_SET_LONG_FIELD,
            raw_arg!() as i64
        ),
        Some(b'F') => write_prim!(
            unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, f32),
            unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, f32),
            JNI_SET_STATIC_FLOAT_FIELD,
            JNI_SET_FLOAT_FIELD,
            f32::from_bits(raw_arg!() as u32)
        ),
        Some(b'D') => write_prim!(
            unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, f64),
            unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, f64),
            JNI_SET_STATIC_DOUBLE_FIELD,
            JNI_SET_DOUBLE_FIELD,
            f64::from_bits(raw_arg!())
        ),
        Some(b'L') | Some(b'[') => {
            let mut locals = Vec::new();
            let obj = build_executor_object_arg(env, sig, value, &mut locals)?;
            if is_static {
                type F =
                    unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, *mut std::ffi::c_void);
                let f: F = jni_fn!(env, F, JNI_SET_STATIC_OBJECT_FIELD);
                f(env, target, field_id, obj);
            } else {
                type F =
                    unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, *mut std::ffi::c_void);
                let f: F = jni_fn!(env, F, JNI_SET_OBJECT_FIELD);
                f(env, target, field_id, obj);
            }
            let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
            for local in locals {
                if !local.is_null() {
                    delete_local_ref(env, local);
                }
            }
            if jni_check_exc(env) {
                Err("Java executor exception during object field write".to_string())
            } else {
                Ok(ExecutorValue::Undefined)
            }
        }
        _ => Ok(ExecutorValue::Undefined),
    }
}

unsafe fn build_executor_jargs(
    env: JniEnv,
    param_types: &[String],
    args: &[ExecutorArg],
    locals: &mut Vec<*mut std::ffi::c_void>,
) -> Result<Vec<u64>, String> {
    let mut out = Vec::with_capacity(param_types.len());
    for (idx, sig) in param_types.iter().enumerate() {
        let arg = args
            .get(idx)
            .ok_or_else(|| "Java executor missing argument".to_string())?;
        let raw = match sig.as_bytes().first().copied() {
            Some(b'Z') => match arg {
                ExecutorArg::Raw(v) => (*v != 0) as u64,
                _ => 0,
            },
            Some(b'B') | Some(b'C') | Some(b'S') | Some(b'I') | Some(b'J') => match arg {
                ExecutorArg::Raw(v) => *v,
                _ => 0,
            },
            Some(b'F') => match arg {
                ExecutorArg::Raw(v) => *v as u32 as u64,
                _ => 0,
            },
            Some(b'D') => match arg {
                ExecutorArg::Raw(v) => *v,
                _ => 0,
            },
            Some(b'L') | Some(b'[') => build_executor_object_arg(env, sig, arg, locals)? as u64,
            _ => 0,
        };
        out.push(raw);
    }
    Ok(out)
}

unsafe fn build_executor_object_arg(
    env: JniEnv,
    sig: &str,
    arg: &ExecutorArg,
    locals: &mut Vec<*mut std::ffi::c_void>,
) -> Result<*mut std::ffi::c_void, String> {
    match arg {
        ExecutorArg::Null => Ok(std::ptr::null_mut()),
        ExecutorArg::String(s) if sig == "Ljava/lang/String;" => {
            let new_string: NewStringUtfFn = jni_fn!(env, NewStringUtfFn, JNI_NEW_STRING_UTF);
            let c = std::ffi::CString::new(s.as_str()).map_err(|_| "Java executor string contains NUL".to_string())?;
            let local = new_string(env, c.as_ptr());
            if jni_null_or_exc(env, local) {
                return Err("Java executor NewStringUTF failed".to_string());
            }
            locals.push(local);
            Ok(local)
        }
        ExecutorArg::Object(raw) | ExecutorArg::Raw(raw) => {
            if *raw == 0 {
                return Ok(std::ptr::null_mut());
            }
            let local = raw_mirror_to_local_ref(env, *raw);
            if jni_null_or_exc(env, local) {
                return Err("Java executor object local-ref conversion failed".to_string());
            }
            locals.push(local);
            Ok(local)
        }
        ExecutorArg::GlobalRef(raw) => {
            if *raw == 0 {
                return Ok(std::ptr::null_mut());
            }
            let new_local_ref: NewLocalRefFn = jni_fn!(env, NewLocalRefFn, JNI_NEW_LOCAL_REF);
            let local = new_local_ref(env, *raw as *mut std::ffi::c_void);
            if jni_null_or_exc(env, local) {
                return Err("Java executor global-ref local conversion failed".to_string());
            }
            locals.push(local);
            Ok(local)
        }
        ExecutorArg::String(_) => Err(format!("Java executor cannot pass JS string to {}", sig)),
    }
}

unsafe fn call_executor_method(
    env: JniEnv,
    target: *mut std::ffi::c_void,
    mid: *mut std::ffi::c_void,
    method_sig: &str,
    is_static: bool,
    jargs: *const u64,
) -> ExecutorResult {
    let ret = get_return_type_from_sig(method_sig);
    let ret_sig = get_return_type_sig(method_sig);
    let jargs = jargs as *const std::ffi::c_void;

    macro_rules! call_prim {
        ($static_ty:ty, $inst_ty:ty, $static_idx:expr, $inst_idx:expr, $convert:expr) => {{
            if is_static {
                let f: $static_ty = jni_fn!(env, $static_ty, $static_idx);
                let v = f(env, target, mid, jargs);
                if jni_check_exc(env) {
                    return Err("Java executor exception during static method call".to_string());
                }
                $convert(v)
            } else {
                let f: $inst_ty = jni_fn!(env, $inst_ty, $inst_idx);
                let v = f(env, target, mid, jargs);
                if jni_check_exc(env) {
                    return Err("Java executor exception during instance method call".to_string());
                }
                $convert(v)
            }
        }};
    }

    match ret {
        b'V' => {
            if is_static {
                type F =
                    unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, *const std::ffi::c_void);
                let f: F = jni_fn!(env, F, JNI_CALL_STATIC_VOID_METHOD_A);
                f(env, target, mid, jargs);
            } else {
                type F =
                    unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, *const std::ffi::c_void);
                let f: F = jni_fn!(env, F, JNI_CALL_VOID_METHOD_A);
                f(env, target, mid, jargs);
            }
            if jni_check_exc(env) {
                Err("Java executor exception during void method call".to_string())
            } else {
                Ok(ExecutorValue::Undefined)
            }
        }
        b'Z' => call_prim!(
            ExecCallStaticBooleanMethodAFn,
            CallBooleanMethodAFn,
            JNI_CALL_STATIC_BOOLEAN_METHOD_A,
            JNI_CALL_BOOLEAN_METHOD_A,
            |v: u8| Ok(ExecutorValue::Bool(v != 0))
        ),
        b'B' => call_prim!(
            ExecCallStaticByteMethodAFn,
            CallByteMethodAFn,
            JNI_CALL_STATIC_BYTE_METHOD_A,
            JNI_CALL_BYTE_METHOD_A,
            |v: i8| Ok(ExecutorValue::Int(v as i32))
        ),
        b'C' => call_prim!(
            ExecCallStaticCharMethodAFn,
            CallCharMethodAFn,
            JNI_CALL_STATIC_CHAR_METHOD_A,
            JNI_CALL_CHAR_METHOD_A,
            |v: u16| Ok(ExecutorValue::String(
                std::char::from_u32(v as u32).unwrap_or('\0').to_string()
            ))
        ),
        b'S' => call_prim!(
            ExecCallStaticShortMethodAFn,
            CallShortMethodAFn,
            JNI_CALL_STATIC_SHORT_METHOD_A,
            JNI_CALL_SHORT_METHOD_A,
            |v: i16| Ok(ExecutorValue::Int(v as i32))
        ),
        b'I' => call_prim!(
            CallStaticIntMethodAFn,
            CallIntMethodAFn,
            JNI_CALL_STATIC_INT_METHOD_A,
            JNI_CALL_INT_METHOD_A,
            |v: i32| Ok(ExecutorValue::Int(v))
        ),
        b'J' => call_prim!(
            ExecCallStaticLongMethodAFn,
            CallLongMethodAFn,
            JNI_CALL_STATIC_LONG_METHOD_A,
            JNI_CALL_LONG_METHOD_A,
            |v: i64| Ok(ExecutorValue::BigU64(v as u64))
        ),
        b'F' => call_prim!(
            ExecCallStaticFloatMethodAFn,
            CallFloatMethodAFn,
            JNI_CALL_STATIC_FLOAT_METHOD_A,
            JNI_CALL_FLOAT_METHOD_A,
            |v: f32| Ok(ExecutorValue::Float(v as f64))
        ),
        b'D' => call_prim!(
            ExecCallStaticDoubleMethodAFn,
            CallDoubleMethodAFn,
            JNI_CALL_STATIC_DOUBLE_METHOD_A,
            JNI_CALL_DOUBLE_METHOD_A,
            |v: f64| Ok(ExecutorValue::Float(v))
        ),
        b'L' | b'[' => {
            let obj = if is_static {
                type F = unsafe extern "C" fn(
                    JniEnv,
                    *mut std::ffi::c_void,
                    *mut std::ffi::c_void,
                    *const std::ffi::c_void,
                ) -> *mut std::ffi::c_void;
                let f: F = jni_fn!(env, F, JNI_CALL_STATIC_OBJECT_METHOD_A);
                f(env, target, mid, jargs)
            } else {
                type F = unsafe extern "C" fn(
                    JniEnv,
                    *mut std::ffi::c_void,
                    *mut std::ffi::c_void,
                    *const std::ffi::c_void,
                ) -> *mut std::ffi::c_void;
                let f: F = jni_fn!(env, F, JNI_CALL_OBJECT_METHOD_A);
                f(env, target, mid, jargs)
            };
            if jni_check_exc(env) {
                if !obj.is_null() {
                    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
                    delete_local_ref(env, obj);
                }
                return Err("Java executor exception during object method call".to_string());
            }
            object_result_from_local_ref(env, obj, &ret_sig)
        }
        _ => Ok(ExecutorValue::Undefined),
    }
}

unsafe fn object_result_from_local_ref(env: JniEnv, obj: *mut std::ffi::c_void, ret_sig: &str) -> ExecutorResult {
    object_result_from_local_ref_inner(env, obj, ret_sig, true)
}

unsafe fn object_result_from_local_ref_for_new_object(
    env: JniEnv,
    obj: *mut std::ffi::c_void,
    ret_sig: &str,
) -> ExecutorResult {
    object_result_from_local_ref_inner(env, obj, ret_sig, false)
}

unsafe fn object_result_from_local_ref_inner(
    env: JniEnv,
    obj: *mut std::ffi::c_void,
    ret_sig: &str,
    convert_string: bool,
) -> ExecutorResult {
    if obj.is_null() {
        return Ok(ExecutorValue::Null);
    }

    if convert_string && ret_sig == "Ljava/lang/String;" {
        let get_str: GetStringUtfCharsFn = jni_fn!(env, GetStringUtfCharsFn, JNI_GET_STRING_UTF_CHARS);
        let rel_str: ReleaseStringUtfCharsFn = jni_fn!(env, ReleaseStringUtfCharsFn, JNI_RELEASE_STRING_UTF_CHARS);
        let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
        let chars = get_str(env, obj, std::ptr::null_mut());
        let chars_failed = {
            let had_exc = jni_check_exc(env);
            chars.is_null() || had_exc
        };
        if chars_failed {
            delete_local_ref(env, obj);
            return Err("Java executor GetStringUTFChars failed".to_string());
        }
        let s = std::ffi::CStr::from_ptr(chars).to_string_lossy().to_string();
        rel_str(env, obj, chars);
        delete_local_ref(env, obj);
        return Ok(ExecutorValue::String(s));
    }

    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
    let new_global_ref: NewGlobalRefFn = jni_fn!(env, NewGlobalRefFn, JNI_NEW_GLOBAL_REF);
    let global = new_global_ref(env, obj);
    delete_local_ref(env, obj);
    if jni_null_or_exc(env, global) {
        return Err("Java executor NewGlobalRef failed for object result".to_string());
    }
    remember_executor_global_ref(global as u64);
    Ok(ExecutorValue::Object {
        ptr: global as u64,
        class_name: jni_object_sig_to_class_name(ret_sig),
        is_global: true,
    })
}

fn remember_executor_global_ref(global: u64) {
    if global == 0 {
        return;
    }
    let mut refs = EXECUTOR_GLOBAL_REFS.lock().unwrap_or_else(|e| e.into_inner());
    refs.push(global);
}

fn forget_executor_global_ref(global: u64) -> bool {
    if global == 0 {
        return false;
    }
    let mut refs = EXECUTOR_GLOBAL_REFS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(pos) = refs.iter().position(|item| *item == global) {
        refs.swap_remove(pos);
        true
    } else {
        false
    }
}

fn take_executor_global_refs() -> Vec<u64> {
    let mut refs = EXECUTOR_GLOBAL_REFS.lock().unwrap_or_else(|e| e.into_inner());
    std::mem::take(&mut *refs)
}

unsafe fn release_executor_global_refs_on_java_thread(env: JniEnv, refs: &[u64]) {
    if env.is_null() || refs.is_empty() {
        return;
    }
    let delete_global_ref: DeleteGlobalRefFn = jni_fn!(env, DeleteGlobalRefFn, JNI_DELETE_GLOBAL_REF);
    for raw in refs {
        if *raw != 0 {
            delete_global_ref(env, *raw as *mut std::ffi::c_void);
        }
    }
}

unsafe fn collect_executor_args(
    ctx: *mut ffi::JSContext,
    argv: *mut ffi::JSValue,
    start: i32,
    param_types: &[String],
) -> Result<Vec<ExecutorArg>, String> {
    let mut out = Vec::with_capacity(param_types.len());
    for (idx, sig) in param_types.iter().enumerate() {
        let val = JSValue(*argv.add(start as usize + idx));
        let arg = match sig.as_bytes().first().copied() {
            Some(b'Z') => ExecutorArg::Raw(val.to_bool().map(|v| v as u64).or_else(|| val.to_u64(ctx)).unwrap_or(0)),
            Some(b'B') | Some(b'C') | Some(b'S') | Some(b'I') | Some(b'J') => {
                ExecutorArg::Raw(val.to_u64(ctx).unwrap_or(0))
            }
            Some(b'F') => ExecutorArg::Raw((val.to_float().unwrap_or(0.0) as f32).to_bits() as u64),
            Some(b'D') => ExecutorArg::Raw(val.to_float().unwrap_or(0.0).to_bits()),
            Some(b'L') | Some(b'[') => collect_executor_object_arg(ctx, val, sig)?,
            _ => ExecutorArg::Raw(0),
        };
        out.push(arg);
    }
    Ok(out)
}

unsafe fn collect_executor_object_arg(
    ctx: *mut ffi::JSContext,
    val: JSValue,
    sig: &str,
) -> Result<ExecutorArg, String> {
    if val.is_null() || val.is_undefined() {
        return Ok(ExecutorArg::Null);
    }
    if sig == "Ljava/lang/String;" && val.is_string() {
        return val
            .to_string(ctx)
            .map(ExecutorArg::String)
            .ok_or_else(|| "Java executor failed to read JS string".to_string());
    }
    if val.is_object() {
        let jptr = val.get_property(ctx, "__jptr");
        let ptr = jptr.to_u64(ctx).unwrap_or(0);
        jptr.free(ctx);
        if ptr != 0 {
            let is_global = val.get_property(ctx, "__jglobal").to_bool().unwrap_or(false);
            return Ok(if is_global {
                ExecutorArg::GlobalRef(ptr)
            } else {
                ExecutorArg::Object(ptr)
            });
        }
    }
    if let Some(ptr) = val.to_u64(ctx) {
        return Ok(ExecutorArg::Object(ptr));
    }
    Err(format!("Java executor cannot marshal argument for {}", sig))
}

pub(super) unsafe fn invoke_instance_via_executor(
    ctx: *mut ffi::JSContext,
    obj_ptr: u64,
    obj_is_global: bool,
    class_name: String,
    method_name: String,
    method_sig: String,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let param_types = parse_jni_param_types(&method_sig);
    let args = match collect_executor_args(ctx, argv, 4, &param_types) {
        Ok(v) => v,
        Err(err) => return js_throw_internal_error(ctx, err),
    };
    let result = enqueue_executor_task(
        ExecutorTaskKind::Instance {
            obj_ptr,
            obj_is_global,
            class_name,
            method_name,
            method_sig,
        },
        param_types,
        args,
    );
    executor_value_to_js(ctx, result)
}

pub(super) unsafe fn resolve_method_via_executor(
    class_name: String,
    method_name: String,
    method_sig: String,
    force_static: bool,
) -> Result<(u64, bool), String> {
    match enqueue_executor_task(
        ExecutorTaskKind::ResolveMethod {
            class_name,
            method_name,
            method_sig,
            force_static,
        },
        Vec::new(),
        Vec::new(),
    ) {
        Ok(ExecutorValue::Method { art_method, is_static }) => Ok((art_method, is_static)),
        Ok(_) => Err("Java executor returned non-method resolve result".to_string()),
        Err(err) => Err(err),
    }
}

pub(super) unsafe fn invoke_static_via_executor(
    ctx: *mut ffi::JSContext,
    class_name: String,
    method_name: String,
    method_sig: String,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let param_types = parse_jni_param_types(&method_sig);
    let args = match collect_executor_args(ctx, argv, 3, &param_types) {
        Ok(v) => v,
        Err(err) => return js_throw_internal_error(ctx, err),
    };
    let result = enqueue_executor_task(
        ExecutorTaskKind::Static {
            class_name,
            method_name,
            method_sig,
        },
        param_types,
        args,
    );
    executor_value_to_js(ctx, result)
}

pub(super) unsafe fn new_object_via_executor(
    ctx: *mut ffi::JSContext,
    class_name: String,
    ctor_sig: String,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let param_types = parse_jni_param_types(&ctor_sig);
    let args = match collect_executor_args(ctx, argv, 2, &param_types) {
        Ok(v) => v,
        Err(err) => return js_throw_internal_error(ctx, err),
    };
    let result = enqueue_executor_task(ExecutorTaskKind::NewObject { class_name, ctor_sig }, param_types, args);
    executor_value_to_js(ctx, result)
}

pub(super) unsafe fn array_length_via_executor(
    ctx: *mut ffi::JSContext,
    array_ptr: u64,
    array_is_global: bool,
) -> ffi::JSValue {
    let result = enqueue_executor_task(
        ExecutorTaskKind::ArrayLength {
            array_ptr,
            array_is_global,
        },
        Vec::new(),
        Vec::new(),
    );
    executor_value_to_js(ctx, result)
}

pub(super) unsafe fn array_get_via_executor(
    ctx: *mut ffi::JSContext,
    array_ptr: u64,
    array_is_global: bool,
    index: i32,
    elem_sig: String,
) -> ffi::JSValue {
    let result = enqueue_executor_task(
        ExecutorTaskKind::ArrayGet {
            array_ptr,
            array_is_global,
            index,
            elem_sig,
        },
        Vec::new(),
        Vec::new(),
    );
    executor_value_to_js(ctx, result)
}

pub(super) unsafe fn field_meta_via_executor(
    ctx: *mut ffi::JSContext,
    class_name: String,
    field_name: String,
) -> ffi::JSValue {
    let result = enqueue_executor_task(
        ExecutorTaskKind::FieldMeta { class_name, field_name },
        Vec::new(),
        Vec::new(),
    );
    executor_value_to_js(ctx, result)
}

pub(super) unsafe fn field_read_via_executor(
    ctx: *mut ffi::JSContext,
    obj_ptr: u64,
    obj_is_global: bool,
    class_name: String,
    field_id: u64,
    sig: String,
    is_static: bool,
) -> ffi::JSValue {
    let result = enqueue_executor_task(
        ExecutorTaskKind::FieldRead {
            obj_ptr,
            obj_is_global,
            class_name,
            field_id,
            sig,
            is_static,
        },
        Vec::new(),
        Vec::new(),
    );
    executor_value_to_js(ctx, result)
}

pub(super) unsafe fn field_write_via_executor(
    ctx: *mut ffi::JSContext,
    obj_ptr: u64,
    obj_is_global: bool,
    class_name: String,
    field_id: u64,
    sig: String,
    is_static: bool,
    value: JSValue,
) -> ffi::JSValue {
    let arg = match collect_executor_field_arg(ctx, value, &sig) {
        Ok(v) => v,
        Err(err) => return js_throw_internal_error(ctx, err),
    };
    let result = enqueue_executor_task(
        ExecutorTaskKind::FieldWrite {
            obj_ptr,
            obj_is_global,
            class_name,
            field_id,
            sig,
            is_static,
        },
        Vec::new(),
        vec![arg],
    );
    executor_value_to_js(ctx, result)
}

pub(super) unsafe fn direct_get_field_via_executor(
    ctx: *mut ffi::JSContext,
    obj_ptr: u64,
    class_name: String,
    field_name: String,
    field_sig: String,
) -> ffi::JSValue {
    let result = enqueue_executor_task(
        ExecutorTaskKind::DirectGetField {
            obj_ptr,
            class_name,
            field_name,
            field_sig,
        },
        Vec::new(),
        Vec::new(),
    );
    executor_value_to_js(ctx, result)
}

pub(super) unsafe fn enumerate_instances_via_executor(
    ctx: *mut ffi::JSContext,
    class_name: String,
    include_subtypes: bool,
    max_count: usize,
) -> ffi::JSValue {
    if !ensure_executor_loop_ready() {
        return js_throw_internal_error(ctx, "Java executor loop hook is not installed".to_string());
    }
    let result = enqueue_executor_task(
        ExecutorTaskKind::EnumerateInstances {
            class_name,
            include_subtypes,
            max_count,
        },
        Vec::new(),
        Vec::new(),
    );
    executor_value_to_js(ctx, result)
}

pub(super) unsafe fn release_global_refs_via_executor(refs: Vec<u64>) -> Result<(), String> {
    if refs.is_empty() {
        return Ok(());
    }
    if !ensure_executor_loop_ready() {
        return Err("Java executor loop hook is not installed".to_string());
    }
    match enqueue_executor_task(ExecutorTaskKind::CleanupGlobals { refs }, Vec::new(), Vec::new()) {
        Ok(_) => Ok(()),
        Err(err) => Err(err),
    }
}

pub(super) unsafe fn classloaders_via_executor(ctx: *mut ffi::JSContext) -> ffi::JSValue {
    if !ensure_executor_loop_ready() {
        return js_throw_internal_error(ctx, "Java executor loop hook is not installed".to_string());
    }
    executor_value_to_js(
        ctx,
        enqueue_executor_task(ExecutorTaskKind::ClassLoaders, Vec::new(), Vec::new()),
    )
}

pub(super) unsafe fn find_class_with_loader_via_executor(
    ctx: *mut ffi::JSContext,
    loader_ptr: u64,
    class_name: String,
) -> ffi::JSValue {
    if !ensure_executor_loop_ready() {
        return js_throw_internal_error(ctx, "Java executor loop hook is not installed".to_string());
    }
    executor_value_to_js(
        ctx,
        enqueue_executor_task(
            ExecutorTaskKind::FindClassWithLoader { loader_ptr, class_name },
            Vec::new(),
            Vec::new(),
        ),
    )
}

pub(super) unsafe fn find_class_object_via_executor(ctx: *mut ffi::JSContext, class_name: String) -> ffi::JSValue {
    if !ensure_executor_loop_ready() {
        return js_throw_internal_error(ctx, "Java executor loop hook is not installed".to_string());
    }
    executor_value_to_js(
        ctx,
        enqueue_executor_task(ExecutorTaskKind::FindClassObject { class_name }, Vec::new(), Vec::new()),
    )
}

pub(super) unsafe fn set_classloader_via_executor(ctx: *mut ffi::JSContext, loader_ptr: u64) -> ffi::JSValue {
    if crate::is_raw_clone_js_thread() && super::reflect::set_classloader_override_global_fast(loader_ptr) {
        return JSValue::bool(true).raw();
    }
    if !ensure_executor_loop_ready() {
        return js_throw_internal_error(ctx, "Java executor loop hook is not installed".to_string());
    }
    executor_value_to_js(
        ctx,
        enqueue_executor_task(ExecutorTaskKind::SetClassLoader { loader_ptr }, Vec::new(), Vec::new()),
    )
}

pub(super) unsafe fn resolve_fast_method_via_executor(
    class_name: String,
    method_name: String,
    method_sig: String,
    force_static: bool,
    should_compile: bool,
    compile_kind: super::java_fast_api::RequestedCompileKind,
) -> Result<(u64, u64, u64, bool), String> {
    if !ensure_executor_loop_ready() {
        return Err("Java executor loop hook is not installed".to_string());
    }
    match enqueue_executor_task(
        ExecutorTaskKind::ResolveFastMethod {
            class_name,
            method_name,
            method_sig,
            force_static,
            should_compile,
            compile_kind,
        },
        Vec::new(),
        Vec::new(),
    ) {
        Ok(ExecutorValue::FastMethod {
            art_method,
            class_global_ref,
            class_mirror,
            is_static,
        }) => Ok((art_method, class_global_ref, class_mirror, is_static)),
        Ok(_) => Err("Java executor returned non-fast-method result".to_string()),
        Err(err) => Err(err),
    }
}

pub(super) unsafe fn resolve_fast_field_via_executor(
    class_name: String,
    field_name: String,
    requested_sig: Option<String>,
) -> Result<super::java_fast_api::FastField, String> {
    if !ensure_executor_loop_ready() {
        return Err("Java executor loop hook is not installed".to_string());
    }
    match enqueue_executor_task(
        ExecutorTaskKind::ResolveFastField {
            class_name,
            field_name,
            requested_sig,
        },
        Vec::new(),
        Vec::new(),
    ) {
        Ok(ExecutorValue::FastField(field)) => Ok(field),
        Ok(_) => Err("Java executor returned non-fast-field result".to_string()),
        Err(err) => Err(err),
    }
}

pub(super) unsafe fn managed_hook_dsl_via_executor(
    class_name: String,
    method_name: String,
    method_sig: String,
    dsl: String,
    message_capacity: i32,
) -> Result<super::java_hook_api::ManagedDslInstallResult, String> {
    if !ensure_executor_loop_ready() {
        return Err("Java executor loop hook is not installed".to_string());
    }
    match enqueue_executor_task(
        ExecutorTaskKind::ManagedHookDsl {
            class_name,
            method_name,
            method_sig,
            dsl,
            message_capacity,
        },
        Vec::new(),
        Vec::new(),
    ) {
        Ok(ExecutorValue::ManagedHookDsl(result)) => Ok(result),
        Ok(_) => Err("Java executor returned non-managed-hook result".to_string()),
        Err(err) => Err(err),
    }
}

pub(super) unsafe fn fast_hook_via_executor(
    class_name: String,
    method_name: String,
    method_sig: String,
    dsl: String,
) -> Result<(), String> {
    if !ensure_executor_loop_ready() {
        return Err("Java executor loop hook is not installed".to_string());
    }
    match enqueue_executor_task(
        ExecutorTaskKind::FastHook {
            class_name,
            method_name,
            method_sig,
            dsl,
        },
        Vec::new(),
        Vec::new(),
    ) {
        Ok(ExecutorValue::Bool(true)) => Ok(()),
        Ok(_) => Err("Java executor returned non-fast-hook result".to_string()),
        Err(err) => Err(err),
    }
}

pub(super) unsafe fn deoptimize_method_via_executor(
    class_name: String,
    method_name: String,
    method_sig: String,
    force_static: bool,
) -> Result<(), String> {
    if !ensure_executor_loop_ready() {
        return Err("Java executor loop hook is not installed".to_string());
    }
    match enqueue_executor_task(
        ExecutorTaskKind::DeoptimizeMethod {
            class_name,
            method_name,
            method_sig,
            force_static,
        },
        Vec::new(),
        Vec::new(),
    ) {
        Ok(ExecutorValue::Bool(true)) => Ok(()),
        Ok(_) => Err("Java executor returned non-deoptimize result".to_string()),
        Err(err) => Err(err),
    }
}

pub(super) unsafe fn compile_method_via_executor(
    class_name: String,
    method_name: String,
    method_sig: String,
    force_static: bool,
    compile_kind: super::java_fast_api::RequestedCompileKind,
) -> Result<(u64, super::java_fast_api::CompileResult), String> {
    if !ensure_executor_loop_ready() {
        return Err("Java executor loop hook is not installed".to_string());
    }
    match enqueue_executor_task(
        ExecutorTaskKind::CompileMethod {
            class_name,
            method_name,
            method_sig,
            force_static,
            compile_kind,
        },
        Vec::new(),
        Vec::new(),
    ) {
        Ok(ExecutorValue::CompileResult { art_method, result }) => Ok((art_method, result)),
        Ok(_) => Err("Java executor returned non-compile result".to_string()),
        Err(err) => Err(err),
    }
}

pub(super) unsafe fn jit_info_via_executor(ctx: *mut ffi::JSContext) -> ffi::JSValue {
    if !ensure_executor_loop_ready() {
        return js_throw_internal_error(ctx, "Java executor loop hook is not installed".to_string());
    }
    executor_value_to_js(
        ctx,
        enqueue_executor_task(ExecutorTaskKind::JitInfo, Vec::new(), Vec::new()),
    )
}

pub(super) unsafe fn reprobe_classloader_via_executor(ctx: *mut ffi::JSContext, once: bool) -> ffi::JSValue {
    if !ensure_executor_loop_ready() {
        return js_throw_internal_error(ctx, "Java executor loop hook is not installed".to_string());
    }
    executor_value_to_js(
        ctx,
        enqueue_executor_task(ExecutorTaskKind::ReprobeClassLoader { once }, Vec::new(), Vec::new()),
    )
}

pub(super) unsafe fn managed_drain_messages_via_executor(
    helper_class: String,
    max_items_requested: Option<i64>,
) -> Result<super::java_hook_api::ManagedDrainResult, String> {
    if !ensure_executor_loop_ready() {
        return Err("Java executor loop hook is not installed".to_string());
    }
    match enqueue_executor_task(
        ExecutorTaskKind::ManagedDrainMessages {
            helper_class,
            max_items_requested,
        },
        Vec::new(),
        Vec::new(),
    ) {
        Ok(ExecutorValue::ManagedDrain(result)) => Ok(result),
        Ok(_) => Err("Java executor returned non-managed-drain result".to_string()),
        Err(err) => Err(err),
    }
}

pub(super) unsafe fn managed_read_counter_via_executor(
    helper_class: String,
    field_name: String,
) -> Result<u64, String> {
    if !ensure_executor_loop_ready() {
        return Err("Java executor loop hook is not installed".to_string());
    }
    match enqueue_executor_task(
        ExecutorTaskKind::ManagedReadCounter {
            helper_class,
            field_name,
        },
        Vec::new(),
        Vec::new(),
    ) {
        Ok(ExecutorValue::BigU64(value)) => Ok(value),
        Ok(_) => Err("Java executor returned non-managed-counter result".to_string()),
        Err(err) => Err(err),
    }
}

unsafe fn collect_executor_field_arg(
    ctx: *mut ffi::JSContext,
    value: JSValue,
    sig: &str,
) -> Result<ExecutorArg, String> {
    match sig.as_bytes().first().copied() {
        Some(b'Z') => Ok(ExecutorArg::Raw(
            value
                .to_bool()
                .map(|v| v as u64)
                .or_else(|| value.to_u64(ctx))
                .unwrap_or(0),
        )),
        Some(b'B') | Some(b'S') | Some(b'I') | Some(b'J') => Ok(ExecutorArg::Raw(value.to_u64(ctx).unwrap_or(0))),
        Some(b'C') => {
            if let Some(s) = value.to_string(ctx) {
                Ok(ExecutorArg::Raw(s.chars().next().map(|c| c as u64).unwrap_or(0)))
            } else {
                Ok(ExecutorArg::Raw(value.to_u64(ctx).unwrap_or(0)))
            }
        }
        Some(b'F') => Ok(ExecutorArg::Raw(
            (value.to_float().unwrap_or(0.0) as f32).to_bits() as u64
        )),
        Some(b'D') => Ok(ExecutorArg::Raw(value.to_float().unwrap_or(0.0).to_bits())),
        Some(b'L') | Some(b'[') => collect_executor_object_arg(ctx, value, sig),
        _ => Ok(ExecutorArg::Raw(0)),
    }
}

unsafe fn executor_value_to_js(ctx: *mut ffi::JSContext, result: ExecutorResult) -> ffi::JSValue {
    match result {
        Ok(ExecutorValue::Undefined) => ffi::qjs_undefined(),
        Ok(ExecutorValue::Null) => ffi::qjs_null(),
        Ok(ExecutorValue::Bool(v)) => JSValue::bool(v).raw(),
        Ok(ExecutorValue::Int(v)) => JSValue::int(v).raw(),
        Ok(ExecutorValue::BigU64(v)) => ffi::JS_NewBigUint64(ctx, v),
        Ok(ExecutorValue::Pointer(v)) => crate::jsapi::ptr::create_native_pointer(ctx, v).raw(),
        Ok(ExecutorValue::Float(v)) => JSValue::float(v).raw(),
        Ok(ExecutorValue::String(v)) => JSValue::string(ctx, &v).raw(),
        Ok(ExecutorValue::Object {
            ptr,
            class_name,
            is_global,
        }) => wrap_executor_object_value(ctx, ptr, &class_name, is_global),
        Ok(ExecutorValue::FieldMeta {
            field_id,
            sig,
            is_static,
            class_name,
            field_offset,
        }) => wrap_executor_field_meta(ctx, field_id, &sig, is_static, &class_name, field_offset),
        Ok(ExecutorValue::InstanceRefs { refs, class_name }) => wrap_executor_instance_refs(ctx, &refs, &class_name),
        Ok(ExecutorValue::Method { .. }) => {
            js_throw_internal_error(ctx, "Java executor returned method resolve to value bridge".to_string())
        }
        Ok(ExecutorValue::Methods(_)) => {
            js_throw_internal_error(ctx, "Java executor returned method list to value bridge".to_string())
        }
        Ok(ExecutorValue::ClassLoaders(loaders)) => wrap_executor_classloaders(ctx, &loaders),
        Ok(ExecutorValue::FindClassWithLoader {
            loader_ptr,
            class_name,
            via,
        }) => wrap_executor_find_class_with_loader(ctx, loader_ptr, &class_name, via),
        Ok(ExecutorValue::FastMethod { .. }) => js_throw_internal_error(
            ctx,
            "Java executor returned fast method resolve to value bridge".to_string(),
        ),
        Ok(ExecutorValue::FastField(_)) => js_throw_internal_error(
            ctx,
            "Java executor returned fast field resolve to value bridge".to_string(),
        ),
        Ok(ExecutorValue::ManagedHookDsl(_)) => js_throw_internal_error(
            ctx,
            "Java executor returned managed hook result to value bridge".to_string(),
        ),
        Ok(ExecutorValue::ManagedDrain(_)) => {
            js_throw_internal_error(ctx, "Java executor returned managed drain to value bridge".to_string())
        }
        Ok(ExecutorValue::CompileResult { .. }) => {
            js_throw_internal_error(ctx, "Java executor returned compile result to value bridge".to_string())
        }
        Ok(ExecutorValue::JitInfo {
            runtime,
            java_vm_offset,
            jit_offset,
            jit_code_cache_offset,
            direct_jit,
            runtime_jit_code_cache,
            direct_get_code_cache,
            found_jit,
            message,
        }) => wrap_executor_jit_info(
            ctx,
            runtime,
            java_vm_offset,
            jit_offset,
            jit_code_cache_offset,
            direct_jit,
            runtime_jit_code_cache,
            direct_get_code_cache,
            found_jit,
            &message,
        ),
        Err(err) => js_throw_internal_error(ctx, err),
    }
}

unsafe fn wrap_executor_jit_info(
    ctx: *mut ffi::JSContext,
    runtime: u64,
    java_vm_offset: u64,
    jit_offset: u64,
    jit_code_cache_offset: u64,
    direct_jit: u64,
    runtime_jit_code_cache: u64,
    direct_get_code_cache: u64,
    found_jit: u64,
    message: &str,
) -> ffi::JSValue {
    let obj = ffi::JS_NewObject(ctx);
    let obj_v = JSValue(obj);
    crate::jsapi::callback_util::set_js_u64_property(ctx, obj, "runtime", runtime);
    crate::jsapi::callback_util::set_js_u64_property(ctx, obj, "javaVmOffset", java_vm_offset);
    crate::jsapi::callback_util::set_js_u64_property(ctx, obj, "jitOffset", jit_offset);
    crate::jsapi::callback_util::set_js_u64_property(ctx, obj, "jitCodeCacheOffset", jit_code_cache_offset);
    crate::jsapi::callback_util::set_js_u64_property(ctx, obj, "directJit", direct_jit);
    crate::jsapi::callback_util::set_js_u64_property(ctx, obj, "runtimeJitCodeCache", runtime_jit_code_cache);
    crate::jsapi::callback_util::set_js_u64_property(ctx, obj, "directGetCodeCache", direct_get_code_cache);
    crate::jsapi::callback_util::set_js_u64_property(ctx, obj, "foundJit", found_jit);
    obj_v.set_property(ctx, "message", JSValue::string(ctx, message));
    obj
}

unsafe fn wrap_executor_classloaders(ctx: *mut ffi::JSContext, loaders: &[ClassLoaderInfo]) -> ffi::JSValue {
    let arr = ffi::JS_NewArray(ctx);
    for (index, loader) in loaders.iter().enumerate() {
        let obj = ffi::JS_NewObject(ctx);
        let obj_val = JSValue(obj);
        obj_val.set_property(ctx, "ptr", JSValue(ffi::JS_NewBigUint64(ctx, loader.ptr)));
        obj_val.set_property(ctx, "source", JSValue::string(ctx, &loader.source));
        obj_val.set_property(ctx, "loaderClassName", JSValue::string(ctx, &loader.loader_class_name));
        obj_val.set_property(ctx, "description", JSValue::string(ctx, &loader.description));
        ffi::JS_SetPropertyUint32(ctx, arr, index as u32, obj);
    }
    arr
}

unsafe fn wrap_executor_find_class_with_loader(
    ctx: *mut ffi::JSContext,
    loader_ptr: u64,
    class_name: &str,
    via: Option<&'static str>,
) -> ffi::JSValue {
    let result = ffi::JS_NewObject(ctx);
    let result_val = JSValue(result);
    result_val.set_property(ctx, "ok", JSValue::bool(via.is_some()));
    result_val.set_property(ctx, "className", JSValue::string(ctx, class_name));
    result_val.set_property(ctx, "loaderPtr", JSValue(ffi::JS_NewBigUint64(ctx, loader_ptr)));
    if let Some(via) = via {
        result_val.set_property(ctx, "via", JSValue::string(ctx, via));
    } else {
        result_val.set_property(ctx, "via", JSValue::null());
    }
    result
}

unsafe fn wrap_executor_object_value(
    ctx: *mut ffi::JSContext,
    raw_ptr: u64,
    class_name: &str,
    is_global: bool,
) -> ffi::JSValue {
    let wrapper = ffi::JS_NewObject(ctx);
    let wrapper_val = JSValue(wrapper);

    let ptr_val = ffi::JS_NewBigUint64(ctx, raw_ptr);
    wrapper_val.set_property(ctx, "__jptr", JSValue(ptr_val));
    wrapper_val.set_property(ctx, "__jclass", JSValue::string(ctx, class_name));
    wrapper_val.set_property(ctx, "__jraw", JSValue::bool(true));
    if is_global {
        wrapper_val.set_property(ctx, "__jglobal", JSValue::bool(true));
    }

    wrapper
}

unsafe fn wrap_executor_field_meta(
    ctx: *mut ffi::JSContext,
    field_id: u64,
    sig: &str,
    is_static: bool,
    class_name: &str,
    field_offset: u32,
) -> ffi::JSValue {
    let obj = ffi::JS_NewObject(ctx);
    let obj_val = JSValue(obj);
    obj_val.set_property(ctx, "id", JSValue(ffi::JS_NewBigUint64(ctx, field_id)));
    obj_val.set_property(ctx, "sig", JSValue::string(ctx, sig));
    obj_val.set_property(ctx, "st", JSValue::bool(is_static));
    obj_val.set_property(ctx, "cls", JSValue::string(ctx, class_name));
    obj_val.set_property(ctx, "off", JSValue::int(field_offset as i32));
    obj
}

unsafe fn wrap_executor_instance_refs(ctx: *mut ffi::JSContext, refs: &[u64], class_name: &str) -> ffi::JSValue {
    let arr = ffi::JS_NewArray(ctx);
    for (idx, raw) in refs.iter().enumerate() {
        if *raw == 0 {
            continue;
        }
        let wrapper = ffi::JS_NewObject(ctx);
        let wrapper_val = JSValue(wrapper);
        wrapper_val.set_property(ctx, "__jptr", JSValue(ffi::JS_NewBigUint64(ctx, *raw)));
        wrapper_val.set_property(ctx, "__jclass", JSValue::string(ctx, class_name));
        wrapper_val.set_property(ctx, "__jglobal", JSValue::bool(true));
        ffi::JS_SetPropertyUint32(ctx, arr, idx as u32, wrapper);
    }
    arr
}
