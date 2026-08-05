//! QuickJS loader module for the agent
//!
//! This module provides JavaScript loading and execution capabilities
//! using the quickjs-hook crate.

#![cfg(feature = "quickjs")]

use crate::vma_name::set_anon_vma_name_raw;
use libc::{munmap, sysconf, MAP_FAILED, _SC_PAGESIZE};

#[cfg(feature = "qbdi")]
use quickjs_hook::shutdown_qbdi_helper;
use quickjs_hook::{
    cleanup_engine, cleanup_wxshadow_patches, complete_script, cut_art_controller_routing_hooks,
    cut_art_controller_walkstack_guards, cut_java_hooks, cut_native_hooks, detach_current_jni_thread,
    drain_thunk_in_flight, free_art_controller_state, free_java_hooks, free_native_hooks, get_or_init_engine,
    init_hook_engine, load_script, load_script_with_filename, set_art_controller_reload_paused, set_console_callback,
    set_qbdi_helper_blob, set_qbdi_output_dir,
};
use std::collections::VecDeque;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::mpsc;
use std::sync::{Condvar, Mutex, OnceLock};

use crate::communication::{log_msg, write_stream};

const JAVA_WORKER_EVAL_TIMEOUT_MS: u64 = 60_000;
const JAVA_WORKER_BUSY_FAST_FAIL_MS: u64 = 500;
const JAVA_WORKER_LOOP_READY_TIMEOUT_MS: u64 = 1_500;

static ENGINE_INITIALIZED: AtomicBool = AtomicBool::new(false);
static HOOK_RUNTIME_INITIALIZED: AtomicBool = AtomicBool::new(false);
static JAVA_WORKER_START_REQUESTED: AtomicBool = AtomicBool::new(false);
static JAVA_WORKER_STARTED: AtomicBool = AtomicBool::new(false);
static JAVA_WORKER_LOOP_ENTERED: AtomicBool = AtomicBool::new(false);
static JAVA_WORKER_LOOP_RUNNING: AtomicBool = AtomicBool::new(false);
static JAVA_WORKER_EVAL_IN_FLIGHT: AtomicBool = AtomicBool::new(false);
static JAVA_WORKER_NATIVE_RELEASED: AtomicBool = AtomicBool::new(false);
static JAVA_WORKER_TID: AtomicI32 = AtomicI32::new(0);
static EXEC_MEM_UNMAPPED: AtomicBool = AtomicBool::new(false);
static JAVA_WORKER_QUEUE: OnceLock<JavaWorkerQueue> = OnceLock::new();
static HOOK_EXEC_VMA_NAME: &[u8] = b"wwb_hook_exec\0";

enum JavaWorkerTask {
    Eval {
        script: String,
        filename: String,
        init_engine: bool,
        reply: mpsc::Sender<Result<String, String>>,
    },
    Stop,
}

struct JavaWorkerQueue {
    tasks: Mutex<VecDeque<JavaWorkerTask>>,
    cv: Condvar,
}

impl JavaWorkerQueue {
    fn get() -> &'static Self {
        JAVA_WORKER_QUEUE.get_or_init(|| Self {
            tasks: Mutex::new(VecDeque::new()),
            cv: Condvar::new(),
        })
    }

    fn push(&self, task: JavaWorkerTask) {
        let mut tasks = self.tasks.lock().unwrap_or_else(|e| e.into_inner());
        tasks.push_back(task);
        self.cv.notify_one();
    }

    fn pop(&self) -> JavaWorkerTask {
        let mut tasks = self.tasks.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            if let Some(task) = tasks.pop_front() {
                return task;
            }
            tasks = self.cv.wait(tasks).unwrap_or_else(|e| e.into_inner());
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ExecPoolRange {
    base: u64,
    size: u64,
}

extern "C" {
    fn hook_engine_get_exec_ranges(out: *mut ExecPoolRange, cap: i32) -> i32;
}

fn hook_engine_exec_ranges() -> Vec<(u64, u64)> {
    let mut ranges = [ExecPoolRange { base: 0, size: 0 }; 128];
    let n = unsafe { hook_engine_get_exec_ranges(ranges.as_mut_ptr(), ranges.len() as i32) };
    if n <= 0 {
        return Vec::new();
    }
    ranges
        .iter()
        .take(n as usize)
        .filter_map(|r| (r.base != 0 && r.size != 0).then_some((r.base, r.size)))
        .collect()
}

fn hook_runtime_initialized() -> bool {
    HOOK_RUNTIME_INITIALIZED.load(Ordering::SeqCst)
}

/// 从 /proc/self/maps 找 libart.so 的 r-xp 基址（用作 mmap hint）
fn find_libart_base() -> Option<usize> {
    let maps = std::fs::read_to_string("/proc/self/maps").ok()?;
    for line in maps.lines() {
        if line.contains("libart.so") && line.contains("r-xp") {
            let addr = line.split('-').next()?;
            return usize::from_str_radix(addr, 16).ok();
        }
    }
    None
}

/// Executable memory for hooks
static EXEC_MEM: OnceLock<ExecMemory> = OnceLock::new();

/// Executable memory region wrapper
struct ExecMemory {
    ptr: *mut u8,
    size: usize,
}

impl ExecMemory {
    /// 调用 C 侧 hook_mmap_near 扫描 maps 空隙分配 nearby RWX 内存。
    /// hint=0 时退化为普通 mmap。
    fn new_near(size: usize, hint: usize) -> Option<Self> {
        let page_size = unsafe { sysconf(_SC_PAGESIZE) as usize };
        let alloc_size = ((size + page_size - 1) / page_size) * page_size;

        extern "C" {
            fn hook_mmap_near(target: *mut std::ffi::c_void, alloc_size: usize) -> *mut std::ffi::c_void;
        }

        let ptr = unsafe { hook_mmap_near(hint as *mut std::ffi::c_void, alloc_size) };

        if ptr == MAP_FAILED as *mut std::ffi::c_void {
            return None;
        }

        match set_anon_vma_name_raw(ptr as *mut u8, alloc_size, HOOK_EXEC_VMA_NAME) {
            Ok(()) => {}
            Err(_) => {}
        }

        Some(ExecMemory {
            ptr: ptr as *mut u8,
            size: alloc_size,
        })
    }

    fn new(size: usize) -> Option<Self> {
        Self::new_near(size, 0)
    }

    fn as_ptr(&self) -> *mut u8 {
        self.ptr
    }

    fn size(&self) -> usize {
        self.size
    }
}

impl Drop for ExecMemory {
    fn drop(&mut self) {
        unsafe {
            munmap(self.ptr as *mut _, self.size);
        }
    }
}

// Safety: ExecMemory is only accessed from the JS thread
unsafe impl Send for ExecMemory {}
unsafe impl Sync for ExecMemory {}

/// Initialize the hook engine and recomp bridge without creating a QuickJS runtime.
///
/// This is needed by spawn-time ART pre-initialization: Java stealth mode must be
/// selected before any ART controller patch is installed.
pub fn init_hook_runtime() -> Result<(), String> {
    if HOOK_RUNTIME_INITIALIZED.load(Ordering::SeqCst) {
        return Ok(());
    }

    // Allocate executable memory for hooks (64KB), near libart.so for ADRP range
    let libart_hint = find_libart_base().unwrap_or(0);
    let exec_mem = EXEC_MEM
        .get_or_init(|| ExecMemory::new_near(64 * 1024, libart_hint).expect("Failed to allocate executable memory"));

    // Initialize hook engine
    init_hook_engine(exec_mem.as_ptr(), exec_mem.size())?;

    // 注册 recomp handlers
    quickjs_hook::recomp::set_handler(|addr| crate::recompiler::ensure_and_translate(addr));
    quickjs_hook::recomp::set_translate_existing_handler(|addr| crate::recompiler::translate_addr(addr).ok());
    quickjs_hook::recomp::set_alloc_slot_handler(|addr| crate::recompiler::alloc_trampoline_slot(addr));
    quickjs_hook::recomp::set_fixup_handler(|trampoline, addr| {
        crate::recompiler::fixup_slot_trampoline(trampoline, addr)
    });
    quickjs_hook::recomp::set_commit_handler(|addr| crate::recompiler::commit_slot_patch(addr));
    quickjs_hook::recomp::set_revert_handler(|addr| crate::recompiler::revert_slot_patch(addr));
    quickjs_hook::recomp::set_install_patch_handler(|addr, bytes| crate::recompiler::install_patch(addr, bytes));
    quickjs_hook::recomp::set_try_revert_handler(|addr| crate::recompiler::try_revert_slot_patch(addr));
    quickjs_hook::recomp::set_try_revert_slot_handler(|slot| crate::recompiler::try_revert_slot_patch_by_slot(slot));
    quickjs_hook::recomp::set_reverse_translate_handler(|addr| crate::recompiler::translate_recomp_to_orig(addr));
    quickjs_hook::recomp::set_patch_suspend_polls_handler(|addr, entry| {
        crate::recompiler::patch_suspend_polls(addr, entry)
    });

    HOOK_RUNTIME_INITIALIZED.store(true, Ordering::SeqCst);
    Ok(())
}

/// Initialize the QuickJS engine and hook system
pub fn init() -> Result<(), String> {
    if ENGINE_INITIALIZED.load(Ordering::SeqCst) {
        return Err("JS 引擎已初始化".to_string());
    }

    quickjs_hook::recomp::set_cleanup_release_only(false);
    init_hook_runtime()?;

    if let Some(output_path) = crate::OUTPUT_PATH.get() {
        set_qbdi_output_dir(output_path.clone());
    }

    // 先设置 console callback，确保引擎初始化期间的日志（如 [jniIds]）能通过 socket 输出
    set_console_callback(|msg| {
        write_stream(format!("[JS] {}", msg).as_bytes());
    });

    // 初始化 JS 引擎（complete_script 依赖它）
    get_or_init_engine()?;

    ENGINE_INITIALIZED.store(true, Ordering::SeqCst);

    Ok(())
}

unsafe extern "C" fn java_worker_native_loop(
    _env: *mut *const *const std::ffi::c_void,
    _cls: *mut std::ffi::c_void,
) -> u8 {
    JAVA_WORKER_TID.store(libc::syscall(libc::SYS_gettid) as i32, Ordering::Release);
    JAVA_WORKER_LOOP_ENTERED.store(true, Ordering::Release);
    JAVA_WORKER_LOOP_RUNNING.store(true, Ordering::Release);
    let result = std::panic::catch_unwind(|| match JavaWorkerQueue::get().pop() {
        JavaWorkerTask::Eval {
            script,
            filename,
            init_engine,
            reply,
        } => {
            let result = run_eval_task(&script, &filename, init_engine);
            JAVA_WORKER_EVAL_IN_FLIGHT.store(false, Ordering::Release);
            let _ = reply.send(result);
            true
        }
        JavaWorkerTask::Stop => {
            let released = unsafe { quickjs_hook::finish_java_worker_thread_from_native(_env, _cls) };
            match released {
                Ok(()) => {
                    JAVA_WORKER_NATIVE_RELEASED.store(true, Ordering::Release);
                }
                Err(err) => {
                    write_stream(format!("[java worker] native release failed: {}", err).as_bytes());
                }
            }
            false
        }
    });
    match result {
        Ok(true) => 1,
        Ok(false) => {
            JAVA_WORKER_EVAL_IN_FLIGHT.store(false, Ordering::Release);
            JAVA_WORKER_LOOP_RUNNING.store(false, Ordering::Release);
            0
        }
        Err(_) => {
            write_stream(b"[java worker] native loop panic");
            JAVA_WORKER_EVAL_IN_FLIGHT.store(false, Ordering::Release);
            JAVA_WORKER_LOOP_RUNNING.store(false, Ordering::Release);
            0
        }
    }
}

fn run_eval_task(script: &str, filename: &str, init_engine: bool) -> Result<String, String> {
    if init_engine {
        match init() {
            Ok(()) => {}
            Err(e) if e.contains("已初始化") => {}
            Err(e) => return Err(e),
        }
    }

    if filename.is_empty() {
        execute_script(script)
    } else {
        execute_script_with_filename(script, filename)
    }
}

fn wait_java_worker_loop_entered(timeout_ms: u64) -> bool {
    let start = std::time::Instant::now();
    loop {
        if JAVA_WORKER_LOOP_ENTERED.load(Ordering::Acquire) && JAVA_WORKER_LOOP_RUNNING.load(Ordering::Acquire) {
            return true;
        }
        if start.elapsed() >= std::time::Duration::from_millis(timeout_ms) {
            return false;
        }
        crate::raw_thread::sleep_ms(5);
    }
}

pub fn start_java_worker() -> Result<(), String> {
    if JAVA_WORKER_STARTED.load(Ordering::Acquire) {
        if JAVA_WORKER_LOOP_RUNNING.load(Ordering::Acquire) {
            return Ok(());
        }
        return Err("java worker thread exists but native loop is not running".to_string());
    }
    init_hook_runtime()?;
    set_console_callback(|msg| {
        write_stream(format!("[JS] {}", msg).as_bytes());
    });
    write_stream(b"[java worker] starting");
    JAVA_WORKER_LOOP_ENTERED.store(false, Ordering::Release);
    JAVA_WORKER_NATIVE_RELEASED.store(false, Ordering::Release);
    JAVA_WORKER_TID.store(0, Ordering::Release);
    JAVA_WORKER_START_REQUESTED.store(true, Ordering::Release);
    if let Err(err) = quickjs_hook::start_java_worker_thread(java_worker_native_loop as *mut std::ffi::c_void) {
        JAVA_WORKER_START_REQUESTED.store(false, Ordering::Release);
        return Err(err);
    }
    JAVA_WORKER_STARTED.store(true, Ordering::Release);
    if !wait_java_worker_loop_entered(JAVA_WORKER_LOOP_READY_TIMEOUT_MS) {
        JAVA_WORKER_START_REQUESTED.store(false, Ordering::Release);
        JAVA_WORKER_STARTED.store(false, Ordering::Release);
        return Err(format!(
            "java worker native loop did not enter within {}ms",
            JAVA_WORKER_LOOP_READY_TIMEOUT_MS
        ));
    }
    write_stream(b"[java worker] ready");
    Ok(())
}

pub fn cut_java_executor_hook() -> Result<bool, String> {
    let cut = quickjs_hook::abort_raw_clone_java_executor_for_unload();
    if !cut {
        return Err("raw-clone Java executor hook cut failed".to_string());
    }
    Ok(!quickjs_hook::raw_clone_java_executor_hook_active())
}

pub fn is_java_worker_started() -> bool {
    JAVA_WORKER_STARTED.load(Ordering::Acquire)
}

pub fn stop_java_worker() -> bool {
    let requested = JAVA_WORKER_START_REQUESTED.swap(false, Ordering::AcqRel);
    let started = JAVA_WORKER_STARTED.swap(false, Ordering::AcqRel);
    if requested || started {
        JavaWorkerQueue::get().push(JavaWorkerTask::Stop);
    }
    requested || started
}

fn wait_java_worker_stopped(had_worker: bool, timeout_ms: u64) -> bool {
    if !had_worker {
        return true;
    }
    let started = std::time::Instant::now();
    loop {
        let tid = JAVA_WORKER_TID.load(Ordering::Acquire);
        let thread_exists = tid > 0 && unsafe { libc::syscall(libc::SYS_tgkill, libc::getpid(), tid, 0) } == 0;
        if JAVA_WORKER_LOOP_ENTERED.load(Ordering::Acquire)
            && !JAVA_WORKER_LOOP_RUNNING.load(Ordering::Acquire)
            && !thread_exists
        {
            break;
        }
        if started.elapsed() >= std::time::Duration::from_millis(timeout_ms) {
            return false;
        }
        crate::raw_thread::sleep_ms(5);
    }

    if !JAVA_WORKER_NATIVE_RELEASED.load(Ordering::Acquire) {
        write_stream(b"[java worker] native binding was not removed before thread exit");
        return false;
    }
    JAVA_WORKER_TID.store(0, Ordering::Release);
    JAVA_WORKER_LOOP_RUNNING.store(false, Ordering::Release);
    true
}

pub fn eval_on_java_worker(script: String, filename: String, init_engine: bool) -> Result<String, String> {
    start_java_worker()?;
    if !JAVA_WORKER_LOOP_RUNNING.load(Ordering::Acquire) {
        return Err("Java worker loop is not running".to_string());
    }
    let queue = JavaWorkerQueue::get();
    if JAVA_WORKER_EVAL_IN_FLIGHT
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err("Java worker busy: previous Java eval is still running".to_string());
    }
    let (tx, rx) = mpsc::channel();
    queue.push(JavaWorkerTask::Eval {
        script,
        filename,
        init_engine,
        reply: tx,
    });
    let timeout_ms = if init_engine {
        JAVA_WORKER_EVAL_TIMEOUT_MS
    } else {
        JAVA_WORKER_BUSY_FAST_FAIL_MS
    };
    rx.recv_timeout(std::time::Duration::from_millis(timeout_ms))
        .map_err(|e| {
            if matches!(e, mpsc::RecvTimeoutError::Disconnected) {
                JAVA_WORKER_EVAL_IN_FLIGHT.store(false, Ordering::Release);
            }
            format!(
                "java worker eval timed out after {}ms or channel closed: {}; task remains in-flight until worker returns",
                timeout_ms, e
            )
        })?
}

pub fn install_qbdi_helper(blob: Vec<u8>) {
    set_qbdi_helper_blob(blob);
}

/// Load and execute a JavaScript script
pub fn execute_script(script: &str) -> Result<String, String> {
    if !ENGINE_INITIALIZED.load(Ordering::SeqCst) {
        return Err("JS 引擎未初始化，请先执行 jsinit".to_string());
    }

    load_script(script)
}

/// Load + execute 指定源文件名的脚本（错误信息会显示 `filename:line:col`）
pub fn execute_script_with_filename(script: &str, filename: &str) -> Result<String, String> {
    if !ENGINE_INITIALIZED.load(Ordering::SeqCst) {
        return Err("JS 引擎未初始化，请先执行 jsinit".to_string());
    }

    load_script_with_filename(script, filename)
}

/// Get tab-completion candidates for the given prefix from the live JS engine.
pub fn complete(prefix: &str) -> String {
    if !ENGINE_INITIALIZED.load(Ordering::SeqCst) {
        return String::new();
    }
    let candidates = complete_script(prefix);
    candidates.join("\t")
}

/// 检查 JS 引擎是否已初始化
pub fn is_initialized() -> bool {
    ENGINE_INITIALIZED.load(Ordering::SeqCst)
}

/// Cleanup QuickJS resources — 4 阶段编排
///
/// Phase 1: **切断所有 hook 入口** (Java + Native + OAT inline)。之后 g_thunk_in_flight 只减不增。
/// Phase 2: **drain g_thunk_in_flight → 0**。归零表示无线程在 thunk 或 callee 中。
/// Phase 3: **注销 recomp + 全线程 safepoint**。确认活动栈不再引用生成代码。
/// Phase 4: **释放资源 + hook_engine cleanup + munmap pool/recomp 页**。
pub fn cleanup() -> bool {
    use std::time::Instant;
    let t0 = Instant::now();
    let mut t = t0;
    let stage = |label: &str, prev: &mut Instant| {
        let now = Instant::now();
        let delta = now.duration_since(*prev).as_millis();
        let total = now.duration_since(t0).as_millis();
        log_msg(format!("[quickjs] {} (+{}ms, total {}ms)\n", label, delta, total));
        *prev = now;
    };

    stage("cleanup start", &mut t);
    let had_java_worker = stop_java_worker();
    if !wait_java_worker_stopped(had_java_worker, 800) {
        log_msg("[quickjs] Java worker native loop still running; destructive cleanup skipped\n".to_string());
        detach_current_jni_thread();
        stage("cleanup detach_jni_thread", &mut t);
        return false;
    }
    ENGINE_INITIALIZED.store(false, Ordering::SeqCst);
    quickjs_hook::recomp::set_cleanup_release_only(false);
    if quickjs_hook::raw_clone_java_executor_hook_active() {
        let executor_cut = quickjs_hook::abort_raw_clone_java_executor_for_unload();
        if !executor_cut || quickjs_hook::raw_clone_java_executor_hook_active() {
            log_msg("[quickjs] raw-clone Java executor hook still active; destructive cleanup skipped\n".to_string());
            detach_current_jni_thread();
            stage("cleanup detach_jni_thread", &mut t);
            return false;
        }
        stage("phase0 cut_raw_clone_executor", &mut t);
    }

    // ============================================================
    // Phase 1: 切断所有 "入口 / 路由" hook，阻止新 thunk 进入。
    //   - Java per-method inline patch (Layer 3)
    //   - Native hook (export 入口)
    //   - art_controller 路由: Layer1 (shared stub) / Layer2 (DoCall) / GC 同步 / Fixup
    //
    //   **刻意保留** walkstack 防护 (OAT header hook / PrettyMethod / 内联 OAT patch) ——
    //   它们只影响 ART 看到 thunk frame 时会不会 abort，与路由无关。
    //   必须等 drain=0 (栈上无任何 thunk PC) 后才能拆。
    // ============================================================
    cut_java_hooks();
    stage("phase1 cut_java_hooks", &mut t);
    cut_native_hooks();
    stage("phase1 cut_native_hooks", &mut t);
    cut_art_controller_routing_hooks();
    stage("phase1 cut_art_controller_routing", &mut t);

    // ============================================================
    // Phase 2: drain g_thunk_in_flight → 0
    //   归零 → 无 in-flight thunk → 栈上不可能再有 thunk LR
    //   → OAT bypass 可以安全卸载
    //   → pool 可以安全 munmap
    // ============================================================
    let drained = drain_thunk_in_flight();
    stage("phase2 drain_thunk_in_flight", &mut t);
    if !drained {
        log_msg(format!(
            "[quickjs] drain timeout: keep hook resources and executable memory mapped; destructive cleanup skipped (total {}ms)\n",
            t0.elapsed().as_millis()
        ));
        detach_current_jni_thread();
        stage("cleanup detach_jni_thread", &mut t);
        return false;
    }

    // ============================================================
    // Phase 3: 切断 walkstack guard，再停止新 recomp 执行，并等待所有线程活动栈离开 hook/recomp 地址。
    //
    // drain=0 只说明没有线程仍在 thunk 中执行；ART quick 栈上仍可能保留
    // generated return PC，后续 Throwable/ANR/GC StackVisitor 还会读到它。
    // 因此必须在拆 walkstack guards 和 munmap 前做全线程栈 safepoint。
    // ============================================================
    cut_art_controller_walkstack_guards();
    stage("phase3 cut_art_controller_walkstack_guards", &mut t);
    quickjs_hook::recomp::set_cleanup_release_only(true);
    crate::recompiler::release_all();
    stage("phase3 release_all_recomp", &mut t);

    let mut protected_ranges = hook_engine_exec_ranges();
    let retained_recomp_ranges = crate::recompiler::get_retained_ranges();
    // Java router/replacement execution is covered by g_thunk_in_flight before
    // we reach this safepoint. Scanning every thread's live stack from a signal
    // handler is too invasive for apps with crash/anti-debug components, so only
    // enable full stack scanning when recomp pages are retained.
    let scan_stack_for_art_frames = !retained_recomp_ranges.is_empty();
    protected_ranges.extend(retained_recomp_ranges);
    if !protected_ranges.is_empty() {
        log_msg(format!(
            "[quickjs] safepoint protected ranges={}, mode={}\n",
            protected_ranges.len(),
            if scan_stack_for_art_frames {
                "pc/lr/stack"
            } else {
                "pc/lr"
            }
        ));
    }
    const CLEANUP_SAFEPOINT_BUDGET_MS: u64 = 2_500;
    let stack_clean = if scan_stack_for_art_frames {
        crate::safepoint::wait_until_clean(&protected_ranges, CLEANUP_SAFEPOINT_BUDGET_MS)
    } else {
        crate::safepoint::wait_until_pc_lr_clean(&protected_ranges, CLEANUP_SAFEPOINT_BUDGET_MS)
    };
    stage("phase3 safepoint_stack_clean", &mut t);
    if !stack_clean {
        log_msg(
            "[quickjs] safepoint timeout: keep walkstack guards and executable memory mapped; destructive cleanup skipped\n"
                .to_string(),
        );
        detach_current_jni_thread();
        stage("cleanup detach_jni_thread", &mut t);
        return false;
    }

    // ============================================================
    // Phase 4: 释放资源 + 同步释放 pool/recomp
    // ============================================================
    free_art_controller_state();
    stage("phase4 free_art_controller_state", &mut t);
    free_java_hooks();
    stage("phase4 free_java_hooks", &mut t);
    free_native_hooks();
    stage("phase4 free_native_hooks", &mut t);
    #[cfg(feature = "qbdi")]
    {
        shutdown_qbdi_helper();
        stage("phase4 shutdown_qbdi_helper", &mut t);
    }
    detach_current_jni_thread();
    stage("phase4 detach_jni_thread", &mut t);
    cleanup_engine();
    stage("phase4 cleanup_engine", &mut t);
    cleanup_wxshadow_patches();
    stage("phase4 cleanup_wxshadow_patches", &mut t);
    let (recomp_ok, recomp_fail, recomp_bytes) = unsafe { crate::recompiler::munmap_retained_ranges() };
    if recomp_ok + recomp_fail > 0 {
        log_msg(format!(
            "[quickjs] munmap recomp: ok={} fail={} bytes={}\n",
            recomp_ok, recomp_fail, recomp_bytes
        ));
    }
    unsafe {
        quickjs_hook::ffi::hook::hook_engine_munmap_pools_direct();
    }
    stage("phase4 munmap_pools_direct", &mut t);

    log_msg(format!(
        "[quickjs] cleanup done (total {}ms)\n",
        t0.elapsed().as_millis()
    ));
    true
}

// 注：full cleanup 在 callback/exec 两套计数都归零后同步 munmap hook pool/recomp 页。

fn munmap_initial_exec_mem_for_unload() {
    if EXEC_MEM_UNMAPPED.swap(true, Ordering::AcqRel) {
        return;
    }
    let Some(exec_mem) = EXEC_MEM.get() else {
        return;
    };
    unsafe {
        let ret = munmap(exec_mem.ptr as *mut _, exec_mem.size);
        if ret == 0 {
            log_msg(format!("[quickjs] munmap initial hook exec: bytes={}\n", exec_mem.size));
        } else {
            log_msg(format!(
                "[quickjs] munmap initial hook exec failed: {}\n",
                std::io::Error::last_os_error()
            ));
        }
    }
}

pub fn cleanup_for_unload() {
    if cleanup() {
        munmap_initial_exec_mem_for_unload();
    } else {
        log_msg("[quickjs] unload cleanup retained initial executable memory after timeout\n".to_string());
    }
}

pub fn prepare_unload_fast() -> bool {
    if !hook_runtime_initialized() {
        return true;
    }

    let executor_cut = quickjs_hook::abort_raw_clone_java_executor_for_unload();
    if !executor_cut {
        log_msg("[quickjs] raw-clone Java executor hook cut failed; keep executable memory mapped\n".to_string());
        return false;
    }

    !quickjs_hook::raw_clone_java_executor_hook_active()
}

/// Agent unload path for hot managed hooks.
///
/// Cut hook entry points, wait until callback/thunk/managed-helper counters all
/// drain to zero, then free JS-facing resources. The loader unmaps the agent
/// image after this returns, so ART guards whose callbacks live in the agent
/// must be removed here instead of being retained in libsigchain/hook_engine.
pub fn cleanup_for_unload_leak_safe() -> bool {
    use std::time::Instant;
    let t0 = Instant::now();
    let mut t = t0;
    let stage = |label: &str, prev: &mut Instant| {
        let now = Instant::now();
        let delta = now.duration_since(*prev).as_millis();
        let total = now.duration_since(t0).as_millis();
        log_msg(format!("[quickjs] {} (+{}ms, total {}ms)\n", label, delta, total));
        *prev = now;
    };

    stage("cleanup start (managed-safe unload)", &mut t);
    ENGINE_INITIALIZED.store(false, Ordering::SeqCst);
    quickjs_hook::recomp::set_cleanup_release_only(false);
    if quickjs_hook::raw_clone_java_executor_hook_active() {
        let executor_cut = quickjs_hook::abort_raw_clone_java_executor_for_unload();
        if !executor_cut || quickjs_hook::raw_clone_java_executor_hook_active() {
            log_msg(
                "[quickjs] raw-clone Java executor hook still active; managed-safe unload cleanup skipped\n"
                    .to_string(),
            );
            detach_current_jni_thread();
            stage("cleanup detach_jni_thread", &mut t);
            return false;
        }
        stage("phase0 cut_raw_clone_executor", &mut t);
    }

    cut_java_hooks();
    stage("phase1 cut_java_hooks", &mut t);
    cut_native_hooks();
    stage("phase1 cut_native_hooks", &mut t);
    cut_art_controller_routing_hooks();
    stage("phase1 cut_art_controller_routing", &mut t);

    let drained = drain_thunk_in_flight();
    stage("phase2 drain_thunk_in_flight", &mut t);
    if !drained {
        log_msg(format!(
            "[quickjs] managed-safe unload drain timeout: keep hook resources and walkstack guards; destructive cleanup skipped (total {}ms)\n",
            t0.elapsed().as_millis()
        ));
        detach_current_jni_thread();
        stage("cleanup detach_jni_thread", &mut t);
        return false;
    }

    // Stop the Java worker only after hook entry points are cut and all managed
    // helper invocations have drained. Its final JNI call unregisters every
    // generated helper native before the agent image can be unmapped.
    let had_java_worker = stop_java_worker();
    if wait_java_worker_stopped(had_java_worker, 800) {
        stage("phase2 stop_java_worker", &mut t);
    } else {
        stage("phase2 stop_java_worker_timeout", &mut t);
        log_msg(
            "[quickjs] Java worker native loop still running; skip managed-safe unload to avoid unmapping agent code\n"
                .to_string(),
        );
        detach_current_jni_thread();
        stage("cleanup detach_jni_thread", &mut t);
        return false;
    }

    cut_art_controller_walkstack_guards();
    stage("phase3 cut_art_controller_walkstack_guards", &mut t);
    quickjs_hook::recomp::set_cleanup_release_only(true);
    crate::recompiler::release_all();
    stage("phase3 release_all_recomp", &mut t);

    let retained_recomp_ranges = crate::recompiler::get_retained_ranges();
    if !retained_recomp_ranges.is_empty() {
        log_msg(format!(
            "[quickjs] managed-safe retaining inactive recomp ranges={}\n",
            retained_recomp_ranges.len()
        ));
        // release_all() has already restored the original execution mapping.
        // Keep the now-inactive recomp pages mapped for this leak-safe unload:
        // probing every app thread with an RT signal is incompatible with apps
        // that own the same signal or install crash/anti-debug handlers.
        stage("phase3 retained_recomp_mapped", &mut t);
    }

    free_art_controller_state();
    stage("phase3 free_art_controller_state", &mut t);

    free_java_hooks();
    stage("phase3 free_java_hooks", &mut t);
    free_native_hooks();
    stage("phase3 free_native_hooks", &mut t);
    #[cfg(feature = "qbdi")]
    {
        shutdown_qbdi_helper();
        stage("phase3 shutdown_qbdi_helper", &mut t);
    }
    detach_current_jni_thread();
    stage("phase3 detach_jni_thread", &mut t);
    cleanup_engine();
    stage("phase3 cleanup_engine", &mut t);

    log_msg(format!(
        "[quickjs] cleanup done (managed-safe unload, executable pools retained, walkstack guards removed, total {}ms)\n",
        t0.elapsed().as_millis()
    ));
    true
}

/// **软清理**：完整 unhook + drain=0 + 销毁 runtime，保留 hook 基础设施和 RWX 内存。
///
/// `%reload` 使用。与 full `cleanup()` 相同的 hook 释放路径（drain=0 原子不变量保持），
/// 但刻意保留 art_controller / pool / recomp 页 / wxshadow —— 这些内存可能仍被 ART
/// 内部的 ArtMethod 拷贝 / class copy / OAT 缓存引用。full cleanup 的 munmap 只在
/// agent 退出（地址永不复用）时安全；同进程 reload 必须保留。
///
/// 做：
/// - Phase 1: `cut_java_hooks` + `cut_native_hooks`（per-hook wxshadow/recomp-B 反转在这里）
/// - Phase 2: `drain_thunk_in_flight` → 0
/// - Phase 3: `free_java_hooks` + `free_native_hooks` + `cleanup_engine`
///
/// 保留：art_controller routing + walkstack guards + hook pools + recomp 页 + wxshadow。
///
/// drain 超时：拒绝 free，返回 Err，调用方中止 reload。
pub fn cleanup_soft() -> Result<(), String> {
    use std::time::Instant;

    if !ENGINE_INITIALIZED.load(Ordering::SeqCst) {
        return Err("JS 引擎未初始化".to_string());
    }

    let t0 = Instant::now();
    let mut t = t0;
    let stage = |label: &str, prev: &mut Instant| {
        let now = Instant::now();
        let delta = now.duration_since(*prev).as_millis();
        let total = now.duration_since(t0).as_millis();
        log_msg(format!("[quickjs-soft] {} (+{}ms, total {}ms)\n", label, delta, total));
        *prev = now;
    };

    stage("soft cleanup start", &mut t);
    quickjs_hook::recomp::set_cleanup_release_only(false);
    set_art_controller_reload_paused(true);
    stage("phase0 pause_art_controller_reload", &mut t);

    // Phase 1: 切 JS 侧入口（保留 art_controller routing / walkstack guards）
    cut_java_hooks();
    stage("phase1 cut_java_hooks", &mut t);
    cut_native_hooks();
    stage("phase1 cut_native_hooks", &mut t);

    // Phase 2: drain thunk —— 必须归零才能安全 free callback JSValue
    let drained = drain_thunk_in_flight();
    stage("phase2 drain_thunk_in_flight", &mut t);

    if !drained {
        set_art_controller_reload_paused(false);
        log_msg(format!(
            "[quickjs-soft] drain 未归零：保留 hook 资源 (leak 到进程退出). \
             拒绝降级 (会让醒来的线程 UAF JS callback). total {}ms\n",
            t0.elapsed().as_millis()
        ));
        detach_current_jni_thread();
        stage("soft cleanup detach_jni_thread", &mut t);
        return Err("drain timeout，软清理已放弃".to_string());
    }

    // Phase 3: 完整 free JS hook 资源 + 销毁 runtime
    free_java_hooks();
    stage("phase3 free_java_hooks", &mut t);
    free_native_hooks();
    stage("phase3 free_native_hooks", &mut t);
    set_art_controller_reload_paused(false);
    stage("phase3 resume_art_controller_reload", &mut t);
    detach_current_jni_thread();
    stage("phase3 detach_jni_thread", &mut t);
    ENGINE_INITIALIZED.store(false, Ordering::SeqCst);
    cleanup_engine();
    stage("phase3 cleanup_engine", &mut t);

    log_msg(format!(
        "[quickjs-soft] soft cleanup done (total {}ms) — art_controller + pool + recomp 保留\n",
        t0.elapsed().as_millis()
    ));
    Ok(())
}
