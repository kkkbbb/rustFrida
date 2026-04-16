//! QuickJS loader module for the agent
//!
//! This module provides JavaScript loading and execution capabilities
//! using the quickjs-hook crate.

#![cfg(feature = "quickjs")]

use crate::vma_name::set_anon_vma_name_raw;
use libc::{munmap, sysconf, MAP_FAILED, _SC_PAGESIZE};

use quickjs_hook::{
    cleanup_engine, cleanup_hook_engine, cleanup_hooks, cleanup_java_hooks, cleanup_wxshadow_patches,
    complete_script, get_or_init_engine, init_hook_engine, load_script, load_script_with_filename,
    set_console_callback, set_qbdi_helper_blob, set_qbdi_output_dir,
};
#[cfg(feature = "qbdi")]
use quickjs_hook::{preload_qbdi_helper, shutdown_qbdi_helper};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use crate::communication::{log_msg, write_stream};

static ENGINE_INITIALIZED: AtomicBool = AtomicBool::new(false);
static HOOK_EXEC_VMA_NAME: &[u8] = b"wwb_hook_exec\0";

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

/// Initialize the QuickJS engine and hook system
pub fn init() -> Result<(), String> {
    if ENGINE_INITIALIZED.load(Ordering::SeqCst) {
        return Err("JS 引擎已初始化".to_string());
    }

    // Allocate executable memory for hooks (64KB), near libart.so for ADRP range
    let libart_hint = find_libart_base().unwrap_or(0);
    let exec_mem = EXEC_MEM
        .get_or_init(|| ExecMemory::new_near(64 * 1024, libart_hint).expect("Failed to allocate executable memory"));

    // Initialize hook engine
    init_hook_engine(exec_mem.as_ptr(), exec_mem.size())?;

    // 注册 recomp handlers
    quickjs_hook::recomp::set_handler(|addr| crate::recompiler::ensure_and_translate(addr));
    quickjs_hook::recomp::set_alloc_slot_handler(|addr| crate::recompiler::alloc_trampoline_slot(addr));
    quickjs_hook::recomp::set_fixup_handler(|trampoline, addr| crate::recompiler::fixup_slot_trampoline(trampoline, addr));
    quickjs_hook::recomp::set_commit_handler(|addr| crate::recompiler::commit_slot_patch(addr));
    quickjs_hook::recomp::set_revert_handler(|addr| crate::recompiler::revert_slot_patch(addr));
    quickjs_hook::recomp::set_install_patch_handler(|addr, bytes| crate::recompiler::install_patch(addr, bytes));
    quickjs_hook::recomp::set_try_revert_handler(|addr| crate::recompiler::try_revert_slot_patch(addr));

    if let Some(output_path) = crate::OUTPUT_PATH.get() {
        set_qbdi_output_dir(output_path.clone());
    }

    // 先设置 console callback，确保引擎初始化期间的日志（如 [jniIds]）能通过 socket 输出
    set_console_callback(|msg| {
        write_stream(format!("[JS] {}", msg).as_bytes());
    });

    // 初始化 JS 引擎（complete_script 依赖它）
    get_or_init_engine()?;

    #[cfg(feature = "qbdi")]
    if let Err(err) = preload_qbdi_helper() {
        if err != "qbdi helper blob not configured" {
            write_stream(format!("[qbdi] preload on jsinit failed: {}", err).as_bytes());
        }
    }

    ENGINE_INITIALIZED.store(true, Ordering::SeqCst);

    Ok(())
}

pub fn install_qbdi_helper(blob: Vec<u8>) {
    set_qbdi_helper_blob(blob);
    #[cfg(feature = "qbdi")]
    if let Err(err) = preload_qbdi_helper() {
        write_stream(format!("[qbdi] preload on helper install failed: {}", err).as_bytes());
    }
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

/// Cleanup QuickJS resources
pub fn cleanup() {
    log_msg("[quickjs] cleanup start\n".to_string());
    ENGINE_INITIALIZED.store(false, Ordering::SeqCst);
    // Unhook Java hooks (restore ArtMethod + OAT inline patches on recomp 页)
    log_msg("[quickjs] cleanup_java_hooks\n".to_string());
    cleanup_java_hooks();
    // Unhook all inline hooks while the JS context (ctx) is still valid
    log_msg("[quickjs] cleanup_hooks\n".to_string());
    cleanup_hooks();
    #[cfg(feature = "qbdi")]
    {
        log_msg("[quickjs] shutdown_qbdi_helper\n".to_string());
        shutdown_qbdi_helper();
    }
    // Destroy JSEngine (JS_FreeContext + JS_FreeRuntime)
    log_msg("[quickjs] cleanup_engine\n".to_string());
    cleanup_engine();
    // Reset hook engine state and free the executable pool metadata
    log_msg("[quickjs] cleanup_hook_engine\n".to_string());
    cleanup_hook_engine();
    // 清理 writeBytes(bytes, 1) 装的 wxshadow patch. 这些不进 hook_engine,
    // 所以 hook_engine_cleanup 看不到, 需要独立的轨迹清理.
    log_msg("[quickjs] cleanup_wxshadow_patches\n".to_string());
    cleanup_wxshadow_patches();
    // 最后释放 recomp 页: prctl release 注销重定向，内核恢复原始页 X 权限。
    // 必须在所有 hook cleanup 之后: OAT patch restore 需要写 recomp 页，
    // hook_engine_cleanup 恢复 slot 原始字节也在 recomp 跳板区。
    // 不 munmap: 其他线程 icache 可能仍有 recomp 页指令。
    crate::recompiler::release_all();
    log_msg("[quickjs] cleanup done\n".to_string());
}
