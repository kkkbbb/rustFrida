use crate::data::TraceBundleMetadata;
use crossbeam_channel::Sender;
use lazy_static::lazy_static;
use qbdi::{VirtualStack, VM};
use std::collections::HashMap;
use std::ffi::{c_char, CStr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Condvar, Mutex, OnceLock};
use std::thread::JoinHandle;

pub(crate) const TRACE_BUNDLE_MAGIC: &[u8; 4] = b"TRB1";
pub(crate) const DYNAMIC_EXEC_CHUNK_SIZE: usize = 1024 * 1024;
pub(crate) const TRACE_MAX_PENDING_BYTES: usize = 1024 * 1024 * 1024;
pub(crate) const TRACE_PROGRESS_EVERY: u64 = 1_000;
pub(crate) const TRACE_CHUNK_SIZE: usize = 1024 * 1024;
pub(crate) const TRACE_SHARDS: usize = 4;

#[derive(Clone, Debug)]
pub(crate) struct ExecMap {
    pub(crate) start: u64,
    pub(crate) end: u64,
    pub(crate) perms: String,
    pub(crate) path: String,
}

pub(crate) struct TraceWriter {
    pub(crate) session_id: u64,
    pub(crate) shard_senders: Vec<Sender<TraceChunk>>,
    pub(crate) dynamic_senders: Vec<Sender<TraceChunk>>,
    pub(crate) joins: Vec<JoinHandle<()>>,
    pub(crate) base: String,
}

pub(crate) struct TraceChunk {
    pub(crate) seq: u64,
    pub(crate) payload: Vec<u8>,
}

pub(crate) struct TraceQueueBudget {
    pub(crate) pending_bytes: Mutex<usize>,
    pub(crate) condvar: Condvar,
}

pub(crate) struct ManagedVm {
    pub(crate) vm: VM,
    pub(crate) stacks: Vec<VirtualStack>,
    pub(crate) trace_callback_ids: Vec<u32>,
}

unsafe impl Send for ManagedVm {}

impl TraceQueueBudget {
    pub(crate) fn reserve(&self, bytes: usize) {
        let mut pending = self.pending_bytes.lock().unwrap_or_else(|e| e.into_inner());
        while *pending != 0 && pending.saturating_add(bytes) > TRACE_MAX_PENDING_BYTES {
            pending = self.condvar.wait(pending).unwrap_or_else(|e| e.into_inner());
        }
        *pending = pending.saturating_add(bytes);
    }

    pub(crate) fn release(&self, bytes: usize) {
        let mut pending = self.pending_bytes.lock().unwrap_or_else(|e| e.into_inner());
        *pending = pending.saturating_sub(bytes);
        self.condvar.notify_all();
    }
}

pub(crate) static TRACE_OUTPUT_DIR: OnceLock<String> = OnceLock::new();
pub(crate) static LAST_ERROR: Mutex<Option<Vec<u8>>> = Mutex::new(None);
pub(crate) static TRACE_BUNDLE_METADATA: Mutex<Option<TraceBundleMetadata>> = Mutex::new(None);
pub(crate) static TRACE_WRITER: Mutex<Option<TraceWriter>> = Mutex::new(None);
pub(crate) static TRACE_FINALIZERS: Mutex<Vec<JoinHandle<()>>> = Mutex::new(Vec::new());
pub(crate) static TRACE_NEXT_SEQ: AtomicU64 = AtomicU64::new(0);
pub(crate) static TRACE_SESSION_SEQ: AtomicU64 = AtomicU64::new(0);
pub(crate) static TRACE_EVENT_COUNT: AtomicU64 = AtomicU64::new(0);
pub(crate) static TRACE_RAW_BYTES: AtomicU64 = AtomicU64::new(0);
pub(crate) static TRACE_CHUNKS_SUBMITTED: AtomicU64 = AtomicU64::new(0);
pub(crate) static TRACE_CHUNKS_DROPPED_FULL: AtomicU64 = AtomicU64::new(0);
pub(crate) static TRACE_CHUNKS_DROPPED_DISCONNECTED: AtomicU64 = AtomicU64::new(0);
pub(crate) static TRACE_BYTES_DROPPED_FULL: AtomicU64 = AtomicU64::new(0);
pub(crate) static TRACE_BYTES_DROPPED_DISCONNECTED: AtomicU64 = AtomicU64::new(0);
pub(crate) static TRACE_DYNAMIC_CHUNKS_SUBMITTED: AtomicU64 = AtomicU64::new(0);
pub(crate) static TRACE_DYNAMIC_CHUNKS_DROPPED_FULL: AtomicU64 = AtomicU64::new(0);
pub(crate) static TRACE_DYNAMIC_CHUNKS_DROPPED_DISCONNECTED: AtomicU64 = AtomicU64::new(0);
pub(crate) static TRACE_DYNAMIC_BYTES_DROPPED_FULL: AtomicU64 = AtomicU64::new(0);
pub(crate) static TRACE_DYNAMIC_BYTES_DROPPED_DISCONNECTED: AtomicU64 = AtomicU64::new(0);
pub(crate) static TRACE_MAX_CHUNK_BYTES: AtomicU64 = AtomicU64::new(0);
pub(crate) static TRACE_TRANSCODE_NS: AtomicU64 = AtomicU64::new(0);
pub(crate) static TRACE_MERGE_NS: AtomicU64 = AtomicU64::new(0);
pub(crate) static TRACE_PUBLISHED_SESSION: AtomicU64 = AtomicU64::new(0);
pub(crate) static TRACE_PUBLISH_LOCK: Mutex<()> = Mutex::new(());
pub(crate) static TRACE_EXECUTED_INSTRUCTIONS: AtomicU64 = AtomicU64::new(0);
pub(crate) static NEXT_VM_HANDLE: AtomicU64 = AtomicU64::new(1);

lazy_static! {
    pub(crate) static ref TRACE_QUEUE_BUDGET: TraceQueueBudget = TraceQueueBudget {
        pending_bytes: Mutex::new(0),
        condvar: Condvar::new(),
    };
    pub(crate) static ref VM_REGISTRY: Mutex<HashMap<u64, ManagedVm>> = Mutex::new(HashMap::new());
    pub(crate) static ref ADDED_DYNAMIC_RANGES: Mutex<std::collections::HashSet<(u64, u64)>> =
        Mutex::new(std::collections::HashSet::new());
    pub(crate) static ref DUMPED_DYNAMIC_RANGES: Mutex<std::collections::HashSet<(u64, u64)>> =
        Mutex::new(std::collections::HashSet::new());
    /// 已添加到 instrumented range 的模块路径集合 (避免重复添加)
    pub(crate) static ref ADDED_MODULES: Mutex<std::collections::HashSet<String>> =
        Mutex::new(std::collections::HashSet::new());
}

pub(crate) fn update_max(atomic: &AtomicU64, value: u64) {
    let mut current = atomic.load(Ordering::Relaxed);
    while value > current {
        match atomic.compare_exchange_weak(current, value, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}

pub(crate) fn reset_trace_stats() {
    TRACE_EVENT_COUNT.store(0, Ordering::Relaxed);
    TRACE_RAW_BYTES.store(0, Ordering::Relaxed);
    TRACE_CHUNKS_SUBMITTED.store(0, Ordering::Relaxed);
    TRACE_CHUNKS_DROPPED_FULL.store(0, Ordering::Relaxed);
    TRACE_CHUNKS_DROPPED_DISCONNECTED.store(0, Ordering::Relaxed);
    TRACE_BYTES_DROPPED_FULL.store(0, Ordering::Relaxed);
    TRACE_BYTES_DROPPED_DISCONNECTED.store(0, Ordering::Relaxed);
    TRACE_DYNAMIC_CHUNKS_SUBMITTED.store(0, Ordering::Relaxed);
    TRACE_DYNAMIC_CHUNKS_DROPPED_FULL.store(0, Ordering::Relaxed);
    TRACE_DYNAMIC_CHUNKS_DROPPED_DISCONNECTED.store(0, Ordering::Relaxed);
    TRACE_DYNAMIC_BYTES_DROPPED_FULL.store(0, Ordering::Relaxed);
    TRACE_DYNAMIC_BYTES_DROPPED_DISCONNECTED.store(0, Ordering::Relaxed);
    TRACE_MAX_CHUNK_BYTES.store(0, Ordering::Relaxed);
    TRACE_TRANSCODE_NS.store(0, Ordering::Relaxed);
    TRACE_MERGE_NS.store(0, Ordering::Relaxed);
    TRACE_EXECUTED_INSTRUCTIONS.store(0, Ordering::Relaxed);
}

pub(crate) fn log_trace_stats(base: &str) {
    helper_log(&format!(
        "[qbdi-helper] trace stats: base={} events={} raw_bytes={} chunks={} dropped_full={} dropped_disconnected={} dropped_full_bytes={} dropped_disconnected_bytes={} dynamic_chunks={} dynamic_dropped_full={} dynamic_dropped_disconnected={} dynamic_dropped_full_bytes={} dynamic_dropped_disconnected_bytes={} max_chunk_bytes={} transcode_ns={} merge_ns={}",
        base,
        TRACE_EVENT_COUNT.load(Ordering::Relaxed),
        TRACE_RAW_BYTES.load(Ordering::Relaxed),
        TRACE_CHUNKS_SUBMITTED.load(Ordering::Relaxed),
        TRACE_CHUNKS_DROPPED_FULL.load(Ordering::Relaxed),
        TRACE_CHUNKS_DROPPED_DISCONNECTED.load(Ordering::Relaxed),
        TRACE_BYTES_DROPPED_FULL.load(Ordering::Relaxed),
        TRACE_BYTES_DROPPED_DISCONNECTED.load(Ordering::Relaxed),
        TRACE_DYNAMIC_CHUNKS_SUBMITTED.load(Ordering::Relaxed),
        TRACE_DYNAMIC_CHUNKS_DROPPED_FULL.load(Ordering::Relaxed),
        TRACE_DYNAMIC_CHUNKS_DROPPED_DISCONNECTED.load(Ordering::Relaxed),
        TRACE_DYNAMIC_BYTES_DROPPED_FULL.load(Ordering::Relaxed),
        TRACE_DYNAMIC_BYTES_DROPPED_DISCONNECTED.load(Ordering::Relaxed),
        TRACE_MAX_CHUNK_BYTES.load(Ordering::Relaxed),
        TRACE_TRANSCODE_NS.load(Ordering::Relaxed),
        TRACE_MERGE_NS.load(Ordering::Relaxed),
    ));
}

pub(crate) fn set_last_error(msg: impl AsRef<str>) {
    let mut buf = msg.as_ref().as_bytes().to_vec();
    if !buf.ends_with(&[0]) {
        buf.push(0);
    }
    *LAST_ERROR.lock().unwrap_or_else(|e| e.into_inner()) = Some(buf);
}

pub(crate) fn clear_last_error() {
    *LAST_ERROR.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

#[no_mangle]
pub extern "C" fn qbdi_trace_last_error() -> *const c_char {
    let guard = LAST_ERROR.lock().unwrap_or_else(|e| e.into_inner());
    match guard.as_ref() {
        Some(buf) => buf.as_ptr() as *const c_char,
        None => std::ptr::null(),
    }
}

pub(crate) fn set_trace_output_dir(path: &str) {
    let _ = TRACE_OUTPUT_DIR.set(path.to_string());
}

pub(crate) fn set_trace_bundle_metadata(module_path: String, module_base: u64) {
    *TRACE_BUNDLE_METADATA.lock().unwrap_or_else(|e| e.into_inner()) = Some(TraceBundleMetadata {
        module_path,
        module_base,
    });
}

pub(crate) fn get_trace_bundle_metadata() -> Option<TraceBundleMetadata> {
    TRACE_BUNDLE_METADATA.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

#[no_mangle]
pub extern "C" fn qbdi_trace_set_bundle_metadata(module_path: *const c_char, module_base: u64) -> i32 {
    clear_last_error();
    if module_path.is_null() {
        set_last_error("module_path is null");
        return -1;
    }
    let module_path = match unsafe { CStr::from_ptr(module_path) }.to_str() {
        Ok(path) if !path.is_empty() => path,
        Ok(_) => {
            set_last_error("empty module_path");
            return -1;
        }
        Err(_) => {
            set_last_error("invalid module_path");
            return -1;
        }
    };
    set_trace_bundle_metadata(module_path.to_string(), module_base);
    0
}

pub(crate) fn helper_log(msg: &str) {
    unsafe {
        extern "C" {
            fn __android_log_write(prio: i32, tag: *const c_char, text: *const c_char) -> i32;
        }
        let tag = b"rustFrida\0";
        let mut buf = msg.as_bytes().to_vec();
        buf.push(0);
        let _ = __android_log_write(4, tag.as_ptr() as *const c_char, buf.as_ptr() as *const c_char);
    }
}

pub(crate) fn with_vm<R>(handle: u64, f: impl FnOnce(&mut ManagedVm) -> Result<R, String>) -> Result<R, String> {
    let mut registry = VM_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    let managed = registry
        .get_mut(&handle)
        .ok_or_else(|| format!("invalid qbdi vm handle {}", handle))?;
    f(managed)
}

pub(crate) fn decode_args<'a>(args_ptr: *const u64, args_len: u32) -> Result<&'a [u64], String> {
    if args_len == 0 {
        Ok(&[][..])
    } else if args_ptr.is_null() {
        Err("args_ptr is null while args_len > 0".to_string())
    } else {
        Ok(unsafe { std::slice::from_raw_parts(args_ptr, args_len as usize) })
    }
}

pub(crate) fn decode_memory_access_type(bits: u32) -> Result<u32, String> {
    match bits {
        x if x == qbdi::ffi::MemoryAccessType_QBDI_MEMORY_READ => Ok(x),
        x if x == qbdi::ffi::MemoryAccessType_QBDI_MEMORY_WRITE => Ok(x),
        x if x == qbdi::ffi::MemoryAccessType_QBDI_MEMORY_READ_WRITE => Ok(x),
        other => Err(format!("invalid memory access type {}", other)),
    }
}
