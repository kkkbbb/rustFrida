/* frida-gum stalker 功能模块 */
#![cfg(feature = "frida-gum")]

use crate::communication::{log_msg, write_stream};
use crate::OUTPUT_PATH;
use crossbeam_channel::{bounded, Sender};
use frida_gum::interceptor::{Interceptor, InvocationContext, InvocationListener, ProbeListener};
use frida_gum::stalker::{Event, EventMask, EventSink, Stalker, Transformer};
use frida_gum::{Gum, ModuleMap, NativePointer, Process};
use lazy_static::lazy_static;
use prost::Message;
use std::cell::UnsafeCell;
use std::collections::HashMap;
use std::ffi::c_void;
use std::ffi::CString;
use std::fs::OpenOptions;
use std::io::Write;
use std::ptr::null_mut;
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;

// Android log priority levels
const ANDROID_LOG_INFO: i32 = 4;

extern "C" {
    fn __android_log_print(prio: i32, tag: *const i8, fmt: *const i8, ...) -> i32;
}

pub fn logcat(msg: &str) {
    let tag = CString::new("rustFrida").unwrap();
    let fmt = CString::new("%s").unwrap();
    let msg_c = CString::new(msg).unwrap_or_else(|_| CString::new("invalid msg").unwrap());
    unsafe {
        __android_log_print(
            ANDROID_LOG_INFO,
            tag.as_ptr() as *const i8,
            fmt.as_ptr() as *const i8,
            msg_c.as_ptr() as *const i8,
        );
    }
}

// 寄存器变化记录（只记录有变化的寄存器）
#[derive(Clone, PartialEq, Message)]
struct RegChange {
    #[prost(uint32, tag = "1")]
    reg_num: u32,
    #[prost(uint64, tag = "2")]
    value: u64,
}

// 原始指令消息（在通道中传输，包含完整寄存器）
#[derive(Clone)]
struct RawInstrMessage {
    addr: u64,
    bytes: Arc<Vec<u8>>,
    module: Arc<String>,
    regs: [u64; 32],
}

// 定义指令跟踪消息（最终写入文件的 protobuf 格式）
#[derive(Clone, PartialEq, Message)]
struct InstrMessage {
    #[prost(uint64, tag = "1")]
    addr: u64,
    #[prost(bytes, tag = "2")]
    bytes: Vec<u8>,
    #[prost(message, repeated, tag = "3")]
    ctx: Vec<RegChange>,
}

define_sync_cell!(StalkerCell, Stalker);
define_sync_cell!(ModuleMapCell, ModuleMap);
define_sync_cell!(InterceptorCell, Interceptor);

static GLOBAL_STALKER: OnceLock<StalkerCell> = OnceLock::new();
static GLOBAL_MODULE_MAP: OnceLock<ModuleMapCell> = OnceLock::new();
static GLOBAL_INTERCEPTOR: OnceLock<InterceptorCell> = OnceLock::new();

// 全局 target 和 original 变量
pub static GLOBAL_TARGET: OnceLock<usize> = OnceLock::new();
pub static GLOBAL_ORIGINAL: OnceLock<usize> = OnceLock::new();

lazy_static! {
    pub static ref GUM: Gum = unsafe { Gum::obtain() };
    static ref BLOCK_COUNT_MAP: Mutex<HashMap<u64, usize>> = Mutex::new(HashMap::new());

    // 创建有界通道
    static ref INSTR_SENDER: Sender<RawInstrMessage> = {
        let (sender, receiver) = bounded::<RawInstrMessage>(100000);

        thread::spawn(move || {
            let log_path = match OUTPUT_PATH.get() {
                Some(base) => format!("{}/trace.pb", base),
                None => {
                    log_msg("错误: OUTPUT_PATH 未设置，无法创建日志文件".to_string());
                    return;
                }
            };

            let mut log_file = match OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_path)
            {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("无法打开日志文件 {}: {}", log_path, e);
                    return;
                }
            };

            while let Ok(raw_msg) = receiver.recv() {
                if let Err(e) = log_file.write_all(&raw_msg.addr.to_le_bytes()) {
                    log_msg(format!("写入日志失败: {}", e));
                }
            }
        });

        sender
    };
}

/// 获取全局 Stalker
#[inline]
pub fn get_stalker() -> &'static mut Stalker {
    let cell = GLOBAL_STALKER.get_or_init(|| StalkerCell(UnsafeCell::new(Stalker::new(&GUM))));
    unsafe { &mut *cell.0.get() }
}

/// 获取全局 Interceptor
#[inline]
pub fn get_interceptor() -> &'static mut Interceptor {
    let cell = GLOBAL_INTERCEPTOR.get_or_init(|| InterceptorCell(UnsafeCell::new(Interceptor::obtain(&GUM))));
    unsafe { &mut *cell.0.get() }
}

/// 获取全局 ModuleMap
#[inline]
fn get_module_map() -> &'static ModuleMap {
    let cell = GLOBAL_MODULE_MAP.get_or_init(|| {
        let mut map = ModuleMap::new();
        map.update();
        ModuleMapCell(UnsafeCell::new(map))
    });
    unsafe { &*cell.0.get() }
}

/// 更新全局 ModuleMap
pub fn update_module_map() {
    let cell = GLOBAL_MODULE_MAP.get_or_init(|| {
        let mut map = ModuleMap::new();
        map.update();
        ModuleMapCell(UnsafeCell::new(map))
    });
    unsafe {
        (*cell.0.get()).update();
    }
    log_msg("ModuleMap 已更新".to_string());
}

struct SampleEventSink;

impl EventSink for SampleEventSink {
    fn query_mask(&mut self) -> EventMask {
        EventMask::None
    }
    fn start(&mut self) {
        println!("start");
    }
    fn process(&mut self, _event: &Event) {
        println!("process");
    }
    fn flush(&mut self) {
        println!("flush");
    }
    fn stop(&mut self) {
        println!("stop");
    }
}

pub fn follow(tid: usize) {
    let mut stalker = Stalker::new(&GUM);

    let transformer = Transformer::from_callback(&GUM, |basic_block, _output| {
        let mdmap = get_module_map();
        let mut module_info: Option<(String, u64, String)> = None;
        let mut should_trace: Option<bool> = None;

        for instr in basic_block {
            let addr = instr.instr().address();

            if module_info.is_none() {
                let (md_path, module_base, module_name) = match mdmap.find(addr) {
                    Some(m) => (
                        m.path().to_string(),
                        m.range().base_address().0 as u64,
                        m.name().to_string(),
                    ),
                    None => ("unknown".to_string(), 0u64, "unknown".to_string()),
                };

                should_trace = Some(
                    !(md_path.contains("apex")
                        || md_path.contains("system")
                        || md_path.contains("unknown")
                        || md_path.contains("memfd")),
                );

                module_info = Some((md_path, module_base, module_name));
            }

            if !should_trace.unwrap() {
                instr.keep();
                continue;
            }

            let (_, module_base, module_name) = module_info.as_ref().unwrap();
            let instr_bytes = instr.instr().bytes();
            let bytes = Arc::new(instr_bytes[0..4].to_vec());
            let md_name = Arc::new(format!("{}+0x{:x}", module_name, addr - module_base));

            unsafe {
                instr.put_callout(move |_cpu_context| {
                    log_msg(format!("{:x}", _cpu_context.pc()));
                });
            }
            instr.keep();
        }
    });

    log_msg(format!("following {}", tid));
    if tid == 0 {
        stalker.follow_me(&transformer, Some(&mut SampleEventSink));
    } else {
        stalker.follow(tid, &transformer, Some(&mut SampleEventSink));
    }
}

struct OpenListener;

impl InvocationListener for OpenListener {
    fn on_enter(&mut self, _context: InvocationContext) {
        log_msg(format!("oopps stalker {}", _context.thread_id()));
    }
    fn on_leave(&mut self, _context: InvocationContext) {
        write_stream(b"end trace");
        get_stalker().deactivate();
    }
}

struct Plistener;

impl ProbeListener for Plistener {
    fn on_hit(&mut self, context: InvocationContext) {
        log_msg("hooked !".to_string());
        follow(context.thread_id() as usize);
    }
}

struct Blistener;

impl ProbeListener for Blistener {
    fn on_hit(&mut self, context: InvocationContext) {
        log_msg("follow stopd!".to_string());
        get_stalker().unfollow(context.thread_id() as usize);
        get_stalker().garbage_collect();
        get_stalker().flush();
    }
}

pub extern "C" fn replacecb(arg1: usize) -> usize {
    log_msg("start !".to_string());
    let original = *GLOBAL_ORIGINAL.get().unwrap();
    let original_fn: extern "C" fn(usize) -> usize = unsafe { std::mem::transmute(original) };
    original_fn(arg1)
}

pub extern "C" fn replacecc() {
    log_msg("stop !".to_string());
    get_stalker().stop();
}

pub fn hfollow(_lib: &str, addr: usize) {
    let target = addr;
    let _ = GLOBAL_TARGET.set(target);
    let mut interceptor = Interceptor::obtain(&GUM);
    log_msg(format!("begin trace {:x}", target));

    match interceptor.replace(
        NativePointer(target as *mut c_void),
        NativePointer(replacecb as *mut c_void),
        NativePointer(null_mut()),
    ) {
        Ok(original) => {
            let _ = GLOBAL_ORIGINAL.set(original.0 as usize);
            log_msg(format!(
                "replace success, original trampoline: {:x}",
                original.0 as usize
            ));
        }
        Err(e) => {
            log_msg(format!("replace failed: {:?}", e));
        }
    }
}
