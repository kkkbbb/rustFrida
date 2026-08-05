#![cfg(all(target_os = "android", target_arch = "aarch64"))]
#![allow(dead_code)]

/// 生成 UnsafeCell 包装结构体，自动实现 Send + Sync。
/// 用于将非 Send/Sync 类型安全地存入 OnceLock 全局变量。
#[cfg(any(feature = "frida-gum", feature = "qbdi"))]
macro_rules! define_sync_cell {
    ($name:ident, $inner:ty) => {
        struct $name(std::cell::UnsafeCell<$inner>);
        unsafe impl Sync for $name {}
        unsafe impl Send for $name {}
    };
}

mod arm64_relocator;
mod communication;
mod crash_handler;
mod exec_mem;
mod gumlibc;
mod linker;
mod pthread_shim;
mod raw_thread;
pub mod recompiler;
pub mod safepoint;
mod trace;
mod vma_name;

#[cfg(feature = "frida-gum")]
mod memory_dump;
#[cfg(feature = "quickjs")]
mod quickjs_loader;
#[cfg(feature = "frida-gum")]
mod stalker;

use crate::communication::{
    flush_cached_logs, is_cmd_frame, is_qbdi_helper_frame, log_msg, log_msg_sync, register_stream_fd, send_bye,
    send_complete, send_eval_err, send_eval_ok, send_hello, send_rpc_err, send_rpc_ok, shutdown_log_writer,
    shutdown_stream, start_log_writer, write_stream, GLOBAL_STREAM,
};
use crate::crash_handler::install_panic_hook;
use libc::{kill, pid_t, SIGSTOP};
use std::ffi::c_void;
use std::os::fd::AsRawFd;
use std::os::unix::io::FromRawFd;
use std::os::unix::net::UnixStream;
use std::process;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::OnceLock;

#[no_mangle]
pub extern "C" fn rust_get_hide_result() -> *const c_void {
    null_mut()
}

// 定义我们自己的Result类型，错误统一为String
type Result<T> = std::result::Result<T, String>;

// StringTable 结构定义（需要和 main.rs 中的定义完全一致）
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct StringTable {
    pub sym_name: u64,
    pub sym_name_len: u32,
    pub dlsym_err: u64,
    pub dlsym_err_len: u32,
    pub cmdline: u64,
    pub cmdline_len: u32,
    pub output_path: u64,
    pub output_path_len: u32,
}

impl StringTable {
    /// 从指针地址读取字符串（不包含末尾的 NULL）
    unsafe fn read_string(&self, addr: u64, len: u32) -> Option<String> {
        if addr == 0 || len == 0 {
            return None;
        }
        let ptr = addr as *const u8;
        let slice = std::slice::from_raw_parts(ptr, len as usize);
        // 去掉末尾的 NULL 字符
        let end = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
        String::from_utf8(slice[..end].to_vec()).ok()
    }

    /// 获取 cmdline
    pub unsafe fn get_cmdline(&self) -> Option<String> {
        self.read_string(self.cmdline, self.cmdline_len)
    }

    /// 获取 output_path
    pub unsafe fn get_output_path(&self) -> Option<String> {
        self.read_string(self.output_path, self.output_path_len)
    }
}

static SHOULD_EXIT: AtomicBool = AtomicBool::new(false);
static SHOULD_DETACH: AtomicBool = AtomicBool::new(false);
pub static OUTPUT_PATH: OnceLock<String> = OnceLock::new();
#[cfg(feature = "quickjs")]
static JS_TASKS_IN_FLIGHT: AtomicUsize = AtomicUsize::new(0);
#[cfg(feature = "quickjs")]
const JS_TASK_UNLOAD_WAIT_MS: u64 = 500;

fn read_exact_raw_fd(fd: i32, buf: &mut [u8]) -> std::io::Result<()> {
    let mut done = 0usize;
    while done < buf.len() {
        let n = unsafe { libc::read(fd, buf[done..].as_mut_ptr() as *mut libc::c_void, buf.len() - done) };
        if n == 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "socket eof"));
        }
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        done += n as usize;
    }
    Ok(())
}

/// 注入参数结构体（与 rust_frida/src/types.rs 和 loader.c 完全一致）
#[repr(C)]
pub struct AgentArgs {
    pub table: u64,       // *const StringTable（目标进程内地址）
    pub ctrl_fd: i32,     // socketpair fd1（agent 端）
    pub agent_memfd: i32, // 目标进程内的 agent.so memfd
}

#[no_mangle]
pub extern "C" fn hello_entry(args_ptr: *mut c_void) -> *mut c_void {
    install_panic_hook();
    SHOULD_EXIT.store(false, Ordering::Relaxed);
    SHOULD_DETACH.store(false, Ordering::Relaxed);
    // Keep native crash handlers disabled for this target.
    // install_crash_handlers();

    // 从 AgentArgs 读取 ctrl_fd 和 StringTable 指针
    let (ctrl_fd, table) = unsafe {
        let args = &*(args_ptr as *const AgentArgs);
        (args.ctrl_fd, &*(args.table as *const StringTable))
    };

    unsafe {
        // 读取 output_path 并保存到全局变量
        if let Some(output) = table.get_output_path() {
            if output != "novalue" {
                let _ = OUTPUT_PATH.set(output.clone());
            }
        }

        // 读取 cmdline 参数
        if let Some(cmd) = table.get_cmdline() {
            if cmd != "novalue" {
                let first = cmd.split_whitespace().next().unwrap_or("");
                if first != "shutdown" && first != "detach" {
                    process_cmd(&cmd);
                }
            }
        }
    }

    // 不设置线程名，保持继承的进程名，避免被安全 SDK 通过 /proc/self/task/*/comm 检测

    // 使用 ctrl_fd（socketpair 的 agent 端），已通过 socketpair 连接到 host
    let sock = unsafe { UnixStream::from_raw_fd(ctrl_fd) };
    let write_half = sock.try_clone().expect("stream clone failed");
    register_stream_fd(&write_half);
    GLOBAL_STREAM.set(std::sync::Mutex::new(write_half)).unwrap();
    // 启动异步日志 writer 线程：write_stream() 只 push channel，此线程通过 GLOBAL_STREAM 写 socket
    start_log_writer();
    send_hello();
    raw_thread::sleep_ms(100);
    flush_cached_logs();

    let reader = sock;
    let reader_fd_for_raw = reader.as_raw_fd();
    loop {
        let mut header = [0u8; 5];
        match read_exact_raw_fd(reader_fd_for_raw, &mut header).and_then(|_| {
            let kind = header[0];
            let len = u32::from_le_bytes([header[1], header[2], header[3], header[4]]) as usize;
            let mut payload = vec![0u8; len];
            read_exact_raw_fd(reader_fd_for_raw, &mut payload)?;
            Ok((kind, payload))
        }) {
            Ok((kind, payload)) => {
                if is_cmd_frame(kind) {
                    if payload.is_empty() {
                        continue;
                    }
                    let cmd = String::from_utf8_lossy(&payload).trim().to_string();
                    if !cmd.is_empty() {
                        process_cmd(&cmd);
                    }
                } else if is_qbdi_helper_frame(kind) {
                    #[cfg(feature = "quickjs")]
                    quickjs_loader::install_qbdi_helper(payload);
                } else {
                    write_stream(format!("未知 frame kind: {}", kind).as_bytes());
                }
                if SHOULD_EXIT.load(Ordering::Relaxed) || SHOULD_DETACH.load(Ordering::Relaxed) {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => {
                // 读取错误
                write_stream(format!("读取命令错误: {}", e).as_bytes());
                break;
            }
        }
    }
    if SHOULD_EXIT.load(Ordering::Relaxed) {
        log_msg_sync("收到 shutdown，开始退出清理\n".to_string());
    } else if SHOULD_DETACH.load(Ordering::Relaxed) {
        log_msg_sync("收到 detach，跳过目标进程内清理，准备关闭 socket\n".to_string());
    }
    if SHOULD_EXIT.load(Ordering::Relaxed) {
        #[cfg(feature = "quickjs")]
        {
            let fast_unload_ok = quickjs_loader::prepare_unload_fast();
            let safe_to_return = if stop_js_worker_for_unload(JS_TASK_UNLOAD_WAIT_MS) {
                cleanup_agent_runtime_for_unload(fast_unload_ok)
            } else {
                log_msg_sync("JS worker 未在 500ms 内退出，保留 agent 驻留以避免卸载仍在执行的代码\n".to_string());
                false
            };
            if !safe_to_return {
                park_agent_after_unsafe_unload();
            }
        }
        #[cfg(not(feature = "quickjs"))]
        {
            let _ = cleanup_agent_runtime_for_unload(true);
        }
    }
    if SHOULD_EXIT.load(Ordering::Relaxed) {
        log_msg_sync("退出清理完成，准备关闭 socket\n".to_string());
    } else if SHOULD_DETACH.load(Ordering::Relaxed) {
        log_msg_sync("detach 完成，准备关闭 socket\n".to_string());
    }
    shutdown_log_writer();
    send_bye();
    // 关闭 socket，host 收到 EOF 自然退出
    let reader_fd = reader.as_raw_fd();
    shutdown_stream();
    unsafe {
        libc::shutdown(reader_fd, libc::SHUT_RD);
        libc::close(reader_fd);
    }
    std::mem::forget(reader);

    null_mut()
}

/// 解析 loadjs 命令的 payload（已去掉 "loadjs " 前缀的部分），
/// 识别可选的 `[filename]\n<script>` 头部，返回 (filename, script)。
///
/// 格式规则:
///   `[name]\n<script>`  → filename = "name"，script = <script>（首行即 line 1）
///   `[name]`            → filename = "name"，script 为空
///   其他               → filename = ""（表示 <eval>），script = 原 payload
///
/// filename 必须不含换行/方括号；否则不识别为 filename。
#[cfg(feature = "quickjs")]
fn parse_loadjs_payload(payload: &str) -> (&str, &str) {
    if !payload.starts_with('[') {
        return ("", payload);
    }
    // 在首行内（遇到 \n 之前）找 `]`
    let first_line_end = payload.find('\n').unwrap_or(payload.len());
    let first_line = &payload[..first_line_end];
    if !first_line.ends_with(']') {
        return ("", payload);
    }
    let filename = &first_line[1..first_line.len() - 1];
    if filename.is_empty() || filename.contains('[') || filename.contains(']') {
        return ("", payload);
    }
    // 跳过分隔的 \n（如果存在）
    let script_start = if first_line_end < payload.len() {
        first_line_end + 1 // skip '\n'
    } else {
        payload.len()
    };
    (filename, &payload[script_start..])
}

/// 执行 JS 脚本并通过 EVAL/EVAL_ERR 协议返回结果。
/// loadjs 和 jseval 共用此逻辑。
///
/// `filename` 用于 QuickJS 报错时显示真实来源文件（如 `script.js:5:12`）。
/// 传空字符串时退化为 `<eval>`。
#[cfg(feature = "quickjs")]
fn eval_and_respond(script: &str, filename: &str, empty_err: &[u8]) {
    if script.is_empty() {
        send_eval_err(std::str::from_utf8(empty_err).unwrap_or("[quickjs] empty script"));
    } else if !quickjs_loader::is_initialized() {
        send_eval_err("[quickjs] JS 引擎未初始化，请先执行 jsinit");
    } else {
        let result = if filename.is_empty() {
            quickjs_loader::execute_script(script)
        } else {
            quickjs_loader::execute_script_with_filename(script, filename)
        };
        match result {
            Ok(result) => send_eval_ok(&result),
            // 错误直接透传（包含 \n 换行），host 侧用 println! 显示多行
            Err(e) => send_eval_err(&e),
        }
    }
}

#[cfg(feature = "quickjs")]
fn eval_on_java_worker_and_respond(script: String, filename: String, init_engine: bool, empty_err: &[u8]) {
    if script.is_empty() {
        send_eval_err(std::str::from_utf8(empty_err).unwrap_or("[quickjs] empty script"));
        return;
    }
    match quickjs_loader::eval_on_java_worker(script, filename, init_engine) {
        Ok(result) => send_eval_ok(&result),
        Err(e) => send_eval_err(&e),
    }
}

#[cfg(feature = "quickjs")]
fn start_java_worker_and_respond() {
    match quickjs_loader::start_java_worker() {
        Ok(()) => send_eval_ok("java-worker-ready"),
        Err(e) => send_eval_err(&format!("java worker start failed: {}", e)),
    }
}

#[cfg(feature = "quickjs")]
fn cut_java_executor_hook_and_respond() {
    match quickjs_loader::cut_java_executor_hook() {
        Ok(true) => send_eval_ok("java-executor-cut"),
        Ok(false) => send_eval_err("java executor hook still active after cut"),
        Err(e) => send_eval_err(&format!("java executor hook cut failed: {}", e)),
    }
}

#[cfg(feature = "quickjs")]
fn init_js_and_respond() {
    match quickjs_loader::init() {
        Ok(_) => send_eval_ok("initialized"),
        Err(e) => send_eval_err(&e),
    }
}

#[cfg(feature = "quickjs")]
fn init_eval_and_respond(script: &str, filename: &str) {
    match quickjs_loader::init() {
        Ok(_) => eval_and_respond(script, filename, b"[quickjs] Error: empty script"),
        Err(ref e) if e.contains("已初始化") => {
            eval_and_respond(script, filename, b"[quickjs] Error: empty script")
        }
        Err(e) => send_eval_err(&e),
    }
}

#[cfg(feature = "quickjs")]
#[no_mangle]
pub extern "C" fn rustfrida_loadjs_current_thread(
    script_ptr: *const u8,
    script_len: usize,
    filename_ptr: *const u8,
    filename_len: usize,
    init_engine: i32,
) -> i32 {
    let result = std::panic::catch_unwind(|| {
        if script_ptr.is_null() && script_len != 0 {
            send_eval_err("[quickjs] remote script pointer is null");
            return -1;
        }
        if filename_ptr.is_null() && filename_len != 0 {
            send_eval_err("[quickjs] remote filename pointer is null");
            return -1;
        }

        let script_bytes = unsafe { std::slice::from_raw_parts(script_ptr, script_len) };
        let filename_bytes = unsafe { std::slice::from_raw_parts(filename_ptr, filename_len) };
        let script = match std::str::from_utf8(script_bytes) {
            Ok(s) => s,
            Err(_) => {
                send_eval_err("[quickjs] script is not valid UTF-8");
                return -1;
            }
        };
        let filename = match std::str::from_utf8(filename_bytes) {
            Ok(s) => s,
            Err(_) => {
                send_eval_err("[quickjs] filename is not valid UTF-8");
                return -1;
            }
        };

        if init_engine != 0 {
            init_eval_and_respond(script, filename);
        } else {
            eval_and_respond(script, filename, b"[quickjs] Error: empty script");
        }
        0
    });

    result.unwrap_or_else(|_| {
        send_eval_err("[quickjs] current-thread eval panicked");
        -1
    })
}

#[cfg(feature = "quickjs")]
fn set_java_stealth_and_respond(mode: i64) {
    match quickjs_hook::jsapi::java::set_host_stealth_mode(mode).map(|m| m.to_string()) {
        Ok(mode) => send_eval_ok(&format!("javastealth={}", mode)),
        Err(e) => send_eval_err(&format!("javastealth failed: {}", e)),
    }
}

#[cfg(feature = "quickjs")]
fn dispatch_js_task<F>(task: F)
where
    F: FnOnce() + Send + 'static,
{
    JS_TASKS_IN_FLIGHT.fetch_add(1, Ordering::AcqRel);
    match raw_thread::spawn_detached(b"wwb-js\0", move || {
        let _raw_clone_js = quickjs_hook::mark_raw_clone_js_thread();
        if let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(task)) {
            let msg = payload
                .downcast_ref::<&str>()
                .copied()
                .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
                .unwrap_or("unknown panic");
            send_eval_err(&format!("[quickjs] JS worker panic: {}", msg));
        }
        JS_TASKS_IN_FLIGHT.fetch_sub(1, Ordering::AcqRel);
    }) {
        Ok(_) => {}
        Err(e) => {
            JS_TASKS_IN_FLIGHT.fetch_sub(1, Ordering::AcqRel);
            send_eval_err(&format!("[quickjs] JS worker 启动失败: {}", e));
        }
    }
}

#[cfg(feature = "quickjs")]
fn stop_js_worker_for_unload(timeout_ms: u64) -> bool {
    let start = std::time::Instant::now();
    while JS_TASKS_IN_FLIGHT.load(Ordering::Acquire) != 0 {
        if start.elapsed() >= std::time::Duration::from_millis(timeout_ms) {
            return false;
        }
        raw_thread::sleep_ms(10);
    }
    true
}

fn cleanup_agent_runtime_for_unload(fast_unload_ok: bool) -> bool {
    let mut safe_to_return = true;
    #[cfg(feature = "quickjs")]
    {
        if !fast_unload_ok {
            log_msg_sync(
                "Java executor hook 未确认切断，跳过目标进程内破坏性清理以避免释放仍可能被 ART 调用的 recomp 页\n"
                    .to_string(),
            );
            return false;
        }
        if quickjs_loader::is_initialized() {
            safe_to_return = quickjs_loader::cleanup_for_unload_leak_safe();
        }
    }
    if safe_to_return {
        crash_handler::uninstall_crash_handlers();
    }
    safe_to_return
}

fn park_agent_after_unsafe_unload() -> ! {
    log_msg_sync("agent 保持驻留：已切断 hook 入口，等待目标进程退出，避免 loader 卸载 agent 本体\n".to_string());
    loop {
        raw_thread::sleep_ms(60_000);
    }
}

fn process_cmd(command: &str) {
    match command.split_whitespace().next() {
        Some("trace") => {
            let tid = command
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            raw_thread::spawn_detached(b"wwb-trace\0", move || {
                match trace::gum_modify_thread(tid) {
                    Ok(pid) => {
                        write_stream(format!("clone success {}", pid).as_bytes());
                    }
                    Err(e) => {
                        write_stream(format!("error: {}", e).as_bytes());
                    }
                }
                unsafe {
                    kill(process::id() as pid_t, SIGSTOP);
                }
            })
            .expect("spawn raw wwb-trace thread");
        }
        #[cfg(feature = "frida-gum")]
        Some("stalker") => {
            let tid = command
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            stalker::follow(tid)
        }
        #[cfg(feature = "frida-gum")]
        Some("hfl") => {
            let mut cmds = command.split_whitespace();
            let md = cmds.nth(1).unwrap();
            let offset = cmds
                .next()
                .and_then(|s| {
                    let s = s.strip_prefix("0x").unwrap_or(s);
                    usize::from_str_radix(s, 16).ok()
                })
                .unwrap_or(0);
            stalker::hfollow(md, offset)
        }
        #[cfg(feature = "quickjs")]
        Some("__set_verbose__") => {
            quickjs_hook::set_verbose(true);
        }
        #[cfg(feature = "quickjs")]
        Some("javastealth") => {
            let mode = command
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse::<i64>().ok())
                .unwrap_or(0);
            dispatch_js_task(move || set_java_stealth_and_respond(mode));
        }
        #[cfg(feature = "quickjs")]
        Some("artinit") => {
            // 预初始化 artController Layer 1+2 (spawn 模式, 进程暂停时调用)
            dispatch_js_task(|| {
                match quickjs_loader::init_hook_runtime()
                    .and_then(|_| quickjs_hook::jsapi::java::pre_init_art_controller())
                {
                    Ok(_) => send_eval_ok("artinit_ok"),
                    Err(e) => send_eval_err(&format!("artinit failed: {}", e)),
                }
            });
        }
        #[cfg(feature = "quickjs")]
        Some("jsinit") => dispatch_js_task(init_js_and_respond),
        #[cfg(feature = "quickjs")]
        Some("loadjs_init") => {
            let rest = command
                .strip_prefix("loadjs_init ")
                .or_else(|| command.strip_prefix("loadjs_init\n"))
                .or_else(|| command.strip_prefix("loadjs_init"))
                .unwrap_or("");
            let (filename, script) = parse_loadjs_payload(rest);
            let filename = filename.to_string();
            let script = script.to_string();
            dispatch_js_task(move || init_eval_and_respond(&script, &filename));
        }
        #[cfg(feature = "quickjs")]
        Some("javaworker_init") => dispatch_js_task(start_java_worker_and_respond),
        #[cfg(feature = "quickjs")]
        Some("javaexecutor_cut") => dispatch_js_task(cut_java_executor_hook_and_respond),
        #[cfg(feature = "quickjs")]
        Some("java_loadjs_init") => {
            let rest = command
                .strip_prefix("java_loadjs_init ")
                .or_else(|| command.strip_prefix("java_loadjs_init\n"))
                .or_else(|| command.strip_prefix("java_loadjs_init"))
                .unwrap_or("");
            let (filename, script) = parse_loadjs_payload(rest);
            eval_on_java_worker_and_respond(
                script.to_string(),
                filename.to_string(),
                true,
                b"[quickjs] Error: empty script",
            );
        }
        #[cfg(feature = "quickjs")]
        Some("java_loadjs") => {
            let rest = command
                .strip_prefix("java_loadjs ")
                .or_else(|| command.strip_prefix("java_loadjs\n"))
                .or_else(|| command.strip_prefix("java_loadjs"))
                .unwrap_or("");
            let (filename, script) = parse_loadjs_payload(rest);
            eval_on_java_worker_and_respond(
                script.to_string(),
                filename.to_string(),
                true,
                b"[quickjs] Error: empty script",
            );
        }
        #[cfg(feature = "quickjs")]
        Some("java_jseval") => {
            let expr = command
                .strip_prefix("java_jseval ")
                .or_else(|| command.strip_prefix("java_jseval"))
                .unwrap_or("")
                .trim()
                .to_string();
            eval_on_java_worker_and_respond(
                expr,
                String::new(),
                true,
                "[quickjs] 用法: jseval <expression>".as_bytes(),
            );
        }
        #[cfg(feature = "quickjs")]
        Some("jsworker_stop") => {
            send_eval_ok("jsworker_not_persistent");
        }
        // javainit: 延迟 JNI 初始化（spawn 模式 resume 后调用）
        // AttachCurrentThread + cache reflect IDs
        #[cfg(feature = "quickjs")]
        Some("javainit") => dispatch_js_task(|| match quickjs_hook::deferred_java_init() {
            Ok(_) => send_eval_ok("java_initialized"),
            Err(e) => send_eval_err(&e),
        }),
        #[cfg(feature = "quickjs")]
        Some("loadjs") => {
            // 支持两种格式:
            //   loadjs <script>                      — 匿名脚本，错误定位 <eval>
            //   loadjs [filename]\n<script>          — 带文件名，错误显示 filename:line:col
            //
            // 注意: 只 strip "loadjs" + 紧跟的一个分隔符（空格或换行），
            // 不做 .trim()，以保留脚本的首行换行，避免 QuickJS 行号偏移。
            let rest = command
                .strip_prefix("loadjs ")
                .or_else(|| command.strip_prefix("loadjs\n"))
                .or_else(|| command.strip_prefix("loadjs"))
                .unwrap_or("");
            let (filename, script) = parse_loadjs_payload(rest);
            let filename = filename.to_string();
            let script = script.to_string();
            if quickjs_loader::is_java_worker_started() {
                eval_on_java_worker_and_respond(script, filename, true, b"[quickjs] Error: empty script");
            } else {
                dispatch_js_task(move || eval_and_respond(&script, &filename, b"[quickjs] Error: empty script"));
            }
        }
        #[cfg(feature = "quickjs")]
        Some("jseval") => {
            // jseval 是 REPL 单行表达式，不支持 filename 前缀
            let expr = command
                .strip_prefix("jseval ")
                .or_else(|| command.strip_prefix("jseval"))
                .unwrap_or("")
                .trim();
            let expr = expr.to_string();
            if quickjs_loader::is_java_worker_started() {
                eval_on_java_worker_and_respond(
                    expr,
                    String::new(),
                    false,
                    "[quickjs] 用法: jseval <expression>".as_bytes(),
                );
            } else {
                dispatch_js_task(move || eval_and_respond(&expr, "", "[quickjs] 用法: jseval <expression>".as_bytes()));
            }
        }
        // rpccall <method> <args_json>
        //   method    — 注册在 rpc.exports 上的函数名
        //   args_json — 参数 JSON 数组字符串，可省略（等价空数组）
        //
        // 回复走独立的 RPC 帧 (FRAME_KIND_RPC_OK/ERR)，与 REPL eval_state 解耦，
        // 避免 HTTP RPC 与交互式命令互相抢占同一个响应通道。
        #[cfg(feature = "quickjs")]
        Some("rpccall") => {
            let rest = command.strip_prefix("rpccall").unwrap_or("").trim_start();
            if rest.is_empty() {
                send_rpc_err("rpccall: 缺少 method 参数");
            } else {
                let rest = rest.to_string();
                dispatch_js_task(move || {
                    if !quickjs_loader::is_initialized() {
                        send_rpc_err("JS 引擎未初始化，请先执行 jsinit");
                    } else {
                        // 第一个空白前为 method，其余为 args_json（可为空）
                        let (method, args_json) = match rest.split_once(char::is_whitespace) {
                            Some((m, a)) => (m, a.trim()),
                            None => (rest.as_str(), ""),
                        };
                        match quickjs_hook::dispatch_rpc(method, args_json) {
                            Ok(result) => send_rpc_ok(&result),
                            Err(e) => send_rpc_err(&e),
                        }
                    }
                });
            }
        }
        #[cfg(feature = "quickjs")]
        Some("managedcounter") => {
            send_eval_ok("managedcounter requires host main-thread bridge");
        }
        #[cfg(feature = "quickjs")]
        Some("jscomplete") => {
            let prefix = command.strip_prefix("jscomplete").unwrap_or("").trim();
            let prefix = prefix.to_string();
            dispatch_js_task(move || {
                let result = quickjs_loader::complete(&prefix);
                send_complete(&result);
            });
        }
        #[cfg(feature = "quickjs")]
        Some("jsclean") if !quickjs_loader::is_initialized() => {
            send_eval_err("[quickjs] JS 引擎未初始化");
        }
        #[cfg(feature = "quickjs")]
        Some("jsclean") => dispatch_js_task(|| {
            if quickjs_loader::cleanup() {
                send_eval_ok("cleaned up");
            } else {
                send_eval_err("[quickjs] cleanup timeout; destructive free/unmap skipped");
            }
        }),
        // jsclean_soft: %reload 专用。完整 unhook + drain=0 + 销毁 runtime，
        // 但保留 art_controller / pool / recomp / wxshadow（同进程 reload 复用）。
        #[cfg(feature = "quickjs")]
        Some("jsclean_soft") if !quickjs_loader::is_initialized() => {
            send_eval_err("[quickjs] JS 引擎未初始化");
        }
        #[cfg(feature = "quickjs")]
        Some("jsclean_soft") => dispatch_js_task(|| {
            if !quickjs_loader::is_initialized() {
                send_eval_err("[quickjs] JS 引擎未初始化");
            } else {
                match quickjs_loader::cleanup_soft() {
                    Ok(_) => send_eval_ok("soft cleaned up"),
                    Err(e) => send_eval_err(&format!("[quickjs] {}", e)),
                }
            }
        }),
        Some("recomp") => {
            let addr_str = command.split_whitespace().nth(1).unwrap_or("");
            let addr_str = addr_str.strip_prefix("0x").unwrap_or(addr_str);
            match usize::from_str_radix(addr_str, 16) {
                Ok(addr) => match recompiler::recompile(addr, 0) {
                    Ok((recomp_base, stats)) => {
                        send_eval_ok(&format!(
                            "recomp 0x{:x} → 0x{:x} (copied={} intra={} reloc={} tramp={})",
                            addr,
                            recomp_base,
                            stats.num_copied,
                            stats.num_intra_page,
                            stats.num_direct_reloc,
                            stats.num_trampolines
                        ));
                    }
                    Err(e) => send_eval_err(&e),
                },
                Err(_) => send_eval_err("用法: recomp 0x<page_addr>"),
            }
        }
        Some("recomp-release") => {
            let addr_str = command.split_whitespace().nth(1).unwrap_or("");
            let addr_str = addr_str.strip_prefix("0x").unwrap_or(addr_str);
            match usize::from_str_radix(addr_str, 16) {
                Ok(addr) => match recompiler::release(addr, 0) {
                    Ok(_) => send_eval_ok("released"),
                    Err(e) => send_eval_err(&e),
                },
                Err(_) => send_eval_err("用法: recomp-release 0x<page_addr>"),
            }
        }
        Some("recomp-dry") => {
            let addr_str = command.split_whitespace().nth(1).unwrap_or("");
            let addr_str = addr_str.strip_prefix("0x").unwrap_or(addr_str);
            match usize::from_str_radix(addr_str, 16) {
                Ok(addr) => match recompiler::dry_run(addr) {
                    Ok(output) => send_eval_ok(&output),
                    Err(e) => send_eval_err(&e),
                },
                Err(_) => send_eval_err("用法: recomp-dry 0x<addr>"),
            }
        }
        Some("recomp-list") => {
            let pages = recompiler::list_pages();
            if pages.is_empty() {
                send_eval_ok("无重编译页");
            } else {
                let mut msg = String::new();
                for (orig, recomp, tramp) in &pages {
                    msg.push_str(&format!("0x{:x} → 0x{:x} (tramp={})\n", orig, recomp, tramp));
                }
                send_eval_ok(&msg);
            }
        }
        // shutdown — 先完整清理并输出日志，最后由 agent 主动关闭 socket
        Some("shutdown") => {
            SHOULD_EXIT.store(true, Ordering::Relaxed);
        }
        Some("detach") => {
            SHOULD_DETACH.store(true, Ordering::Relaxed);
        }
        _ => {
            let cmd_name = command.split_whitespace().next().unwrap_or("(empty)");
            log_msg(format!("无效命令 '{}'，在 REPL 中输入 help 查看可用命令\n", cmd_name));
        }
    }
}
