#![cfg(all(target_os = "android", target_arch = "aarch64"))]

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
pub mod recompiler;
mod trace;
mod vma_name;

#[cfg(feature = "frida-gum")]
mod memory_dump;
#[cfg(feature = "quickjs")]
mod quickjs_loader;
#[cfg(feature = "frida-gum")]
mod stalker;

use crate::communication::{
    flush_cached_logs, is_cmd_frame, is_qbdi_helper_frame, log_msg, read_frame, register_stream_fd, send_complete,
    send_eval_err, send_eval_ok, send_hello, send_rpc_err, send_rpc_ok, shutdown_stream, start_log_writer,
    write_stream, GLOBAL_STREAM,
};
use crate::crash_handler::{install_crash_handlers, install_panic_hook};
use libc::{kill, pid_t, SIGSTOP};
use std::ffi::c_void;
use std::os::unix::io::FromRawFd;
use std::os::unix::net::UnixStream;
use std::process;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use std::time::Duration;

// hide_soinfo.c 中的调试结果函数（.init_array 构造函数填充）
// 通过 Rust #[no_mangle] 重导出到动态符号表，供 host 端 dlsym 查询
extern "C" {
    fn get_hide_result() -> *const c_void;
}

#[no_mangle]
pub extern "C" fn rust_get_hide_result() -> *const c_void {
    unsafe { get_hide_result() }
}

// 定义我们自己的Result类型，错误统一为String
type Result<T> = std::result::Result<T, String>;

// StringTable 结构定义（需要和 main.rs 中的定义完全一致）
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct StringTable {
    pub sym_name: u64,
    pub sym_name_len: u32,
    pub pthread_err: u64,
    pub pthread_err_len: u32,
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
pub static OUTPUT_PATH: OnceLock<String> = OnceLock::new();

/// 注入参数结构体（与 rust_frida/src/types.rs 和 loader.c 完全一致）
#[repr(C)]
pub struct AgentArgs {
    pub table: u64,       // *const StringTable（目标进程内地址）
    pub ctrl_fd: i32,     // socketpair fd1（agent 端）
    pub agent_memfd: i32, // 目标进程内的 agent.so memfd
}

#[no_mangle]
pub extern "C" fn hello_entry(args_ptr: *mut c_void) -> *mut c_void {
    // 安装Rust panic hook（需要在最前面，捕获Rust层面的panic）
    install_panic_hook();
    install_crash_handlers();

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
                process_cmd(&cmd);
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
    std::thread::sleep(Duration::from_millis(100));
    flush_cached_logs();

    let mut reader = sock;
    loop {
        match read_frame(&mut reader) {
            Ok((kind, payload)) => {
                if is_cmd_frame(kind) {
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
                if SHOULD_EXIT.load(Ordering::Relaxed) {
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
    // 关闭 socket，host 收到 EOF 自然退出
    shutdown_stream();
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

fn process_cmd(command: &str) {
    match command.split_whitespace().next() {
        Some("trace") => {
            let tid = command
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            std::thread::spawn(move || {
                match trace::gum_modify_thread(tid) {
                    Ok(pid) => {
                        write_stream(format!("clone success {}", pid).as_bytes());
                    }
                    Err(e) => {
                        write_stream(format!("error: {}", e).as_bytes());
                    }
                }
                unsafe { kill(process::id() as pid_t, SIGSTOP) }
            });
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
        Some("artinit") => {
            // 预初始化 artController Layer 1+2 (spawn 模式, 进程暂停时调用)
            match quickjs_hook::jsapi::java::pre_init_art_controller() {
                Ok(_) => send_eval_ok("artinit_ok"),
                Err(e) => send_eval_err(&format!("artinit failed: {}", e)),
            }
        }
        #[cfg(feature = "quickjs")]
        Some("jsinit") => match quickjs_loader::init() {
            Ok(_) => send_eval_ok("initialized"),
            Err(e) => send_eval_err(&e),
        },
        // javainit: 延迟 JNI 初始化（spawn 模式 resume 后调用）
        // AttachCurrentThread + cache reflect IDs
        #[cfg(feature = "quickjs")]
        Some("javainit") => match quickjs_hook::deferred_java_init() {
            Ok(_) => send_eval_ok("java_initialized"),
            Err(e) => send_eval_err(&e),
        },
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
            eval_and_respond(script, filename, b"[quickjs] Error: empty script");
        }
        #[cfg(feature = "quickjs")]
        Some("jseval") => {
            // jseval 是 REPL 单行表达式，不支持 filename 前缀
            let expr = command
                .strip_prefix("jseval ")
                .or_else(|| command.strip_prefix("jseval"))
                .unwrap_or("")
                .trim();
            eval_and_respond(expr, "", "[quickjs] 用法: jseval <expression>".as_bytes());
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
            } else if !quickjs_loader::is_initialized() {
                send_rpc_err("JS 引擎未初始化，请先执行 jsinit");
            } else {
                // 第一个空白前为 method，其余为 args_json（可为空）
                let (method, args_json) = match rest.split_once(char::is_whitespace) {
                    Some((m, a)) => (m, a.trim()),
                    None => (rest, ""),
                };
                match quickjs_hook::dispatch_rpc(method, args_json) {
                    Ok(result) => send_rpc_ok(&result),
                    Err(e) => send_rpc_err(&e),
                }
            }
        }
        #[cfg(feature = "quickjs")]
        Some("jscomplete") => {
            let prefix = command.strip_prefix("jscomplete").unwrap_or("").trim();
            let result = quickjs_loader::complete(prefix);
            send_complete(&result);
        }
        #[cfg(feature = "quickjs")]
        Some("jsclean") => {
            if !quickjs_loader::is_initialized() {
                send_eval_err("[quickjs] JS 引擎未初始化");
            } else {
                quickjs_loader::cleanup();
                send_eval_ok("cleaned up");
            }
        }
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
            log_msg("收到 shutdown，开始退出清理\n".to_string());
            #[cfg(feature = "quickjs")]
            if quickjs_loader::is_initialized() {
                quickjs_loader::cleanup();
            }
            // 关键: 在 agent SO 被 dlclose 之前恢复旧信号处理器，
            // 否则 sigaction 表中的 handler 指针指向已卸载的内存，
            // 进程触发任何信号(如 ART 隐式 null check)即崩溃
            crash_handler::uninstall_crash_handlers();
            log_msg("退出清理完成，准备关闭 socket\n".to_string());
            SHOULD_EXIT.store(true, Ordering::Relaxed);
        }
        _ => {
            let cmd_name = command.split_whitespace().next().unwrap_or("(empty)");
            log_msg(format!("无效命令 '{}'，在 REPL 中输入 help 查看可用命令\n", cmd_name));
        }
    }
}
