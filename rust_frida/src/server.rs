#![cfg(all(target_os = "android", target_arch = "aarch64"))]

//! Server daemon 模式：多 session 并发 spawn/inject，--profile 持续生效。
//!
//! 两层 REPL:
//!   server>          — 管理命令 (spawn/attach/list/use/detach/help/exit)
//!   rustfrida#N>     — session 命令 (jsinit/loadjs/jsrepl/..., back 返回)

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use rustyline::completion::{Completer, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::{Context, Editor, Helper};

use crate::args::Args;
use crate::communication::{send_command, start_socketpair_handler};
use crate::injection::inject_via_bootstrapper;
use crate::process::find_pid_by_name;
use crate::repl::{print_eval_result, print_help, run_js_repl};
use crate::session::{Session, SessionManager};
use crate::spawn;
use crate::{log_error, log_info, log_success, log_warn};

// ────────────────────────── Server 命令补全 ──────────────────────────

const SERVER_CMDS: &[(&str, &str, &str)] = &[
    ("spawn", "<package> [-l script.js]", "Spawn 模式注入 App"),
    ("attach", "<pid|name> [-l script.js]", "按 PID 或进程名注入"),
    ("list", "", "列出所有 session"),
    ("sessions", "", "列出所有 session（同 list）"),
    ("use", "<id>", "进入指定 session 的交互模式"),
    ("detach", "<id>", "断开指定 session"),
    ("detachall", "", "断开所有 session"),
    ("help", "", "显示帮助"),
    ("exit", "", "退出 server（quit 同效）"),
];

struct ServerCompleter;

impl Completer for ServerCompleter {
    type Candidate = Pair;
    fn complete(&self, line: &str, pos: usize, _ctx: &Context<'_>) -> rustyline::Result<(usize, Vec<Pair>)> {
        let before = &line[..pos];
        if before.contains(' ') {
            return Ok((pos, vec![]));
        }
        let candidates: Vec<Pair> = SERVER_CMDS
            .iter()
            .filter(|(cmd, _, _)| cmd.starts_with(before))
            .map(|(cmd, _, _)| Pair {
                display: cmd.to_string(),
                replacement: cmd.to_string(),
            })
            .collect();
        Ok((0, candidates))
    }
}
impl Hinter for ServerCompleter {
    type Hint = String;
}
impl Highlighter for ServerCompleter {}
impl Validator for ServerCompleter {}
impl Helper for ServerCompleter {}

// ────────────────────────── Session 命令补全 ──────────────────────────

/// Session 模式补全器：在 CommandCompleter 基础上追加 back 命令
struct SessionModeCompleter;

impl SessionModeCompleter {
    fn new() -> Self {
        SessionModeCompleter
    }
}

impl Completer for SessionModeCompleter {
    type Candidate = Pair;
    fn complete(&self, line: &str, pos: usize, _ctx: &Context<'_>) -> rustyline::Result<(usize, Vec<Pair>)> {
        let before = &line[..pos];
        if before.contains(' ') {
            return Ok((pos, vec![]));
        }
        let extra = ["back", "server"];
        let candidates: Vec<Pair> = crate::repl::commands()
            .iter()
            .map(|(cmd, _, _)| *cmd)
            .chain(extra.iter().copied())
            .filter(|cmd| cmd.starts_with(before))
            .map(|cmd| Pair {
                display: cmd.to_string(),
                replacement: cmd.to_string(),
            })
            .collect();
        Ok((0, candidates))
    }
}
impl Hinter for SessionModeCompleter {
    type Hint = String;
}
impl Highlighter for SessionModeCompleter {}
impl Validator for SessionModeCompleter {}
impl Helper for SessionModeCompleter {}

// ────────────────────────── 辅助函数 ──────────────────────────

/// 解析 spawn/attach 行中的 -l <script> 参数
fn parse_script_flag(parts: &[&str]) -> (Vec<String>, Option<String>) {
    let mut positional = vec![];
    let mut script = None;
    let mut i = 0;
    while i < parts.len() {
        if parts[i] == "-l" && i + 1 < parts.len() {
            script = Some(parts[i + 1].to_string());
            i += 2;
        } else {
            positional.push(parts[i].to_string());
            i += 1;
        }
    }
    (positional, script)
}

/// 在目标进程暂停期间加载脚本（用于 spawn 模式）
fn load_script_on_session(session: &Session, script_path: &str) {
    let sender = match session.get_sender() {
        Some(s) => s,
        None => {
            log_error!("[#{}] agent 未连接，无法加载脚本", session.id);
            return;
        }
    };
    let script = match std::fs::read_to_string(script_path) {
        Ok(s) => s,
        Err(e) => {
            log_error!("[#{}] 读取脚本 '{}' 失败: {}", session.id, script_path, e);
            return;
        }
    };

    // jsinit
    session.eval_state.clear();
    if let Err(e) = send_command(sender, "jsinit") {
        log_error!("[#{}] 发送 jsinit 失败: {}", session.id, e);
        return;
    }
    match session
        .eval_state
        .recv_timeout(std::time::Duration::from_secs(10))
    {
        None => {
            log_warn!("[#{}] 等待引擎初始化超时", session.id);
            return;
        }
        Some(Err(e)) => {
            log_error!("[#{}] 引擎初始化失败: {}", session.id, e);
            return;
        }
        Some(Ok(_)) => {}
    }

    // loadjs
    session.eval_state.clear();
    let cmd = crate::repl::build_loadjs_cmd(&script, Some(script_path));
    if let Err(e) = send_command(sender, cmd) {
        log_error!("[#{}] 发送 loadjs 失败: {}", session.id, e);
        return;
    }
    match session
        .eval_state
        .recv_timeout(std::time::Duration::from_secs(30))
    {
        None => log_warn!("[#{}] 脚本加载超时", session.id),
        Some(Err(e)) => log_error!("[#{}] 脚本执行失败: {}", session.id, e),
        Some(Ok(out)) => {
            if !out.is_empty() {
                log_success!("[#{}] => {}", session.id, out);
            }
        }
    }
}

/// 发送 shutdown 并等待 agent 断连
fn shutdown_session(session: &Session) {
    let sender = match session.get_sender() {
        Some(s) => s,
        None => return,
    };
    if session.disconnected.load(Ordering::Acquire) {
        return;
    }
    let _ = send_command(sender, "shutdown");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    while !session.disconnected.load(Ordering::Acquire) {
        if std::time::Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

// ────────────────────────── 后台 spawn/inject ──────────────────────────

fn do_spawn(
    session: Arc<Session>,
    package: String,
    script: Option<String>,
    string_overrides: HashMap<String, String>,
    verbose: bool,
) {
    let sid = session.id;
    std::thread::spawn(move || {
        // ensure_zymbiote_loaded 内部有幂等保护，并发安全
        match spawn::spawn_and_inject(&package, &string_overrides) {
            Ok((pid, host_fd)) => {
                session.pid.store(pid, Ordering::Relaxed);
                let _handle = start_socketpair_handler(host_fd, session.clone());

                if !session.wait_connected(30) {
                    log_error!("[#{}] 等待 agent 连接超时", sid);
                    session.failed.store(true, Ordering::Release);
                    // 尝试恢复子进程
                    let _ = spawn::resume_child(pid as u32);
                    return;
                }

                // 传递 verbose 标志
                if verbose {
                    if let Some(sender) = session.get_sender() {
                        let _ = send_command(sender, "__set_verbose__");
                    }
                }

                // 在子进程暂停期间加载脚本
                if let Some(ref script_path) = script {
                    load_script_on_session(&session, script_path);
                }

                // resume 子进程
                if let Err(e) = spawn::resume_child(pid as u32) {
                    log_error!("[#{}] 恢复子进程失败: {}", sid, e);
                }

                log_success!("[#{}] {} 已就绪 (PID: {})", sid, package, pid);
            }
            Err(e) => {
                log_error!("[#{}] Spawn {} 失败: {}", sid, package, e);
                session.failed.store(true, Ordering::Release);
            }
        }
    });
}

fn do_attach(
    session: Arc<Session>,
    pid: i32,
    label: String,
    script: Option<String>,
    string_overrides: HashMap<String, String>,
    verbose: bool,
) {
    let sid = session.id;
    std::thread::spawn(move || {
        match inject_via_bootstrapper(pid, &string_overrides) {
            Ok(host_fd) => {
                session.pid.store(pid, Ordering::Relaxed);
                let _handle = start_socketpair_handler(host_fd, session.clone());

                if !session.wait_connected(30) {
                    log_error!("[#{}] 等待 agent 连接超时", sid);
                    session.failed.store(true, Ordering::Release);
                    return;
                }

                if verbose {
                    if let Some(sender) = session.get_sender() {
                        let _ = send_command(sender, "__set_verbose__");
                    }
                }

                // 非 spawn 模式：先连接再加载脚本
                if let Some(ref script_path) = script {
                    load_script_on_session(&session, script_path);
                }

                log_success!("[#{}] {} 已就绪 (PID: {})", sid, label, pid);
            }
            Err(e) => {
                log_error!("[#{}] 注入 {} 失败: {}", sid, label, e);
                session.failed.store(true, Ordering::Release);
            }
        }
    });
}

// ────────────────────────── Session REPL ──────────────────────────

/// 进入 session 交互模式，输入 back 返回 server REPL
/// 返回 true 表示 session 已 exit/shutdown，应从 manager 移除
fn run_session_repl(session: &Arc<Session>) -> bool {
    use crate::logger::{DIM, RESET};

    let mut rl = match Editor::new() {
        Ok(e) => e,
        Err(e) => {
            log_error!("初始化行编辑器失败: {}", e);
            return false;
        }
    };
    rl.set_helper(Some(SessionModeCompleter::new()));

    let label = session.label.lock().unwrap().clone();
    let prompt = format!("rustfrida#{}> ", session.id);
    println!(
        "  {DIM}[#{}] {} (PID: {}) — 输入 back 返回 server, help 查看命令{RESET}",
        session.id,
        label,
        session.pid.load(Ordering::Relaxed)
    );

    let send_shutdown = |s: &Session| {
        if let Some(sender) = s.get_sender() {
            if let Err(e) = send_command(sender, "shutdown") {
                log_error!("发送 shutdown 失败: {}", e);
            } else {
                log_info!("已发送 shutdown，等待 agent 主动断开连接...");
            }
        }
    };

    let mut should_remove = false;

    loop {
        if session.disconnected.load(Ordering::Acquire) {
            log_error!("[#{}] Agent 连接已断开", session.id);
            should_remove = true;
            break;
        }

        match rl.readline(&prompt) {
            Ok(line) => {
                let line = line.trim().to_string();
                if line.is_empty() {
                    continue;
                }
                let _ = rl.add_history_entry(&line);

                if line == "back" || line == "server" {
                    break;
                }
                if line == "help" {
                    print_help();
                    continue;
                }
                if line == "exit" || line == "quit" {
                    log_info!("[#{}] 断开 session", session.id);
                    send_shutdown(session);
                    break;
                }
                if line == "jsrepl" {
                    run_js_repl(session);
                    continue;
                }

                // hfl 参数校验
                {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if matches!(parts.first().copied(), Some("hfl")) && parts.len() < 3 {
                        log_warn!("用法: {} <module> <offset>", parts[0]);
                        continue;
                    }
                }

                let is_recomp = line.starts_with("recomp");
                let is_eval_cmd = line.starts_with("jseval ")
                    || line.starts_with("loadjs ")
                    || line == "jsinit"
                    || line == "jsclean"
                    || is_recomp;

                if is_eval_cmd {
                    session.eval_state.clear();
                }

                let sender = match session.get_sender() {
                    Some(s) => s,
                    None => {
                        log_error!("agent 未连接");
                        should_remove = true;
                        break;
                    }
                };
                match send_command(sender, &line) {
                    Ok(_) => {}
                    Err(e) => {
                        log_error!("发送命令失败: {}", e);
                        should_remove = true;
                        break;
                    }
                }

                if is_eval_cmd {
                    let timeout = if is_recomp { 15 } else { 5 };
                    print_eval_result(session, timeout);
                }
            }
            Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => {
                break;
            }
            Err(e) => {
                log_error!("读取输入失败: {}", e);
                break;
            }
        }
    }

    should_remove
}

// ────────────────────────── Server REPL ──────────────────────────

fn print_server_help() {
    use crate::logger::{BOLD, CYAN, DIM, GREEN, RESET, YELLOW};
    println!("\n{BOLD}{CYAN}Server 命令:{RESET}");
    println!("{DIM}  {:<12} {:<28} {}{RESET}", "命令", "参数", "说明");
    println!("{DIM}  {:-<12} {:-<28} {:-<20}{RESET}", "", "", "");
    for (cmd, args, desc) in SERVER_CMDS {
        println!(
            "  {BOLD}{GREEN}{:<12}{RESET} {YELLOW}{:<28}{RESET} {}",
            cmd, args, desc
        );
    }
    println!();
    println!("{DIM}  进入 session 后可使用全部 agent 命令 (jsinit/loadjs/jsrepl/hook 等){RESET}");
    println!("{DIM}  spawn/attach 在后台运行，可以同时发起多个注入{RESET}");
    println!();
}

fn print_sessions(mgr: &SessionManager) {
    use crate::logger::{BOLD, CYAN, DIM, GREEN, RED, RESET, YELLOW};
    let sessions = mgr.list_sessions();
    if sessions.is_empty() {
        println!("{DIM}  无活跃 session{RESET}");
        return;
    }
    println!("\n{BOLD}{CYAN}Sessions:{RESET}");
    for (id, pid, label, status, active) in &sessions {
        let marker = if *active { " *" } else { "  " };
        let status_color = match *status {
            "connected" => GREEN,
            "connecting" => YELLOW,
            _ => RED,
        };
        println!(
            "{marker} {BOLD}#{:<3}{RESET} {:<30} PID:{:<8} {status_color}[{}]{RESET}",
            id, label, pid, status,
        );
    }
    println!();
}

/// Server daemon 主入口
pub(crate) fn run_server(args: &Args) {
    use crate::logger::{BOLD, CYAN, DIM, RESET};

    let mgr = Arc::new(SessionManager::new());

    // 注册信号处理（Ctrl+C 触发清理）
    spawn::register_cleanup_handler();

    // 收集 string_overrides（全局复用）
    let string_overrides: HashMap<String, String> = {
        let mut map = HashMap::new();
        let available_names = crate::types::get_string_table_names();
        for s in &args.strings {
            if let Some((name, value)) = s.split_once('=') {
                if available_names.contains(&name) {
                    map.insert(name.to_string(), value.to_string());
                } else {
                    log_warn!("未知的字符串名称 '{}', 可用名称: {}", name, available_names.join(", "));
                }
            }
        }
        map
    };

    // 预注入 zygote: daemon 启动即准备好，后续 spawn 不再等待注入
    log_info!("正在预注入 Zygote...");
    match spawn::ensure_zymbiote_loaded() {
        Ok(()) => log_success!("Zygote 预注入完成，spawn 命令将即时生效"),
        Err(e) => log_error!("Zygote 预注入失败: {} (spawn 命令将自动重试)", e),
    }

    // ── RPC HTTP 服务器（如启用）──
    if let Some(ref rpc_arg) = args.rpc_port {
        let bind = crate::parse_rpc_bind(rpc_arg);
        if let Err(e) = crate::http_rpc::start(mgr.clone(), &bind) {
            log_error!("{}", e);
        }
    }

    println!(
        "\n  {BOLD}{CYAN}Server 模式已启动{RESET} {DIM}— 输入 help 查看命令, spawn/attach 开始注入{RESET}"
    );
    if args.profile.is_some() {
        log_info!("属性 profile 已加载，spawn 的进程将自动应用");
    }
    println!();

    let mut rl = match Editor::new() {
        Ok(e) => e,
        Err(e) => {
            log_error!("初始化行编辑器失败: {}", e);
            return;
        }
    };
    rl.set_helper(Some(ServerCompleter));
    let _ = rl.load_history(".rustfrida_server_history");

    loop {
        // 信号检查
        if spawn::signal_received() {
            log_info!("收到终止信号，正在退出...");
            break;
        }

        match rl.readline("server> ") {
            Ok(line) => {
                let line = line.trim().to_string();
                if line.is_empty() {
                    continue;
                }
                let _ = rl.add_history_entry(&line);
                let parts: Vec<&str> = line.split_whitespace().collect();

                match parts[0] {
                    // ── spawn <package> [-l script.js] ──
                    "spawn" => {
                        if parts.len() < 2 {
                            log_warn!("用法: spawn <package> [-l script.js]");
                            continue;
                        }
                        let (positional, script) = parse_script_flag(&parts[1..]);
                        if positional.is_empty() {
                            log_warn!("用法: spawn <package> [-l script.js]");
                            continue;
                        }
                        let package = &positional[0];
                        let session = mgr.create_session(package.clone());
                        log_info!("[#{}] 正在 spawn {}...", session.id, package);
                        do_spawn(
                            session,
                            package.clone(),
                            script,
                            string_overrides.clone(),
                            args.verbose,
                        );
                    }

                    // ── attach <pid|name> [-l script.js] ──
                    "attach" => {
                        if parts.len() < 2 {
                            log_warn!("用法: attach <pid|name> [-l script.js]");
                            continue;
                        }
                        let (positional, script) = parse_script_flag(&parts[1..]);
                        if positional.is_empty() {
                            log_warn!("用法: attach <pid|name> [-l script.js]");
                            continue;
                        }
                        let target = &positional[0];
                        // 自动判断: 纯数字 → PID，否则 → 进程名
                        let (pid, label) = if let Ok(p) = target.parse::<i32>() {
                            (p, format!("PID:{}", p))
                        } else {
                            match find_pid_by_name(target) {
                                Ok(p) => {
                                    log_success!("按名称 '{}' 找到进程 PID: {}", target, p);
                                    (p, target.to_string())
                                }
                                Err(e) => {
                                    log_error!("{}", e);
                                    continue;
                                }
                            }
                        };
                        let session = mgr.create_session(label.clone());
                        log_info!("[#{}] 正在注入 {} (PID: {})...", session.id, label, pid);
                        do_attach(
                            session,
                            pid,
                            label,
                            script,
                            string_overrides.clone(),
                            args.verbose,
                        );
                    }

                    // ── list / sessions ──
                    "list" | "sessions" => {
                        print_sessions(&mgr);
                    }

                    // ── use <id> ──
                    "use" => {
                        if parts.len() < 2 {
                            log_warn!("用法: use <session_id>");
                            continue;
                        }
                        let id = match parts[1].parse::<u32>() {
                            Ok(id) => id,
                            Err(_) => {
                                log_error!("无效的 session ID: {}", parts[1]);
                                continue;
                            }
                        };
                        match mgr.get_session(id) {
                            None => {
                                log_error!("Session #{} 不存在", id);
                            }
                            Some(session) => {
                                if !session.is_connected() {
                                    let status = session.status();
                                    if status == "disconnected" || status == "failed" {
                                        log_warn!("Session #{} 已断开，正在清理", id);
                                        mgr.remove_session(id);
                                    } else {
                                        log_warn!("Session #{} 当前状态: {} — 请等待连接就绪", id, status);
                                    }
                                    continue;
                                }
                                mgr.set_active(Some(id));
                                let should_remove = run_session_repl(&session);
                                mgr.set_active(None);
                                if should_remove {
                                    mgr.remove_session(id);
                                }
                            }
                        }
                    }

                    // ── detach <id> ──
                    "detach" => {
                        if parts.len() < 2 {
                            log_warn!("用法: detach <session_id>");
                            continue;
                        }
                        let id = match parts[1].parse::<u32>() {
                            Ok(id) => id,
                            Err(_) => {
                                log_error!("无效的 session ID: {}", parts[1]);
                                continue;
                            }
                        };
                        match mgr.remove_session(id) {
                            None => {
                                log_error!("Session #{} 不存在", id);
                            }
                            Some(session) => {
                                shutdown_session(&session);
                                log_success!("[#{}] 已断开", id);
                            }
                        }
                    }

                    // ── detachall ──
                    "detachall" => {
                        let sessions = mgr.all_sessions();
                        for session in &sessions {
                            let id = session.id;
                            shutdown_session(session);
                            mgr.remove_session(id);
                            log_success!("[#{}] 已断开", id);
                        }
                    }

                    // ── help ──
                    "help" => {
                        print_server_help();
                    }

                    // ── exit / quit ──
                    "exit" | "quit" => {
                        log_info!("正在退出 server...");
                        break;
                    }

                    other => {
                        log_warn!("未知命令: {} — 输入 help 查看可用命令", other);
                    }
                }
            }
            Err(ReadlineError::Interrupted) => {
                // Ctrl+C: 不立即退出，提示用户
                println!();
                log_info!("按 Ctrl+C 收到中断 — 输入 exit 退出 server");
            }
            Err(ReadlineError::Eof) => {
                log_info!("正在退出 server...");
                break;
            }
            Err(e) => {
                log_error!("读取输入失败: {}", e);
                break;
            }
        }
    }

    let _ = rl.save_history(".rustfrida_server_history");

    // 清理所有 session
    log_info!("清理所有 session...");
    let sessions = mgr.all_sessions();
    for session in &sessions {
        shutdown_session(session);
    }

    // 还原 Zygote patch
    spawn::cleanup_zygote_patches();

    log_success!("Server 已退出");
}
