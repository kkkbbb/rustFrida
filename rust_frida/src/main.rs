#![cfg(all(target_os = "android", target_arch = "aarch64"))]

mod args;
mod communication;
mod http_rpc;
mod injection;
mod logger;
mod proc_mem;
mod process;
mod props;
mod repl;
mod selinux;
mod server;
mod session;
mod spawn;
mod types;

/// 解析 `--rpc-port` 参数为绑定地址：
/// * 纯数字 → `0.0.0.0:<port>`
/// * 带冒号 → 原样使用（例如 `127.0.0.1:9191`）
pub(crate) fn parse_rpc_bind(arg: &str) -> String {
    if arg.contains(':') {
        arg.to_string()
    } else {
        format!("0.0.0.0:{}", arg)
    }
}

use crate::logger::{DIM, RESET};
use args::Args;
use clap::Parser;
#[cfg(feature = "qbdi")]
use communication::send_qbdi_helper;
use communication::{send_command, start_socketpair_handler};
use injection::{inject_via_bootstrapper, watch_and_inject};
use process::find_pid_by_name;
use repl::{build_loadjs_cmd, print_eval_result, print_help, run_js_repl, CommandCompleter};
use rustyline::error::ReadlineError;
use rustyline::Editor;
use session::{Session, SessionManager};
use std::os::unix::io::RawFd;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use types::get_string_table_names;

fn main() {
    // Fix #8: 先解析参数（--help/--version 在此退出），再打印 banner
    let args = Args::parse();
    logger::print_banner();

    // 初始化 verbose 模式
    logger::VERBOSE.store(args.verbose, Ordering::Relaxed);

    // --dump-props: 独立操作，dump 后退出
    if let Some(ref profile_name) = args.dump_props {
        match props::dump_props(profile_name) {
            Ok(()) => std::process::exit(0),
            Err(e) => {
                log_error!("Dump 属性失败: {}", e);
                std::process::exit(1);
            }
        }
    }

    // --set-prop: 独立操作，修改属性后退出
    if let Some(ref set_args) = args.set_prop {
        match props::set_prop(&set_args[0], &set_args[1]) {
            Ok(()) => std::process::exit(0),
            Err(e) => {
                log_error!("设置属性失败: {}", e);
                std::process::exit(1);
            }
        }
    }

    // --del-prop: 独立操作，删除属性后退出
    if let Some(ref del_args) = args.del_prop {
        match props::del_prop(&del_args[0], &del_args[1]) {
            Ok(()) => std::process::exit(0),
            Err(e) => {
                log_error!("删除属性失败: {}", e);
                std::process::exit(1);
            }
        }
    }

    // --repack-props: 独立操作，重排后退出
    if let Some(ref profile_name) = args.repack_props {
        match props::repack_props(profile_name) {
            Ok(()) => std::process::exit(0),
            Err(e) => {
                log_error!("重排失败: {}", e);
                std::process::exit(1);
            }
        }
    }

    // --profile 校验: 仅 --spawn 或 --server 可用
    if args.profile.is_some() && args.spawn.is_none() && !args.server {
        log_error!("--profile 仅在 --spawn 或 --server 模式下可用");
        std::process::exit(1);
    }

    // 属性 profile 预处理
    if let Some(ref profile_name) = args.profile {
        match props::prep_prop_profile(profile_name) {
            Ok(profile_dir) => {
                spawn::set_prop_profile(Some(profile_dir));
            }
            Err(e) => {
                log_error!("属性 profile 预处理失败: {}", e);
                std::process::exit(1);
            }
        }
    }

    // ── Server daemon 模式 ──
    if args.server {
        server::run_server(&args);
        return;
    }

    // ── 以下为 legacy 单 session 模式 ──

    // 解析 --name 到 PID（如果指定）
    let resolved_pid: Option<i32> = if let Some(ref name) = args.name {
        match find_pid_by_name(name) {
            Ok(pid) => {
                log_success!("按名称 '{}' 找到进程 PID: {}", name, pid);
                Some(pid)
            }
            Err(e) => {
                log_error!("{}", e);
                std::process::exit(1);
            }
        }
    } else {
        args.pid
    };

    // 解析字符串覆盖参数（格式：name=value）
    let mut string_overrides = std::collections::HashMap::new();
    let available_names = get_string_table_names();

    for s in &args.strings {
        if let Some((name, value)) = s.split_once('=') {
            if available_names.contains(&name) {
                string_overrides.insert(name.to_string(), value.to_string());
            } else {
                log_warn!("未知的字符串名称 '{}', 可用名称: {}", name, available_names.join(", "));
            }
        } else {
            log_warn!("无效的字符串格式 '{}', 应为 name=value", s);
        }
    }

    // 打印字符串覆盖信息
    if !string_overrides.is_empty() {
        log_info!("字符串覆盖列表 ({} 个):", string_overrides.len());
        for (name, value) in &string_overrides {
            println!("     {} = {}", name, value);
        }
    }

    // 根据参数选择注入方式，返回 (target_pid, host_fd)
    let (target_pid, host_fd): (Option<i32>, RawFd) = if let Some(ref package) = args.spawn {
        // Spawn 模式：注册信号处理函数，确保 Ctrl+C 时还原 Zygote patch
        spawn::register_cleanup_handler();
        // Spawn 模式：注入 Zygote 后启动 App
        match spawn::spawn_and_inject(package, &string_overrides) {
            Ok((pid, fd)) => (Some(pid), fd),
            Err(e) => {
                log_error!("Spawn 注入失败: {}", e);
                spawn::cleanup_zygote_patches();
                std::process::exit(1);
            }
        }
    } else if let Some(so_pattern) = &args.watch_so {
        // 使用 eBPF 监听 SO 加载
        match watch_and_inject(so_pattern, args.timeout, &string_overrides) {
            Ok(fd) => (resolved_pid, fd),
            Err(e) => {
                log_error!("注入失败: {}", e);
                std::process::exit(1);
            }
        }
    } else if let Some(pid) = resolved_pid {
        // 直接附加到指定 PID（来自 --pid 或 --name 解析结果）
        // 注入前 patch SELinux policy，确保目标进程能读写 memfd
        if let Err(e) = crate::selinux::patch_selinux() {
            log_warn!("SELinux patch 失败（非致命）: {}", e);
        }
        match inject_via_bootstrapper(pid, &string_overrides) {
            Ok(fd) => (Some(pid), fd),
            Err(e) => {
                log_error!("注入失败: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        log_error!("必须指定 --pid、--name、--watch-so、--spawn 或 --server");
        std::process::exit(1);
    };

    // 创建 legacy session (id=0)
    let label = if let Some(ref pkg) = args.spawn {
        pkg.clone()
    } else if let Some(ref name) = args.name {
        name.clone()
    } else if let Some(pid) = target_pid {
        format!("PID:{}", pid)
    } else {
        "unknown".to_string()
    };
    let session = Arc::new(Session::new(0, label));
    if let Some(pid) = target_pid {
        session.pid.store(pid, Ordering::Relaxed);
    }

    // 启动 socketpair handler（在 host_fd 上读写）
    let _handle = start_socketpair_handler(host_fd, session.clone());

    // 等待 agent 连接，默认超时 30s（可通过 --connect-timeout 调整）
    {
        log_info!("等待 agent 连接... (最长 {}s)", args.connect_timeout);
        let connected = if args.spawn.is_some() {
            session.wait_connected_with_signal(args.connect_timeout, || spawn::signal_received())
        } else {
            session.wait_connected(args.connect_timeout)
        };

        if args.spawn.is_some() && spawn::signal_received() {
            log_info!("收到终止信号，正在清理...");
            spawn::cleanup_zygote_patches();
            std::process::exit(1);
        }

        if !connected {
            log_error!("等待 agent 连接超时 ({}s)，请检查:", args.connect_timeout);
            if let Some(pid) = target_pid {
                if std::path::Path::new(&format!("/proc/{}/status", pid)).exists() {
                    log_warn!("  目标进程 {} 仍在运行（agent 可能崩溃或未加载）", pid);
                } else {
                    log_warn!("  目标进程 {} 已退出（可能被 OOM 或信号终止）", pid);
                }
            }
            log_warn!("  1. dmesg | grep -i 'deny\\|avc'  （SELinux 拦截？）");
            log_warn!("  2. logcat | grep -E 'FATAL|crash'  （agent 崩溃？）");
            log_warn!("  3. 使用 --verbose 重新运行查看详细注入日志");
            log_warn!("  4. adb logcat | grep rustFrida  （查看 agent 日志）");
            if let Some(pid) = target_pid {
                if args.spawn.is_some() {
                    let _ = spawn::resume_child(pid as u32);
                }
            }
            std::process::exit(1);
        }
    }
    let sender = session.get_sender().unwrap();

    // 传递 verbose 标志给 agent
    if args.verbose {
        let _ = send_command(sender, "__set_verbose__");
    }

    // ── RPC HTTP 服务器（如启用）──
    // legacy 模式只有一个 session (id=0)，用 SessionManager 包一层供 http_rpc 复用
    if let Some(ref rpc_arg) = args.rpc_port {
        let mgr = Arc::new(SessionManager::new());
        mgr.insert_session(session.clone());
        let bind = parse_rpc_bind(rpc_arg);
        if let Err(e) = http_rpc::start(mgr, &bind) {
            log_error!("{}", e);
        }
    }

    #[cfg(feature = "qbdi")]
    {
        if let Err(e) = send_qbdi_helper(sender, crate::injection::QBDI_HELPER_SO.to_vec()) {
            log_error!("发送 QBDI helper 失败: {}", e);
            std::process::exit(1);
        }
    }

    // Spawn 模式: propload → jsinit → loadjs → resume
    if let Some(ref _package) = args.spawn {
        if let Some(pid) = target_pid {
            if spawn::signal_received() {
                log_info!("收到终止信号，正在清理...");
                spawn::cleanup_zygote_patches();
                std::process::exit(1);
            }
            if let Some(script_path) = &args.load_script {
                match std::fs::read_to_string(script_path) {
                    Ok(script) => {
                        log_info!("加载脚本 (子进程暂停中): {}", script_path);
                        session.eval_state.clear();
                        if let Err(e) = send_command(sender, "jsinit") {
                            log_error!("发送 jsinit 失败: {}", e);
                        } else {
                            match session
                                .eval_state
                                .recv_timeout(std::time::Duration::from_secs(10))
                            {
                                None => log_warn!("等待引擎初始化超时"),
                                Some(Err(e)) => log_error!("引擎初始化失败: {}", e),
                                Some(Ok(_)) => {
                                    session.eval_state.clear();
                                    let cmd = build_loadjs_cmd(&script, Some(script_path));
                                    if let Err(e) = send_command(sender, cmd) {
                                        log_error!("发送 loadjs 失败: {}", e);
                                    } else {
                                        print_eval_result(&session, 30);
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        log_error!("读取脚本文件 '{}' 失败: {}", script_path, e);
                    }
                }
            }
            // resume: hook 已就位，恢复子进程
            if let Err(e) = spawn::resume_child(pid as u32) {
                log_error!("恢复子进程失败: {}", e);
            }
        }
    }

    // 非 spawn 模式: --load-script 在 resume 后加载（进程已在运行）
    if args.spawn.is_none() {
        if let Some(script_path) = &args.load_script {
            match std::fs::read_to_string(script_path) {
                Ok(script) => {
                    log_info!("加载脚本: {}", script_path);
                    session.eval_state.clear();
                    if let Err(e) = send_command(sender, "jsinit") {
                        log_error!("发送 jsinit 失败: {}", e);
                    } else {
                        match session
                            .eval_state
                            .recv_timeout(std::time::Duration::from_secs(10))
                        {
                            None => log_warn!("等待引擎初始化超时"),
                            Some(Err(e)) => log_error!("引擎初始化失败: {}", e),
                            Some(Ok(_)) => {
                                session.eval_state.clear();
                                let cmd = build_loadjs_cmd(&script, Some(script_path));
                                if let Err(e) = send_command(sender, cmd) {
                                    log_error!("发送 loadjs 失败: {}", e);
                                } else {
                                    print_eval_result(&session, 30);
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    log_error!("读取脚本文件 '{}' 失败: {}", script_path, e);
                }
            }
        }
    }

    let mut rl = match Editor::new() {
        Ok(e) => e,
        Err(e) => {
            log_error!("初始化行编辑器失败: {}", e);
            std::process::exit(1);
        }
    };
    rl.set_helper(Some(CommandCompleter::new()));
    let _ = rl.load_history(".rustfrida_history");
    println!("  {DIM}输入 help 查看命令，exit 退出{RESET}");

    // 发送 shutdown 到 agent，随后等待 agent 完整清理并主动关闭 socket
    let send_shutdown = |s: &Session| {
        if let Some(sender) = s.get_sender() {
            if let Err(e) = send_command(sender, "shutdown") {
                log_error!("发送 shutdown 失败: {}", e);
            } else {
                log_info!("已发送 shutdown，等待 agent 主动断开连接...");
            }
        }
    };

    loop {
        // 检测 agent 是否已断连（agent 崩溃或目标进程被杀）
        if session.disconnected.load(Ordering::Acquire) {
            log_error!("Agent 连接已断开，请重新注入");
            break;
        }

        // Spawn 模式：检测是否收到终止信号
        if args.spawn.is_some() && spawn::signal_received() {
            log_info!("收到终止信号，正在退出...");
            send_shutdown(&session);
            break;
        }

        match rl.readline("rustfrida> ") {
            Ok(line) => {
                let line = line.trim().to_string();
                if line.is_empty() {
                    continue;
                }
                let _ = rl.add_history_entry(&line);
                if line == "help" {
                    print_help();
                    continue;
                }
                if line == "exit" || line == "quit" {
                    log_info!("退出交互模式");
                    send_shutdown(&session);
                    break;
                }
                if line == "jsrepl" {
                    run_js_repl(&session);
                    continue;
                }
                // 校验 hfl 必须带 <module> <offset> 两个参数
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
                match send_command(sender, &line) {
                    Ok(_) => {}
                    Err(e) => {
                        log_error!("发送命令失败: {}", e);
                        break;
                    }
                }
                if is_eval_cmd {
                    let timeout = if is_recomp { 15 } else { 5 };
                    print_eval_result(&session, timeout);
                }
            }
            Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => {
                log_info!("退出交互模式");
                send_shutdown(&session);
                break;
            }
            Err(e) => {
                log_error!("读取输入失败: {}", e);
                break;
            }
        }
    }

    let _ = rl.save_history(".rustfrida_history");

    // Spawn 模式：退出前还原 Zygote patch
    if args.spawn.is_some() {
        spawn::cleanup_zygote_patches();
    }

    // 等待 agent 断开连接
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !session.disconnected.load(Ordering::Acquire) {
        if std::time::Instant::now() >= deadline {
            log_warn!("等待 agent 断开超时 (5s)，强制退出");
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}
