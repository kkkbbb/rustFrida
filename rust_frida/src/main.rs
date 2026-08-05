#![cfg(all(target_os = "android", target_arch = "aarch64"))]

mod args;
mod communication;
mod http_rpc;
mod injection;
mod logger;
mod proc_mem;
mod process;
mod props;
mod remote_agent;
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
use injection::{inject_via_bootstrapper, InjectionResult};
#[cfg(feature = "ldmonitor")]
use injection::watch_and_inject;
use nix::sys::ptrace;
use nix::unistd::Pid;
use process::{attach_to_process, call_target_function, find_pid_by_name};
use repl::{
    ensure_java_worker_ready_after_resume, load_script_file, load_script_file_pre_resume, print_eval_result,
    print_help, rewrite_jseval_for_agent, run_js_repl, script_uses_java_api, try_jseval_on_main_thread_if_java_or_dsl,
    try_loadjs_on_main_thread_if_java, try_managedcounter_on_main_thread, CommandCompleter, EVAL_DEFAULT_TIMEOUT_SECS,
    EVAL_JAVA_TIMEOUT_SECS, EVAL_RECOMP_TIMEOUT_SECS,
};
use rustyline::error::ReadlineError;
use rustyline::Editor;
use session::{Session, SessionManager};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use types::get_string_table_names;

const AGENT_SHUTDOWN_WAIT_SECS: u64 = 1;

fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes"))
        .unwrap_or(false)
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(default)
}

fn wait_process_alive(pid: i32, seconds: u64, label: &str) -> bool {
    for elapsed in 0..seconds {
        if !std::path::Path::new(&format!("/proc/{}/status", pid)).exists() {
            log_warn!("{}: 进程 {} 在 {}s 后退出", label, pid, elapsed);
            return false;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    let alive = std::path::Path::new(&format!("/proc/{}/status", pid)).exists();
    if alive {
        log_success!("{}: 进程 {} 存活 {}s", label, pid, seconds);
    } else {
        log_warn!("{}: 进程 {} 在检查结束时已退出", label, pid);
    }
    alive
}

fn set_current_thread_name(name: &'static [u8]) {
    unsafe {
        let _ = libc::prctl(libc::PR_SET_NAME, name.as_ptr(), 0, 0, 0);
    }
}

fn cleanup_remote_loader_mappings(pid: i32, injection: &InjectionResult) {
    if pid <= 0 || injection.libc_munmap == 0 {
        return;
    }
    let mut ranges = Vec::new();
    if injection.loader_stack != 0 && injection.loader_stack_size != 0 {
        ranges.push(("loader stack", injection.loader_stack, injection.loader_stack_size));
    }
    if injection.loader_alloc_base != 0 && injection.loader_alloc_size != 0 {
        ranges.push((
            "loader mapping",
            injection.loader_alloc_base,
            injection.loader_alloc_size,
        ));
    }
    if ranges.is_empty() {
        return;
    }
    if !std::path::Path::new(&format!("/proc/{}/status", pid)).exists() {
        return;
    }

    let tid = injection::choose_injection_thread(pid);
    if let Err(e) = attach_to_process(tid) {
        log_warn!("loader 残留清理跳过: attach tid={} 失败: {}", tid, e);
        return;
    }
    for (label, base, size) in ranges {
        match call_target_function(
            tid,
            injection.libc_munmap as usize,
            &[base as usize, size as usize],
            None,
        ) {
            Ok(ret) if ret == 0 => log_verbose!("已清理 {}: 0x{:x}+0x{:x}", label, base, size),
            Ok(ret) => log_verbose!("清理 {} 返回 {}: 0x{:x}+0x{:x}", label, ret, base, size),
            Err(e) => log_warn!("清理 {} 失败: {}", label, e),
        }
    }
    let _ = ptrace::detach(Pid::from_raw(tid), None);
    unsafe {
        libc::kill(pid, libc::SIGCONT);
    }
}

fn main() {
    set_current_thread_name(b"wwb-rfmain\0");

    // Fix #8: 先解析参数（--help/--version 在此退出），再打印 banner
    let args = Args::parse();

    // 初始化 verbose 模式
    logger::VERBOSE.store(args.verbose, Ordering::Relaxed);
    if let Some(ref path) = args.output {
        if let Err(e) = logger::init_output_file(path) {
            eprintln!("初始化日志文件 '{}' 失败: {}", path, e);
            std::process::exit(1);
        }
    }

    logger::print_banner();

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

    if let Some(ref package) = args.spawn {
        if env_flag("RF_DIAG_ZYM_PASSIVE_SETARGV0") {
            spawn::register_cleanup_handler();
            match spawn::spawn_passive_setargv0_launch(package) {
                Ok(pid) => {
                    let hold_secs = env_u64("RF_DIAG_HOLD_SECS", 20);
                    wait_process_alive(pid as i32, hold_secs, "RF_DIAG_ZYM_PASSIVE_SETARGV0");
                    spawn::cleanup_zygote_patches();
                    return;
                }
                Err(e) => {
                    log_error!("Passive setArgV0 诊断失败: {}", e);
                    spawn::cleanup_zygote_patches();
                    std::process::exit(1);
                }
            }
        }

        if env_flag("RF_DIAG_SPAWN_ONLY") {
            spawn::register_cleanup_handler();
            match spawn::spawn_only_and_resume(package) {
                Ok(pid) => {
                    let hold_secs = env_u64("RF_DIAG_HOLD_SECS", 20);
                    wait_process_alive(pid as i32, hold_secs, "RF_DIAG_SPAWN_ONLY");
                    spawn::cleanup_zygote_patches();
                    return;
                }
                Err(e) => {
                    log_error!("Spawn-only 诊断失败: {}", e);
                    spawn::cleanup_zygote_patches();
                    std::process::exit(1);
                }
            }
        }
    }

    // 根据参数选择注入方式，返回 (target_pid, host_fd)
    let (target_pid, injection): (Option<i32>, InjectionResult) = if let Some(ref package) = args.spawn {
        // Spawn 模式：注册信号处理函数，确保 Ctrl+C 时还原 Zygote patch
        spawn::register_cleanup_handler();
        // Spawn 模式：注入 Zygote 后启动 App
        match spawn::spawn_and_inject(package, &string_overrides) {
            Ok((pid, result)) => (Some(pid), result),
            Err(e) => {
                log_error!("Spawn 注入失败: {}", e);
                spawn::cleanup_zygote_patches();
                std::process::exit(1);
            }
        }
    } else if let Some(_so_pattern) = &args.watch_so {
        #[cfg(feature = "ldmonitor")]
        {
            // 使用 eBPF 监听 SO 加载
            if let Err(e) = crate::selinux::patch_selinux() {
                log_warn!("SELinux patch 失败（非致命）: {}", e);
            }
            match watch_and_inject(_so_pattern, args.timeout, &string_overrides) {
                Ok(result) => (Some(result.target_pid), result),
                Err(e) => {
                    log_error!("注入失败: {}", e);
                    std::process::exit(1);
                }
            }
        }
        #[cfg(not(feature = "ldmonitor"))]
        {
            log_error!("--watch-so 需要启用 ldmonitor feature，请使用 cargo build -p rust_frida --release --features ldmonitor");
            std::process::exit(1);
        }
    } else if let Some(pid) = resolved_pid {
        // 直接附加到指定 PID（来自 --pid 或 --name 解析结果）
        // 注入前 patch SELinux policy，确保目标进程能读写 memfd
        if let Err(e) = crate::selinux::patch_selinux() {
            log_warn!("SELinux patch 失败（非致命）: {}", e);
        }
        match inject_via_bootstrapper(pid, &string_overrides) {
            Ok(result) => (Some(pid), result),
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
    session.set_remote_agent_info(injection.loader_ctx_addr, injection.agent_current_thread_eval_impl);

    // 启动 socketpair handler（在 host_fd 上读写）
    let _handle = start_socketpair_handler(injection.host_fd, session.clone());

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
            let mut post_resume_java_worker_needed = false;
            if let Some(script_path) = &args.load_script {
                log_info!("子进程暂停中，准备加载脚本");
                match load_script_file_pre_resume(&session, script_path) {
                    Ok(state) => {
                        post_resume_java_worker_needed |= state.needs_post_resume_java_worker();
                    }
                    Err(e) => {
                        log_error!("{}", e);
                        spawn::abort_pending_children_and_cleanup_zygote_patches();
                        std::process::exit(1);
                    }
                }
            }
            // resume: hook 已就位，恢复子进程
            if let Err(e) = spawn::resume_child(pid as u32) {
                log_error!("恢复子进程失败: {}", e);
            }
            if let Err(e) = ensure_java_worker_ready_after_resume(&session, post_resume_java_worker_needed) {
                log_warn!("Java worker 启动失败，后续 Java 操作需要重新初始化 worker: {}", e);
            }
        }
    }

    // 非 spawn 模式: --load-script 在 resume 后加载（进程已在运行）
    if args.spawn.is_none() {
        if let Some(script_path) = &args.load_script {
            if let Err(e) = load_script_file(&session, script_path, false) {
                log_error!("{}", e);
            }
        }
    }

    // %reload 用：记住最近一次加载的脚本路径
    let mut last_script_path: Option<String> = args.load_script.clone();

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
            s.shutdown_requested.store(true, Ordering::Release);
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
                // %reload [path]: 清理 JS 引擎并重新加载脚本（不退出进程）
                if line == "%reload" || line.starts_with("%reload ") {
                    let arg = line["%reload".len()..].trim();
                    let path = if arg.is_empty() {
                        last_script_path.clone()
                    } else {
                        Some(arg.to_string())
                    };
                    match path {
                        None => {
                            log_warn!("用法: %reload <path>（未指定 --load-script 时必须给路径）");
                        }
                        Some(p) => {
                            if let Err(e) = load_script_file(&session, &p, true) {
                                log_error!("{}", e);
                            } else {
                                last_script_path = Some(p);
                            }
                        }
                    }
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
                    || line.starts_with("managedcounter ")
                    || is_recomp;
                if is_eval_cmd {
                    session.eval_state.clear();
                }
                let handled_by_main_thread = match try_managedcounter_on_main_thread(&session, &line)
                    .and_then(|handled| {
                        if handled {
                            Ok(true)
                        } else {
                            try_loadjs_on_main_thread_if_java(&session, &line)
                        }
                    })
                    .and_then(|handled| {
                        if handled {
                            Ok(true)
                        } else {
                            try_jseval_on_main_thread_if_java_or_dsl(&session, &line)
                        }
                    }) {
                    Ok(v) => v,
                    Err(e) => {
                        log_error!("{}", e);
                        continue;
                    }
                };
                if !handled_by_main_thread {
                    let command = rewrite_jseval_for_agent(&line).unwrap_or_else(|| line.clone());
                    match send_command(sender, &command) {
                        Ok(_) => {}
                        Err(e) => {
                            log_error!("发送命令失败: {}", e);
                            break;
                        }
                    }
                }
                if is_eval_cmd {
                    let timeout = if is_recomp {
                        EVAL_RECOMP_TIMEOUT_SECS
                    } else if script_uses_java_api(&line) {
                        EVAL_JAVA_TIMEOUT_SECS
                    } else {
                        EVAL_DEFAULT_TIMEOUT_SECS
                    };
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

    // 等待 agent 完成清理并主动关闭 socket。交互路径不能无限等：
    // 超时后直接返回，并跳过远端 loader 残留清理，避免打断仍在清理中的 agent。
    let start = std::time::Instant::now();
    let shutdown_deadline = std::time::Duration::from_secs(AGENT_SHUTDOWN_WAIT_SECS);
    while !session.disconnected.load(Ordering::Acquire) && start.elapsed() < shutdown_deadline {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let total = start.elapsed();
    let agent_disconnected = session.disconnected.load(Ordering::Acquire);
    if agent_disconnected && total.as_secs() >= 1 {
        log_info!("agent 已断开 (总耗时 {}s)", total.as_secs());
    } else if !agent_disconnected {
        log_warn!(
            "agent 清理等待超过 {}s，已返回交互；目标内资源保留，跳过 loader 残留清理",
            AGENT_SHUTDOWN_WAIT_SECS
        );
    }

    if agent_disconnected {
        if let Some(pid) = target_pid {
            cleanup_remote_loader_mappings(pid, &injection);
        }
    }

    // Spawn 模式：agent 完整退出后再还原 Zygote patch，避免两个清理流程交错。
    if args.spawn.is_some() {
        spawn::cleanup_zygote_patches();
    }
}
