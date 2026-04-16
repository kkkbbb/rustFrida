#![cfg(all(target_os = "android", target_arch = "aarch64"))]

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex, OnceLock};

use crate::communication::{send_command, HostToAgentMessage, SyncChannel};

/// 单个注入会话：一个目标进程对应一个 Session
pub(crate) struct Session {
    pub(crate) id: u32,
    pub(crate) pid: AtomicI32,
    pub(crate) label: Mutex<String>,
    pub(crate) sender: OnceLock<Sender<HostToAgentMessage>>,
    pub(crate) eval_state: SyncChannel<Result<String, String>>,
    pub(crate) complete_state: SyncChannel<Vec<String>>,
    /// RPC 调用回复通道（与 eval_state 解耦，避免 HTTP RPC 抢占 REPL eval）
    pub(crate) rpc_state: SyncChannel<Result<String, String>>,
    /// 串行化并发 RPC 调用：rpc_state 是单槽 channel，多个请求并发会互相覆盖
    pub(crate) rpc_lock: Mutex<()>,
    pub(crate) connected: AtomicBool,
    pub(crate) disconnected: AtomicBool,
    pub(crate) failed: AtomicBool,
}

impl Session {
    pub(crate) fn new(id: u32, label: String) -> Self {
        Session {
            id,
            pid: AtomicI32::new(0),
            label: Mutex::new(label),
            sender: OnceLock::new(),
            eval_state: SyncChannel::new(),
            complete_state: SyncChannel::new(),
            rpc_state: SyncChannel::new(),
            rpc_lock: Mutex::new(()),
            connected: AtomicBool::new(false),
            disconnected: AtomicBool::new(false),
            failed: AtomicBool::new(false),
        }
    }

    /// 向 agent 派发 RPC 调用并等待结果。
    ///
    /// * `method`    — 注册在 `rpc.exports` 上的方法名（不能包含空白）
    /// * `args_json` — 参数 JSON 数组字符串（如 `"[1,2,3]"`），空字符串等价空数组
    /// * `timeout`   — 等待 agent 回复的超时时间
    ///
    /// 返回值为 JSON 字符串化后的结果；`Err` 表示会话未就绪 / 方法不存在 / 超时 / JS 异常。
    pub(crate) fn rpc_call(
        &self,
        method: &str,
        args_json: &str,
        timeout: std::time::Duration,
    ) -> Result<String, String> {
        if method.is_empty() || method.chars().any(char::is_whitespace) {
            return Err("invalid rpc method name".to_string());
        }
        if !self.is_connected() {
            return Err("session not connected".to_string());
        }
        let sender = self.get_sender().ok_or("session has no sender")?;
        let cmd = if args_json.is_empty() {
            format!("rpccall {}", method)
        } else {
            format!("rpccall {} {}", method, args_json)
        };
        // 串行化并发 RPC 请求；rpc_state 是单槽，不能并发使用。
        let _guard = self.rpc_lock.lock().unwrap_or_else(|e| e.into_inner());
        let reply = self.rpc_state.clear_then_recv(timeout, || {
            let _ = send_command(sender, cmd);
        });
        match reply {
            None => Err("rpc call timed out".to_string()),
            Some(Ok(s)) => Ok(s),
            Some(Err(e)) => Err(e),
        }
    }

    /// 等待 agent 连接，返回是否成功
    pub(crate) fn wait_connected(&self, timeout_secs: u64) -> bool {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
        while !self.connected.load(Ordering::Acquire) {
            if self.failed.load(Ordering::Acquire) {
                return false;
            }
            if std::time::Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        true
    }

    /// 带信号检查的等待（用于 spawn 模式）
    pub(crate) fn wait_connected_with_signal(
        &self,
        timeout_secs: u64,
        signal_check: impl Fn() -> bool,
    ) -> bool {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
        while !self.connected.load(Ordering::Acquire) {
            if self.failed.load(Ordering::Acquire) || signal_check() {
                return false;
            }
            if std::time::Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        true
    }

    pub(crate) fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Acquire) && !self.disconnected.load(Ordering::Acquire)
    }

    pub(crate) fn get_sender(&self) -> Option<&Sender<HostToAgentMessage>> {
        self.sender.get()
    }

    pub(crate) fn status(&self) -> &'static str {
        if self.failed.load(Ordering::Acquire) {
            "failed"
        } else if self.disconnected.load(Ordering::Acquire) {
            "disconnected"
        } else if self.connected.load(Ordering::Acquire) {
            "connected"
        } else {
            "connecting"
        }
    }
}

/// 多会话管理器
pub(crate) struct SessionManager {
    sessions: Mutex<HashMap<u32, Arc<Session>>>,
    next_id: AtomicU32,
    active_id: Mutex<Option<u32>>,
}

impl SessionManager {
    pub(crate) fn new() -> Self {
        SessionManager {
            sessions: Mutex::new(HashMap::new()),
            next_id: AtomicU32::new(1),
            active_id: Mutex::new(None),
        }
    }

    pub(crate) fn create_session(&self, label: String) -> Arc<Session> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let session = Arc::new(Session::new(id, label));
        self.sessions.lock().unwrap().insert(id, session.clone());
        session
    }

    /// 插入一个已经创建好的 Session（例如 legacy 模式下的 id=0 session）。
    /// 仅供 HTTP RPC 在非 server 模式下将 single session 暴露给 SessionManager。
    pub(crate) fn insert_session(&self, session: Arc<Session>) {
        self.sessions.lock().unwrap().insert(session.id, session);
    }

    pub(crate) fn get_session(&self, id: u32) -> Option<Arc<Session>> {
        self.sessions.lock().unwrap().get(&id).cloned()
    }

    pub(crate) fn set_active(&self, id: Option<u32>) {
        *self.active_id.lock().unwrap() = id;
    }

    pub(crate) fn remove_session(&self, id: u32) -> Option<Arc<Session>> {
        let removed = self.sessions.lock().unwrap().remove(&id);
        let mut active = self.active_id.lock().unwrap();
        if *active == Some(id) {
            *active = None;
        }
        removed
    }

    /// 返回 (id, pid, label, status, is_active)
    pub(crate) fn list_sessions(&self) -> Vec<(u32, i32, String, &'static str, bool)> {
        let sessions = self.sessions.lock().unwrap();
        let active_id = *self.active_id.lock().unwrap();
        let mut result: Vec<_> = sessions
            .iter()
            .map(|(&id, s)| {
                (
                    id,
                    s.pid.load(Ordering::Relaxed),
                    s.label.lock().unwrap().clone(),
                    s.status(),
                    active_id == Some(id),
                )
            })
            .collect();
        result.sort_by_key(|(id, _, _, _, _)| *id);
        result
    }

    pub(crate) fn all_sessions(&self) -> Vec<Arc<Session>> {
        self.sessions.lock().unwrap().values().cloned().collect()
    }
}
