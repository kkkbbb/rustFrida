#![cfg(all(target_os = "android", target_arch = "aarch64"))]

use std::io::{Read, Write};
use std::os::unix::io::{FromRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::atomic::Ordering;
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::thread::JoinHandle;
use std::time::Duration;

use crate::session::Session;
use crate::{log_agent, log_error, log_success};

const FRAME_KIND_CMD: u8 = 1;
#[cfg(feature = "qbdi")]
const FRAME_KIND_QBDI_HELPER: u8 = 2;

const FRAME_KIND_HELLO: u8 = 0x80;
const FRAME_KIND_LOG: u8 = 0x81;
const FRAME_KIND_COMPLETE: u8 = 0x82;
const FRAME_KIND_EVAL_OK: u8 = 0x83;
const FRAME_KIND_EVAL_ERR: u8 = 0x84;
const FRAME_KIND_RPC_OK: u8 = 0x85;
const FRAME_KIND_RPC_ERR: u8 = 0x86;

#[derive(Clone)]
pub(crate) enum HostToAgentMessage {
    Command(String),
    #[cfg(feature = "qbdi")]
    QbdiHelper(Vec<u8>),
}

/// 泛型同步通道：在多线程间传递单次值，支持超时等待。
pub(crate) struct SyncChannel<T> {
    mutex: Mutex<Option<T>>,
    cvar: Condvar,
}

impl<T: Clone> SyncChannel<T> {
    pub(crate) fn new() -> Self {
        SyncChannel {
            mutex: Mutex::new(None),
            cvar: Condvar::new(),
        }
    }

    /// 获取 mutex 锁，中毒时自动恢复。
    fn lock_or_recover(&self) -> std::sync::MutexGuard<'_, Option<T>> {
        self.mutex.lock().unwrap_or_else(|e| {
            log_error!("SyncChannel: mutex poisoned, recovering");
            e.into_inner()
        })
    }

    /// 设置值并通知所有等待者（由 handle_socket_connection 调用）。
    pub(crate) fn send(&self, val: T) {
        let mut guard = self.lock_or_recover();
        *guard = Some(val);
        self.cvar.notify_all();
    }

    /// 清除当前值。
    pub(crate) fn clear(&self) {
        let mut guard = self.lock_or_recover();
        *guard = None;
    }

    /// 持锁等待值到来或超时，返回值的克隆。
    fn wait_for_value(&self, guard: std::sync::MutexGuard<'_, Option<T>>, dur: Duration) -> Option<T> {
        match self.cvar.wait_timeout_while(guard, dur, |val| val.is_none()) {
            Ok((guard, timeout)) => {
                if timeout.timed_out() {
                    None
                } else {
                    guard.clone()
                }
            }
            Err(_) => None,
        }
    }

    /// 在持锁状态下清除值、调用 `f`（通常用于发送请求），再阻塞等待值到来或超时。
    /// 保证"清除→发请求→等待"之间不存在竞态窗口。
    pub(crate) fn clear_then_recv<F: FnOnce()>(&self, dur: Duration, f: F) -> Option<T> {
        let mut guard = match self.mutex.lock() {
            Ok(g) => g,
            Err(_) => return None,
        };
        *guard = None;
        f();
        self.wait_for_value(guard, dur)
    }

    /// 阻塞等待值到来或超时（调用前需自行 clear）。
    pub(crate) fn recv_timeout(&self, dur: Duration) -> Option<T> {
        let guard = match self.mutex.lock() {
            Ok(g) => g,
            Err(_) => return None,
        };
        self.wait_for_value(guard, dur)
    }
}

pub(crate) fn send_command(
    sender: &Sender<HostToAgentMessage>,
    cmd: impl Into<String>,
) -> Result<(), std::sync::mpsc::SendError<HostToAgentMessage>> {
    sender.send(HostToAgentMessage::Command(cmd.into()))
}

#[cfg(feature = "qbdi")]
pub(crate) fn send_qbdi_helper(
    sender: &Sender<HostToAgentMessage>,
    blob: Vec<u8>,
) -> Result<(), std::sync::mpsc::SendError<HostToAgentMessage>> {
    sender.send(HostToAgentMessage::QbdiHelper(blob))
}

fn write_frame(stream: &mut UnixStream, kind: u8, payload: &[u8]) -> std::io::Result<()> {
    stream.write_all(&[kind])?;
    stream.write_all(&(payload.len() as u32).to_le_bytes())?;
    stream.write_all(payload)
}

fn read_frame(reader: &mut dyn Read) -> std::io::Result<(u8, Vec<u8>)> {
    let mut kind = [0u8; 1];
    reader.read_exact(&mut kind)?;
    let mut len = [0u8; 4];
    reader.read_exact(&mut len)?;
    let len = u32::from_le_bytes(len) as usize;
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload)?;
    Ok((kind[0], payload))
}

fn handle_socket_connection(stream: UnixStream, session: Arc<Session>) {
    let mut reader = stream;

    loop {
        match read_frame(&mut reader) {
            Ok((kind, payload)) => match kind {
                FRAME_KIND_HELLO => {
                    if session.id == 0 {
                        log_success!("Agent 已连接");
                    } else {
                        log_success!("[#{}] Agent 已连接", session.id);
                    }
                    let stream_clone = match reader.try_clone() {
                        Ok(s) => s,
                        Err(e) => {
                            log_error!("clone stream 失败: {}", e);
                            return;
                        }
                    };
                    let session2 = session.clone();
                    thread::spawn(move || {
                        let mut stream_clone = stream_clone;
                        let (sd, rx) = channel();
                        match session2.sender.set(sd) {
                            Ok(_) => {}
                            Err(_) => {
                                log_error!("[#{}] sender already set!", session2.id);
                                return;
                            }
                        }
                        session2.connected.store(true, Ordering::Release);
                        while let Ok(msg) = rx.recv() {
                            let (kind, payload) = match msg {
                                HostToAgentMessage::Command(cmd) => (FRAME_KIND_CMD, cmd.into_bytes()),
                                #[cfg(feature = "qbdi")]
                                HostToAgentMessage::QbdiHelper(blob) => (FRAME_KIND_QBDI_HELPER, blob),
                            };
                            if let Err(e) = write_frame(&mut stream_clone, kind, &payload) {
                                log_error!("[#{}] stream 写入失败: {}", session2.id, e);
                                session2.disconnected.store(true, Ordering::Release);
                                break;
                            }
                        }
                    });
                }
                FRAME_KIND_COMPLETE => {
                    let text = String::from_utf8(payload).unwrap_or_default();
                    let candidates: Vec<String> = if text.is_empty() {
                        vec![]
                    } else {
                        text.split('\t')
                            .map(|s| s.to_string())
                            .filter(|s| !s.is_empty())
                            .collect()
                    };
                    session.complete_state.send(candidates);
                }
                FRAME_KIND_EVAL_OK => {
                    session
                        .eval_state
                        .send(Ok(String::from_utf8(payload).unwrap_or_default()));
                }
                FRAME_KIND_EVAL_ERR => {
                    session
                        .eval_state
                        .send(Err(String::from_utf8(payload).unwrap_or_default()));
                }
                FRAME_KIND_RPC_OK => {
                    session
                        .rpc_state
                        .send(Ok(String::from_utf8(payload).unwrap_or_default()));
                }
                FRAME_KIND_RPC_ERR => {
                    session
                        .rpc_state
                        .send(Err(String::from_utf8(payload).unwrap_or_default()));
                }
                FRAME_KIND_LOG => {
                    let msg = String::from_utf8(payload).unwrap_or_default();
                    let msg = msg.strip_suffix('\n').unwrap_or(&msg);
                    if !msg.is_empty() {
                        if session.id == 0 {
                            log_agent!("{}", msg);
                        } else {
                            println!(
                                "{}{} [agent#{}]{} {}",
                                crate::logger::BOLD,
                                crate::logger::MAGENTA,
                                session.id,
                                crate::logger::RESET,
                                msg
                            );
                        }
                    }
                }
                other => {
                    log_error!("未知 agent frame kind: {}", other);
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                if session.id == 0 {
                    // legacy 模式静默断连
                } else {
                    log_error!("[#{}] Agent 连接已断开", session.id);
                }
                session.disconnected.store(true, Ordering::Release);
                break;
            }
            Err(e) => {
                log_error!("[#{}] 读取连接失败: {}", session.id, e);
                if e.kind() == std::io::ErrorKind::ConnectionReset {
                    log_error!("可能原因: 目标进程权限不足 / agent 崩溃 / SELinux 拦截");
                    log_error!("排查: dmesg | grep -i 'deny\\|avc'  或  logcat | grep -E 'FATAL|crash'");
                }
                session.disconnected.store(true, Ordering::Release);
                break;
            }
        }
    }
}

/// 包装 socketpair 的 host_fd 为 UnixStream，启动处理线程
pub(crate) fn start_socketpair_handler(host_fd: RawFd, session: Arc<Session>) -> JoinHandle<()> {
    let stream = unsafe { UnixStream::from_raw_fd(host_fd) };
    thread::spawn(move || {
        handle_socket_connection(stream, session);
    })
}
