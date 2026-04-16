//! agent 端 socket 通信模块
//!
//! 日志消息 (FRAME_KIND_LOG) 通过异步队列发送，hook 线程只做 channel push，
//! 不直接接触 socket I/O。独立的 writer 线程消费队列写 socket。
//! 控制消息 (HELLO/COMPLETE/EVAL_OK/EVAL_ERR) 仍走同步路径（低频且需要保序）。

use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::sync::mpsc;
use std::sync::{Mutex, OnceLock};

const FRAME_KIND_CMD: u8 = 1;
const FRAME_KIND_QBDI_HELPER: u8 = 2;

const FRAME_KIND_HELLO: u8 = 0x80;
const FRAME_KIND_LOG: u8 = 0x81;
const FRAME_KIND_COMPLETE: u8 = 0x82;
const FRAME_KIND_EVAL_OK: u8 = 0x83;
const FRAME_KIND_EVAL_ERR: u8 = 0x84;
const FRAME_KIND_RPC_OK: u8 = 0x85;
const FRAME_KIND_RPC_ERR: u8 = 0x86;

/// Write-half of the agent↔host socket, protected by Mutex to serialize messages.
/// 控制消息 (HELLO/COMPLETE/EVAL_OK/EVAL_ERR) 直接走此 stream。
pub static GLOBAL_STREAM: OnceLock<Mutex<UnixStream>> = OnceLock::new();
pub static GLOBAL_STREAM_FD: OnceLock<i32> = OnceLock::new();

/// 异步日志 channel 发送端（hook 线程 push，无界 channel，永不阻塞也不丢弃）
static LOG_SENDER: OnceLock<mpsc::Sender<Vec<u8>>> = OnceLock::new();

fn write_frame(stream: &mut UnixStream, kind: u8, payload: &[u8]) -> std::io::Result<()> {
    stream.write_all(&[kind])?;
    stream.write_all(&(payload.len() as u32).to_le_bytes())?;
    stream.write_all(payload)
}

pub(crate) fn read_frame(stream: &mut UnixStream) -> std::io::Result<(u8, Vec<u8>)> {
    let mut kind = [0u8; 1];
    stream.read_exact(&mut kind)?;
    let mut len = [0u8; 4];
    stream.read_exact(&mut len)?;
    let len = u32::from_le_bytes(len) as usize;
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload)?;
    Ok((kind[0], payload))
}

/// 启动异步日志 writer 线程。在 socket 连接建立后调用一次。
/// writer 线程通过 GLOBAL_STREAM mutex 写 socket，与控制消息共享同一把锁，避免帧交错。
pub(crate) fn start_log_writer() {
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    let _ = LOG_SENDER.set(tx);

    std::thread::Builder::new()
        .name("log-writer".into())
        .spawn(move || {
            while let Ok(payload) = rx.recv() {
                if let Some(m) = GLOBAL_STREAM.get() {
                    // try_lock: 如果控制消息正在写 socket，跳过这条日志避免阻塞。
                    // 高频 hook (HashMap.put) 丢几条日志无所谓，但持锁阻塞会导致
                    // 控制消息 (EVAL_OK) 拿不到锁 → host 不读 socket → socket 满 → 死锁。
                    let mut stream = match m.try_lock() {
                        Ok(s) => s,
                        Err(std::sync::TryLockError::WouldBlock) => continue,
                        Err(std::sync::TryLockError::Poisoned(e)) => e.into_inner(),
                    };
                    // 设置写超时: socket 缓冲区满时不无限阻塞，超时则丢弃并继续
                    let _ = stream.set_write_timeout(Some(std::time::Duration::from_millis(50)));
                    if write_frame(&mut stream, FRAME_KIND_LOG, &payload).is_err() {
                        // 写失败(超时/断连): 清除超时设置，继续尝试下一条
                        let _ = stream.set_write_timeout(None);
                        // 如果是断连则退出
                        if stream.peer_addr().is_err() {
                            break;
                        }
                        continue;
                    }
                    let _ = stream.set_write_timeout(None);
                }
            }
        })
        .expect("spawn log-writer thread");
}

/// 异步写日志：push 到无界 channel，永不阻塞调用线程。
pub(crate) fn write_stream(data: &[u8]) {
    if let Some(tx) = LOG_SENDER.get() {
        let _ = tx.send(data.to_vec());
    } else if let Some(m) = GLOBAL_STREAM.get() {
        // fallback: log writer 未启动时（如启动早期）同步写
        let _ = write_frame(&mut m.lock().unwrap_or_else(|e| e.into_inner()), FRAME_KIND_LOG, data);
    }
}

/// 直接通过原始 fd 写 socket，供崩溃处理等场景使用。
pub(crate) fn write_stream_raw(data: &[u8]) {
    if let Some(fd) = GLOBAL_STREAM_FD.get() {
        let mut header = [0u8; 5];
        header[0] = FRAME_KIND_LOG;
        header[1..].copy_from_slice(&(data.len() as u32).to_le_bytes());
        let _ = unsafe { libc::write(*fd, header.as_ptr() as *const libc::c_void, header.len()) };
        let mut offset = 0usize;
        while offset < data.len() {
            let wrote =
                unsafe { libc::write(*fd, data[offset..].as_ptr() as *const libc::c_void, data.len() - offset) };
            if wrote <= 0 {
                break;
            }
            offset += wrote as usize;
        }
    }
}

pub(crate) fn send_hello() {
    if let Some(m) = GLOBAL_STREAM.get() {
        let _ = write_frame(&mut m.lock().unwrap_or_else(|e| e.into_inner()), FRAME_KIND_HELLO, &[]);
    }
}

pub(crate) fn send_complete(text: &str) {
    if let Some(m) = GLOBAL_STREAM.get() {
        let _ = write_frame(
            &mut m.lock().unwrap_or_else(|e| e.into_inner()),
            FRAME_KIND_COMPLETE,
            text.as_bytes(),
        );
    }
}

pub(crate) fn send_eval_ok(text: &str) {
    if let Some(m) = GLOBAL_STREAM.get() {
        let _ = write_frame(
            &mut m.lock().unwrap_or_else(|e| e.into_inner()),
            FRAME_KIND_EVAL_OK,
            text.as_bytes(),
        );
    }
}

pub(crate) fn send_eval_err(text: &str) {
    if let Some(m) = GLOBAL_STREAM.get() {
        let _ = write_frame(
            &mut m.lock().unwrap_or_else(|e| e.into_inner()),
            FRAME_KIND_EVAL_ERR,
            text.as_bytes(),
        );
    }
}

pub(crate) fn send_rpc_ok(text: &str) {
    if let Some(m) = GLOBAL_STREAM.get() {
        let _ = write_frame(
            &mut m.lock().unwrap_or_else(|e| e.into_inner()),
            FRAME_KIND_RPC_OK,
            text.as_bytes(),
        );
    }
}

pub(crate) fn send_rpc_err(text: &str) {
    if let Some(m) = GLOBAL_STREAM.get() {
        let _ = write_frame(
            &mut m.lock().unwrap_or_else(|e| e.into_inner()),
            FRAME_KIND_RPC_ERR,
            text.as_bytes(),
        );
    }
}

pub(crate) fn is_cmd_frame(kind: u8) -> bool {
    kind == FRAME_KIND_CMD
}

pub(crate) fn is_qbdi_helper_frame(kind: u8) -> bool {
    kind == FRAME_KIND_QBDI_HELPER
}

pub(crate) static CACHE_LOG: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// 日志函数：socket未连接时缓存，log writer 启动后走异步队列
/// 自动添加 [agent] 前缀
pub(crate) fn log_msg(msg: String) {
    let prefixed = format!("[agent] {}", msg);
    if LOG_SENDER.get().is_some() || GLOBAL_STREAM.get().is_some() {
        write_stream(prefixed.as_bytes());
    } else {
        // Socket未连接，缓存日志
        if let Ok(mut cache) = CACHE_LOG.lock() {
            cache.push(prefixed);
        }
    }
}

/// 关闭 socket 连接，通知 host 收到 EOF 自然退出
pub(crate) fn shutdown_stream() {
    // shutdown + close 双保险：shutdown 标记不再读写，close 释放 fd 触发 peer EOF
    if let Some(m) = GLOBAL_STREAM.get() {
        if let Ok(stream) = m.lock() {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }
    if let Some(fd) = GLOBAL_STREAM_FD.get() {
        unsafe { libc::close(*fd); }
    }
}

pub(crate) fn register_stream_fd(stream: &UnixStream) {
    let _ = GLOBAL_STREAM_FD.set(stream.as_raw_fd());
}

/// 刷新缓存的日志，在socket连接后调用
pub(crate) fn flush_cached_logs() {
    if GLOBAL_STREAM.get().is_some() {
        if let Ok(mut cache) = CACHE_LOG.lock() {
            for msg in cache.drain(..) {
                write_stream(msg.as_bytes());
            }
        }
    }
}
