#![cfg(all(target_os = "android", target_arch = "aarch64"))]

//! 最小 HTTP/1.1 服务器，暴露 agent 端的 `rpc.exports` 为 REST 接口。
//!
//! 路由：
//!   GET  /                      — 健康检查
//!   GET  /sessions              — 列出所有 session (JSON)
//!   POST /rpc/<session>/<method> body=<json args array>
//!
//! RPC 调用流程：
//!   1. HTTP handler 解析 path / body
//!   2. 在目标 Session 上调用 `rpc_call(method, args_json, timeout)`
//!   3. agent 端通过 `rpccall` 命令派发到 `rpc.exports[method]`
//!   4. 结果 JSON 字符串沿原路返回
//!
//! 该服务器走 std::net::TcpListener，纯同步 + thread-per-connection。
//! 避免引入额外 HTTP crate，保持 aarch64 交叉编译体积可控。

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::session::SessionManager;
use crate::{log_error, log_info, log_success};

const MAX_REQUEST_LINE_LEN: usize = 8 * 1024;
const MAX_HEADERS_LEN: usize = 16 * 1024;
const MAX_BODY_LEN: usize = 4 * 1024 * 1024; // 4MB 足够承载任何合理 RPC payload
const READ_TIMEOUT: Duration = Duration::from_secs(30);
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
const RPC_CALL_TIMEOUT: Duration = Duration::from_secs(30);

/// 启动 HTTP RPC 服务器（后台线程）。
///
/// `bind_addr` 可以是 `"0.0.0.0:9191"` 或 `"127.0.0.1:9191"`。
pub(crate) fn start(mgr: Arc<SessionManager>, bind_addr: &str) -> Result<(), String> {
    let listener = TcpListener::bind(bind_addr)
        .map_err(|e| format!("RPC HTTP bind {} 失败: {}", bind_addr, e))?;
    let actual = listener
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| bind_addr.to_string());
    log_success!("RPC HTTP server listening on {}", actual);
    log_info!("  curl -X POST http://{}/rpc/<session>/<method> -d '[args]'", actual);

    thread::Builder::new()
        .name("rpc-http-accept".into())
        .spawn(move || accept_loop(listener, mgr))
        .map_err(|e| format!("spawn rpc-http-accept 失败: {}", e))?;
    Ok(())
}

fn accept_loop(listener: TcpListener, mgr: Arc<SessionManager>) {
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let mgr = mgr.clone();
                let _ = thread::Builder::new()
                    .name("rpc-http-conn".into())
                    .spawn(move || {
                        if let Err(e) = handle_connection(s, mgr) {
                            log_error!("RPC HTTP 处理失败: {}", e);
                        }
                    });
            }
            Err(e) => {
                log_error!("RPC HTTP accept 失败: {}", e);
            }
        }
    }
}

// ─────────────────────────── HTTP 请求解析 ───────────────────────────

struct HttpRequest {
    method: String,
    path: String,
    body: Vec<u8>,
}

fn handle_connection(stream: TcpStream, mgr: Arc<SessionManager>) -> Result<(), String> {
    stream
        .set_read_timeout(Some(READ_TIMEOUT))
        .map_err(|e| format!("set_read_timeout: {}", e))?;
    stream
        .set_write_timeout(Some(WRITE_TIMEOUT))
        .map_err(|e| format!("set_write_timeout: {}", e))?;

    let write_stream = stream.try_clone().map_err(|e| format!("clone stream: {}", e))?;
    let mut reader = BufReader::new(stream);

    let req = match read_request(&mut reader) {
        Ok(r) => r,
        Err(e) => {
            send_response(write_stream, 400, "text/plain; charset=utf-8", e.as_bytes());
            return Ok(());
        }
    };

    dispatch(req, &mgr, write_stream);
    Ok(())
}

fn read_request(reader: &mut BufReader<TcpStream>) -> Result<HttpRequest, String> {
    // Request line
    let mut request_line = String::new();
    let n = reader
        .read_line(&mut request_line)
        .map_err(|e| format!("read request line: {}", e))?;
    if n == 0 {
        return Err("empty request".to_string());
    }
    if request_line.len() > MAX_REQUEST_LINE_LEN {
        return Err("request line too long".to_string());
    }
    let trimmed = request_line.trim_end_matches(&['\r', '\n'][..]);
    let mut parts = trimmed.split(' ');
    let method = parts
        .next()
        .ok_or_else(|| "missing method".to_string())?
        .to_string();
    let path = parts
        .next()
        .ok_or_else(|| "missing path".to_string())?
        .to_string();
    let _version = parts.next().ok_or_else(|| "missing version".to_string())?;

    // Headers
    let mut content_length: usize = 0;
    let mut headers_total = 0usize;
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).map_err(|e| format!("read header: {}", e))?;
        if n == 0 {
            break;
        }
        headers_total += n;
        if headers_total > MAX_HEADERS_LEN {
            return Err("headers too large".to_string());
        }
        let trimmed = line.trim_end_matches(&['\r', '\n'][..]);
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, value)) = trimmed.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value
                    .trim()
                    .parse()
                    .map_err(|e| format!("invalid content-length: {}", e))?;
                if content_length > MAX_BODY_LEN {
                    return Err("body too large".to_string());
                }
            }
        }
    }

    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader
            .read_exact(&mut body)
            .map_err(|e| format!("read body: {}", e))?;
    }

    Ok(HttpRequest { method, path, body })
}

// ─────────────────────────── 路由 ───────────────────────────

fn dispatch(req: HttpRequest, mgr: &SessionManager, stream: TcpStream) {
    // 去掉 query string（简单处理，不支持 URL decode）
    let path = req.path.split('?').next().unwrap_or("").to_string();

    match (req.method.as_str(), path.as_str()) {
        ("GET", "/") | ("GET", "/health") => {
            send_json(stream, 200, "{\"status\":\"ok\"}");
        }
        ("GET", "/sessions") => handle_list_sessions(stream, mgr),
        ("POST", p) if p.starts_with("/rpc/") => handle_rpc_call(stream, mgr, p, &req.body),
        _ => send_response(stream, 404, "text/plain; charset=utf-8", b"not found"),
    }
}

fn handle_list_sessions(stream: TcpStream, mgr: &SessionManager) {
    let sessions = mgr.list_sessions();
    let mut json = String::from("[");
    for (i, (id, pid, label, status, _active)) in sessions.iter().enumerate() {
        if i > 0 {
            json.push(',');
        }
        json.push_str(&format!(
            "{{\"id\":{},\"pid\":{},\"label\":{},\"status\":\"{}\"}}",
            id,
            pid,
            json_string(label),
            status,
        ));
    }
    json.push(']');
    send_json(stream, 200, &json);
}

fn handle_rpc_call(stream: TcpStream, mgr: &SessionManager, path: &str, body: &[u8]) {
    // /rpc/<session>/<method>
    let rest = &path["/rpc/".len()..];
    let (session_str, method) = match rest.split_once('/') {
        Some((s, m)) if !s.is_empty() && !m.is_empty() => (s, m),
        _ => {
            send_json_error(stream, 400, "URL must be /rpc/<session>/<method>");
            return;
        }
    };

    let session_id: u32 = match session_str.parse() {
        Ok(id) => id,
        Err(_) => {
            send_json_error(stream, 400, "invalid session id");
            return;
        }
    };

    let session = match mgr.get_session(session_id) {
        Some(s) => s,
        None => {
            send_json_error(stream, 404, &format!("session #{} not found", session_id));
            return;
        }
    };

    if !session.is_connected() {
        send_json_error(stream, 503, "session not connected");
        return;
    }

    let args_json = if body.is_empty() {
        "[]".to_string()
    } else {
        match std::str::from_utf8(body) {
            Ok(s) => {
                let trimmed = s.trim();
                if trimmed.is_empty() {
                    "[]".to_string()
                } else {
                    trimmed.to_string()
                }
            }
            Err(_) => {
                send_json_error(stream, 400, "body must be UTF-8");
                return;
            }
        }
    };

    match session.rpc_call(method, &args_json, RPC_CALL_TIMEOUT) {
        Ok(result) => {
            // result 已经是 JSON 字符串，可直接拼入响应
            let payload = format!("{{\"ok\":true,\"result\":{}}}", result);
            send_json(stream, 200, &payload);
        }
        Err(e) => {
            let payload = format!("{{\"ok\":false,\"error\":{}}}", json_string(&e));
            send_json(stream, 500, &payload);
        }
    }
}

// ─────────────────────────── 响应辅助 ───────────────────────────

fn send_json(stream: TcpStream, status: u16, payload: &str) {
    send_response(stream, status, "application/json; charset=utf-8", payload.as_bytes());
}

fn send_json_error(stream: TcpStream, status: u16, msg: &str) {
    let payload = format!("{{\"ok\":false,\"error\":{}}}", json_string(msg));
    send_json(stream, status, &payload);
}

fn send_response(mut stream: TcpStream, status: u16, content_type: &str, body: &[u8]) {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Response",
    };
    let header = format!(
        "HTTP/1.1 {} {}\r\n\
         Content-Type: {}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         Access-Control-Allow-Origin: *\r\n\
         \r\n",
        status,
        reason,
        content_type,
        body.len()
    );
    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
}

/// 将任意 Rust 字符串编码为 JSON 字符串字面量（带双引号）
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

