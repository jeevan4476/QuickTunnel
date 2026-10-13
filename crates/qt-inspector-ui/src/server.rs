//! Web Inspector HTTP server, SSE hub, and request replay engine.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Notify;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::store::{CapturedRequest, HeaderPair, InspectorStore, ResponseDetails};
use qt_proto::{ProtoError, Result};

/// Maximum HTTP request headers size (16 KiB)
pub const MAX_HEADER_SIZE: usize = 16 * 1024;

/// Maximum request body size accepted by inspector API (2 MiB)
pub const MAX_BODY_SIZE: usize = 2 * 1024 * 1024;

/// Aggregate metrics returned by `GET /api/metrics`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InspectorMetrics {
    pub total_requests: usize,
    pub status_2xx: usize,
    pub status_3xx: usize,
    pub status_4xx: usize,
    pub status_5xx: usize,
    pub avg_latency_ms: f64,
    pub bytes_transferred: usize,
}

/// Computes aggregate statistics from the current stored requests.
pub fn calculate_metrics(store: &InspectorStore) -> InspectorMetrics {
    let requests = store.list(store.capacity());
    let total_requests = requests.len();
    let mut status_2xx = 0;
    let mut status_3xx = 0;
    let mut status_4xx = 0;
    let mut status_5xx = 0;
    let mut total_latency = 0u64;
    let mut latency_count = 0usize;
    let mut bytes_transferred = 0usize;

    for req in &requests {
        bytes_transferred += req.request.body_size;
        if let Some(ref resp) = req.response {
            match resp.status {
                200..=299 => status_2xx += 1,
                300..=399 => status_3xx += 1,
                400..=499 => status_4xx += 1,
                500..=599 => status_5xx += 1,
                _ => {}
            }
            bytes_transferred += resp.body_size;
            if req.timing.total_ms > 0 {
                total_latency += req.timing.total_ms;
                latency_count += 1;
            }
        }
    }

    let avg_latency_ms = if latency_count > 0 {
        (total_latency as f64) / (latency_count as f64)
    } else {
        0.0
    };

    InspectorMetrics {
        total_requests,
        status_2xx,
        status_3xx,
        status_4xx,
        status_5xx,
        avg_latency_ms,
        bytes_transferred,
    }
}

/// Validates whether a `Host` header represents loopback to prevent DNS rebinding attacks (§14.5).
pub fn is_valid_host(host_header: &str) -> bool {
    let host = host_header.trim();
    if host.is_empty() {
        return false;
    }

    let hostname = if host.starts_with('[') {
        if let Some(end) = host.find(']') {
            &host[..=end]
        } else {
            return false;
        }
    } else {
        host.split(':').next().unwrap_or("")
    };

    hostname.eq_ignore_ascii_case("localhost") || hostname == "127.0.0.1" || hostname == "[::1]"
}

/// Checks whether an HTTP header is hop-by-hop and must be dropped during request replay.
pub fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
            | "proxy-connection"
            | "content-length"
    )
}

/// Error encountered during request replay.
#[derive(Debug, PartialEq, Eq)]
pub enum ReplayError {
    NotFound,
    TargetError(String),
    Timeout,
}

/// Executes a replay of an existing captured request against `local_target`.
pub async fn execute_replay(
    id: &str,
    store: &InspectorStore,
    local_target: SocketAddr,
) -> std::result::Result<Arc<CapturedRequest>, ReplayError> {
    let original = store.get(id).ok_or(ReplayError::NotFound)?;
    let replay_req = original.create_replay();
    let replay_id = replay_req.id.clone();
    let added = store.add_request(replay_req);

    let start_instant = std::time::Instant::now();

    let record_error = |status: u16, status_text: &str, msg: &str| {
        let total_ms = start_instant.elapsed().as_millis() as u64;
        let body = format!("{{\"error\":\"{}\"}}", msg);
        let resp_details = ResponseDetails {
            status,
            status_text: status_text.to_string(),
            headers: vec![HeaderPair::new("Content-Type", "application/json")],
            body_size: body.len(),
            body: Some(body),
            body_truncated: false,
        };
        store.record_response(&replay_id, resp_details, total_ms, total_ms);
    };

    let connect_fut = tokio::net::TcpStream::connect(local_target);
    let mut target_stream = match tokio::time::timeout(Duration::from_secs(3), connect_fut).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            let msg = format!("Connection refused: {e}");
            record_error(502, "Bad Gateway", &msg);
            return Err(ReplayError::TargetError(msg));
        }
        Err(_) => {
            let msg = "Connection to local target timed out (3s)".to_string();
            record_error(504, "Gateway Timeout", &msg);
            return Err(ReplayError::Timeout);
        }
    };

    let body_bytes = added
        .request
        .body
        .as_ref()
        .map(|b| b.as_bytes())
        .unwrap_or(&[]);

    let mut req_wire = Vec::new();
    req_wire.extend_from_slice(
        format!(
            "{} {} HTTP/1.1\r\n",
            added.request.method, added.request.path
        )
        .as_bytes(),
    );

    let mut has_host = false;
    for h in &added.request.headers {
        if is_hop_by_hop(&h.name) {
            continue;
        }
        if h.name.eq_ignore_ascii_case("host") {
            has_host = true;
        }
        req_wire.extend_from_slice(format!("{}: {}\r\n", h.name, h.value).as_bytes());
    }

    if !has_host {
        req_wire.extend_from_slice(format!("Host: {}\r\n", local_target).as_bytes());
    }

    req_wire.extend_from_slice(format!("Content-Length: {}\r\n", body_bytes.len()).as_bytes());
    req_wire.extend_from_slice(b"Connection: close\r\n\r\n");
    req_wire.extend_from_slice(body_bytes);

    if let Err(e) = target_stream.write_all(&req_wire).await {
        let msg = format!("Write failed: {e}");
        record_error(502, "Bad Gateway", &msg);
        return Err(ReplayError::TargetError(msg));
    }
    if let Err(e) = target_stream.flush().await {
        let msg = format!("Flush failed: {e}");
        record_error(502, "Bad Gateway", &msg);
        return Err(ReplayError::TargetError(msg));
    }

    let mut resp_buf = Vec::new();
    let mut first_byte = true;
    let mut ttfb_ms = 0u64;
    let mut chunk = [0u8; 8192];
    let mut header_end: Option<usize> = None;
    let mut expected_content_len: Option<usize> = None;

    loop {
        let read_fut = target_stream.read(&mut chunk);
        let n = match tokio::time::timeout(Duration::from_secs(3), read_fut).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => n,
            Ok(Err(e)) => {
                let msg = format!("Read failed: {e}");
                record_error(502, "Bad Gateway", &msg);
                return Err(ReplayError::TargetError(msg));
            }
            Err(_) => {
                let msg = "Reading response timed out (3s)".to_string();
                record_error(504, "Gateway Timeout", &msg);
                return Err(ReplayError::Timeout);
            }
        };
        if first_byte {
            ttfb_ms = start_instant.elapsed().as_millis() as u64;
            first_byte = false;
        }
        resp_buf.extend_from_slice(&chunk[..n]);

        // Incremental check: parse headers as soon as CRLF CRLF is found
        if header_end.is_none() {
            if let Some(pos) = find_crlf_crlf(&resp_buf) {
                let h_end = pos + 4;
                header_end = Some(h_end);

                let mut headers_pool = [httparse::EMPTY_HEADER; 64];
                let mut parsed = httparse::Response::new(&mut headers_pool);
                if let Ok(httparse::Status::Complete(_)) = parsed.parse(&resp_buf[..h_end]) {
                    let status = parsed.code.unwrap_or(200);
                    if status == 204 || status == 304 || (100..200).contains(&status) {
                        expected_content_len = Some(0);
                    } else {
                        for h in parsed.headers {
                            if h.name.eq_ignore_ascii_case("content-length") {
                                if let Ok(val_str) = std::str::from_utf8(h.value) {
                                    if let Ok(len) = val_str.trim().parse::<usize>() {
                                        expected_content_len = Some(len);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Early break if complete Content-Length received (fixes keep-alive hanging)
        if let (Some(h_end), Some(cl)) = (header_end, expected_content_len) {
            if resp_buf.len() >= h_end.saturating_add(cl) {
                break;
            }
        }

        // Response buffer cap: break if exceeding MAX_BODY_SIZE + MAX_HEADER_SIZE
        if resp_buf.len() >= MAX_BODY_SIZE + MAX_HEADER_SIZE {
            break;
        }
    }
    let total_ms = start_instant.elapsed().as_millis() as u64;

    let mut headers_pool = [httparse::EMPTY_HEADER; 64];
    let mut parsed = httparse::Response::new(&mut headers_pool);
    let body_start = match parsed.parse(&resp_buf) {
        Ok(httparse::Status::Complete(offset)) => offset,
        _ => {
            let msg = "Malformed HTTP response from target".to_string();
            record_error(502, "Bad Gateway", &msg);
            return Err(ReplayError::TargetError(msg));
        }
    };

    let status = parsed.code.unwrap_or(200);
    let status_text = parsed.reason.unwrap_or("OK").to_string();
    let mut headers_vec = Vec::new();
    for h in parsed.headers {
        headers_vec.push(HeaderPair::new(
            h.name.to_string(),
            String::from_utf8_lossy(h.value).into_owned(),
        ));
    }

    let body_slice = &resp_buf[body_start..];
    let (final_body_slice, truncated) = if body_slice.len() > MAX_BODY_SIZE {
        (&body_slice[..MAX_BODY_SIZE], true)
    } else {
        (body_slice, false)
    };
    let body_str = String::from_utf8_lossy(final_body_slice).into_owned();

    let resp_details = ResponseDetails {
        status,
        status_text,
        headers: headers_vec,
        body: Some(body_str),
        body_size: body_slice.len(),
        body_truncated: truncated,
    };

    let updated = store
        .record_response(&replay_id, resp_details, total_ms, ttfb_ms)
        .ok_or_else(|| {
            let msg = "Failed to record replay response".to_string();
            record_error(502, "Bad Gateway", &msg);
            ReplayError::TargetError(msg)
        })?;

    Ok(updated)
}

fn find_crlf_crlf(buf: &[u8]) -> Option<usize> {
    for i in 0..buf.len().saturating_sub(3) {
        if &buf[i..i + 4] == b"\r\n\r\n" {
            return Some(i);
        }
    }
    None
}

/// Reads a complete HTTP request (headers + body) from the stream with 5-second read timeout.
async fn read_http_request(
    stream: &mut tokio::net::TcpStream,
) -> Result<Option<(Vec<u8>, usize, usize)>> {
    let mut buffer = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    let mut header_end = None;

    while header_end.is_none() {
        if buffer.len() >= MAX_HEADER_SIZE {
            return Err(ProtoError::FrameTooLarge(
                buffer.len() as u32,
                MAX_HEADER_SIZE as u32,
            ));
        }

        let read_fut = stream.read(&mut chunk);
        let n = match tokio::time::timeout(Duration::from_secs(5), read_fut).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(ProtoError::IoError(e.to_string())),
            Err(_) => return Err(ProtoError::IoError("HTTP request read timeout".into())),
        };
        if n == 0 {
            if buffer.is_empty() {
                return Ok(None);
            }
            return Err(ProtoError::IoError("Connection closed prematurely".into()));
        }
        buffer.extend_from_slice(&chunk[..n]);
        if let Some(pos) = find_crlf_crlf(&buffer) {
            header_end = Some(pos + 4);
        }
    }

    let h_end =
        header_end.ok_or_else(|| ProtoError::IoError("Malformed HTTP header boundary".into()))?;

    let mut headers_pool = [httparse::EMPTY_HEADER; 64];
    let mut parsed = httparse::Request::new(&mut headers_pool);
    if parsed.parse(&buffer[..h_end]).is_err() {
        return Err(ProtoError::IoError("Malformed HTTP headers".into()));
    }

    let mut content_len = 0usize;
    for h in parsed.headers {
        if h.name.eq_ignore_ascii_case("content-length") {
            if let Ok(val_str) = std::str::from_utf8(h.value) {
                if let Ok(len) = val_str.trim().parse::<usize>() {
                    content_len = len;
                }
            }
        }
    }

    if content_len > MAX_BODY_SIZE {
        return Err(ProtoError::IoError("Payload too large".into()));
    }

    let target_total_len = h_end.saturating_add(content_len);
    while buffer.len() < target_total_len {
        let read_fut = stream.read(&mut chunk);
        let n = match tokio::time::timeout(Duration::from_secs(5), read_fut).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(ProtoError::IoError(e.to_string())),
            Err(_) => return Err(ProtoError::IoError("HTTP request read timeout".into())),
        };
        if n == 0 {
            return Err(ProtoError::IoError(
                "Connection closed before receiving full body".into(),
            ));
        }
        buffer.extend_from_slice(&chunk[..n]);
    }

    Ok(Some((buffer, h_end, content_len)))
}

/// Web Inspector HTTP server.
#[derive(Clone)]
pub struct InspectorServer {
    bind_addr: SocketAddr,
    actual_addr: Arc<RwLock<Option<SocketAddr>>>,
    store: Arc<InspectorStore>,
    local_target: SocketAddr,
    shutdown_notify: Arc<Notify>,
    shutdown_flag: Arc<AtomicBool>,
}

impl InspectorServer {
    /// Creates a new `InspectorServer`.
    pub fn new(
        bind_addr: SocketAddr,
        store: Arc<InspectorStore>,
        local_target: SocketAddr,
    ) -> Self {
        Self {
            bind_addr,
            actual_addr: Arc::new(RwLock::new(None)),
            store,
            local_target,
            shutdown_notify: Arc::new(Notify::new()),
            shutdown_flag: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Returns the bound socket address, if the listener has been started.
    pub fn local_addr(&self) -> Option<SocketAddr> {
        *self.actual_addr.read()
    }

    /// Returns the configured bind address.
    pub fn bind_addr(&self) -> SocketAddr {
        self.bind_addr
    }

    /// Returns the local target address.
    pub fn local_target(&self) -> SocketAddr {
        self.local_target
    }

    /// Returns a reference to the inspector store.
    pub fn store(&self) -> &Arc<InspectorStore> {
        &self.store
    }

    /// Runs the HTTP inspector server loop until shutdown is signaled.
    pub async fn run(&self) -> Result<()> {
        let listener = tokio::net::TcpListener::bind(self.bind_addr)
            .await
            .map_err(|e| ProtoError::IoError(e.to_string()))?;

        if let Ok(addr) = listener.local_addr() {
            *self.actual_addr.write() = Some(addr);
        }

        loop {
            if self.shutdown_flag.load(Ordering::SeqCst) {
                break;
            }

            tokio::select! {
                _ = self.shutdown_notify.notified() => {
                    break;
                }
                accept_res = listener.accept() => {
                    let (stream, _peer_addr) = match accept_res {
                        Ok(conn) => conn,
                        Err(e) => {
                            tracing::debug!("Inspector accept error: {e}");
                            continue;
                        }
                    };

                    let store = self.store.clone();
                    let local_target = self.local_target;
                    let shutdown_notify = self.shutdown_notify.clone();

                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream, store, local_target, shutdown_notify).await {
                            tracing::debug!("Inspector connection error: {e}");
                        }
                    });
                }
            }
        }

        Ok(())
    }

    /// Signals the inspector server to shutdown.
    pub fn shutdown(&self) {
        self.shutdown_flag.store(true, Ordering::SeqCst);
        self.shutdown_notify.notify_waiters();
    }
}

async fn handle_connection(
    mut stream: tokio::net::TcpStream,
    store: Arc<InspectorStore>,
    local_target: SocketAddr,
    shutdown_notify: Arc<Notify>,
) -> Result<()> {
    let (buffer, header_end, _body_len) = match read_http_request(&mut stream).await {
        Ok(Some(req_data)) => req_data,
        Ok(None) => return Ok(()),
        Err(e) => {
            if matches!(&e, ProtoError::IoError(msg) if msg == "Payload too large") {
                let resp = b"HTTP/1.1 413 Payload Too Large\r\nContent-Length: 22\r\nConnection: close\r\n\r\n413 Payload Too Large\n";
                let _ = stream.write_all(resp).await;
                let _ = stream.flush().await;
            } else if matches!(e, ProtoError::FrameTooLarge(_, _)) {
                let resp = b"HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Length: 36\r\nConnection: close\r\n\r\n431 Request Header Fields Too Large\n";
                let _ = stream.write_all(resp).await;
                let _ = stream.flush().await;
            } else if matches!(&e, ProtoError::IoError(msg) if msg == "Malformed HTTP headers") {
                let resp = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 16\r\nConnection: close\r\n\r\n400 Bad Request\n";
                let _ = stream.write_all(resp).await;
                let _ = stream.flush().await;
            } else if matches!(&e, ProtoError::IoError(msg) if msg == "HTTP request read timeout") {
                let resp = b"HTTP/1.1 408 Request Timeout\r\nContent-Length: 20\r\nConnection: close\r\n\r\n408 Request Timeout\n";
                let _ = stream.write_all(resp).await;
                let _ = stream.flush().await;
            }
            return Err(e);
        }
    };

    let mut headers_pool = [httparse::EMPTY_HEADER; 64];
    let mut parsed = httparse::Request::new(&mut headers_pool);
    if parsed.parse(&buffer[..header_end]).is_err() {
        let resp = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 16\r\nConnection: close\r\n\r\n400 Bad Request\n";
        let _ = stream.write_all(resp).await;
        let _ = stream.flush().await;
        return Ok(());
    }

    // DNS Rebinding Defense (§14.5): Validate Host header
    let host_header = parsed
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("host"))
        .and_then(|h| std::str::from_utf8(h.value).ok());

    match host_header {
        Some(host) if is_valid_host(host) => {}
        _ => {
            let resp = b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 28\r\nConnection: close\r\n\r\n403 Forbidden: Invalid Host\n";
            let _ = stream.write_all(resp).await;
            let _ = stream.flush().await;
            return Ok(());
        }
    }

    let method = parsed.method.unwrap_or("").to_string();
    let raw_path = parsed.path.unwrap_or("/").to_string();
    let path = raw_path.split('?').next().unwrap_or(&raw_path).to_string();

    // Route: GET / or GET /index.html
    if method == "GET" && (path == "/" || path == "/index.html") {
        let html = include_str!("../ui/index.html");
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            html.len(),
            html
        );
        stream.write_all(resp.as_bytes()).await.ok();
        stream.flush().await.ok();
        return Ok(());
    }

    // Route: GET /api/requests
    if method == "GET" && path == "/api/requests" {
        let requests = store.list(100);
        let req_refs: Vec<&CapturedRequest> = requests.iter().map(|r| &**r).collect();
        let json = serde_json::to_string(&req_refs).unwrap_or_else(|_| "[]".to_string());
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            json.len(),
            json
        );
        stream.write_all(resp.as_bytes()).await.ok();
        stream.flush().await.ok();
        return Ok(());
    }

    // Route: GET /api/requests/:id
    if method == "GET" && path.starts_with("/api/requests/") {
        let id = &path["/api/requests/".len()..];
        if let Some(req) = store.get(id) {
            let json = serde_json::to_string(&*req).unwrap_or_default();
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                json.len(),
                json
            );
            stream.write_all(resp.as_bytes()).await.ok();
            stream.flush().await.ok();
        } else {
            let err = r#"{"error":"Request not found"}"#;
            let resp = format!(
                "HTTP/1.1 404 Not Found\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                err.len(),
                err
            );
            stream.write_all(resp.as_bytes()).await.ok();
            stream.flush().await.ok();
        }
        return Ok(());
    }

    // Route: GET /api/metrics
    if method == "GET" && path == "/api/metrics" {
        let metrics = calculate_metrics(&store);
        let json = serde_json::to_string(&metrics).unwrap_or_default();
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            json.len(),
            json
        );
        stream.write_all(resp.as_bytes()).await.ok();
        stream.flush().await.ok();
        return Ok(());
    }

    // Route: GET /events (Server-Sent Events without CORS wildcard)
    if method == "GET" && path == "/events" {
        let header = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\n\r\n";
        if stream.write_all(header.as_bytes()).await.is_err() {
            return Ok(());
        }
        if stream.flush().await.is_err() {
            return Ok(());
        }

        let mut rx = store.subscribe();
        loop {
            tokio::select! {
                _ = shutdown_notify.notified() => {
                    break;
                }
                msg = rx.recv() => {
                    match msg {
                        Ok(req) => {
                            let json = serde_json::to_string(&*req).unwrap_or_default();
                            let chunk = format!("data: {}\n\n", json);
                            if stream.write_all(chunk.as_bytes()).await.is_err() {
                                break;
                            }
                            if stream.flush().await.is_err() {
                                break;
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
                _ = tokio::time::sleep(Duration::from_secs(15)) => {
                    if stream.write_all(b": ping\n\n").await.is_err() {
                        break;
                    }
                    if stream.flush().await.is_err() {
                        break;
                    }
                }
            }
        }
        return Ok(());
    }

    // Route: POST /api/replay/:id
    if method == "POST" && path.starts_with("/api/replay/") {
        let id = &path["/api/replay/".len()..];
        match execute_replay(id, &store, local_target).await {
            Ok(replayed) => {
                let json = serde_json::to_string(&*replayed).unwrap_or_default();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    json.len(),
                    json
                );
                stream.write_all(resp.as_bytes()).await.ok();
                stream.flush().await.ok();
            }
            Err(ReplayError::NotFound) => {
                let err = r#"{"error":"Request not found"}"#;
                let resp = format!(
                    "HTTP/1.1 404 Not Found\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    err.len(),
                    err
                );
                stream.write_all(resp.as_bytes()).await.ok();
                stream.flush().await.ok();
            }
            Err(ReplayError::TargetError(msg)) => {
                let err_json = serde_json::json!({ "error": msg }).to_string();
                let resp = format!(
                    "HTTP/1.1 502 Bad Gateway\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    err_json.len(),
                    err_json
                );
                stream.write_all(resp.as_bytes()).await.ok();
                stream.flush().await.ok();
            }
            Err(ReplayError::Timeout) => {
                let err_json =
                    r#"{"error":"Gateway Timeout: local target did not respond in 3 seconds"}"#;
                let resp = format!(
                    "HTTP/1.1 504 Gateway Timeout\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    err_json.len(),
                    err_json
                );
                stream.write_all(resp.as_bytes()).await.ok();
                stream.flush().await.ok();
            }
        }
        return Ok(());
    }

    // Default 404 Not Found
    let resp = b"HTTP/1.1 404 Not Found\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 13\r\nConnection: close\r\n\r\n404 Not Found";
    stream.write_all(resp).await.ok();
    stream.flush().await.ok();

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::RequestDetails;

    #[tokio::test]
    async fn test_inspector_server_endpoints_and_dns_rebinding() {
        let store = Arc::new(InspectorStore::new(100, 1024 * 1024));
        let server_probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_probe.local_addr().unwrap();
        drop(server_probe);

        let local_probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = local_probe.local_addr().unwrap();
        drop(local_probe);

        let server = Arc::new(InspectorServer::new(server_addr, store.clone(), local_addr));
        let server_clone = server.clone();
        tokio::spawn(async move {
            let _ = server_clone.run().await;
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        // 1. GET / serves embedded HTML
        let mut sock = tokio::net::TcpStream::connect(server_addr).await.unwrap();
        sock.write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            .await
            .unwrap();
        let mut resp = vec![0u8; 4096];
        let n = sock.read(&mut resp).await.unwrap();
        let resp_str = String::from_utf8_lossy(&resp[..n]);
        assert!(resp_str.contains("200 OK"));
        assert!(resp_str.contains("QuickTunnel Inspector"));

        // 2. DNS rebinding rejection (evil.com Host header)
        let mut sock2 = tokio::net::TcpStream::connect(server_addr).await.unwrap();
        sock2
            .write_all(b"GET /api/requests HTTP/1.1\r\nHost: evil.com\r\n\r\n")
            .await
            .unwrap();
        let mut resp2 = vec![0u8; 1024];
        let n2 = sock2.read(&mut resp2).await.unwrap();
        let resp2_str = String::from_utf8_lossy(&resp2[..n2]);
        assert!(resp2_str.contains("403 Forbidden"));

        server.shutdown();
    }

    #[tokio::test]
    async fn test_inspector_requests_and_details_endpoints() {
        let store = Arc::new(InspectorStore::new(100, 1024 * 1024));
        let mut req1 = CapturedRequest::new_mock("GET", "/api/v1/users");
        req1.id = "01TESTREQ00000000000000001".to_string();
        let added1 = store.add_request(req1);

        let server_probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_probe.local_addr().unwrap();
        drop(server_probe);

        let server = Arc::new(InspectorServer::new(
            server_addr,
            store.clone(),
            server_addr,
        ));
        let server_clone = server.clone();
        tokio::spawn(async move {
            let _ = server_clone.run().await;
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        // 1. GET /api/requests
        let mut sock = tokio::net::TcpStream::connect(server_addr).await.unwrap();
        sock.write_all(b"GET /api/requests HTTP/1.1\r\nHost: localhost:4040\r\n\r\n")
            .await
            .unwrap();
        let mut resp = vec![0u8; 4096];
        let n = sock.read(&mut resp).await.unwrap();
        let resp_str = String::from_utf8_lossy(&resp[..n]);
        assert!(resp_str.contains("200 OK"));
        assert!(resp_str.contains("application/json"));
        assert!(resp_str.contains("/api/v1/users"));

        // 2. GET /api/requests/:id found
        let mut sock2 = tokio::net::TcpStream::connect(server_addr).await.unwrap();
        let path = format!(
            "GET /api/requests/{} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            added1.id
        );
        sock2.write_all(path.as_bytes()).await.unwrap();
        let mut resp2 = vec![0u8; 4096];
        let n2 = sock2.read(&mut resp2).await.unwrap();
        let resp2_str = String::from_utf8_lossy(&resp2[..n2]);
        assert!(resp2_str.contains("200 OK"));
        assert!(resp2_str.contains(&added1.id));

        // 3. GET /api/requests/:id not found
        let mut sock3 = tokio::net::TcpStream::connect(server_addr).await.unwrap();
        sock3
            .write_all(b"GET /api/requests/nonexistent HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            .await
            .unwrap();
        let mut resp3 = vec![0u8; 1024];
        let n3 = sock3.read(&mut resp3).await.unwrap();
        let resp3_str = String::from_utf8_lossy(&resp3[..n3]);
        assert!(resp3_str.contains("404 Not Found"));

        server.shutdown();
    }

    #[tokio::test]
    async fn test_inspector_metrics_endpoint() {
        let store = Arc::new(InspectorStore::new(100, 1024 * 1024));

        let mut req_2xx = CapturedRequest::new_mock("GET", "/ok");
        req_2xx.id = "REQ2XX".to_string();
        store.add_request(req_2xx);
        store.record_response(
            "REQ2XX",
            ResponseDetails {
                status: 200,
                status_text: "OK".into(),
                headers: vec![],
                body: Some("ok body".into()),
                body_size: 7,
                body_truncated: false,
            },
            50,
            20,
        );

        let mut req_4xx = CapturedRequest::new_mock("POST", "/bad");
        req_4xx.id = "REQ4XX".to_string();
        req_4xx.request.body_size = 10;
        store.add_request(req_4xx);
        store.record_response(
            "REQ4XX",
            ResponseDetails {
                status: 404,
                status_text: "Not Found".into(),
                headers: vec![],
                body: Some("not found".into()),
                body_size: 9,
                body_truncated: false,
            },
            100,
            40,
        );

        let server_probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_probe.local_addr().unwrap();
        drop(server_probe);

        let server = Arc::new(InspectorServer::new(
            server_addr,
            store.clone(),
            server_addr,
        ));
        let server_clone = server.clone();
        tokio::spawn(async move {
            let _ = server_clone.run().await;
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut sock = tokio::net::TcpStream::connect(server_addr).await.unwrap();
        sock.write_all(b"GET /api/metrics HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            .await
            .unwrap();
        let mut resp = vec![0u8; 2048];
        let n = sock.read(&mut resp).await.unwrap();
        let resp_str = String::from_utf8_lossy(&resp[..n]);
        assert!(resp_str.contains("200 OK"));

        let body_pos = resp_str.find("\r\n\r\n").unwrap() + 4;
        let metrics: InspectorMetrics = serde_json::from_str(&resp_str[body_pos..]).unwrap();

        assert_eq!(metrics.total_requests, 2);
        assert_eq!(metrics.status_2xx, 1);
        assert_eq!(metrics.status_4xx, 1);
        assert_eq!(metrics.status_5xx, 0);
        assert_eq!(metrics.avg_latency_ms, 75.0); // (50 + 100) / 2
        assert_eq!(metrics.bytes_transferred, 26); // 7 + 10 + 9

        server.shutdown();
    }

    #[tokio::test]
    async fn test_inspector_sse_events_streaming() {
        let store = Arc::new(InspectorStore::new(100, 1024 * 1024));
        let server_probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_probe.local_addr().unwrap();
        drop(server_probe);

        let server = Arc::new(InspectorServer::new(
            server_addr,
            store.clone(),
            server_addr,
        ));
        let server_clone = server.clone();
        tokio::spawn(async move {
            let _ = server_clone.run().await;
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut sse_sock = tokio::net::TcpStream::connect(server_addr).await.unwrap();
        sse_sock
            .write_all(b"GET /events HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            .await
            .unwrap();

        // Check SSE response headers
        let mut buf = vec![0u8; 1024];
        let n = sse_sock.read(&mut buf).await.unwrap();
        let resp_str = String::from_utf8_lossy(&buf[..n]);
        assert!(resp_str.contains("200 OK"));
        assert!(resp_str.contains("text/event-stream"));
        assert!(!resp_str
            .to_lowercase()
            .contains("access-control-allow-origin"));

        // Emit an event to the store
        let mut new_req = CapturedRequest::new_mock("POST", "/webhook/stripe");
        new_req.id = "SSE_EVENT_001".to_string();
        store.add_request(new_req);

        // SSE client should receive the event
        let mut event_buf = vec![0u8; 2048];
        let event_n = sse_sock.read(&mut event_buf).await.unwrap();
        let event_str = String::from_utf8_lossy(&event_buf[..event_n]);
        assert!(event_str.contains("data: {"));
        assert!(event_str.contains("SSE_EVENT_001"));
        assert!(event_str.contains("/webhook/stripe"));

        server.shutdown();
    }

    #[tokio::test]
    async fn test_inspector_replay_engine() {
        // 1. Mock local target server
        let mock_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = mock_listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut socket, _) = mock_listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let n = socket.read(&mut buf).await.unwrap();
            let req_str = String::from_utf8_lossy(&buf[..n]);

            // Verify hop-by-hop headers were stripped
            assert!(!req_str.to_lowercase().contains("upgrade:"));
            assert!(!req_str.to_lowercase().contains("keep-alive:"));

            // Verify request content forwarded
            assert!(req_str.contains("POST /api/action HTTP/1.1"));
            assert!(req_str.contains("X-Custom-Header: TestVal"));
            assert!(req_str.contains("Content-Length: 14"));
            assert!(req_str.contains("{\"msg\":\"test\"}"));

            let resp = b"HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: 18\r\nConnection: close\r\n\r\n{\"status\":\"created\"}";
            socket.write_all(resp).await.unwrap();
            socket.flush().await.unwrap();
        });

        // 2. Setup InspectorServer
        let store = Arc::new(InspectorStore::new(100, 1024 * 1024));
        let server_probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_probe.local_addr().unwrap();
        drop(server_probe);

        let server = Arc::new(InspectorServer::new(server_addr, store.clone(), local_addr));
        let server_clone = server.clone();
        tokio::spawn(async move {
            let _ = server_clone.run().await;
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        // Add original request to store with hop-by-hop headers
        let orig_req = CapturedRequest {
            id: "ORIG_REQ_999".to_string(),
            visitor_ip: "10.0.0.1".to_string(),
            request: RequestDetails {
                method: "POST".into(),
                path: "/api/action".into(),
                http_version: "HTTP/1.1".into(),
                headers: vec![
                    HeaderPair::new("X-Custom-Header", "TestVal"),
                    HeaderPair::new("Connection", "upgrade"),
                    HeaderPair::new("Upgrade", "websocket"),
                    HeaderPair::new("Content-Length", "9999"), // old content-length to recalculate
                ],
                body: Some("{\"msg\":\"test\"}".into()),
                body_size: 14,
                body_truncated: false,
            },
            response: None,
            timing: crate::store::TimingDetails::default(),
            is_replay: false,
            parent_id: None,
        };
        store.add_request(orig_req);

        // 3. Trigger Replay POST /api/replay/ORIG_REQ_999
        let mut sock = tokio::net::TcpStream::connect(server_addr).await.unwrap();
        sock.write_all(b"POST /api/replay/ORIG_REQ_999 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            .await
            .unwrap();
        let mut resp_buf = vec![0u8; 4096];
        let n = sock.read(&mut resp_buf).await.unwrap();
        let resp_str = String::from_utf8_lossy(&resp_buf[..n]);

        assert!(resp_str.contains("200 OK"));
        let body_pos = resp_str.find("\r\n\r\n").unwrap() + 4;
        let replay_json: serde_json::Value = serde_json::from_str(&resp_str[body_pos..]).unwrap();
        assert_eq!(replay_json["is_replay"], true);
        assert_eq!(replay_json["parent_id"], "ORIG_REQ_999");
        assert_eq!(replay_json["response"]["status"], 201);
        assert_eq!(replay_json["response"]["body"], "{\"status\":\"created\"}");

        // Verify store now has 2 requests and replay record is present
        assert_eq!(store.count(), 2);
        let list = store.list(10);
        let replay_record = list.iter().find(|r| r.is_replay).expect("replay record");
        assert_eq!(replay_record.parent_id, Some("ORIG_REQ_999".to_string()));
        let resp_details = replay_record.response.as_ref().unwrap();
        assert_eq!(resp_details.status, 201);
        assert_eq!(
            resp_details.body.as_deref(),
            Some("{\"status\":\"created\"}")
        );

        // 4. Test Replay of Non-existent request returns 404
        let mut sock_404 = tokio::net::TcpStream::connect(server_addr).await.unwrap();
        sock_404
            .write_all(b"POST /api/replay/NONEXISTENT HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            .await
            .unwrap();
        let mut resp_404 = vec![0u8; 1024];
        let n_404 = sock_404.read(&mut resp_404).await.unwrap();
        let str_404 = String::from_utf8_lossy(&resp_404[..n_404]);
        assert!(str_404.contains("404 Not Found"));

        server.shutdown();
    }

    #[tokio::test]
    async fn test_inspector_replay_target_offline_returns_502() {
        let store = Arc::new(InspectorStore::new(100, 1024 * 1024));
        let unused_target: SocketAddr = "127.0.0.1:29999".parse().unwrap();

        let server_probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_probe.local_addr().unwrap();
        drop(server_probe);

        let server = Arc::new(InspectorServer::new(
            server_addr,
            store.clone(),
            unused_target,
        ));
        let server_clone = server.clone();
        tokio::spawn(async move {
            let _ = server_clone.run().await;
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        let orig_req = CapturedRequest::new_mock("GET", "/ping");
        let added = store.add_request(orig_req);

        let mut sock = tokio::net::TcpStream::connect(server_addr).await.unwrap();
        let path = format!(
            "POST /api/replay/{} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            added.id
        );
        sock.write_all(path.as_bytes()).await.unwrap();

        let mut resp = vec![0u8; 1024];
        let n = sock.read(&mut resp).await.unwrap();
        let resp_str = String::from_utf8_lossy(&resp[..n]);
        assert!(resp_str.contains("502 Bad Gateway"));

        // Verify synthetic 502 response was recorded in store (no orphaned Pending... records)
        assert_eq!(store.count(), 2);
        let list = store.list(10);
        let replay_record = list.iter().find(|r| r.is_replay).expect("replay record");
        let resp = replay_record
            .response
            .as_ref()
            .expect("synthetic error response");
        assert_eq!(resp.status, 502);

        server.shutdown();
    }

    #[tokio::test]
    async fn test_replay_keep_alive_target_breaks_early() {
        let mock_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = mock_listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut socket, _) = mock_listener.accept().await.unwrap();
            let mut buf = vec![0u8; 1024];
            let _ = socket.read(&mut buf).await.unwrap();

            // Send full response with Content-Length, but DO NOT close socket (keep-alive)
            let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
            socket.write_all(resp).await.unwrap();
            socket.flush().await.unwrap();

            // Sleep without closing socket
            tokio::time::sleep(Duration::from_secs(5)).await;
        });

        let store = Arc::new(InspectorStore::new(100, 1024 * 1024));
        let orig_req = CapturedRequest::new_mock("GET", "/keepalive");
        let added = store.add_request(orig_req);

        let server_probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_probe.local_addr().unwrap();
        drop(server_probe);

        let server = Arc::new(InspectorServer::new(server_addr, store.clone(), local_addr));
        let server_clone = server.clone();
        tokio::spawn(async move {
            let _ = server_clone.run().await;
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        let start = std::time::Instant::now();
        let mut sock = tokio::net::TcpStream::connect(server_addr).await.unwrap();
        let path = format!(
            "POST /api/replay/{} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            added.id
        );
        sock.write_all(path.as_bytes()).await.unwrap();

        let mut resp = vec![0u8; 2048];
        let n = sock.read(&mut resp).await.unwrap();
        let elapsed = start.elapsed();

        let resp_str = String::from_utf8_lossy(&resp[..n]);
        assert!(resp_str.contains("200 OK"));
        // Must complete promptly without hanging for 3s target timeout
        assert!(elapsed < Duration::from_secs(2));

        server.shutdown();
    }

    #[test]
    fn test_is_valid_host_matrix() {
        assert!(is_valid_host("localhost"));
        assert!(is_valid_host("LOCALHOST"));
        assert!(is_valid_host("localhost:4040"));
        assert!(is_valid_host("127.0.0.1"));
        assert!(is_valid_host("127.0.0.1:4040"));
        assert!(is_valid_host("[::1]"));
        assert!(is_valid_host("[::1]:4040"));

        assert!(!is_valid_host("evil.com"));
        assert!(!is_valid_host("evil.com:4040"));
        assert!(!is_valid_host("localhost.attacker.com"));
        assert!(!is_valid_host("127.0.0.1.attacker.com"));
        assert!(!is_valid_host(""));
        assert!(!is_valid_host("[::2]"));
        assert!(!is_valid_host("[malformed"));
    }

    #[test]
    fn test_is_hop_by_hop_matrix() {
        assert!(is_hop_by_hop("Connection"));
        assert!(is_hop_by_hop("keep-alive"));
        assert!(is_hop_by_hop("Upgrade"));
        assert!(is_hop_by_hop("Transfer-Encoding"));
        assert!(is_hop_by_hop("Content-Length"));
        assert!(is_hop_by_hop("te"));
        assert!(is_hop_by_hop("trailer"));
        assert!(is_hop_by_hop("proxy-connection"));

        assert!(!is_hop_by_hop("Host"));
        assert!(!is_hop_by_hop("User-Agent"));
        assert!(!is_hop_by_hop("Authorization"));
        assert!(!is_hop_by_hop("Content-Type"));
    }

    #[tokio::test]
    async fn test_inspector_shutdown_and_accessors() {
        let store = Arc::new(InspectorStore::new(100, 1024 * 1024));
        let server_probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_probe.local_addr().unwrap();
        drop(server_probe);

        let target_addr: SocketAddr = "127.0.0.1:3000".parse().unwrap();
        let server = InspectorServer::new(server_addr, store.clone(), target_addr);

        assert_eq!(server.bind_addr(), server_addr);
        assert_eq!(server.local_target(), target_addr);
        assert_eq!(server.store().capacity(), 100);
        assert!(server.local_addr().is_none());

        let server_clone = server.clone();
        let handle = tokio::spawn(async move { server_clone.run().await });

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(server.local_addr(), Some(server_addr));

        server.shutdown();
        let res = handle.await.unwrap();
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_unknown_path_returns_404() {
        let store = Arc::new(InspectorStore::new(100, 1024 * 1024));
        let server_probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_probe.local_addr().unwrap();
        drop(server_probe);

        let server = Arc::new(InspectorServer::new(
            server_addr,
            store.clone(),
            server_addr,
        ));
        let server_clone = server.clone();
        tokio::spawn(async move {
            let _ = server_clone.run().await;
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut sock = tokio::net::TcpStream::connect(server_addr).await.unwrap();
        sock.write_all(b"GET /unknown/route HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            .await
            .unwrap();
        let mut resp = vec![0u8; 1024];
        let n = sock.read(&mut resp).await.unwrap();
        let resp_str = String::from_utf8_lossy(&resp[..n]);
        assert!(resp_str.contains("404 Not Found"));

        server.shutdown();
    }

    #[tokio::test]
    async fn test_index_html_and_query_params() {
        let store = Arc::new(InspectorStore::new(100, 1024 * 1024));
        let server_probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_probe.local_addr().unwrap();
        drop(server_probe);

        let server = Arc::new(InspectorServer::new(
            server_addr,
            store.clone(),
            server_addr,
        ));
        let server_clone = server.clone();
        tokio::spawn(async move {
            let _ = server_clone.run().await;
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        // 1. GET /index.html
        let mut sock = tokio::net::TcpStream::connect(server_addr).await.unwrap();
        sock.write_all(b"GET /index.html HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            .await
            .unwrap();
        let mut resp = vec![0u8; 4096];
        let n = sock.read(&mut resp).await.unwrap();
        let resp_str = String::from_utf8_lossy(&resp[..n]);
        assert!(resp_str.contains("200 OK"));
        assert!(resp_str.contains("QuickTunnel Inspector"));

        // 2. GET /api/requests?limit=10 with query param
        let mut sock2 = tokio::net::TcpStream::connect(server_addr).await.unwrap();
        sock2
            .write_all(b"GET /api/requests?limit=10 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            .await
            .unwrap();
        let mut resp2 = vec![0u8; 1024];
        let n2 = sock2.read(&mut resp2).await.unwrap();
        let resp2_str = String::from_utf8_lossy(&resp2[..n2]);
        assert!(resp2_str.contains("200 OK"));
        assert!(resp2_str.contains("[]"));

        server.shutdown();
    }

    #[tokio::test]
    async fn test_oversized_headers_and_malformed_requests() {
        let store = Arc::new(InspectorStore::new(100, 1024 * 1024));
        let server_probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_probe.local_addr().unwrap();
        drop(server_probe);

        let server = Arc::new(InspectorServer::new(
            server_addr,
            store.clone(),
            server_addr,
        ));
        let server_clone = server.clone();
        tokio::spawn(async move {
            let _ = server_clone.run().await;
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        // 1. Oversized headers (> 16 KiB) -> 431
        let mut sock = tokio::net::TcpStream::connect(server_addr).await.unwrap();
        let large_header = "A".repeat(17000);
        let req = format!(
            "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Large: {}\r\n\r\n",
            large_header
        );
        sock.write_all(req.as_bytes()).await.unwrap();
        let mut resp = vec![0u8; 1024];
        let n = sock.read(&mut resp).await.unwrap();
        let resp_str = String::from_utf8_lossy(&resp[..n]);
        assert!(resp_str.contains("431 Request Header Fields Too Large"));

        // 2. Malformed request line -> 400 Bad Request
        let mut sock2 = tokio::net::TcpStream::connect(server_addr).await.unwrap();
        sock2
            .write_all(b"INVALID HTTP REQUEST LINE\r\nHost: 127.0.0.1\r\n\r\n")
            .await
            .unwrap();
        let mut resp2 = vec![0u8; 1024];
        let n2 = sock2.read(&mut resp2).await.unwrap();
        let resp2_str = String::from_utf8_lossy(&resp2[..n2]);
        assert!(resp2_str.contains("400 Bad Request"));

        // 3. Premature EOF (connect and drop)
        let sock3 = tokio::net::TcpStream::connect(server_addr).await.unwrap();
        drop(sock3);

        server.shutdown();
    }

    #[tokio::test]
    async fn test_replay_target_malformed_response() {
        // Mock listener returning garbage HTTP response
        let mock_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = mock_listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut socket, _) = mock_listener.accept().await.unwrap();
            let mut buf = vec![0u8; 1024];
            let _ = socket.read(&mut buf).await.unwrap();
            socket.write_all(b"NOT HTTP AT ALL\r\n\r\n").await.unwrap();
            socket.flush().await.unwrap();
        });

        let store = Arc::new(InspectorStore::new(100, 1024 * 1024));
        let mut orig_req = CapturedRequest::new_mock("GET", "/test");
        orig_req.request.headers.clear(); // test without host header
        let added = store.add_request(orig_req);

        let server_probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_probe.local_addr().unwrap();
        drop(server_probe);

        let server = Arc::new(InspectorServer::new(server_addr, store.clone(), local_addr));
        let server_clone = server.clone();
        tokio::spawn(async move {
            let _ = server_clone.run().await;
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut sock = tokio::net::TcpStream::connect(server_addr).await.unwrap();
        let path = format!(
            "POST /api/replay/{} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            added.id
        );
        sock.write_all(path.as_bytes()).await.unwrap();

        let mut resp = vec![0u8; 1024];
        let n = sock.read(&mut resp).await.unwrap();
        let resp_str = String::from_utf8_lossy(&resp[..n]);
        assert!(resp_str.contains("502 Bad Gateway"));

        server.shutdown();
    }

    #[test]
    fn test_calculate_metrics_comprehensive() {
        let store = InspectorStore::new(100, 1024 * 1024);

        // Empty store
        let m0 = calculate_metrics(&store);
        assert_eq!(m0.total_requests, 0);
        assert_eq!(m0.avg_latency_ms, 0.0);
        assert_eq!(m0.bytes_transferred, 0);

        // Add 3xx and 5xx requests
        let mut req_3xx = CapturedRequest::new_mock("GET", "/redirect");
        req_3xx.id = "R3XX".into();
        store.add_request(req_3xx);
        store.record_response(
            "R3XX",
            ResponseDetails {
                status: 302,
                status_text: "Found".into(),
                headers: vec![],
                body: None,
                body_size: 0,
                body_truncated: false,
            },
            20,
            10,
        );

        let mut req_5xx = CapturedRequest::new_mock("GET", "/error");
        req_5xx.id = "R5XX".into();
        store.add_request(req_5xx);
        store.record_response(
            "R5XX",
            ResponseDetails {
                status: 500,
                status_text: "Internal Error".into(),
                headers: vec![],
                body: Some("server err".into()),
                body_size: 10,
                body_truncated: false,
            },
            40,
            20,
        );

        let m = calculate_metrics(&store);
        assert_eq!(m.total_requests, 2);
        assert_eq!(m.status_3xx, 1);
        assert_eq!(m.status_5xx, 1);
        assert_eq!(m.avg_latency_ms, 30.0); // (20 + 40) / 2
        assert_eq!(m.bytes_transferred, 10);
    }

    #[tokio::test]
    async fn test_oversized_body_and_incomplete_body() {
        let store = Arc::new(InspectorStore::new(100, 1024 * 1024));
        let server_probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_probe.local_addr().unwrap();
        drop(server_probe);

        let server = Arc::new(InspectorServer::new(
            server_addr,
            store.clone(),
            server_addr,
        ));
        let server_clone = server.clone();
        tokio::spawn(async move {
            let _ = server_clone.run().await;
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        // 1. Content-Length > MAX_BODY_SIZE (2 MiB)
        let mut sock = tokio::net::TcpStream::connect(server_addr).await.unwrap();
        sock.write_all(
            b"POST /api/action HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 3000000\r\n\r\n",
        )
        .await
        .unwrap();
        let mut resp = vec![0u8; 1024];
        let n = sock.read(&mut resp).await.unwrap();
        let resp_str = String::from_utf8_lossy(&resp[..n]);
        assert!(resp_str.contains("413 Payload Too Large"));

        // 2. Incomplete body (Content-Length: 100, sent 10 bytes then closed)
        let mut sock2 = tokio::net::TcpStream::connect(server_addr).await.unwrap();
        sock2.write_all(b"POST /api/action HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 100\r\n\r\n1234567890")
            .await
            .unwrap();
        drop(sock2); // close stream prematurely

        server.shutdown();
    }
}
