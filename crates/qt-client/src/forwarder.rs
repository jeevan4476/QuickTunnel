//! Local forwarder & HTTP header rewriter
//!
//! Accepts inbound virtual streams dispatched by `MuxHandle::accept_stream()`,
//! rewrites HTTP `Host` headers or forwards transparent raw TCP to local target listeners,
//! handles bidirectional splicing, and generates branded 502 Bad Gateway error pages
//! if the local target is unreachable or dial times out.

use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use qt_inspector_ui::tap::HttpTapSender;
use qt_mux::MuxHandle;
use qt_proto::{ProtoError, Result, TunnelMode};

use crate::config::HostHeaderRewrite;

/// Maximum HTTP request headers size (8 KiB)
pub const MAX_HEADER_SIZE: usize = 8192;

/// Default connect dial timeout to local target (§12.2)
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// Local forwarder proxying multiplexed streams to a local service.
#[derive(Clone, Debug)]
pub struct LocalForwarder {
    local_target: SocketAddr,
    mode: TunnelMode,
    host_header: HostHeaderRewrite,
    connect_timeout: Duration,
    tap: Option<HttpTapSender>,
}

impl LocalForwarder {
    /// Create a new `LocalForwarder`.
    pub fn new(local_target: SocketAddr, mode: TunnelMode, host_header: HostHeaderRewrite) -> Self {
        Self {
            local_target,
            mode,
            host_header,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            tap: None,
        }
    }

    /// Set custom dial timeout for connecting to local target.
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Attach an optional HTTP tap pipeline for inspecting traffic.
    pub fn with_tap(mut self, tap: HttpTapSender) -> Self {
        self.tap = Some(tap);
        self
    }

    /// Configured HTTP tap pipeline, if any.
    pub fn tap(&self) -> Option<&HttpTapSender> {
        self.tap.as_ref()
    }

    /// Configured local target address.
    pub fn local_target(&self) -> SocketAddr {
        self.local_target
    }

    /// Configured tunnel mode.
    pub fn mode(&self) -> TunnelMode {
        self.mode
    }

    /// Configured Host header rewrite policy.
    pub fn host_header(&self) -> &HostHeaderRewrite {
        &self.host_header
    }

    /// Configured local dial timeout.
    pub fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    /// Forward a single stream to `local_target`.
    pub async fn forward_stream<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
        &self,
        mut stream: S,
    ) -> Result<()> {
        if self.mode == TunnelMode::Tcp {
            let connect_fut = tokio::net::TcpStream::connect(self.local_target);
            let mut local_socket =
                match tokio::time::timeout(self.connect_timeout, connect_fut).await {
                    Ok(Ok(s)) => {
                        s.set_nodelay(true).ok();
                        s
                    }
                    Ok(Err(e)) => {
                        tracing::warn!(
                            "Failed to connect to local target {}: {}",
                            self.local_target,
                            e
                        );
                        return Err(ProtoError::IoError(format!(
                            "Failed to connect to local target {}: {e}",
                            self.local_target
                        )));
                    }
                    Err(_) => {
                        tracing::warn!(
                            "Timeout connecting to local target {} (after {:?})",
                            self.local_target,
                            self.connect_timeout
                        );
                        return Err(ProtoError::IoError(format!(
                            "Timeout connecting to local target {}",
                            self.local_target
                        )));
                    }
                };

            tokio::io::copy_bidirectional(&mut stream, &mut local_socket)
                .await
                .map_err(|e| ProtoError::IoError(e.to_string()))?;

            return Ok(());
        }

        // HTTP mode: read headers, rewrite Host header, proxy and splice
        let (buffer, header_end) = match read_http_headers(&mut stream).await {
            Ok(res) => res,
            Err(e) => {
                if matches!(e, ProtoError::FrameTooLarge(_, _)) {
                    let resp = b"HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\nContent-Length: 36\r\n\r\n431 Request Header Fields Too Large\n";
                    stream.write_all(resp).await.ok();
                    stream.flush().await.ok();
                }
                return Err(e);
            }
        };

        let visitor_ip = extract_visitor_ip(&buffer);
        let tap_req_id = if let Some(ref tap) = self.tap {
            tap.tap_request(visitor_ip, &buffer)
        } else {
            None
        };
        let req_start_time = tokio::time::Instant::now();

        let replacement = self.host_header.resolve_host(&self.local_target);
        let rewritten_bytes = match rewrite_http_headers(
            &buffer,
            header_end,
            replacement.as_deref(),
        ) {
            Ok(b) => b,
            Err(e) => {
                let resp = b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 25\r\n\r\n400 Bad Request: invalid\n";
                stream.write_all(resp).await.ok();
                stream.flush().await.ok();
                return Err(e);
            }
        };

        // Connect to local service with dial timeout (§12.2)
        let connect_fut = tokio::net::TcpStream::connect(self.local_target);
        let mut local_socket = match tokio::time::timeout(self.connect_timeout, connect_fut).await {
            Ok(Ok(s)) => {
                s.set_nodelay(true).ok();
                s
            }
            Ok(Err(e)) => {
                tracing::warn!(
                    "Failed to connect to local target {}: {}",
                    self.local_target,
                    e
                );
                let bad_gw = format_502_bad_gateway(&self.local_target);
                if let (Some(tap), Some(id)) = (&self.tap, &tap_req_id) {
                    tap.tap_response(id.clone(), &bad_gw, req_start_time.elapsed());
                }
                stream
                    .write_all(&bad_gw)
                    .await
                    .map_err(|err| ProtoError::IoError(err.to_string()))?;
                stream
                    .flush()
                    .await
                    .map_err(|err| ProtoError::IoError(err.to_string()))?;
                return Ok(());
            }
            Err(_) => {
                tracing::warn!(
                    "Timeout connecting to local target {} (after {:?})",
                    self.local_target,
                    self.connect_timeout
                );
                let bad_gw = format_502_bad_gateway(&self.local_target);
                if let (Some(tap), Some(id)) = (&self.tap, &tap_req_id) {
                    tap.tap_response(id.clone(), &bad_gw, req_start_time.elapsed());
                }
                stream
                    .write_all(&bad_gw)
                    .await
                    .map_err(|err| ProtoError::IoError(err.to_string()))?;
                stream
                    .flush()
                    .await
                    .map_err(|err| ProtoError::IoError(err.to_string()))?;
                return Ok(());
            }
        };

        // Write rewritten headers (and any pre-buffered body bytes) to local service
        local_socket
            .write_all(&rewritten_bytes)
            .await
            .map_err(|e| ProtoError::IoError(e.to_string()))?;
        local_socket
            .flush()
            .await
            .map_err(|e| ProtoError::IoError(e.to_string()))?;

        let initial_body_len = buffer.len().saturating_sub(header_end + 4);
        if let (Some(tap), Some(id)) = (self.tap.clone(), tap_req_id) {
            forward_and_tap_response(
                stream,
                local_socket,
                tap,
                id,
                req_start_time,
                initial_body_len,
            )
            .await?;
        } else {
            // Splice bidirectionally
            tokio::io::copy_bidirectional(&mut stream, &mut local_socket)
                .await
                .map_err(|e| ProtoError::IoError(e.to_string()))?;
        }

        Ok(())
    }

    /// Continuously accept streams from `mux_handle` and forward them.
    pub async fn run_loop(&self, mux_handle: MuxHandle) -> Result<()> {
        while let Some(stream) = mux_handle.accept_stream().await {
            let forwarder = self.clone();
            tokio::spawn(async move {
                if let Err(e) = forwarder.forward_stream(stream).await {
                    tracing::debug!("Local forwarder stream error: {}", e);
                }
            });
        }
        Ok(())
    }
}

/// Generate branded HTTP 502 Bad Gateway response page
pub fn format_502_bad_gateway(local_target: &SocketAddr) -> Vec<u8> {
    let body = format!(
        "<!DOCTYPE html>\n\
        <html lang=\"en\">\n\
        <head>\n\
        <meta charset=\"utf-8\">\n\
        <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n\
        <title>502 Bad Gateway - QuickTunnel</title>\n\
        <style>\n\
        body {{ font-family: -apple-system, BlinkMacSystemFont, \"Segoe UI\", Roboto, Helvetica, Arial, sans-serif; background: #0f172a; color: #f8fafc; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; padding: 1rem; box-sizing: border-box; }}\n\
        .card {{ background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 2rem; max-width: 480px; width: 100%; text-align: center; box-shadow: 0 10px 15px -3px rgba(0,0,0,0.3); }}\n\
        h1 {{ color: #ef4444; margin-top: 0; font-size: 1.75rem; }}\n\
        p {{ color: #94a3b8; line-height: 1.5; margin: 0.5rem 0; }}\n\
        .code {{ background: #0f172a; padding: 0.5rem 1rem; border-radius: 4px; font-family: monospace; font-size: 0.875rem; color: #38bdf8; margin: 1.25rem 0; word-break: break-all; }}\n\
        .footer {{ font-size: 0.75rem; color: #64748b; margin-top: 1.5rem; border-top: 1px solid #334155; padding-top: 1rem; }}\n\
        </style>\n\
        </head>\n\
        <body>\n\
        <div class=\"card\">\n\
        <h1>502 Bad Gateway</h1>\n\
        <p>QuickTunnel was unable to reach the local target service.</p>\n\
        <div class=\"code\">Target: {local_target}</div>\n\
        <p>Make sure your local server is running and listening on this address.</p>\n\
        <div class=\"footer\">QuickTunnel Proxy</div>\n\
        </div>\n\
        </body>\n\
        </html>\n"
    );

    format!(
        "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    )
    .into_bytes()
}

/// Forwards traffic bidirectionally while capturing response bytes and calculating TTFB and total duration for the HTTP tap.
async fn forward_and_tap_response<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    stream: S,
    mut local_socket: tokio::net::TcpStream,
    tap: HttpTapSender,
    req_id: String,
    req_start_time: tokio::time::Instant,
    initial_body_len: usize,
) -> Result<()> {
    let (mut stream_r, mut stream_w) = tokio::io::split(stream);
    let (mut local_r, mut local_w) = local_socket.split();

    let req_id_c2l = req_id.clone();
    let tap_c2l = tap.clone();
    let client_to_local = async {
        let mut buf = [0u8; 8192];
        let mut captured_total = initial_body_len;
        let mut res = Ok(());
        loop {
            match stream_r.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if captured_total < qt_inspector_ui::tap::MAX_BODY_CAPTURE_SIZE {
                        let to_capture =
                            n.min(qt_inspector_ui::tap::MAX_BODY_CAPTURE_SIZE - captured_total);
                        tap_c2l.tap_request_body_chunk(req_id_c2l.clone(), &buf[..to_capture]);
                        captured_total += to_capture;
                    }
                    if let Err(e) = local_w.write_all(&buf[..n]).await {
                        res = Err(e);
                        break;
                    }
                }
                Err(e) => {
                    res = Err(e);
                    break;
                }
            }
        }
        let _ = local_w.shutdown().await;
        res
    };

    let local_to_client = async {
        const MAX_CAPTURE: usize = 1024 * 1024 + 16384;
        let mut captured_bytes = Vec::new();
        let mut ttfb: Option<Duration> = None;
        let mut buf = [0u8; 8192];
        let mut res = Ok(());

        let mut parsed_headers = false;
        let mut expected_response_len: Option<usize> = None;
        let mut response_tapped = false;
        let mut total_transferred: usize = 0;

        loop {
            match local_r.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if ttfb.is_none() {
                        ttfb = Some(req_start_time.elapsed());
                    }
                    total_transferred += n;
                    if captured_bytes.len() < MAX_CAPTURE {
                        let to_take = n.min(MAX_CAPTURE - captured_bytes.len());
                        captured_bytes.extend_from_slice(&buf[..to_take]);
                    }
                    if let Err(e) = stream_w.write_all(&buf[..n]).await {
                        res = Err(e);
                        break;
                    }

                    // Check for headers end and Content-Length
                    if !parsed_headers {
                        if let Some(crlf_pos) = find_crlf_crlf(&captured_bytes) {
                            parsed_headers = true;
                            let header_end_offset = crlf_pos + 4;
                            let mut headers = [httparse::EMPTY_HEADER; 64];
                            let mut resp = httparse::Response::new(&mut headers);
                            if let Ok(httparse::Status::Complete(_)) = resp.parse(&captured_bytes) {
                                if let Some(h) = resp
                                    .headers
                                    .iter()
                                    .find(|h| h.name.eq_ignore_ascii_case("Content-Length"))
                                {
                                    if let Ok(s) = std::str::from_utf8(h.value) {
                                        if let Ok(cl) = s.trim().parse::<usize>() {
                                            expected_response_len = Some(header_end_offset + cl);
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // If expected total response bytes reached, trigger tap immediately
                    if let Some(expected_len) = expected_response_len {
                        if total_transferred >= expected_len {
                            if !response_tapped && !captured_bytes.is_empty() {
                                let total_duration = req_start_time.elapsed();
                                let ttfb_duration = ttfb.unwrap_or(total_duration);
                                tap.tap_response_with_ttfb(
                                    req_id.clone(),
                                    &captured_bytes,
                                    total_duration,
                                    ttfb_duration,
                                );
                                response_tapped = true;
                            }
                            let _ = stream_w.flush().await;
                            break;
                        }
                    }
                }
                Err(e) => {
                    res = Err(e);
                    break;
                }
            }
        }
        let _ = stream_w.flush().await;
        let _ = stream_w.shutdown().await;

        let total_duration = req_start_time.elapsed();
        let ttfb_duration = ttfb.unwrap_or(total_duration);
        if !response_tapped && !captured_bytes.is_empty() {
            tap.tap_response_with_ttfb(req_id, &captured_bytes, total_duration, ttfb_duration);
        }

        res
    };

    tokio::pin!(client_to_local);
    tokio::pin!(local_to_client);

    tokio::select! {
        c2l = &mut client_to_local => {
            if let Err(e) = c2l {
                tracing::debug!("client_to_local finished with error: {e}");
            }
            let _ = local_to_client.await;
        }
        l2c = &mut local_to_client => {
            if let Err(e) = l2c {
                tracing::debug!("local_to_client finished with error: {e}");
            }
        }
    }

    Ok(())
}

/// Extract visitor IP from X-Forwarded-For header, falling back to 127.0.0.1:0.
fn extract_visitor_ip(buffer: &[u8]) -> SocketAddr {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);
    if let Ok(httparse::Status::Complete(_)) = req.parse(buffer) {
        for h in req.headers {
            if h.name.eq_ignore_ascii_case("X-Forwarded-For") {
                if let Ok(val) = std::str::from_utf8(h.value) {
                    if let Some(first_ip) = val.split(',').next() {
                        let trimmed = first_ip.trim();
                        if let Ok(addr) = trimmed.parse::<SocketAddr>() {
                            return addr;
                        }
                        if let Ok(ip) = trimmed.parse::<std::net::IpAddr>() {
                            return SocketAddr::new(ip, 0);
                        }
                    }
                }
            }
        }
    }
    SocketAddr::from(([127, 0, 0, 1], 0))
}

/// Find index of `\r\n\r\n` header delimiter
fn find_crlf_crlf(buf: &[u8]) -> Option<usize> {
    for i in 0..buf.len().saturating_sub(3) {
        if &buf[i..i + 4] == b"\r\n\r\n" {
            return Some(i);
        }
    }
    None
}

/// Read HTTP headers from stream until `\r\n\r\n` boundary
async fn read_http_headers<S: AsyncRead + Unpin>(io: &mut S) -> Result<(Vec<u8>, usize)> {
    let mut buffer = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];

    loop {
        if let Some(pos) = find_crlf_crlf(&buffer) {
            if pos + 4 > MAX_HEADER_SIZE {
                return Err(ProtoError::FrameTooLarge(
                    (pos + 4) as u32,
                    MAX_HEADER_SIZE as u32,
                ));
            }
            return Ok((buffer, pos));
        }

        if buffer.len() >= MAX_HEADER_SIZE {
            return Err(ProtoError::FrameTooLarge(
                buffer.len() as u32,
                MAX_HEADER_SIZE as u32,
            ));
        }

        let n = io
            .read(&mut chunk)
            .await
            .map_err(|e| ProtoError::IoError(e.to_string()))?;
        if n == 0 {
            if buffer.is_empty() {
                return Err(ProtoError::IoError(
                    "Stream closed before sending request".into(),
                ));
            }
            return Err(ProtoError::IoError(
                "Stream closed before completing HTTP headers".into(),
            ));
        }
        buffer.extend_from_slice(&chunk[..n]);
    }
}

/// Parse and rewrite HTTP Host and Connection headers according to rewrite policy
pub fn rewrite_http_headers(
    buffer: &[u8],
    header_end: usize,
    new_host: Option<&str>,
) -> Result<Vec<u8>> {
    let mut headers = [httparse::EMPTY_HEADER; 128];
    let mut req = httparse::Request::new(&mut headers);
    let status = req
        .parse(&buffer[..header_end + 4])
        .map_err(|e| ProtoError::ProtocolError(format!("HTTP parse error: {e}")))?;

    if !status.is_complete() {
        return Err(ProtoError::ProtocolError("Incomplete HTTP headers".into()));
    }

    let host_count = req
        .headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case("Host"))
        .count();
    if host_count > 1 {
        return Err(ProtoError::ProtocolError(
            "Multiple Host headers in request".into(),
        ));
    }

    let new_host = match new_host {
        Some(h) => {
            // Header injection prevention: validate no CR or LF in host
            if h.contains('\r') || h.contains('\n') {
                return Err(ProtoError::ProtocolError(
                    "Host header contains newline characters".into(),
                ));
            }
            Some(h)
        }
        None => None,
    };

    let buf_base = buffer.as_ptr() as usize;

    let find_header_line_range = |h: &httparse::Header| {
        let name_start = h.name.as_ptr() as usize - buf_base;
        let val_end = (h.value.as_ptr() as usize - buf_base) + h.value.len();

        let line_start = buffer[..name_start]
            .iter()
            .rposition(|&b| b == b'\n')
            .map(|p| p + 1)
            .unwrap_or(0);

        let line_end = buffer[val_end..header_end + 4]
            .iter()
            .position(|&b| b == b'\n')
            .map(|p| val_end + p + 1)
            .unwrap_or(header_end + 4);

        (line_start, line_end)
    };

    let mut replacements: Vec<(usize, usize, Vec<u8>)> = Vec::new();

    let host_header = req
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("Host"));

    let mut need_append_host: Option<&str> = None;
    if let Some(host_val) = new_host {
        if let Some(h) = host_header {
            let (start, end) = find_header_line_range(h);
            replacements.push((start, end, format!("Host: {host_val}\r\n").into_bytes()));
        } else {
            need_append_host = Some(host_val);
        }
    }

    let mut connection_headers = req
        .headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case("Connection"));

    if let Some(first_conn) = connection_headers.next() {
        let (start, end) = find_header_line_range(first_conn);
        replacements.push((start, end, b"Connection: close\r\n".to_vec()));

        for extra_conn in connection_headers {
            let (start, end) = find_header_line_range(extra_conn);
            replacements.push((start, end, Vec::new()));
        }
    }

    if replacements.is_empty() && need_append_host.is_none() {
        return Ok(buffer.to_vec());
    }

    replacements.sort_by_key(|&(start, _, _)| start);

    let mut rewritten = Vec::with_capacity(buffer.len() + 64);
    let mut cur = 0;
    for (start, end, repl) in replacements {
        if start > cur {
            rewritten.extend_from_slice(&buffer[cur..start]);
        }
        rewritten.extend_from_slice(&repl);
        cur = end;
    }

    if let Some(host_val) = need_append_host {
        if cur < header_end {
            rewritten.extend_from_slice(&buffer[cur..header_end]);
        }
        rewritten.extend_from_slice(b"\r\nHost: ");
        rewritten.extend_from_slice(host_val.as_bytes());
        rewritten.extend_from_slice(b"\r\n\r\n");
        if buffer.len() > header_end + 4 {
            rewritten.extend_from_slice(&buffer[header_end + 4..]);
        }
    } else if cur < buffer.len() {
        rewritten.extend_from_slice(&buffer[cur..]);
    }

    Ok(rewritten)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const TEST_TIMEOUT: Duration = Duration::from_secs(5);

    #[tokio::test]
    async fn test_forwarder_http_host_rewrite() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut socket, _) = tokio::time::timeout(TEST_TIMEOUT, listener.accept())
                .await
                .unwrap()
                .unwrap();
            let mut buf = vec![0u8; 1024];
            let n = tokio::time::timeout(TEST_TIMEOUT, socket.read(&mut buf))
                .await
                .unwrap()
                .unwrap();
            let req_str = String::from_utf8_lossy(&buf[..n]);
            assert!(req_str.contains(&format!("Host: 127.0.0.1:{}", local_addr.port())));
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\npong")
                .await
                .unwrap();
        });

        let forwarder =
            LocalForwarder::new(local_addr, TunnelMode::Http, HostHeaderRewrite::Rewrite);

        assert_eq!(forwarder.local_target(), local_addr);
        assert_eq!(forwarder.mode(), TunnelMode::Http);
        assert_eq!(forwarder.host_header(), &HostHeaderRewrite::Rewrite);
        assert_eq!(forwarder.connect_timeout(), DEFAULT_CONNECT_TIMEOUT);

        let (mut visitor_stream, mux_stream) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            forwarder.forward_stream(mux_stream).await.unwrap();
        });

        // Visitor sends request with public domain
        visitor_stream
            .write_all(b"GET / HTTP/1.1\r\nHost: myapp.tunnel.example.com\r\n\r\n")
            .await
            .unwrap();

        let mut resp = vec![0u8; 1024];
        let n = tokio::time::timeout(TEST_TIMEOUT, visitor_stream.read(&mut resp))
            .await
            .unwrap()
            .unwrap();
        assert!(String::from_utf8_lossy(&resp[..n]).contains("200 OK"));
        assert!(String::from_utf8_lossy(&resp[..n]).contains("pong"));
    }

    #[tokio::test]
    async fn test_forwarder_http_host_preserve() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut socket, _) = tokio::time::timeout(TEST_TIMEOUT, listener.accept())
                .await
                .unwrap()
                .unwrap();
            let mut buf = vec![0u8; 1024];
            let n = tokio::time::timeout(TEST_TIMEOUT, socket.read(&mut buf))
                .await
                .unwrap()
                .unwrap();
            let req_str = String::from_utf8_lossy(&buf[..n]);
            assert!(req_str.contains("Host: myapp.tunnel.example.com"));
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await
                .unwrap();
        });

        let forwarder =
            LocalForwarder::new(local_addr, TunnelMode::Http, HostHeaderRewrite::Preserve);

        let (mut visitor_stream, mux_stream) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            forwarder.forward_stream(mux_stream).await.unwrap();
        });

        visitor_stream
            .write_all(b"GET /preserved HTTP/1.1\r\nHost: myapp.tunnel.example.com\r\n\r\n")
            .await
            .unwrap();

        let mut resp = vec![0u8; 1024];
        let n = tokio::time::timeout(TEST_TIMEOUT, visitor_stream.read(&mut resp))
            .await
            .unwrap()
            .unwrap();
        assert!(String::from_utf8_lossy(&resp[..n]).contains("200 OK"));
    }

    #[tokio::test]
    async fn test_forwarder_http_host_custom() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut socket, _) = tokio::time::timeout(TEST_TIMEOUT, listener.accept())
                .await
                .unwrap()
                .unwrap();
            let mut buf = vec![0u8; 1024];
            let n = tokio::time::timeout(TEST_TIMEOUT, socket.read(&mut buf))
                .await
                .unwrap()
                .unwrap();
            let req_str = String::from_utf8_lossy(&buf[..n]);
            assert!(req_str.contains("Host: custom.internal.domain"));
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await
                .unwrap();
        });

        let forwarder = LocalForwarder::new(
            local_addr,
            TunnelMode::Http,
            HostHeaderRewrite::Custom("custom.internal.domain".into()),
        );

        let (mut visitor_stream, mux_stream) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            forwarder.forward_stream(mux_stream).await.unwrap();
        });

        visitor_stream
            .write_all(b"GET /custom HTTP/1.1\r\nHost: public.tunnel.com\r\n\r\n")
            .await
            .unwrap();

        let mut resp = vec![0u8; 1024];
        let n = tokio::time::timeout(TEST_TIMEOUT, visitor_stream.read(&mut resp))
            .await
            .unwrap()
            .unwrap();
        assert!(String::from_utf8_lossy(&resp[..n]).contains("200 OK"));
    }

    #[tokio::test]
    async fn test_forwarder_local_service_down_returns_502() {
        let closed_addr: SocketAddr = "127.0.0.1:54329".parse().unwrap();
        let forwarder =
            LocalForwarder::new(closed_addr, TunnelMode::Http, HostHeaderRewrite::Rewrite);

        let (mut visitor_stream, mux_stream) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            let _ = forwarder.forward_stream(mux_stream).await;
        });

        visitor_stream
            .write_all(b"GET / HTTP/1.1\r\nHost: demo.example.com\r\n\r\n")
            .await
            .unwrap();

        let mut resp = vec![0u8; 1024];
        let n = tokio::time::timeout(TEST_TIMEOUT, visitor_stream.read(&mut resp))
            .await
            .unwrap()
            .unwrap();
        let resp_str = String::from_utf8_lossy(&resp[..n]);
        assert!(resp_str.contains("502 Bad Gateway"));
        assert!(resp_str.contains("QuickTunnel"));
        assert!(resp_str.contains("<!DOCTYPE html>"));
    }

    #[tokio::test]
    async fn test_forwarder_local_dial_timeout_http_returns_502() {
        // Use non-routable TEST-NET-1 IP with a short timeout to trigger dial timeout
        let blackhole_addr: SocketAddr = "192.0.2.1:1234".parse().unwrap();
        let forwarder =
            LocalForwarder::new(blackhole_addr, TunnelMode::Http, HostHeaderRewrite::Rewrite)
                .with_connect_timeout(Duration::from_millis(50));

        assert_eq!(forwarder.connect_timeout(), Duration::from_millis(50));

        let (mut visitor_stream, mux_stream) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            let _ = forwarder.forward_stream(mux_stream).await;
        });

        visitor_stream
            .write_all(b"GET /timeout HTTP/1.1\r\nHost: demo.example.com\r\n\r\n")
            .await
            .unwrap();

        let mut resp = vec![0u8; 4096];
        let n = tokio::time::timeout(TEST_TIMEOUT, visitor_stream.read(&mut resp))
            .await
            .unwrap()
            .unwrap();
        let resp_str = String::from_utf8_lossy(&resp[..n]);
        assert!(resp_str.contains("502 Bad Gateway"));
        assert!(resp_str.contains("QuickTunnel"));
        assert!(resp_str.contains("Target: 192.0.2.1:1234"));
    }

    #[tokio::test]
    async fn test_forwarder_local_dial_timeout_tcp_returns_error() {
        let blackhole_addr: SocketAddr = "192.0.2.1:1234".parse().unwrap();
        let forwarder =
            LocalForwarder::new(blackhole_addr, TunnelMode::Tcp, HostHeaderRewrite::Rewrite)
                .with_connect_timeout(Duration::from_millis(50));

        let (_visitor_stream, mux_stream) = tokio::io::duplex(4096);
        let res = forwarder.forward_stream(mux_stream).await;
        assert!(res.is_err());
        let err_msg = res.unwrap_err().to_string();
        assert!(err_msg.contains("Timeout connecting to local target"));
    }

    #[tokio::test]
    async fn test_forwarder_tcp_mode_proxying() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut socket, _) = tokio::time::timeout(TEST_TIMEOUT, listener.accept())
                .await
                .unwrap()
                .unwrap();
            let mut buf = vec![0u8; 1024];
            let n = tokio::time::timeout(TEST_TIMEOUT, socket.read(&mut buf))
                .await
                .unwrap()
                .unwrap();
            // Echo raw bytes back
            socket.write_all(&buf[..n]).await.unwrap();
        });

        let forwarder =
            LocalForwarder::new(local_addr, TunnelMode::Tcp, HostHeaderRewrite::Rewrite);

        let (mut visitor_stream, mux_stream) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            forwarder.forward_stream(mux_stream).await.unwrap();
        });

        let payload = b"\x01\x02\x03\x04\xff\xfe\xfd";
        visitor_stream.write_all(payload).await.unwrap();

        let mut resp = vec![0u8; 1024];
        let n = tokio::time::timeout(TEST_TIMEOUT, visitor_stream.read(&mut resp))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&resp[..n], payload);
    }

    #[tokio::test]
    async fn test_forwarder_tcp_mode_unreachable_target() {
        let closed_addr: SocketAddr = "127.0.0.1:54329".parse().unwrap();
        let forwarder =
            LocalForwarder::new(closed_addr, TunnelMode::Tcp, HostHeaderRewrite::Rewrite);

        let (_visitor_stream, mux_stream) = tokio::io::duplex(4096);
        let res = forwarder.forward_stream(mux_stream).await;
        assert!(res.is_err());
        assert!(matches!(res.unwrap_err(), ProtoError::IoError(_)));
    }

    #[tokio::test]
    async fn test_forwarder_header_size_limit_exceeded() {
        let forwarder = LocalForwarder::new(
            "127.0.0.1:8080".parse().unwrap(),
            TunnelMode::Http,
            HostHeaderRewrite::Rewrite,
        );

        let (mut visitor_stream, mux_stream) = tokio::io::duplex(16384);
        let forward_task = tokio::spawn(async move { forwarder.forward_stream(mux_stream).await });

        // Send > 8 KiB headers without CRLF CRLF
        let huge_header = "X-Padding: ".to_string() + &"a".repeat(8500) + "\r\n";
        visitor_stream
            .write_all(format!("GET / HTTP/1.1\r\n{huge_header}").as_bytes())
            .await
            .unwrap();

        let res = tokio::time::timeout(TEST_TIMEOUT, forward_task)
            .await
            .unwrap()
            .unwrap();
        assert!(res.is_err());
        assert!(matches!(res.unwrap_err(), ProtoError::FrameTooLarge(_, _)));

        // Expect 431 response written back
        let mut resp = vec![0u8; 1024];
        let n = tokio::time::timeout(TEST_TIMEOUT, visitor_stream.read(&mut resp))
            .await
            .unwrap()
            .unwrap();
        let resp_str = String::from_utf8_lossy(&resp[..n]);
        assert!(resp_str.contains("431 Request Header Fields Too Large"));
    }

    #[tokio::test]
    async fn test_forwarder_header_boundary_exact_limit() {
        let forwarder = LocalForwarder::new(
            "127.0.0.1:8080".parse().unwrap(),
            TunnelMode::Http,
            HostHeaderRewrite::Rewrite,
        );

        let (mut visitor_stream, mux_stream) = tokio::io::duplex(16384);
        let forward_task = tokio::spawn(async move { forwarder.forward_stream(mux_stream).await });

        // Construct request where \r\n\r\n ends exactly at 8193 (> MAX_HEADER_SIZE 8192)
        let padding = "b".repeat(8170);
        let request = format!("GET / HTTP/1.1\r\nX: {padding}\r\n\r\n");
        assert_eq!(request.len(), 8193);

        visitor_stream.write_all(request.as_bytes()).await.unwrap();

        let res = tokio::time::timeout(TEST_TIMEOUT, forward_task)
            .await
            .unwrap()
            .unwrap();
        assert!(res.is_err());
        assert!(matches!(res.unwrap_err(), ProtoError::FrameTooLarge(_, _)));
    }

    #[tokio::test]
    async fn test_forwarder_http_post_with_body() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut socket, _) = tokio::time::timeout(TEST_TIMEOUT, listener.accept())
                .await
                .unwrap()
                .unwrap();
            let mut buf = vec![0u8; 1024];
            let n = tokio::time::timeout(TEST_TIMEOUT, socket.read(&mut buf))
                .await
                .unwrap()
                .unwrap();
            let req_str = String::from_utf8_lossy(&buf[..n]);
            assert!(req_str.contains("POST /submit HTTP/1.1"));
            assert!(req_str.contains(&format!("Host: 127.0.0.1:{}", local_addr.port())));
            assert!(req_str.contains("hello world body"));
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nreceived")
                .await
                .unwrap();
        });

        let forwarder =
            LocalForwarder::new(local_addr, TunnelMode::Http, HostHeaderRewrite::Rewrite);

        let (mut visitor_stream, mux_stream) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            forwarder.forward_stream(mux_stream).await.unwrap();
        });

        visitor_stream
            .write_all(
                b"POST /submit HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 16\r\n\r\nhello world body",
            )
            .await
            .unwrap();

        let mut resp = vec![0u8; 1024];
        let n = tokio::time::timeout(TEST_TIMEOUT, visitor_stream.read(&mut resp))
            .await
            .unwrap()
            .unwrap();
        assert!(String::from_utf8_lossy(&resp[..n]).contains("received"));
    }

    #[tokio::test]
    async fn test_forwarder_http_missing_host_header_inserts_host() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut socket, _) = tokio::time::timeout(TEST_TIMEOUT, listener.accept())
                .await
                .unwrap()
                .unwrap();
            let mut buf = vec![0u8; 1024];
            let n = tokio::time::timeout(TEST_TIMEOUT, socket.read(&mut buf))
                .await
                .unwrap()
                .unwrap();
            let req_str = String::from_utf8_lossy(&buf[..n]);
            assert!(req_str.contains(&format!("Host: 127.0.0.1:{}", local_addr.port())));
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await
                .unwrap();
        });

        let forwarder =
            LocalForwarder::new(local_addr, TunnelMode::Http, HostHeaderRewrite::Rewrite);

        let (mut visitor_stream, mux_stream) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            forwarder.forward_stream(mux_stream).await.unwrap();
        });

        // HTTP request without Host header
        visitor_stream
            .write_all(b"GET /nohost HTTP/1.0\r\n\r\n")
            .await
            .unwrap();

        let mut resp = vec![0u8; 1024];
        let n = tokio::time::timeout(TEST_TIMEOUT, visitor_stream.read(&mut resp))
            .await
            .unwrap()
            .unwrap();
        assert!(String::from_utf8_lossy(&resp[..n]).contains("200 OK"));
    }

    #[tokio::test]
    async fn test_forwarder_http_malformed_request_returns_400() {
        let forwarder = LocalForwarder::new(
            "127.0.0.1:8080".parse().unwrap(),
            TunnelMode::Http,
            HostHeaderRewrite::Rewrite,
        );

        let (mut visitor_stream, mux_stream) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            let _ = forwarder.forward_stream(mux_stream).await;
        });

        // Malformed HTTP request
        visitor_stream
            .write_all(b"NOT_A_VALID_HTTP_REQUEST\r\n\r\n")
            .await
            .unwrap();

        let mut resp = vec![0u8; 1024];
        let n = tokio::time::timeout(TEST_TIMEOUT, visitor_stream.read(&mut resp))
            .await
            .unwrap()
            .unwrap();
        let resp_str = String::from_utf8_lossy(&resp[..n]);
        assert!(resp_str.contains("400 Bad Request"));
    }

    #[tokio::test]
    async fn test_forwarder_http_multiple_host_headers_returns_400() {
        let forwarder = LocalForwarder::new(
            "127.0.0.1:8080".parse().unwrap(),
            TunnelMode::Http,
            HostHeaderRewrite::Rewrite,
        );

        let (mut visitor_stream, mux_stream) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            let _ = forwarder.forward_stream(mux_stream).await;
        });

        visitor_stream
            .write_all(b"GET / HTTP/1.1\r\nHost: a.com\r\nHost: b.com\r\n\r\n")
            .await
            .unwrap();

        let mut resp = vec![0u8; 1024];
        let n = tokio::time::timeout(TEST_TIMEOUT, visitor_stream.read(&mut resp))
            .await
            .unwrap()
            .unwrap();
        let resp_str = String::from_utf8_lossy(&resp[..n]);
        assert!(resp_str.contains("400 Bad Request"));
    }

    #[tokio::test]
    async fn test_forwarder_http_host_header_injection_prevented() {
        let forwarder = LocalForwarder::new(
            "127.0.0.1:8080".parse().unwrap(),
            TunnelMode::Http,
            HostHeaderRewrite::Custom("bad.com\r\nInjected: malicious".into()),
        );

        let (mut visitor_stream, mux_stream) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            let _ = forwarder.forward_stream(mux_stream).await;
        });

        visitor_stream
            .write_all(b"GET / HTTP/1.1\r\nHost: normal.com\r\n\r\n")
            .await
            .unwrap();

        let mut resp = vec![0u8; 1024];
        let n = tokio::time::timeout(TEST_TIMEOUT, visitor_stream.read(&mut resp))
            .await
            .unwrap()
            .unwrap();
        let resp_str = String::from_utf8_lossy(&resp[..n]);
        assert!(resp_str.contains("400 Bad Request"));
    }

    #[tokio::test]
    async fn test_forwarder_stream_early_close() {
        let forwarder = LocalForwarder::new(
            "127.0.0.1:8080".parse().unwrap(),
            TunnelMode::Http,
            HostHeaderRewrite::Rewrite,
        );

        let (visitor_stream, mux_stream) = tokio::io::duplex(4096);
        drop(visitor_stream); // Close immediately

        let res = forwarder.forward_stream(mux_stream).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_forwarder_stream_partial_headers_close() {
        let forwarder = LocalForwarder::new(
            "127.0.0.1:8080".parse().unwrap(),
            TunnelMode::Http,
            HostHeaderRewrite::Rewrite,
        );

        let (mut visitor_stream, mux_stream) = tokio::io::duplex(4096);
        let forward_task = tokio::spawn(async move { forwarder.forward_stream(mux_stream).await });

        // Send partial request then close
        visitor_stream
            .write_all(b"GET /partial HTTP/1.1\r\nHost: partial")
            .await
            .unwrap();
        drop(visitor_stream);

        let res = tokio::time::timeout(TEST_TIMEOUT, forward_task)
            .await
            .unwrap()
            .unwrap();
        assert!(res.is_err());
        assert!(matches!(res.unwrap_err(), ProtoError::IoError(_)));
    }

    #[tokio::test]
    async fn test_rewrite_http_headers_helpers() {
        // Test rewrite_http_headers directly
        let raw = b"GET / HTTP/1.1\r\nHost: old.com\r\n\r\nbody";
        let end = find_crlf_crlf(raw).unwrap();
        let rewritten = rewrite_http_headers(raw, end, Some("new.com")).unwrap();
        assert_eq!(
            String::from_utf8_lossy(&rewritten),
            "GET / HTTP/1.1\r\nHost: new.com\r\n\r\nbody"
        );

        // Test with no Host header and body
        let raw_nohost = b"GET / HTTP/1.0\r\n\r\nbody";
        let end_nohost = find_crlf_crlf(raw_nohost).unwrap();
        let rewritten_nohost =
            rewrite_http_headers(raw_nohost, end_nohost, Some("injected.com")).unwrap();
        assert_eq!(
            String::from_utf8_lossy(&rewritten_nohost),
            "GET / HTTP/1.0\r\nHost: injected.com\r\n\r\nbody"
        );

        // Test with preserve (new_host = None)
        let preserved = rewrite_http_headers(raw, end, None).unwrap();
        assert_eq!(preserved, raw);

        // Test newline injection rejection
        let err_cr = rewrite_http_headers(raw, end, Some("bad.com\r\nBad: val"));
        assert!(err_cr.is_err());
        assert!(matches!(err_cr.unwrap_err(), ProtoError::ProtocolError(_)));

        let err_lf = rewrite_http_headers(raw, end, Some("bad.com\nBad: val"));
        assert!(err_lf.is_err());

        // Test incomplete headers error
        let incomplete = b"GET / HTTP/1.1\r\nHost: old.com";
        let err = rewrite_http_headers(incomplete, incomplete.len() - 4, Some("new.com"));
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn test_forwarder_run_loop_accepts_and_proxies() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 1024];
                    let n = socket.read(&mut buf).await.unwrap();
                    let req_str = String::from_utf8_lossy(&buf[..n]);
                    assert!(req_str.contains("GET /ping"));
                    socket
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\npong")
                        .await
                        .unwrap();
                });
            }
        });

        let forwarder =
            LocalForwarder::new(local_addr, TunnelMode::Http, HostHeaderRewrite::Rewrite);

        // Create MuxSession pair
        let (mux_client_io, mux_server_io) = tokio::io::duplex(65536);
        let (server_session, server_handle) =
            qt_mux::MuxSession::new(mux_server_io, qt_mux::MuxConfig::server());
        let (client_session, client_handle) =
            qt_mux::MuxSession::new(mux_client_io, qt_mux::MuxConfig::client());
        tokio::spawn(server_session.run());
        tokio::spawn(client_session.run());

        // Spawn run_loop with client_handle
        let forwarder_clone = forwarder.clone();
        let loop_handle = client_handle.clone();
        let run_task = tokio::spawn(async move { forwarder_clone.run_loop(loop_handle).await });

        // Server opens stream 1 to client
        let mut stream1 = server_handle.open_stream().await.unwrap();
        stream1
            .write_all(b"GET /ping HTTP/1.1\r\nHost: visitor.domain.com\r\n\r\n")
            .await
            .unwrap();

        let mut resp1 = vec![0u8; 1024];
        let n1 = tokio::time::timeout(TEST_TIMEOUT, stream1.read(&mut resp1))
            .await
            .unwrap()
            .unwrap();
        assert!(String::from_utf8_lossy(&resp1[..n1]).contains("pong"));

        // Server opens stream 2 to client
        let mut stream2 = server_handle.open_stream().await.unwrap();
        stream2
            .write_all(b"GET /ping HTTP/1.1\r\nHost: visitor2.domain.com\r\n\r\n")
            .await
            .unwrap();

        let mut resp2 = vec![0u8; 1024];
        let n2 = tokio::time::timeout(TEST_TIMEOUT, stream2.read(&mut resp2))
            .await
            .unwrap()
            .unwrap();
        assert!(String::from_utf8_lossy(&resp2[..n2]).contains("pong"));

        // Close client session to end run_loop
        client_handle.close().await.unwrap();
        let run_res = tokio::time::timeout(TEST_TIMEOUT, run_task)
            .await
            .unwrap()
            .unwrap();
        assert!(run_res.is_ok());
    }

    #[tokio::test]
    async fn test_forwarder_with_tap_http_success() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = vec![0u8; 1024];
                let _ = socket.read(&mut buf).await.unwrap();
                socket
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\ntapped pong")
                    .await
                    .unwrap();
            }
        });

        let store = std::sync::Arc::new(qt_inspector_ui::InspectorStore::new(100, 1024 * 1024));
        let (tap, _handle) = qt_inspector_ui::HttpTapSender::new(store.clone());

        let forwarder =
            LocalForwarder::new(local_addr, TunnelMode::Http, HostHeaderRewrite::Rewrite)
                .with_tap(tap);

        let (mut client_stream, server_stream) = tokio::io::duplex(4096);
        let fwd_task = tokio::spawn(async move { forwarder.forward_stream(server_stream).await });

        client_stream
            .write_all(b"GET /tapped HTTP/1.1\r\nHost: myapp.com\r\nX-Forwarded-For: 198.51.100.25\r\n\r\n")
            .await
            .unwrap();

        let mut resp = vec![0u8; 1024];
        let n = client_stream.read(&mut resp).await.unwrap();
        let resp_str = String::from_utf8_lossy(&resp[..n]);
        assert!(resp_str.contains("tapped pong"));

        fwd_task.await.unwrap().unwrap();

        // Allow background tap actor to process
        tokio::time::sleep(Duration::from_millis(30)).await;

        let list = store.list(100);
        assert_eq!(list.len(), 1);
        let captured = &list[0];
        assert_eq!(captured.request.method, "GET");
        assert_eq!(captured.request.path, "/tapped");
        assert_eq!(captured.visitor_ip, "198.51.100.25");
        let resp = captured
            .response
            .as_ref()
            .expect("response must be captured");
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body.as_deref(), Some("tapped pong"));
    }

    #[tokio::test]
    async fn test_forwarder_with_tap_502_bad_gateway() {
        // Closed port
        let closed_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed_addr = closed_listener.local_addr().unwrap();
        drop(closed_listener);

        let store = std::sync::Arc::new(qt_inspector_ui::InspectorStore::new(100, 1024 * 1024));
        let (tap, _handle) = qt_inspector_ui::HttpTapSender::new(store.clone());

        let forwarder =
            LocalForwarder::new(closed_addr, TunnelMode::Http, HostHeaderRewrite::Rewrite)
                .with_tap(tap);

        let (mut client_stream, server_stream) = tokio::io::duplex(4096);
        let fwd_task = tokio::spawn(async move { forwarder.forward_stream(server_stream).await });

        client_stream
            .write_all(b"GET /fail HTTP/1.1\r\nHost: fail.com\r\n\r\n")
            .await
            .unwrap();

        let mut resp = vec![0u8; 1024];
        let n = client_stream.read(&mut resp).await.unwrap();
        let resp_str = String::from_utf8_lossy(&resp[..n]);
        assert!(resp_str.contains("502 Bad Gateway"));

        fwd_task.await.unwrap().unwrap();

        tokio::time::sleep(Duration::from_millis(30)).await;

        let list = store.list(100);
        assert_eq!(list.len(), 1);
        let captured = &list[0];
        assert_eq!(captured.request.path, "/fail");
        let resp = captured
            .response
            .as_ref()
            .expect("502 response must be captured");
        assert_eq!(resp.status, 502);
    }

    #[tokio::test]
    async fn test_forwarder_tap_accessors() {
        let dummy_addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let forwarder =
            LocalForwarder::new(dummy_addr, TunnelMode::Http, HostHeaderRewrite::Rewrite);
        assert!(forwarder.tap().is_none());

        let store = std::sync::Arc::new(qt_inspector_ui::InspectorStore::new(100, 1024 * 1024));
        let (tap, _handle) = qt_inspector_ui::HttpTapSender::new(store);
        let forwarder_with_tap = forwarder.with_tap(tap);
        assert!(forwarder_with_tap.tap().is_some());
    }

    #[tokio::test]
    async fn test_rewrite_http_headers_connection_header() {
        // Rewrite Connection: keep-alive to Connection: close
        let raw = b"GET /keepalive HTTP/1.1\r\nHost: old.com\r\nConnection: keep-alive\r\n\r\n";
        let end = find_crlf_crlf(raw).unwrap();
        let rewritten = rewrite_http_headers(raw, end, Some("new.com")).unwrap();
        let s = String::from_utf8_lossy(&rewritten);
        assert!(s.contains("Host: new.com\r\n"));
        assert!(s.contains("Connection: close\r\n"));
        assert!(!s.contains("keep-alive"));

        // Multiple Connection headers collapsed to single Connection: close
        let raw_multi = b"GET /multi HTTP/1.1\r\nHost: old.com\r\nConnection: keep-alive\r\nConnection: Upgrade\r\n\r\n";
        let end_multi = find_crlf_crlf(raw_multi).unwrap();
        let rewritten_multi = rewrite_http_headers(raw_multi, end_multi, None).unwrap();
        let s_multi = String::from_utf8_lossy(&rewritten_multi);
        assert_eq!(s_multi.matches("Connection: close").count(), 1);
        assert!(!s_multi.contains("Upgrade"));
    }

    #[tokio::test]
    async fn test_forwarder_keep_alive_response_notifies_tap_without_eof() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = listener.local_addr().unwrap();

        // Local server responds with Content-Length but keeps socket open (does NOT close)
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = vec![0u8; 1024];
                let _ = socket.read(&mut buf).await.unwrap();
                socket
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: keep-alive\r\n\r\nquick")
                    .await
                    .unwrap();
                socket.flush().await.unwrap();
                // Sleep long time to simulate persistent keep-alive connection
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        });

        let store = std::sync::Arc::new(qt_inspector_ui::InspectorStore::new(100, 1024 * 1024));
        let (tap, _handle) = qt_inspector_ui::HttpTapSender::new(store.clone());

        let forwarder =
            LocalForwarder::new(local_addr, TunnelMode::Http, HostHeaderRewrite::Rewrite)
                .with_tap(tap);

        let (mut client_stream, server_stream) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            let _ = forwarder.forward_stream(server_stream).await;
        });

        client_stream
            .write_all(b"GET /ka HTTP/1.1\r\nHost: ka.example.com\r\n\r\n")
            .await
            .unwrap();

        // Read response
        let mut resp = vec![0u8; 1024];
        let n = tokio::time::timeout(Duration::from_millis(500), client_stream.read(&mut resp))
            .await
            .expect("must read response quickly")
            .unwrap();
        assert!(String::from_utf8_lossy(&resp[..n]).contains("quick"));

        // Tap should be notified immediately without waiting for the 10s sleep
        let mut captured = None;
        for _ in 0..20 {
            tokio::time::sleep(Duration::from_millis(20)).await;
            let list = store.list(10);
            if !list.is_empty() && list[0].response.is_some() {
                captured = Some(list[0].clone());
                break;
            }
        }

        let req = captured.expect("tap must capture response without waiting for socket EOF");
        let r = req.response.as_ref().unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.body.as_deref(), Some("quick"));
    }

    #[tokio::test]
    async fn test_forwarder_large_body_capture_across_chunks() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = listener.local_addr().unwrap();

        // 32 KiB payload
        let body_size = 32 * 1024;
        let large_body = vec![b'Z'; body_size];
        let large_body_clone = large_body.clone();

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut received = Vec::new();
                let mut buf = vec![0u8; 8192];
                while received.len() < body_size {
                    let n = socket.read(&mut buf).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    received.extend_from_slice(&buf[..n]);
                }
                socket
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK",
                    )
                    .await
                    .unwrap();
            }
        });

        let store =
            std::sync::Arc::new(qt_inspector_ui::InspectorStore::new(100, 10 * 1024 * 1024));
        let (tap, _handle) = qt_inspector_ui::HttpTapSender::new(store.clone());

        let forwarder =
            LocalForwarder::new(local_addr, TunnelMode::Http, HostHeaderRewrite::Rewrite)
                .with_tap(tap);

        let (mut client_stream, server_stream) = tokio::io::duplex(65536);
        tokio::spawn(async move {
            let _ = forwarder.forward_stream(server_stream).await;
        });

        // Write headers with Content-Length
        let req_header = format!(
            "POST /large HTTP/1.1\r\nHost: upload.com\r\nContent-Length: {}\r\n\r\n",
            body_size
        );
        client_stream
            .write_all(req_header.as_bytes())
            .await
            .unwrap();

        // Write body in multiple 4 KiB chunks
        for chunk in large_body_clone.chunks(4096) {
            client_stream.write_all(chunk).await.unwrap();
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        let mut resp = vec![0u8; 1024];
        let _ = tokio::time::timeout(Duration::from_secs(2), client_stream.read(&mut resp))
            .await
            .unwrap()
            .unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;
        let list = store.list(10);
        assert_eq!(list.len(), 1);
        let captured = &list[0];
        assert_eq!(captured.request.body_size, body_size);
        assert!(!captured.request.body_truncated);
        assert_eq!(
            captured.request.body.as_ref().map(|b| b.len()),
            Some(body_size)
        );
    }
}
