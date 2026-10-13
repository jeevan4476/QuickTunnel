//! Public HTTP visitor edge proxy

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use qt_proto::{ProtoError, Result};

use crate::registry::TunnelRegistry;

/// Maximum HTTP request headers size (8 KiB)
pub const MAX_HEADER_SIZE: usize = 8192;

/// Slowloris read timeout on public HTTP listener
pub const DEFAULT_SLOWLORIS_TIMEOUT: Duration = Duration::from_secs(10);

/// Edge HTTP proxy routing public HTTP visitor requests to target tunnels
#[derive(Clone)]
pub struct HttpProxy {
    bind_addr: SocketAddr,
    registry: Arc<TunnelRegistry>,
    root_domain: String,
    read_timeout: Duration,
}

impl HttpProxy {
    /// Create a new HttpProxy
    pub fn new(bind_addr: SocketAddr, registry: Arc<TunnelRegistry>, root_domain: String) -> Self {
        Self {
            bind_addr,
            registry,
            root_domain,
            read_timeout: DEFAULT_SLOWLORIS_TIMEOUT,
        }
    }

    /// Set read timeout for Slowloris protection
    pub fn with_read_timeout(mut self, timeout: Duration) -> Self {
        self.read_timeout = timeout;
        self
    }

    /// Bind address
    pub fn bind_addr(&self) -> SocketAddr {
        self.bind_addr
    }

    /// Root domain
    pub fn root_domain(&self) -> &str {
        &self.root_domain
    }

    /// Run the public HTTP listener accept loop
    pub async fn run(&self) -> Result<()> {
        let listener = tokio::net::TcpListener::bind(self.bind_addr)
            .await
            .map_err(|e| ProtoError::IoError(e.to_string()))?;

        loop {
            let (socket, peer_addr) = listener
                .accept()
                .await
                .map_err(|e| ProtoError::IoError(e.to_string()))?;
            socket.set_nodelay(true).ok();

            let this = self.clone();
            tokio::spawn(async move {
                if let Err(e) = this.handle_visitor(socket, peer_addr).await {
                    tracing::debug!("HTTP visitor proxy error: {}", e);
                }
            });
        }
    }

    /// Handle an incoming visitor connection
    pub async fn handle_visitor<T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static>(
        &self,
        mut visitor_io: T,
        peer_addr: SocketAddr,
    ) -> Result<()> {
        let mut initial_read = true;
        let mut leftover = Vec::new();

        loop {
            let timeout = if initial_read {
                self.read_timeout
            } else {
                Duration::from_secs(5)
            };

            let read_headers_fut = read_http_headers_with_leftover(&mut visitor_io, leftover);
            let (buffer, header_end) = match tokio::time::timeout(timeout, read_headers_fut).await {
                Ok(Ok(res)) => res,
                Ok(Err(e)) => {
                    if !initial_read
                        && matches!(e, ProtoError::IoError(ref s) if s.contains("Visitor closed connection"))
                    {
                        return Ok(());
                    }
                    if matches!(e, ProtoError::FrameTooLarge(_, _)) {
                        let resp = b"HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\nContent-Length: 36\r\n\r\n431 Request Header Fields Too Large\n";
                        visitor_io.write_all(resp).await.ok();
                        visitor_io.flush().await.ok();
                    }
                    return Err(e);
                }
                Err(_) => {
                    if !initial_read {
                        return Ok(());
                    }
                    let resp = b"HTTP/1.1 408 Request Timeout\r\nConnection: close\r\nContent-Length: 21\r\n\r\n408 Request Timeout\n";
                    visitor_io.write_all(resp).await.ok();
                    visitor_io.flush().await.ok();
                    return Err(ProtoError::ProtocolError("HTTP header read timeout".into()));
                }
            };
            initial_read = false;

            // Parse HTTP request headers using httparse
            let mut headers = [httparse::EMPTY_HEADER; 64];
            let mut req = httparse::Request::new(&mut headers);
            if let Err(e) = req.parse(&buffer[..header_end + 4]) {
                let resp = b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 25\r\n\r\n400 Bad Request: invalid\n";
                visitor_io.write_all(resp).await.ok();
                visitor_io.flush().await.ok();
                return Err(ProtoError::ProtocolError(format!("HTTP parse error: {e}")));
            }

            let is_http_11 = req.version.unwrap_or(1) == 1;
            let mut client_close = false;
            let mut client_keepalive = false;
            let mut req_content_length: Option<usize> = None;

            for h in req.headers.iter() {
                if h.name.eq_ignore_ascii_case("Connection") {
                    if let Ok(val) = std::str::from_utf8(h.value) {
                        let lower = val.to_ascii_lowercase();
                        if lower.contains("close") {
                            client_close = true;
                        }
                        if lower.contains("keep-alive") {
                            client_keepalive = true;
                        }
                    }
                } else if h.name.eq_ignore_ascii_case("Content-Length") {
                    if let Ok(val) = std::str::from_utf8(h.value) {
                        if let Ok(cl) = val.trim().parse::<usize>() {
                            req_content_length = Some(cl);
                        }
                    }
                }
            }

            let visitor_wants_keepalive = if is_http_11 {
                !client_close
            } else {
                client_keepalive
            };

            // Find Host header
            let host_val = req
                .headers
                .iter()
                .find(|h| h.name.eq_ignore_ascii_case("Host"))
                .and_then(|h| std::str::from_utf8(h.value).ok());

            let host = match host_val {
                Some(h) => h,
                None => {
                    let resp = b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 30\r\n\r\n400 Bad Request: missing Host\n";
                    visitor_io.write_all(resp).await.ok();
                    visitor_io.flush().await.ok();
                    return Err(ProtoError::ProtocolError("Missing Host header".into()));
                }
            };

            let subdomain = extract_subdomain(host, &self.root_domain);
            let tunnel_opt = match subdomain.as_deref() {
                Some(s) => self.registry.find_http(s),
                None => self.registry.find_single_http(),
            };
            let tunnel = match tunnel_opt {
                Some(entry) => entry,
                None => {
                    let body = "404 Not Found: tunnel not found\n";
                    let resp = format!(
                        "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    visitor_io.write_all(resp.as_bytes()).await.ok();
                    visitor_io.flush().await.ok();
                    return Ok(());
                }
            };

            // Open virtual stream over MuxSession to client
            let mut mux_stream = match tunnel.mux_handle.open_stream().await {
                Ok(s) => s,
                Err(_) => {
                    let body = "502 Bad Gateway: tunnel unavailable\n";
                    let resp = format!(
                        "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    visitor_io.write_all(resp.as_bytes()).await.ok();
                    visitor_io.flush().await.ok();
                    return Ok(());
                }
            };

            // Inject standard X-Forwarded-* proxy headers
            let mut forwarded = Vec::with_capacity(header_end + 256);
            forwarded.extend_from_slice(&buffer[..header_end]);
            let injected = format!(
                "\r\nX-Forwarded-For: {}\r\nX-Forwarded-Proto: https\r\nX-Forwarded-Host: {}\r\n\r\n",
                peer_addr.ip(),
                host
            );
            forwarded.extend_from_slice(injected.as_bytes());

            let already_buffered_body = buffer.len().saturating_sub(header_end + 4);
            let req_body_total = req_content_length.unwrap_or(0);
            let buffered_to_send = already_buffered_body.min(req_body_total);

            if buffered_to_send > 0 {
                forwarded
                    .extend_from_slice(&buffer[header_end + 4..header_end + 4 + buffered_to_send]);
            }

            let leftover_offset = header_end + 4 + buffered_to_send;
            leftover = if buffer.len() > leftover_offset {
                buffer[leftover_offset..].to_vec()
            } else {
                Vec::new()
            };

            // Send rewritten request headers + any buffered body bytes
            mux_stream
                .write_all(&forwarded)
                .await
                .map_err(|e| ProtoError::IoError(e.to_string()))?;
            mux_stream
                .flush()
                .await
                .map_err(|e| ProtoError::IoError(e.to_string()))?;

            let remaining_req_body = req_body_total.saturating_sub(buffered_to_send);

            let (mut visitor_r, mut visitor_w) = tokio::io::split(&mut visitor_io);
            let (mut mux_r, mut mux_w) = tokio::io::split(&mut mux_stream);

            let body_fut = async {
                if remaining_req_body > 0 {
                    let mut copied = 0;
                    let mut chunk = [0u8; 8192];
                    while copied < remaining_req_body {
                        let to_read = (remaining_req_body - copied).min(chunk.len());
                        let n = visitor_r.read(&mut chunk[..to_read]).await?;
                        if n == 0 {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "Visitor body premature EOF",
                            ));
                        }
                        mux_w.write_all(&chunk[..n]).await?;
                        copied += n;
                    }
                    mux_w.flush().await?;
                }
                Ok::<(), std::io::Error>(())
            };

            let mut resp_can_keepalive = true;
            let resp_fut = async {
                let mut buf = [0u8; 8192];
                let mut header_buf = Vec::new();
                let mut parsed_headers = false;
                let mut expected_response_len: Option<usize> = None;
                let mut total_transferred = 0;

                loop {
                    let n = mux_r.read(&mut buf).await?;
                    if n == 0 {
                        if expected_response_len.is_some()
                            && total_transferred < expected_response_len.unwrap()
                        {
                            resp_can_keepalive = false;
                        }
                        break;
                    }

                    total_transferred += n;
                    visitor_w.write_all(&buf[..n]).await?;

                    if !parsed_headers {
                        header_buf.extend_from_slice(&buf[..n]);
                        if let Some(crlf_pos) = find_crlf_crlf(&header_buf) {
                            parsed_headers = true;
                            let header_end_offset = crlf_pos + 4;
                            let mut resp_headers = [httparse::EMPTY_HEADER; 64];
                            let mut resp = httparse::Response::new(&mut resp_headers);
                            if let Ok(httparse::Status::Complete(_)) = resp.parse(&header_buf) {
                                for h in resp.headers.iter() {
                                    if h.name.eq_ignore_ascii_case("Connection") {
                                        if let Ok(s) = std::str::from_utf8(h.value) {
                                            if s.to_ascii_lowercase().contains("close") {
                                                resp_can_keepalive = false;
                                            }
                                        }
                                    } else if h.name.eq_ignore_ascii_case("Content-Length") {
                                        if let Ok(s) = std::str::from_utf8(h.value) {
                                            if let Ok(cl) = s.trim().parse::<usize>() {
                                                expected_response_len =
                                                    Some(header_end_offset + cl);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if let Some(expected_len) = expected_response_len {
                        if total_transferred >= expected_len {
                            visitor_w.flush().await?;
                            break;
                        }
                    }
                }

                visitor_w.flush().await?;
                if expected_response_len.is_none() {
                    resp_can_keepalive = false;
                }
                Ok::<(), std::io::Error>(())
            };

            tokio::try_join!(body_fut, resp_fut).map_err(|e| ProtoError::IoError(e.to_string()))?;

            if !visitor_wants_keepalive || !resp_can_keepalive {
                break;
            }
        }

        Ok(())
    }
}

/// Extract subdomain from Host header, matching against root_domain
pub fn extract_subdomain(host: &str, root_domain: &str) -> Option<String> {
    let clean_host = host.split(':').next()?.trim();
    let root = root_domain.trim();

    if clean_host.eq_ignore_ascii_case(root) {
        return None;
    }

    let suffix = format!(".{root}");
    if clean_host
        .to_ascii_lowercase()
        .ends_with(&suffix.to_ascii_lowercase())
    {
        let sub = &clean_host[..clean_host.len() - suffix.len()];
        if !sub.is_empty() {
            return Some(sub.to_string());
        }
    }

    // Direct fallback if host is simply the subdomain name without domain
    if !clean_host.contains('.') && !clean_host.is_empty() {
        return Some(clean_host.to_string());
    }

    None
}

/// Read HTTP headers from stream with existing leftover bytes until `\r\n\r\n` is found
async fn read_http_headers_with_leftover<T: AsyncRead + Unpin>(
    io: &mut T,
    mut buffer: Vec<u8>,
) -> Result<(Vec<u8>, usize)> {
    let mut chunk = [0u8; 1024];

    loop {
        if let Some(pos) = find_crlf_crlf(&buffer) {
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
            return Err(ProtoError::IoError(
                "Visitor closed connection before completing HTTP headers".into(),
            ));
        }
        buffer.extend_from_slice(&chunk[..n]);
    }
}

fn find_crlf_crlf(buf: &[u8]) -> Option<usize> {
    for i in 0..buf.len().saturating_sub(3) {
        if &buf[i..i + 4] == b"\r\n\r\n" {
            return Some(i);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_subdomain() {
        assert_eq!(
            extract_subdomain("demo.example.com", "example.com"),
            Some("demo".into())
        );
        assert_eq!(
            extract_subdomain("demo.example.com:8080", "example.com"),
            Some("demo".into())
        );
        assert_eq!(
            extract_subdomain("multi.level.example.com", "example.com"),
            Some("multi.level".into())
        );
        assert_eq!(extract_subdomain("example.com", "example.com"), None);
        assert_eq!(extract_subdomain("another.org", "example.com"), None);
        assert_eq!(
            extract_subdomain("standalone", "example.com"),
            Some("standalone".into())
        );
    }

    #[tokio::test]
    async fn test_http_proxy_unknown_subdomain_returns_404() {
        let registry = Arc::new(TunnelRegistry::new(20000..=20010, "example.com".into()));
        let proxy = HttpProxy::new(
            "127.0.0.1:8080".parse().unwrap(),
            registry,
            "example.com".into(),
        );

        assert_eq!(proxy.bind_addr(), "127.0.0.1:8080".parse().unwrap());
        assert_eq!(proxy.root_domain(), "example.com");

        let (mut visitor_client, visitor_server) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            proxy
                .handle_visitor(visitor_server, "192.168.1.1:12345".parse().unwrap())
                .await
        });

        visitor_client
            .write_all(b"GET / HTTP/1.1\r\nHost: unknown.example.com\r\n\r\n")
            .await
            .unwrap();

        let mut resp = vec![0u8; 1024];
        let n = visitor_client.read(&mut resp).await.unwrap();
        let resp_str = String::from_utf8_lossy(&resp[..n]);
        assert!(resp_str.contains("404 Not Found"));
        assert!(resp_str.contains("tunnel not found"));
    }

    #[tokio::test]
    async fn test_http_proxy_valid_subdomain_bridges_traffic() {
        let registry = Arc::new(TunnelRegistry::new(20000..=20010, "example.com".into()));
        let proxy = HttpProxy::new(
            "127.0.0.1:8080".parse().unwrap(),
            registry.clone(),
            "example.com".into(),
        );

        // Register active tunnel
        let (mux_client_io, mux_server_io) = tokio::io::duplex(65536);
        let (server_session, server_handle) =
            qt_mux::MuxSession::new(mux_server_io, qt_mux::MuxConfig::server());
        let (client_session, client_handle) =
            qt_mux::MuxSession::new(mux_client_io, qt_mux::MuxConfig::client());
        tokio::spawn(server_session.run());
        tokio::spawn(client_session.run());

        registry
            .register_http(1, 10, Some("demo"), server_handle)
            .unwrap();

        let (mut visitor_client, visitor_server) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            proxy
                .handle_visitor(visitor_server, "192.168.1.1:54321".parse().unwrap())
                .await
        });

        // Visitor sends request
        visitor_client
            .write_all(b"GET /hello HTTP/1.1\r\nHost: demo.example.com\r\n\r\n")
            .await
            .unwrap();

        // Client accepts the forwarded stream
        let mut client_stream = client_handle.accept_stream().await.unwrap();
        let mut received = vec![0u8; 1024];
        let n = client_stream.read(&mut received).await.unwrap();
        assert!(String::from_utf8_lossy(&received[..n]).contains("GET /hello HTTP/1.1"));
        assert!(String::from_utf8_lossy(&received[..n]).contains("X-Forwarded-For: 192.168.1.1"));

        // Client replies
        client_stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
            .await
            .unwrap();

        // Visitor reads response
        let mut visitor_resp = vec![0u8; 1024];
        let n = visitor_client.read(&mut visitor_resp).await.unwrap();
        assert!(String::from_utf8_lossy(&visitor_resp[..n]).contains("200 OK"));
    }

    #[tokio::test]
    async fn test_http_proxy_direct_ip_fallback() {
        let registry = Arc::new(TunnelRegistry::new(20000..=20010, "example.com".into()));
        let proxy = HttpProxy::new(
            "127.0.0.1:8080".parse().unwrap(),
            registry.clone(),
            "example.com".into(),
        );

        let (mux_client_io, mux_server_io) = tokio::io::duplex(1024);
        let (server_session, server_handle) =
            qt_mux::MuxSession::new(mux_server_io, qt_mux::MuxConfig::server());
        let (client_session, client_handle) =
            qt_mux::MuxSession::new(mux_client_io, qt_mux::MuxConfig::client());
        tokio::spawn(async move { server_session.run().await });
        tokio::spawn(async move { client_session.run().await });

        registry
            .register_http(1, 10, Some("demo"), server_handle)
            .unwrap();

        let (mut visitor_client, visitor_server) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            proxy
                .handle_visitor(visitor_server, "192.168.1.1:54321".parse().unwrap())
                .await
        });

        // Visitor accesses via IP address (no subdomain)
        visitor_client
            .write_all(b"GET /via-ip HTTP/1.1\r\nHost: 192.168.1.5:8080\r\n\r\n")
            .await
            .unwrap();

        let mut client_stream = client_handle.accept_stream().await.unwrap();
        let mut received = vec![0u8; 1024];
        let n = client_stream.read(&mut received).await.unwrap();
        assert!(String::from_utf8_lossy(&received[..n]).contains("GET /via-ip HTTP/1.1"));

        client_stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            .await
            .unwrap();

        let mut visitor_resp = vec![0u8; 1024];
        let n = visitor_client.read(&mut visitor_resp).await.unwrap();
        assert!(String::from_utf8_lossy(&visitor_resp[..n]).contains("200 OK"));
    }

    #[tokio::test]
    async fn test_http_proxy_502_when_mux_closed() {
        let registry = Arc::new(TunnelRegistry::new(20000..=20010, "example.com".into()));
        let proxy = HttpProxy::new(
            "127.0.0.1:8080".parse().unwrap(),
            registry.clone(),
            "example.com".into(),
        );

        // Register tunnel with closed mux handle
        let (mux_client_io, mux_server_io) = tokio::io::duplex(1024);
        let (server_session, server_handle) =
            qt_mux::MuxSession::new(mux_server_io, qt_mux::MuxConfig::server());
        drop(mux_client_io);
        drop(server_session); // dropped/closed

        registry
            .register_http(1, 10, Some("broken"), server_handle)
            .unwrap();

        let (mut visitor_client, visitor_server) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            proxy
                .handle_visitor(visitor_server, "192.168.1.1:54321".parse().unwrap())
                .await
        });

        visitor_client
            .write_all(b"GET / HTTP/1.1\r\nHost: broken.example.com\r\n\r\n")
            .await
            .unwrap();

        let mut resp = vec![0u8; 1024];
        let n = visitor_client.read(&mut resp).await.unwrap();
        let resp_str = String::from_utf8_lossy(&resp[..n]);
        assert!(resp_str.contains("502 Bad Gateway"));
        assert!(resp_str.contains("tunnel unavailable"));
    }

    #[tokio::test]
    async fn test_http_proxy_missing_host_header() {
        let registry = Arc::new(TunnelRegistry::new(20000..=20010, "example.com".into()));
        let proxy = HttpProxy::new(
            "127.0.0.1:8080".parse().unwrap(),
            registry,
            "example.com".into(),
        );

        let (mut visitor_client, visitor_server) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            proxy
                .handle_visitor(visitor_server, "192.168.1.1:12345".parse().unwrap())
                .await
        });

        visitor_client
            .write_all(b"GET / HTTP/1.1\r\n\r\n")
            .await
            .unwrap();

        let mut resp = vec![0u8; 1024];
        let n = visitor_client.read(&mut resp).await.unwrap();
        assert!(String::from_utf8_lossy(&resp[..n]).contains("400 Bad Request"));
    }

    #[tokio::test]
    async fn test_http_proxy_oversized_headers_431() {
        let registry = Arc::new(TunnelRegistry::new(20000..=20010, "example.com".into()));
        let proxy = HttpProxy::new(
            "127.0.0.1:8080".parse().unwrap(),
            registry,
            "example.com".into(),
        );

        let (mut visitor_client, visitor_server) = tokio::io::duplex(16384);
        tokio::spawn(async move {
            proxy
                .handle_visitor(visitor_server, "192.168.1.1:12345".parse().unwrap())
                .await
        });

        let huge_header = "X-Padding: ".to_string() + &"a".repeat(9000);
        let req = format!("GET / HTTP/1.1\r\nHost: test.example.com\r\n{huge_header}\r\n\r\n");
        visitor_client.write_all(req.as_bytes()).await.unwrap();

        let mut resp = vec![0u8; 1024];
        let n = visitor_client.read(&mut resp).await.unwrap();
        assert!(String::from_utf8_lossy(&resp[..n]).contains("431 Request Header Fields Too Large"));
    }

    #[tokio::test]
    async fn test_http_proxy_slowloris_timeout() {
        let registry = Arc::new(TunnelRegistry::new(20000..=20010, "example.com".into()));
        let proxy = HttpProxy::new(
            "127.0.0.1:8080".parse().unwrap(),
            registry,
            "example.com".into(),
        )
        .with_read_timeout(Duration::from_millis(50));

        let (mut visitor_client, visitor_server) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            proxy
                .handle_visitor(visitor_server, "192.168.1.1:12345".parse().unwrap())
                .await
        });

        // Visitor sends incomplete header and waits
        visitor_client
            .write_all(b"GET / HTTP/1.1\r\nHost: foo")
            .await
            .unwrap();

        let mut resp = vec![0u8; 1024];
        let n = visitor_client.read(&mut resp).await.unwrap();
        assert!(String::from_utf8_lossy(&resp[..n]).contains("408 Request Timeout"));
    }

    #[tokio::test]
    async fn test_http_proxy_real_tcp_run() {
        let registry = Arc::new(TunnelRegistry::new(20000..=20010, "example.com".into()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = listener.local_addr().unwrap();
        drop(listener);

        let proxy = HttpProxy::new(local_addr, registry, "example.com".into());
        let run_task = tokio::spawn({
            let p = proxy.clone();
            async move { p.run().await }
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut client = tokio::net::TcpStream::connect(local_addr).await.unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: notfound.example.com\r\n\r\n")
            .await
            .unwrap();

        let mut resp = vec![0u8; 1024];
        let n = client.read(&mut resp).await.unwrap();
        assert!(String::from_utf8_lossy(&resp[..n]).contains("404 Not Found"));

        run_task.abort();
    }

    #[tokio::test]
    async fn test_http_proxy_keepalive_multiple_requests() {
        let registry = Arc::new(TunnelRegistry::new(20000..=20010, "example.com".into()));
        let proxy = HttpProxy::new(
            "127.0.0.1:8080".parse().unwrap(),
            registry.clone(),
            "example.com".into(),
        );

        let (mux_client_io, mux_server_io) = tokio::io::duplex(65536);
        let (server_session, server_handle) =
            qt_mux::MuxSession::new(mux_server_io, qt_mux::MuxConfig::server());
        let (client_session, client_handle) =
            qt_mux::MuxSession::new(mux_client_io, qt_mux::MuxConfig::client());
        tokio::spawn(server_session.run());
        tokio::spawn(client_session.run());

        registry
            .register_http(1, 10, Some("demo"), server_handle)
            .unwrap();

        let (mut visitor_client, visitor_server) = tokio::io::duplex(4096);
        let visitor_task = tokio::spawn(async move {
            proxy
                .handle_visitor(visitor_server, "192.168.1.1:54321".parse().unwrap())
                .await
        });

        // Request 1
        visitor_client
            .write_all(b"GET /req1 HTTP/1.1\r\nHost: demo.example.com\r\n\r\n")
            .await
            .unwrap();

        let mut stream1 = client_handle.accept_stream().await.unwrap();
        let mut req_buf1 = vec![0u8; 1024];
        let n1 = stream1.read(&mut req_buf1).await.unwrap();
        assert!(String::from_utf8_lossy(&req_buf1[..n1]).contains("GET /req1"));

        stream1
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nres1")
            .await
            .unwrap();

        let mut resp_buf1 = vec![0u8; 1024];
        let n1_resp = visitor_client.read(&mut resp_buf1).await.unwrap();
        assert!(String::from_utf8_lossy(&resp_buf1[..n1_resp]).contains("res1"));

        // Request 2 on the SAME visitor socket
        visitor_client
            .write_all(b"GET /req2 HTTP/1.1\r\nHost: demo.example.com\r\n\r\n")
            .await
            .unwrap();

        let mut stream2 = client_handle.accept_stream().await.unwrap();
        let mut req_buf2 = vec![0u8; 1024];
        let n2 = stream2.read(&mut req_buf2).await.unwrap();
        assert!(String::from_utf8_lossy(&req_buf2[..n2]).contains("GET /req2"));

        stream2
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nres2")
            .await
            .unwrap();

        let mut resp_buf2 = vec![0u8; 1024];
        let n2_resp = visitor_client.read(&mut resp_buf2).await.unwrap();
        assert!(String::from_utf8_lossy(&resp_buf2[..n2_resp]).contains("res2"));

        // Close visitor cleanly
        drop(visitor_client);
        assert!(visitor_task.await.unwrap().is_ok());
    }
}
