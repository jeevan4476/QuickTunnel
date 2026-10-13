//! Client tunnel orchestrator and daemon supervisor.
//!
//! Manages the complete QuickTunnel client lifecycle:
//! 1. Connects to `qt-server` control plane via `ClientConnector`.
//! 2. Supervises multiplexed visitor traffic via `LocalForwarder`.
//! 3. Recovers from transient drops using decorrelated jittered backoff.
//! 4. Aborts immediately on fatal errors (auth failure, subdomain collision) per §13.1.
//! 5. Supports graceful shutdown via `shutdown()`.

use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;

use parking_lot::{Mutex, RwLock};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Notify;

use qt_mux::MuxHandle;
use qt_proto::{ProtoError, Result};

use crate::config::ClientConfig;
use crate::connector::ClientConnector;
use crate::forwarder::LocalForwarder;
use crate::retry::{classify_error, BackoffPolicy};

pub const STATE_IDLE: u8 = 0;
pub const STATE_ACTIVE: u8 = 1;
pub const STATE_SHUTDOWN: u8 = 2;

struct RunGuard {
    execution_state: Arc<AtomicU8>,
    is_running: Arc<AtomicBool>,
    public_url: Arc<RwLock<Option<String>>>,
    assigned_port: Arc<RwLock<Option<u16>>>,
}

impl Drop for RunGuard {
    fn drop(&mut self) {
        self.is_running.store(false, Ordering::Release);
        *self.public_url.write() = None;
        *self.assigned_port.write() = None;
        let _ = self.execution_state.compare_exchange(
            STATE_ACTIVE,
            STATE_IDLE,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }
}

/// QuickTunnel client orchestrator managing connection lifecycle and local traffic forwarding.
#[derive(Clone)]
pub struct ClientTunnel {
    config: ClientConfig,
    connector: ClientConnector,
    forwarder: LocalForwarder,
    execution_state: Arc<AtomicU8>,
    is_running: Arc<AtomicBool>,
    shutdown_notify: Arc<Notify>,
    public_url: Arc<RwLock<Option<String>>>,
    assigned_port: Arc<RwLock<Option<u16>>>,
    active_mux: Arc<Mutex<Option<MuxHandle>>>,
    active_forwarder_task: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
    connected_notify: Arc<Notify>,
}

impl ClientTunnel {
    /// Create a new `ClientTunnel` from the provided configuration.
    pub fn new(config: ClientConfig) -> Self {
        let connector = ClientConnector::new(config.clone());
        let forwarder =
            LocalForwarder::new(config.local_target, config.mode, config.host_header.clone());
        Self {
            config,
            connector,
            forwarder,
            execution_state: Arc::new(AtomicU8::new(STATE_IDLE)),
            is_running: Arc::new(AtomicBool::new(false)),
            shutdown_notify: Arc::new(Notify::new()),
            public_url: Arc::new(RwLock::new(None)),
            assigned_port: Arc::new(RwLock::new(None)),
            active_mux: Arc::new(Mutex::new(None)),
            active_forwarder_task: Arc::new(Mutex::new(None)),
            connected_notify: Arc::new(Notify::new()),
        }
    }

    /// Attach an optional HTTP tap pipeline for inspecting traffic.
    pub fn with_tap(mut self, tap: qt_inspector_ui::tap::HttpTapSender) -> Self {
        self.forwarder = self.forwarder.with_tap(tap);
        self
    }

    /// Return the connected notification primitive.
    pub fn connected_notify(&self) -> Arc<Notify> {
        self.connected_notify.clone()
    }

    /// Access the client configuration.
    pub fn config(&self) -> &ClientConfig {
        &self.config
    }

    /// Check if the tunnel is actively connected and forwarding traffic.
    pub fn is_running(&self) -> bool {
        self.is_running.load(Ordering::Acquire)
    }

    /// Check if the tunnel has initiated shutdown.
    pub fn is_shutdown(&self) -> bool {
        self.execution_state.load(Ordering::Acquire) == STATE_SHUTDOWN
    }

    /// Check if the tunnel daemon is actively executing (`run()` or `run_stream()`).
    pub fn is_active(&self) -> bool {
        self.execution_state.load(Ordering::Acquire) == STATE_ACTIVE
    }

    /// Assigned public URL (if currently established).
    pub fn public_url(&self) -> Option<String> {
        self.public_url.read().clone()
    }

    /// Assigned public TCP port (for TCP tunnel mode).
    pub fn assigned_port(&self) -> Option<u16> {
        *self.assigned_port.read()
    }

    /// Initiate graceful shutdown of the client daemon.
    pub fn shutdown(&self) {
        self.execution_state
            .store(STATE_SHUTDOWN, Ordering::Release);
        self.is_running.store(false, Ordering::Release);
        *self.public_url.write() = None;
        *self.assigned_port.write() = None;
        if let Some(mux) = self.active_mux.lock().take() {
            tokio::spawn(async move {
                let _ = mux.close().await;
            });
        }
        if let Some(handle) = self.active_forwarder_task.lock().take() {
            handle.abort();
        }
        self.shutdown_notify.notify_waiters();
        self.connected_notify.notify_waiters();
    }

    /// Run the tunnel over a single provided asynchronous stream (for in-memory testing).
    ///
    /// Performs the handshake, spawns the local forwarder, and returns the assigned public URL.
    pub async fn run_stream<T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static>(
        &self,
        io: T,
    ) -> Result<String> {
        let current = self.execution_state.load(Ordering::Acquire);
        if current == STATE_SHUTDOWN {
            return Err(ProtoError::IoError("ClientTunnel is shut down".into()));
        }
        if self
            .execution_state
            .compare_exchange(
                STATE_IDLE,
                STATE_ACTIVE,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            let current = self.execution_state.load(Ordering::Acquire);
            if current == STATE_SHUTDOWN {
                return Err(ProtoError::IoError("ClientTunnel is shut down".into()));
            }
            return Err(ProtoError::ProtocolError(
                "ClientTunnel is already active/running".into(),
            ));
        }

        let handshake_fut = self.connector.connect_stream(io);
        let handshake = tokio::select! {
            _ = self.shutdown_notify.notified() => {
                let _ = self.execution_state.compare_exchange(
                    STATE_ACTIVE,
                    STATE_IDLE,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                );
                return Err(ProtoError::IoError("Client tunnel shut down during handshake".into()));
            }
            res = handshake_fut => match res {
                Ok(h) => h,
                Err(e) => {
                    let _ = self.execution_state.compare_exchange(
                        STATE_ACTIVE,
                        STATE_IDLE,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    );
                    return Err(e);
                }
            },
        };

        let url = handshake.public_url.clone();
        *self.public_url.write() = Some(handshake.public_url);
        *self.assigned_port.write() = handshake.assigned_port;
        *self.active_mux.lock() = Some(handshake.mux_handle.clone());
        self.is_running.store(true, Ordering::Release);
        self.connected_notify.notify_waiters();

        let forwarder = self.forwarder.clone();
        let mux_handle = handshake.mux_handle;
        let is_running = self.is_running.clone();
        let public_url = self.public_url.clone();
        let assigned_port = self.assigned_port.clone();
        let execution_state = self.execution_state.clone();
        let shutdown_notify = self.shutdown_notify.clone();

        let handle = tokio::spawn(async move {
            tokio::select! {
                _ = shutdown_notify.notified() => {
                    let _ = mux_handle.close().await;
                }
                _ = forwarder.run_loop(mux_handle.clone()) => {}
            }
            is_running.store(false, Ordering::Release);
            *public_url.write() = None;
            *assigned_port.write() = None;
            let _ = execution_state.compare_exchange(
                STATE_ACTIVE,
                STATE_IDLE,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
        });
        *self.active_forwarder_task.lock() = Some(handle);

        Ok(url)
    }

    /// Run the client daemon loop.
    ///
    /// Connects to `config.server_addr`, runs the QTP v1 handshake and forwarder loop,
    /// reconnects with decorrelated jittered backoff on transient errors, and aborts
    /// immediately on fatal errors (authentication failure, subdomain taken) per §13.1.
    pub async fn run(&self) -> Result<()> {
        let current = self.execution_state.load(Ordering::Acquire);
        if current == STATE_SHUTDOWN {
            return Ok(());
        }
        if self
            .execution_state
            .compare_exchange(
                STATE_IDLE,
                STATE_ACTIVE,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            let current = self.execution_state.load(Ordering::Acquire);
            if current == STATE_SHUTDOWN {
                return Ok(());
            }
            return Err(ProtoError::ProtocolError(
                "ClientTunnel is already active/running".into(),
            ));
        }

        let _guard = RunGuard {
            execution_state: self.execution_state.clone(),
            is_running: self.is_running.clone(),
            public_url: self.public_url.clone(),
            assigned_port: self.assigned_port.clone(),
        };

        let mut backoff = BackoffPolicy::from_config(&self.config);

        loop {
            if self.is_shutdown() {
                return Ok(());
            }

            tracing::info!(
                "Connecting to QuickTunnel server at {}",
                self.config.server_addr
            );
            let connect_fut = tokio::net::TcpStream::connect(self.config.server_addr);
            let stream = tokio::select! {
                _ = self.shutdown_notify.notified() => {
                    return Ok(());
                }
                res = connect_fut => {
                    match res {
                        Ok(s) => {
                            s.set_nodelay(true).ok();
                            s
                        }
                        Err(e) => {
                            let proto_err = ProtoError::IoError(e.to_string());
                            let severity = classify_error(&proto_err);
                            if severity.is_fatal() {
                                return Err(proto_err);
                            }
                            match backoff.next_delay() {
                                Some(delay) => {
                                    tracing::warn!("Connection failed: {}. Retrying in {:?}", e, delay);
                                    tokio::select! {
                                        _ = self.shutdown_notify.notified() => {
                                            return Ok(());
                                        }
                                        _ = tokio::time::sleep(delay) => {
                                            continue;
                                        }
                                    }
                                }
                                None => {
                                    return Err(ProtoError::IoError(format!(
                                        "Connection failed and max retries ({:?}) exhausted: {}",
                                        self.config.max_retries, e
                                    )));
                                }
                            }
                        }
                    }
                }
            };

            if self.is_shutdown() {
                return Ok(());
            }

            // Perform handshake over established TCP stream
            let handshake_fut = self.connector.connect_stream(stream);
            let handshake = tokio::select! {
                _ = self.shutdown_notify.notified() => {
                    return Ok(());
                }
                res = handshake_fut => {
                    match res {
                        Ok(h) => h,
                        Err(e) => {
                            let severity = classify_error(&e);
                            if severity.is_fatal() {
                                tracing::error!("Fatal handshake error: {}. Aborting.", e);
                                return Err(e);
                            }
                            match backoff.next_delay() {
                                Some(delay) => {
                                    tracing::warn!("Handshake error: {}. Retrying in {:?}", e, delay);
                                    tokio::select! {
                                        _ = self.shutdown_notify.notified() => {
                                            return Ok(());
                                        }
                                        _ = tokio::time::sleep(delay) => {
                                            continue;
                                        }
                                    }
                                }
                                None => {
                                    return Err(e);
                                }
                            }
                        }
                    }
                }
            };

            // Handshake succeeded!
            tracing::info!(
                "Tunnel established! Public URL: {}, assigned port: {:?}",
                handshake.public_url,
                handshake.assigned_port
            );
            *self.public_url.write() = Some(handshake.public_url);
            *self.assigned_port.write() = handshake.assigned_port;
            *self.active_mux.lock() = Some(handshake.mux_handle.clone());
            self.is_running.store(true, Ordering::Release);
            self.connected_notify.notify_waiters();

            let connected_at = std::time::Instant::now();
            let forwarder = self.forwarder.clone();
            let mux_handle = handshake.mux_handle;
            let shutdown_notify = self.shutdown_notify.clone();

            tokio::select! {
                _ = shutdown_notify.notified() => {
                    tracing::info!("Shutdown requested; closing tunnel session");
                    let _ = mux_handle.close().await;
                    self.is_running.store(false, Ordering::Release);
                    *self.public_url.write() = None;
                    *self.assigned_port.write() = None;
                    *self.active_mux.lock() = None;
                    return Ok(());
                }
                _ = forwarder.run_loop(mux_handle.clone()) => {
                    tracing::warn!("Tunnel session dropped");
                }
            }

            self.is_running.store(false, Ordering::Release);
            *self.public_url.write() = None;
            *self.assigned_port.write() = None;
            *self.active_mux.lock() = None;

            if self.is_shutdown() {
                return Ok(());
            }

            // Section 13.1: Reset attempt counter if connection was healthy for > 60s
            if connected_at.elapsed() >= std::time::Duration::from_secs(60) {
                backoff.reset();
            }

            // Backoff before reconnecting
            match backoff.next_delay() {
                Some(delay) => {
                    tracing::info!("Reconnecting in {:?}", delay);
                    tokio::select! {
                        _ = self.shutdown_notify.notified() => {
                            return Ok(());
                        }
                        _ = tokio::time::sleep(delay) => {}
                    }
                }
                None => {
                    return Err(ProtoError::IoError(format!(
                        "Max retries ({:?}) exhausted after disconnect",
                        self.config.max_retries
                    )));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use qt_proto::TunnelMode;

    #[tokio::test]
    async fn test_client_tunnel_end_to_end_http() {
        // 1. Setup local target mock HTTP server
        let local_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = local_listener.local_addr().unwrap();

        tokio::spawn(async move {
            loop {
                if let Ok((mut sock, _)) = local_listener.accept().await {
                    tokio::spawn(async move {
                        let mut buf = [0u8; 1024];
                        let n = sock.read(&mut buf).await.unwrap();
                        assert!(String::from_utf8_lossy(&buf[..n]).contains("GET /api/ping"));
                        sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\npong")
                            .await
                            .unwrap();
                    });
                }
            }
        });

        // 2. Setup qt-server
        let s_probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ctrl_addr = s_probe.local_addr().unwrap();
        drop(s_probe);

        let h_probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_addr = h_probe.local_addr().unwrap();
        drop(h_probe);

        let server_cfg = qt_server::ServerConfig::new()
            .with_control_bind(ctrl_addr)
            .with_http_bind(http_addr)
            .with_root_domain("tunnel.local")
            .with_secret("shared-secret");
        let server = Arc::new(qt_server::Server::new(server_cfg));
        let server_clone = server.clone();
        tokio::spawn(async move { server_clone.run().await });

        tokio::time::sleep(Duration::from_millis(50)).await;

        // 3. Setup qt-client
        let client_cfg = ClientConfig::new()
            .with_server_addr(ctrl_addr)
            .with_local_target(local_addr)
            .with_subdomain("myservice")
            .with_secret("shared-secret");
        let client = Arc::new(ClientTunnel::new(client_cfg));
        let client_clone = client.clone();

        tokio::spawn(async move {
            let _ = client_clone.run().await;
        });

        for _ in 0..100 {
            if client.is_running() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(client.is_running());
        assert_eq!(
            client.public_url(),
            Some("https://myservice.tunnel.local".into())
        );
        assert!(client.assigned_port().is_none());

        // 4. Visitor dials server public HTTP proxy
        let mut visitor = tokio::net::TcpStream::connect(http_addr).await.unwrap();
        visitor
            .write_all(b"GET /api/ping HTTP/1.1\r\nHost: myservice.tunnel.local\r\n\r\n")
            .await
            .unwrap();

        let mut resp = vec![0u8; 1024];
        let n = visitor.read(&mut resp).await.unwrap();
        let resp_str = String::from_utf8_lossy(&resp[..n]);
        assert!(resp_str.contains("200 OK"));
        assert!(resp_str.contains("pong"));

        client.shutdown();
        server.shutdown();
        assert!(!client.is_running());
        assert!(client.is_shutdown());
    }

    #[tokio::test]
    async fn test_client_tunnel_end_to_end_tcp() {
        // 1. Setup local target mock TCP echo server
        let local_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = local_listener.local_addr().unwrap();

        tokio::spawn(async move {
            while let Ok((mut sock, _)) = local_listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    while let Ok(n) = sock.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        if sock.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });

        // 2. Setup qt-server with dynamic TCP port range
        let s_probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ctrl_addr = s_probe.local_addr().unwrap();
        drop(s_probe);

        let h_probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_addr = h_probe.local_addr().unwrap();
        drop(h_probe);

        let tcp_probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_port = tcp_probe.local_addr().unwrap().port();
        drop(tcp_probe);

        let server_cfg = qt_server::ServerConfig::new()
            .with_control_bind(ctrl_addr)
            .with_http_bind(http_addr)
            .with_root_domain("tunnel.local")
            .with_secret("shared-secret")
            .with_tcp_port_range(tcp_port..=tcp_port + 5);
        let server = Arc::new(qt_server::Server::new(server_cfg));
        let server_clone = server.clone();
        tokio::spawn(async move { server_clone.run().await });

        tokio::time::sleep(Duration::from_millis(50)).await;

        // 3. Setup qt-client in TCP mode
        let client_cfg = ClientConfig::new()
            .with_server_addr(ctrl_addr)
            .with_local_target(local_addr)
            .with_mode(TunnelMode::Tcp)
            .with_remote_port(tcp_port)
            .with_secret("shared-secret");
        let client = Arc::new(ClientTunnel::new(client_cfg));
        let client_clone = client.clone();

        tokio::spawn(async move {
            let _ = client_clone.run().await;
        });

        for _ in 0..100 {
            if client.is_running() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(client.is_running());
        assert_eq!(client.assigned_port(), Some(tcp_port));

        // 4. Visitor connects directly to server public TCP port (started by server on registration)
        let mut visitor = tokio::net::TcpStream::connect(("127.0.0.1", tcp_port))
            .await
            .unwrap();
        visitor.write_all(b"PING TCP ECHO 12345").await.unwrap();

        let mut resp = [0u8; 19];
        visitor.read_exact(&mut resp).await.unwrap();
        assert_eq!(&resp, b"PING TCP ECHO 12345");

        client.shutdown();
        server.shutdown();
    }

    async fn ephemeral_server_config(
        secret: &str,
    ) -> (
        qt_server::ServerConfig,
        std::net::SocketAddr,
        std::net::SocketAddr,
    ) {
        let s_probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ctrl_addr = s_probe.local_addr().unwrap();
        drop(s_probe);

        let h_probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_addr = h_probe.local_addr().unwrap();
        drop(h_probe);

        let cfg = qt_server::ServerConfig::new()
            .with_control_bind(ctrl_addr)
            .with_http_bind(http_addr)
            .with_root_domain("tunnel.local")
            .with_secret(secret);
        (cfg, ctrl_addr, http_addr)
    }

    #[tokio::test]
    async fn test_client_tunnel_fatal_error_auth_failure() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (server_cfg, ctrl_addr, _) = ephemeral_server_config("correct-secret").await;
            let server = Arc::new(qt_server::Server::new(server_cfg));
            let server_clone = server.clone();
            tokio::spawn(async move { server_clone.run().await });

            tokio::time::sleep(Duration::from_millis(50)).await;

            // Setup qt-client with "wrong-secret"
            let client_cfg = ClientConfig::new()
                .with_server_addr(ctrl_addr)
                .with_secret("wrong-secret")
                .with_client_id("agent-test");
            let client = ClientTunnel::new(client_cfg);

            // run() must abort immediately with AuthFailed error
            let res = client.run().await;
            assert!(res.is_err());
            assert!(matches!(res.unwrap_err(), ProtoError::AuthFailed(_)));
            assert!(!client.is_running());

            server.shutdown();
        })
        .await
        .expect("test timed out");
    }

    #[tokio::test]
    async fn test_client_tunnel_fatal_error_version_mismatch() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let ctrl_addr = listener.local_addr().unwrap();

            // Mock server that returns incompatible PROTOCOL_VERSION (99)
            let server_task = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let hello_frame = crate::connector::read_frame(&mut socket).await.unwrap();
                assert_eq!(hello_frame.header.ty, qt_proto::FrameType::Hello);

                let mut encoder = qt_proto::tlv::TlvEncoder::new();
                encoder
                    .push(
                        qt_proto::tlv::Tlv::new_u8(qt_proto::tlv::hello_ack_tags::VERSION, 99)
                            .unwrap(),
                    )
                    .unwrap();
                encoder
                    .push(
                        qt_proto::tlv::Tlv::new(qt_proto::tlv::hello_ack_tags::NONCE, &[1u8; 32])
                            .unwrap(),
                    )
                    .unwrap();
                encoder
                    .push(
                        qt_proto::tlv::Tlv::new_u32(
                            qt_proto::tlv::hello_ack_tags::MAX_FRAME,
                            16384,
                        )
                        .unwrap(),
                    )
                    .unwrap();
                encoder
                    .push(
                        qt_proto::tlv::Tlv::new_u64(qt_proto::tlv::hello_ack_tags::CAPABILITIES, 0)
                            .unwrap(),
                    )
                    .unwrap();
                let payload = encoder.finish();
                let ack = qt_proto::Frame::new(qt_proto::FrameType::HelloAck, 0, payload).unwrap();
                crate::connector::write_frame(&mut socket, &ack)
                    .await
                    .unwrap();
            });

            let client_cfg = ClientConfig::new().with_server_addr(ctrl_addr);
            let client = ClientTunnel::new(client_cfg);

            // Version mismatch must abort immediately without retry
            let res = client.run().await;
            assert!(res.is_err());
            assert!(matches!(
                res.unwrap_err(),
                ProtoError::VersionMismatch { .. }
            ));
            assert!(!client.is_running());

            server_task.await.unwrap();
        })
        .await
        .expect("test timed out");
    }

    #[tokio::test]
    async fn test_client_tunnel_graceful_shutdown() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (server_cfg, ctrl_addr, _) = ephemeral_server_config("sec").await;
            let server = Arc::new(qt_server::Server::new(server_cfg));
            let server_clone = server.clone();
            tokio::spawn(async move { server_clone.run().await });

            tokio::time::sleep(Duration::from_millis(50)).await;

            let client_cfg = ClientConfig::new()
                .with_server_addr(ctrl_addr)
                .with_secret("sec");
            let client = Arc::new(ClientTunnel::new(client_cfg));
            let client_clone = client.clone();

            let run_task = tokio::spawn(async move { client_clone.run().await });

            for _ in 0..100 {
                if client.is_running() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            assert!(client.is_running());

            // Graceful shutdown stops run() promptly
            client.shutdown();

            let res = tokio::time::timeout(Duration::from_secs(2), run_task)
                .await
                .expect("shutdown promptly stops run")
                .unwrap();
            assert!(res.is_ok());
            assert!(!client.is_running());
            assert!(client.is_shutdown());

            // Calling run() after shutdown returns Ok(()) immediately
            assert!(client.run().await.is_ok());

            server.shutdown();
        })
        .await
        .expect("test timed out");
    }

    #[tokio::test]
    async fn test_client_tunnel_run_stream_in_memory() {
        // Setup local target HTTP server
        let local_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = local_listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = local_listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = sock.read(&mut buf).await.unwrap();
                    sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
                        .await
                        .unwrap();
                });
            }
        });

        let (client_io, mut server_io) = tokio::io::duplex(65536);

        let client_cfg = ClientConfig::new()
            .with_local_target(local_addr)
            .with_subdomain("memory-test")
            .with_secret("in-mem-secret")
            .with_client_id("agent-mem");
        let client = ClientTunnel::new(client_cfg);

        // Server mock task handling QTP v1 handshake over in-memory stream
        let server_task = tokio::spawn(async move {
            // 1. Read HELLO
            let hello = crate::connector::read_frame(&mut server_io).await.unwrap();
            assert_eq!(hello.header.ty, qt_proto::FrameType::Hello);

            // 2. Send HELLO_ACK
            let nonce = [7u8; 32];
            let ack = qt_proto::Frame::hello_ack(&nonce, 16384, 0).unwrap();
            crate::connector::write_frame(&mut server_io, &ack)
                .await
                .unwrap();

            // 3. Read AUTH
            let auth = crate::connector::read_frame(&mut server_io).await.unwrap();
            assert_eq!(auth.header.ty, qt_proto::FrameType::Auth);

            // 4. Send READY
            let ready = qt_proto::Frame::ready(100, &[1u8; 32], 100, 10, None).unwrap();
            crate::connector::write_frame(&mut server_io, &ready)
                .await
                .unwrap();

            // 5. Read REGISTER
            let reg = crate::connector::read_frame(&mut server_io).await.unwrap();
            assert_eq!(reg.header.ty, qt_proto::FrameType::Register);

            // 6. Send REGISTER_ACK
            let reg_ack =
                qt_proto::Frame::register_ack(1, "https://memory-test.tunnel.local", None).unwrap();
            crate::connector::write_frame(&mut server_io, &reg_ack)
                .await
                .unwrap();

            // 7. Start server MuxSession
            let (session, server_mux) =
                qt_mux::MuxSession::new(server_io, qt_mux::MuxConfig::server());
            tokio::spawn(async move {
                let _ = session.run().await;
            });

            // 8. Open stream to client and send HTTP request
            let mut stream = server_mux.open_stream().await.unwrap();
            stream
                .write_all(b"GET / HTTP/1.1\r\nHost: memory-test.tunnel.local\r\n\r\n")
                .await
                .unwrap();

            let mut resp = vec![0u8; 1024];
            let n = stream.read(&mut resp).await.unwrap();
            assert!(String::from_utf8_lossy(&resp[..n]).contains("hello"));

            server_mux.close().await.unwrap();
        });

        let url = client.run_stream(client_io).await.unwrap();
        assert_eq!(url, "https://memory-test.tunnel.local");
        assert!(client.is_running());
        assert_eq!(
            client.public_url(),
            Some("https://memory-test.tunnel.local".into())
        );

        server_task.await.unwrap();

        client.shutdown();
        assert!(!client.is_running());
        assert!(client.is_shutdown());
    }

    #[tokio::test]
    async fn test_client_tunnel_already_running_and_shutdown_guards() {
        let (client_io1, server_io1) = tokio::io::duplex(1024);
        drop(server_io1);

        let client = ClientTunnel::new(ClientConfig::new());
        assert!(!client.is_running());
        assert!(!client.is_shutdown());
        assert_eq!(client.config().client_id, "");

        // Shutdown before run
        client.shutdown();
        assert!(client.is_shutdown());

        // run_stream fails if shut down
        let err = client.run_stream(client_io1).await.unwrap_err();
        assert!(matches!(err, ProtoError::IoError(_)));

        // Test already running guard
        let active_client = ClientTunnel::new(ClientConfig::new());
        active_client
            .execution_state
            .store(STATE_ACTIVE, Ordering::Release);
        assert!(active_client.is_active());

        let (client_io2, _server_io2) = tokio::io::duplex(1024);
        let err_stream = active_client.run_stream(client_io2).await.unwrap_err();
        assert!(matches!(err_stream, ProtoError::ProtocolError(_)));
        assert!(err_stream.to_string().contains("already active/running"));

        let err_run = active_client.run().await.unwrap_err();
        assert!(matches!(err_run, ProtoError::ProtocolError(_)));
        assert!(err_run.to_string().contains("already active/running"));
    }

    #[tokio::test]
    async fn test_client_tunnel_reconnection_exhaustion() {
        // Point client to unused port with max_retries = 2
        let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let unused_addr = probe.local_addr().unwrap();
        drop(probe);

        let client_cfg = ClientConfig::new()
            .with_server_addr(unused_addr)
            .with_max_retries(Some(2))
            .with_initial_backoff(Duration::from_millis(5))
            .with_max_backoff(Duration::from_millis(20));

        let client = ClientTunnel::new(client_cfg);
        let res = client.run().await;
        assert!(res.is_err());
        let err_msg = res.unwrap_err().to_string();
        assert!(err_msg.contains("max retries"));
    }

    async fn run_mock_handshake<T: AsyncRead + AsyncWrite + Unpin>(
        mut io: T,
        secret: &str,
        url: &str,
    ) -> Result<T> {
        use qt_proto::control::compute_auth_hmac;
        use qt_proto::tlv::parse_tlvs;
        use qt_proto::{Frame, FrameType, Hello, Register};

        // 1. Read HELLO
        let f = crate::connector::read_frame(&mut io).await?;
        assert_eq!(f.header.ty, FrameType::Hello);
        let tlvs = parse_tlvs(&f.payload)?;
        let hello = Hello::from_tlvs(&tlvs)?;

        // 2. Send HELLO_ACK
        let nonce = [42u8; 32];
        let ack = Frame::hello_ack(&nonce, 16384, 0)?;
        crate::connector::write_frame(&mut io, &ack).await?;

        // 3. Read AUTH
        let f = crate::connector::read_frame(&mut io).await?;
        assert_eq!(f.header.ty, FrameType::Auth);
        let tlvs = parse_tlvs(&f.payload)?;
        let auth = qt_proto::Auth::from_tlvs(&tlvs)?;
        let expected = compute_auth_hmac(secret.as_bytes(), &nonce, &hello.client_id);
        assert_eq!(auth.hmac, expected);

        // 4. Send READY
        let ready = Frame::ready(1, &[0u8; 32], 100, 10, None)?;
        crate::connector::write_frame(&mut io, &ready).await?;

        // 5. Read REGISTER
        let f = crate::connector::read_frame(&mut io).await?;
        assert_eq!(f.header.ty, FrameType::Register);
        let tlvs = parse_tlvs(&f.payload)?;
        let reg = Register::from_tlvs(&tlvs)?;

        // 6. Send REGISTER_ACK
        let reg_ack = Frame::register_ack(reg.tunnel_id, url, None)?;
        crate::connector::write_frame(&mut io, &reg_ack).await?;

        Ok(io)
    }

    #[tokio::test]
    async fn test_client_tunnel_reconnects_after_transient_drop() {
        tokio::time::timeout(Duration::from_secs(8), async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let ctrl_addr = listener.local_addr().unwrap();

            let server_task = tokio::spawn(async move {
                // Connection 1
                let (sock1, _) = listener.accept().await.unwrap();
                let sock1 = run_mock_handshake(sock1, "reconn-sec", "https://reconn.tunnel.local")
                    .await
                    .unwrap();
                let (session1, handle1) =
                    qt_mux::MuxSession::new(sock1, qt_mux::MuxConfig::server());
                tokio::spawn(async move {
                    let _ = session1.run().await;
                });

                tokio::time::sleep(Duration::from_millis(50)).await;
                // Close session 1 to simulate server drop
                let _ = handle1.close().await;

                // Connection 2 (client reconnects)
                let (sock2, _) = listener.accept().await.unwrap();
                let sock2 = run_mock_handshake(sock2, "reconn-sec", "https://reconn.tunnel.local")
                    .await
                    .unwrap();
                let (session2, _handle2) =
                    qt_mux::MuxSession::new(sock2, qt_mux::MuxConfig::server());
                tokio::spawn(async move {
                    let _ = session2.run().await;
                });

                tokio::time::sleep(Duration::from_millis(100)).await;
            });

            let client_cfg = ClientConfig::new()
                .with_server_addr(ctrl_addr)
                .with_secret("reconn-sec")
                .with_subdomain("reconn")
                .with_initial_backoff(Duration::from_millis(10))
                .with_max_backoff(Duration::from_millis(50));
            let client = Arc::new(ClientTunnel::new(client_cfg));
            let client_clone = client.clone();
            tokio::spawn(async move {
                let _ = client_clone.run().await;
            });

            for _ in 0..100 {
                if client.is_running() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            assert!(client.is_running());
            assert_eq!(
                client.public_url(),
                Some("https://reconn.tunnel.local".into())
            );

            // Server closed connection 1, wait for client to notice drop
            for _ in 0..100 {
                if !client.is_running() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            assert!(!client.is_running());
            // Item 3: verify public URL and port are cleared on drop
            assert!(client.public_url().is_none());
            assert!(client.assigned_port().is_none());

            // Client reconnects on connection 2
            for _ in 0..100 {
                if client.is_running() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            assert!(client.is_running());
            assert_eq!(
                client.public_url(),
                Some("https://reconn.tunnel.local".into())
            );

            client.shutdown();
            server_task.await.unwrap();
        })
        .await
        .expect("test timed out");
    }

    #[tokio::test]
    async fn test_client_tunnel_concurrent_run_race_condition() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (server_cfg, ctrl_addr, _) = ephemeral_server_config("shared-sec").await;
            let server = Arc::new(qt_server::Server::new(server_cfg));
            let server_clone = server.clone();
            tokio::spawn(async move { server_clone.run().await });

            tokio::time::sleep(Duration::from_millis(50)).await;

            let client = Arc::new(ClientTunnel::new(
                ClientConfig::new()
                    .with_server_addr(ctrl_addr)
                    .with_secret("shared-sec"),
            ));

            let client1 = client.clone();
            let client2 = client.clone();

            // Spawn both concurrently
            let handle1 = tokio::spawn(async move { client1.run().await });
            let handle2 = tokio::spawn(async move { client2.run().await });

            // Wait for client to become running
            for _ in 0..100 {
                if client.is_running() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            assert!(client.is_running());

            // Shut down client to allow the active run task to terminate
            client.shutdown();
            server.shutdown();

            let res1 = handle1.await.unwrap();
            let res2 = handle2.await.unwrap();

            // Exactly one must be Ok(()), the other must be ProtoError::ProtocolError("ClientTunnel is already active/running")
            let (ok_cnt, err_cnt) = match (&res1, &res2) {
                (Ok(()), Err(ProtoError::ProtocolError(msg))) => {
                    assert!(msg.contains("already active/running"));
                    (1, 1)
                }
                (Err(ProtoError::ProtocolError(msg)), Ok(())) => {
                    assert!(msg.contains("already active/running"));
                    (1, 1)
                }
                _ => panic!("Expected exactly one Ok and one ProtocolError, got res1: {res1:?}, res2: {res2:?}"),
            };
            assert_eq!(ok_cnt, 1);
            assert_eq!(err_cnt, 1);
        })
        .await
        .expect("test timed out");
    }
}
