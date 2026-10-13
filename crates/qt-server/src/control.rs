//! Control plane listener and QTP v1 handshake state machine

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use qt_mux::{MuxConfig, MuxSession};
use qt_proto::tlv::parse_tlvs;
use qt_proto::{
    error_codes, Frame, FrameType, Header, Hello, ProtoError, Register, Result, TunnelMode,
    ABSOLUTE_MAX_PAYLOAD, DEFAULT_MAX_PAYLOAD, PROTOCOL_VERSION,
};

use crate::auth::Authenticator;
use crate::registry::TunnelRegistry;
use crate::tcp_proxy::TcpProxyManager;

/// Default handshake deadline to block Slowloris attacks
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Read a single frame from an asynchronous stream
pub(crate) async fn read_frame<T: AsyncRead + Unpin>(io: &mut T) -> Result<Frame> {
    let mut header_buf = [0u8; 12];
    io.read_exact(&mut header_buf)
        .await
        .map_err(|e| ProtoError::IoError(e.to_string()))?;
    let header = Header::decode(&header_buf, ABSOLUTE_MAX_PAYLOAD)?;
    let mut payload = vec![0u8; header.len as usize];
    if header.len > 0 {
        io.read_exact(&mut payload)
            .await
            .map_err(|e| ProtoError::IoError(e.to_string()))?;
    }
    Ok(Frame {
        header,
        payload: bytes::Bytes::from(payload),
    })
}

/// Write a single frame to an asynchronous stream
pub(crate) async fn write_frame<T: AsyncWrite + Unpin>(io: &mut T, frame: &Frame) -> Result<()> {
    let mut buf = BytesMut::new();
    frame.encode(&mut buf);
    io.write_all(&buf)
        .await
        .map_err(|e| ProtoError::IoError(e.to_string()))?;
    io.flush()
        .await
        .map_err(|e| ProtoError::IoError(e.to_string()))?;
    Ok(())
}

/// Control listener accepting incoming client tunnel connections
#[derive(Clone)]
pub struct ControlListener {
    bind_addr: SocketAddr,
    authenticator: Arc<Authenticator>,
    registry: Arc<TunnelRegistry>,
    handshake_timeout: Duration,
    tcp_proxy: Option<TcpProxyManager>,
}

impl ControlListener {
    /// Create a new ControlListener
    pub fn new(
        bind_addr: SocketAddr,
        authenticator: Arc<Authenticator>,
        registry: Arc<TunnelRegistry>,
    ) -> Self {
        Self {
            bind_addr,
            authenticator,
            registry,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            tcp_proxy: None,
        }
    }

    /// Attach a TcpProxyManager for dynamic TCP visitor port listener creation
    pub fn with_tcp_proxy(mut self, tcp_proxy: TcpProxyManager) -> Self {
        self.tcp_proxy = Some(tcp_proxy);
        self
    }

    /// Override the handshake timeout (primarily for testing)
    pub fn with_handshake_timeout(mut self, timeout: Duration) -> Self {
        self.handshake_timeout = timeout;
        self
    }

    /// Get configured bind address
    pub fn bind_addr(&self) -> SocketAddr {
        self.bind_addr
    }

    /// Run the control plane TCP accept loop
    pub async fn run(&self) -> Result<()> {
        let listener = tokio::net::TcpListener::bind(self.bind_addr)
            .await
            .map_err(|e| ProtoError::IoError(e.to_string()))?;

        loop {
            let (socket, _) = listener
                .accept()
                .await
                .map_err(|e| ProtoError::IoError(e.to_string()))?;
            socket.set_nodelay(true).ok();

            let this = self.clone();
            tokio::spawn(async move {
                if let Err(e) = this.handle_connection(socket).await {
                    tracing::debug!("Control connection error: {}", e);
                }
            });
        }
    }

    /// Perform handshake, authentication, and tunnel registration, then hand off to `MuxSession`
    pub async fn handle_connection<T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static>(
        &self,
        mut io: T,
    ) -> Result<()> {
        let timeout = self.handshake_timeout;
        let handshake_fut = self.execute_handshake_and_register(&mut io);

        let (session_id, reg, url, port) = match tokio::time::timeout(timeout, handshake_fut).await
        {
            Ok(res) => res?,
            Err(_) => {
                return Err(ProtoError::ProtocolError(
                    "Handshake timed out (5s deadline exceeded)".into(),
                ));
            }
        };

        // Send REGISTER_ACK directly on wire before mux session takes over
        let reg_ack = Frame::register_ack(reg.tunnel_id, &url, port)?;
        write_frame(&mut io, &reg_ack).await?;

        // Initialize MuxSession
        let (session, handle) = MuxSession::new(io, MuxConfig::server());

        // Register route with MuxHandle
        match reg.mode {
            TunnelMode::Http => {
                self.registry.register_http(
                    session_id,
                    reg.tunnel_id,
                    reg.subdomain.as_deref(),
                    handle,
                )?;
            }
            TunnelMode::Tcp | TunnelMode::TcpPassthrough => {
                let port_num = port.ok_or_else(|| {
                    ProtoError::ProtocolError("No port assigned for TCP tunnel".into())
                })?;
                self.registry
                    .register_tcp(session_id, reg.tunnel_id, port, handle)?;
                if let Some(ref tcp_proxy) = self.tcp_proxy {
                    tcp_proxy.start_listener(port_num).await?;
                }
            }
        }

        // Spawn MuxSession actor with session cleanup on termination
        let registry = self.registry.clone();
        let tcp_proxy = self.tcp_proxy.clone();
        tokio::spawn(async move {
            let _ = session.run().await;
            registry.remove_session(session_id);
            if let Some(p) = port {
                if let Some(ref proxy) = tcp_proxy {
                    proxy.stop_listener(p);
                }
            }
        });

        Ok(())
    }

    async fn execute_handshake_and_register<T: AsyncRead + AsyncWrite + Unpin>(
        &self,
        io: &mut T,
    ) -> Result<(u64, Register, String, Option<u16>)> {
        // 1. Read HELLO
        let hello_frame = read_frame(io).await?;
        if hello_frame.header.ty != FrameType::Hello {
            return Err(ProtoError::ProtocolError(format!(
                "Expected HELLO frame, got {:?}",
                hello_frame.header.ty
            )));
        }
        let tlvs = parse_tlvs(&hello_frame.payload)?;
        let hello = Hello::from_tlvs(&tlvs)?;
        if hello.version != PROTOCOL_VERSION {
            let goaway = Frame::goaway(0, error_codes::PROTOCOL_ERROR)?;
            write_frame(io, &goaway).await.ok();
            return Err(ProtoError::VersionMismatch {
                client: hello.version,
                server: PROTOCOL_VERSION,
            });
        }

        // 2. Send HELLO_ACK
        let nonce = self.authenticator.generate_challenge();
        let max_frame = hello.max_frame.min(DEFAULT_MAX_PAYLOAD);
        let hello_ack = Frame::hello_ack(&nonce, max_frame, hello.capabilities)?;
        write_frame(io, &hello_ack).await?;

        // 3. Read AUTH
        let auth_frame = read_frame(io).await?;
        if auth_frame.header.ty != FrameType::Auth {
            return Err(ProtoError::ProtocolError(format!(
                "Expected AUTH frame, got {:?}",
                auth_frame.header.ty
            )));
        }
        let tlvs = parse_tlvs(&auth_frame.payload)?;
        let auth = qt_proto::Auth::from_tlvs(&tlvs)?;

        let valid = self
            .authenticator
            .verify_auth(&hello.client_id, &nonce, &auth.hmac)?;
        if !valid {
            let goaway = Frame::goaway(0, error_codes::AUTH_FAILED)?;
            write_frame(io, &goaway).await.ok();
            return Err(ProtoError::AuthFailed(format!(
                "Invalid auth HMAC for client '{}'",
                hello.client_id
            )));
        }

        // 4. Send READY
        let (session_id, resume_secret) = self.authenticator.generate_session_credentials();
        let limits = self.authenticator.limits();
        let ready = Frame::ready(
            session_id,
            &resume_secret,
            limits.max_streams,
            limits.max_tunnels,
            None,
        )?;
        write_frame(io, &ready).await?;

        // 5. Read REGISTER
        let reg_frame = read_frame(io).await?;
        if reg_frame.header.ty != FrameType::Register {
            return Err(ProtoError::ProtocolError(format!(
                "Expected REGISTER frame, got {:?}",
                reg_frame.header.ty
            )));
        }
        let tlvs = parse_tlvs(&reg_frame.payload)?;
        let reg = Register::from_tlvs(&tlvs)?;

        // Pre-validate registration and compute public url/port
        let (url, port) = match reg.mode {
            TunnelMode::Http => {
                let sub = match reg.subdomain.as_deref() {
                    Some(s) => {
                        crate::registry::validate_subdomain(s)?;
                        if self.registry.find_http(s).is_some() {
                            return Err(ProtoError::ProtocolError(format!(
                                "Subdomain '{s}' already in use"
                            )));
                        }
                        s.to_string()
                    }
                    None => "assigned".to_string(),
                };
                let url = format!("https://{}.{}", sub, self.registry.root_domain());
                (url, None)
            }
            TunnelMode::Tcp | TunnelMode::TcpPassthrough => {
                let port = match reg.remote_port {
                    Some(p) => {
                        if !self.registry.tcp_port_range().contains(&p) {
                            return Err(ProtoError::ProtocolError(format!(
                                "Port {p} outside allowed range"
                            )));
                        }
                        if self.registry.find_tcp(p).is_some() {
                            return Err(ProtoError::ProtocolError(format!(
                                "Port {p} already in use"
                            )));
                        }
                        p
                    }
                    None => {
                        let mut found = None;
                        for p in self.registry.tcp_port_range().clone() {
                            if self.registry.find_tcp(p).is_none() {
                                found = Some(p);
                                break;
                            }
                        }
                        found.ok_or_else(|| {
                            ProtoError::ProtocolError("No available TCP ports in range".into())
                        })?
                    }
                };
                let url = format!("tcp://{}:{}", self.registry.root_domain(), port);
                (url, Some(port))
            }
        };

        Ok((session_id, reg, url, port))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qt_proto::{compute_auth_hmac, HelloAck, SessionLimits};
    use std::sync::Arc;

    async fn run_test_client_handshake<T: AsyncRead + AsyncWrite + Unpin>(
        mut io: T,
        secret: &str,
        client_id: &str,
        subdomain: Option<&str>,
    ) -> Result<T> {
        // 1. Send HELLO
        let hello = Frame::hello(client_id, 16384, 256 * 1024, 0)?;
        write_frame(&mut io, &hello).await?;

        // 2. Read HELLO_ACK
        let ack_frame = read_frame(&mut io).await?;
        assert_eq!(ack_frame.header.ty, FrameType::HelloAck);
        let tlvs = parse_tlvs(&ack_frame.payload)?;
        let ack = HelloAck::from_tlvs(&tlvs)?;

        // 3. Send AUTH
        let hmac = compute_auth_hmac(secret.as_bytes(), &ack.nonce, client_id);
        let auth = Frame::auth(&hmac)?;
        write_frame(&mut io, &auth).await?;

        // 4. Read READY
        let ready_frame = read_frame(&mut io).await?;
        if ready_frame.header.ty == FrameType::GoAway {
            return Err(ProtoError::AuthFailed("Server sent GOAWAY".into()));
        }
        assert_eq!(ready_frame.header.ty, FrameType::Ready);

        // 5. Send REGISTER
        let reg = Frame::register(TunnelMode::Http, subdomain, None, 1)?;
        write_frame(&mut io, &reg).await?;

        // 6. Read REGISTER_ACK
        let reg_ack_frame = read_frame(&mut io).await?;
        assert_eq!(reg_ack_frame.header.ty, FrameType::RegisterAck);

        Ok(io)
    }

    async fn run_test_client_tcp_handshake<T: AsyncRead + AsyncWrite + Unpin>(
        mut io: T,
        secret: &str,
        client_id: &str,
        port: Option<u16>,
    ) -> Result<T> {
        let hello = Frame::hello(client_id, 16384, 256 * 1024, 0)?;
        write_frame(&mut io, &hello).await?;

        let ack_frame = read_frame(&mut io).await?;
        let tlvs = parse_tlvs(&ack_frame.payload)?;
        let ack = HelloAck::from_tlvs(&tlvs)?;

        let hmac = compute_auth_hmac(secret.as_bytes(), &ack.nonce, client_id);
        let auth = Frame::auth(&hmac)?;
        write_frame(&mut io, &auth).await?;

        let ready_frame = read_frame(&mut io).await?;
        assert_eq!(ready_frame.header.ty, FrameType::Ready);

        let reg = Frame::register(TunnelMode::Tcp, None, port, 1)?;
        write_frame(&mut io, &reg).await?;

        let reg_ack_frame = read_frame(&mut io).await?;
        assert_eq!(reg_ack_frame.header.ty, FrameType::RegisterAck);

        Ok(io)
    }

    #[tokio::test]
    async fn test_control_listener_handshake_and_registration() {
        let auth = Arc::new(Authenticator::new("secret", SessionLimits::default()));
        let registry = Arc::new(TunnelRegistry::new(20000..=20010, "example.com".into()));
        let listener = ControlListener::new(
            "127.0.0.1:7000".parse().unwrap(),
            auth.clone(),
            registry.clone(),
        );

        assert_eq!(listener.bind_addr(), "127.0.0.1:7000".parse().unwrap());

        let (client_io, server_io) = tokio::io::duplex(65536);

        let server_task = tokio::spawn(async move { listener.handle_connection(server_io).await });

        let client_task = tokio::spawn(async move {
            run_test_client_handshake(client_io, "secret", "agent-1", Some("sub1")).await
        });

        let (server_res, client_res) = tokio::join!(server_task, client_task);
        server_res.unwrap().unwrap();
        let _client_io = client_res.unwrap().unwrap();

        assert!(registry.find_http("sub1").is_some());
    }

    #[tokio::test]
    async fn test_control_listener_tcp_registration() {
        let auth = Arc::new(Authenticator::new("secret", SessionLimits::default()));
        let registry = Arc::new(TunnelRegistry::new(20000..=20010, "example.com".into()));
        let listener = ControlListener::new(
            "127.0.0.1:7000".parse().unwrap(),
            auth.clone(),
            registry.clone(),
        );

        let (client_io, server_io) = tokio::io::duplex(65536);

        let server_task = tokio::spawn(async move { listener.handle_connection(server_io).await });

        let client_task = tokio::spawn(async move {
            run_test_client_tcp_handshake(client_io, "secret", "agent-2", Some(20005)).await
        });

        let (server_res, client_res) = tokio::join!(server_task, client_task);
        server_res.unwrap().unwrap();
        let _client_io = client_res.unwrap().unwrap();

        assert!(registry.find_tcp(20005).is_some());
    }

    #[tokio::test]
    async fn test_control_listener_invalid_auth() {
        let auth = Arc::new(Authenticator::new(
            "correct-secret",
            SessionLimits::default(),
        ));
        let registry = Arc::new(TunnelRegistry::new(20000..=20010, "example.com".into()));
        let listener = ControlListener::new(
            "127.0.0.1:7000".parse().unwrap(),
            auth.clone(),
            registry.clone(),
        );

        let (client_io, server_io) = tokio::io::duplex(65536);

        let server_task = tokio::spawn(async move { listener.handle_connection(server_io).await });

        let client_task = tokio::spawn(async move {
            run_test_client_handshake(client_io, "wrong-secret", "agent-1", Some("sub1")).await
        });

        let (server_res, client_res) = tokio::join!(server_task, client_task);
        assert!(server_res.unwrap().is_err());
        assert!(client_res.unwrap().is_err());
    }

    #[tokio::test]
    async fn test_control_listener_handshake_timeout() {
        let auth = Arc::new(Authenticator::new("secret", SessionLimits::default()));
        let registry = Arc::new(TunnelRegistry::new(20000..=20010, "example.com".into()));
        let listener = ControlListener::new(
            "127.0.0.1:7000".parse().unwrap(),
            auth.clone(),
            registry.clone(),
        )
        .with_handshake_timeout(Duration::from_millis(50));

        let (_client_io, server_io) = tokio::io::duplex(65536);

        // Server waits, client does nothing
        let res = listener.handle_connection(server_io).await;
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("deadline"));
    }

    #[tokio::test]
    async fn test_control_listener_wrong_initial_frame() {
        let auth = Arc::new(Authenticator::new("secret", SessionLimits::default()));
        let registry = Arc::new(TunnelRegistry::new(20000..=20010, "example.com".into()));
        let listener = ControlListener::new(
            "127.0.0.1:7000".parse().unwrap(),
            auth.clone(),
            registry.clone(),
        );

        let (mut client_io, server_io) = tokio::io::duplex(65536);

        let server_task = tokio::spawn(async move { listener.handle_connection(server_io).await });

        // Client sends PING instead of HELLO
        let ping = Frame::ping(12345).unwrap();
        write_frame(&mut client_io, &ping).await.unwrap();

        let res = server_task.await.unwrap();
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_control_listener_version_mismatch() {
        let auth = Arc::new(Authenticator::new("secret", SessionLimits::default()));
        let registry = Arc::new(TunnelRegistry::new(20000..=20010, "example.com".into()));
        let listener = ControlListener::new(
            "127.0.0.1:7000".parse().unwrap(),
            auth.clone(),
            registry.clone(),
        );

        let (mut client_io, server_io) = tokio::io::duplex(65536);

        let server_task = tokio::spawn(async move { listener.handle_connection(server_io).await });

        // Client sends HELLO with version 99
        let mut encoder = qt_proto::tlv::TlvEncoder::new();
        encoder
            .push(qt_proto::tlv::Tlv::new_u8(qt_proto::tlv::hello_tags::VERSION, 99).unwrap())
            .unwrap();
        encoder
            .push(
                qt_proto::tlv::Tlv::new(qt_proto::tlv::hello_tags::CLIENT_ID, b"client-99")
                    .unwrap(),
            )
            .unwrap();
        encoder
            .push(qt_proto::tlv::Tlv::new_u32(qt_proto::tlv::hello_tags::MAX_FRAME, 16384).unwrap())
            .unwrap();
        encoder
            .push(
                qt_proto::tlv::Tlv::new_u32(qt_proto::tlv::hello_tags::INITIAL_WINDOW, 65536)
                    .unwrap(),
            )
            .unwrap();
        encoder
            .push(qt_proto::tlv::Tlv::new_u64(qt_proto::tlv::hello_tags::CAPABILITIES, 0).unwrap())
            .unwrap();
        let payload = encoder.finish();
        let hello_bad_ver = Frame {
            header: Header {
                ty: FrameType::Hello,
                flags: 0,
                stream_id: 0,
                len: payload.len() as u32,
            },
            payload,
        };
        write_frame(&mut client_io, &hello_bad_ver).await.unwrap();

        let res = server_task.await.unwrap();
        assert!(res.is_err());
        assert!(matches!(
            res.unwrap_err(),
            ProtoError::VersionMismatch { .. }
        ));
    }

    #[tokio::test]
    async fn test_control_listener_wrong_auth_frame_type() {
        let auth = Arc::new(Authenticator::new("secret", SessionLimits::default()));
        let registry = Arc::new(TunnelRegistry::new(20000..=20010, "example.com".into()));
        let listener = ControlListener::new(
            "127.0.0.1:7000".parse().unwrap(),
            auth.clone(),
            registry.clone(),
        );

        let (mut client_io, server_io) = tokio::io::duplex(65536);

        let server_task = tokio::spawn(async move { listener.handle_connection(server_io).await });

        // Step 1: Send valid HELLO
        let hello = Frame::hello("client-1", 16384, 65536, 0).unwrap();
        write_frame(&mut client_io, &hello).await.unwrap();

        // Step 2: Read HELLO_ACK
        let _ = read_frame(&mut client_io).await.unwrap();

        // Step 3: Send PING instead of AUTH
        let ping = Frame::ping(999).unwrap();
        write_frame(&mut client_io, &ping).await.unwrap();

        let res = server_task.await.unwrap();
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_control_listener_wrong_register_frame_type() {
        let auth = Arc::new(Authenticator::new("secret", SessionLimits::default()));
        let registry = Arc::new(TunnelRegistry::new(20000..=20010, "example.com".into()));
        let listener = ControlListener::new(
            "127.0.0.1:7000".parse().unwrap(),
            auth.clone(),
            registry.clone(),
        );

        let (mut client_io, server_io) = tokio::io::duplex(65536);

        let server_task = tokio::spawn(async move { listener.handle_connection(server_io).await });

        // Step 1: Send HELLO
        let hello = Frame::hello("client-1", 16384, 65536, 0).unwrap();
        write_frame(&mut client_io, &hello).await.unwrap();

        // Step 2: Read HELLO_ACK
        let ack_frame = read_frame(&mut client_io).await.unwrap();
        let tlvs = parse_tlvs(&ack_frame.payload).unwrap();
        let ack = HelloAck::from_tlvs(&tlvs).unwrap();

        // Step 3: Send AUTH
        let mac = compute_auth_hmac(b"secret", &ack.nonce, "client-1");
        let auth_frame = Frame::auth(&mac).unwrap();
        write_frame(&mut client_io, &auth_frame).await.unwrap();

        // Step 4: Read READY
        let _ = read_frame(&mut client_io).await.unwrap();

        // Step 5: Send PING instead of REGISTER
        let ping = Frame::ping(111).unwrap();
        write_frame(&mut client_io, &ping).await.unwrap();

        let res = server_task.await.unwrap();
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_control_listener_subdomain_already_in_use() {
        let auth = Arc::new(Authenticator::new("secret", SessionLimits::default()));
        let registry = Arc::new(TunnelRegistry::new(20000..=20010, "example.com".into()));
        let (dummy_io, _) = tokio::io::duplex(1024);
        let (_, handle) = MuxSession::new(dummy_io, MuxConfig::server());
        registry
            .register_http(99, 1, Some("taken"), handle)
            .unwrap();

        let listener = ControlListener::new(
            "127.0.0.1:7000".parse().unwrap(),
            auth.clone(),
            registry.clone(),
        );

        let (client_io, server_io) = tokio::io::duplex(65536);

        let server_task = tokio::spawn(async move { listener.handle_connection(server_io).await });

        let client_task = tokio::spawn(async move {
            run_test_client_handshake(client_io, "secret", "client-1", Some("taken")).await
        });

        let (server_res, client_res) = tokio::join!(server_task, client_task);
        assert!(server_res.unwrap().is_err());
        assert!(client_res.unwrap().is_err());
    }

    #[tokio::test]
    async fn test_control_listener_tcp_port_errors() {
        let auth = Arc::new(Authenticator::new("secret", SessionLimits::default()));
        let registry = Arc::new(TunnelRegistry::new(20000..=20001, "example.com".into()));
        let (dummy_io, _) = tokio::io::duplex(1024);
        let (_, handle) = MuxSession::new(dummy_io, MuxConfig::server());
        registry.register_tcp(99, 1, Some(20000), handle).unwrap();

        let listener = ControlListener::new(
            "127.0.0.1:7000".parse().unwrap(),
            auth.clone(),
            registry.clone(),
        );

        // Test port out of range
        let (client_io, server_io) = tokio::io::duplex(65536);
        let s_task = tokio::spawn({
            let l = listener.clone();
            async move { l.handle_connection(server_io).await }
        });
        let c_task = tokio::spawn(async move {
            run_test_client_tcp_handshake(client_io, "secret", "c1", Some(30000)).await
        });
        let (s_res, c_res) = tokio::join!(s_task, c_task);
        assert!(s_res.unwrap().is_err());
        assert!(c_res.unwrap().is_err());

        // Test port already taken
        let (client_io2, server_io2) = tokio::io::duplex(65536);
        let s_task2 = tokio::spawn({
            let l = listener.clone();
            async move { l.handle_connection(server_io2).await }
        });
        let c_task2 = tokio::spawn(async move {
            run_test_client_tcp_handshake(client_io2, "secret", "c2", Some(20000)).await
        });
        let (s_res2, c_res2) = tokio::join!(s_task2, c_task2);
        assert!(s_res2.unwrap().is_err());
        assert!(c_res2.unwrap().is_err());

        // Test exhaustion when port is None
        // Allocate remaining port 20001
        let (dummy_io2, _) = tokio::io::duplex(1024);
        let (_, handle2) = MuxSession::new(dummy_io2, MuxConfig::server());
        registry.register_tcp(100, 2, Some(20001), handle2).unwrap();

        let (client_io3, server_io3) = tokio::io::duplex(65536);
        let s_task3 = tokio::spawn({
            let l = listener.clone();
            async move { l.handle_connection(server_io3).await }
        });
        let c_task3 = tokio::spawn(async move {
            run_test_client_tcp_handshake(client_io3, "secret", "c3", None).await
        });
        let (s_res3, c_res3) = tokio::join!(s_task3, c_task3);
        assert!(s_res3.unwrap().is_err());
        assert!(c_res3.unwrap().is_err());
    }

    #[tokio::test]
    async fn test_control_listener_real_tcp_run() {
        let auth = Arc::new(Authenticator::new("secret", SessionLimits::default()));
        let registry = Arc::new(TunnelRegistry::new(20000..=20010, "example.com".into()));

        // Bind on OS-assigned ephemeral port
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = listener.local_addr().unwrap();
        drop(listener); // release so listener.run can bind

        let ctrl_listener = ControlListener::new(local_addr, auth.clone(), registry.clone());
        let run_task = tokio::spawn({
            let cl = ctrl_listener.clone();
            async move { cl.run().await }
        });

        // Give listener a moment to bind
        tokio::time::sleep(Duration::from_millis(50)).await;

        let client_socket = tokio::net::TcpStream::connect(local_addr).await.unwrap();
        let client_res =
            run_test_client_handshake(client_socket, "secret", "client-real", Some("real-app"))
                .await;
        assert!(client_res.is_ok());

        assert!(registry.find_http("real-app").is_some());
        run_task.abort();
    }
}
