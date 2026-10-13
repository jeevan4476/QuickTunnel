//! Client connector and QTP v1 handshake state machine.

use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use qt_mux::{MuxConfig, MuxHandle, MuxSession};
use qt_proto::control::{compute_auth_hmac, HelloAck, Ready, RegisterAck};
use qt_proto::tlv::{capabilities, parse_tlvs};
use qt_proto::{
    error_codes, Frame, FrameType, Header, ProtoError, Result, TunnelMode, ABSOLUTE_MAX_PAYLOAD,
    DEFAULT_MAX_PAYLOAD, PROTOCOL_VERSION,
};

use crate::config::ClientConfig;

/// Result of a successful QTP v1 control handshake.
#[derive(Clone)]
pub struct HandshakeResult {
    /// Server-assigned unique session identifier.
    pub session_id: u64,
    /// 32-byte secret used for session resumption.
    pub resume_secret: [u8; 32],
    /// Publicly accessible tunnel URL (e.g. `https://demo.tunnel.local`).
    pub public_url: String,
    /// Assigned public port for TCP tunnels, or `None` for HTTP tunnels.
    pub assigned_port: Option<u16>,
    /// Active multiplexer session handle for opening/accepting streams.
    pub mux_handle: MuxHandle,
}

impl std::fmt::Debug for HandshakeResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandshakeResult")
            .field("session_id", &self.session_id)
            .field("resume_secret", &"[redacted]")
            .field("public_url", &self.public_url)
            .field("assigned_port", &self.assigned_port)
            .finish()
    }
}

/// Read a single frame from an asynchronous stream.
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

/// Write a single frame to an asynchronous stream.
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

fn handle_goaway(frame: &Frame) -> ProtoError {
    let error_code = if frame.payload.len() >= 8 {
        u32::from_be_bytes(frame.payload[4..8].try_into().unwrap_or([0; 4]))
    } else {
        error_codes::PROTOCOL_ERROR
    };

    if error_code == error_codes::AUTH_FAILED {
        ProtoError::AuthFailed("server rejected authentication (AUTH_FAILED)".into())
    } else {
        ProtoError::ProtocolError(format!("server sent GOAWAY (error code {error_code})"))
    }
}

/// Negotiates and establishes QTP v1 connections with the QuickTunnel control plane.
#[derive(Clone, Debug)]
pub struct ClientConnector {
    config: ClientConfig,
}

impl ClientConnector {
    /// Create a new `ClientConnector` with the given configuration.
    pub fn new(config: ClientConfig) -> Self {
        Self { config }
    }

    /// Access the connector's configuration.
    pub fn config(&self) -> &ClientConfig {
        &self.config
    }

    /// Perform QTP v1 handshake over an existing asynchronous I/O stream, returning the active session.
    pub async fn connect_stream<T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static>(
        &self,
        mut io: T,
    ) -> Result<HandshakeResult> {
        // 1. Send HELLO
        let hello = Frame::hello(
            &self.config.client_id,
            DEFAULT_MAX_PAYLOAD,
            256 * 1024,
            capabilities::CAP_RESUME
                | capabilities::CAP_PROXY_PROTOCOL
                | capabilities::CAP_PRIORITY,
        )?;
        write_frame(&mut io, &hello).await?;

        // 2. Read HELLO_ACK
        let frame = read_frame(&mut io).await?;
        if frame.header.ty == FrameType::GoAway {
            return Err(handle_goaway(&frame));
        }
        if frame.header.ty != FrameType::HelloAck {
            return Err(ProtoError::ProtocolError(format!(
                "expected HELLO_ACK frame, got {:?}",
                frame.header.ty
            )));
        }
        let tlvs = parse_tlvs(&frame.payload)?;
        let hello_ack = HelloAck::from_tlvs(&tlvs)?;
        if hello_ack.version != PROTOCOL_VERSION {
            return Err(ProtoError::VersionMismatch {
                client: PROTOCOL_VERSION,
                server: hello_ack.version,
            });
        }

        // 3. Compute HMAC and send AUTH
        let hmac = compute_auth_hmac(
            self.config.secret.as_bytes(),
            &hello_ack.nonce,
            &self.config.client_id,
        );
        let auth = Frame::auth(&hmac)?;
        write_frame(&mut io, &auth).await?;

        // 4. Read READY
        let frame = read_frame(&mut io).await?;
        if frame.header.ty == FrameType::GoAway {
            return Err(handle_goaway(&frame));
        }
        if frame.header.ty != FrameType::Ready {
            return Err(ProtoError::ProtocolError(format!(
                "expected READY frame, got {:?}",
                frame.header.ty
            )));
        }
        let tlvs = parse_tlvs(&frame.payload)?;
        let ready = Ready::from_tlvs(&tlvs)?;

        // 5. Send REGISTER (tunnel_id 1 is the first client-initiated stream/tunnel)
        let reg = match self.config.mode {
            TunnelMode::Http => {
                Frame::register(TunnelMode::Http, self.config.subdomain.as_deref(), None, 1)?
            }
            mode => Frame::register(mode, None, self.config.remote_port, 1)?,
        };
        write_frame(&mut io, &reg).await?;

        // 6. Read REGISTER_ACK
        let frame = read_frame(&mut io).await?;
        if frame.header.ty == FrameType::GoAway {
            return Err(handle_goaway(&frame));
        }
        if frame.header.ty != FrameType::RegisterAck {
            return Err(ProtoError::ProtocolError(format!(
                "expected REGISTER_ACK frame, got {:?}",
                frame.header.ty
            )));
        }
        let tlvs = parse_tlvs(&frame.payload)?;
        let reg_ack = RegisterAck::from_tlvs(&tlvs)?;

        // 7. Initialize MuxSession in client mode and spawn session actor
        let mut mux_config = MuxConfig::client();
        if hello_ack.max_frame > 0 {
            mux_config.max_payload_size = hello_ack.max_frame.min(DEFAULT_MAX_PAYLOAD);
        }
        let (session, mux_handle) = MuxSession::new(io, mux_config);
        tokio::spawn(async move {
            if let Err(e) = session.run().await {
                tracing::debug!("MuxSession actor terminated: {}", e);
            }
        });

        Ok(HandshakeResult {
            session_id: ready.session_id,
            resume_secret: ready.resume_secret,
            public_url: reg_ack.public_url,
            assigned_port: reg_ack.assigned_port,
            mux_handle,
        })
    }

    /// Establish a TCP connection to `config.server_addr` and execute the QTP v1 handshake.
    pub async fn connect(&self) -> Result<HandshakeResult> {
        let stream = tokio::net::TcpStream::connect(self.config.server_addr)
            .await
            .map_err(|e| ProtoError::IoError(e.to_string()))?;
        stream.set_nodelay(true).ok();
        self.connect_stream(stream).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qt_proto::control::compute_auth_hmac;
    use qt_proto::tlv::parse_tlvs;
    use qt_proto::{error_codes, FrameType, Hello, Register, TunnelMode};

    async fn run_mock_server_handshake<T: AsyncRead + AsyncWrite + Unpin>(
        mut io: T,
        expected_secret: &str,
        public_url: &str,
        assigned_port: Option<u16>,
    ) -> Result<T> {
        // 1. Read HELLO
        let hello_frame = read_frame(&mut io).await?;
        assert_eq!(hello_frame.header.ty, FrameType::Hello);
        let tlvs = parse_tlvs(&hello_frame.payload)?;
        let hello = Hello::from_tlvs(&tlvs)?;

        // 2. Send HELLO_ACK
        let nonce = [42u8; 32];
        let hello_ack = Frame::hello_ack(&nonce, 16384, 0)?;
        write_frame(&mut io, &hello_ack).await?;

        // 3. Read AUTH
        let auth_frame = read_frame(&mut io).await?;
        assert_eq!(auth_frame.header.ty, FrameType::Auth);
        let tlvs = parse_tlvs(&auth_frame.payload)?;
        let auth = qt_proto::Auth::from_tlvs(&tlvs)?;

        let expected_hmac = compute_auth_hmac(expected_secret.as_bytes(), &nonce, &hello.client_id);
        if auth.hmac != expected_hmac {
            let goaway = Frame::goaway(0, error_codes::AUTH_FAILED)?;
            write_frame(&mut io, &goaway).await?;
            return Err(ProtoError::AuthFailed("Invalid HMAC".into()));
        }

        // 4. Send READY
        let session_id = 42;
        let resume_secret = [99u8; 32];
        let ready = Frame::ready(session_id, &resume_secret, 100, 10, None)?;
        write_frame(&mut io, &ready).await?;

        // 5. Read REGISTER
        let reg_frame = read_frame(&mut io).await?;
        assert_eq!(reg_frame.header.ty, FrameType::Register);
        let tlvs = parse_tlvs(&reg_frame.payload)?;
        let reg = Register::from_tlvs(&tlvs)?;

        // 6. Send REGISTER_ACK
        let reg_ack = Frame::register_ack(reg.tunnel_id, public_url, assigned_port)?;
        write_frame(&mut io, &reg_ack).await?;

        Ok(io)
    }

    #[tokio::test]
    async fn test_client_connector_handshake_http_success() {
        let (client_io, server_io) = tokio::io::duplex(65536);

        let config = ClientConfig::new()
            .with_secret("my-secret")
            .with_client_id("agent-1")
            .with_subdomain("demo")
            .with_mode(TunnelMode::Http);
        let connector = ClientConnector::new(config);

        // Spawn mock server responding to HELLO, AUTH, and REGISTER
        let server_task = tokio::spawn(async move {
            run_mock_server_handshake(server_io, "my-secret", "https://demo.tunnel.local", None)
                .await
        });

        let client_task = tokio::spawn(async move { connector.connect_stream(client_io).await });

        let (server_res, client_res) = tokio::join!(server_task, client_task);
        server_res.unwrap().unwrap();
        let handshake = client_res.unwrap().unwrap();

        assert_eq!(handshake.public_url, "https://demo.tunnel.local");
        assert_eq!(handshake.session_id, 42);
        assert_eq!(handshake.resume_secret, [99u8; 32]);
        assert!(handshake.assigned_port.is_none());
    }

    #[tokio::test]
    async fn test_client_connector_auth_failure_is_fatal() {
        let (client_io, server_io) = tokio::io::duplex(65536);

        let config = ClientConfig::new()
            .with_secret("wrong-secret")
            .with_client_id("agent-1");
        let connector = ClientConnector::new(config);

        let server_task = tokio::spawn(async move {
            run_mock_server_handshake(
                server_io,
                "correct-secret",
                "https://demo.tunnel.local",
                None,
            )
            .await
        });

        let client_task = tokio::spawn(async move { connector.connect_stream(client_io).await });

        let (_server_res, client_res) = tokio::join!(server_task, client_task);
        let err = client_res.unwrap().unwrap_err();
        assert!(matches!(err, ProtoError::AuthFailed(_)));
    }

    #[tokio::test]
    async fn test_client_connector_handshake_tcp_success() {
        let (client_io, server_io) = tokio::io::duplex(65536);

        let config = ClientConfig::new()
            .with_secret("tcp-secret")
            .with_client_id("agent-tcp")
            .with_mode(TunnelMode::Tcp)
            .with_remote_port(20431);
        let connector = ClientConnector::new(config);

        let server_task = tokio::spawn(async move {
            run_mock_server_handshake(
                server_io,
                "tcp-secret",
                "tcp://tunnel.local:20431",
                Some(20431),
            )
            .await
        });

        let client_task = tokio::spawn(async move { connector.connect_stream(client_io).await });

        let (server_res, client_res) = tokio::join!(server_task, client_task);
        server_res.unwrap().unwrap();
        let handshake = client_res.unwrap().unwrap();

        assert_eq!(handshake.public_url, "tcp://tunnel.local:20431");
        assert_eq!(handshake.assigned_port, Some(20431));
        assert_eq!(handshake.session_id, 42);
    }

    #[tokio::test]
    async fn test_client_connector_version_mismatch() {
        let (client_io, mut server_io) = tokio::io::duplex(65536);

        let config = ClientConfig::new()
            .with_secret("my-secret")
            .with_client_id("agent-1");
        let connector = ClientConnector::new(config);

        let server_task = tokio::spawn(async move {
            let hello_frame = read_frame(&mut server_io).await?;
            assert_eq!(hello_frame.header.ty, FrameType::Hello);

            // Respond with an incompatible version (version 99)
            let mut encoder = qt_proto::tlv::TlvEncoder::new();
            encoder.push(qt_proto::tlv::Tlv::new_u8(
                qt_proto::tlv::hello_ack_tags::VERSION,
                99,
            )?)?;
            encoder.push(qt_proto::tlv::Tlv::new(
                qt_proto::tlv::hello_ack_tags::NONCE,
                &[1u8; 32],
            )?)?;
            encoder.push(qt_proto::tlv::Tlv::new_u32(
                qt_proto::tlv::hello_ack_tags::MAX_FRAME,
                16384,
            )?)?;
            encoder.push(qt_proto::tlv::Tlv::new_u64(
                qt_proto::tlv::hello_ack_tags::CAPABILITIES,
                0,
            )?)?;
            let payload = encoder.finish();
            let frame = Frame::new(FrameType::HelloAck, 0, payload)?;
            write_frame(&mut server_io, &frame).await?;
            Ok::<(), ProtoError>(())
        });

        let client_task = tokio::spawn(async move { connector.connect_stream(client_io).await });

        let (server_res, client_res) = tokio::join!(server_task, client_task);
        server_res.unwrap().unwrap();
        let err = client_res.unwrap().unwrap_err();
        assert!(matches!(
            err,
            ProtoError::VersionMismatch {
                client: 1,
                server: 99
            }
        ));
    }

    #[tokio::test]
    async fn test_client_connector_unexpected_frame_types() {
        // Unexpected frame on HELLO_ACK
        let (client_io, mut server_io) = tokio::io::duplex(65536);
        let connector = ClientConnector::new(ClientConfig::new());
        let server_task = tokio::spawn(async move {
            let _ = read_frame(&mut server_io).await?;
            let ping = Frame::ping(123)?;
            write_frame(&mut server_io, &ping).await?;
            Ok::<(), ProtoError>(())
        });
        let client_task = tokio::spawn(async move { connector.connect_stream(client_io).await });
        let (_s, c) = tokio::join!(server_task, client_task);
        let err = c.unwrap().unwrap_err();
        assert!(matches!(err, ProtoError::ProtocolError(_)));
        assert!(err.to_string().contains("expected HELLO_ACK frame"));

        // Unexpected frame on READY
        let (client_io, mut server_io) = tokio::io::duplex(65536);
        let connector =
            ClientConnector::new(ClientConfig::new().with_secret("s").with_client_id("c"));
        let server_task = tokio::spawn(async move {
            let _ = read_frame(&mut server_io).await?;
            let ack = Frame::hello_ack(&[0u8; 32], 16384, 0)?;
            write_frame(&mut server_io, &ack).await?;
            let _ = read_frame(&mut server_io).await?;
            let ping = Frame::ping(456)?;
            write_frame(&mut server_io, &ping).await?;
            Ok::<(), ProtoError>(())
        });
        let client_task = tokio::spawn(async move { connector.connect_stream(client_io).await });
        let (_s, c) = tokio::join!(server_task, client_task);
        let err = c.unwrap().unwrap_err();
        assert!(matches!(err, ProtoError::ProtocolError(_)));
        assert!(err.to_string().contains("expected READY frame"));

        // Unexpected frame on REGISTER_ACK
        let (client_io, mut server_io) = tokio::io::duplex(65536);
        let connector =
            ClientConnector::new(ClientConfig::new().with_secret("s").with_client_id("c"));
        let server_task = tokio::spawn(async move {
            let _ = read_frame(&mut server_io).await?;
            let ack = Frame::hello_ack(&[0u8; 32], 16384, 0)?;
            write_frame(&mut server_io, &ack).await?;
            let _ = read_frame(&mut server_io).await?;
            let ready = Frame::ready(1, &[0u8; 32], 10, 10, None)?;
            write_frame(&mut server_io, &ready).await?;
            let _ = read_frame(&mut server_io).await?;
            let ping = Frame::ping(789)?;
            write_frame(&mut server_io, &ping).await?;
            Ok::<(), ProtoError>(())
        });
        let client_task = tokio::spawn(async move { connector.connect_stream(client_io).await });
        let (_s, c) = tokio::join!(server_task, client_task);
        let err = c.unwrap().unwrap_err();
        assert!(matches!(err, ProtoError::ProtocolError(_)));
        assert!(err.to_string().contains("expected REGISTER_ACK frame"));
    }

    #[tokio::test]
    async fn test_client_connector_server_goaway_handling() {
        // GoAway on HELLO
        let (client_io, mut server_io) = tokio::io::duplex(65536);
        let connector = ClientConnector::new(ClientConfig::new());
        let server_task = tokio::spawn(async move {
            let _ = read_frame(&mut server_io).await?;
            let goaway = Frame::goaway(0, error_codes::PROTOCOL_ERROR)?;
            write_frame(&mut server_io, &goaway).await?;
            Ok::<(), ProtoError>(())
        });
        let client_task = tokio::spawn(async move { connector.connect_stream(client_io).await });
        let (_s, c) = tokio::join!(server_task, client_task);
        let err = c.unwrap().unwrap_err();
        assert!(matches!(err, ProtoError::ProtocolError(_)));
        assert!(err.to_string().contains("server sent GOAWAY"));

        // GoAway on REGISTER
        let (client_io, mut server_io) = tokio::io::duplex(65536);
        let connector =
            ClientConnector::new(ClientConfig::new().with_secret("s").with_client_id("c"));
        let server_task = tokio::spawn(async move {
            let _ = read_frame(&mut server_io).await?;
            let ack = Frame::hello_ack(&[0u8; 32], 16384, 0)?;
            write_frame(&mut server_io, &ack).await?;
            let _ = read_frame(&mut server_io).await?;
            let ready = Frame::ready(1, &[0u8; 32], 10, 10, None)?;
            write_frame(&mut server_io, &ready).await?;
            let _ = read_frame(&mut server_io).await?;
            let goaway = Frame::goaway(0, error_codes::PROTOCOL_ERROR)?;
            write_frame(&mut server_io, &goaway).await?;
            Ok::<(), ProtoError>(())
        });
        let client_task = tokio::spawn(async move { connector.connect_stream(client_io).await });
        let (_s, c) = tokio::join!(server_task, client_task);
        let err = c.unwrap().unwrap_err();
        assert!(matches!(err, ProtoError::ProtocolError(_)));

        // GoAway with short payload (< 8 bytes) defaults to PROTOCOL_ERROR
        let (client_io, mut server_io) = tokio::io::duplex(65536);
        let connector = ClientConnector::new(ClientConfig::new());
        let server_task = tokio::spawn(async move {
            let _ = read_frame(&mut server_io).await?;
            let short_goaway =
                Frame::new(FrameType::GoAway, 0, bytes::Bytes::from_static(&[0, 1]))?;
            write_frame(&mut server_io, &short_goaway).await?;
            Ok::<(), ProtoError>(())
        });
        let client_task = tokio::spawn(async move { connector.connect_stream(client_io).await });
        let (_s, c) = tokio::join!(server_task, client_task);
        let err = c.unwrap().unwrap_err();
        assert!(matches!(err, ProtoError::ProtocolError(_)));
        assert!(err.to_string().contains("code 1"));
    }

    #[tokio::test]
    async fn test_client_connector_early_eof() {
        let (client_io, server_io) = tokio::io::duplex(65536);
        drop(server_io);

        let connector = ClientConnector::new(ClientConfig::new());
        let err = connector.connect_stream(client_io).await.unwrap_err();
        assert!(matches!(err, ProtoError::IoError(_)));
    }

    #[tokio::test]
    async fn test_client_connector_tcp_connect_e2e() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let config = ClientConfig::new()
            .with_server_addr(addr)
            .with_secret("real-secret")
            .with_client_id("tcp-agent")
            .with_mode(TunnelMode::Http)
            .with_subdomain("real-sub");
        let connector = ClientConnector::new(config);

        let (server_stop_tx, server_stop_rx) = tokio::sync::oneshot::channel::<()>();

        let server_task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let socket = run_mock_server_handshake(
                socket,
                "real-secret",
                "https://real-sub.quicktunnel.io",
                None,
            )
            .await?;
            let (session, server_handle) = MuxSession::new(socket, MuxConfig::server());
            tokio::spawn(async move {
                let _ = session.run().await;
            });
            let _ = server_stop_rx.await;
            let _ = server_handle.close().await;
            Ok::<(), ProtoError>(())
        });

        let handshake = connector.connect().await.unwrap();
        assert_eq!(handshake.public_url, "https://real-sub.quicktunnel.io");
        assert_eq!(handshake.session_id, 42);
        assert!(handshake.mux_handle.close().await.is_ok());

        let _ = server_stop_tx.send(());
        server_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn test_client_connector_tcp_connect_refused() {
        // Pick an unused local port
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener); // close immediately

        let config = ClientConfig::new().with_server_addr(addr);
        let connector = ClientConnector::new(config);
        let err = connector.connect().await.unwrap_err();
        assert!(matches!(err, ProtoError::IoError(_)));
    }

    #[test]
    fn test_handshake_result_debug_redaction_and_accessors() {
        let (client_io, _server_io) = tokio::io::duplex(64);
        let (_session, mux_handle) = MuxSession::new(client_io, MuxConfig::client());

        let res = HandshakeResult {
            session_id: 12345,
            resume_secret: [0xaa; 32],
            public_url: "https://foo.bar".into(),
            assigned_port: Some(9999),
            mux_handle,
        };

        let debug_str = format!("{res:?}");
        assert!(debug_str.contains("12345"));
        assert!(debug_str.contains("[redacted]"));
        assert!(!debug_str.contains("170")); // 0xaa in decimal
        assert!(debug_str.contains("https://foo.bar"));
        assert!(debug_str.contains("9999"));

        let cloned_res = res.clone();
        assert_eq!(cloned_res.session_id, 12345);
        assert_eq!(cloned_res.public_url, "https://foo.bar");
        assert_eq!(cloned_res.assigned_port, Some(9999));

        let config = ClientConfig::new().with_client_id("agent-x");
        let connector = ClientConnector::new(config.clone());
        assert_eq!(connector.config().client_id, "agent-x");
        let cloned = connector.clone();
        assert_eq!(cloned.config().client_id, "agent-x");
    }
}
