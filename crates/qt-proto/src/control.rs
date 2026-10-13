//! Control payload structures for handshake, auth, and tunnel registration

use crate::frame::TunnelMode;
use crate::{tlv::*, ProtoError, Result};
use bytes::Bytes;

/// HELLO payload (client -> server)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    pub version: u8,
    pub client_id: String,
    pub max_frame: u32,
    pub initial_window: u32,
    pub capabilities: u64,
}

impl Hello {
    pub fn new(client_id: impl Into<String>) -> Self {
        Hello {
            version: crate::PROTOCOL_VERSION,
            client_id: client_id.into(),
            max_frame: crate::DEFAULT_MAX_PAYLOAD,
            initial_window: 256 * 1024, // 256 KiB default
            capabilities: capabilities::CAP_RESUME
                | capabilities::CAP_PROXY_PROTOCOL
                | capabilities::CAP_PRIORITY,
        }
    }

    pub fn to_tlvs(&self) -> Vec<Tlv> {
        vec![
            Tlv::new_u8(hello_tags::VERSION, self.version).unwrap(),
            Tlv::new(hello_tags::CLIENT_ID, self.client_id.as_bytes()).unwrap(),
            Tlv::new_u32(hello_tags::MAX_FRAME, self.max_frame).unwrap(),
            Tlv::new_u32(hello_tags::INITIAL_WINDOW, self.initial_window).unwrap(),
            Tlv::new_u64(hello_tags::CAPABILITIES, self.capabilities).unwrap(),
        ]
    }

    pub fn from_tlvs(tlvs: &[Tlv]) -> Result<Self> {
        let version = find_tlv_by_tag(tlvs, hello_tags::VERSION)?
            .ok_or(ProtoError::MissingRequiredTlv(hello_tags::VERSION))?
            .as_u8()?;
        let client_id = find_tlv_by_tag(tlvs, hello_tags::CLIENT_ID)?
            .ok_or(ProtoError::MissingRequiredTlv(hello_tags::CLIENT_ID))?
            .as_str()?
            .to_string();
        let max_frame = find_tlv_by_tag(tlvs, hello_tags::MAX_FRAME)?
            .ok_or(ProtoError::MissingRequiredTlv(hello_tags::MAX_FRAME))?
            .as_u32()?;
        let initial_window = find_tlv_by_tag(tlvs, hello_tags::INITIAL_WINDOW)?
            .ok_or(ProtoError::MissingRequiredTlv(hello_tags::INITIAL_WINDOW))?
            .as_u32()?;
        let capabilities = find_tlv_by_tag(tlvs, hello_tags::CAPABILITIES)?
            .ok_or(ProtoError::MissingRequiredTlv(hello_tags::CAPABILITIES))?
            .as_u64()?;

        Ok(Hello {
            version,
            client_id,
            max_frame,
            initial_window,
            capabilities,
        })
    }
}

/// HELLO_ACK payload (server -> client)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloAck {
    pub version: u8,
    pub nonce: [u8; 32],
    pub max_frame: u32,
    pub capabilities: u64,
}

impl HelloAck {
    pub fn new(nonce: [u8; 32], max_frame: u32, capabilities: u64) -> Self {
        HelloAck {
            version: crate::PROTOCOL_VERSION,
            nonce,
            max_frame,
            capabilities,
        }
    }

    pub fn to_tlvs(&self) -> Vec<Tlv> {
        vec![
            Tlv::new_u8(hello_ack_tags::VERSION, self.version).unwrap(),
            Tlv::new(hello_ack_tags::NONCE, &self.nonce).unwrap(),
            Tlv::new_u32(hello_ack_tags::MAX_FRAME, self.max_frame).unwrap(),
            Tlv::new_u64(hello_ack_tags::CAPABILITIES, self.capabilities).unwrap(),
        ]
    }

    pub fn from_tlvs(tlvs: &[Tlv]) -> Result<Self> {
        let version = find_tlv_by_tag(tlvs, hello_ack_tags::VERSION)?
            .ok_or(ProtoError::MissingRequiredTlv(hello_ack_tags::VERSION))?
            .as_u8()?;
        let nonce_bytes = find_tlv_by_tag(tlvs, hello_ack_tags::NONCE)?
            .ok_or(ProtoError::MissingRequiredTlv(hello_ack_tags::NONCE))?
            .as_bytes();
        if nonce_bytes.len() != 32 {
            return Err(ProtoError::TlvValueTooLong(nonce_bytes.len(), 32));
        }
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(nonce_bytes);

        let max_frame = find_tlv_by_tag(tlvs, hello_ack_tags::MAX_FRAME)?
            .ok_or(ProtoError::MissingRequiredTlv(hello_ack_tags::MAX_FRAME))?
            .as_u32()?;
        let capabilities = find_tlv_by_tag(tlvs, hello_ack_tags::CAPABILITIES)?
            .ok_or(ProtoError::MissingRequiredTlv(hello_ack_tags::CAPABILITIES))?
            .as_u64()?;

        Ok(HelloAck {
            version,
            nonce,
            max_frame,
            capabilities,
        })
    }
}

/// AUTH payload (client -> server)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Auth {
    pub hmac: [u8; 32],
}

impl Auth {
    pub fn new(hmac: [u8; 32]) -> Self {
        Auth { hmac }
    }

    pub fn to_tlvs(&self) -> Vec<Tlv> {
        vec![Tlv::new(auth_tags::HMAC, &self.hmac).unwrap()]
    }

    pub fn from_tlvs(tlvs: &[Tlv]) -> Result<Self> {
        let hmac_bytes = find_tlv_by_tag(tlvs, auth_tags::HMAC)?
            .ok_or(ProtoError::MissingRequiredTlv(auth_tags::HMAC))?
            .as_bytes();
        if hmac_bytes.len() != 32 {
            return Err(ProtoError::TlvValueTooLong(hmac_bytes.len(), 32));
        }
        let mut hmac = [0u8; 32];
        hmac.copy_from_slice(hmac_bytes);
        Ok(Auth { hmac })
    }
}

/// READY payload (server -> client)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ready {
    pub session_id: u64,
    pub resume_secret: [u8; 32],
    pub max_streams: u32,
    pub max_tunnels: u32,
    pub bandwidth_limit: Option<u64>,
}

impl Ready {
    pub fn new(
        session_id: u64,
        resume_secret: [u8; 32],
        max_streams: u32,
        max_tunnels: u32,
        bandwidth_limit: Option<u64>,
    ) -> Self {
        Ready {
            session_id,
            resume_secret,
            max_streams,
            max_tunnels,
            bandwidth_limit,
        }
    }

    pub fn to_tlvs(&self) -> Vec<Tlv> {
        let mut tlvs = vec![
            Tlv::new_u64(ready_tags::SESSION_ID, self.session_id).unwrap(),
            Tlv::new(ready_tags::RESUME_SECRET, &self.resume_secret).unwrap(),
            Tlv::new_u32(ready_tags::MAX_STREAMS, self.max_streams).unwrap(),
            Tlv::new_u32(ready_tags::MAX_TUNNELS, self.max_tunnels).unwrap(),
        ];
        if let Some(bw) = self.bandwidth_limit {
            tlvs.push(Tlv::new_u64(ready_tags::BANDWIDTH_LIMIT, bw).unwrap());
        }
        tlvs
    }

    pub fn from_tlvs(tlvs: &[Tlv]) -> Result<Self> {
        let session_id = find_tlv_by_tag(tlvs, ready_tags::SESSION_ID)?
            .ok_or(ProtoError::MissingRequiredTlv(ready_tags::SESSION_ID))?
            .as_u64()?;
        let resume_bytes = find_tlv_by_tag(tlvs, ready_tags::RESUME_SECRET)?
            .ok_or(ProtoError::MissingRequiredTlv(ready_tags::RESUME_SECRET))?
            .as_bytes();
        if resume_bytes.len() != 32 {
            return Err(ProtoError::TlvValueTooLong(resume_bytes.len(), 32));
        }
        let mut resume_secret = [0u8; 32];
        resume_secret.copy_from_slice(resume_bytes);

        let max_streams = find_tlv_by_tag(tlvs, ready_tags::MAX_STREAMS)?
            .ok_or(ProtoError::MissingRequiredTlv(ready_tags::MAX_STREAMS))?
            .as_u32()?;
        let max_tunnels = find_tlv_by_tag(tlvs, ready_tags::MAX_TUNNELS)?
            .ok_or(ProtoError::MissingRequiredTlv(ready_tags::MAX_TUNNELS))?
            .as_u32()?;

        let bandwidth_limit = find_tlv_by_tag(tlvs, ready_tags::BANDWIDTH_LIMIT)?
            .map(|t| t.as_u64())
            .transpose()?;

        Ok(Ready {
            session_id,
            resume_secret,
            max_streams,
            max_tunnels,
            bandwidth_limit,
        })
    }
}

/// REGISTER payload (client -> server)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Register {
    pub mode: TunnelMode,
    pub tunnel_id: u32,
    pub subdomain: Option<String>,
    pub remote_port: Option<u16>,
}

impl Register {
    pub fn new_http(tunnel_id: u32, subdomain: Option<String>) -> Self {
        Register {
            mode: TunnelMode::Http,
            tunnel_id,
            subdomain,
            remote_port: None,
        }
    }

    pub fn new_tcp(tunnel_id: u32, remote_port: Option<u16>) -> Self {
        Register {
            mode: TunnelMode::Tcp,
            tunnel_id,
            subdomain: None,
            remote_port,
        }
    }

    pub fn to_tlvs(&self) -> Vec<Tlv> {
        let mut tlvs = vec![
            Tlv::new_u8(register_tags::MODE, self.mode as u8).unwrap(),
            Tlv::new_u32(register_tags::TUNNEL_ID, self.tunnel_id).unwrap(),
        ];
        if let Some(ref sub) = self.subdomain {
            tlvs.push(Tlv::new(register_tags::SUBDOMAIN, sub.as_bytes()).unwrap());
        }
        if let Some(port) = self.remote_port {
            tlvs.push(Tlv::new_u16(register_tags::REMOTE_PORT, port).unwrap());
        }
        tlvs
    }

    pub fn from_tlvs(tlvs: &[Tlv]) -> Result<Self> {
        let mode_byte = find_tlv_by_tag(tlvs, register_tags::MODE)?
            .ok_or(ProtoError::MissingRequiredTlv(register_tags::MODE))?
            .as_u8()?;
        let mode = TunnelMode::try_from(mode_byte)?;
        let tunnel_id = find_tlv_by_tag(tlvs, register_tags::TUNNEL_ID)?
            .ok_or(ProtoError::MissingRequiredTlv(register_tags::TUNNEL_ID))?
            .as_u32()?;

        let subdomain = find_tlv_by_tag(tlvs, register_tags::SUBDOMAIN)?
            .map(|t| t.as_str().map(|s| s.to_string()))
            .transpose()?;
        let remote_port = find_tlv_by_tag(tlvs, register_tags::REMOTE_PORT)?
            .map(|t| t.as_u16())
            .transpose()?;

        Ok(Register {
            mode,
            tunnel_id,
            subdomain,
            remote_port,
        })
    }
}

/// REGISTER_ACK payload (server -> client)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterAck {
    pub public_url: String,
    pub tunnel_id: u32,
    pub assigned_port: Option<u16>,
}

impl RegisterAck {
    pub fn new(public_url: impl Into<String>, tunnel_id: u32, assigned_port: Option<u16>) -> Self {
        RegisterAck {
            public_url: public_url.into(),
            tunnel_id,
            assigned_port,
        }
    }

    pub fn to_tlvs(&self) -> Vec<Tlv> {
        let mut tlvs = vec![
            Tlv::new(register_ack_tags::PUBLIC_URL, self.public_url.as_bytes()).unwrap(),
            Tlv::new_u32(register_ack_tags::TUNNEL_ID, self.tunnel_id).unwrap(),
        ];
        if let Some(port) = self.assigned_port {
            tlvs.push(Tlv::new_u16(register_ack_tags::ASSIGNED_PORT, port).unwrap());
        }
        tlvs
    }

    pub fn from_tlvs(tlvs: &[Tlv]) -> Result<Self> {
        let public_url = find_tlv_by_tag(tlvs, register_ack_tags::PUBLIC_URL)?
            .ok_or(ProtoError::MissingRequiredTlv(
                register_ack_tags::PUBLIC_URL,
            ))?
            .as_str()?
            .to_string();
        let tunnel_id = find_tlv_by_tag(tlvs, register_ack_tags::TUNNEL_ID)?
            .ok_or(ProtoError::MissingRequiredTlv(register_ack_tags::TUNNEL_ID))?
            .as_u32()?;
        let assigned_port = find_tlv_by_tag(tlvs, register_ack_tags::ASSIGNED_PORT)?
            .map(|t| t.as_u16())
            .transpose()?;

        Ok(RegisterAck {
            public_url,
            tunnel_id,
            assigned_port,
        })
    }
}

/// OPEN payload (server -> client, for inbound visitor connections)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenPayload {
    pub peer_addr: String,
    pub sni_or_host: String,
    pub tunnel_id: u32,
    pub proxy_protocol: Option<Bytes>,
    pub priority: Option<u8>,
}

impl OpenPayload {
    pub fn new(
        peer_addr: impl Into<String>,
        sni_or_host: impl Into<String>,
        tunnel_id: u32,
    ) -> Self {
        OpenPayload {
            peer_addr: peer_addr.into(),
            sni_or_host: sni_or_host.into(),
            tunnel_id,
            proxy_protocol: None,
            priority: None,
        }
    }

    pub fn with_proxy_protocol(mut self, header: Bytes) -> Self {
        self.proxy_protocol = Some(header);
        self
    }

    pub fn with_priority(mut self, priority: u8) -> Self {
        self.priority = Some(priority);
        self
    }

    pub fn to_tlvs(&self) -> Vec<Tlv> {
        let mut tlvs = vec![
            Tlv::new(open_tags::PEER_ADDR, self.peer_addr.as_bytes()).unwrap(),
            Tlv::new(open_tags::SNI_OR_HOST, self.sni_or_host.as_bytes()).unwrap(),
            Tlv::new_u32(open_tags::TUNNEL_ID, self.tunnel_id).unwrap(),
        ];
        if let Some(ref pp) = self.proxy_protocol {
            tlvs.push(Tlv::new(open_tags::PROXY_PROTOCOL, pp).unwrap());
        }
        if let Some(p) = self.priority {
            tlvs.push(Tlv::new_u8(open_tags::PRIORITY, p).unwrap());
        }
        tlvs
    }

    pub fn from_tlvs(tlvs: &[Tlv], priority_flag: bool) -> Result<Self> {
        let peer_addr = find_tlv_by_tag(tlvs, open_tags::PEER_ADDR)?
            .ok_or(ProtoError::MissingRequiredTlv(open_tags::PEER_ADDR))?
            .as_str()?
            .to_string();
        let sni_or_host = find_tlv_by_tag(tlvs, open_tags::SNI_OR_HOST)?
            .ok_or(ProtoError::MissingRequiredTlv(open_tags::SNI_OR_HOST))?
            .as_str()?
            .to_string();
        let tunnel_id = find_tlv_by_tag(tlvs, open_tags::TUNNEL_ID)?
            .ok_or(ProtoError::MissingRequiredTlv(open_tags::TUNNEL_ID))?
            .as_u32()?;

        let proxy_protocol =
            find_tlv_by_tag(tlvs, open_tags::PROXY_PROTOCOL)?.map(|t| t.value.clone());
        let priority = if priority_flag {
            find_tlv_by_tag(tlvs, open_tags::PRIORITY)?
                .map(|t| t.as_u8())
                .transpose()?
        } else {
            None
        };

        Ok(OpenPayload {
            peer_addr,
            sni_or_host,
            tunnel_id,
            proxy_protocol,
            priority,
        })
    }
}

/// Helper to find a TLV by tag in a slice
fn find_tlv_by_tag(tlvs: &[Tlv], tag: u8) -> Result<Option<&Tlv>> {
    Ok(tlvs.iter().find(|t| t.tag == tag))
}

/// Session limits configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionLimits {
    pub max_streams: u32,
    pub max_tunnels: u32,
    pub max_frame_payload: u32,
    pub initial_window: u32,
    pub connection_window: u32,
    pub handshake_timeout_secs: u64,
    pub idle_timeout_secs: u64,
    pub max_header_size: usize,
}

impl Default for SessionLimits {
    fn default() -> Self {
        SessionLimits {
            max_streams: 256,
            max_tunnels: 5,
            max_frame_payload: 16 * 1024,
            initial_window: 256 * 1024,
            connection_window: 1024 * 1024, // 1 MiB
            handshake_timeout_secs: 5,
            idle_timeout_secs: 5 * 60,
            max_header_size: 16 * 1024,
        }
    }
}

/// Token-based authentication limits (per token)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenLimits {
    pub token_id: String,
    pub max_tunnels: u32,
    pub max_bandwidth_bps: Option<u64>,
    pub allowed_subdomain_prefix: Option<String>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl Default for TokenLimits {
    fn default() -> Self {
        TokenLimits {
            token_id: String::new(),
            max_tunnels: 5,
            max_bandwidth_bps: None,
            allowed_subdomain_prefix: None,
            expires_at: None,
        }
    }
}

/// Resumption state
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumeState {
    pub session_id: u64,
    pub resume_secret: [u8; 32],
    pub tunnels: Vec<ResumeTunnel>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumeTunnel {
    pub tunnel_id: u32,
    pub mode: TunnelMode,
    pub subdomain: Option<String>,
    pub remote_port: Option<u16>,
}

/// Auth token for challenge-response
pub fn compute_auth_hmac(token: &[u8], nonce: &[u8], client_id: &str) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(token).expect("HMAC key length");
    mac.update(nonce);
    mac.update(client_id.as_bytes());
    let result = mac.finalize().into_bytes();
    let mut hmac = [0u8; 32];
    hmac.copy_from_slice(&result);
    hmac
}

/// Verify auth HMAC in constant time
pub fn verify_auth_hmac(token: &[u8], nonce: &[u8], client_id: &str, provided: &[u8; 32]) -> bool {
    let expected = compute_auth_hmac(token, nonce, client_id);
    subtle::ConstantTimeEq::ct_eq(&expected[..], provided).into()
}

/// Generate a secure random nonce
pub fn generate_nonce() -> [u8; 32] {
    use rand::RngCore;
    let mut nonce = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

/// Generate a secure random resume secret
pub fn generate_resume_secret() -> [u8; 32] {
    generate_nonce()
}

/// Generate a session ID
pub fn generate_session_id() -> u64 {
    use rand::Rng;
    rand::thread_rng().gen()
}

/// Generate a tunnel ID (odd for client, even for server)
pub fn generate_tunnel_id(client_initiated: bool) -> u32 {
    use rand::Rng;
    let base = rand::thread_rng().gen_range(1..=u32::MAX / 2) * 2;
    if client_initiated {
        base + 1
    } else {
        base
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hello_roundtrip() {
        let hello = Hello::new("test-client");
        let tlvs = hello.to_tlvs();
        let decoded = Hello::from_tlvs(&tlvs).unwrap();
        assert_eq!(hello.client_id, decoded.client_id);
        assert_eq!(hello.max_frame, decoded.max_frame);
        assert_eq!(hello.initial_window, decoded.initial_window);
        assert_eq!(hello.capabilities, decoded.capabilities);
    }

    #[test]
    fn test_hello_ack_roundtrip() {
        let nonce = generate_nonce();
        let ack = HelloAck::new(nonce, 16384, capabilities::CAP_RESUME);
        let tlvs = ack.to_tlvs();
        let decoded = HelloAck::from_tlvs(&tlvs).unwrap();
        assert_eq!(ack.nonce, decoded.nonce);
        assert_eq!(ack.max_frame, decoded.max_frame);
        assert_eq!(ack.capabilities, decoded.capabilities);
    }

    #[test]
    fn test_auth_hmac() {
        let token = b"secret-token";
        let nonce = generate_nonce();
        let client_id = "test-client";
        let hmac = compute_auth_hmac(token, &nonce, client_id);
        assert!(verify_auth_hmac(token, &nonce, client_id, &hmac));

        // Wrong token should fail
        assert!(!verify_auth_hmac(b"wrong", &nonce, client_id, &hmac));
        // Wrong nonce should fail
        assert!(!verify_auth_hmac(
            token,
            &generate_nonce(),
            client_id,
            &hmac
        ));
    }

    #[test]
    fn test_register_http_roundtrip() {
        let reg = Register::new_http(1, Some("myapp".into()));
        let tlvs = reg.to_tlvs();
        let decoded = Register::from_tlvs(&tlvs).unwrap();
        assert_eq!(reg.mode, decoded.mode);
        assert_eq!(reg.tunnel_id, decoded.tunnel_id);
        assert_eq!(reg.subdomain, decoded.subdomain);
    }

    #[test]
    fn test_register_tcp_roundtrip() {
        let reg = Register::new_tcp(2, Some(20431));
        let tlvs = reg.to_tlvs();
        let decoded = Register::from_tlvs(&tlvs).unwrap();
        assert_eq!(reg.mode, decoded.mode);
        assert_eq!(reg.tunnel_id, decoded.tunnel_id);
        assert_eq!(reg.remote_port, decoded.remote_port);
    }

    #[test]
    fn test_register_ack_roundtrip() {
        let ack = RegisterAck::new("https://myapp.example.com", 1, Some(20431));
        let tlvs = ack.to_tlvs();
        let decoded = RegisterAck::from_tlvs(&tlvs).unwrap();
        assert_eq!(ack.public_url, decoded.public_url);
        assert_eq!(ack.tunnel_id, decoded.tunnel_id);
        assert_eq!(ack.assigned_port, decoded.assigned_port);
    }

    #[test]
    fn test_open_payload_roundtrip() {
        let open = OpenPayload::new("192.168.1.1:12345", "myapp.example.com", 2).with_priority(4);
        let tlvs = open.to_tlvs();
        let decoded = OpenPayload::from_tlvs(&tlvs, true).unwrap();
        assert_eq!(open.peer_addr, decoded.peer_addr);
        assert_eq!(open.sni_or_host, decoded.sni_or_host);
        assert_eq!(open.tunnel_id, decoded.tunnel_id);
        assert_eq!(open.priority, decoded.priority);
    }

    #[test]
    fn test_ready_roundtrip() {
        let secret = generate_resume_secret();
        let ready = Ready::new(42, secret, 256, 5, Some(1024 * 1024));
        let tlvs = ready.to_tlvs();
        let decoded = Ready::from_tlvs(&tlvs).unwrap();
        assert_eq!(ready.session_id, decoded.session_id);
        assert_eq!(ready.resume_secret, decoded.resume_secret);
        assert_eq!(ready.max_streams, decoded.max_streams);
        assert_eq!(ready.max_tunnels, decoded.max_tunnels);
        assert_eq!(ready.bandwidth_limit, decoded.bandwidth_limit);
    }

    #[test]
    fn test_auth_roundtrip_and_errors() {
        let auth = Auth::new([0xAAu8; 32]);
        let tlvs = auth.to_tlvs();
        let decoded = Auth::from_tlvs(&tlvs).unwrap();
        assert_eq!(auth.hmac, decoded.hmac);

        // Auth with short HMAC
        let bad_tlv = vec![Tlv::new(auth_tags::HMAC, &[1, 2, 3]).unwrap()];
        assert!(Auth::from_tlvs(&bad_tlv).is_err());
    }

    #[test]
    fn test_hello_ack_invalid_nonce() {
        let bad_tlv = vec![
            Tlv::new_u8(hello_ack_tags::VERSION, 1).unwrap(),
            Tlv::new(hello_ack_tags::NONCE, &[1u8; 16]).unwrap(), // only 16 bytes
            Tlv::new_u32(hello_ack_tags::MAX_FRAME, 16384).unwrap(),
            Tlv::new_u64(hello_ack_tags::CAPABILITIES, 0).unwrap(),
        ];
        assert!(HelloAck::from_tlvs(&bad_tlv).is_err());
    }

    #[test]
    fn test_open_payload_with_proxy_protocol_and_no_priority_flag() {
        let pp = bytes::Bytes::from_static(b"PROXY TCP4 1.1.1.1 2.2.2.2 123 456\r\n");
        let open = OpenPayload::new("1.1.1.1:123", "sub.domain.com", 1)
            .with_proxy_protocol(pp.clone())
            .with_priority(5);
        let tlvs = open.to_tlvs();

        // Decode with priority_flag = true
        let decoded = OpenPayload::from_tlvs(&tlvs, true).unwrap();
        assert_eq!(decoded.proxy_protocol, Some(pp));
        assert_eq!(decoded.priority, Some(5));

        // Decode with priority_flag = false -> priority should be None
        let decoded_no_prio = OpenPayload::from_tlvs(&tlvs, false).unwrap();
        assert_eq!(decoded_no_prio.priority, None);
    }

    #[test]
    fn test_limits_resume_and_id_generators() {
        let sess_limits = SessionLimits::default();
        assert_eq!(sess_limits.max_streams, 256);

        let tok_limits = TokenLimits::default();
        assert_eq!(tok_limits.max_tunnels, 5);

        let res_tun = ResumeTunnel {
            tunnel_id: 1,
            mode: TunnelMode::Http,
            subdomain: Some("abc".into()),
            remote_port: None,
        };
        let res_state = ResumeState {
            session_id: 12345,
            resume_secret: [0xBB; 32],
            tunnels: vec![res_tun],
            expires_at: chrono::Utc::now(),
        };
        assert_eq!(res_state.session_id, 12345);

        let sid = generate_session_id();
        assert_ne!(sid, 0);

        let client_tid = generate_tunnel_id(true);
        assert_eq!(client_tid % 2, 1); // client is odd

        let server_tid = generate_tunnel_id(false);
        assert_eq!(server_tid % 2, 0); // server is even
    }

    #[test]
    fn test_missing_required_tlvs() {
        assert!(Hello::from_tlvs(&[]).is_err());
        assert!(HelloAck::from_tlvs(&[]).is_err());
        assert!(Auth::from_tlvs(&[]).is_err());
        assert!(Ready::from_tlvs(&[]).is_err());
        assert!(Register::from_tlvs(&[]).is_err());
        assert!(RegisterAck::from_tlvs(&[]).is_err());
        assert!(OpenPayload::from_tlvs(&[], false).is_err());
    }
}
