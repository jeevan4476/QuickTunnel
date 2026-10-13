//! Frame types, header codec, and frame structures

use crate::tlv::{Tlv, TlvEncoder};
use crate::{ProtoError, Result, CONTROL_STREAM_ID, DEFAULT_MAX_PAYLOAD, HEADER_LEN};
use bytes::{BufMut, Bytes, BytesMut};

/// QTP frame types
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum FrameType {
    Data = 0x00,
    Open = 0x01,
    WindowUpdate = 0x02,
    Fin = 0x03,
    Rst = 0x04,
    Ping = 0x05,
    Pong = 0x06,
    GoAway = 0x07,
    Hello = 0x08,
    HelloAck = 0x09,
    Auth = 0x0A,
    Ready = 0x0B,
    Register = 0x0C,
    RegisterAck = 0x0D,
}

impl TryFrom<u8> for FrameType {
    type Error = ProtoError;

    fn try_from(v: u8) -> Result<Self> {
        match v {
            0x00 => Ok(FrameType::Data),
            0x01 => Ok(FrameType::Open),
            0x02 => Ok(FrameType::WindowUpdate),
            0x03 => Ok(FrameType::Fin),
            0x04 => Ok(FrameType::Rst),
            0x05 => Ok(FrameType::Ping),
            0x06 => Ok(FrameType::Pong),
            0x07 => Ok(FrameType::GoAway),
            0x08 => Ok(FrameType::Hello),
            0x09 => Ok(FrameType::HelloAck),
            0x0A => Ok(FrameType::Auth),
            0x0B => Ok(FrameType::Ready),
            0x0C => Ok(FrameType::Register),
            0x0D => Ok(FrameType::RegisterAck),
            _ => Err(ProtoError::UnknownType(v)),
        }
    }
}

/// Frame flags
pub mod flags {
    pub const ACK: u8 = 0x01; // PING/PONG reply marker
    pub const FIN: u8 = 0x02; // DATA: last data on stream
    pub const PRIO: u8 = 0x04; // OPEN: priority hint present
}

/// Stream state (for state machine validation)
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum StreamState {
    Idle,
    Open,
    HalfClosedLocal,
    HalfClosedRemote,
    Closed,
}

/// Frame header (12 bytes fixed)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub ty: FrameType,
    pub flags: u8,
    pub stream_id: u32,
    pub len: u32,
}

impl Header {
    /// Encode header into a 12-byte buffer
    pub fn encode(&self, out: &mut [u8; HEADER_LEN]) {
        out[0] = self.ty as u8;
        out[1] = self.flags;
        out[2..4].copy_from_slice(&0u16.to_be_bytes()); // reserved
        out[4..8].copy_from_slice(&self.stream_id.to_be_bytes());
        out[8..12].copy_from_slice(&self.len.to_be_bytes());
    }

    /// Decode header from 12 bytes
    pub fn decode(buf: &[u8; HEADER_LEN], max_payload: u32) -> Result<Self> {
        let ty = FrameType::try_from(buf[0])?;
        let flags = buf[1];

        // Reserved bits: ignore on receive (forward compatibility)
        // let reserved = u16::from_be_bytes([buf[2], buf[3]]);

        let stream_id = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let len = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);

        if len > max_payload {
            return Err(ProtoError::FrameTooLarge(len, max_payload));
        }

        Ok(Header {
            ty,
            flags,
            stream_id,
            len,
        })
    }

    /// Check if this is a control frame (stream_id == 0)
    pub fn is_control(&self) -> bool {
        self.stream_id == CONTROL_STREAM_ID
    }

    /// Check if FIN flag is set
    pub fn has_fin(&self) -> bool {
        self.flags & flags::FIN != 0
    }

    /// Check if PRIO flag is set
    pub fn has_prio(&self) -> bool {
        self.flags & flags::PRIO != 0
    }
}

/// A complete frame with header and payload
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub header: Header,
    pub payload: Bytes,
}

impl Frame {
    /// Create a new frame
    pub fn new(ty: FrameType, stream_id: u32, payload: Bytes) -> Result<Self> {
        let len = payload.len() as u32;
        if len > DEFAULT_MAX_PAYLOAD {
            return Err(ProtoError::FrameTooLarge(len, DEFAULT_MAX_PAYLOAD));
        }
        Ok(Frame {
            header: Header {
                ty,
                flags: 0,
                stream_id,
                len,
            },
            payload,
        })
    }

    /// Create a DATA frame
    pub fn data(stream_id: u32, payload: Bytes, fin: bool) -> Result<Self> {
        if stream_id == 0 {
            return Err(ProtoError::ProtocolError(
                "DATA frame must have stream_id > 0".into(),
            ));
        }
        let mut flags = 0;
        if fin {
            flags |= flags::FIN;
        }
        let len = payload.len() as u32;
        if len > DEFAULT_MAX_PAYLOAD {
            return Err(ProtoError::FrameTooLarge(len, DEFAULT_MAX_PAYLOAD));
        }
        Ok(Frame {
            header: Header {
                ty: FrameType::Data,
                flags,
                stream_id,
                len,
            },
            payload,
        })
    }

    /// Create an OPEN frame with TLV payload
    pub fn open(stream_id: u32, tlvs: &[Tlv], prio: Option<u8>) -> Result<Self> {
        if stream_id == 0 {
            return Err(ProtoError::ProtocolError(
                "OPEN frame must have stream_id > 0".into(),
            ));
        }
        let mut encoder = TlvEncoder::new();
        for tlv in tlvs {
            encoder.push(tlv.clone())?;
        }
        let payload = encoder.finish();
        let mut flags = 0;
        if prio.is_some() {
            flags |= flags::PRIO;
        }
        // Priority is encoded as TLV tag 0x05 inside the TLVs, not prepended
        let len = payload.len() as u32;
        if len > DEFAULT_MAX_PAYLOAD {
            return Err(ProtoError::FrameTooLarge(len, DEFAULT_MAX_PAYLOAD));
        }
        Ok(Frame {
            header: Header {
                ty: FrameType::Open,
                flags,
                stream_id,
                len,
            },
            payload,
        })
    }

    /// Create a WINDOW_UPDATE frame
    pub fn window_update(stream_id: u32, delta: u32) -> Result<Self> {
        let mut payload = BytesMut::with_capacity(4);
        payload.put_u32(delta);
        Ok(Frame {
            header: Header {
                ty: FrameType::WindowUpdate,
                flags: 0,
                stream_id,
                len: 4,
            },
            payload: payload.freeze(),
        })
    }

    /// Create a FIN frame
    pub fn fin(stream_id: u32) -> Result<Self> {
        if stream_id == 0 {
            return Err(ProtoError::ProtocolError(
                "FIN frame must have stream_id > 0".into(),
            ));
        }
        Ok(Frame {
            header: Header {
                ty: FrameType::Fin,
                flags: 0,
                stream_id,
                len: 0,
            },
            payload: Bytes::new(),
        })
    }

    /// Create an RST frame
    pub fn rst(stream_id: u32, error_code: u32) -> Result<Self> {
        if stream_id == 0 {
            return Err(ProtoError::ProtocolError(
                "RST frame must have stream_id > 0".into(),
            ));
        }
        let mut payload = BytesMut::with_capacity(4);
        payload.put_u32(error_code);
        Ok(Frame {
            header: Header {
                ty: FrameType::Rst,
                flags: 0,
                stream_id,
                len: 4,
            },
            payload: payload.freeze(),
        })
    }

    /// Create a PING frame
    pub fn ping(nonce: u64) -> Result<Self> {
        let mut payload = BytesMut::with_capacity(8);
        payload.put_u64(nonce);
        Ok(Frame {
            header: Header {
                ty: FrameType::Ping,
                flags: 0,
                stream_id: CONTROL_STREAM_ID,
                len: 8,
            },
            payload: payload.freeze(),
        })
    }

    /// Create a PONG frame
    pub fn pong(nonce: u64) -> Result<Self> {
        let mut payload = BytesMut::with_capacity(8);
        payload.put_u64(nonce);
        Ok(Frame {
            header: Header {
                ty: FrameType::Pong,
                flags: flags::ACK,
                stream_id: CONTROL_STREAM_ID,
                len: 8,
            },
            payload: payload.freeze(),
        })
    }

    /// Create a GOAWAY frame
    pub fn goaway(last_stream_id: u32, error_code: u32) -> Result<Self> {
        let mut payload = BytesMut::with_capacity(8);
        payload.put_u32(last_stream_id);
        payload.put_u32(error_code);
        Ok(Frame {
            header: Header {
                ty: FrameType::GoAway,
                flags: 0,
                stream_id: CONTROL_STREAM_ID,
                len: 8,
            },
            payload: payload.freeze(),
        })
    }

    /// Create a HELLO frame
    pub fn hello(client_id: &str, max_frame: u32, window: u32, caps: u64) -> Result<Self> {
        let mut encoder = TlvEncoder::new();
        encoder.push(Tlv::new_u8(
            crate::tlv::hello_tags::VERSION,
            crate::PROTOCOL_VERSION,
        )?)?; // version
        encoder.push(Tlv::new(
            crate::tlv::hello_tags::CLIENT_ID,
            client_id.as_bytes(),
        )?)?; // client_id
        encoder.push(Tlv::new_u32(crate::tlv::hello_tags::MAX_FRAME, max_frame)?)?; // max_frame
        encoder.push(Tlv::new_u32(
            crate::tlv::hello_tags::INITIAL_WINDOW,
            window,
        )?)?; // initial_window
        encoder.push(Tlv::new_u64(crate::tlv::hello_tags::CAPABILITIES, caps)?)?; // capabilities
        let payload = encoder.finish();
        Ok(Frame {
            header: Header {
                ty: FrameType::Hello,
                flags: 0,
                stream_id: CONTROL_STREAM_ID,
                len: payload.len() as u32,
            },
            payload,
        })
    }

    /// Create a HELLO_ACK frame
    pub fn hello_ack(nonce: &[u8; 32], max_frame: u32, caps: u64) -> Result<Self> {
        let mut encoder = TlvEncoder::new();
        encoder.push(Tlv::new_u8(
            crate::tlv::hello_ack_tags::VERSION,
            crate::PROTOCOL_VERSION,
        )?)?; // version
        encoder.push(Tlv::new(crate::tlv::hello_ack_tags::NONCE, nonce)?)?; // nonce
        encoder.push(Tlv::new_u32(
            crate::tlv::hello_ack_tags::MAX_FRAME,
            max_frame,
        )?)?; // max_frame
        encoder.push(Tlv::new_u64(
            crate::tlv::hello_ack_tags::CAPABILITIES,
            caps,
        )?)?; // capabilities
        let payload = encoder.finish();
        Ok(Frame {
            header: Header {
                ty: FrameType::HelloAck,
                flags: 0,
                stream_id: CONTROL_STREAM_ID,
                len: payload.len() as u32,
            },
            payload,
        })
    }

    /// Create an AUTH frame
    pub fn auth(mac: &[u8; 32]) -> Result<Self> {
        let mut encoder = TlvEncoder::new();
        encoder.push(Tlv::new(0x01, mac)?)?; // hmac
        let payload = encoder.finish();
        Ok(Frame {
            header: Header {
                ty: FrameType::Auth,
                flags: 0,
                stream_id: CONTROL_STREAM_ID,
                len: payload.len() as u32,
            },
            payload,
        })
    }

    /// Create a READY frame
    pub fn ready(
        session_id: u64,
        resume_secret: &[u8; 32],
        max_streams: u32,
        max_tunnels: u32,
        bandwidth_limit: Option<u64>,
    ) -> Result<Self> {
        let mut encoder = TlvEncoder::new();
        encoder.push(Tlv::new_u64(0x01, session_id)?)?; // session_id
        encoder.push(Tlv::new(0x02, resume_secret)?)?; // resume_secret
        encoder.push(Tlv::new_u32(0x03, max_streams)?)?; // max_streams
        encoder.push(Tlv::new_u32(0x04, max_tunnels)?)?; // max_tunnels
        if let Some(bw) = bandwidth_limit {
            encoder.push(Tlv::new_u64(0x05, bw)?)?; // bandwidth_limit
        }
        let payload = encoder.finish();
        Ok(Frame {
            header: Header {
                ty: FrameType::Ready,
                flags: 0,
                stream_id: CONTROL_STREAM_ID,
                len: payload.len() as u32,
            },
            payload,
        })
    }

    /// Create a REGISTER frame
    pub fn register(
        mode: TunnelMode,
        subdomain: Option<&str>,
        remote_port: Option<u16>,
        tunnel_id: u32,
    ) -> Result<Self> {
        if tunnel_id.is_multiple_of(2) {
            return Err(ProtoError::ProtocolError(
                "REGISTER must have odd tunnel_id (stream_id)".into(),
            ));
        }
        let mut encoder = TlvEncoder::new();
        encoder.push(Tlv::new_u8(0x01, mode as u8)?)?; // mode
        encoder.push(Tlv::new_u32(0x02, tunnel_id)?)?; // tunnel_id
        if let Some(sub) = subdomain {
            encoder.push(Tlv::new(0x03, sub.as_bytes())?)?; // subdomain
        }
        if let Some(port) = remote_port {
            encoder.push(Tlv::new_u16(0x04, port)?)?; // remote_port
        }
        let payload = encoder.finish();
        Ok(Frame {
            header: Header {
                ty: FrameType::Register,
                flags: 0,
                stream_id: tunnel_id, // odd for client-initiated
                len: payload.len() as u32,
            },
            payload,
        })
    }

    /// Create a REGISTER_ACK frame
    pub fn register_ack(tunnel_id: u32, url: &str, assigned_port: Option<u16>) -> Result<Self> {
        let mut encoder = TlvEncoder::new();
        encoder.push(Tlv::new(0x01, url.as_bytes())?)?; // public_url
        encoder.push(Tlv::new_u32(0x02, tunnel_id)?)?; // tunnel_id
        if let Some(port) = assigned_port {
            encoder.push(Tlv::new_u16(0x03, port)?)?; // assigned_port
        }
        let payload = encoder.finish();
        Ok(Frame {
            header: Header {
                ty: FrameType::RegisterAck,
                flags: 0,
                stream_id: tunnel_id,
                len: payload.len() as u32,
            },
            payload,
        })
    }

    /// Encode frame to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        let mut header_bytes = [0u8; HEADER_LEN];
        self.header.encode(&mut header_bytes);
        buf.extend_from_slice(&header_bytes);
        buf.extend_from_slice(&self.payload);
    }

    /// Get the frame type
    pub fn frame_type(&self) -> FrameType {
        self.header.ty
    }

    /// Get the stream ID
    pub fn stream_id(&self) -> u32 {
        self.header.stream_id
    }

    /// Get the payload length
    pub fn len(&self) -> u32 {
        self.header.len
    }

    /// Check if frame payload is empty
    pub fn is_empty(&self) -> bool {
        self.header.len == 0
    }

    /// Check if frame has FIN flag
    pub fn is_fin(&self) -> bool {
        self.header.has_fin()
    }

    /// Check if frame has PRIO flag
    pub fn has_prio(&self) -> bool {
        self.header.has_prio()
    }

    /// Parse WINDOW_UPDATE payload - returns delta
    pub fn parse_window_update(&self) -> Result<u32> {
        if self.header.ty != FrameType::WindowUpdate {
            return Err(ProtoError::ProtocolError(
                "not a WINDOW_UPDATE frame".into(),
            ));
        }
        if self.payload.len() != 4 {
            return Err(ProtoError::ProtocolError(
                "WINDOW_UPDATE payload must be 4 bytes".into(),
            ));
        }
        Ok(u32::from_be_bytes([
            self.payload[0],
            self.payload[1],
            self.payload[2],
            self.payload[3],
        ]))
    }

    /// Parse PING payload - returns nonce
    pub fn parse_ping(&self) -> Result<u64> {
        if self.header.ty != FrameType::Ping {
            return Err(ProtoError::ProtocolError("not a PING frame".into()));
        }
        if self.payload.len() != 8 {
            return Err(ProtoError::ProtocolError(
                "PING payload must be 8 bytes".into(),
            ));
        }
        Ok(u64::from_be_bytes([
            self.payload[0],
            self.payload[1],
            self.payload[2],
            self.payload[3],
            self.payload[4],
            self.payload[5],
            self.payload[6],
            self.payload[7],
        ]))
    }

    /// Parse PONG payload - returns nonce
    pub fn parse_pong(&self) -> Result<u64> {
        if self.header.ty != FrameType::Pong {
            return Err(ProtoError::ProtocolError("not a PONG frame".into()));
        }
        if self.payload.len() != 8 {
            return Err(ProtoError::ProtocolError(
                "PONG payload must be 8 bytes".into(),
            ));
        }
        Ok(u64::from_be_bytes([
            self.payload[0],
            self.payload[1],
            self.payload[2],
            self.payload[3],
            self.payload[4],
            self.payload[5],
            self.payload[6],
            self.payload[7],
        ]))
    }

    /// Parse RST payload - returns error code
    pub fn parse_rst(&self) -> Result<u32> {
        if self.header.ty != FrameType::Rst {
            return Err(ProtoError::ProtocolError("not an RST frame".into()));
        }
        if self.payload.len() != 4 {
            return Err(ProtoError::ProtocolError(
                "RST payload must be 4 bytes".into(),
            ));
        }
        Ok(u32::from_be_bytes([
            self.payload[0],
            self.payload[1],
            self.payload[2],
            self.payload[3],
        ]))
    }

    /// Parse GOAWAY payload - returns (last_stream_id, error_code)
    pub fn parse_goaway(&self) -> Result<(u32, u32)> {
        if self.header.ty != FrameType::GoAway {
            return Err(ProtoError::ProtocolError("not a GOAWAY frame".into()));
        }
        if self.payload.len() != 8 {
            return Err(ProtoError::ProtocolError(
                "GOAWAY payload must be 8 bytes".into(),
            ));
        }
        let last_stream_id = u32::from_be_bytes([
            self.payload[0],
            self.payload[1],
            self.payload[2],
            self.payload[3],
        ]);
        let error_code = u32::from_be_bytes([
            self.payload[4],
            self.payload[5],
            self.payload[6],
            self.payload[7],
        ]);
        Ok((last_stream_id, error_code))
    }

    /// Parse FIN frame - validates zero payload
    pub fn parse_fin(&self) -> Result<()> {
        if self.header.ty != FrameType::Fin {
            return Err(ProtoError::ProtocolError("not a FIN frame".into()));
        }
        if !self.payload.is_empty() {
            return Err(ProtoError::ProtocolError(
                "FIN payload must be empty".into(),
            ));
        }
        Ok(())
    }

    /// Get DATA payload (with optional FIN flag check)
    pub fn data_payload(&self) -> Result<Bytes> {
        if self.header.ty != FrameType::Data {
            return Err(ProtoError::ProtocolError("not a DATA frame".into()));
        }
        Ok(self.payload.clone())
    }

    /// Validate stream ID invariants per protocol spec
    pub fn validate_stream_id(&self) -> Result<()> {
        let stream_id = self.header.stream_id;
        match self.header.ty {
            FrameType::Data | FrameType::Fin | FrameType::Rst => {
                if stream_id == 0 {
                    return Err(ProtoError::ProtocolError(
                        "application frame must have stream_id > 0".into(),
                    ));
                }
            }
            FrameType::Open => {
                if stream_id == 0 {
                    return Err(ProtoError::ProtocolError(
                        "OPEN must have stream_id > 0".into(),
                    ));
                }
            }
            FrameType::Ping
            | FrameType::Pong
            | FrameType::GoAway
            | FrameType::Hello
            | FrameType::HelloAck
            | FrameType::Auth
            | FrameType::Ready => {
                if stream_id != CONTROL_STREAM_ID {
                    return Err(ProtoError::ProtocolError(
                        "control frame must have stream_id == 0".into(),
                    ));
                }
            }
            FrameType::Register | FrameType::RegisterAck => {
                if stream_id.is_multiple_of(2) {
                    return Err(ProtoError::ProtocolError(
                        "REGISTER/REGISTER_ACK must have odd stream_id".into(),
                    ));
                }
            }
            FrameType::WindowUpdate => {
                // stream_id >= 0 (0 is connection window, >0 is stream window) - always valid
            }
        }
        Ok(())
    }

    /// Validate payload length for fixed-size frame types
    pub fn validate_payload_length(&self) -> Result<()> {
        match self.header.ty {
            FrameType::Fin => {
                if self.header.len != 0 {
                    return Err(ProtoError::ProtocolError(
                        "FIN payload length must be 0".into(),
                    ));
                }
            }
            FrameType::WindowUpdate => {
                if self.header.len != 4 {
                    return Err(ProtoError::ProtocolError(
                        "WINDOW_UPDATE payload length must be 4".into(),
                    ));
                }
            }
            FrameType::Rst => {
                if self.header.len != 4 {
                    return Err(ProtoError::ProtocolError(
                        "RST payload length must be 4".into(),
                    ));
                }
            }
            FrameType::Ping | FrameType::Pong => {
                if self.header.len != 8 {
                    return Err(ProtoError::ProtocolError(
                        "PING/PONG payload length must be 8".into(),
                    ));
                }
            }
            FrameType::GoAway if self.header.len != 8 => {
                return Err(ProtoError::ProtocolError(
                    "GOAWAY payload length must be 8".into(),
                ));
            }
            _ => {} // Variable length frames: Data, Open, Hello, HelloAck, Auth, Ready, Register, RegisterAck
        }
        Ok(())
    }
}

/// Tunnel mode
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum TunnelMode {
    Http = 0x01,
    Tcp = 0x02,
    TcpPassthrough = 0x03,
}

impl TryFrom<u8> for TunnelMode {
    type Error = ProtoError;

    fn try_from(v: u8) -> Result<Self> {
        match v {
            0x01 => Ok(TunnelMode::Http),
            0x02 => Ok(TunnelMode::Tcp),
            0x03 => Ok(TunnelMode::TcpPassthrough),
            _ => Err(ProtoError::ProtocolError(format!(
                "unknown tunnel mode: {}",
                v
            ))),
        }
    }
}

/// Maximum frame payload (16 KiB default)
pub const MAX_FRAME_PAYLOAD: u32 = DEFAULT_MAX_PAYLOAD;

/// Error codes for RST and GOAWAY frames
pub mod error_codes {
    pub const NO_ERROR: u32 = 0;
    pub const PROTOCOL_ERROR: u32 = 1;
    pub const FLOW_CONTROL_ERROR: u32 = 2;
    pub const STREAM_REFUSED: u32 = 3;
    pub const CONNECT_FAILED: u32 = 4;
    pub const CANCEL: u32 = 5;
    pub const INTERNAL_ERROR: u32 = 6;
    pub const AUTH_FAILED: u32 = 7;
    pub const RATE_LIMITED: u32 = 8;
    pub const TIMEOUT: u32 = 9;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{flags, Frame, FrameType, Header, DEFAULT_MAX_PAYLOAD};

    #[test]
    fn test_header_roundtrip() {
        let header = Header {
            ty: FrameType::Data,
            flags: flags::FIN,
            stream_id: 42,
            len: 100,
        };
        let mut buf = [0u8; HEADER_LEN];
        header.encode(&mut buf);
        let decoded = Header::decode(&buf, DEFAULT_MAX_PAYLOAD).unwrap();
        assert_eq!(decoded.ty, FrameType::Data);
        assert_eq!(decoded.flags, flags::FIN);
        assert_eq!(decoded.stream_id, 42);
        assert_eq!(decoded.len, 100);
    }

    #[test]
    fn test_header_max_payload_enforcement() {
        let header = Header {
            ty: FrameType::Data,
            flags: 0,
            stream_id: 1,
            len: DEFAULT_MAX_PAYLOAD + 1,
        };
        let mut buf = [0u8; HEADER_LEN];
        header.encode(&mut buf);
        let err = Header::decode(&buf, DEFAULT_MAX_PAYLOAD).unwrap_err();
        assert!(matches!(err, ProtoError::FrameTooLarge { .. }));
    }

    #[test]
    fn test_header_unknown_type_rejected() {
        let mut buf = [0u8; HEADER_LEN];
        buf[0] = 0x0E; // Unknown frame type
        buf[1] = 0;
        buf[4..8].copy_from_slice(&1u32.to_be_bytes());
        buf[8..12].copy_from_slice(&0u32.to_be_bytes());
        let err = Header::decode(&buf, DEFAULT_MAX_PAYLOAD).unwrap_err();
        assert!(matches!(err, ProtoError::UnknownType(0x0E)));
    }

    #[test]
    fn test_header_reserved_bits_ignored_on_receive() {
        // Reserved bits should be ignored on receive (forward compatibility)
        let mut buf = [0u8; HEADER_LEN];
        buf[0] = FrameType::Data as u8;
        buf[1] = 0;
        buf[2] = 0xFF; // Reserved bits non-zero
        buf[3] = 0xFF;
        buf[4..8].copy_from_slice(&1u32.to_be_bytes());
        buf[8..12].copy_from_slice(&10u32.to_be_bytes());
        let decoded = Header::decode(&buf, DEFAULT_MAX_PAYLOAD).unwrap();
        assert_eq!(decoded.ty, FrameType::Data);
        assert_eq!(decoded.stream_id, 1);
        assert_eq!(decoded.len, 10);
    }

    #[test]
    fn test_frame_data_constructor_validates_stream_id() {
        let err = Frame::data(0, Bytes::from_static(b"test"), false).unwrap_err();
        assert!(err.to_string().contains("stream_id > 0"));
    }

    #[test]
    fn test_frame_fin_constructor_validates_stream_id() {
        let err = Frame::fin(0).unwrap_err();
        assert!(err.to_string().contains("stream_id > 0"));
    }

    #[test]
    fn test_frame_rst_constructor_validates_stream_id() {
        let err = Frame::rst(0, 1).unwrap_err();
        assert!(err.to_string().contains("stream_id > 0"));
    }

    #[test]
    fn test_frame_open_constructor_validates_stream_id() {
        let err = Frame::open(0, &[], None).unwrap_err();
        assert!(err.to_string().contains("stream_id > 0"));
    }

    #[test]
    fn test_frame_register_constructor_validates_odd_stream_id() {
        let err = Frame::register(TunnelMode::Http, None, None, 2).unwrap_err(); // even
        assert!(err.to_string().contains("odd"));
    }

    #[test]
    fn test_frame_validate_stream_id_control_frames() {
        let frame = Frame::hello("client", 16384, 65535, 0).unwrap();
        assert!(frame.validate_stream_id().is_ok());

        // Mutate stream_id to non-zero
        let mut bad_frame = frame;
        bad_frame.header.stream_id = 1;
        assert!(bad_frame.validate_stream_id().is_err());
    }

    #[test]
    fn test_frame_validate_stream_id_application_frames() {
        let frame = Frame::data(1, Bytes::from_static(b"test"), false).unwrap();
        assert!(frame.validate_stream_id().is_ok());

        // Mutate stream_id to 0
        let mut bad_frame = frame;
        bad_frame.header.stream_id = 0;
        assert!(bad_frame.validate_stream_id().is_err());
    }

    #[test]
    fn test_frame_validate_stream_id_register_frames() {
        let frame = Frame::register(TunnelMode::Http, None, None, 1).unwrap(); // odd
        assert!(frame.validate_stream_id().is_ok());

        // Mutate stream_id to even
        let mut bad_frame = frame;
        bad_frame.header.stream_id = 2;
        assert!(bad_frame.validate_stream_id().is_err());
    }

    #[test]
    fn test_frame_validate_payload_length_fixed_frames() {
        // FIN: must be 0
        let mut frame = Frame::fin(1).unwrap();
        frame.header.len = 5;
        assert!(frame.validate_payload_length().is_err());

        // WINDOW_UPDATE: must be 4
        frame = Frame::window_update(1, 100).unwrap();
        frame.header.len = 8;
        assert!(frame.validate_payload_length().is_err());

        // RST: must be 4
        frame = Frame::rst(1, 1).unwrap();
        frame.header.len = 5;
        assert!(frame.validate_payload_length().is_err());

        // PING: must be 8
        frame = Frame::ping(12345).unwrap();
        frame.header.len = 4;
        assert!(frame.validate_payload_length().is_err());

        // PONG: must be 8
        frame = Frame::pong(12345).unwrap();
        frame.header.len = 4;
        assert!(frame.validate_payload_length().is_err());

        // GOAWAY: must be 8
        frame = Frame::goaway(10, 0).unwrap();
        frame.header.len = 4;
        assert!(frame.validate_payload_length().is_err());
    }

    #[test]
    fn test_frame_parse_window_update() {
        let frame = Frame::window_update(1, 1000).unwrap();
        assert_eq!(frame.parse_window_update().unwrap(), 1000);
    }

    #[test]
    fn test_frame_parse_ping() {
        let frame = Frame::ping(0x123456789ABCDEF0).unwrap();
        assert_eq!(frame.parse_ping().unwrap(), 0x123456789ABCDEF0);
    }

    #[test]
    fn test_frame_parse_pong() {
        let frame = Frame::pong(0x123456789ABCDEF0).unwrap();
        assert_eq!(frame.parse_pong().unwrap(), 0x123456789ABCDEF0);
    }

    #[test]
    fn test_frame_parse_rst() {
        let frame = Frame::rst(1, 5).unwrap();
        assert_eq!(frame.parse_rst().unwrap(), 5);
    }

    #[test]
    fn test_frame_parse_goaway() {
        let frame = Frame::goaway(42, 3).unwrap();
        let (last_stream, error) = frame.parse_goaway().unwrap();
        assert_eq!(last_stream, 42);
        assert_eq!(error, 3);
    }

    #[test]
    fn test_frame_parse_fin() {
        let frame = Frame::fin(1).unwrap();
        assert!(frame.parse_fin().is_ok());
    }

    #[test]
    fn test_frame_data_payload() {
        let frame = Frame::data(1, Bytes::from_static(b"hello"), false).unwrap();
        assert_eq!(&frame.data_payload().unwrap()[..], b"hello");
    }

    #[test]
    fn test_frame_wrong_type_decoder_rejected() {
        let frame = Frame::data(1, Bytes::from_static(b"test"), false).unwrap();
        assert!(frame.parse_window_update().is_err());
        assert!(frame.parse_ping().is_err());
        assert!(frame.parse_pong().is_err());
        assert!(frame.parse_rst().is_err());
        assert!(frame.parse_goaway().is_err());
        assert!(frame.parse_fin().is_err());
    }

    #[test]
    fn test_frame_type_try_from_all_variants() {
        let expected = [
            (0x00, FrameType::Data),
            (0x01, FrameType::Open),
            (0x02, FrameType::WindowUpdate),
            (0x03, FrameType::Fin),
            (0x04, FrameType::Rst),
            (0x05, FrameType::Ping),
            (0x06, FrameType::Pong),
            (0x07, FrameType::GoAway),
            (0x08, FrameType::Hello),
            (0x09, FrameType::HelloAck),
            (0x0A, FrameType::Auth),
            (0x0B, FrameType::Ready),
            (0x0C, FrameType::Register),
            (0x0D, FrameType::RegisterAck),
        ];
        for (code, ty) in expected {
            assert_eq!(FrameType::try_from(code).unwrap(), ty);
        }
        assert!(FrameType::try_from(0x0E).is_err());
        assert!(FrameType::try_from(0xFF).is_err());
    }

    #[test]
    fn test_header_helpers() {
        let h_ctrl = Header {
            ty: FrameType::Ping,
            flags: 0,
            stream_id: CONTROL_STREAM_ID,
            len: 8,
        };
        assert!(h_ctrl.is_control());
        assert!(!h_ctrl.has_fin());
        assert!(!h_ctrl.has_prio());

        let h_prio = Header {
            ty: FrameType::Open,
            flags: flags::PRIO | flags::FIN,
            stream_id: 2,
            len: 10,
        };
        assert!(!h_prio.is_control());
        assert!(h_prio.has_fin());
        assert!(h_prio.has_prio());
    }

    #[test]
    fn test_frame_new_and_encode() {
        let payload = Bytes::from_static(b"frame payload");
        let frame = Frame::new(FrameType::Data, 1, payload.clone()).unwrap();
        assert_eq!(frame.frame_type(), FrameType::Data);
        assert_eq!(frame.stream_id(), 1);
        assert_eq!(frame.len(), payload.len() as u32);
        assert!(!frame.is_empty());
        assert!(!frame.is_fin());
        assert!(!frame.has_prio());

        let mut buf = BytesMut::new();
        frame.encode(&mut buf);
        assert_eq!(buf.len(), HEADER_LEN + payload.len());

        // Oversized payload
        let large = vec![0u8; (DEFAULT_MAX_PAYLOAD + 1) as usize];
        assert!(Frame::new(FrameType::Data, 1, Bytes::from(large.clone())).is_err());
        assert!(Frame::data(1, Bytes::from(large.clone()), false).is_err());
    }

    #[test]
    fn test_frame_open_prio_and_oversized() {
        let tlv = crate::Tlv::new_u8(1, 42).unwrap();
        let frame = Frame::open(1, &[tlv], Some(7)).unwrap();
        assert!(frame.has_prio());
        assert_eq!(frame.frame_type(), FrameType::Open);
    }

    #[test]
    fn test_frame_all_constructors() {
        let f_ack = Frame::hello_ack(&[1u8; 32], 16384, 0).unwrap();
        assert_eq!(f_ack.frame_type(), FrameType::HelloAck);

        let f_auth = Frame::auth(&[2u8; 32]).unwrap();
        assert_eq!(f_auth.frame_type(), FrameType::Auth);

        let f_ready_bw = Frame::ready(123, &[3u8; 32], 100, 10, Some(1_000_000)).unwrap();
        assert_eq!(f_ready_bw.frame_type(), FrameType::Ready);

        let f_reg = Frame::register(TunnelMode::Http, Some("sub"), Some(8080), 3).unwrap();
        assert_eq!(f_reg.frame_type(), FrameType::Register);

        let f_reg_ack = Frame::register_ack(3, "https://url", Some(8080)).unwrap();
        assert_eq!(f_reg_ack.frame_type(), FrameType::RegisterAck);
    }

    #[test]
    fn test_tunnel_mode_try_from() {
        assert_eq!(TunnelMode::try_from(1).unwrap(), TunnelMode::Http);
        assert_eq!(TunnelMode::try_from(2).unwrap(), TunnelMode::Tcp);
        assert_eq!(TunnelMode::try_from(3).unwrap(), TunnelMode::TcpPassthrough);
        assert!(TunnelMode::try_from(0).is_err());
        assert!(TunnelMode::try_from(4).is_err());
    }

    #[test]
    fn test_frame_decoder_payload_length_errors() {
        // Bad window update length
        let mut f_wu = Frame::window_update(1, 10).unwrap();
        f_wu.payload = Bytes::from_static(b"12"); // 2 bytes instead of 4
        assert!(f_wu.parse_window_update().is_err());

        // Bad ping length
        let mut f_ping = Frame::ping(10).unwrap();
        f_ping.payload = Bytes::from_static(b"1234");
        assert!(f_ping.parse_ping().is_err());

        // Bad pong length
        let mut f_pong = Frame::pong(10).unwrap();
        f_pong.payload = Bytes::from_static(b"1234");
        assert!(f_pong.parse_pong().is_err());

        // Bad rst length
        let mut f_rst = Frame::rst(1, 10).unwrap();
        f_rst.payload = Bytes::from_static(b"12");
        assert!(f_rst.parse_rst().is_err());

        // Bad goaway length
        let mut f_go = Frame::goaway(1, 10).unwrap();
        f_go.payload = Bytes::from_static(b"1234");
        assert!(f_go.parse_goaway().is_err());

        // Bad fin length
        let mut f_fin = Frame::fin(1).unwrap();
        f_fin.payload = Bytes::from_static(b"extra");
        assert!(f_fin.parse_fin().is_err());

        // data_payload on non-data frame
        assert!(f_fin.data_payload().is_err());
    }

    #[test]
    fn test_stream_id_and_payload_length_validation_edge_cases() {
        // Open with stream 0 error
        let mut f_open = Frame::open(1, &[], None).unwrap();
        f_open.header.stream_id = 0;
        assert!(f_open.validate_stream_id().is_err());

        // WindowUpdate with stream 0 and stream 1 both ok
        let f_wu0 = Frame::window_update(0, 100).unwrap();
        assert!(f_wu0.validate_stream_id().is_ok());
        let f_wu1 = Frame::window_update(1, 100).unwrap();
        assert!(f_wu1.validate_stream_id().is_ok());

        // Variable length frame validate_payload_length is ok
        let f_data = Frame::data(1, Bytes::from_static(b"test"), false).unwrap();
        assert!(f_data.validate_payload_length().is_ok());
    }
}
