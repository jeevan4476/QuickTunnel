//! TLV (Type-Length-Value) encoding for structured payloads

use crate::{ProtoError, Result};
use bytes::{BufMut, Bytes, BytesMut};

/// Maximum TLV value length (64 KiB)
pub const MAX_TLV_VALUE_LEN: usize = 64 * 1024;

/// TLV tag
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct TlvTag(pub u8);

/// A single TLV entry
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tlv {
    pub tag: u8,
    pub value: Bytes,
}

impl Tlv {
    /// Create a new TLV with raw bytes
    pub fn new(tag: u8, value: &[u8]) -> Result<Self> {
        if value.len() > MAX_TLV_VALUE_LEN {
            return Err(ProtoError::TlvValueTooLong(value.len(), MAX_TLV_VALUE_LEN));
        }
        Ok(Tlv {
            tag,
            value: Bytes::copy_from_slice(value),
        })
    }

    /// Create a TLV with a u8 value
    pub fn new_u8(tag: u8, value: u8) -> Result<Self> {
        Self::new(tag, &[value])
    }

    /// Create a TLV with a u16 value (big-endian)
    pub fn new_u16(tag: u8, value: u16) -> Result<Self> {
        Self::new(tag, &value.to_be_bytes())
    }

    /// Create a TLV with a u32 value (big-endian)
    pub fn new_u32(tag: u8, value: u32) -> Result<Self> {
        Self::new(tag, &value.to_be_bytes())
    }

    /// Create a TLV with a u64 value (big-endian)
    pub fn new_u64(tag: u8, value: u64) -> Result<Self> {
        Self::new(tag, &value.to_be_bytes())
    }

    /// Get the value as a u8
    pub fn as_u8(&self) -> Result<u8> {
        if self.value.len() != 1 {
            return Err(ProtoError::TlvValueTooLong(self.value.len(), 1));
        }
        Ok(self.value[0])
    }

    /// Get the value as a u16
    pub fn as_u16(&self) -> Result<u16> {
        if self.value.len() != 2 {
            return Err(ProtoError::TlvValueTooLong(self.value.len(), 2));
        }
        Ok(u16::from_be_bytes([self.value[0], self.value[1]]))
    }

    /// Get the value as a u32
    pub fn as_u32(&self) -> Result<u32> {
        if self.value.len() != 4 {
            return Err(ProtoError::TlvValueTooLong(self.value.len(), 4));
        }
        Ok(u32::from_be_bytes([
            self.value[0],
            self.value[1],
            self.value[2],
            self.value[3],
        ]))
    }

    /// Get the value as a u64
    pub fn as_u64(&self) -> Result<u64> {
        if self.value.len() != 8 {
            return Err(ProtoError::TlvValueTooLong(self.value.len(), 8));
        }
        Ok(u64::from_be_bytes([
            self.value[0],
            self.value[1],
            self.value[2],
            self.value[3],
            self.value[4],
            self.value[5],
            self.value[6],
            self.value[7],
        ]))
    }

    /// Get the value as a string
    pub fn as_str(&self) -> Result<&str> {
        std::str::from_utf8(&self.value)
            .map_err(|_| ProtoError::ProtocolError("invalid UTF-8 in TLV".into()))
    }

    /// Get the value as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.value
    }

    /// Get the encoded length (1 + 2 + value_len)
    pub fn encoded_len(&self) -> usize {
        1 + 2 + self.value.len()
    }
}

/// TLV encoder - builds a buffer of concatenated TLVs
pub struct TlvEncoder {
    buf: BytesMut,
    seen_tags: std::collections::HashSet<u8>,
}

impl TlvEncoder {
    /// Create a new encoder
    pub fn new() -> Self {
        TlvEncoder {
            buf: BytesMut::new(),
            seen_tags: std::collections::HashSet::new(),
        }
    }

    /// Push a TLV (checks for duplicates)
    pub fn push(&mut self, tlv: Tlv) -> Result<()> {
        if self.seen_tags.contains(&tlv.tag) {
            return Err(ProtoError::DuplicateTlvTag(tlv.tag));
        }
        self.seen_tags.insert(tlv.tag);

        // tag (1 byte) + length (2 bytes, big-endian) + value
        if tlv.value.len() > u16::MAX as usize {
            return Err(ProtoError::TlvValueTooLong(
                tlv.value.len(),
                u16::MAX as usize,
            ));
        }
        self.buf.put_u8(tlv.tag);
        self.buf.put_u16(tlv.value.len() as u16);
        self.buf.extend_from_slice(&tlv.value);
        Ok(())
    }

    /// Finish and return the encoded bytes
    pub fn finish(self) -> Bytes {
        self.buf.freeze()
    }

    /// Get current length
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

impl Default for TlvEncoder {
    fn default() -> Self {
        Self::new()
    }
}

/// TLV decoder - parses a buffer of concatenated TLVs
pub struct TlvDecoder<'a> {
    buf: &'a [u8],
    pos: usize,
    seen_tags: std::collections::HashSet<u8>,
}

impl<'a> TlvDecoder<'a> {
    /// Create a new decoder from a byte slice
    pub fn new(buf: &'a [u8]) -> Self {
        TlvDecoder {
            buf,
            pos: 0,
            seen_tags: std::collections::HashSet::new(),
        }
    }

    /// Get the next TLV
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<Option<Tlv>> {
        if self.pos >= self.buf.len() {
            return Ok(None);
        }

        // Need at least 3 bytes (tag + length)
        if self.pos + 3 > self.buf.len() {
            return Err(ProtoError::TlvBufferTooShort {
                need: 3,
                have: self.buf.len() - self.pos,
            });
        }

        let tag = self.buf[self.pos];
        let len = u16::from_be_bytes([self.buf[self.pos + 1], self.buf[self.pos + 2]]) as usize;
        self.pos += 3;

        if self.pos + len > self.buf.len() {
            return Err(ProtoError::TlvBufferTooShort {
                need: self.pos + len,
                have: self.buf.len(),
            });
        }

        let value = Bytes::copy_from_slice(&self.buf[self.pos..self.pos + len]);
        self.pos += len;

        // Check for duplicate tags (optional - forward compatibility says skip unknown)
        // For required tags we can enforce, for optional we skip
        if self.seen_tags.contains(&tag) {
            // Don't error on duplicate, just skip per forward compatibility
            // But we track it
        }
        self.seen_tags.insert(tag);

        Ok(Some(Tlv { tag, value }))
    }

    /// Collect all TLVs into a vector
    pub fn collect_all(mut self) -> Result<Vec<Tlv>> {
        let mut tlvs = Vec::new();
        while let Some(tlv) = self.next()? {
            tlvs.push(tlv);
        }
        Ok(tlvs)
    }

    /// Find a specific tag
    pub fn find_tag(mut self, tag: u8) -> Result<Option<Tlv>> {
        while let Some(tlv) = self.next()? {
            if tlv.tag == tag {
                return Ok(Some(tlv));
            }
        }
        Ok(None)
    }

    /// Get remaining bytes
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
}

/// Parse TLVs from a byte slice, returning a vector
pub fn parse_tlvs(buf: &[u8]) -> Result<Vec<Tlv>> {
    TlvDecoder::new(buf).collect_all()
}

/// Find a specific TLV tag in a buffer
pub fn find_tlv(buf: &[u8], tag: u8) -> Result<Option<Tlv>> {
    TlvDecoder::new(buf).find_tag(tag)
}

/// Standard TLV tags for OPEN payload
pub mod open_tags {
    pub const PEER_ADDR: u8 = 0x01; // string: visitor IP:port
    pub const SNI_OR_HOST: u8 = 0x02; // string: SNI or Host header
    pub const TUNNEL_ID: u8 = 0x03; // u32: tunnel ID
    pub const PROXY_PROTOCOL: u8 = 0x04; // bytes: PROXY v2 header
    pub const PRIORITY: u8 = 0x05; // u8: priority hint
}

/// Standard TLV tags for HELLO payload
pub mod hello_tags {
    pub const VERSION: u8 = 0x00; // u8: protocol version
    pub const CLIENT_ID: u8 = 0x01; // string: client identifier
    pub const MAX_FRAME: u8 = 0x02; // u32: max frame payload
    pub const INITIAL_WINDOW: u8 = 0x03; // u32: initial window size
    pub const CAPABILITIES: u8 = 0x04; // u64: capability bitset
    pub const PRIORITY: u8 = 0x05; // u8: priority hint
}

/// Standard TLV tags for HELLO_ACK payload
pub mod hello_ack_tags {
    pub const VERSION: u8 = 0x00; // u8: protocol version
    pub const NONCE: u8 = 0x01; // 32 bytes: server nonce
    pub const MAX_FRAME: u8 = 0x02; // u32: negotiated max frame
    pub const CAPABILITIES: u8 = 0x03; // u64: negotiated capabilities
}

/// Standard TLV tags for AUTH payload
pub mod auth_tags {
    pub const HMAC: u8 = 0x01; // 32 bytes: HMAC-SHA256
}

/// Standard TLV tags for READY payload
pub mod ready_tags {
    pub const SESSION_ID: u8 = 0x01; // u64: session ID
    pub const RESUME_SECRET: u8 = 0x02; // 32 bytes: resume secret
    pub const MAX_STREAMS: u8 = 0x03; // u32: max streams per session
    pub const MAX_TUNNELS: u8 = 0x04; // u32: max tunnels per token
    pub const BANDWIDTH_LIMIT: u8 = 0x05; // u64: bytes/sec (optional)
}

/// Standard TLV tags for REGISTER payload
pub mod register_tags {
    pub const MODE: u8 = 0x01; // u8: TunnelMode
    pub const TUNNEL_ID: u8 = 0x02; // u32: requested tunnel ID
    pub const SUBDOMAIN: u8 = 0x03; // string: requested subdomain
    pub const REMOTE_PORT: u8 = 0x04; // u16: requested TCP port
}

/// Standard TLV tags for REGISTER_ACK payload
pub mod register_ack_tags {
    pub const PUBLIC_URL: u8 = 0x01; // string: public URL
    pub const TUNNEL_ID: u8 = 0x02; // u32: assigned tunnel ID
    pub const ASSIGNED_PORT: u8 = 0x03; // u16: assigned TCP port (TCP mode)
}

/// Capability bits (HELLO/HELLO_ACK)
pub mod capabilities {
    pub const CAP_COMPRESSION: u64 = 1 << 0; // per-frame compression
    pub const CAP_PROXY_PROTOCOL: u64 = 1 << 1; // PROXY protocol v2
    pub const CAP_RESUME: u64 = 1 << 2; // session resumption
    pub const CAP_WEBSOCKET: u64 = 1 << 3; // WebSocket passthrough
    pub const CAP_METRICS: u64 = 1 << 4; // metrics export
    pub const CAP_PRIORITY: u64 = 1 << 5; // stream priority hints
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tlv_encode_decode() {
        let mut encoder = TlvEncoder::new();
        encoder.push(Tlv::new(0x01, b"hello").unwrap()).unwrap();
        encoder.push(Tlv::new_u32(0x02, 42).unwrap()).unwrap();
        encoder
            .push(Tlv::new_u64(0x03, 123456789).unwrap())
            .unwrap();
        let encoded = encoder.finish();

        let tlvs = parse_tlvs(&encoded).unwrap();
        assert_eq!(tlvs.len(), 3);
        assert_eq!(tlvs[0].tag, 0x01);
        assert_eq!(tlvs[0].as_str().unwrap(), "hello");
        assert_eq!(tlvs[1].tag, 0x02);
        assert_eq!(tlvs[1].as_u32().unwrap(), 42);
        assert_eq!(tlvs[2].tag, 0x03);
        assert_eq!(tlvs[2].as_u64().unwrap(), 123456789);
    }

    #[test]
    fn test_tlv_find_tag() {
        let mut encoder = TlvEncoder::new();
        encoder.push(Tlv::new(0x01, b"first").unwrap()).unwrap();
        encoder.push(Tlv::new(0x02, b"second").unwrap()).unwrap();
        let encoded = encoder.finish();

        let found = find_tlv(&encoded, 0x02).unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().as_str().unwrap(), "second");

        let not_found = find_tlv(&encoded, 0x99).unwrap();
        assert!(not_found.is_none());
    }

    #[test]
    fn test_tlv_duplicate_tag_error() {
        let mut encoder = TlvEncoder::new();
        encoder.push(Tlv::new(0x01, b"first").unwrap()).unwrap();
        let result = encoder.push(Tlv::new(0x01, b"second").unwrap());
        assert!(result.is_err());
    }

    #[test]
    fn test_tlv_value_too_long() {
        let large = vec![0u8; MAX_TLV_VALUE_LEN + 1];
        let result = Tlv::new(0x01, &large);
        assert!(result.is_err());
    }

    #[test]
    fn test_tlv_truncated() {
        let buf = [0x01, 0x00, 0x05, 0x68, 0x65]; // tag=1, len=5, but only 2 bytes of value
        let result = parse_tlvs(&buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_tlv_type_conversions_and_errors() {
        let tlv_u8 = Tlv::new_u8(1, 42).unwrap();
        assert_eq!(tlv_u8.as_u8().unwrap(), 42);
        assert!(tlv_u8.as_u16().is_err());
        assert!(tlv_u8.as_u32().is_err());
        assert!(tlv_u8.as_u64().is_err());
        assert_eq!(tlv_u8.encoded_len(), 4);

        let tlv_u16 = Tlv::new_u16(2, 1000).unwrap();
        assert_eq!(tlv_u16.as_u16().unwrap(), 1000);
        assert!(tlv_u16.as_u8().is_err());

        let tlv_u32 = Tlv::new_u32(3, 100_000).unwrap();
        assert_eq!(tlv_u32.as_u32().unwrap(), 100_000);
        assert!(tlv_u32.as_u64().is_err());

        let tlv_invalid_utf8 = Tlv::new(4, &[0xFF, 0xFE]).unwrap();
        assert!(tlv_invalid_utf8.as_str().is_err());
        assert_eq!(tlv_invalid_utf8.as_bytes(), &[0xFF, 0xFE]);
    }

    #[test]
    fn test_tlv_encoder_helpers() {
        let mut encoder = TlvEncoder::default();
        assert!(encoder.is_empty());
        assert_eq!(encoder.len(), 0);

        encoder.push(Tlv::new_u8(1, 10).unwrap()).unwrap();
        assert!(!encoder.is_empty());
        assert_eq!(encoder.len(), 4);
    }

    #[test]
    fn test_tlv_decoder_short_header_and_remaining() {
        let mut decoder = TlvDecoder::new(&[0x01, 0x00]); // only 2 bytes, needs 3
        assert_eq!(decoder.remaining(), 2);
        assert!(decoder.next().is_err());

        let valid_encoded = [0x01, 0x00, 0x01, 0x7A];
        let mut decoder2 = TlvDecoder::new(&valid_encoded);
        assert_eq!(decoder2.remaining(), 4);
        let t = decoder2.next().unwrap().unwrap();
        assert_eq!(t.tag, 0x01);
        assert_eq!(decoder2.remaining(), 0);
        assert!(decoder2.next().unwrap().is_none());
    }
}
