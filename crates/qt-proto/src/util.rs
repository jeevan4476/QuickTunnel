//! Utility functions: checksums, encoding, framing helpers, byte ordering

use crate::{ProtoError, Result, HEADER_LEN};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::net::SocketAddr;

/// Compute a simple CRC32C (Castagnoli) checksum
/// Note: In production, use hardware-accelerated crc32c via ring or crc32fast
pub fn crc32c(data: &[u8]) -> u32 {
    crc32fast::hash(data)
}

/// Verify CRC32C checksum
pub fn verify_crc32c(data: &[u8], expected: u32) -> bool {
    crc32c(data) == expected
}

/// Write a u16 in big-endian
pub fn write_u16_be(buf: &mut [u8], val: u16) {
    buf.copy_from_slice(&val.to_be_bytes());
}

/// Write a u32 in big-endian
pub fn write_u32_be(buf: &mut [u8], val: u32) {
    buf.copy_from_slice(&val.to_be_bytes());
}

/// Write a u64 in big-endian
pub fn write_u64_be(buf: &mut [u8], val: u64) {
    buf.copy_from_slice(&val.to_be_bytes());
}

/// Read a u16 in big-endian
pub fn read_u16_be(buf: &[u8]) -> u16 {
    u16::from_be_bytes([buf[0], buf[1]])
}

/// Read a u32 in big-endian
pub fn read_u32_be(buf: &[u8]) -> u32 {
    u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]])
}

/// Read a u64 in big-endian
pub fn read_u64_be(buf: &[u8]) -> u64 {
    u64::from_be_bytes([
        buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
    ])
}

/// Frame assembler for assembling/disassembling frames
pub struct FrameAssembler {
    buffer: BytesMut,
    max_payload: u32,
    header: Option<crate::Header>,
}

impl FrameAssembler {
    pub fn new(max_payload: u32) -> Self {
        FrameAssembler {
            buffer: BytesMut::new(),
            max_payload,
            header: None,
        }
    }

    /// Feed data and extract complete frames
    pub fn feed(&mut self, data: &[u8]) -> Result<Vec<crate::Frame>> {
        self.buffer.extend_from_slice(data);
        let mut frames = Vec::new();

        loop {
            if self.header.is_none() {
                // Need to read header
                if self.buffer.len() >= HEADER_LEN {
                    let header_bytes: [u8; HEADER_LEN] = self.buffer[..HEADER_LEN]
                        .try_into()
                        .map_err(|_| ProtoError::ProtocolError("header copy failed".into()))?;
                    let header = crate::Header::decode(&header_bytes, self.max_payload)?;
                    self.buffer.advance(HEADER_LEN);
                    self.header = Some(header);
                } else {
                    break;
                }
            }

            // Have header, need payload
            let header = self.header.unwrap();
            if self.buffer.len() >= header.len as usize {
                let payload = self.buffer.split_to(header.len as usize).freeze();
                let frame = crate::Frame { header, payload };
                frames.push(frame);
                self.header = None;
            } else {
                break;
            }
        }
        Ok(frames)
    }

    /// Check if we have a partial frame
    pub fn has_partial(&self) -> bool {
        self.header.is_some() || !self.buffer.is_empty()
    }

    /// Remaining bytes needed for current frame
    pub fn needed(&self) -> usize {
        if let Some(header) = self.header {
            header.len as usize - self.buffer.len()
        } else {
            HEADER_LEN - self.buffer.len()
        }
    }

    /// Reset state
    pub fn reset(&mut self) {
        self.buffer.clear();
        self.header = None;
    }
}

/// Encode a socket address to bytes (for PROXY protocol or logging)
pub fn encode_socket_addr(addr: &SocketAddr) -> Bytes {
    let mut buf = BytesMut::new();
    match addr {
        SocketAddr::V4(v4) => {
            buf.put_u8(1); // IPv4
            buf.extend_from_slice(&v4.ip().octets());
            buf.put_u16(v4.port());
        }
        SocketAddr::V6(v6) => {
            buf.put_u8(2); // IPv6
            buf.extend_from_slice(&v6.ip().octets());
            buf.put_u16(v6.port());
        }
    }
    buf.freeze()
}

/// Decode socket address from bytes
pub fn decode_socket_addr(buf: &[u8]) -> Result<SocketAddr> {
    if buf.len() < 3 {
        return Err(ProtoError::ProtocolError("socket addr too short".into()));
    }
    match buf[0] {
        1 => {
            if buf.len() < 7 {
                return Err(ProtoError::ProtocolError("IPv4 addr too short".into()));
            }
            let ip = std::net::Ipv4Addr::new(buf[1], buf[2], buf[3], buf[4]);
            let port = u16::from_be_bytes([buf[5], buf[6]]);
            Ok(SocketAddr::new(std::net::IpAddr::V4(ip), port))
        }
        2 => {
            if buf.len() < 19 {
                return Err(ProtoError::ProtocolError("IPv6 addr too short".into()));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[1..17]);
            let ip = std::net::Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([buf[17], buf[18]]);
            Ok(SocketAddr::new(std::net::IpAddr::V6(ip), port))
        }
        _ => Err(ProtoError::ProtocolError("unknown address family".into())),
    }
}

/// Variable-length integer encoding (LEB128-like but simpler)
pub fn encode_varint(mut val: u64, buf: &mut BytesMut) {
    while val >= 0x80 {
        buf.put_u8((val & 0x7F) as u8 | 0x80);
        val >>= 7;
    }
    buf.put_u8(val as u8);
}

/// Decode variable-length integer
pub fn decode_varint(buf: &mut &[u8]) -> Result<u64> {
    let mut val: u64 = 0;
    let mut shift = 0;
    let mut i = 0;
    while i < buf.len() {
        let byte = buf[i];
        val |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            *buf = &buf[i + 1..];
            return Ok(val);
        }
        shift += 7;
        if shift > 63 {
            return Err(ProtoError::ProtocolError("varint too long".into()));
        }
        i += 1;
    }
    Err(ProtoError::ProtocolError("truncated varint".into()))
}

/// Format bytes as hex string
pub fn hex_encode(data: &[u8]) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut out = String::with_capacity(data.len() * 2);
    for &b in data {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xF) as usize] as char);
    }
    out
}

/// Parse hex string to bytes
pub fn hex_decode(s: &str) -> Result<Bytes> {
    if !s.len().is_multiple_of(2) {
        return Err(ProtoError::ProtocolError("odd hex length".into()));
    }
    let mut out = BytesMut::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = from_hex(bytes[i])?;
        let lo = from_hex(bytes[i + 1])?;
        out.put_u8((hi << 4) | lo);
    }
    Ok(out.freeze())
}

fn from_hex(b: u8) -> Result<u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(ProtoError::ProtocolError("invalid hex char".into())),
    }
}

/// Human-readable frame summary
pub fn frame_summary(frame: &crate::Frame) -> String {
    use crate::FrameType;
    let ty = match frame.header.ty {
        FrameType::Data => "DATA",
        FrameType::Open => "OPEN",
        FrameType::WindowUpdate => "WIN_UPDATE",
        FrameType::Fin => "FIN",
        FrameType::Rst => "RST",
        FrameType::Ping => "PING",
        FrameType::Pong => "PONG",
        FrameType::GoAway => "GOAWAY",
        FrameType::Hello => "HELLO",
        FrameType::HelloAck => "HELLO_ACK",
        FrameType::Auth => "AUTH",
        FrameType::Ready => "READY",
        FrameType::Register => "REGISTER",
        FrameType::RegisterAck => "REGISTER_ACK",
    };
    let flags = if frame.header.flags != 0 {
        format!(" flags={:#04x}", frame.header.flags)
    } else {
        String::new()
    };
    format!(
        "{} sid={} len={}{}",
        ty, frame.header.stream_id, frame.header.len, flags
    )
}

/// Rate limiter using token bucket
pub struct TokenBucket {
    capacity: u64,
    tokens: f64,
    refill_rate: f64, // tokens per second
    last_refill: std::time::Instant,
}

impl TokenBucket {
    pub fn new(capacity: u64, refill_rate: f64) -> Self {
        TokenBucket {
            capacity,
            tokens: capacity as f64,
            refill_rate,
            last_refill: std::time::Instant::now(),
        }
    }

    pub fn try_take(&mut self, n: u64) -> bool {
        self.refill();
        if self.tokens >= n as f64 {
            self.tokens -= n as f64;
            true
        } else {
            false
        }
    }

    pub fn take_or_wait(&mut self, n: u64) -> std::time::Duration {
        self.refill();
        if self.tokens >= n as f64 {
            self.tokens -= n as f64;
            std::time::Duration::ZERO
        } else {
            let needed = n as f64 - self.tokens;
            let wait_secs = needed / self.refill_rate;
            std::time::Duration::from_secs_f64(wait_secs)
        }
    }

    fn refill(&mut self) {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.capacity as f64);
        self.last_refill = now;
    }

    pub fn available(&self) -> u64 {
        self.tokens.floor() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Frame, FrameType, DEFAULT_MAX_PAYLOAD};
    use bytes::BytesMut;

    #[test]
    fn test_write_read_u16() {
        let mut buf = [0u8; 2];
        write_u16_be(&mut buf, 0x1234);
        assert_eq!(read_u16_be(&buf), 0x1234);
    }

    #[test]
    fn test_write_read_u32() {
        let mut buf = [0u8; 4];
        write_u32_be(&mut buf, 0x12345678);
        assert_eq!(read_u32_be(&buf), 0x12345678);
    }

    #[test]
    fn test_write_read_u64() {
        let mut buf = [0u8; 8];
        write_u64_be(&mut buf, 0x123456789ABCDEF0);
        assert_eq!(read_u64_be(&buf), 0x123456789ABCDEF0);
    }

    #[test]
    fn test_varint_encode_decode() {
        let mut buf = BytesMut::new();
        encode_varint(0, &mut buf);
        encode_varint(127, &mut buf);
        encode_varint(128, &mut buf);
        encode_varint(16383, &mut buf);
        encode_varint(16384, &mut buf);

        let mut slice = &buf[..];
        assert_eq!(decode_varint(&mut slice).unwrap(), 0);
        assert_eq!(decode_varint(&mut slice).unwrap(), 127);
        assert_eq!(decode_varint(&mut slice).unwrap(), 128);
        assert_eq!(decode_varint(&mut slice).unwrap(), 16383);
        assert_eq!(decode_varint(&mut slice).unwrap(), 16384);
        assert!(slice.is_empty());
    }

    #[test]
    fn test_hex_encode_decode() {
        let data = b"hello world";
        let encoded = hex_encode(data);
        let decoded = hex_decode(&encoded).unwrap();
        assert_eq!(&decoded[..], data);
    }

    #[test]
    fn test_token_bucket() {
        let mut bucket = TokenBucket::new(100, 10.0); // 100 capacity, 10/sec
        assert!(bucket.try_take(50));
        assert_eq!(bucket.available(), 50);
        assert!(!bucket.try_take(60));
        assert!(bucket.try_take(40));
        assert_eq!(bucket.available(), 10);
    }

    #[test]
    fn test_socket_addr_encode_decode() {
        let addr: SocketAddr = "192.168.1.1:8080".parse().unwrap();
        let encoded = encode_socket_addr(&addr);
        let decoded = decode_socket_addr(&encoded).unwrap();
        assert_eq!(addr, decoded);

        let addr6: SocketAddr = "[::1]:8080".parse().unwrap();
        let encoded = encode_socket_addr(&addr6);
        let decoded = decode_socket_addr(&encoded).unwrap();
        assert_eq!(addr6, decoded);
    }

    #[test]
    fn test_frame_assembler_basic() {
        let mut assembler = FrameAssembler::new(DEFAULT_MAX_PAYLOAD);
        let frame = Frame::data(1, Bytes::from_static(b"hello"), false).unwrap();
        let mut encoded = BytesMut::new();
        frame.encode(&mut encoded);

        // Feed in one shot
        let frames = assembler.feed(&encoded).unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].header.ty, FrameType::Data);
        assert_eq!(frames[0].header.stream_id, 1);
        assert_eq!(&frames[0].payload[..], b"hello");
    }

    #[test]
    fn test_frame_assembler_partial_feed() {
        let mut assembler = FrameAssembler::new(DEFAULT_MAX_PAYLOAD);
        let frame = Frame::data(1, Bytes::from_static(b"hello world"), false).unwrap();
        let mut encoded = BytesMut::new();
        frame.encode(&mut encoded);

        // Feed 1 byte at a time
        let mut frames = Vec::new();
        for byte in encoded.iter() {
            let chunk = [*byte];
            let result = assembler.feed(&chunk).unwrap();
            frames.extend(result);
        }
        assert_eq!(frames.len(), 1);
        assert_eq!(&frames[0].payload[..], b"hello world");
    }

    #[test]
    fn test_frame_assembler_multiple_frames() {
        let mut assembler = FrameAssembler::new(DEFAULT_MAX_PAYLOAD);
        let frame1 = Frame::data(1, Bytes::from_static(b"first"), false).unwrap();
        let frame2 = Frame::data(2, Bytes::from_static(b"second"), false).unwrap();
        let mut encoded = BytesMut::new();
        frame1.encode(&mut encoded);
        frame2.encode(&mut encoded);

        let frames = assembler.feed(&encoded).unwrap();
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].header.stream_id, 1);
        assert_eq!(frames[1].header.stream_id, 2);
    }

    #[test]
    fn test_crc32c() {
        let data = b"quicktunnel checksum test";
        let c = crc32c(data);
        assert!(verify_crc32c(data, c));
        assert!(!verify_crc32c(data, c ^ 1));
    }

    #[test]
    fn test_frame_assembler_partial_needed_reset() {
        let mut assembler = FrameAssembler::new(DEFAULT_MAX_PAYLOAD);
        assert!(!assembler.has_partial());
        assert_eq!(assembler.needed(), crate::HEADER_LEN);

        let partial_header = [0u8; 6];
        let _ = assembler.feed(&partial_header).unwrap();
        assert!(assembler.has_partial());
        assert_eq!(assembler.needed(), 6);

        assembler.reset();
        assert!(!assembler.has_partial());
        assert_eq!(assembler.needed(), crate::HEADER_LEN);
    }

    #[test]
    fn test_socket_addr_error_cases() {
        assert!(decode_socket_addr(&[]).is_err());
        assert!(decode_socket_addr(&[1, 127, 0, 0]).is_err()); // short ipv4
        assert!(decode_socket_addr(&[2, 0, 1]).is_err()); // short ipv6
        assert!(decode_socket_addr(&[99, 1, 2, 3]).is_err()); // unknown family
    }

    #[test]
    fn test_varint_errors() {
        // Varint truncated
        let truncated = [0x80u8, 0x80u8];
        let mut slice = &truncated[..];
        assert!(decode_varint(&mut slice).is_err());

        // Varint too long (> 10 bytes with msb set)
        let too_long = [0x80u8; 11];
        let mut slice = &too_long[..];
        assert!(decode_varint(&mut slice).is_err());
    }

    #[test]
    fn test_hex_errors() {
        assert!(hex_decode("abc").is_err()); // odd length
        assert!(hex_decode("zz").is_err()); // invalid hex
    }

    #[test]
    fn test_token_bucket_wait() {
        let mut bucket = TokenBucket::new(10, 100.0);
        let wait0 = bucket.take_or_wait(5);
        assert_eq!(wait0, std::time::Duration::ZERO);

        let wait_needed = bucket.take_or_wait(20);
        assert!(wait_needed > std::time::Duration::ZERO);
    }

    #[test]
    fn test_frame_summary_all_types() {
        let f_data = Frame::data(1, Bytes::from_static(b"x"), true).unwrap();
        assert!(frame_summary(&f_data).contains("DATA"));
        assert!(frame_summary(&f_data).contains("flags="));

        let f_wu = Frame::window_update(0, 4096).unwrap();
        assert!(frame_summary(&f_wu).contains("WIN_UPDATE"));

        let f_fin = Frame::fin(1).unwrap();
        assert!(frame_summary(&f_fin).contains("FIN"));

        let f_rst = Frame::rst(1, 0).unwrap();
        assert!(frame_summary(&f_rst).contains("RST"));

        let f_ping = Frame::ping(123).unwrap();
        assert!(frame_summary(&f_ping).contains("PING"));

        let f_pong = Frame::pong(123).unwrap();
        assert!(frame_summary(&f_pong).contains("PONG"));

        let f_goaway = Frame::goaway(10, 0).unwrap();
        assert!(frame_summary(&f_goaway).contains("GOAWAY"));

        let f_hello = Frame::hello("c1", 16384, 65536, 0).unwrap();
        assert!(frame_summary(&f_hello).contains("HELLO"));

        let f_ack = Frame::hello_ack(&[0u8; 32], 16384, 0).unwrap();
        assert!(frame_summary(&f_ack).contains("HELLO_ACK"));

        let f_auth = Frame::auth(&[0u8; 32]).unwrap();
        assert!(frame_summary(&f_auth).contains("AUTH"));

        let f_ready = Frame::ready(1, &[0u8; 32], 10, 10, None).unwrap();
        assert!(frame_summary(&f_ready).contains("READY"));

        let f_reg = Frame::register(crate::TunnelMode::Http, None, None, 1).unwrap();
        assert!(frame_summary(&f_reg).contains("REGISTER"));

        let f_reg_ack = Frame::register_ack(1, "http://test", None).unwrap();
        assert!(frame_summary(&f_reg_ack).contains("REGISTER_ACK"));
    }
}
