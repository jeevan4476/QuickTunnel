//! QTP v1 — QuickTunnel Protocol
//!
//! This crate defines the wire protocol: frame types, header codec, TLV encoding,
//! error codes, and control payload structures. It is I/O-free and has no tokio
//! dependency so it can be fuzzed in isolation and used from WASM.

pub mod control;
pub mod error;
pub mod frame;
pub mod tlv;
pub mod util;

pub use control::{
    compute_auth_hmac, generate_nonce, generate_resume_secret, generate_session_id,
    generate_tunnel_id, verify_auth_hmac, Auth, Hello, HelloAck, OpenPayload, Ready, Register,
    RegisterAck, ResumeState, ResumeTunnel, SessionLimits, TokenLimits,
};
pub use error::{ProtoError, Result};
pub use frame::{
    error_codes, flags, Frame, FrameType, Header, StreamState, TunnelMode, MAX_FRAME_PAYLOAD,
};
pub use tlv::{
    auth_tags, capabilities, find_tlv, hello_ack_tags, hello_tags, open_tags, parse_tlvs,
    ready_tags, register_ack_tags, register_tags, Tlv, TlvDecoder, TlvEncoder, TlvTag,
    MAX_TLV_VALUE_LEN,
};
pub use util::{
    crc32c, decode_socket_addr, decode_varint, encode_socket_addr, encode_varint, frame_summary,
    hex_decode, hex_encode, read_u16_be, read_u32_be, read_u64_be, verify_crc32c, write_u16_be,
    write_u32_be, write_u64_be, FrameAssembler, TokenBucket,
};

/// Protocol version
pub const PROTOCOL_VERSION: u8 = 1;

/// Default maximum frame payload (16 KiB)
pub const DEFAULT_MAX_PAYLOAD: u32 = 16 * 1024;

/// Maximum negotiable frame payload (1 MiB)
pub const ABSOLUTE_MAX_PAYLOAD: u32 = 1024 * 1024;

/// Header length in bytes (fixed 12)
pub const HEADER_LEN: usize = 12;

/// Stream ID 0 is the connection/control scope
pub const CONTROL_STREAM_ID: u32 = 0;
