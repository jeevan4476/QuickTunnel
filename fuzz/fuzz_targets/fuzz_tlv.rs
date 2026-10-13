//! Fuzz target for TLV parsing

#![no_main]

use libfuzzer_sys::fuzz_target;
use qt_proto::tlv::{
    auth_tags, hello_ack_tags, hello_tags, open_tags, parse_tlvs, ready_tags, register_ack_tags,
    register_tags, Tlv, TlvEncoder, MAX_TLV_VALUE_LEN,
};

fuzz_target!(|data: &[u8]| {
    // Test TLV parsing - should never panic regardless of input
    let _ = parse_tlvs(data);

    // Test roundtrip with arbitrary TLVs
    if !data.is_empty() {
        let mut encoder = TlvEncoder::new();
        // Try to encode some arbitrary bytes as TLVs
        // Use a subset of known tags
        let tags = [
            open_tags::PEER_ADDR,
            open_tags::SNI_OR_HOST,
            open_tags::TUNNEL_ID,
            open_tags::PROXY_PROTOCOL,
            open_tags::PRIORITY,
            hello_tags::VERSION,
            hello_tags::CLIENT_ID,
            hello_tags::MAX_FRAME,
            hello_tags::INITIAL_WINDOW,
            hello_tags::CAPABILITIES,
            hello_tags::PRIORITY,
            hello_ack_tags::VERSION,
            hello_ack_tags::NONCE,
            hello_ack_tags::MAX_FRAME,
            hello_ack_tags::CAPABILITIES,
            register_tags::MODE,
            register_tags::TUNNEL_ID,
            register_tags::SUBDOMAIN,
            register_tags::REMOTE_PORT,
            register_ack_tags::PUBLIC_URL,
            register_ack_tags::TUNNEL_ID,
            register_ack_tags::ASSIGNED_PORT,
            auth_tags::HMAC,
            ready_tags::SESSION_ID,
            ready_tags::RESUME_SECRET,
            ready_tags::MAX_STREAMS,
            ready_tags::MAX_TUNNELS,
            ready_tags::BANDWIDTH_LIMIT,
        ];

        // Try to push a few TLVs with the fuzz data
        for (i, &tag) in tags.iter().enumerate() {
            if i >= data.len() {
                break;
            }
            let val_len = (data[i] as usize)
                .min(MAX_TLV_VALUE_LEN)
                .min(data.len().saturating_sub(i + 1));
            if i + 1 + val_len <= data.len() {
                if let Ok(tlv) = Tlv::new(tag, &data[i + 1..i + 1 + val_len]) {
                    let _ = encoder.push(tlv);
                }
            }
        }

        let encoded = encoder.finish();
        // Parsing our own encoded data should work
        let _ = parse_tlvs(&encoded);
    }
});
