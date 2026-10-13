//! Fuzz target for Header::decode

#![no_main]

use libfuzzer_sys::fuzz_target;
use qt_proto::{Header, ProtoError, DEFAULT_MAX_PAYLOAD, HEADER_LEN};

fuzz_target!(|data: &[u8]| {
    if data.len() != HEADER_LEN {
        return;
    }

    let mut buf = [0u8; HEADER_LEN];
    buf.copy_from_slice(data);

    // Try to decode the header - this should never panic
    let result = Header::decode(&buf, DEFAULT_MAX_PAYLOAD);

    // Verify it handles all cases correctly
    match result {
        Ok(header) => {
            // Verify frame type is valid
            let _ = header.ty as u8;
            // Verify length is within bounds
            assert!(header.len <= DEFAULT_MAX_PAYLOAD);
        }
        Err(ProtoError::UnknownType(_)) => {
            // Valid: unknown frame type rejected
        }
        Err(ProtoError::FrameTooLarge { .. }) => {
            // Valid: frame too large rejected
        }
        Err(ProtoError::ProtocolError(_)) => {
            // Valid: other protocol errors
        }
        Err(_) => {
            // Other error types are also valid
        }
    }
});
