//! Fuzz target for Frame decoding

#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use qt_proto::{Frame, FrameType, Header, DEFAULT_MAX_PAYLOAD, HEADER_LEN};

fuzz_target!(|data: &[u8]| {
    // Try to decode arbitrary data as frames
    if data.len() < HEADER_LEN {
        return;
    }

    // Check if it looks like a valid header
    let frame_type = FrameType::try_from(data[0]);
    if frame_type.is_err() {
        return; // Invalid frame type, skip
    }

    let len = u32::from_be_bytes([
        data[data.len().min(12) - 4],
        data[data.len().min(12) - 3],
        data[data.len().min(12) - 2],
        data[data.len().min(12) - 1],
    ]);

    // If the length is way too large, skip
    if len > DEFAULT_MAX_PAYLOAD || len as usize > data.len() {
        return;
    }

    // Try to build a frame manually and test its safe decoders
    // This tests the safe typed payload decoders don't panic
    let header_data = &data[..HEADER_LEN.min(data.len())];
    let payload_data = &data[HEADER_LEN.min(data.len())..];

    // Test with a few frame types that have fixed-size payloads
    let mut test_header = [0u8; HEADER_LEN];
    if header_data.len() == HEADER_LEN {
        test_header.copy_from_slice(header_data);

        if let Ok(header) = Header::decode(&test_header, DEFAULT_MAX_PAYLOAD) {
            // Only test fixed-size frame types to avoid OOB
            match header.ty {
                FrameType::WindowUpdate if header.len == 4 && payload_data.len() >= 4 => {
                    let frame = Frame {
                        header,
                        payload: Bytes::copy_from_slice(&payload_data[..4]),
                    };
                    let _ = frame.parse_window_update();
                }
                FrameType::Ping if header.len == 8 && payload_data.len() >= 8 => {
                    let frame = Frame {
                        header,
                        payload: Bytes::copy_from_slice(&payload_data[..8]),
                    };
                    let _ = frame.parse_ping();
                }
                FrameType::Pong if header.len == 8 && payload_data.len() >= 8 => {
                    let frame = Frame {
                        header,
                        payload: Bytes::copy_from_slice(&payload_data[..8]),
                    };
                    let _ = frame.parse_pong();
                }
                FrameType::Rst if header.len == 4 && payload_data.len() >= 4 => {
                    let frame = Frame {
                        header,
                        payload: Bytes::copy_from_slice(&payload_data[..4]),
                    };
                    let _ = frame.parse_rst();
                }
                FrameType::GoAway if header.len == 8 && payload_data.len() >= 8 => {
                    let frame = Frame {
                        header,
                        payload: Bytes::copy_from_slice(&payload_data[..8]),
                    };
                    let _ = frame.parse_goaway();
                }
                FrameType::Fin if header.len == 0 => {
                    let frame = Frame {
                        header,
                        payload: Bytes::new(),
                    };
                    let _ = frame.parse_fin();
                }
                _ => {}
            }
        }
    }
});
