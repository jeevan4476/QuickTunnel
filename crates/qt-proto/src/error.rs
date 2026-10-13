//! Protocol errors

use thiserror::Error;

/// Protocol-level errors
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum ProtoError {
    /// Unknown frame type byte
    #[error("unknown frame type: {0}")]
    UnknownType(u8),

    /// Frame payload exceeds negotiated maximum
    #[error("frame payload too large: {0} bytes (max {1})")]
    FrameTooLarge(u32, u32),

    /// Reserved bits in header were non-zero
    #[error("reserved header bits must be zero")]
    ReservedBitsNonZero,

    /// Stream ID allocation violation (not strictly increasing per initiator)
    #[error("stream ID {0} not greater than last seen {1} for this initiator")]
    StreamIdNotIncreasing(u32, u32),

    /// Invalid state transition for a stream
    #[error("invalid state transition: {current:?} --{frame:?}--> {next:?}")]
    InvalidStateTransition {
        current: &'static str,
        frame: &'static str,
        next: &'static str,
    },

    /// Flow control violation: sent beyond granted credit
    #[error("flow control error: sent {sent} bytes, credit was {credit}")]
    FlowControlError { sent: u32, credit: u32 },

    /// TLV parsing errors
    #[error("TLV buffer too short: need {need}, have {have}")]
    TlvBufferTooShort { need: usize, have: usize },

    #[error("unknown TLV tag: {0}")]
    UnknownTlvTag(u8),

    #[error("duplicate TLV tag: {0}")]
    DuplicateTlvTag(u8),

    #[error("required TLV tag missing: {0}")]
    MissingRequiredTlv(u8),

    #[error("TLV value too long: {0} bytes (max {1})")]
    TlvValueTooLong(usize, usize),

    /// Authentication errors
    #[error("authentication failed: {0}")]
    AuthFailed(String),

    /// Protocol version mismatch
    #[error("protocol version mismatch: client={client}, server={server}")]
    VersionMismatch { client: u8, server: u8 },

    /// Capability negotiation failure
    #[error("capability negotiation failed: {0}")]
    CapabilityNegotiationFailed(String),

    /// Generic protocol error
    #[error("protocol error: {0}")]
    ProtocolError(String),

    /// I/O error wrapper
    #[error("I/O error: {0}")]
    IoError(String),
}

impl From<std::io::Error> for ProtoError {
    fn from(e: std::io::Error) -> Self {
        ProtoError::IoError(e.to_string())
    }
}

/// Result type alias
pub type Result<T> = std::result::Result<T, ProtoError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "pipe broken");
        let proto_err = ProtoError::from(io_err);
        assert!(matches!(proto_err, ProtoError::IoError(_)));
        assert!(proto_err.to_string().contains("pipe broken"));
    }

    #[test]
    fn test_error_display() {
        let err = ProtoError::FrameTooLarge(20000, 16384);
        assert!(err.to_string().contains("frame payload too large"));

        let err = ProtoError::VersionMismatch {
            client: 1,
            server: 2,
        };
        assert!(err.to_string().contains("version mismatch"));

        let err = ProtoError::FlowControlError {
            sent: 50,
            credit: 10,
        };
        assert!(err.to_string().contains("flow control"));
    }
}
