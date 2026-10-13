//! Reconnection backoff policy and error severity classification.

use std::fmt;
use std::time::Duration;

use rand::Rng;

use qt_proto::ProtoError;

use crate::config::ClientConfig;

/// Severity classification for errors encountered during connection or session lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorSeverity {
    /// Fatal unrecoverable error; client must abort immediately without retrying.
    Fatal,
    /// Transient error; client may retry with backoff.
    Retryable,
}

impl fmt::Display for ErrorSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fatal => write!(f, "fatal"),
            Self::Retryable => write!(f, "retryable"),
        }
    }
}

impl ErrorSeverity {
    /// Return `true` if this error severity is fatal.
    pub fn is_fatal(&self) -> bool {
        matches!(self, Self::Fatal)
    }

    /// Return `true` if this error severity is retryable.
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Retryable)
    }
}

/// Classify a protocol or connection error into fatal vs retryable per §13.1.
///
/// Fatal errors abort reconnect loops immediately:
/// - Authentication failures (`AUTH_FAILED`, invalid HMAC/secret)
/// - Protocol version mismatches and unsupported capabilities
/// - Subdomain or port collisions / validation failures (already in use, reserved, invalid)
///
/// Retryable errors back off and reconnect:
/// - I/O errors (connection refused, timeouts, resets, broken pipes)
/// - Transient protocol state drops or framing errors
pub fn classify_error(err: &ProtoError) -> ErrorSeverity {
    match err {
        ProtoError::AuthFailed(_)
        | ProtoError::VersionMismatch { .. }
        | ProtoError::CapabilityNegotiationFailed(_) => ErrorSeverity::Fatal,
        ProtoError::ProtocolError(msg) => {
            let lower = msg.to_ascii_lowercase();
            if lower.contains("subdomain")
                || lower.contains("already in use")
                || lower.contains("already registered")
                || lower.contains("collision")
                || lower.contains("taken")
                || lower.contains("reserved")
                || lower.contains("outside allowed range")
                || lower.contains("no available tcp ports")
                || lower.contains("auth_failed")
                || lower.contains("authentication failed")
                || lower.contains("invalid credentials")
                || lower.contains("unauthorized")
                || lower.contains("forbidden")
            {
                ErrorSeverity::Fatal
            } else {
                ErrorSeverity::Retryable
            }
        }
        _ => ErrorSeverity::Retryable,
    }
}

/// Exponential backoff policy with decorrelated jitter per §13.1.
///
/// The backoff duration for attempt $k$ (0-indexed) is:
/// $$t = \min(t_{\text{max}}, t_{\text{base}} \times 2^k + \text{jitter})$$
/// where jitter is uniformly chosen in $[0, t_{\text{base}} \times 2^k]$,
/// bounding each attempt's delay in $[t_{\text{base}} \times 2^k, \min(t_{\text{max}}, 2 \times t_{\text{base}} \times 2^k)]$.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackoffPolicy {
    initial: Duration,
    max: Duration,
    max_retries: Option<u32>,
    attempts: u32,
}

impl Default for BackoffPolicy {
    fn default() -> Self {
        Self::new(Duration::from_millis(500), Duration::from_secs(30), None)
    }
}

impl BackoffPolicy {
    /// Create a new `BackoffPolicy`.
    pub fn new(initial: Duration, max: Duration, max_retries: Option<u32>) -> Self {
        Self {
            initial,
            max,
            max_retries,
            attempts: 0,
        }
    }

    /// Construct a `BackoffPolicy` from `ClientConfig`.
    pub fn from_config(config: &ClientConfig) -> Self {
        Self::new(
            config.initial_backoff,
            config.max_backoff,
            config.max_retries,
        )
    }

    /// Initial base backoff duration.
    pub fn initial(&self) -> Duration {
        self.initial
    }

    /// Maximum backoff duration cap.
    pub fn max(&self) -> Duration {
        self.max
    }

    /// Configured maximum retry attempts (`None` = unlimited).
    pub fn max_retries(&self) -> Option<u32> {
        self.max_retries
    }

    /// Number of attempts made so far in the current reconnect cycle.
    pub fn attempts(&self) -> u32 {
        self.attempts
    }

    /// Reset attempt counter to 0 (e.g. after connection is healthy for > 60s).
    pub fn reset(&mut self) {
        self.attempts = 0;
    }

    /// Calculate next retry delay, or `None` if `max_retries` is exhausted.
    pub fn next_delay(&mut self) -> Option<Duration> {
        if let Some(max_retries) = self.max_retries {
            if self.attempts >= max_retries {
                return None;
            }
        }

        let k = self.attempts;
        self.attempts = self.attempts.saturating_add(1);

        // Compute base delay for attempt k: initial * 2^k
        let mut tk = self.initial;
        for _ in 0..k.min(62) {
            tk = tk.saturating_mul(2);
            if tk >= self.max {
                tk = self.max;
                break;
            }
        }

        if tk >= self.max {
            return Some(self.max);
        }

        // Random jitter in [0, tk]
        let tk_nanos = tk.as_nanos();
        let jitter_nanos = if tk_nanos > 0 {
            rand::thread_rng().gen_range(0..=tk_nanos.min(u64::MAX as u128)) as u64
        } else {
            0
        };
        let jitter = Duration::from_nanos(jitter_nanos);

        Some(tk.saturating_add(jitter).min(self.max))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_severity_classification() {
        assert_eq!(
            classify_error(&ProtoError::AuthFailed("bad key".into())),
            ErrorSeverity::Fatal
        );
        assert_eq!(
            classify_error(&ProtoError::ProtocolError(
                "subdomain 'foo' is already in use".into()
            )),
            ErrorSeverity::Fatal
        );
        assert_eq!(
            classify_error(&ProtoError::IoError("connection reset by peer".into())),
            ErrorSeverity::Retryable
        );
    }

    #[test]
    fn test_error_severity_methods_and_display() {
        assert!(ErrorSeverity::Fatal.is_fatal());
        assert!(!ErrorSeverity::Fatal.is_retryable());
        assert_eq!(ErrorSeverity::Fatal.to_string(), "fatal");

        assert!(ErrorSeverity::Retryable.is_retryable());
        assert!(!ErrorSeverity::Retryable.is_fatal());
        assert_eq!(ErrorSeverity::Retryable.to_string(), "retryable");
    }

    #[test]
    fn test_classify_all_proto_error_variants() {
        // Fatal variants
        assert_eq!(
            classify_error(&ProtoError::AuthFailed("invalid HMAC challenge".into())),
            ErrorSeverity::Fatal
        );
        assert_eq!(
            classify_error(&ProtoError::VersionMismatch {
                client: 1,
                server: 2
            }),
            ErrorSeverity::Fatal
        );
        assert_eq!(
            classify_error(&ProtoError::CapabilityNegotiationFailed(
                "missing resumption".into()
            )),
            ErrorSeverity::Fatal
        );

        // Subdomain & registration conflict protocol errors (Fatal)
        assert_eq!(
            classify_error(&ProtoError::ProtocolError(
                "Subdomain 'myservice' already in use".into()
            )),
            ErrorSeverity::Fatal
        );
        assert_eq!(
            classify_error(&ProtoError::ProtocolError(
                "subdomain 'api' is reserved".into()
            )),
            ErrorSeverity::Fatal
        );
        assert_eq!(
            classify_error(&ProtoError::ProtocolError(
                "subdomain 'test' is already registered".into()
            )),
            ErrorSeverity::Fatal
        );
        assert_eq!(
            classify_error(&ProtoError::ProtocolError(
                "subdomain length must be between 1 and 63 characters".into()
            )),
            ErrorSeverity::Fatal
        );
        assert_eq!(
            classify_error(&ProtoError::ProtocolError(
                "subdomain collision detected on cluster".into()
            )),
            ErrorSeverity::Fatal
        );
        assert_eq!(
            classify_error(&ProtoError::ProtocolError(
                "requested subdomain was taken".into()
            )),
            ErrorSeverity::Fatal
        );
        assert_eq!(
            classify_error(&ProtoError::ProtocolError(
                "Port 8080 already in use".into()
            )),
            ErrorSeverity::Fatal
        );
        assert_eq!(
            classify_error(&ProtoError::ProtocolError(
                "Port 99999 outside allowed range".into()
            )),
            ErrorSeverity::Fatal
        );
        assert_eq!(
            classify_error(&ProtoError::ProtocolError(
                "No available TCP ports in range".into()
            )),
            ErrorSeverity::Fatal
        );
        assert_eq!(
            classify_error(&ProtoError::ProtocolError(
                "unauthorized tunnel registration attempt".into()
            )),
            ErrorSeverity::Fatal
        );
        assert_eq!(
            classify_error(&ProtoError::ProtocolError(
                "authentication failed for user".into()
            )),
            ErrorSeverity::Fatal
        );
        assert_eq!(
            classify_error(&ProtoError::ProtocolError(
                "invalid credentials provided".into()
            )),
            ErrorSeverity::Fatal
        );
        assert_eq!(
            classify_error(&ProtoError::ProtocolError("forbidden operation".into())),
            ErrorSeverity::Fatal
        );
        assert_eq!(
            classify_error(&ProtoError::ProtocolError("AUTH_FAILED".into())),
            ErrorSeverity::Fatal
        );

        // Retryable variants
        assert_eq!(
            classify_error(&ProtoError::IoError("connection timed out".into())),
            ErrorSeverity::Retryable
        );
        assert_eq!(
            classify_error(&ProtoError::IoError("broken pipe".into())),
            ErrorSeverity::Retryable
        );
        assert_eq!(
            classify_error(&ProtoError::ProtocolError(
                "Handshake timed out (5s deadline exceeded)".into()
            )),
            ErrorSeverity::Retryable
        );
        assert_eq!(
            classify_error(&ProtoError::ProtocolError(
                "server sent GOAWAY (error code 0)".into()
            )),
            ErrorSeverity::Retryable
        );
        assert_eq!(
            classify_error(&ProtoError::ProtocolError(
                "expected HELLO_ACK frame, got Ping".into()
            )),
            ErrorSeverity::Retryable
        );
        assert_eq!(
            classify_error(&ProtoError::UnknownType(255)),
            ErrorSeverity::Retryable
        );
        assert_eq!(
            classify_error(&ProtoError::FrameTooLarge(100_000, 16_384)),
            ErrorSeverity::Retryable
        );
        assert_eq!(
            classify_error(&ProtoError::ReservedBitsNonZero),
            ErrorSeverity::Retryable
        );
        assert_eq!(
            classify_error(&ProtoError::StreamIdNotIncreasing(1, 3)),
            ErrorSeverity::Retryable
        );
        assert_eq!(
            classify_error(&ProtoError::InvalidStateTransition {
                current: "Idle",
                frame: "Data",
                next: "Error"
            }),
            ErrorSeverity::Retryable
        );
        assert_eq!(
            classify_error(&ProtoError::FlowControlError {
                sent: 100,
                credit: 50
            }),
            ErrorSeverity::Retryable
        );
        assert_eq!(
            classify_error(&ProtoError::TlvBufferTooShort { need: 4, have: 2 }),
            ErrorSeverity::Retryable
        );
        assert_eq!(
            classify_error(&ProtoError::UnknownTlvTag(99)),
            ErrorSeverity::Retryable
        );
        assert_eq!(
            classify_error(&ProtoError::DuplicateTlvTag(1)),
            ErrorSeverity::Retryable
        );
        assert_eq!(
            classify_error(&ProtoError::MissingRequiredTlv(1)),
            ErrorSeverity::Retryable
        );
        assert_eq!(
            classify_error(&ProtoError::TlvValueTooLong(100, 50)),
            ErrorSeverity::Retryable
        );
    }

    #[test]
    fn test_backoff_policy_exponential_and_jitter() {
        let mut policy =
            BackoffPolicy::new(Duration::from_millis(100), Duration::from_secs(10), Some(3));

        assert_eq!(policy.attempts(), 0);
        let d1 = policy.next_delay().unwrap();
        assert!(d1 >= Duration::from_millis(100) && d1 <= Duration::from_millis(200));

        let d2 = policy.next_delay().unwrap();
        assert!(d2 >= Duration::from_millis(200) && d2 <= Duration::from_millis(400));

        let d3 = policy.next_delay().unwrap();
        assert!(d3 >= Duration::from_millis(400) && d3 <= Duration::from_millis(800));

        // 4th attempt exceeds max_retries = 3
        assert_eq!(policy.next_delay(), None);

        policy.reset();
        assert_eq!(policy.attempts(), 0);
    }

    #[test]
    fn test_backoff_policy_cap_at_max() {
        let mut policy = BackoffPolicy::new(
            Duration::from_millis(500),
            Duration::from_millis(2500),
            None,
        );

        assert_eq!(policy.max(), Duration::from_millis(2500));
        assert_eq!(policy.initial(), Duration::from_millis(500));
        assert_eq!(policy.max_retries(), None);

        for _ in 0..10 {
            let delay = policy.next_delay().unwrap();
            assert!(
                delay <= Duration::from_millis(2500),
                "delay {delay:?} must not exceed cap of 2500ms"
            );
        }

        // At attempt 10, delay must be strictly capped at max
        assert_eq!(policy.attempts(), 10);
        assert_eq!(policy.next_delay(), Some(Duration::from_millis(2500)));
    }

    #[test]
    fn test_backoff_policy_zero_initial() {
        let mut policy = BackoffPolicy::new(Duration::ZERO, Duration::from_secs(5), Some(2));
        assert_eq!(policy.next_delay(), Some(Duration::ZERO));
        assert_eq!(policy.next_delay(), Some(Duration::ZERO));
        assert_eq!(policy.next_delay(), None);
    }

    #[test]
    fn test_backoff_policy_initial_larger_than_max() {
        let mut policy =
            BackoffPolicy::new(Duration::from_secs(10), Duration::from_secs(2), Some(2));
        assert_eq!(policy.next_delay(), Some(Duration::from_secs(2)));
        assert_eq!(policy.next_delay(), Some(Duration::from_secs(2)));
        assert_eq!(policy.next_delay(), None);
    }

    #[test]
    fn test_backoff_policy_max_retries_zero() {
        let mut policy =
            BackoffPolicy::new(Duration::from_millis(100), Duration::from_secs(1), Some(0));
        assert_eq!(policy.next_delay(), None);
        assert_eq!(policy.attempts(), 0);
    }

    #[test]
    fn test_backoff_policy_from_config_and_default() {
        let cfg = ClientConfig::new()
            .with_initial_backoff(Duration::from_millis(300))
            .with_max_backoff(Duration::from_secs(15))
            .with_max_retries(Some(4));

        let policy = BackoffPolicy::from_config(&cfg);
        assert_eq!(policy.initial(), Duration::from_millis(300));
        assert_eq!(policy.max(), Duration::from_secs(15));
        assert_eq!(policy.max_retries(), Some(4));

        let default_policy = BackoffPolicy::default();
        assert_eq!(default_policy.initial(), Duration::from_millis(500));
        assert_eq!(default_policy.max(), Duration::from_secs(30));
        assert_eq!(default_policy.max_retries(), None);
    }

    #[test]
    fn test_backoff_jitter_variance() {
        // Run several samples and verify jitter introduces variation
        let mut samples = Vec::new();
        for _ in 0..20 {
            let mut policy =
                BackoffPolicy::new(Duration::from_millis(100), Duration::from_secs(5), None);
            samples.push(policy.next_delay().unwrap());
        }

        // Verify that not all samples are identical
        let all_identical = samples.windows(2).all(|w| w[0] == w[1]);
        assert!(!all_identical, "Jitter should produce varying delays");
    }
}
