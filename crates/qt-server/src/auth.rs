//! Server authentication and challenge token validation

use rand::RngCore;

use qt_proto::verify_auth_hmac;
use qt_proto::{Result, SessionLimits};

/// Authenticator validating client HMAC challenge responses and generating session credentials
#[derive(Debug, Clone)]
pub struct Authenticator {
    secret: String,
    limits: SessionLimits,
}

impl Authenticator {
    /// Create a new Authenticator with a shared secret and session limits
    pub fn new(secret: impl Into<String>, limits: SessionLimits) -> Self {
        Self {
            secret: secret.into(),
            limits,
        }
    }

    /// Generate a 32-byte cryptographic random challenge nonce
    pub fn generate_challenge(&self) -> [u8; 32] {
        let mut nonce = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce);
        nonce
    }

    /// Verify client AUTH MAC: HMAC-SHA256(secret, nonce || client_id)
    pub fn verify_auth(&self, client_id: &str, nonce: &[u8; 32], mac: &[u8; 32]) -> Result<bool> {
        Ok(verify_auth_hmac(
            self.secret.as_bytes(),
            nonce,
            client_id,
            mac,
        ))
    }

    /// Generate a new session ID and 32-byte resume secret
    pub fn generate_session_credentials(&self) -> (u64, [u8; 32]) {
        let session_id = rand::random::<u64>();
        let mut resume_secret = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut resume_secret);
        (session_id, resume_secret)
    }

    /// Get configured session limits
    pub fn limits(&self) -> &SessionLimits {
        &self.limits
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qt_proto::compute_auth_hmac;

    #[test]
    fn test_authenticator_success() {
        let auth = Authenticator::new("secret-key", SessionLimits::default());
        let nonce = auth.generate_challenge();
        let client_id = "agent-007";
        let valid_mac = compute_auth_hmac(b"secret-key", &nonce, client_id);

        assert!(auth.verify_auth(client_id, &nonce, &valid_mac).unwrap());
    }

    #[test]
    fn test_authenticator_invalid_secret_or_nonce() {
        let auth = Authenticator::new("secret-key", SessionLimits::default());
        let nonce = auth.generate_challenge();
        let wrong_mac = compute_auth_hmac(b"wrong-secret", &nonce, "agent-007");

        assert!(!auth.verify_auth("agent-007", &nonce, &wrong_mac).unwrap());
    }

    #[test]
    fn test_session_credentials_and_limits() {
        let limits = SessionLimits {
            max_streams: 50,
            max_tunnels: 5,
            ..Default::default()
        };
        let auth = Authenticator::new("secret-key", limits);
        assert_eq!(auth.limits().max_streams, 50);
        assert_eq!(auth.limits().max_tunnels, 5);

        let (session_id_1, secret_1) = auth.generate_session_credentials();
        let (session_id_2, secret_2) = auth.generate_session_credentials();

        assert_ne!(session_id_1, session_id_2);
        assert_ne!(secret_1, secret_2);
    }
}
