//! Client configuration and host header policy.

use std::borrow::Cow;
use std::fmt;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;

use qt_proto::TunnelMode;

/// Host header rewrite policy for HTTP tunnels.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum HostHeaderRewrite {
    /// Rewrite `Host` header to match `local_target` (e.g. `127.0.0.1:3000`).
    #[default]
    Rewrite,
    /// Preserve incoming visitor `Host` header unchanged.
    Preserve,
    /// Override `Host` header with a custom value.
    Custom(String),
}

impl fmt::Display for HostHeaderRewrite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rewrite => write!(f, "rewrite"),
            Self::Preserve => write!(f, "preserve"),
            Self::Custom(custom) => write!(f, "{custom}"),
        }
    }
}

impl FromStr for HostHeaderRewrite {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "rewrite" => Ok(Self::Rewrite),
            "preserve" => Ok(Self::Preserve),
            _ => Ok(Self::Custom(s.to_string())),
        }
    }
}

impl HostHeaderRewrite {
    /// Compute the replacement Host header value, or `None` if preserving the original.
    pub fn resolve_host<'a>(&'a self, local_target: &SocketAddr) -> Option<Cow<'a, str>> {
        match self {
            Self::Rewrite => Some(Cow::Owned(local_target.to_string())),
            Self::Preserve => None,
            Self::Custom(custom) => Some(Cow::Borrowed(custom.as_str())),
        }
    }
}

/// QuickTunnel client configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientConfig {
    /// QuickTunnel server control plane address (e.g. 127.0.0.1:7000).
    pub server_addr: SocketAddr,
    /// Local service target address (e.g. 127.0.0.1:3000).
    pub local_target: SocketAddr,
    /// Tunnel protocol mode (HTTP or raw TCP).
    pub mode: TunnelMode,
    /// Desired subdomain name for HTTP mode (None = server assigned random subdomain).
    pub subdomain: Option<String>,
    /// Desired remote TCP port for TCP mode (None = server assigned random port).
    pub remote_port: Option<u16>,
    /// Shared authentication secret token.
    pub secret: String,
    /// Unique client identifier for authentication challenge response.
    pub client_id: String,
    /// HTTP Host header rewrite policy.
    pub host_header: HostHeaderRewrite,
    /// Maximum reconnection attempts before aborting (None = infinite retries).
    pub max_retries: Option<u32>,
    /// Initial backoff delay for reconnect attempts.
    pub initial_backoff: Duration,
    /// Maximum backoff delay cap for reconnect attempts.
    pub max_backoff: Duration,
}

impl Default for ClientConfig {
    fn default() -> Self {
        ClientConfig {
            server_addr: SocketAddr::from(([127, 0, 0, 1], 7000)),
            local_target: SocketAddr::from(([127, 0, 0, 1], 3000)),
            mode: TunnelMode::Http,
            subdomain: None,
            remote_port: None,
            secret: String::new(),
            client_id: String::new(),
            host_header: HostHeaderRewrite::Rewrite,
            max_retries: None,
            initial_backoff: Duration::from_millis(500),
            max_backoff: Duration::from_secs(30),
        }
    }
}

impl ClientConfig {
    /// Create a new `ClientConfig` builder initialized with standard defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set server control plane address.
    pub fn with_server_addr(mut self, addr: SocketAddr) -> Self {
        self.server_addr = addr;
        self
    }

    /// Set local target service address.
    pub fn with_local_target(mut self, addr: SocketAddr) -> Self {
        self.local_target = addr;
        self
    }

    /// Set tunnel mode (`TunnelMode::Http` or `TunnelMode::Tcp`).
    pub fn with_mode(mut self, mode: TunnelMode) -> Self {
        self.mode = mode;
        self
    }

    /// Set requested subdomain name (HTTP mode).
    pub fn with_subdomain(mut self, subdomain: impl Into<String>) -> Self {
        self.subdomain = Some(subdomain.into());
        self
    }

    /// Set optional subdomain name (HTTP mode).
    pub fn with_optional_subdomain(mut self, subdomain: Option<String>) -> Self {
        self.subdomain = subdomain;
        self
    }

    /// Set requested remote port (TCP mode).
    pub fn with_remote_port(mut self, port: u16) -> Self {
        self.remote_port = Some(port);
        self
    }

    /// Set optional remote port (TCP mode).
    pub fn with_optional_remote_port(mut self, port: Option<u16>) -> Self {
        self.remote_port = port;
        self
    }

    /// Set authentication secret.
    pub fn with_secret(mut self, secret: impl Into<String>) -> Self {
        self.secret = secret.into();
        self
    }

    /// Set client ID.
    pub fn with_client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = client_id.into();
        self
    }

    /// Set Host header rewrite policy.
    pub fn with_host_header(mut self, host_header: HostHeaderRewrite) -> Self {
        self.host_header = host_header;
        self
    }

    /// Set maximum reconnection attempts.
    pub fn with_max_retries(mut self, max_retries: Option<u32>) -> Self {
        self.max_retries = max_retries;
        self
    }

    /// Set initial reconnection backoff duration.
    pub fn with_initial_backoff(mut self, backoff: Duration) -> Self {
        self.initial_backoff = backoff;
        self
    }

    /// Set maximum reconnection backoff duration.
    pub fn with_max_backoff(mut self, backoff: Duration) -> Self {
        self.max_backoff = backoff;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_config_defaults() {
        let config = ClientConfig::default();
        assert_eq!(config.server_addr, "127.0.0.1:7000".parse().unwrap());
        assert_eq!(config.local_target, "127.0.0.1:3000".parse().unwrap());
        assert_eq!(config.mode, TunnelMode::Http);
        assert_eq!(config.host_header, HostHeaderRewrite::Rewrite);
        assert!(config.subdomain.is_none());
        assert!(config.remote_port.is_none());
        assert_eq!(config.secret, "");
        assert_eq!(config.client_id, "");
        assert_eq!(config.max_retries, None);
        assert_eq!(config.initial_backoff, Duration::from_millis(500));
        assert_eq!(config.max_backoff, Duration::from_secs(30));
    }

    #[test]
    fn test_client_config_builder() {
        let config = ClientConfig::new()
            .with_server_addr("192.168.1.100:7000".parse().unwrap())
            .with_local_target("127.0.0.1:8080".parse().unwrap())
            .with_mode(TunnelMode::Tcp)
            .with_remote_port(20431)
            .with_subdomain("my-app")
            .with_secret("test-token")
            .with_client_id("agent-42")
            .with_host_header(HostHeaderRewrite::Custom("custom.local".into()))
            .with_max_retries(Some(5))
            .with_initial_backoff(Duration::from_millis(250))
            .with_max_backoff(Duration::from_secs(10));

        assert_eq!(config.server_addr, "192.168.1.100:7000".parse().unwrap());
        assert_eq!(config.local_target, "127.0.0.1:8080".parse().unwrap());
        assert_eq!(config.mode, TunnelMode::Tcp);
        assert_eq!(config.remote_port, Some(20431));
        assert_eq!(config.subdomain, Some("my-app".into()));
        assert_eq!(config.secret, "test-token");
        assert_eq!(config.client_id, "agent-42");
        assert_eq!(
            config.host_header,
            HostHeaderRewrite::Custom("custom.local".into())
        );
        assert_eq!(config.max_retries, Some(5));
        assert_eq!(config.initial_backoff, Duration::from_millis(250));
        assert_eq!(config.max_backoff, Duration::from_secs(10));
    }

    #[test]
    fn test_client_config_optional_setters_and_clone() {
        let config = ClientConfig::default()
            .with_optional_subdomain(Some("sub".into()))
            .with_optional_remote_port(Some(8081));

        let cloned = config.clone();
        assert_eq!(config, cloned);
        assert_eq!(cloned.subdomain, Some("sub".into()));
        assert_eq!(cloned.remote_port, Some(8081));

        let reset = cloned
            .with_optional_subdomain(None)
            .with_optional_remote_port(None);
        assert!(reset.subdomain.is_none());
        assert!(reset.remote_port.is_none());
    }

    #[test]
    fn test_host_header_rewrite_display_and_from_str() {
        assert_eq!(HostHeaderRewrite::default(), HostHeaderRewrite::Rewrite);

        assert_eq!(HostHeaderRewrite::Rewrite.to_string(), "rewrite");
        assert_eq!(HostHeaderRewrite::Preserve.to_string(), "preserve");
        assert_eq!(
            HostHeaderRewrite::Custom("api.internal".into()).to_string(),
            "api.internal"
        );

        assert_eq!(
            "rewrite".parse::<HostHeaderRewrite>().unwrap(),
            HostHeaderRewrite::Rewrite
        );
        assert_eq!(
            "REWRITE".parse::<HostHeaderRewrite>().unwrap(),
            HostHeaderRewrite::Rewrite
        );
        assert_eq!(
            "preserve".parse::<HostHeaderRewrite>().unwrap(),
            HostHeaderRewrite::Preserve
        );
        assert_eq!(
            "PRESERVE".parse::<HostHeaderRewrite>().unwrap(),
            HostHeaderRewrite::Preserve
        );
        assert_eq!(
            "myhost.local".parse::<HostHeaderRewrite>().unwrap(),
            HostHeaderRewrite::Custom("myhost.local".into())
        );
    }

    #[test]
    fn test_host_header_rewrite_resolve() {
        let target: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        assert_eq!(
            HostHeaderRewrite::Rewrite.resolve_host(&target),
            Some(Cow::Owned("127.0.0.1:8080".to_string()))
        );
        assert_eq!(HostHeaderRewrite::Preserve.resolve_host(&target), None);
        assert_eq!(
            HostHeaderRewrite::Custom("example.com".into()).resolve_host(&target),
            Some(Cow::Borrowed("example.com"))
        );
    }
}
