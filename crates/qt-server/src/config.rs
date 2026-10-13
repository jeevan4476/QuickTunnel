//! Server configuration

use std::net::SocketAddr;
use std::ops::RangeInclusive;

use qt_proto::SessionLimits;

/// Global configuration for QuickTunnel server
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Control plane listen address (e.g. 0.0.0.0:7000)
    pub control_bind: SocketAddr,
    /// Public HTTP visitor listen address (e.g. 0.0.0.0:8080)
    pub http_bind: SocketAddr,
    /// TCP tunnel port range (e.g. 20000..=29999)
    pub tcp_port_range: RangeInclusive<u16>,
    /// Root domain for HTTP subdomains (e.g. tunnel.local)
    pub root_domain: String,
    /// Shared authentication secret
    pub secret: String,
    /// Session limits
    pub limits: SessionLimits,
    /// Optional TLS certificate path
    pub tls_cert: Option<String>,
    /// Optional TLS private key path
    pub tls_key: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            control_bind: "0.0.0.0:7000".parse().unwrap(),
            http_bind: "0.0.0.0:8080".parse().unwrap(),
            tcp_port_range: 20000..=29999,
            root_domain: "tunnel.local".into(),
            secret: String::new(),
            limits: SessionLimits::default(),
            tls_cert: None,
            tls_key: None,
        }
    }
}

impl ServerConfig {
    /// Create a new ServerConfig builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Set control plane bind address
    pub fn with_control_bind(mut self, addr: SocketAddr) -> Self {
        self.control_bind = addr;
        self
    }

    /// Set public HTTP bind address
    pub fn with_http_bind(mut self, addr: SocketAddr) -> Self {
        self.http_bind = addr;
        self
    }

    /// Set TCP port allocation range
    pub fn with_tcp_port_range(mut self, range: RangeInclusive<u16>) -> Self {
        self.tcp_port_range = range;
        self
    }

    /// Set root domain
    pub fn with_root_domain(mut self, domain: impl Into<String>) -> Self {
        self.root_domain = domain.into();
        self
    }

    /// Set secret token
    pub fn with_secret(mut self, secret: impl Into<String>) -> Self {
        self.secret = secret.into();
        self
    }

    /// Set session limits
    pub fn with_limits(mut self, limits: SessionLimits) -> Self {
        self.limits = limits;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_config_defaults_and_builder() {
        let default_cfg = ServerConfig::default();
        assert_eq!(default_cfg.control_bind, "0.0.0.0:7000".parse().unwrap());
        assert_eq!(default_cfg.http_bind, "0.0.0.0:8080".parse().unwrap());
        assert_eq!(default_cfg.root_domain, "tunnel.local");
        assert_eq!(default_cfg.tcp_port_range, 20000..=29999);

        let custom = ServerConfig::new()
            .with_control_bind("127.0.0.1:9000".parse().unwrap())
            .with_http_bind("127.0.0.1:9080".parse().unwrap())
            .with_tcp_port_range(30000..=31000)
            .with_root_domain("quicktunnel.io")
            .with_secret("my-super-secret")
            .with_limits(SessionLimits {
                max_streams: 100,
                ..Default::default()
            });

        assert_eq!(custom.control_bind, "127.0.0.1:9000".parse().unwrap());
        assert_eq!(custom.http_bind, "127.0.0.1:9080".parse().unwrap());
        assert_eq!(custom.tcp_port_range, 30000..=31000);
        assert_eq!(custom.root_domain, "quicktunnel.io");
        assert_eq!(custom.secret, "my-super-secret");
        assert_eq!(custom.limits.max_streams, 100);
    }
}
