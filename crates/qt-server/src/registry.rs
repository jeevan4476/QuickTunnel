//! Multi-tenant tunnel registry and route allocator

use std::collections::HashMap;
use std::ops::RangeInclusive;

use parking_lot::RwLock;
use rand::Rng;

use qt_mux::MuxHandle;
use qt_proto::{ProtoError, Result};

/// Blacklist of reserved subdomains
pub const RESERVED_SUBDOMAINS: &[&str] = &[
    "www",
    "api",
    "admin",
    "static",
    "assets",
    "mail",
    "smtp",
    "pop",
    "imap",
    "ftp",
    "ssh",
    "ns",
    "ns1",
    "ns2",
    "dns",
    "gateway",
    "internal",
    "local",
    "localhost",
    "autodiscover",
    "cpanel",
    "webmail",
    "proxy",
    "vpn",
    "dashboard",
    "status",
    "billing",
    "app",
    "auth",
    "login",
    "register",
];

/// Validate that a requested subdomain meets RFC 1035 format and is not reserved
pub fn validate_subdomain(subdomain: &str) -> Result<()> {
    if subdomain.is_empty() || subdomain.len() > 63 {
        return Err(ProtoError::ProtocolError(
            "subdomain length must be between 1 and 63 characters".into(),
        ));
    }

    let bytes = subdomain.as_bytes();
    let first = bytes[0];
    let last = bytes[bytes.len() - 1];

    if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
        return Err(ProtoError::ProtocolError(
            "subdomain must start with a lowercase alphanumeric character".into(),
        ));
    }
    if !last.is_ascii_lowercase() && !last.is_ascii_digit() {
        return Err(ProtoError::ProtocolError(
            "subdomain must end with a lowercase alphanumeric character".into(),
        ));
    }

    if bytes.len() > 2 {
        for &b in &bytes[1..bytes.len() - 1] {
            if !b.is_ascii_lowercase() && !b.is_ascii_digit() && b != b'-' {
                return Err(ProtoError::ProtocolError(
                    "subdomain contains invalid character; only [a-z0-9-] allowed".into(),
                ));
            }
        }
    }

    if is_reserved_subdomain(subdomain) {
        return Err(ProtoError::ProtocolError(format!(
            "subdomain '{subdomain}' is reserved"
        )));
    }

    Ok(())
}

/// Check if a subdomain is reserved
pub fn is_reserved_subdomain(subdomain: &str) -> bool {
    RESERVED_SUBDOMAINS.contains(&subdomain)
}

/// Tunnel routing destination
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunnelRoute {
    Http { subdomain: String },
    Tcp { port: u16 },
}

/// Active registered tunnel entry
#[derive(Clone)]
pub struct TunnelEntry {
    pub session_id: u64,
    pub tunnel_id: u32,
    pub route: TunnelRoute,
    pub mux_handle: MuxHandle,
}

enum RouteKey {
    Http(String),
    Tcp(u16),
}

#[derive(Default)]
struct RegistryInner {
    http_routes: HashMap<String, TunnelEntry>,
    tcp_routes: HashMap<u16, TunnelEntry>,
    session_routes: HashMap<u64, Vec<RouteKey>>,
}

/// Multi-tenant registry tracking active public HTTP subdomains and TCP port listeners
pub struct TunnelRegistry {
    tcp_port_range: RangeInclusive<u16>,
    root_domain: String,
    inner: RwLock<RegistryInner>,
}

impl TunnelRegistry {
    /// Create a new tunnel registry with given TCP port range and root domain
    pub fn new(tcp_port_range: RangeInclusive<u16>, root_domain: String) -> Self {
        Self {
            tcp_port_range,
            root_domain,
            inner: RwLock::new(RegistryInner::default()),
        }
    }

    /// Root domain configured on the server
    pub fn root_domain(&self) -> &str {
        &self.root_domain
    }

    /// Configured TCP port range
    pub fn tcp_port_range(&self) -> &RangeInclusive<u16> {
        &self.tcp_port_range
    }

    /// Register an HTTP tunnel for a session. Returns `(subdomain, public_url)`.
    pub fn register_http(
        &self,
        session_id: u64,
        tunnel_id: u32,
        requested_subdomain: Option<&str>,
        mux_handle: MuxHandle,
    ) -> Result<(String, String)> {
        let mut inner = self.inner.write();

        let subdomain = match requested_subdomain {
            Some(sub) => {
                validate_subdomain(sub)?;
                if inner.http_routes.contains_key(sub) {
                    return Err(ProtoError::ProtocolError(format!(
                        "subdomain '{sub}' is already registered"
                    )));
                }
                sub.to_string()
            }
            None => {
                // Generate a random 8-character subdomain
                let mut attempts = 0;
                loop {
                    attempts += 1;
                    if attempts > 100 {
                        return Err(ProtoError::ProtocolError(
                            "failed to allocate an available random subdomain".into(),
                        ));
                    }
                    let candidate = generate_random_subdomain(8);
                    if !is_reserved_subdomain(&candidate)
                        && !inner.http_routes.contains_key(&candidate)
                    {
                        break candidate;
                    }
                }
            }
        };

        let public_url = format!("https://{}.{}", subdomain, self.root_domain);
        let entry = TunnelEntry {
            session_id,
            tunnel_id,
            route: TunnelRoute::Http {
                subdomain: subdomain.clone(),
            },
            mux_handle,
        };

        inner.http_routes.insert(subdomain.clone(), entry);
        inner
            .session_routes
            .entry(session_id)
            .or_default()
            .push(RouteKey::Http(subdomain.clone()));

        Ok((subdomain, public_url))
    }

    /// Register a TCP tunnel for a session. Returns the allocated port.
    pub fn register_tcp(
        &self,
        session_id: u64,
        tunnel_id: u32,
        requested_port: Option<u16>,
        mux_handle: MuxHandle,
    ) -> Result<u16> {
        let mut inner = self.inner.write();

        let port = match requested_port {
            Some(port) => {
                if !self.tcp_port_range.contains(&port) {
                    return Err(ProtoError::ProtocolError(format!(
                        "requested port {port} is outside allowed range {}..={}",
                        self.tcp_port_range.start(),
                        self.tcp_port_range.end()
                    )));
                }
                if inner.tcp_routes.contains_key(&port) {
                    return Err(ProtoError::ProtocolError(format!(
                        "TCP port {port} is already in use"
                    )));
                }
                port
            }
            None => {
                let mut selected = None;
                for p in self.tcp_port_range.clone() {
                    if !inner.tcp_routes.contains_key(&p) {
                        selected = Some(p);
                        break;
                    }
                }
                selected.ok_or_else(|| {
                    ProtoError::ProtocolError("no available TCP ports in range".into())
                })?
            }
        };

        let entry = TunnelEntry {
            session_id,
            tunnel_id,
            route: TunnelRoute::Tcp { port },
            mux_handle,
        };

        inner.tcp_routes.insert(port, entry);
        inner
            .session_routes
            .entry(session_id)
            .or_default()
            .push(RouteKey::Tcp(port));

        Ok(port)
    }

    /// Look up an HTTP tunnel entry by subdomain
    pub fn find_http(&self, subdomain: &str) -> Option<TunnelEntry> {
        self.inner.read().http_routes.get(subdomain).cloned()
    }

    /// Return the single active HTTP tunnel if exactly one exists (fallback for direct IP access)
    pub fn find_single_http(&self) -> Option<TunnelEntry> {
        let inner = self.inner.read();
        if inner.http_routes.len() == 1 {
            inner.http_routes.values().next().cloned()
        } else {
            None
        }
    }

    /// Look up a TCP tunnel entry by port
    pub fn find_tcp(&self, port: u16) -> Option<TunnelEntry> {
        self.inner.read().tcp_routes.get(&port).cloned()
    }

    /// Unbind and remove all tunnels associated with a session
    pub fn remove_session(&self, session_id: u64) {
        let mut inner = self.inner.write();
        if let Some(routes) = inner.session_routes.remove(&session_id) {
            for route in routes {
                match route {
                    RouteKey::Http(sub) => {
                        inner.http_routes.remove(&sub);
                    }
                    RouteKey::Tcp(port) => {
                        inner.tcp_routes.remove(&port);
                    }
                }
            }
        }
    }

    /// Number of active tunnels across HTTP and TCP
    pub fn count(&self) -> usize {
        let inner = self.inner.read();
        inner.http_routes.len() + inner.tcp_routes.len()
    }
}

fn generate_random_subdomain(len: usize) -> String {
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subdomain_validation() {
        assert!(validate_subdomain("myapp").is_ok());
        assert!(validate_subdomain("my-app-123").is_ok());
        assert!(validate_subdomain("a").is_ok());
        assert!(validate_subdomain("").is_err());
        assert!(validate_subdomain("-invalid").is_err());
        assert!(validate_subdomain("invalid-").is_err());
        assert!(validate_subdomain("inv@lid").is_err());
        assert!(validate_subdomain("api").is_err()); // reserved
        assert!(validate_subdomain("www").is_err()); // reserved
        let too_long = "a".repeat(64);
        assert!(validate_subdomain(&too_long).is_err());
    }

    #[tokio::test]
    async fn test_register_and_lookup_http() {
        let registry = TunnelRegistry::new(20000..=20100, "tunnel.example.com".into());
        let (dummy_io, _) = tokio::io::duplex(1024);
        let (_, handle) = qt_mux::MuxSession::new(dummy_io, qt_mux::MuxConfig::server());

        let (sub, url) = registry
            .register_http(1, 10, Some("mytest"), handle.clone())
            .unwrap();
        assert_eq!(sub, "mytest");
        assert_eq!(url, "https://mytest.tunnel.example.com");

        let entry = registry.find_http("mytest").unwrap();
        assert_eq!(entry.session_id, 1);
        assert_eq!(entry.tunnel_id, 10);
        assert_eq!(
            entry.route,
            TunnelRoute::Http {
                subdomain: "mytest".into()
            }
        );

        // Duplicate registration fails
        assert!(registry
            .register_http(2, 20, Some("mytest"), handle.clone())
            .is_err());

        // Session removal unbinds route
        registry.remove_session(1);
        assert!(registry.find_http("mytest").is_none());
    }

    #[tokio::test]
    async fn test_register_http_random() {
        let registry = TunnelRegistry::new(20000..=20100, "tunnel.example.com".into());
        let (dummy_io, _) = tokio::io::duplex(1024);
        let (_, handle) = qt_mux::MuxSession::new(dummy_io, qt_mux::MuxConfig::server());

        let (sub, url) = registry.register_http(1, 10, None, handle).unwrap();
        assert_eq!(sub.len(), 8);
        assert!(url.starts_with("https://"));
        assert!(registry.find_http(&sub).is_some());
        assert_eq!(registry.count(), 1);
    }

    #[tokio::test]
    async fn test_register_and_lookup_tcp() {
        let registry = TunnelRegistry::new(20000..=20002, "tunnel.example.com".into());
        let (dummy_io, _) = tokio::io::duplex(1024);
        let (_, handle) = qt_mux::MuxSession::new(dummy_io, qt_mux::MuxConfig::server());

        let port = registry.register_tcp(1, 10, None, handle.clone()).unwrap();
        assert!((20000..=20002).contains(&port));

        let entry = registry.find_tcp(port).unwrap();
        assert_eq!(entry.session_id, 1);
        assert_eq!(entry.route, TunnelRoute::Tcp { port });

        // Test requested port in range
        let port2 = registry
            .register_tcp(1, 11, Some(20001), handle.clone())
            .unwrap();
        assert_eq!(port2, 20001);

        // Test duplicate port fails
        assert!(registry
            .register_tcp(2, 12, Some(20001), handle.clone())
            .is_err());

        // Test port out of range fails
        assert!(registry
            .register_tcp(1, 13, Some(30000), handle.clone())
            .is_err());

        registry.remove_session(1);
        assert!(registry.find_tcp(port).is_none());
        assert!(registry.find_tcp(port2).is_none());
    }

    #[tokio::test]
    async fn test_register_tcp_exhaustion() {
        let registry = TunnelRegistry::new(20000..=20001, "tunnel.example.com".into());
        let (dummy_io, _) = tokio::io::duplex(1024);
        let (_, handle) = qt_mux::MuxSession::new(dummy_io, qt_mux::MuxConfig::server());

        let p1 = registry.register_tcp(1, 10, None, handle.clone()).unwrap();
        let p2 = registry.register_tcp(1, 11, None, handle.clone()).unwrap();
        assert_ne!(p1, p2);

        // Third allocation must fail (exhausted)
        assert!(registry.register_tcp(1, 12, None, handle).is_err());
    }

    #[test]
    fn test_registry_accessors() {
        let registry = TunnelRegistry::new(1000..=2000, "example.com".into());
        assert_eq!(registry.root_domain(), "example.com");
        assert_eq!(registry.tcp_port_range(), &(1000..=2000));
        assert_eq!(registry.count(), 0);
    }
}
