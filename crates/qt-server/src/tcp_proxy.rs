//! Public TCP visitor edge proxy manager

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::oneshot;

use qt_proto::{ProtoError, Result};

use crate::registry::TunnelRegistry;

/// Manager for dynamic TCP visitor port listeners
#[derive(Clone)]
pub struct TcpProxyManager {
    registry: Arc<TunnelRegistry>,
    listeners: Arc<Mutex<HashMap<u16, oneshot::Sender<()>>>>,
    bind_ip: IpAddr,
}

impl TcpProxyManager {
    /// Create a new TcpProxyManager with default 0.0.0.0 bind address
    pub fn new(registry: Arc<TunnelRegistry>) -> Self {
        Self::with_bind_ip(registry, IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)))
    }

    /// Create a new TcpProxyManager with a specific bind IP
    pub fn with_bind_ip(registry: Arc<TunnelRegistry>, bind_ip: IpAddr) -> Self {
        Self {
            registry,
            listeners: Arc::new(Mutex::new(HashMap::new())),
            bind_ip,
        }
    }

    /// Access the underlying registry
    pub fn registry(&self) -> &Arc<TunnelRegistry> {
        &self.registry
    }

    /// Check if a listener is active on the given port
    pub fn has_listener(&self, port: u16) -> bool {
        self.listeners.lock().contains_key(&port)
    }

    /// Stop an active port listener
    pub fn stop_listener(&self, port: u16) -> bool {
        if let Some(tx) = self.listeners.lock().remove(&port) {
            tx.send(()).is_ok()
        } else {
            false
        }
    }

    /// Stop all active port listeners
    pub fn stop_all(&self) {
        let mut listeners = self.listeners.lock();
        for (_, tx) in listeners.drain() {
            let _ = tx.send(());
        }
    }

    /// Start a dynamic TCP listener on the specified port
    pub async fn start_listener(&self, port: u16) -> Result<oneshot::Sender<()>> {
        {
            let listeners = self.listeners.lock();
            if listeners.contains_key(&port) {
                return Err(ProtoError::ProtocolError(format!(
                    "TCP listener already active on port {port}"
                )));
            }
        }

        let bind_addr = SocketAddr::new(self.bind_ip, port);
        let listener = tokio::net::TcpListener::bind(bind_addr)
            .await
            .map_err(|e| ProtoError::IoError(e.to_string()))?;

        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
        let (external_tx, mut external_rx) = oneshot::channel::<()>();

        let this = self.clone();
        tokio::spawn(async move {
            let mut external_rx_active = true;
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => {
                        break;
                    }
                    res = &mut external_rx, if external_rx_active => {
                        match res {
                            Ok(()) => break,
                            Err(_) => {
                                external_rx_active = false;
                            }
                        }
                    }
                    accept_res = listener.accept() => {
                        match accept_res {
                            Ok((socket, peer_addr)) => {
                                socket.set_nodelay(true).ok();
                                let mgr = this.clone();
                                tokio::spawn(async move {
                                    if let Err(e) = mgr.bridge_tcp(socket, peer_addr, port).await {
                                        tracing::debug!("TCP bridge error on port {port}: {e}");
                                    }
                                });
                            }
                            Err(e) => {
                                tracing::debug!("TCP accept error on port {port}: {e}");
                                break;
                            }
                        }
                    }
                }
            }
            this.listeners.lock().remove(&port);
        });

        self.listeners.lock().insert(port, shutdown_tx);
        Ok(external_tx)
    }

    /// Bridge raw TCP visitor traffic bidirectionally to target QTP stream
    pub async fn bridge_tcp<T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static>(
        &self,
        mut visitor_io: T,
        _peer_addr: SocketAddr,
        port: u16,
    ) -> Result<()> {
        let tunnel = self.registry.find_tcp(port).ok_or_else(|| {
            ProtoError::ProtocolError(format!("No tunnel registered for TCP port {port}"))
        })?;

        let mut mux_stream = tunnel.mux_handle.open_stream().await?;

        tokio::io::copy_bidirectional(&mut visitor_io, &mut mux_stream)
            .await
            .map_err(|e| ProtoError::IoError(e.to_string()))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn test_tcp_proxy_bridge_traffic() {
        let registry = Arc::new(TunnelRegistry::new(20000..=20010, "example.com".into()));
        let manager = TcpProxyManager::new(registry.clone());

        let (mux_client_io, mux_server_io) = tokio::io::duplex(65536);
        let (server_session, server_handle) =
            qt_mux::MuxSession::new(mux_server_io, qt_mux::MuxConfig::server());
        let (client_session, client_handle) =
            qt_mux::MuxSession::new(mux_client_io, qt_mux::MuxConfig::client());
        tokio::spawn(server_session.run());
        tokio::spawn(client_session.run());

        let port = registry
            .register_tcp(1, 10, Some(20005), server_handle)
            .unwrap();

        let (mut visitor_client, visitor_server) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            manager
                .bridge_tcp(visitor_server, "1.2.3.4:9999".parse().unwrap(), port)
                .await
        });

        visitor_client.write_all(b"raw tcp bytes").await.unwrap();

        let mut client_stream = client_handle.accept_stream().await.unwrap();
        let mut buf = [0u8; 13];
        client_stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"raw tcp bytes");

        // Client replies back
        client_stream.write_all(b"echo back").await.unwrap();
        let mut reply = [0u8; 9];
        visitor_client.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"echo back");
    }

    #[tokio::test]
    async fn test_tcp_proxy_unregistered_port_fails() {
        let registry = Arc::new(TunnelRegistry::new(20000..=20010, "example.com".into()));
        let manager = TcpProxyManager::new(registry.clone());

        let (_visitor_client, visitor_server) = tokio::io::duplex(4096);
        let res = manager
            .bridge_tcp(visitor_server, "1.2.3.4:9999".parse().unwrap(), 20005)
            .await;
        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .to_string()
            .contains("No tunnel registered"));
    }

    #[tokio::test]
    async fn test_tcp_proxy_start_stop_listener() {
        let registry = Arc::new(TunnelRegistry::new(20000..=20010, "example.com".into()));
        let manager = TcpProxyManager::with_bind_ip(
            registry.clone(),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        );

        // Find free ephemeral port
        let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);

        let stop_tx = manager.start_listener(port).await.unwrap();
        assert!(manager.has_listener(port));

        // Duplicate start fails
        assert!(manager.start_listener(port).await.is_err());

        // Connect probe
        let client = tokio::net::TcpStream::connect(("127.0.0.1", port)).await;
        assert!(client.is_ok());

        // Stop listener via stop_tx
        let _ = stop_tx.send(());
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!manager.has_listener(port));

        // Test stop_all and manager accessors
        assert_eq!(manager.registry().root_domain(), "example.com");
        assert!(!manager.stop_listener(9999));
        manager.stop_all();
    }

    #[tokio::test]
    async fn test_tcp_proxy_listener_accepts_and_bridges() {
        // Find free ephemeral port
        let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);

        let registry = Arc::new(TunnelRegistry::new(port..=port + 10, "example.com".into()));
        let manager = TcpProxyManager::with_bind_ip(
            registry.clone(),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        );

        // Set up MuxSession
        let (mux_client_io, mux_server_io) = tokio::io::duplex(65536);
        let (server_session, server_handle) =
            qt_mux::MuxSession::new(mux_server_io, qt_mux::MuxConfig::server());
        let (client_session, client_handle) =
            qt_mux::MuxSession::new(mux_client_io, qt_mux::MuxConfig::client());
        tokio::spawn(server_session.run());
        tokio::spawn(client_session.run());

        // Register TCP tunnel in registry
        registry
            .register_tcp(1, 10, Some(port), server_handle)
            .unwrap();

        let stop_tx = manager.start_listener(port).await.unwrap();

        // Visitor connects via real TCP
        let mut visitor_socket = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        visitor_socket
            .write_all(b"hello from tcp visitor")
            .await
            .unwrap();

        // Client accepts the forwarded stream
        let mut client_stream = client_handle.accept_stream().await.unwrap();
        let mut buf = [0u8; 22];
        client_stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello from tcp visitor");

        client_stream.write_all(b"ack visitor").await.unwrap();
        let mut reply = [0u8; 11];
        visitor_socket.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"ack visitor");

        let _ = stop_tx.send(());
    }
}
