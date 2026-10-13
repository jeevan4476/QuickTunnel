//! Server orchestrator daemon

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tokio::sync::Notify;

use qt_proto::Result;

use crate::auth::Authenticator;
use crate::config::ServerConfig;
use crate::control::ControlListener;
use crate::http_proxy::HttpProxy;
use crate::registry::TunnelRegistry;
use crate::tcp_proxy::TcpProxyManager;

/// QuickTunnel server orchestrator daemon managing control plane and visitor proxies
pub struct Server {
    config: ServerConfig,
    registry: Arc<TunnelRegistry>,
    authenticator: Arc<Authenticator>,
    control_listener: ControlListener,
    http_proxy: HttpProxy,
    tcp_proxy: TcpProxyManager,
    shutdown_notify: Arc<Notify>,
    is_shutdown: Arc<AtomicBool>,
}

impl Server {
    /// Create a new Server from the configuration
    pub fn new(config: ServerConfig) -> Self {
        let registry = Arc::new(TunnelRegistry::new(
            config.tcp_port_range.clone(),
            config.root_domain.clone(),
        ));
        let authenticator = Arc::new(Authenticator::new(&config.secret, config.limits));
        let tcp_proxy = TcpProxyManager::new(registry.clone());
        let control_listener =
            ControlListener::new(config.control_bind, authenticator.clone(), registry.clone())
                .with_tcp_proxy(tcp_proxy.clone());
        let http_proxy = HttpProxy::new(
            config.http_bind,
            registry.clone(),
            config.root_domain.clone(),
        );
        let shutdown_notify = Arc::new(Notify::new());
        let is_shutdown = Arc::new(AtomicBool::new(false));

        Self {
            config,
            registry,
            authenticator,
            control_listener,
            http_proxy,
            tcp_proxy,
            shutdown_notify,
            is_shutdown,
        }
    }

    /// Access configuration
    pub fn config(&self) -> &ServerConfig {
        &self.config
    }

    /// Access registry
    pub fn registry(&self) -> &Arc<TunnelRegistry> {
        &self.registry
    }

    /// Access authenticator
    pub fn authenticator(&self) -> &Arc<Authenticator> {
        &self.authenticator
    }

    /// Access control listener
    pub fn control_listener(&self) -> &ControlListener {
        &self.control_listener
    }

    /// Access HTTP edge proxy
    pub fn http_proxy(&self) -> &HttpProxy {
        &self.http_proxy
    }

    /// Access TCP proxy manager
    pub fn tcp_proxy(&self) -> &TcpProxyManager {
        &self.tcp_proxy
    }

    /// Check if server has initiated shutdown
    pub fn is_shutdown(&self) -> bool {
        self.is_shutdown.load(Ordering::Acquire)
    }

    /// Initiate graceful shutdown of all listeners
    pub fn shutdown(&self) {
        self.is_shutdown.store(true, Ordering::Release);
        self.tcp_proxy.stop_all();
        self.shutdown_notify.notify_waiters();
    }

    /// Run all server listeners until shutdown signal or error
    pub async fn run(&self) -> Result<()> {
        let ctrl_fut = self.control_listener.run();
        let http_fut = self.http_proxy.run();

        tokio::select! {
            res = ctrl_fut => res,
            res = http_fut => res,
            _ = self.shutdown_notify.notified() => {
                self.tcp_proxy.stop_all();
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_server_orchestrator_initialization_and_shutdown() {
        let config = ServerConfig {
            secret: "test-secret".into(),
            root_domain: "tunnel.local".into(),
            ..Default::default()
        };
        let server = Server::new(config.clone());

        assert_eq!(server.config().root_domain, "tunnel.local");
        assert_eq!(server.registry().root_domain(), "tunnel.local");
        assert_eq!(server.authenticator().limits().max_streams, 256);
        assert_eq!(server.control_listener().bind_addr(), config.control_bind);
        assert_eq!(server.http_proxy().bind_addr(), config.http_bind);
        assert_eq!(server.tcp_proxy().registry().root_domain(), "tunnel.local");
        assert!(!server.is_shutdown());

        server.shutdown();
        assert!(server.is_shutdown());
    }

    #[tokio::test]
    async fn test_server_run_and_shutdown_signal() {
        // Find 2 ephemeral ports for control and http
        let l1 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let p1 = l1.local_addr().unwrap();
        drop(l1);

        let l2 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let p2 = l2.local_addr().unwrap();
        drop(l2);

        let config = ServerConfig::new()
            .with_control_bind(p1)
            .with_http_bind(p2)
            .with_root_domain("test.local")
            .with_secret("my-sec");

        let server = Arc::new(Server::new(config));
        let server_clone = server.clone();

        let run_task = tokio::spawn(async move { server_clone.run().await });

        // Let listeners bind
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Verify listeners accept TCP probe
        let c1 = tokio::net::TcpStream::connect(p1).await;
        assert!(c1.is_ok());

        let c2 = tokio::net::TcpStream::connect(p2).await;
        assert!(c2.is_ok());

        // Signal shutdown
        server.shutdown();

        let res = run_task.await.unwrap();
        assert!(res.is_ok());
        assert!(server.is_shutdown());
    }
}
