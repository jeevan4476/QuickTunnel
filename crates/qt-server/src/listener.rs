//! Server listener wrapper

use std::sync::Arc;

use qt_proto::Result;

use crate::auth::Authenticator;
use crate::config::ServerConfig;
use crate::control::ControlListener;
use crate::registry::TunnelRegistry;

/// High-level server listener wrapping ControlListener
#[derive(Clone)]
pub struct ServerListener {
    inner: ControlListener,
}

impl ServerListener {
    /// Create a new ServerListener from ServerConfig
    pub fn new(config: &ServerConfig) -> Self {
        let auth = Arc::new(Authenticator::new(&config.secret, config.limits));
        let registry = Arc::new(TunnelRegistry::new(
            config.tcp_port_range.clone(),
            config.root_domain.clone(),
        ));
        let inner = ControlListener::new(config.control_bind, auth, registry);
        Self { inner }
    }

    /// Access underlying ControlListener
    pub fn inner(&self) -> &ControlListener {
        &self.inner
    }

    /// Run listener loop
    pub async fn run(&self) -> Result<()> {
        self.inner.run().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_server_listener_creation_and_run() {
        let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = probe.local_addr().unwrap();
        drop(probe);

        let config = ServerConfig::default().with_control_bind(port);
        let listener = ServerListener::new(&config);
        assert_eq!(listener.inner().bind_addr(), port);

        let listener_clone = listener.clone();
        let run_task = tokio::spawn(async move { listener_clone.run().await });

        tokio::time::sleep(Duration::from_millis(50)).await;
        let client = tokio::net::TcpStream::connect(port).await;
        assert!(client.is_ok());

        run_task.abort();
    }
}
