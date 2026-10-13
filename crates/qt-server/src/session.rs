//! Server tunnel session

use qt_mux::MuxHandle;

use crate::registry::{TunnelEntry, TunnelRoute};

/// Server session representing an active registered tunnel
#[derive(Clone)]
pub struct ServerSession {
    entry: TunnelEntry,
}

impl ServerSession {
    /// Create a new ServerSession from a TunnelEntry
    pub fn new(entry: TunnelEntry) -> Self {
        Self { entry }
    }

    /// Session ID
    pub fn session_id(&self) -> u64 {
        self.entry.session_id
    }

    /// Tunnel ID
    pub fn tunnel_id(&self) -> u32 {
        self.entry.tunnel_id
    }

    /// Assigned route
    pub fn route(&self) -> &TunnelRoute {
        &self.entry.route
    }

    /// Mux handle to open streams
    pub fn mux_handle(&self) -> &MuxHandle {
        &self.entry.mux_handle
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_server_session_accessors() {
        let (io, _) = tokio::io::duplex(1024);
        let (_, handle) = qt_mux::MuxSession::new(io, qt_mux::MuxConfig::server());
        let entry = TunnelEntry {
            session_id: 42,
            tunnel_id: 1,
            route: TunnelRoute::Http {
                subdomain: "app".into(),
            },
            mux_handle: handle,
        };

        let session = ServerSession::new(entry);
        assert_eq!(session.session_id(), 42);
        assert_eq!(session.tunnel_id(), 1);
        assert_eq!(
            session.route(),
            &TunnelRoute::Http {
                subdomain: "app".into()
            }
        );
        let _handle = session.mux_handle();
    }
}
