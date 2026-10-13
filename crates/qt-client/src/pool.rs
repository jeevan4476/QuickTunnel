//! Warm TCP connection pool for local origin service (§12.2 / Improvement 1)

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use qt_proto::{ProtoError, Result};
use tokio::net::TcpStream;

/// Default maximum idle connections kept warm in pool
pub const DEFAULT_MAX_IDLE: usize = 64;

/// Default idle connection timeout (30 seconds)
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Check if a TCP socket is still alive and idle (no pending EOF or reset)
pub fn is_socket_alive(stream: &TcpStream) -> bool {
    let mut buf = [0u8; 1];
    match stream.try_read(&mut buf) {
        Ok(0) => false, // Peer closed connection (EOF / FIN)
        Ok(_) => false, // Unexpected data waiting on idle connection
        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => true, // Socket is open and idle
        Err(_) => false, // Connection reset or other error
    }
}

/// Thread-safe origin connection pool
#[derive(Clone, Debug)]
pub struct OriginPool {
    target: SocketAddr,
    connect_timeout: Duration,
    max_idle: usize,
    idle_timeout: Duration,
    idle: Arc<Mutex<VecDeque<(TcpStream, Instant)>>>,
}

impl OriginPool {
    /// Create a new `OriginPool` targeting `target` with the given dial timeout.
    pub fn new(target: SocketAddr, connect_timeout: Duration) -> Self {
        Self {
            target,
            connect_timeout,
            max_idle: DEFAULT_MAX_IDLE,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            idle: Arc::new(Mutex::new(VecDeque::with_capacity(DEFAULT_MAX_IDLE))),
        }
    }

    /// Set maximum idle connection capacity.
    pub fn with_max_idle(mut self, max: usize) -> Self {
        self.max_idle = max;
        self
    }

    /// Set idle connection expiry timeout.
    pub fn with_idle_timeout(mut self, timeout: Duration) -> Self {
        self.idle_timeout = timeout;
        self
    }

    /// Set connection dial timeout.
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Acquire a warm connection from pool, or connect to target if none available.
    /// Returns `(stream, is_reused)`.
    pub async fn acquire(&self) -> Result<(TcpStream, bool)> {
        // 1. Try warm pool
        loop {
            let item = self.idle.lock().pop_front();
            match item {
                Some((stream, instant)) => {
                    if instant.elapsed() > self.idle_timeout {
                        continue;
                    }
                    if is_socket_alive(&stream) {
                        return Ok((stream, true));
                    }
                }
                None => break,
            }
        }

        // 2. Cold path: dial new connection
        let stream = self.dial_fresh().await?;
        Ok((stream, false))
    }

    /// Dial a fresh connection directly to the target.
    pub async fn dial_fresh(&self) -> Result<TcpStream> {
        let connect_fut = TcpStream::connect(self.target);
        match tokio::time::timeout(self.connect_timeout, connect_fut).await {
            Ok(Ok(s)) => {
                s.set_nodelay(true).ok();
                Ok(s)
            }
            Ok(Err(e)) => Err(ProtoError::IoError(format!(
                "Failed to connect to local target {}: {e}",
                self.target
            ))),
            Err(_) => Err(ProtoError::IoError(format!(
                "Timeout connecting to local target {}",
                self.target
            ))),
        }
    }

    /// Release an intact socket back to the warm pool for reuse.
    pub fn release(&self, stream: TcpStream) {
        let mut idle = self.idle.lock();
        if idle.len() < self.max_idle {
            idle.push_back((stream, Instant::now()));
        }
    }

    /// Count of currently warm idle connections in the pool.
    pub fn idle_count(&self) -> usize {
        self.idle.lock().len()
    }

    /// Target socket address.
    pub fn target(&self) -> SocketAddr {
        self.target
    }

    /// Purge all expired connections.
    pub fn purge_expired(&self) {
        let mut idle = self.idle.lock();
        let timeout = self.idle_timeout;
        idle.retain(|(_, inst)| inst.elapsed() <= timeout);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn test_pool_acquire_cold_dials_target() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.write_all(b"hello").await.unwrap();
        });

        let pool = OriginPool::new(addr, Duration::from_secs(1));
        assert_eq!(pool.idle_count(), 0);

        let (mut stream, is_reused) = pool.acquire().await.unwrap();
        assert!(!is_reused);
        let mut buf = [0u8; 5];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
    }

    #[tokio::test]
    async fn test_pool_release_and_reuse() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut s1, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4];
            s1.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"req1");
            s1.write_all(b"res1").await.unwrap();

            // Same connection receives req2
            s1.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"req2");
            s1.write_all(b"res2").await.unwrap();
        });

        let pool = OriginPool::new(addr, Duration::from_secs(1));
        let (mut stream, is_reused) = pool.acquire().await.unwrap();
        assert!(!is_reused);
        stream.write_all(b"req1").await.unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"res1");

        // Release back to pool
        pool.release(stream);
        assert_eq!(pool.idle_count(), 1);

        // Acquire again - should reuse warm stream
        let (mut reused_stream, is_reused) = pool.acquire().await.unwrap();
        assert!(is_reused);
        assert_eq!(pool.idle_count(), 0);

        reused_stream.write_all(b"req2").await.unwrap();
        reused_stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"res2");
    }

    #[tokio::test]
    async fn test_pool_discards_closed_socket() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (s1, _) = listener.accept().await.unwrap();
            // Drop s1 immediately to close it
            drop(s1);

            // Accept second connection
            let (mut s2, _) = listener.accept().await.unwrap();
            s2.write_all(b"fresh").await.unwrap();
        });

        let pool = OriginPool::new(addr, Duration::from_secs(1));
        let (stream, is_reused) = pool.acquire().await.unwrap();
        assert!(!is_reused);
        pool.release(stream);
        assert_eq!(pool.idle_count(), 1);

        // Allow remote drop to be detected
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Next acquire detects peer closed connection, discards it, and dials fresh
        let (mut fresh, is_reused) = pool.acquire().await.unwrap();
        assert!(!is_reused);
        let mut buf = [0u8; 5];
        fresh.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"fresh");
    }

    #[tokio::test]
    async fn test_pool_max_idle_cap() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            loop {
                if listener.accept().await.is_err() {
                    break;
                }
            }
        });

        let pool = OriginPool::new(addr, Duration::from_secs(1)).with_max_idle(2);
        let (s1, _) = pool.acquire().await.unwrap();
        let (s2, _) = pool.acquire().await.unwrap();
        let (s3, _) = pool.acquire().await.unwrap();

        pool.release(s1);
        pool.release(s2);
        pool.release(s3); // Exceeds capacity 2, should be dropped

        assert_eq!(pool.idle_count(), 2);
    }
}
