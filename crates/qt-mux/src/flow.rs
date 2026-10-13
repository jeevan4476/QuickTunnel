//! Two-level flow control: connection + per-stream windows

use qt_proto::{ProtoError, Result};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use tokio::sync::Notify;

/// Send-side flow control window with async credit acquisition.
/// Uses atomic counter + Notify for wait/notify on credit availability.
#[derive(Debug, Clone)]
pub struct SendWindow {
    credit: Arc<AtomicI64>,
    notify: Arc<Notify>,
}

impl SendWindow {
    /// Create a new send window with initial credit.
    pub fn new(initial_credit: u32) -> Self {
        Self {
            credit: Arc::new(AtomicI64::new(initial_credit as i64)),
            notify: Arc::new(Notify::new()),
        }
    }

    /// Get currently available credit.
    pub fn available(&self) -> u32 {
        self.credit.load(Ordering::Acquire).max(0) as u32
    }

    /// Acquire credit for sending `bytes` bytes.
    /// Waits until enough credit is available or the window is closed.
    pub async fn acquire(&self, bytes: u32) -> u32 {
        if bytes == 0 {
            return 0;
        }

        let needed = bytes as i64;

        // Fast path: enough credit available
        let current = self.credit.load(Ordering::Acquire);
        if current >= needed {
            let new = self.credit.fetch_sub(needed, Ordering::AcqRel);
            if new >= needed {
                return bytes;
            }
            // Race condition: credit changed, put back and retry
            self.credit.fetch_add(needed, Ordering::AcqRel);
        }

        // Slow path: wait for credit
        loop {
            self.notify.notified().await;
            let current = self.credit.load(Ordering::Acquire);
            if current >= needed {
                let new = self.credit.fetch_sub(needed, Ordering::AcqRel);
                if new >= needed {
                    return bytes;
                }
                // Race, put back and retry
                self.credit.fetch_add(needed, Ordering::AcqRel);
            }
        }
    }

    /// Grant additional credit to the window.
    /// Returns error if total would exceed i32::MAX (2^31 - 1).
    pub fn grant(&self, delta: u32) -> Result<()> {
        if delta == 0 {
            return Ok(());
        }

        let delta_i64 = delta as i64;
        let max_credit = i32::MAX as i64;

        // Check overflow before granting
        let mut current = self.credit.load(Ordering::Acquire);
        loop {
            if current > max_credit - delta_i64 {
                return Err(ProtoError::FlowControlError {
                    sent: delta,
                    credit: current as u32,
                });
            }
            match self.credit.compare_exchange_weak(
                current,
                current + delta_i64,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    self.notify.notify_waiters();
                    return Ok(());
                }
                Err(actual) => current = actual,
            }
        }
    }

    /// Try to grant credit without blocking, returns true if granted.
    pub fn try_grant(&self, delta: u32) -> bool {
        if delta == 0 {
            return true;
        }

        let delta_i64 = delta as i64;
        let max_credit = i32::MAX as i64;

        let mut current = self.credit.load(Ordering::Acquire);
        loop {
            if current > max_credit - delta_i64 {
                return false;
            }
            match self.credit.compare_exchange_weak(
                current,
                current + delta_i64,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    self.notify.notify_waiters();
                    return true;
                }
                Err(actual) => current = actual,
            }
        }
    }

    /// Try to acquire up to `want` bytes without blocking. Returns bytes acquired.
    pub fn try_acquire(&self, want: u32) -> u32 {
        if want == 0 {
            return 0;
        }

        let mut current = self.credit.load(Ordering::Acquire);
        loop {
            if current <= 0 {
                return 0;
            }
            let take = (current as u32).min(want);
            let next = current - take as i64;
            match self.credit.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return take,
                Err(actual) => current = actual,
            }
        }
    }
}

/// Receive-side flow control window.
/// Tracks consumed bytes and triggers WINDOW_UPDATE when threshold crossed.
#[derive(Debug, Clone)]
pub struct RecvWindow {
    initial_window: u32,
    consumed: u64,
    last_update: u64,
}

impl RecvWindow {
    /// Create a new receive window.
    pub fn new(initial_window: u32) -> Self {
        Self {
            initial_window,
            consumed: 0,
            last_update: 0,
        }
    }

    /// Called when application consumes `bytes` from the stream.
    /// Returns Some(delta) if a WINDOW_UPDATE should be sent,
    /// None if still below the threshold (initial_window / 2).
    pub fn on_consumed(&mut self, bytes: u32) -> Option<u32> {
        if bytes == 0 {
            return None;
        }

        self.consumed += bytes as u64;
        let threshold = (self.initial_window as u64) / 2;

        // Check if we've crossed the threshold since last update
        if self.consumed >= self.last_update + threshold {
            let delta = (self.consumed - self.last_update) as u32;
            self.last_update = self.consumed;
            Some(delta)
        } else {
            None
        }
    }

    /// Get the current window size (initial - unconsumed)
    pub fn available(&self) -> u32 {
        self.initial_window
            .saturating_sub((self.consumed - self.last_update) as u32)
    }

    /// Get the initial window size
    pub fn initial_window(&self) -> u32 {
        self.initial_window
    }
}

/// Two-level flow controller managing connection window (stream 0) and per-stream windows.
#[derive(Debug)]
pub struct FlowController {
    connection_send: SendWindow,
    connection_recv: parking_lot::Mutex<RecvWindow>,
    stream_send: parking_lot::RwLock<std::collections::HashMap<u32, SendWindow>>,
    stream_recv: parking_lot::RwLock<std::collections::HashMap<u32, RecvWindow>>,
    default_stream_window: u32,
}

impl FlowController {
    /// Create a new flow controller with connection and default stream windows.
    pub fn new(connection_window: u32, default_stream_window: u32) -> Self {
        Self {
            connection_send: SendWindow::new(connection_window),
            connection_recv: parking_lot::Mutex::new(RecvWindow::new(connection_window)),
            stream_send: parking_lot::RwLock::new(std::collections::HashMap::new()),
            stream_recv: parking_lot::RwLock::new(std::collections::HashMap::new()),
            default_stream_window,
        }
    }

    /// Get the connection send window
    pub fn connection_send(&self) -> &SendWindow {
        &self.connection_send
    }

    /// Get the connection receive window mutex
    pub fn connection_recv(&self) -> &parking_lot::Mutex<RecvWindow> {
        &self.connection_recv
    }

    /// Get or create a stream send window
    pub fn get_or_create_stream_send(&self, stream_id: u32) -> SendWindow {
        let mut map = self.stream_send.write();
        map.entry(stream_id)
            .or_insert_with(|| SendWindow::new(self.default_stream_window))
            .clone()
    }

    /// Get or create a stream receive window
    pub fn get_or_create_stream_recv(&self, stream_id: u32) -> RecvWindow {
        let mut map = self.stream_recv.write();
        map.entry(stream_id)
            .or_insert_with(|| RecvWindow::new(self.default_stream_window))
            .clone()
    }

    /// Consume connection credit (for sending frames)
    pub async fn consume_connection(&self, bytes: u32) -> Result<()> {
        self.connection_send.acquire(bytes).await;
        Ok(())
    }

    /// Grant connection credit (when receiving WINDOW_UPDATE)
    pub fn grant_connection(&self, delta: u32) -> Result<()> {
        self.connection_send.grant(delta)
    }

    /// Consume stream credit (for sending data on a stream)
    pub async fn consume_stream(&self, stream_id: u32, bytes: u32) -> Result<()> {
        let window = self.get_or_create_stream_send(stream_id);
        window.acquire(bytes).await;
        Ok(())
    }

    /// Grant stream credit (when receiving WINDOW_UPDATE for a stream)
    pub fn grant_stream(&self, stream_id: u32, delta: u32) -> Result<()> {
        let window = self.get_or_create_stream_send(stream_id);
        window.grant(delta)
    }

    /// Mark bytes consumed on a stream receive window
    /// Returns Some(delta) if WINDOW_UPDATE should be sent
    pub fn on_stream_consumed(&self, stream_id: u32, bytes: u32) -> Option<u32> {
        let mut map = self.stream_recv.write();
        let window = map
            .entry(stream_id)
            .or_insert_with(|| RecvWindow::new(self.default_stream_window));
        window.on_consumed(bytes)
    }

    /// Mark connection bytes consumed
    /// Returns Some(delta) if WINDOW_UPDATE should be sent for connection
    pub fn on_connection_consumed(&self, bytes: u32) -> Option<u32> {
        self.connection_recv.lock().on_consumed(bytes)
    }

    /// Set stream window explicitly (for OPEN frame initial window)
    pub fn set_stream_window(&self, stream_id: u32, window: u32) {
        let mut send_map = self.stream_send.write();
        send_map.insert(stream_id, SendWindow::new(window));
        let mut recv_map = self.stream_recv.write();
        recv_map.insert(stream_id, RecvWindow::new(window));
    }

    /// Remove stream windows (on stream close)
    pub fn remove_stream(&self, stream_id: u32) {
        self.stream_send.write().remove(&stream_id);
        self.stream_recv.write().remove(&stream_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_send_window_acquire_and_grant() {
        let window = SendWindow::new(100);
        assert_eq!(window.available(), 100);

        let acquired = window.acquire(60).await;
        assert_eq!(acquired, 60);
        assert_eq!(window.available(), 40);

        // Concurrently await credit
        let win_clone = window.clone();
        let handle = tokio::spawn(async move { win_clone.acquire(80).await });

        // Grant 100 more credit
        window.grant(100).unwrap();
        let acquired2 = handle.await.unwrap();
        assert_eq!(acquired2, 80);
    }

    #[test]
    fn test_send_window_overflow_guard() {
        let window = SendWindow::new(i32::MAX as u32);
        assert!(window.grant(1).is_err()); // Exceeds 2^31 - 1
    }

    #[test]
    fn test_recv_window_half_threshold_update() {
        let mut recv = RecvWindow::new(65536);
        // Consuming less than half returns None
        assert_eq!(recv.on_consumed(16384), None);
        assert_eq!(recv.on_consumed(16383), None);

        // Hitting >= 32768 returns total delta
        let delta = recv.on_consumed(1);
        assert_eq!(delta, Some(32768));

        // Next small consumption does not trigger update
        assert_eq!(recv.on_consumed(100), None);
    }

    #[test]
    fn test_recv_window_exact_half() {
        let mut recv = RecvWindow::new(100);
        // Consume exactly half
        assert_eq!(recv.on_consumed(50), Some(50));
        // Next consumption triggers at next half
        assert_eq!(recv.on_consumed(25), None);
        assert_eq!(recv.on_consumed(25), Some(50));
    }

    #[tokio::test]
    async fn test_flow_controller_stream_windows() {
        let fc = FlowController::new(65536, 16384);

        // Test stream send window creation and use
        let stream_window = fc.get_or_create_stream_send(1);
        assert_eq!(stream_window.available(), 16384);

        let acquired = stream_window.acquire(5000).await;
        assert_eq!(acquired, 5000);
        assert_eq!(stream_window.available(), 11384);

        fc.grant_stream(1, 10000).unwrap();
        // Window now has 11384 + 10000 = 21384
        let acquired2 = stream_window.acquire(10000).await;
        assert_eq!(acquired2, 10000);
    }

    #[tokio::test]
    async fn test_flow_controller_connection_window() {
        let fc = FlowController::new(1000, 1000);

        // Consume connection credit
        fc.consume_connection(500).await.unwrap();
        assert_eq!(fc.connection_send().available(), 500);

        // Grant connection credit
        fc.grant_connection(200).unwrap();
        assert_eq!(fc.connection_send().available(), 700);
    }

    #[test]
    fn test_flow_controller_stream_recv_updates() {
        let fc = FlowController::new(65536, 16384);

        // Consume bytes on stream 1
        let delta = fc.on_stream_consumed(1, 4096);
        assert_eq!(delta, None); // Below half threshold (8192)

        let delta = fc.on_stream_consumed(1, 4096);
        assert_eq!(delta, Some(8192)); // Crossed threshold

        let delta = fc.on_stream_consumed(1, 100);
        assert_eq!(delta, None); // Below next threshold
    }

    #[tokio::test]
    async fn test_send_window_edge_cases() {
        let win = SendWindow::new(50);
        assert_eq!(win.acquire(0).await, 0);
        assert!(win.grant(0).is_ok());
        assert_eq!(win.try_acquire(0), 0);
        assert!(win.try_grant(0));

        assert_eq!(win.try_acquire(20), 20);
        assert_eq!(win.available(), 30);
        assert_eq!(win.try_acquire(40), 30);
        assert_eq!(win.available(), 0);
        assert_eq!(win.try_acquire(10), 0);

        assert!(win.try_grant(25));
        assert_eq!(win.available(), 25);

        // Overflow on try_grant
        let max_win = SendWindow::new(i32::MAX as u32);
        assert!(!max_win.try_grant(10));
    }

    #[test]
    fn test_recv_window_helpers() {
        let mut rw = RecvWindow::new(1000);
        assert_eq!(rw.initial_window(), 1000);
        assert_eq!(rw.available(), 1000);
        assert_eq!(rw.on_consumed(0), None);

        rw.on_consumed(200);
        assert_eq!(rw.available(), 800);
    }

    #[tokio::test]
    async fn test_flow_controller_full_lifecycle() {
        let fc = FlowController::new(10000, 2000);

        fc.consume_stream(1, 500).await.unwrap();
        let _ = fc.get_or_create_stream_recv(1);
        assert!(fc.connection_recv().lock().available() <= 10000);

        fc.set_stream_window(2, 5000);
        assert_eq!(fc.get_or_create_stream_send(2).available(), 5000);

        fc.remove_stream(2);
        // After removal, re-creating yields default window
        assert_eq!(fc.get_or_create_stream_send(2).available(), 2000);
    }
}
