use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use bytes::Bytes;
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

use qt_proto::Frame;

use crate::flow::{RecvWindow, SendWindow};

/// A virtual stream implementing AsyncRead and AsyncWrite,
/// backed by bounded channels to the multiplexer session.
#[derive(Clone, Debug)]
pub struct Stream {
    /// Stream ID
    id: u32,
    /// Priority hint (default 1)
    priority: u8,
    /// Send channel to session outbound queue
    tx: mpsc::Sender<Frame>,
    /// Send window (credit to transmit data to peer)
    send_window: SendWindow,
    /// Receive window (tracks consumed bytes and threshold updates)
    recv_window: Arc<Mutex<RecvWindow>>,
    /// Receive buffer for incoming data chunks
    read_buffer: Arc<Mutex<VecDeque<Bytes>>>,
    /// Read side closed (FIN received or reset)
    read_closed: Arc<AtomicBool>,
    /// Write side closed (FIN sent or reset)
    write_closed: Arc<AtomicBool>,
    /// Waker for pending reads
    read_waker: Arc<Mutex<Option<Waker>>>,
    /// Waker for pending writes (e.g. waiting for send credit)
    write_waker: Arc<Mutex<Option<Waker>>>,
}

impl Stream {
    /// Create a new Stream
    pub fn new(id: u32, priority: u8, initial_window: u32, tx: mpsc::Sender<Frame>) -> Self {
        Self {
            id,
            priority,
            tx,
            send_window: SendWindow::new(initial_window),
            recv_window: Arc::new(Mutex::new(RecvWindow::new(initial_window))),
            read_buffer: Arc::new(Mutex::new(VecDeque::new())),
            read_closed: Arc::new(AtomicBool::new(false)),
            write_closed: Arc::new(AtomicBool::new(false)),
            read_waker: Arc::new(Mutex::new(None)),
            write_waker: Arc::new(Mutex::new(None)),
        }
    }

    /// Stream ID
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Priority hint
    pub fn priority(&self) -> u8 {
        self.priority
    }

    /// Called by the session when a DATA frame arrives for this stream
    pub fn on_data(&self, data: Bytes, fin: bool) {
        if !data.is_empty() {
            self.read_buffer.lock().push_back(data);
        }
        if fin {
            self.read_closed.store(true, Ordering::Release);
        }
        if let Some(waker) = self.read_waker.lock().take() {
            waker.wake();
        }
    }

    /// Called by the session when a FIN frame arrives
    pub fn on_fin(&self) {
        self.read_closed.store(true, Ordering::Release);
        if let Some(waker) = self.read_waker.lock().take() {
            waker.wake();
        }
    }

    /// Called by the session when RST arrives
    pub fn on_reset(&self) {
        self.read_closed.store(true, Ordering::Release);
        self.write_closed.store(true, Ordering::Release);
        if let Some(waker) = self.read_waker.lock().take() {
            waker.wake();
        }
        if let Some(waker) = self.write_waker.lock().take() {
            waker.wake();
        }
    }

    /// Called by the session when a WINDOW_UPDATE arrives for this stream
    pub fn on_window_update(&self, increment: u32) {
        self.send_window.grant(increment).ok();
        if let Some(waker) = self.write_waker.lock().take() {
            waker.wake();
        }
    }

    /// Send a RST frame aborting the stream
    pub async fn reset(&self, error_code: u32) -> Result<(), qt_proto::ProtoError> {
        self.write_closed.store(true, Ordering::Release);
        self.read_closed.store(true, Ordering::Release);
        let frame = Frame::rst(self.id, error_code)?;
        self.tx
            .send(frame)
            .await
            .map_err(|_| qt_proto::ProtoError::ProtocolError("Session closed".into()))?;
        Ok(())
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        // 1. Drain available data in read buffer
        let mut buffer = this.read_buffer.lock();
        if let Some(mut data) = buffer.pop_front() {
            let to_read = std::cmp::min(data.len(), buf.remaining());
            buf.put_slice(&data[..to_read]);
            if to_read < data.len() {
                buffer.push_front(data.split_off(to_read));
            }
            drop(buffer);

            // Flow control: check if consuming `to_read` bytes triggers WINDOW_UPDATE
            if let Some(delta) = this.recv_window.lock().on_consumed(to_read as u32) {
                if let Ok(wu_frame) = Frame::window_update(this.id, delta) {
                    let _ = this.tx.try_send(wu_frame);
                }
            }

            return Poll::Ready(Ok(()));
        }

        // 2. If no data and read half is closed -> clean EOF
        if this.read_closed.load(Ordering::Acquire) {
            return Poll::Ready(Ok(()));
        }

        // 3. Otherwise register waker and pend
        *this.read_waker.lock() = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();

        if this.write_closed.load(Ordering::Acquire) {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "Stream write closed",
            )));
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // Try to acquire send credit without blocking
        let available = this.send_window.try_acquire(buf.len() as u32);
        if available == 0 {
            *this.write_waker.lock() = Some(cx.waker().clone());
            return Poll::Pending;
        }

        let to_send = available as usize;
        let data = Bytes::copy_from_slice(&buf[..to_send]);
        let frame = Frame::data(this.id, data, false).map_err(std::io::Error::other)?;

        match this.tx.try_send(frame) {
            Ok(()) => Poll::Ready(Ok(to_send)),
            Err(mpsc::error::TrySendError::Full(_)) => {
                // Window credit was acquired but outbound channel was temporarily full.
                // Restore the acquired credit and pend.
                this.send_window.grant(available).ok();
                *this.write_waker.lock() = Some(cx.waker().clone());
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                this.write_closed.store(true, Ordering::Release);
                Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "Session channel closed",
                )))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        if this.write_closed.load(Ordering::Acquire) {
            return Poll::Ready(Ok(()));
        }

        let frame = Frame::fin(this.id).map_err(std::io::Error::other)?;

        match this.tx.try_send(frame) {
            Ok(()) => {
                this.write_closed.store(true, Ordering::Release);
                Poll::Ready(Ok(()))
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                this.write_closed.store(true, Ordering::Release);
                Poll::Ready(Ok(()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qt_proto::{flags, FrameType};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Helper to create an in-memory stream pair for unit tests
    async fn pump(mut rx: mpsc::Receiver<Frame>, target: Stream) {
        while let Some(frame) = rx.recv().await {
            match frame.header.ty {
                FrameType::Data => {
                    let fin = frame.header.flags & flags::FIN != 0;
                    target.on_data(frame.payload, fin);
                }
                FrameType::Fin => target.on_fin(),
                FrameType::Rst => target.on_reset(),
                FrameType::WindowUpdate if frame.payload.len() >= 4 => {
                    let delta = u32::from_be_bytes(frame.payload[..4].try_into().unwrap_or([0; 4]));
                    target.on_window_update(delta);
                }
                _ => {}
            }
        }
    }

    /// Helper to create an in-memory stream pair for unit tests
    fn create_in_memory_stream_pair(id: u32, initial_window: u32) -> (Stream, Stream) {
        let (tx_a, rx_a) = mpsc::channel(128);
        let (tx_b, rx_b) = mpsc::channel(128);

        let stream_a = Stream::new(id, 1, initial_window, tx_a);
        let stream_b = Stream::new(id, 1, initial_window, tx_b);

        tokio::spawn(pump(rx_a, stream_b.clone()));
        tokio::spawn(pump(rx_b, stream_a.clone()));

        (stream_a, stream_b)
    }

    #[tokio::test]
    async fn test_stream_partial_read_and_split() {
        let (tx, _rx) = mpsc::channel(16);
        let mut stream = Stream::new(1, 1, 1024, tx);

        // Push 10 bytes
        stream.on_data(Bytes::from_static(b"0123456789"), false);

        // Read 4 bytes
        let mut buf4 = [0u8; 4];
        stream.read_exact(&mut buf4).await.unwrap();
        assert_eq!(&buf4, b"0123");

        // Read remaining 6 bytes
        let mut buf6 = [0u8; 6];
        stream.read_exact(&mut buf6).await.unwrap();
        assert_eq!(&buf6, b"456789");
    }

    #[tokio::test]
    async fn test_stream_closed_errors() {
        let (tx, rx) = mpsc::channel(16);
        drop(rx); // Close channel

        let mut stream = Stream::new(1, 1, 1024, tx);
        // Write on closed channel returns error
        assert!(stream.write_all(b"test").await.is_err());
        // Subsequent write also fails
        assert!(stream.write_all(b"test").await.is_err());
    }

    #[tokio::test]
    async fn test_stream_on_reset_wakes_pending_read() {
        let (tx, _rx) = mpsc::channel(16);
        let stream = Stream::new(1, 1, 1024, tx);

        let s_clone = stream.clone();
        let handle = tokio::spawn(async move {
            let mut buf = [0u8; 4];
            let n = s_clone.clone().read(&mut buf).await.unwrap();
            assert_eq!(n, 0);
        });

        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        stream.on_reset();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_stream_async_read_write() {
        let (mut stream_a, mut stream_b) = create_in_memory_stream_pair(1, 256 * 1024);

        stream_b.write_all(b"hello multiplexer").await.unwrap();
        let mut buf = vec![0u8; 17];
        stream_a.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf[..], b"hello multiplexer");
    }

    #[tokio::test]
    async fn test_stream_half_close_fin() {
        let (mut stream_a, mut stream_b) = create_in_memory_stream_pair(1, 256 * 1024);
        stream_a.shutdown().await.unwrap();

        let mut buf = [0u8; 1];
        let n = stream_b.read(&mut buf).await.unwrap();
        assert_eq!(n, 0); // Clean EOF upon FIN
    }

    #[tokio::test]
    async fn test_stream_reset() {
        let (stream_a, mut stream_b) = create_in_memory_stream_pair(1, 256 * 1024);
        stream_a.reset(0).await.unwrap();

        // Give task a tick to forward frame
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        let mut buf = [0u8; 1];
        let n = stream_b.read(&mut buf).await.unwrap();
        assert_eq!(n, 0);
        assert!(stream_b.write_all(b"abc").await.is_err());
    }

    #[test]
    fn test_stream_new_properties() {
        let (tx, _rx) = mpsc::channel(16);
        let stream = Stream::new(42, 3, 65536, tx);
        assert_eq!(stream.id(), 42);
        assert_eq!(stream.priority(), 3);
    }

    #[tokio::test]
    async fn test_stream_flow_control_window_update() {
        let (mut stream_a, mut stream_b) = create_in_memory_stream_pair(1, 100);

        // Send 60 bytes from b to a
        let payload = vec![7u8; 60];
        stream_b.write_all(&payload).await.unwrap();

        // Read 60 bytes from a (crossing 50% threshold of 100)
        let mut buf = vec![0u8; 60];
        stream_a.read_exact(&mut buf).await.unwrap();

        // Yield to allow WINDOW_UPDATE frame pumping
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        // stream_b should have received window credit update back
        assert!(stream_b.send_window.available() >= 50);
    }

    #[tokio::test]
    async fn test_stream_zero_write_flush_and_double_shutdown() {
        let (mut stream_a, _stream_b) = create_in_memory_stream_pair(1, 1024);

        // Empty write returns 0
        let n = stream_a.write(&[]).await.unwrap();
        assert_eq!(n, 0);

        // Flush returns Ok
        stream_a.flush().await.unwrap();

        // First shutdown
        stream_a.shutdown().await.unwrap();
        // Second shutdown on already closed stream
        stream_a.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn test_stream_send_window_blocked_then_granted() {
        let (tx, mut rx) = mpsc::channel(16);
        let mut stream = Stream::new(1, 1, 10, tx);

        // Consume all 10 bytes of credit
        assert_eq!(stream.write(&[1u8; 10]).await.unwrap(), 10);
        let _ = rx.recv().await.unwrap();

        // Spawn a task that writes when window is blocked
        let mut s_clone = stream.clone();
        let handle = tokio::spawn(async move {
            s_clone.write_all(&[2u8; 5]).await.unwrap();
        });

        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        // Grant credit to wake the blocked writer
        stream.on_window_update(20);

        handle.await.unwrap();
    }
}
