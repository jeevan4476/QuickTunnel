//! Multiplexer session actor
//!
//! Manages connection lifecycle, frame dispatching, and streams.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::BytesMut;
use parking_lot::Mutex;
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot, Notify};

use qt_proto::tlv::{find_tlv, hello_tags, open_tags};
use qt_proto::util::FrameAssembler;
use qt_proto::{
    flags, Frame, FrameType, ProtoError, Result, CONTROL_STREAM_ID, DEFAULT_MAX_PAYLOAD,
};

use crate::flow::FlowController;
use crate::scheduler::DrrScheduler;
use crate::state::{StreamStateMachine, TombstoneMap};
use crate::stream::Stream;

/// Configuration for MuxSession
#[derive(Debug, Clone)]
pub struct MuxConfig {
    /// Initial stream receive window (bytes)
    pub initial_window: u32,
    /// Connection-level receive window (bytes)
    pub connection_window: u32,
    /// Maximum frame payload size
    pub max_payload_size: u32,
    /// Keep-alive interval
    pub keep_alive_interval: Duration,
    /// Tombstone TTL for stream IDs
    pub tombstone_ttl: Duration,
    /// Whether this is the client (initiator) or server (acceptor)
    pub is_client: bool,
}

impl MuxConfig {
    /// Client configuration (initiates streams with odd IDs)
    pub fn client() -> Self {
        Self {
            initial_window: 256 * 1024,
            connection_window: 1024 * 1024,
            max_payload_size: DEFAULT_MAX_PAYLOAD,
            keep_alive_interval: Duration::from_secs(30),
            tombstone_ttl: Duration::from_secs(30),
            is_client: true,
        }
    }

    /// Server configuration (accepts streams with even IDs)
    pub fn server() -> Self {
        Self {
            initial_window: 256 * 1024,
            connection_window: 1024 * 1024,
            max_payload_size: DEFAULT_MAX_PAYLOAD,
            keep_alive_interval: Duration::from_secs(30),
            tombstone_ttl: Duration::from_secs(30),
            is_client: false,
        }
    }
}

impl Default for MuxConfig {
    fn default() -> Self {
        Self::client()
    }
}

/// Commands sent to the session actor from MuxHandle
enum SessionCommand {
    OpenStream {
        response_tx: oneshot::Sender<Result<Stream>>,
    },
    AcceptStream {
        response_tx: oneshot::Sender<Option<Stream>>,
    },
    Ping {
        response_tx: oneshot::Sender<Result<Duration>>,
    },
    Close {
        response_tx: oneshot::Sender<Result<()>>,
    },
}

/// Handle to interact with the multiplexer session
#[derive(Clone)]
pub struct MuxHandle {
    cmd_tx: mpsc::Sender<SessionCommand>,
}

impl MuxHandle {
    /// Create a new MuxHandle
    fn new(cmd_tx: mpsc::Sender<SessionCommand>) -> Self {
        Self { cmd_tx }
    }

    /// Open a new outbound stream
    pub async fn open_stream(&self) -> Result<Stream> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(SessionCommand::OpenStream { response_tx: tx })
            .await
            .map_err(|_| ProtoError::ProtocolError("Session closed".into()))?;
        rx.await
            .map_err(|_| ProtoError::ProtocolError("Session closed".into()))?
    }

    /// Accept an inbound stream
    pub async fn accept_stream(&self) -> Option<Stream> {
        let (tx, rx) = oneshot::channel();
        if self
            .cmd_tx
            .send(SessionCommand::AcceptStream { response_tx: tx })
            .await
            .is_err()
        {
            return None;
        }
        rx.await.ok().flatten()
    }

    /// Send a ping and measure RTT
    pub async fn ping(&self) -> Result<Duration> {
        let (response_tx, response_rx) = oneshot::channel();
        self.cmd_tx
            .send(SessionCommand::Ping { response_tx })
            .await
            .map_err(|_| ProtoError::ProtocolError("Session closed".into()))?;
        response_rx
            .await
            .map_err(|_| ProtoError::ProtocolError("Session closed".into()))?
    }

    /// Close the session gracefully
    pub async fn close(&self) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(SessionCommand::Close { response_tx: tx })
            .await
            .map_err(|_| ProtoError::ProtocolError("Session closed".into()))?;
        rx.await
            .map_err(|_| ProtoError::ProtocolError("Session closed".into()))?
    }
}

type PingWaiters = Arc<Mutex<HashMap<u64, (Instant, oneshot::Sender<Duration>)>>>;

/// The main multiplexer session actor
pub struct MuxSession<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> {
    io: Option<T>,
    config: MuxConfig,
    flow: Arc<FlowController>,
    scheduler: Arc<Mutex<DrrScheduler>>,
    streams: Arc<Mutex<HashMap<u32, StreamStateMachine>>>,
    stream_handles: Arc<Mutex<HashMap<u32, Stream>>>,
    tombstones: Arc<Mutex<TombstoneMap>>,
    next_stream_id: Arc<AtomicU32>,
    cmd_rx: mpsc::Receiver<SessionCommand>,
    outbound_tx: mpsc::Sender<Frame>,
    outbound_rx: mpsc::Receiver<Frame>,
    write_notify: Arc<Notify>,
    pending_accepts: Arc<Mutex<VecDeque<Stream>>>,
    accept_waiters: Arc<Mutex<VecDeque<oneshot::Sender<Option<Stream>>>>>,
    ping_waiters: PingWaiters,
    closed: Arc<AtomicBool>,
}

impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> MuxSession<T> {
    /// Create a new MuxSession and MuxHandle
    pub fn new(io: T, config: MuxConfig) -> (Self, MuxHandle) {
        let (cmd_tx, cmd_rx) = mpsc::channel(64);
        let (outbound_tx, outbound_rx) = mpsc::channel(256);
        let write_notify = Arc::new(Notify::new());

        let initial_id = if config.is_client { 1 } else { 2 };
        let flow = Arc::new(FlowController::new(
            config.connection_window,
            config.initial_window,
        ));
        let scheduler = Arc::new(Mutex::new(DrrScheduler::new(config.max_payload_size)));
        let tombstones = Arc::new(Mutex::new(TombstoneMap::new(config.tombstone_ttl)));

        let session = Self {
            io: Some(io),
            config,
            flow,
            scheduler,
            streams: Arc::new(Mutex::new(HashMap::new())),
            stream_handles: Arc::new(Mutex::new(HashMap::new())),
            tombstones,
            next_stream_id: Arc::new(AtomicU32::new(initial_id)),
            cmd_rx,
            outbound_tx,
            outbound_rx,
            write_notify,
            pending_accepts: Arc::new(Mutex::new(VecDeque::new())),
            accept_waiters: Arc::new(Mutex::new(VecDeque::new())),
            ping_waiters: Arc::new(Mutex::new(HashMap::new())),
            closed: Arc::new(AtomicBool::new(false)),
        };

        let handle = MuxHandle::new(cmd_tx);
        (session, handle)
    }

    /// Check if the session is closed
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// Run the session to completion
    pub async fn run(mut self) -> Result<()> {
        let io = self
            .io
            .take()
            .ok_or_else(|| ProtoError::ProtocolError("Session I/O already consumed".into()))?;
        let (mut read_half, mut write_half) = tokio::io::split(io);

        // Handshake: Client sends HELLO
        if self.config.is_client {
            let hello = Frame::hello(
                "quicktunnel-client",
                self.config.max_payload_size,
                self.config.initial_window,
                0,
            )?;
            self.scheduler.lock().enqueue_control(hello);
            self.write_notify.notify_one();
        }

        // Channel for frames decoded from read half
        let (inbound_tx, mut inbound_rx) = mpsc::channel::<Frame>(128);

        // Background reader task
        let max_payload = self.config.max_payload_size;
        let reader_closed = self.closed.clone();
        let read_task = tokio::spawn(async move {
            let mut assembler = FrameAssembler::new(max_payload);
            let mut read_buf = [0u8; 16384];
            loop {
                if reader_closed.load(Ordering::Acquire) {
                    break;
                }
                let n = match read_half.read(&mut read_buf).await {
                    Ok(0) => break, // EOF
                    Ok(n) => n,
                    Err(e) => {
                        tracing::debug!("Connection read error: {}", e);
                        break;
                    }
                };

                match assembler.feed(&read_buf[..n]) {
                    Ok(frames) => {
                        for frame in frames {
                            if inbound_tx.send(frame).await.is_err() {
                                return;
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!("Frame assembly error: {}", e);
                        break;
                    }
                }
            }
        });

        // Background writer task
        let sched = self.scheduler.clone();
        let w_notify = self.write_notify.clone();
        let writer_closed = self.closed.clone();
        let write_task = tokio::spawn(async move {
            let mut write_buf = BytesMut::with_capacity(65536);
            while !writer_closed.load(Ordering::Acquire) {
                // Dequeue all pending frames up to 64 KiB
                {
                    let mut s = sched.lock();
                    while let Some(frame) = s.dequeue() {
                        frame.encode(&mut write_buf);
                        if write_buf.len() >= 65536 {
                            break;
                        }
                    }
                }

                if !write_buf.is_empty() {
                    if let Err(e) = write_half.write_all(&write_buf).await {
                        tracing::debug!("Write error: {}", e);
                        break;
                    }
                    if let Err(e) = write_half.flush().await {
                        tracing::debug!("Flush error: {}", e);
                        break;
                    }
                    write_buf.clear();
                }

                // Wait for notification or timeout
                tokio::select! {
                    _ = w_notify.notified() => {}
                    _ = tokio::time::sleep(Duration::from_millis(5)) => {}
                }
            }
        });

        // Main event loop
        let mut keep_alive_timer = tokio::time::interval(self.config.keep_alive_interval);
        keep_alive_timer.tick().await;

        loop {
            if self.closed.load(Ordering::Acquire) {
                break;
            }

            tokio::select! {
                // Inbound frame arrived from peer
                inbound = inbound_rx.recv() => {
                    match inbound {
                        Some(frame) => {
                            if let Err(e) = self.process_inbound_frame(frame).await {
                                tracing::debug!("Inbound frame handling error: {}", e);
                            }
                        }
                        None => {
                            self.closed.store(true, Ordering::Release);
                            break;
                        }
                    }
                }

                // Outbound frame from streams
                outbound = self.outbound_rx.recv() => {
                    if let Some(frame) = outbound {
                        if frame.header.ty == FrameType::Data {
                            self.scheduler.lock().enqueue_data(frame, 1);
                        } else {
                            self.scheduler.lock().enqueue_control(frame);
                        }
                        self.write_notify.notify_one();
                    }
                }

                // Session commands from MuxHandle
                cmd = self.cmd_rx.recv() => {
                    match cmd {
                        Some(SessionCommand::OpenStream { response_tx }) => {
                            let res = self.handle_open_stream().await;
                            let _ = response_tx.send(res);
                        }
                        Some(SessionCommand::AcceptStream { response_tx }) => {
                            self.handle_accept_stream(response_tx).await;
                        }
                        Some(SessionCommand::Ping { response_tx }) => {
                            self.handle_ping(response_tx).await;
                        }
                        Some(SessionCommand::Close { response_tx }) => {
                            let res = self.handle_close().await;
                            let _ = response_tx.send(res);
                            break;
                        }
                        None => {
                            break;
                        }
                    }
                }

                _ = keep_alive_timer.tick() => {
                    // Send keep-alive PING if active client
                    if self.config.is_client && !self.closed.load(Ordering::Acquire) {
                        let nonce = rand::random::<u64>();
                        if let Ok(ping) = Frame::ping(nonce) {
                            self.scheduler.lock().enqueue_control(ping);
                            self.write_notify.notify_one();
                        }
                    }
                    // Prune expired stream tombstones
                    self.tombstones.lock().prune();
                }
            }
        }

        // Clean shutdown
        self.closed.store(true, Ordering::Release);
        self.write_notify.notify_one();

        // Abort background tasks
        read_task.abort();
        write_task.abort();

        // Reset all active streams
        for (_, stream) in self.stream_handles.lock().drain() {
            stream.on_reset();
        }
        for waiter in self.accept_waiters.lock().drain(..) {
            let _ = waiter.send(None);
        }

        Ok(())
    }

    /// Process a complete inbound frame received from the wire
    async fn process_inbound_frame(&self, frame: Frame) -> Result<()> {
        let stream_id = frame.header.stream_id;

        if stream_id == CONTROL_STREAM_ID {
            self.process_control_frame(frame).await
        } else {
            self.process_stream_frame(frame).await
        }
    }

    /// Process a control frame (stream_id == 0)
    async fn process_control_frame(&self, frame: Frame) -> Result<()> {
        match frame.header.ty {
            FrameType::Hello => {
                if !self.config.is_client {
                    let version = find_tlv(&frame.payload, hello_tags::VERSION).ok().flatten();
                    let max_frame = find_tlv(&frame.payload, hello_tags::MAX_FRAME)
                        .ok()
                        .flatten();

                    let negotiated_version = version.and_then(|v| v.as_u8().ok()).unwrap_or(1);
                    let negotiated_max_frame = max_frame
                        .and_then(|v| v.as_u32().ok())
                        .unwrap_or(DEFAULT_MAX_PAYLOAD);

                    let mut nonce = [0u8; 32];
                    rand::thread_rng().fill_bytes(&mut nonce);

                    let hello_ack =
                        Frame::hello_ack(&nonce, negotiated_max_frame, negotiated_version as u64)?;
                    self.scheduler.lock().enqueue_control(hello_ack);
                    self.write_notify.notify_one();
                }
            }
            FrameType::HelloAck => {
                // Client handshake completed
            }
            FrameType::Ping => {
                if frame.payload.len() >= 8 {
                    let nonce = u64::from_be_bytes(frame.payload[..8].try_into().unwrap_or([0; 8]));
                    let pong = Frame::pong(nonce)?;
                    self.scheduler.lock().enqueue_control(pong);
                    self.write_notify.notify_one();
                }
            }
            FrameType::Pong => {
                if frame.payload.len() >= 8 {
                    let nonce = u64::from_be_bytes(frame.payload[..8].try_into().unwrap_or([0; 8]));
                    if let Some((start, tx)) = self.ping_waiters.lock().remove(&nonce) {
                        let _ = tx.send(start.elapsed());
                    }
                }
            }
            FrameType::WindowUpdate => {
                if frame.payload.len() >= 4 {
                    let delta = u32::from_be_bytes(frame.payload[..4].try_into().unwrap_or([0; 4]));
                    self.flow.grant_connection(delta).ok();
                }
            }
            FrameType::GoAway => {
                self.closed.store(true, Ordering::Release);
            }
            _ => {}
        }
        Ok(())
    }

    /// Process a stream frame (stream_id > 0)
    async fn process_stream_frame(&self, frame: Frame) -> Result<()> {
        let stream_id = frame.header.stream_id;

        // Check if stream is tombstoned
        if self.tombstones.lock().is_tombstoned(stream_id) {
            // Late frame on closed stream: return connection credit for DATA
            if frame.header.ty == FrameType::Data {
                if let Some(delta) = self.flow.on_connection_consumed(frame.payload.len() as u32) {
                    if let Ok(wu) = Frame::window_update(0, delta) {
                        self.scheduler.lock().enqueue_control(wu);
                        self.write_notify.notify_one();
                    }
                }
            }
            return Ok(());
        }

        match frame.header.ty {
            FrameType::Open => {
                let mut sm = StreamStateMachine::new(stream_id, false);
                sm.transition_recv(FrameType::Open)?;
                self.streams.lock().insert(stream_id, sm);

                let priority = if frame.header.has_prio() {
                    find_tlv(&frame.payload, open_tags::PRIORITY)
                        .ok()
                        .flatten()
                        .and_then(|t| t.as_u8().ok())
                        .unwrap_or(1)
                } else {
                    1
                };

                let stream = Stream::new(
                    stream_id,
                    priority,
                    self.config.initial_window,
                    self.outbound_tx.clone(),
                );
                self.stream_handles.lock().insert(stream_id, stream.clone());

                // Deliver to waiting accept or queue in pending_accepts
                let mut waiters = self.accept_waiters.lock();
                let delivered = if let Some(waiter) = waiters.pop_front() {
                    waiter.send(Some(stream.clone())).is_ok()
                } else {
                    false
                };
                if !delivered {
                    self.pending_accepts.lock().push_back(stream);
                }
            }
            FrameType::Data => {
                let fin = frame.header.flags & flags::FIN != 0;
                if let Some(stream) = self.stream_handles.lock().get(&stream_id) {
                    stream.on_data(frame.payload.clone(), fin);
                }
                if let Some(sm) = self.streams.lock().get_mut(&stream_id) {
                    sm.transition_recv(FrameType::Data).ok();
                    if fin {
                        sm.transition_recv(FrameType::Fin).ok();
                    }
                }

                // Return connection credit immediately on demux
                if let Some(delta) = self.flow.on_connection_consumed(frame.payload.len() as u32) {
                    if let Ok(wu) = Frame::window_update(0, delta) {
                        self.scheduler.lock().enqueue_control(wu);
                        self.write_notify.notify_one();
                    }
                }
            }
            FrameType::Fin => {
                if let Some(stream) = self.stream_handles.lock().get(&stream_id) {
                    stream.on_fin();
                }
                let mut remove = false;
                if let Some(sm) = self.streams.lock().get_mut(&stream_id) {
                    sm.transition_recv(FrameType::Fin).ok();
                    if sm.state() == crate::state::StreamState::Closed {
                        remove = true;
                    }
                }
                if remove {
                    self.tombstones.lock().insert(stream_id);
                    self.streams.lock().remove(&stream_id);
                    self.stream_handles.lock().remove(&stream_id);
                    self.flow.remove_stream(stream_id);
                }
            }
            FrameType::Rst => {
                if let Some(stream) = self.stream_handles.lock().remove(&stream_id) {
                    stream.on_reset();
                }
                self.streams.lock().remove(&stream_id);
                self.tombstones.lock().insert(stream_id);
                self.flow.remove_stream(stream_id);
            }
            FrameType::WindowUpdate if frame.payload.len() >= 4 => {
                let delta = u32::from_be_bytes(frame.payload[..4].try_into().unwrap_or([0; 4]));
                self.flow.grant_stream(stream_id, delta).ok();
                if let Some(stream) = self.stream_handles.lock().get(&stream_id) {
                    stream.on_window_update(delta);
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Handle OpenStream command
    async fn handle_open_stream(&self) -> Result<Stream> {
        let stream_id = self.next_stream_id.fetch_add(2, Ordering::AcqRel);
        if self.tombstones.lock().is_tombstoned(stream_id) {
            return Err(ProtoError::ProtocolError("Stream ID tombstoned".into()));
        }

        let mut sm = StreamStateMachine::new(stream_id, true);
        sm.transition_send(FrameType::Open)?;
        self.streams.lock().insert(stream_id, sm);

        let stream = Stream::new(
            stream_id,
            1,
            self.config.initial_window,
            self.outbound_tx.clone(),
        );
        self.stream_handles.lock().insert(stream_id, stream.clone());

        let open_frame = Frame::open(stream_id, &[], None)?;
        self.scheduler.lock().enqueue_control(open_frame);
        self.write_notify.notify_one();

        Ok(stream)
    }

    /// Handle AcceptStream command
    async fn handle_accept_stream(&self, response_tx: oneshot::Sender<Option<Stream>>) {
        let mut pending = self.pending_accepts.lock();
        if let Some(stream) = pending.pop_front() {
            let _ = response_tx.send(Some(stream));
        } else {
            self.accept_waiters.lock().push_back(response_tx);
        }
    }

    /// Handle Ping command
    async fn handle_ping(&self, response_tx: oneshot::Sender<Result<Duration>>) {
        let nonce = rand::random::<u64>();
        let (tx, rx) = oneshot::channel();
        self.ping_waiters.lock().insert(nonce, (Instant::now(), tx));

        let frame = match Frame::ping(nonce) {
            Ok(f) => f,
            Err(e) => {
                let _ = response_tx.send(Err(e));
                return;
            }
        };

        self.scheduler.lock().enqueue_control(frame);
        self.write_notify.notify_one();

        tokio::spawn(async move {
            match tokio::time::timeout(Duration::from_secs(5), rx).await {
                Ok(Ok(duration)) => {
                    let _ = response_tx.send(Ok(duration));
                }
                Ok(Err(_)) => {
                    let _ = response_tx.send(Err(ProtoError::ProtocolError(
                        "Ping response channel cancelled".into(),
                    )));
                }
                Err(_) => {
                    let _ = response_tx.send(Err(ProtoError::ProtocolError("Ping timeout".into())));
                }
            }
        });
    }

    /// Handle Close command
    async fn handle_close(&self) -> Result<()> {
        self.closed.store(true, Ordering::Release);
        let goaway = Frame::goaway(0, 0)?;
        self.scheduler.lock().enqueue_control(goaway);
        self.write_notify.notify_one();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn test_session_creation() {
        let (client_io, server_io) = duplex(4096);
        let client_config = MuxConfig::client();
        let server_config = MuxConfig::server();

        let (client_session, _client_handle) = MuxSession::new(client_io, client_config);
        let (server_session, _server_handle) = MuxSession::new(server_io, server_config);

        assert!(!client_session.is_closed());
        assert!(!server_session.is_closed());
    }

    #[tokio::test]
    async fn test_mux_session_multi_stream_transfer() {
        let (client_io, server_io) = duplex(1024 * 1024);
        let (client_session, client_handle) = MuxSession::new(client_io, MuxConfig::client());
        let (server_session, server_handle) = MuxSession::new(server_io, MuxConfig::server());

        tokio::spawn(async move {
            let _ = client_session.run().await;
        });
        tokio::spawn(async move {
            let _ = server_session.run().await;
        });

        // Client opens stream
        let mut client_stream = client_handle.open_stream().await.unwrap();
        let mut server_stream = server_handle.accept_stream().await.unwrap();

        client_stream.write_all(b"ping-pong").await.unwrap();
        let mut buf = [0u8; 9];
        server_stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping-pong");

        // Bi-directional reply
        server_stream.write_all(b"pong-ping").await.unwrap();
        let mut reply_buf = [0u8; 9];
        client_stream.read_exact(&mut reply_buf).await.unwrap();
        assert_eq!(&reply_buf, b"pong-ping");
    }

    #[tokio::test]
    async fn test_mux_session_ping_pong() {
        let (client_io, server_io) = duplex(1024 * 1024);
        let (client_session, client_handle) = MuxSession::new(client_io, MuxConfig::client());
        let (server_session, _server_handle) = MuxSession::new(server_io, MuxConfig::server());

        tokio::spawn(async move {
            let _ = client_session.run().await;
        });
        tokio::spawn(async move {
            let _ = server_session.run().await;
        });

        let rtt = client_handle.ping().await.unwrap();
        assert!(rtt.as_millis() < 5000);
    }

    #[tokio::test]
    async fn test_mux_session_graceful_close() {
        let (client_io, server_io) = duplex(1024 * 1024);
        let (client_session, client_handle) = MuxSession::new(client_io, MuxConfig::client());
        let (server_session, server_handle) = MuxSession::new(server_io, MuxConfig::server());

        tokio::spawn(async move {
            let _ = client_session.run().await;
        });
        tokio::spawn(async move {
            let _ = server_session.run().await;
        });

        client_handle.close().await.unwrap();
        // Give time to process GOAWAY
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(server_handle.accept_stream().await.is_none());
    }

    #[test]
    fn test_mux_config_default() {
        let cfg = MuxConfig::default();
        assert!(cfg.is_client);
        assert_eq!(cfg.initial_window, 256 * 1024);
        assert_eq!(cfg.connection_window, 1024 * 1024);
    }

    #[tokio::test]
    async fn test_mux_session_stream_reset_and_tombstone() {
        let (client_io, server_io) = duplex(1024 * 1024);
        let (client_session, client_handle) = MuxSession::new(client_io, MuxConfig::client());
        let (server_session, server_handle) = MuxSession::new(server_io, MuxConfig::server());

        tokio::spawn(async move {
            let _ = client_session.run().await;
        });
        tokio::spawn(async move {
            let _ = server_session.run().await;
        });

        let client_stream = client_handle.open_stream().await.unwrap();
        let server_stream = server_handle.accept_stream().await.unwrap();

        // Client resets stream
        client_stream.reset(0).await.unwrap();

        // Server stream should see EOF / reset
        tokio::time::sleep(Duration::from_millis(20)).await;
        let mut buf = [0u8; 1];
        let n = server_stream.clone().read(&mut buf).await.unwrap();
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn test_mux_session_late_data_on_tombstone() {
        let (_client_io, server_io) = duplex(1024 * 1024);
        let (server_session, _server_handle) = MuxSession::new(server_io, MuxConfig::server());

        // Pre-populate tombstone for stream 5
        server_session.tombstones.lock().insert(5);

        // Process late DATA frame for stream 5
        let late_data = Frame::data(5, bytes::Bytes::from_static(b"late payload"), false).unwrap();
        assert!(server_session
            .process_inbound_frame(late_data)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn test_mux_session_inbound_control_frames() {
        let (_client_io, server_io) = duplex(1024 * 1024);
        let (server_session, _server_handle) = MuxSession::new(server_io, MuxConfig::server());

        // WindowUpdate for connection
        let wu_frame = Frame::window_update(0, 4096).unwrap();
        assert!(server_session.process_inbound_frame(wu_frame).await.is_ok());

        // WindowUpdate for stream
        let wu_stream = Frame::window_update(1, 2048).unwrap();
        assert!(server_session
            .process_inbound_frame(wu_stream)
            .await
            .is_ok());

        // GoAway
        let goaway = Frame::goaway(0, 0).unwrap();
        assert!(server_session.process_inbound_frame(goaway).await.is_ok());
        assert!(server_session.is_closed());
    }

    #[tokio::test]
    async fn test_mux_session_open_with_priority_and_bidirectional_fin() {
        let (_client_io, server_io) = duplex(1024 * 1024);
        let (server_session, _server_handle) = MuxSession::new(server_io, MuxConfig::server());

        // Inbound OPEN with priority tag 0x05
        let tlvs = vec![qt_proto::Tlv::new_u8(open_tags::PRIORITY, 3).unwrap()];
        let open_frame = Frame::open(7, &tlvs, Some(3)).unwrap();
        assert!(server_session
            .process_inbound_frame(open_frame)
            .await
            .is_ok());

        // Verify stream handle created with priority 3
        let stream = server_session
            .stream_handles
            .lock()
            .get(&7)
            .cloned()
            .unwrap();
        assert_eq!(stream.priority(), 3);

        // Server sends local FIN
        server_session
            .streams
            .lock()
            .get_mut(&7)
            .unwrap()
            .transition_send(FrameType::Fin)
            .unwrap();

        // Remote FIN arrives
        let fin_frame = Frame::fin(7).unwrap();
        assert!(server_session
            .process_inbound_frame(fin_frame)
            .await
            .is_ok());

        // Stream should now be closed, removed, and tombstoned
        assert!(server_session.stream_handles.lock().get(&7).is_none());
        assert!(server_session.tombstones.lock().is_tombstoned(7));
    }

    #[tokio::test]
    async fn test_mux_session_hello_handshake_frames() {
        let (_client_io, server_io) = duplex(1024 * 1024);
        let (server_session, _server_handle) = MuxSession::new(server_io, MuxConfig::server());

        // Server receives HELLO and generates HELLO_ACK
        let hello = Frame::hello("test-agent", 16384, 65536, 0).unwrap();
        assert!(server_session.process_inbound_frame(hello).await.is_ok());

        let ack = server_session.scheduler.lock().dequeue().unwrap();
        assert_eq!(ack.header.ty, FrameType::HelloAck);

        // Client receives HELLO_ACK
        let (client_io, _server_io) = duplex(1024 * 1024);
        let (client_session, _client_handle) = MuxSession::new(client_io, MuxConfig::client());
        assert!(client_session.process_inbound_frame(ack).await.is_ok());
    }

    #[tokio::test]
    async fn test_mux_session_large_data_connection_window_update() {
        let (_client_io, server_io) = duplex(1024 * 1024);
        let mut cfg = MuxConfig::server();
        cfg.connection_window = 1000;
        let (server_session, _server_handle) = MuxSession::new(server_io, cfg);

        // Open stream 3
        let open_frame = Frame::open(3, &[], None).unwrap();
        server_session
            .process_inbound_frame(open_frame)
            .await
            .unwrap();

        // Feed data exceeding 50% threshold of connection window (1000 / 2 = 500)
        let large_data = Frame::data(3, bytes::Bytes::from(vec![1u8; 600]), false).unwrap();
        assert!(server_session
            .process_inbound_frame(large_data)
            .await
            .is_ok());

        // Check if WINDOW_UPDATE for stream 0 was enqueued
        let queued = server_session.scheduler.lock().dequeue().unwrap();
        assert_eq!(queued.header.ty, FrameType::WindowUpdate);
        assert_eq!(queued.header.stream_id, 0);
    }

    #[tokio::test]
    async fn test_mux_session_accept_waiter_woken_by_client_open() {
        let (client_io, server_io) = duplex(1024 * 1024);
        let (client_session, client_handle) = MuxSession::new(client_io, MuxConfig::client());
        let (server_session, server_handle) = MuxSession::new(server_io, MuxConfig::server());

        tokio::spawn(async move {
            let _ = client_session.run().await;
        });
        tokio::spawn(async move {
            let _ = server_session.run().await;
        });

        // Server calls accept_stream BEFORE client has opened any stream
        let accept_fut = tokio::spawn(async move { server_handle.accept_stream().await.unwrap() });

        tokio::time::sleep(Duration::from_millis(20)).await;

        // Client opens stream
        let _client_stream = client_handle.open_stream().await.unwrap();

        // Server accept completes
        let server_stream = accept_fut.await.unwrap();
        assert_eq!(server_stream.id(), 1);
    }

    #[tokio::test]
    async fn test_mux_session_ping_cancellation() {
        let (client_io, server_io) = duplex(1024 * 1024);
        drop(server_io); // server drops immediately
        let (client_session, client_handle) = MuxSession::new(client_io, MuxConfig::client());
        tokio::spawn(async move {
            let _ = client_session.run().await;
        });

        // Ping should fail because peer dropped
        let res = client_handle.ping().await;
        assert!(res.is_err());
    }
}
