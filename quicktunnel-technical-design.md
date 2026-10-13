# quicktunnel — Technical Design & Implementation Guide

A zero-config reverse tunnel that exposes a local TCP/HTTP service through a public server over a single multiplexed, encrypted connection. This document is the full engineering spec: architecture, wire protocol, flow control, scheduling, HTTP routing, TLS, auth, resilience, inspector UI, security, testing, benchmarking, and a milestone plan.

> Code samples are Rust/tokio flavored but the design is language-agnostic. Go equivalents are noted where they differ materially.

---

## Table of Contents

1. [Goals and Non-Goals](#1-goals-and-non-goals)
2. [System Overview](#2-system-overview)
3. [Wire Protocol (QTP v1)](#3-wire-protocol-qtp-v1)
4. [Stream State Machine](#4-stream-state-machine)
5. [Flow Control](#5-flow-control)
6. [Frame Scheduling and Fairness](#6-frame-scheduling-and-fairness)
7. [Session Layer: Handshake, Auth, Keepalive](#7-session-layer-handshake-auth-keepalive)
8. [Tunnel Modes: TCP and HTTP](#8-tunnel-modes-tcp-and-http)
9. [HTTP Routing and Protocol Correctness](#9-http-routing-and-protocol-correctness)
10. [TLS Architecture](#10-tls-architecture)
11. [Server Internals](#11-server-internals)
12. [Client Internals](#12-client-internals)
13. [Resilience and Session Resumption](#13-resilience-and-session-resumption)
14. [Inspector Dashboard and Replay](#14-inspector-dashboard-and-replay)
15. [Security and Threat Model](#15-security-and-threat-model)
16. [Performance Engineering](#16-performance-engineering)
17. [Testing Strategy](#17-testing-strategy)
18. [Benchmark Plan](#18-benchmark-plan)
19. [Observability](#19-observability)
20. [Repository Layout and CLI](#20-repository-layout-and-cli)
21. [Milestone Plan](#21-milestone-plan)
22. [Known Pitfalls](#22-known-pitfalls)
23. [Stretch Goals](#23-stretch-goals)
24. [References](#24-references)

---

## 1. Goals and Non-Goals

### Goals

- Single static binary: `quicktunnel client ...` and `quicktunnel server ...`.
- One long-lived, encrypted connection per client; arbitrarily many concurrent proxied streams over it.
- Custom multiplexing protocol with per-stream flow control (not a wrapper around yamux/h2).
- Two tunnel modes: raw TCP (port per tunnel) and HTTP (host-based routing, subdomains).
- Live request inspector with replay.
- Survives network flaps without changing the public URL.
- Defensible security posture for a public-facing server.

### Non-Goals (v1)

- UDP tunneling.
- Multi-server clustering or global anycast.
- A hosted SaaS or billing system.
- Peer-to-peer NAT traversal (this is a relay, not hole punching).

---

## 2. System Overview

```
                        Internet
                           │
        ┌──────────────────┴───────────────────┐
        │   Public visitor / webhook sender    │
        └──────────────────┬───────────────────┘
                           │  https://abc.example.com  (or tcp://example.com:20001)
                           ▼
 ┌───────────────────────────────────────────────────────┐
 │                    quicktunnel server                  │
 │                                                        │
 │  ┌────────────┐   ┌──────────────┐   ┌──────────────┐  │
 │  │ Public     │──▶│ Router       │──▶│ Session      │  │
 │  │ listeners  │   │ (Host/SNI/   │   │ registry     │  │
 │  │ :80 :443   │   │  port)       │   │              │  │
 │  │ :20000+    │   └──────────────┘   └──────┬───────┘  │
 │  └────────────┘                             │          │
 │  ┌────────────┐                      ┌──────▼───────┐  │
 │  │ Control    │◀────────────────────▶│ Mux          │  │
 │  │ listener   │                      │ (frames,     │  │
 │  │ :7000 TLS  │                      │  windows,    │  │
 │  └────────────┘                      │  scheduler)  │  │
 │                                      └──────┬───────┘  │
 └─────────────────────────────────────────────┼──────────┘
                                               │  ONE TLS/TCP connection
                                               │  carrying N logical streams
 ┌─────────────────────────────────────────────┼──────────┐
 │                    quicktunnel client       │          │
 │                                      ┌──────▼───────┐  │
 │  ┌──────────────┐   ┌─────────────┐  │ Mux          │  │
 │  │ Local target │◀──│ Stream      │◀─│              │  │
 │  │ localhost:   │   │ dispatcher  │  └──────────────┘  │
 │  │ 8000         │   └──────┬──────┘                    │
 │  └──────────────┘          │                           │
 │                     ┌──────▼──────┐                    │
 │                     │ Inspector   │  http://localhost:4040
 │                     │ (capture +  │                    │
 │                     │  replay)    │                    │
 │                     └─────────────┘                    │
 └────────────────────────────────────────────────────────┘
```

### Request lifecycle (HTTP mode)

1. Client dials server `:7000`, completes TLS, performs QTP handshake and authenticates.
2. Client sends `REGISTER` on control stream: "give me an HTTP tunnel, subdomain `abc`".
3. Server records `abc.example.com → session #17` and replies with the public URL.
4. A visitor connects to `:443`. Server reads SNI/Host, finds session #17.
5. Server allocates a new stream ID, sends `OPEN` to the client, then pumps visitor bytes as `DATA` frames.
6. Client receives `OPEN`, dials `127.0.0.1:8000`, pumps local bytes back as `DATA` frames.
7. Either side half-closes with `FIN`; both sides send `FIN` (or either sends `RST`) and the stream is reaped.

---

## 3. Wire Protocol (QTP v1)

QTP (QuickTunnel Protocol) runs on top of a reliable, ordered, encrypted byte stream (TLS over TCP). All integers are **big-endian** (network order).

### 3.1 Frame header (12 bytes)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+---------------+---------------+-------------------------------+
|   Type (u8)   |   Flags (u8)  |        Reserved (u16 = 0)     |
+---------------+---------------+-------------------------------+
|                        Stream ID (u32)                        |
+---------------------------------------------------------------+
|                        Length (u32)                           |
+---------------------------------------------------------------+
|                        Payload (Length bytes)                 |
+---------------------------------------------------------------+
```

- **Length** is payload length only. Receivers MUST reject `Length > MAX_FRAME_PAYLOAD` (default **16 384**; negotiated up to 1 MiB) with `GOAWAY(PROTOCOL_ERROR)`. This bound is a security control, not just a performance one.
- **Reserved** MUST be zero on send and ignored on receive (future extension).
- **Stream ID 0** is the connection/control scope.

### 3.2 Stream ID allocation

| Initiator | IDs                | Notes                                           |
|-----------|--------------------|-------------------------------------------------|
| Client    | odd (1, 3, 5, …)   | Used for control RPCs (e.g. `REGISTER`).        |
| Server    | even (2, 4, 6, …)  | Used for inbound visitor connections.           |

IDs are strictly increasing per initiator and never reused. Upon reaching `2^31`, the session sends `GOAWAY` and the client reconnects. Receiving an `OPEN` for an ID that is not greater than the last-seen ID of that initiator is a protocol error.

### 3.3 Frame types

| Code | Name            | Stream ID | Payload                         | Purpose                                    |
|------|-----------------|-----------|---------------------------------|--------------------------------------------|
| 0x00 | `DATA`          | >0        | raw bytes                       | Application bytes for a stream             |
| 0x01 | `OPEN`          | >0        | `OpenPayload` (TLV)             | Create a stream                            |
| 0x02 | `WINDOW_UPDATE` | ≥0        | `u32` credit delta              | Grant additional send credit               |
| 0x03 | `FIN`           | >0        | empty                           | Sender will send no more data (half-close) |
| 0x04 | `RST`           | >0        | `u32` error code                | Abort stream immediately                   |
| 0x05 | `PING`          | 0         | `u64` opaque                    | Liveness / RTT measurement                 |
| 0x06 | `PONG`          | 0         | `u64` echoed opaque             | Response to `PING`                         |
| 0x07 | `GOAWAY`        | 0         | `u32` last_stream_id, `u32` err | Graceful shutdown / fatal protocol error   |
| 0x08 | `HELLO`         | 0         | `Hello` (TLV)                   | Handshake initiation (client → server)     |
| 0x09 | `HELLO_ACK`     | 0         | `HelloAck` (TLV)                | Handshake reply with challenge             |
| 0x0A | `AUTH`          | 0         | `Auth` (TLV)                    | Challenge response                         |
| 0x0B | `READY`         | 0         | `Ready` (TLV)                   | Auth accepted; session ID, limits          |
| 0x0C | `REGISTER`      | odd       | `Register` (TLV)                | Request a tunnel                           |
| 0x0D | `REGISTER_ACK`  | odd       | `RegisterAck` (TLV)             | Tunnel granted / denied                    |

### 3.4 Flags

| Bit  | Name  | Valid on          | Meaning                                              |
|------|-------|-------------------|------------------------------------------------------|
| 0x01 | `ACK` | `PING`/`PONG`     | Marks reply (redundant with type, kept for symmetry) |
| 0x02 | `FIN` | `DATA`            | Last data on this stream (saves a frame)             |
| 0x04 | `PRIO`| `OPEN`            | Payload carries a priority hint                      |

### 3.5 Error codes

| Code | Name                   | Meaning                                       |
|------|------------------------|-----------------------------------------------|
| 0    | `NO_ERROR`             | Graceful                                      |
| 1    | `PROTOCOL_ERROR`       | Malformed frame, illegal state transition     |
| 2    | `FLOW_CONTROL_ERROR`   | Peer sent beyond window                       |
| 3    | `STREAM_REFUSED`       | Rejected before processing (limits, backend)  |
| 4    | `CONNECT_FAILED`       | Client could not reach local target           |
| 5    | `CANCEL`               | Visitor/local side went away                  |
| 6    | `INTERNAL_ERROR`       | Unexpected condition                          |
| 7    | `AUTH_FAILED`          | Authentication failure                        |
| 8    | `RATE_LIMITED`         | Quota exceeded                                |
| 9    | `TIMEOUT`              | Idle/handshake timeout                        |

### 3.6 TLV encoding for structured payloads

Control payloads use simple Type-Length-Value fields: `tag:u8, len:u16, value`. Unknown tags are skipped (forward compatibility). Example `OpenPayload`:

| Tag  | Field            | Type        |
|------|------------------|-------------|
| 0x01 | `peer_addr`      | string (visitor IP:port) |
| 0x02 | `sni_or_host`    | string      |
| 0x03 | `tunnel_id`      | u32         |
| 0x04 | `proxy_protocol` | bytes (optional PROXY v2 header) |
| 0x05 | `priority`       | u8          |

### 3.7 Rust: header codec

```rust
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FrameType {
    Data = 0x00, Open = 0x01, WindowUpdate = 0x02, Fin = 0x03, Rst = 0x04,
    Ping = 0x05, Pong = 0x06, GoAway = 0x07, Hello = 0x08, HelloAck = 0x09,
    Auth = 0x0A, Ready = 0x0B, Register = 0x0C, RegisterAck = 0x0D,
}

#[derive(Debug, Clone)]
pub struct Header {
    pub ty: FrameType,
    pub flags: u8,
    pub stream_id: u32,
    pub len: u32,
}

pub const HEADER_LEN: usize = 12;
pub const DEFAULT_MAX_PAYLOAD: u32 = 16 * 1024;

impl Header {
    pub fn encode(&self, out: &mut [u8; HEADER_LEN]) {
        out[0] = self.ty as u8;
        out[1] = self.flags;
        out[2..4].copy_from_slice(&0u16.to_be_bytes());
        out[4..8].copy_from_slice(&self.stream_id.to_be_bytes());
        out[8..12].copy_from_slice(&self.len.to_be_bytes());
    }

    pub fn decode(buf: &[u8; HEADER_LEN], max_payload: u32) -> Result<Self, ProtoError> {
        let ty = FrameType::try_from(buf[0]).map_err(|_| ProtoError::UnknownType(buf[0]))?;
        let flags = buf[1];
        let stream_id = u32::from_be_bytes(buf[4..8].try_into().unwrap());
        let len = u32::from_be_bytes(buf[8..12].try_into().unwrap());
        if len > max_payload { return Err(ProtoError::FrameTooLarge(len)); }
        Ok(Self { ty, flags, stream_id, len })
    }
}
```

Use `tokio_util::codec::{Decoder, Encoder}` so partial reads are handled by `BytesMut` rather than hand-rolled buffering. In Go, wrap the `net.Conn` in a `bufio.Reader` and use `io.ReadFull`.

**Fuzz target:** `Header::decode` and every TLV parser. These parse attacker-controlled bytes before authentication.

---

## 4. Stream State Machine

Each stream has independent send and receive directions (like TCP half-close).

```
                         send OPEN / recv OPEN
            ┌──────┐   ───────────────────────▶   ┌──────┐
            │ Idle │                              │ Open │
            └──────┘                              └──┬───┘
                                    send FIN        │        recv FIN
                               ┌────────────────────┤────────────────────┐
                               ▼                    │                    ▼
                    ┌────────────────────┐          │         ┌────────────────────┐
                    │ HalfClosed(Local)  │          │         │ HalfClosed(Remote) │
                    └─────────┬──────────┘          │         └──────────┬─────────┘
                              │ recv FIN            │          send FIN  │
                              ▼                     │                    ▼
                           ┌────────┐   send/recv RST (from any state) ┌────────┐
                           │ Closed │◀─────────────┴───────────────────│ Closed │
                           └────────┘                                  └────────┘
```

Rules:

- `DATA` is legal in `Open` and `HalfClosed(Remote)` (we may still send) for send; `Open` and `HalfClosed(Local)` for receive.
- `RST` is legal in any non-`Idle` state; it frees buffers and releases the stream's window accounting immediately.
- After a stream enters `Closed`, keep a **tombstone** for a short period (e.g. 2×RTT or 5 s) so late `DATA`/`WINDOW_UPDATE` frames from the peer are dropped silently instead of triggering `PROTOCOL_ERROR`. Credit consumed by late `DATA` must still be returned at the connection level if you implement connection-level flow control.

### Mapping to socket events

| Socket event (local TCP)  | Protocol action                     |
|---------------------------|-------------------------------------|
| `read() == 0` (EOF)       | send `FIN` (half-close)             |
| `read()` error / RST      | send `RST(CANCEL)`                  |
| recv `FIN`                | `shutdown(SHUT_WR)` on the socket   |
| recv `RST`                | drop socket (set `SO_LINGER=0` to emit TCP RST) |

Propagating TCP RST vs FIN faithfully is what makes the tunnel "transparent" to protocols that care (e.g. databases, SSH).

---

## 5. Flow Control

Without flow control, one slow visitor can force the server to buffer unbounded data for a stream while a fast one is unaffected only by luck. Flow control is the heart of the multiplexer.

### 5.1 Credit-based windows (per stream)

- Every stream starts with `initial_window` bytes of **send credit** (default 256 KiB; negotiated in `HELLO`).
- A sender MUST NOT send `DATA` bytes exceeding its remaining credit.
- The receiver grants more credit via `WINDOW_UPDATE(stream_id, delta)` **after the application consumes data** (i.e. after the bytes are written to the destination socket), not when the frame is parsed. This ties network backpressure to the actual consumer speed.

```
sender                                receiver
  │  credit = 256K                      │  recv_window = 256K
  │──── DATA 16K ──────────────────────▶│  buffer; write to local socket
  │  credit = 240K                      │
  │──── DATA 16K ──────────────────────▶│
  │  ...                                │  socket drained 128K (≥ threshold)
  │◀─── WINDOW_UPDATE +128K ────────────│
  │  credit += 128K                     │
```

### 5.2 Update strategy

Don't send a `WINDOW_UPDATE` per frame, which would double frame count. Instead:

```
consumed_since_last_update += n
if consumed_since_last_update >= initial_window / 2 {
    send WINDOW_UPDATE(consumed_since_last_update);
    consumed_since_last_update = 0;
}
```

### 5.3 Connection-level window

Add a second window at stream 0 that bounds **total** in-flight bytes across all streams, protecting server memory regardless of stream count.

```
max_buffered_memory ≈ min(
    conn_window,
    max_streams × stream_window
)
```

A frame is sendable only if `stream_credit ≥ len && conn_credit ≥ len`. Receiver returns connection credit as soon as bytes leave the mux buffer for a stream's application queue, and stream credit when the application actually consumes them. (This is the same two-level design HTTP/2 uses.)

### 5.4 Window sizing and bandwidth-delay product

A single stream's max throughput is bounded by `window / RTT`.

| Window  | RTT 20 ms | RTT 100 ms | RTT 250 ms |
|---------|-----------|------------|------------|
| 64 KiB  | 25.6 Mbit/s | 5.2 Mbit/s | 2.1 Mbit/s |
| 256 KiB | 105 Mbit/s  | 21 Mbit/s  | 8.4 Mbit/s |
| 1 MiB   | 419 Mbit/s  | 84 Mbit/s  | 33.5 Mbit/s |

This is exactly why yamux's old 256 KiB default capped throughput on long fat links. **Experiment:** make the window adaptive. Measure RTT with `PING`, estimate throughput, and grow the window up to a cap (similar to TCP receive buffer autotuning). Document the before/after in your benchmark section.

### 5.5 Deadlock hazards

- **Window-update starvation:** `WINDOW_UPDATE` frames must bypass the data scheduler queue (or be put in a high-priority lane). Otherwise a full send queue prevents the grants that would drain it.
- **Control stream isolation:** never let data-stream backpressure block `PING`/`PONG`/`GOAWAY`. Keep a separate high-priority control queue.
- **Reader coupled to writer:** if the connection read loop awaits a full per-stream channel, one slow stream stalls the whole connection (head-of-line blocking *inside your process*). The read loop must never block on a single stream; flow control is what guarantees the per-stream queue cannot overflow (peer cannot send beyond the credit you granted), so use a bounded queue sized to the window and treat overflow as `FLOW_CONTROL_ERROR`.

### 5.6 Rust sketch: credit accounting

```rust
pub struct SendWindow {
    credit: AtomicI64,
    notify: tokio::sync::Notify,
}

impl SendWindow {
    /// Wait until at least 1 byte of credit is available, then take up to `want`.
    pub async fn acquire(&self, want: usize) -> usize {
        loop {
            let cur = self.credit.load(Ordering::Acquire);
            if cur > 0 {
                let take = cur.min(want as i64);
                if self.credit
                    .compare_exchange(cur, cur - take, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    return take as usize;
                }
                continue;
            }
            self.notify.notified().await;
        }
    }

    pub fn grant(&self, delta: u32) {
        let new = self.credit.fetch_add(delta as i64, Ordering::AcqRel) + delta as i64;
        // Overflow guard: HTTP/2 caps at 2^31-1
        if new > i32::MAX as i64 { /* RST(FLOW_CONTROL_ERROR) */ }
        self.notify.notify_waiters();
    }
}
```

---

## 6. Frame Scheduling and Fairness

All streams share one TCP write pipe. If you write frames in arrival order, a 2 GB upload will delay every small request behind it.

### 6.1 Architecture

```
 stream tasks                 writer task
┌───────────┐
│ stream 2  │─┐
├───────────┤ │   ┌────────────────────┐   ┌───────────┐   ┌────────────┐
│ stream 4  │─┼──▶│ per-stream queues  │──▶│ scheduler │──▶│ TLS/TCP    │
├───────────┤ │   └────────────────────┘   │ (DRR)     │   │ write half │
│ stream 6  │─┘   ┌────────────────────┐   └─────▲─────┘   └────────────┘
└───────────┘     │ control queue      │─────────┘ (strict priority)
                  └────────────────────┘
```

### 6.2 Policy

1. **Strict priority lane** for control frames: `PING`, `PONG`, `WINDOW_UPDATE`, `GOAWAY`, `RST`.
2. **Deficit Round Robin (DRR)** among data streams:
   - Each stream has a `deficit` counter and a `quantum` (e.g. 16 KiB).
   - On its turn, a stream may send frames while `deficit ≥ frame_len`; deficit is replenished by `quantum` each round.
   - Cost: O(1) per frame; gives byte-fair sharing regardless of frame size.
3. **Max frame payload** of 16 KiB bounds how long any one frame holds the pipe (at 10 Mbit/s uplink, 16 KiB ≈ 13 ms, which is tolerable; 1 MiB would be ~800 ms of head-of-line blocking).
4. Optional **priority weights** via the `OPEN` priority hint (inspector replay or small API calls get weight 4; bulk gets weight 1).

### 6.3 Write coalescing

Many tiny frames → many small `write()` calls → TLS record overhead and syscalls. The writer should:

- Gather up to N frames (or ≤ 64 KiB) into a single buffer / `writev` before flushing.
- Wrap the socket in `BufWriter`, flush when the queue drains or the buffer fills.
- Beware Nagle × delayed-ACK interaction: set `TCP_NODELAY` on the tunnel socket and rely on your own coalescing.

### 6.4 Measuring fairness

Test: start one 1 GiB upload stream and measure p50/p99 latency of a 1 KiB request on a second stream. Compare:

| Scheduler       | Expected p99 of small request |
|-----------------|-------------------------------|
| FIFO            | seconds (blocked behind bulk) |
| Round robin     | tens of ms                    |
| DRR + 16K frame | ≈ RTT + a few frame times     |

Include this graph in your write-up. It is the clearest demonstration of understanding multiplexing.

---

## 7. Session Layer: Handshake, Auth, Keepalive

### 7.1 Handshake sequence

```
Client                                              Server
  │──────── TCP connect + TLS handshake ───────────▶│
  │                                                  │
  │── HELLO{ver=1, client_id, caps, want_window} ───▶│
  │◀─ HELLO_ACK{ver=1, nonce(32B), caps, max_frame} ─│
  │── AUTH{HMAC-SHA256(token, nonce‖client_id)} ────▶│
  │◀─ READY{session_id, resume_secret, limits} ──────│
  │                                                  │
  │── REGISTER{mode=http, subdomain="abc"} (id=1) ──▶│
  │◀─ REGISTER_ACK{url="https://abc.example.com"} ───│
```

- **Version negotiation:** server picks `min(client_max, server_max)`; if unsupported → `GOAWAY(PROTOCOL_ERROR)`.
- **Capability negotiation:** bitset (e.g. `CAP_COMPRESSION`, `CAP_PROXY_PROTOCOL`, `CAP_RESUME`).
- **Challenge-response auth** (bore uses a similar scheme): the secret never crosses the wire even if TLS were somehow stripped; the nonce prevents replay. Compare MACs using a constant-time comparison (`subtle::ConstantTimeEq` / `hmac.Equal`).
- **Handshake deadline:** 5 s from TCP accept to `READY`, else close. This blocks slowloris on the control port.
- Pre-auth, the server must allocate **no per-client state beyond the socket**, and parse only `HELLO` and `AUTH`.

### 7.2 Token model

Phase 1: single shared secret (`--secret`) like bore.
Phase 2: per-user tokens stored as `argon2id(token)` or as HMAC keys; each token carries limits (max tunnels, bandwidth, allowed subdomain prefix, expiry).
Phase 3 (stretch): mTLS client certs with the cert fingerprint mapped to an identity.

### 7.3 Keepalive and dead-peer detection

TCP keepalive alone is not enough (it detects dead peers in minutes, and middleboxes drop idle NAT mappings in 30–120 s).

- Each side sends `PING(nonce=monotonic_ns)` after `idle_interval` (default 15 s) with no inbound frames.
- If no frame (any frame, not just `PONG`) arrives within `dead_timeout` (default 45 s = 3× interval), declare the peer dead and close.
- `PONG` echoes the nonce; the sender computes **RTT = now − nonce** and keeps an EWMA: `srtt = 0.875·srtt + 0.125·sample`. Expose it in the dashboard and use it for adaptive windows.
- Jitter the ping interval ±10% to avoid synchronized storms from many clients.

### 7.4 Graceful shutdown

`GOAWAY(last_stream_id, NO_ERROR)`:

1. Sender stops accepting new streams (server stops routing new visitors to this session).
2. Streams with ID ≤ `last_stream_id` continue to completion.
3. After a drain deadline (e.g. 30 s) remaining streams are `RST`'d and the connection closes.

This gives zero-downtime server restarts when paired with client auto-reconnect.

---

## 8. Tunnel Modes: TCP and HTTP

### 8.1 TCP mode (bore-style)

```
quicktunnel client --mode tcp --local 5432 --to tunnel.example.com
→ tcp://tunnel.example.com:20431
```

- Server binds a listener on a port from a configured range (`20000–29999`) per registered tunnel (random or requested).
- Each accepted connection → `OPEN` stream → client dials local target.
- Works for any protocol (SSH, Postgres, game servers, Redis) because the server never interprets bytes.
- **Port exhaustion & abuse:** cap tunnels per token; unbind on session death; reserve ports through a lease table.

### 8.2 HTTP mode (ngrok-style)

```
quicktunnel client --mode http --local 3000 --subdomain myapp --to tunnel.example.com
→ https://myapp.tunnel.example.com
```

- Server shares ports 80/443 across all tunnels and routes by hostname.
- Subdomain allocation: random 8-char base32 by default; user-requested names validated against `^[a-z0-9]([a-z0-9-]{1,61}[a-z0-9])$`, reserved list (`www`, `api`, `admin`, …), and token ownership.
- Wildcard DNS `*.tunnel.example.com → server IP` is the only DNS config required.

### 8.3 Choosing routing layer

| Method            | Terminates TLS? | Can inspect HTTP? | E2E encrypted? | Notes |
|-------------------|-----------------|-------------------|----------------|-------|
| Host header       | Server (must)   | Yes               | No             | Needed for inspector with server-side data, redirects, error pages |
| TLS SNI passthrough | No            | No                | Yes            | Server only reads the ClientHello; client terminates TLS |
| Port per tunnel   | n/a             | No                | Depends        | TCP mode |

Support both HTTP-termination (default; works with ACME-issued wildcard cert) and **SNI passthrough** (`--passthrough`; client holds the cert). Passthrough is a good conceptual exercise: you parse only the ClientHello's `server_name` extension (see §10.3) and never see plaintext.

---

## 9. HTTP Routing and Protocol Correctness

The server in HTTP mode must understand just enough HTTP to route; the more it parses, the more attack surface and bugs it has. Decide the depth deliberately.

### 9.1 Minimum viable approach: peek, route, splice

1. Accept visitor connection; read bytes into a bounded buffer (8 KiB) until the end of the first request's headers (`\r\n\r\n`) or limit exceeded (`431`).
2. Parse with `httparse` (Rust) / `net/http` + `bufio.Reader.Peek` (Go) to extract `Host`.
3. Look up the tunnel; if absent → `404` branded error page; if the session is down → `502`.
4. Open the QTP stream; write the already-buffered bytes as the first `DATA`; from then on, **blind-copy** both directions.

This handles keep-alive, chunked bodies, WebSockets, `Upgrade`, `CONNECT`-style streaming and HTTP/1.0 uniformly because after routing the proxy is just a pipe.

**Limitation:** with keep-alive, a second request on the same visitor connection may be for a different `Host`. Options: (a) accept and ignore (route by first request only; acceptable since browsers reuse connections per-origin), or (b) fully parse messages and route per request (see 9.2). Document your choice.

### 9.2 Full HTTP/1.1 message-aware proxying (for the inspector)

To capture request/response pairs, status codes, and timings, you must delimit messages:

- Request/response boundaries via `Content-Length`, `Transfer-Encoding: chunked`, or connection close (responses only).
- `Expect: 100-continue`, `HEAD` (no body despite Content-Length), `204/304` (no body), `1xx` interim responses.
- **Upgrade (WebSocket):** after `101 Switching Protocols`, stop parsing and switch to opaque piping.
- Pipelining: respond in order; most clients don't pipeline but servers must not break.
- **Request smuggling defense:** reject requests with both `Content-Length` and `Transfer-Encoding`, duplicate/conflicting `Content-Length`, whitespace before colon in header names, and obsolete line folding. Read RFC 9112 §6 carefully. If you proxy messages, you are responsible for being at least as strict as the origin.

Where to do this parsing? Best answer: **on the client**, inside the inspector tap (the server stays a dumb router; the user's own machine does the capture). The server forwards bytes; the client's local proxy parses a copy of the stream for the dashboard. This keeps server CPU/memory low and keeps payload data off the server's logs (a privacy win worth stating in your design doc).

### 9.3 Headers the server should add (HTTP termination mode)

- `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host` — or use the `Forwarded` header (RFC 7239).
- Strip any client-supplied versions of these to prevent spoofing.
- For TCP mode or passthrough, offer **PROXY protocol v2** so the local app can learn the visitor's real IP; carry it in `OpenPayload.proxy_protocol`.

### 9.4 Error pages

Return structured, cacheable-disabled responses:

| Condition                         | Status | Body                         |
|-----------------------------------|--------|------------------------------|
| Unknown subdomain                 | 404    | "tunnel not found"           |
| Session offline                   | 502    | "tunnel offline"             |
| Local target refused connection   | 502    | "origin unreachable" (from `RST(CONNECT_FAILED)`) |
| Timeout waiting for origin        | 504    |                              |
| Rate limited                      | 429    | `Retry-After`                |
| Oversized headers                 | 431    |                              |

### 9.5 Timeouts

| Timer                          | Default | Why |
|--------------------------------|---------|-----|
| Visitor header read            | 10 s    | Slowloris |
| OPEN → first byte from client  | 30 s    | Origin hung |
| Idle stream                    | 5 min   | Resource leak (disabled for WebSocket/upgraded streams) |
| Total handshake                | 5 s     | Control-port abuse |

---

## 10. TLS Architecture

Two separate TLS contexts exist; do not conflate them.

### 10.1 Tunnel TLS (client ↔ server on :7000)

- Server presents a certificate (Let's Encrypt for `tunnel.example.com` or self-signed with **certificate pinning** for private deployments).
- Library: `rustls` + `tokio-rustls` (Rust) or `crypto/tls` (Go). Set `min_version = TLS 1.2` (prefer 1.3 only), disable legacy ciphers (defaults in rustls already do).
- Client verification: system roots by default; `--pin-sha256 <hex>` pins the SPKI hash for self-signed servers; `--insecure` for local testing, with a loud warning.
- Optional: **mTLS**, server requires client certs signed by your CA for the control port.

### 10.2 Public TLS (visitor ↔ server on :443)

Options:

1. **Terminate at the server** with a wildcard certificate `*.tunnel.example.com`.
   - Requires ACME **DNS-01** challenge (HTTP-01 can't issue wildcards).
   - Use `instant-acme` (Rust), `lego`, or `autocert` (Go; HTTP-01/TLS-ALPN-01 only, so per-subdomain on-demand certs).
   - Implement a `ResolvesServerCert` that selects certs by SNI and hot-reloads on renewal with no restart (store in `ArcSwap`).
2. **Per-subdomain on-demand certs** (Caddy style): issue on first request for a known-registered subdomain only (never for unregistered names; avoids Let's Encrypt rate limits and abuse).
3. **SNI passthrough** (§10.3): no server certificate involvement.

### 10.3 Parsing SNI for passthrough

You only need to read the TLS record layer + ClientHello:

```
TLS record: type=0x16 (handshake), version, length(u16)
 Handshake: type=0x01 (ClientHello), length(u24)
  client_version(2) random(32) session_id(1+n) cipher_suites(2+n)
  compression(1+n) extensions(2+n)
   ext: type=0x0000 (server_name), len, list_len, name_type=0x00, name_len, hostname
```

Peek (don't consume) the first record using a buffered reader, extract the hostname, then replay the buffered bytes into the tunnel stream. Edge cases: ClientHello fragmented across multiple TLS records, ECH (encrypted ClientHello) hides SNI (passthrough cannot route it; document this limitation), and QUIC/HTTP3 (not handled).

### 10.4 Cert management checklist

- [ ] Key storage with `0600` permissions.
- [ ] Automatic renewal at 2/3 of lifetime.
- [ ] OCSP stapling (nice-to-have).
- [ ] HSTS header on server-generated pages.
- [ ] Test with `testssl.sh` / SSL Labs; target A+.

---

## 11. Server Internals

### 11.1 Concurrency model (Rust/tokio)

```
main
├── control_listener task               accept loop on :7000
│     └── per-connection task           handshake → Session
├── public_http_listener task           :80 (redirect to https + ACME HTTP-01)
├── public_https_listener task          :443 → route → open stream
├── tcp_tunnel_listener tasks           one per allocated port
├── admin/metrics task                  :9090 (localhost only)
└── janitor task                        expire tombstones, leases, stale sessions
```

Each `Session` owns:

```rust
struct Session {
    id: SessionId,
    identity: Identity,
    tx: mpsc::Sender<Outbound>,          // into the writer/scheduler task
    streams: DashMap<StreamId, StreamHandle>,
    next_stream_id: AtomicU32,           // even IDs
    conn_window: SendWindow,
    stats: SessionStats,                 // bytes, streams, srtt
    tunnels: Vec<TunnelId>,
    shutdown: CancellationToken,
}
```

Three tasks per session:

1. **Reader:** `read_frame` loop → dispatch `DATA` to the stream's inbound queue, `WINDOW_UPDATE` to credit, `PING` → enqueue `PONG`, etc. **Never awaits on a stream queue** (see §5.5).
2. **Writer:** drains control queue + DRR scheduler → coalesces → writes to TLS.
3. **Keepalive/timer:** pings, deadlines, idle checks.

Per-stream: two tasks (`visitor → mux` and `mux → visitor`) or one task with `tokio::select!`. Use `tokio::io::split` on the visitor socket.

### 11.2 Registries

```rust
struct Registry {
    http: DashMap<Hostname, TunnelId>,
    tcp_ports: DashMap<u16, TunnelId>,
    tunnels: DashMap<TunnelId, TunnelEntry>,   // → session handle, limits, created_at
    reserved_names: DashMap<String, TokenId>,  // sticky subdomains
}
```

Lifecycle invariants (write these as tests):

- A hostname maps to at most one live tunnel.
- When a session dies, all its tunnels and TCP listeners are removed (unless held by a resumption lease, see §13).
- Registry mutation and listener binding are atomic from an observer's viewpoint (bind first, then publish; unpublish first, then close).

### 11.3 Backpressure from visitor to tunnel

Visitor reads must pause when the tunnel send credit is exhausted:

```rust
loop {
    let want = window.acquire(MAX_FRAME).await;      // blocks when credit is 0 → stops reading socket
    let n = visitor_rd.read(&mut buf[..want]).await?;
    if n == 0 { send_fin(); break; }
    scheduler.enqueue(stream_id, Data(buf[..n].to_vec()));
}
```

Because the task stops calling `read()`, the kernel receive buffer fills, TCP advertises a zero window to the visitor, and the visitor's sender slows. That's end-to-end backpressure across three TCP legs plus your mux, and it's worth drawing in your docs.

### 11.4 Limits (configurable)

| Limit                                  | Default |
|----------------------------------------|---------|
| Max concurrent control connections     | 10 000  |
| Max streams per session                | 256     |
| Max tunnels per token                  | 5       |
| Max header size (HTTP)                 | 16 KiB  |
| Max new streams / second / tunnel      | 100 (token bucket) |
| Bandwidth per session                  | optional token bucket |

---

## 12. Client Internals

### 12.1 Components

```
 ┌──────────────┐   ┌───────────────┐   ┌────────────────┐
 │ Config/CLI   │──▶│ Connection    │──▶│ Mux            │
 │ (clap/cobra) │   │ manager       │   │ (shared w/     │
 └──────────────┘   │ (reconnect)   │   │  server crate) │
                    └───────────────┘   └───────┬────────┘
                                                │ OPEN
                                         ┌──────▼───────┐
                                         │ Dispatcher   │ dial 127.0.0.1:PORT
                                         └──────┬───────┘
                                      ┌─────────┴─────────┐
                                      ▼                   ▼
                              ┌──────────────┐   ┌─────────────────┐
                              │ Raw pipe     │   │ HTTP tap        │
                              │ (TCP mode)   │   │ (parse + record)│
                              └──────────────┘   └────────┬────────┘
                                                          ▼
                                                  ┌───────────────┐
                                                  │ Inspector     │
                                                  │ store + web UI│
                                                  └───────────────┘
```

### 12.2 Dial behavior

- Connect to the local target with a short timeout (3 s). On failure: `RST(CONNECT_FAILED)` and record the failure in the dashboard.
- Optionally rewrite the `Host` header to `localhost:PORT` (`--host-header rewrite`), since many dev servers (Vite, Django `ALLOWED_HOSTS`) reject unknown hosts. This is one of ngrok's most-used flags.
- Support `--local https://localhost:8443` with `--insecure-local` for self-signed local TLS.
- Support non-localhost targets (`--local 192.168.1.10:80`) for tunneling a LAN device.

### 12.3 CLI output (non-interactive and TUI)

Minimal TUI (e.g. `ratatui`, `bubbletea`):

```
quicktunnel                                         (Ctrl+C to quit)

Status        online   (rtt 34ms)
Forwarding    https://myapp.tunnel.example.com → http://localhost:3000
Inspector     http://127.0.0.1:4040

HTTP Requests
─────────────────────────────────────────────────────────────
14:02:11  POST /webhooks/stripe        200 OK        42ms   1.2KB
14:02:09  GET  /api/users              304 Not Mod    8ms   0B
14:01:55  GET  /favicon.ico            404 Not Found  3ms   0B
```

`--log json` prints one JSON object per request for piping.

---

## 13. Resilience and Session Resumption

### 13.1 Reconnect with backoff and jitter

```
delay = min(cap, base * 2^attempt)
sleep(random(0, delay))        // "full jitter"
```

`base = 500 ms`, `cap = 30 s`. Reset `attempt` after the connection has been healthy for > 60 s. Full jitter avoids thundering-herd reconnects after a server restart (see AWS Architecture Blog, "Exponential Backoff and Jitter").

Distinguish failures:

| Failure                     | Action                                |
|-----------------------------|---------------------------------------|
| Network unreachable / timeout | Retry with backoff                  |
| `AUTH_FAILED`               | **Do not retry**; exit with message   |
| `GOAWAY(NO_ERROR)`          | Reconnect promptly (server restarting)|
| Subdomain taken             | Exit or fall back to random per flag  |

### 13.2 Keeping the public URL stable

Without resumption, a reconnect might lose the subdomain (taken by someone else in the window) and the URL changes, breaking webhook configs.

**Lease approach:**

1. `READY` includes `resume_secret` (random 32 B, stored only in client memory/disk).
2. On disconnect, the server keeps the tunnel registrations in a `Leased` state for `lease_ttl` (default 120 s) instead of deleting them. During the lease, visitors get `502 "tunnel reconnecting"` (or are **held briefly**, see below).
3. The client reconnects and sends `HELLO` with `resume_session_id` + `HMAC(resume_secret, nonce)`.
4. The server re-attaches the new connection to the old tunnels. The URL is unchanged.

Resume restores **tunnels, not in-flight streams**: TCP state of in-flight streams is lost, so they're `RST`. (Resuming mid-stream would require application-level acks and retransmit buffers, i.e. reimplementing TCP over TCP; document it as a deliberate non-goal.)

**Visitor hold-queue (optional):** park incoming visitors up to ~10 s during a lease so brief flaps are invisible to webhook senders. Bound the queue size.

### 13.3 Server restarts

- `SIGTERM` → stop accepting; broadcast `GOAWAY`; drain; exit.
- Optionally persist the lease table to disk (SQLite/sled) so a restarted server honors recent leases.
- For true zero-downtime upgrades: pass listening sockets to the new process (`SO_REUSEPORT` or systemd socket activation).

### 13.4 Failure injection checklist

| Fault                        | Tool                          | Expected behavior |
|------------------------------|-------------------------------|-------------------|
| 5% packet loss               | `tc qdisc add dev eth0 root netem loss 5%` | Throughput degrades; no stalls/deadlocks |
| 200 ms ± 50 ms latency       | `tc netem delay 200ms 50ms`   | Window autotune helps; keepalive doesn't false-trigger |
| Connection reset mid-transfer| `toxiproxy reset_peer`        | Client reconnects, URL stable |
| Half-open connection (blackhole) | `iptables -j DROP`        | Dead-peer detection within `dead_timeout` |
| Slow consumer                | local app sleeps on read      | Only that stream stalls (no HOL blocking) |
| Huge number of streams       | load test                     | New streams refused with `STREAM_REFUSED`, existing unaffected |

---

## 14. Inspector Dashboard and Replay

### 14.1 Capture pipeline

```
visitor bytes ─▶ tunnel ─▶ [HTTP tap] ─▶ local app
                              │
                              ├─▶ parser (httparse / net/http)
                              ├─▶ body buffer (≤ 1 MiB per message; truncate flag)
                              └─▶ event: {id, ts, req, resp, timings}
```

The tap is a **passive observer** in the data path: it must never alter or delay bytes. Implementation: copy the byte stream into a parser via a `tee`; parser errors only disable capture for that connection, never break forwarding.

### 14.2 Record schema

```json
{
  "id": "01J9...",                         // ULID: sortable, unique
  "started_at": "2026-10-11T08:32:11.123Z",
  "visitor_ip": "203.0.113.9",
  "request": {
    "method": "POST",
    "target": "/webhooks/stripe?x=1",
    "http_version": "HTTP/1.1",
    "headers": [["host","..."],["content-type","application/json"]],
    "body_ref": "b_8f2...",                // stored separately
    "body_size": 1203,
    "body_truncated": false
  },
  "response": {
    "status": 200,
    "headers": [...],
    "body_ref": "b_91c...",
    "body_size": 42
  },
  "timing": {
    "tunnel_open_ms": 1.4,                 // OPEN → client dial complete
    "ttfb_ms": 38.2,                       // request written → first response byte
    "total_ms": 41.9
  },
  "error": null
}
```

Preserve **header order and duplicates** as lists of pairs, not maps, since order matters for signature verification and debugging.

### 14.3 Storage

- In-memory ring buffer (last 1 000 records, 64 MiB total body cap), eviction by oldest.
- Optional persistence: SQLite with FTS5 for search over method/path/headers/body.
- Bodies content-addressed (SHA-256) for dedupe.

### 14.4 Web UI

Served from the client on `127.0.0.1:4040` only (bind loopback; never `0.0.0.0` by default).

Features:

- Live list via **Server-Sent Events** (`/events`) with no polling.
- Detail pane: headers table, body viewer with JSON pretty-print, form decoding, hex view for binary, gzip/br decompression based on `Content-Encoding`.
- Filter bar: `method:POST status:>=400 path:/webhooks`.
- **Copy as cURL**, copy as `fetch`.
- **Replay:** `POST /api/replay/{id}` re-sends the captured request to the local target (not through the tunnel) and records the new response next to the original. Options: edit headers/body before replay, replay N times, replay against a different local port.

Replay must handle: recalculating `Content-Length`, dropping hop-by-hop headers (`Connection`, `Transfer-Encoding`, `Upgrade`), and warning that signature-bearing webhooks (Stripe, GitHub) with timestamp tolerance windows may be rejected after replay. Stripe's `Stripe-Signature` includes a timestamp, so show a hint.

- **Diff view:** compare original vs. replay response.
- Embed static UI assets in the binary (`include_dir!` / `go:embed`) so it stays single-binary.

### 14.5 Security of the inspector

- Loopback only; require a random per-run token in the URL, or check `Host`/`Origin` to defeat **DNS rebinding** and cross-origin attacks from web pages open in the user's browser (a malicious page could otherwise `fetch('http://localhost:4040/api/replay/...')`).
- Redact `Authorization`, `Cookie`, and configurable header values in exports.

---

## 15. Security and Threat Model

### 15.1 Assets and actors

| Actor                  | Capabilities                                       |
|------------------------|----------------------------------------------------|
| Anonymous internet host| Connect to any public port; send arbitrary bytes   |
| Malicious tunnel user  | Valid token; wants to abuse bandwidth, hijack names, host phishing/malware |
| Network attacker (MITM)| Observe/modify traffic between client and server   |
| Malicious visitor      | Wants to reach other users' tunnels or the server's internals |
| Compromised local app  | Receives tunneled traffic; wants to pivot          |

### 15.2 Threats and mitigations

| # | Threat | Mitigation |
|---|--------|------------|
| T1 | Unauthenticated resource exhaustion on control port | Handshake deadline, pre-auth state cap, per-IP connection limit, cheap-to-verify auth first |
| T2 | Frame-parsing bugs (OOB, huge alloc) | Max frame length check *before* allocation, fuzzing, `#![forbid(unsafe_code)]` where possible |
| T3 | Slowloris on visitor sockets | Header read timeout, min throughput rule, connection caps per IP |
| T4 | Window abuse: peer ignores credit | Enforce credit on receive → `FLOW_CONTROL_ERROR`, close session |
| T5 | "Rapid reset"-style stream churn (OPEN+RST floods, cf. HTTP/2 CVE-2023-44487) | Token bucket on stream creation; count RSTs and `GOAWAY` abusers |
| T6 | Subdomain squatting/hijack | Names tied to token identity; lease & reserved list |
| T7 | Open relay for SSRF into the server's network | Client-side dialing only; **server never dials user-supplied addresses**. (The client connects to local targets; the server only forwards to existing sessions.) |
| T8 | Phishing/malware hosting | Interstitial warning page for first browser visit (ngrok-style), abuse report endpoint, per-token takedown, block-list of hostnames |
| T9 | Token theft | Argon2/HMAC at rest, token scoping, revocation, short-lived tokens in Phase 3 |
| T10 | MITM on tunnel | TLS 1.3, cert verification/pinning, challenge-response auth independent of TLS |
| T11 | Request smuggling via the inspector or header injection | Strict HTTP parsing (§9.2), strip hop-by-hop & `X-Forwarded-*` |
| T12 | Resource exhaustion via bandwidth | Per-session token-bucket shaping, monthly quotas |
| T13 | DNS rebinding on inspector | Loopback bind + Host/Origin checks + token |
| T14 | Memory disclosure across tenants | Zero buffers on stream free if pooling; never share a buffer between sessions; avoid `unsafe` pooling bugs |
| T15 | Timing side channel on auth | Constant-time MAC comparison; uniform error responses |
| T16 | Replay of AUTH | Server-chosen random nonce per connection |
| T17 | Sticky-resume hijack | Resume requires HMAC of resume_secret with fresh nonce |

### 15.3 Deployment hardening

- Run as an unprivileged user; bind `:80/:443` via `CAP_NET_BIND_SERVICE` or systemd socket activation.
- systemd sandboxing: `NoNewPrivileges=yes`, `ProtectSystem=strict`, `PrivateTmp=yes`, `MemoryMax=`, `LimitNOFILE=`.
- Raise `ulimit -n`; tune `net.core.somaxconn`, `net.ipv4.ip_local_port_range`.
- Fail2ban-style: temp-ban IPs after N auth failures.
- Structured audit log: auth success/failure, tunnel create/destroy, with IP & token ID (never tokens or payloads).

Publish this as `SECURITY.md` / `docs/threat-model.md` in the repo. It is a strong signal.

---

## 16. Performance Engineering

### 16.1 Where time goes

Per forwarded byte, the path is:

```
visitor socket → [kernel] → user buffer → frame buffer → TLS encrypt → [kernel] → server↔client wire
                                                      → TLS decrypt → frame parse → user buffer → [kernel] → local socket
```

At least 4 copies and 2 syscalls per hop per direction on the server alone. Target optimizations in order of payoff:

1. **Batching:** coalesce frames, `writev`, larger socket buffers → fewer syscalls and TLS records.
2. **Buffer reuse:** slab or `bytes::BytesMut` pool; avoid `Vec::new()` per frame. Measure allocations with `dhat`/`heaptrack`.
3. **Avoid copying payloads into frames:** `Bytes` is reference-counted; slice from the read buffer and enqueue without `memcpy`.
4. **TLS:** AES-GCM needs AES-NI/ARMv8 crypto (rustls uses `ring`/`aws-lc-rs`; check CPU flags). Consider kTLS (Linux in-kernel TLS) in the stretch phase.
5. **Zero-copy for non-multiplexed pass-through legs:** `tokio::io::copy_bidirectional` for the TCP-mode visitor legs when no inspection is involved; `splice(2)` between sockets via a pipe where applicable (cannot be used across the TLS+frame boundary since bytes must be transformed there; useful only on the visitor-side raw proxying, e.g. SNI passthrough between visitor and a local pipe).
6. **Socket tuning:** `TCP_NODELAY`, enlarged `SO_SNDBUF/SO_RCVBUF` for high BDP links, `TCP_CONGESTION=bbr` on the server for lossy long-haul clients.
7. **Multi-core:** tokio's multi-thread runtime is default; pin the number of worker threads; shard registries (DashMap) to reduce lock contention; consider `SO_REUSEPORT` with multiple accept loops.

### 16.2 Memory per connection

Budget and verify:

| Item | Approx |
|------|--------|
| Visitor socket kernel buffers | 2 × 128 KiB (tunable) |
| Per-stream inbound queue (bounded by window) | ≤ 256 KiB worst case, typically a few KiB |
| Task stacks/futures | ~ 2–10 KiB |
| Stream metadata | < 1 KiB |

Aim: 10 000 idle streams < 100 MiB. Measure, don't guess.

### 16.3 Compression (optional)

Per-frame zstd/LZ4 negotiated via capability. Compressing already-encrypted/compressed bodies wastes CPU; apply only to compressible content types, or sample the first frame's compressibility. Beware CRIME/BREACH-style side channels if compressing secrets and attacker-controlled data together in one context. Mention this in your docs if you implement it.

---

## 17. Testing Strategy

### 17.1 Unit tests

- Frame encode/decode round trip (property-based with `proptest`/`quickcheck`).
- State machine transitions: exhaustive table test (every state × every frame type → expected next state or error).
- Window accounting: credits never negative, never overflow, update thresholds.
- DRR scheduler: byte-share proportional to weight under saturation.
- TLV parser: unknown tags skipped; truncated TLVs rejected.

### 17.2 Property / model tests

Generate random sequences of actions (open, send N bytes, fin, rst, window update, delay) on two in-memory endpoints connected via `tokio::io::duplex` and assert invariants:

- Bytes received == bytes sent for every stream that closes cleanly, in order.
- No frame is accepted beyond credit.
- All resources (streams, tombstones, tasks) are released at the end (no leaks).
- Total buffered memory ≤ conn window.

### 17.3 Fuzzing

```
cargo fuzz run frame_decode
cargo fuzz run tlv_parse
cargo fuzz run http_head_parse   # your own wrapper, if any
cargo fuzz run sni_parse
```

Run in CI nightly with a persistent corpus; seed with real captures.

### 17.4 Integration tests

Spawn real server + client on loopback with ephemeral ports:

- HTTP echo origin; assert end-to-end responses for GET/POST/chunked/gzip.
- WebSocket echo through the tunnel (ping/pong, large messages).
- Server-sent events (long-lived streaming response).
- 1 000 concurrent requests.
- Large body (1 GiB) integrity via hash comparison.
- Origin down → 502; session down → 502; reconnect restores the URL.
- Auth failure paths; handshake timeout.

### 17.5 Chaos tests

Use `toxiproxy` between client and server (latency, bandwidth, slicer, reset_peer, timeout) and run the integration suite on top. `slicer` (fragmenting writes into 1-byte pieces) is great at exposing partial-read bugs in codecs.

### 17.6 Deterministic simulation (advanced)

Abstract the clock and network behind traits, then run the protocol under a deterministic simulator (e.g. `turmoil` for tokio, or your own virtual clock) to reproduce flaky timeout/backoff bugs from a seed. Shows serious engineering maturity.

### 17.7 CI

- `cargo fmt`, `clippy -D warnings`, `cargo deny` (licenses/advisories), `cargo audit`.
- Test matrix: Linux/macOS/Windows.
- Cross-compiled release artifacts (musl static for Linux) with checksums + signatures.
- Coverage (`cargo llvm-cov`), but prioritize protocol invariants over coverage numbers.

---

## 18. Benchmark Plan

Publish methodology and raw numbers. A benchmark without methodology is marketing.

### 18.1 Environment

- Two VMs (e.g. same region): server, and a combined client + load generator; plus a third machine for cross-region RTT tests. Record CPU model, kernel, `rustc` version, and flags (`--release`, LTO).
- Pin CPU governor to `performance`; disable turbo for variance control or report variance.

### 18.2 Metrics

| Metric | Tool | Notes |
|--------|------|-------|
| Bulk throughput (single stream) | `iperf3` over TCP-mode tunnel | Compare vs. direct, vs. `bore`, `chisel`, `frp`, `rathole` |
| Bulk throughput (N parallel streams) | `iperf3 -P 32` | Shows mux scaling |
| Request latency overhead | `wrk2` / `hey` with fixed RPS to a trivial origin | Report p50/p90/p99/p99.9 *with coordinated omission avoided* (wrk2 does this) |
| Small-request latency under bulk load | custom (§6.4) | **The fairness graph** |
| Connection establishment rate | `wrk -c`, new connection per request | Streams/second |
| Max concurrent streams | custom client | Until memory or latency degrades |
| Memory per idle stream | `/proc/PID/smaps`, `heaptrack` | |
| CPU per Gbit/s | `perf stat`, `pidstat` | |
| Reconnect time | script: kill link, time to restored traffic | Show jitter distribution |

### 18.3 Experiments worth including

1. **Window size sweep** (64 K / 256 K / 1 M / adaptive) × RTT (0, 20, 100, 250 ms) → throughput heatmap. Validates §5.4 with data.
2. **Frame size sweep** (4 K–256 K) → throughput vs. small-request p99 tradeoff.
3. **Scheduler comparison** (FIFO vs RR vs DRR).
4. **Own mux vs yamux vs h2** as pluggable backends.
5. **Packet loss** (0, 0.1, 1, 5%) × throughput. A single TCP connection suffers TCP-level head-of-line blocking: one lost packet stalls *all* streams. Discuss this honestly and describe how QUIC (stretch goal) addresses it.
6. **TLS cost:** throughput with and without encryption (loopback) to isolate crypto overhead.
7. **Flamegraphs:** `cargo flamegraph` / `perf record -g`; annotate top 5 hotspots and what you changed.

### 18.4 Reporting

Plot with consistent axes; include error bars from ≥ 5 runs; commit the scripts so they're reproducible (`bench/run.sh`, `bench/plot.py`).

---

## 19. Observability

### 19.1 Metrics (Prometheus on `127.0.0.1:9090/metrics`)

```
qt_sessions_active
qt_sessions_total{result="ok|auth_failed|timeout"}
qt_streams_active
qt_streams_total{mode="http|tcp",result="ok|refused|reset"}
qt_bytes_total{direction="in|out"}
qt_frame_total{type="data|window_update|..."}
qt_rtt_seconds (histogram)
qt_stream_duration_seconds (histogram)
qt_window_stall_seconds_total          # time senders spent blocked on credit
qt_scheduler_queue_depth (histogram)
qt_http_status_total{class="2xx|4xx|5xx"}
qt_reconnects_total (client)
```

`qt_window_stall_seconds_total` is especially insightful: it tells you whether performance is limited by window size (tune it) or by the origin.

### 19.2 Logging

- `tracing` (Rust) / `slog` (Go) with structured fields: `session_id`, `stream_id`, `tunnel`, `peer_ip`.
- Per-stream spans so a single request can be traced across tasks.
- Default level `info`; payloads **never** logged at any level by the server.

### 19.3 Debug tooling

- `quicktunnel debug dump-frames` — wire log in a readable format (also a Wireshark Lua dissector for QTP as a bonus; a custom protocol dissector is a great artifact).
- `tokio-console` for task introspection (stuck tasks, long polls).
- `SIGUSR1` dumps session/stream table.

---

## 20. Repository Layout and CLI

### 20.1 Layout (Cargo workspace)

```
quicktunnel/
├── Cargo.toml
├── crates/
│   ├── qt-proto/          # frame types, codec, TLV, error codes (no I/O, no tokio)
│   ├── qt-mux/            # session, streams, flow control, scheduler (generic over AsyncRead/Write)
│   ├── qt-server/         # listeners, registry, router, TLS, ACME, limits
│   ├── qt-client/         # connection manager, dispatcher, tap, inspector API
│   ├── qt-inspector-ui/   # static web assets (embedded)
│   └── quicktunnel/       # binary: CLI wiring (clap), subcommands
├── fuzz/                  # cargo-fuzz targets
├── bench/                 # scripts, load generators, plots
├── docs/
│   ├── protocol.md        # QTP spec (the wire format in §3, versioned)
│   ├── architecture.md
│   ├── threat-model.md
│   ├── benchmarks.md
│   └── decisions/         # ADRs: 0001-own-mux.md, 0002-tls-termination.md ...
├── tests/                 # integration & chaos tests
├── deploy/                # systemd unit, Dockerfile, docker-compose, Caddy/nginx examples
└── SECURITY.md
```

Keeping `qt-proto` free of I/O makes it trivially fuzzable and reusable (and enables a `wasm` build for an in-browser frame visualizer, if you like).

### 20.2 CLI

```
quicktunnel server
    --control-port 7000
    --domain tunnel.example.com
    --http-port 80 --https-port 443
    --tcp-port-range 20000-29999
    --secret <TOKEN> | --tokens-file tokens.toml
    --acme-email you@example.com --acme-dns-provider cloudflare
    --max-streams-per-session 256
    --config server.toml

quicktunnel client
    --to tunnel.example.com[:7000]
    --local 3000                       # or host:port, or https://host:port
    --mode http|tcp                    # default http
    --subdomain myapp                  # http mode
    --remote-port 20431                # tcp mode
    --secret <TOKEN>
    --host-header rewrite|preserve|<value>
    --inspect-port 4040 | --no-inspect
    --pin-sha256 <hex> | --insecure
    --passthrough                      # SNI passthrough, client terminates TLS
    --log pretty|json
    --config client.toml

quicktunnel debug dump-frames --file capture.qtcap
quicktunnel genkey                     # secure random token
```

Config precedence: flags > env (`QT_SECRET`) > config file > defaults. Never accept secrets only via CLI args in docs examples (they leak via `ps`); prefer env or file.

---

## 21. Milestone Plan

Estimates assume ~10–15 hrs/week. Adjust to taste.

| # | Milestone | Deliverable | Concepts learned | Est. |
|---|-----------|-------------|------------------|------|
| M0 | Foundations | Echo server, `copy_bidirectional` proxy, reading RFCs/yamux spec | async I/O, half-close | 3–4 d |
| M1 | Naive TCP tunnel | One TCP conn per forwarded stream (bore-like), shared-secret auth | control vs data channel | 1 wk |
| M2 | QTP v1 framing | `qt-proto` + codec + fuzz target; single mux connection, OPEN/DATA/FIN/RST | framing, state machine | 1–1.5 wk |
| M3 | Flow control | Per-stream + connection windows, WINDOW_UPDATE, deadlock tests | backpressure | 1 wk |
| M4 | Scheduler & keepalive | DRR, control priority lane, ping/RTT, dead-peer detect, coalesced writes | fairness, HOL blocking | 1 wk |
| M5 | HTTP routing | Host parsing, subdomain registry, error pages, WebSocket passthrough | HTTP semantics | 1 wk |
| M6 | TLS | rustls on control port, pinning, public TLS termination w/ wildcard via ACME DNS-01, SNI passthrough | PKI, ACME | 1.5 wk |
| M7 | Auth & limits | HMAC challenge-response, per-token limits, rate limits, handshake deadlines | threat modeling | 1 wk |
| M8 | Resilience | Reconnect + backoff + jitter, leases/resume, graceful drain, chaos tests | failure handling | 1 wk |
| M9 | Inspector | HTTP tap, ring buffer, SSE UI, replay, cURL export | HTTP parsing, UX | 1.5 wk |
| M10 | Observability | Metrics, tracing, debug dump | ops | 3–4 d |
| M11 | Benchmarks & tuning | All §18 experiments, flamegraphs, optimizations | perf engineering | 1.5 wk |
| M12 | Docs & release | Protocol spec, architecture, threat model, ADRs, release binaries, demo GIF | communication | 1 wk |

Total ≈ 12–14 weeks of part-time work for the full scope. A strong **MVP cut** is M0–M5 + basic TLS + auth (~6 weeks).

---

## 22. Known Pitfalls

1. **Read loop blocking on a slow stream** → whole connection stalls (§5.5).
2. **Sending `WINDOW_UPDATE` at parse time** instead of consume time → no real backpressure, unbounded memory.
3. **Window update frames queued behind data** → deadlock.
4. **Not handling half-close** → hangs on protocols where one side closes write first (HTTP/1.0 responses terminated by close, `nc`, `rsync`).
5. **TCP RST vs FIN conflation** → resets get turned into clean EOFs, silently truncating data.
6. **Nagle + small frames** → 40 ms latency spikes; use `TCP_NODELAY` and manual coalescing.
7. **Per-request `Host` assumption with keep-alive** (§9.1).
8. **Tombstone-less closed streams** → late frames kill the session with a spurious protocol error.
9. **Stream ID exhaustion / reuse** → never reuse; renegotiate by reconnecting.
10. **Unbounded channels** (`mpsc::unbounded_channel`) anywhere in the data path = hidden memory leak under slow consumers.
11. **Task leaks:** spawn tasks tied to a `CancellationToken`/`JoinSet`; verify that after session close, task count returns to baseline.
12. **TLS close_notify:** treat missing `close_notify` as truncation for protocols that need it; log but don't crash.
13. **Clock misuse:** use monotonic time for timeouts/RTT, never wall-clock.
14. **Integer overflow in windows** (HTTP/2 specifies a 2³¹−1 max for good reason).
15. **Inspector DNS rebinding** (§14.5).
16. **Trusting `X-Forwarded-*` from visitors.**
17. **Windows/macOS socket differences** (`SO_REUSEPORT`, half-close semantics); test the matrix early.
18. **ACME rate limits** during development: use the Let's Encrypt **staging** environment until the flow is stable.

---

## 23. Stretch Goals

| Idea | What it teaches |
|------|-----------------|
| **QUIC transport backend** (`quinn`), mapping QTP streams to QUIC streams | Eliminates TCP-level HOL blocking; 0-RTT; connection migration for mobile clients |
| **Multi-path / multi-connection bonding** | Aggregating links, scheduling across paths |
| **kTLS / io_uring backend** (`tokio-uring`, `monoio`) | Kernel-level performance engineering |
| **Wireshark dissector** (Lua) for QTP | Protocol documentation, debugging |
| **Multi-server clustering**: consistent hashing of subdomains → server; gossip or Redis for the registry; visitor-side forwarding between nodes | Distributed systems |
| **UDP tunneling** (datagram frames, no flow control, MTU handling) | Unreliable transport semantics |
| **Built-in webhook mocking & request transformation rules** | Product thinking |
| **Access control on tunnels**: basic auth, OAuth proxy, IP allowlists per tunnel | Edge auth |
| **Traffic shaping simulator** in the dashboard (inject latency/errors for testing mobile conditions) | Developer tooling |
| **Formal model** of the flow-control/state machine in TLA+ or Quint | Model checking: prove no deadlock/overflow |
| **Deterministic simulation testing** (FoundationDB-style) | Testing rigor |
| **Plugin interface via WASM** for request filters | Sandboxing, extensibility |

---

## 24. References

**Protocols and specs**
- RFC 9112 — HTTP/1.1 (message framing, §6 body length, smuggling-relevant rules)
- RFC 9113 — HTTP/2 (frames, flow control §5.2, stream states §5.1)
- RFC 9110 — HTTP Semantics
- RFC 6455 — WebSocket
- RFC 8446 — TLS 1.3; RFC 6066 — TLS extensions (SNI)
- RFC 8555 — ACME; RFC 7239 — Forwarded header
- RFC 9000/9001/9002 — QUIC
- HAProxy PROXY protocol v1/v2 spec
- Yamux spec (`hashicorp/yamux/spec.md`) — closest design cousin to QTP
- SPDY/HTTP2 history; CVE-2023-44487 (HTTP/2 Rapid Reset) writeups

**Code to read**
- `ekzhang/bore` — minimal Rust TCP tunnel (great M1 reference)
- `jpillora/chisel` — Go, SSH-based mux over WebSocket
- `fatedier/frp` — feature-rich Go reverse proxy
- `rapiz1/rathole` — Rust, performance-focused
- `hashicorp/yamux`, `libp2p/rust-yamux` — multiplexer implementations
- `hyperium/h2` — a production HTTP/2 implementation in Rust (flow control module)
- `cloudflare/quiche`, `quinn-rs/quinn` — QUIC
- `rustls`, `tokio-rustls`, `instant-acme`

**Learning resources**
- *TCP/IP Illustrated, Vol. 1* (Stevens) — flow/congestion control foundations
- *High Performance Browser Networking* (Grigorik) — free online; TLS, HTTP/2, QUIC chapters
- *Computer Networking: A Top-Down Approach* — scheduling & queueing background
- AWS Architecture Blog: "Exponential Backoff and Jitter"
- Gil Tene, "How NOT to Measure Latency" (coordinated omission)
- Shreedhar & Varghese, "Efficient Fair Queuing using Deficit Round Robin"
- Tokio tutorial and `tokio-console` docs
- Cloudflare blog: TCP tuning, HTTP/2 Rapid Reset analysis

---

### Appendix A — Minimal end-to-end sequence (annotated)

```
t0   C→S  TLS ClientHello ... handshake complete
t1   C→S  HELLO        sid=0  len=..   ver=1 window=262144 caps=[RESUME]
t2   S→C  HELLO_ACK    sid=0  len=..   nonce=9f..  max_frame=16384
t3   C→S  AUTH         sid=0  len=32   mac=HMAC(tok, nonce‖client_id)
t4   S→C  READY        sid=0  len=..   session=17 resume_secret=.. limits=..
t5   C→S  REGISTER     sid=1  mode=http subdomain=myapp
t6   S→C  REGISTER_ACK sid=1  url=https://myapp.tunnel.example.com
          ── visitor GET /hook arrives at :443 ──
t7   S→C  OPEN         sid=2  peer=203.0.113.9:51234 host=myapp.tunnel...
t8   S→C  DATA         sid=2  "POST /hook HTTP/1.1\r\nHost: ..."   (≤16 KiB)
t9   C→S  DATA         sid=2  "HTTP/1.1 200 OK\r\n..."             
t10  S→C  WINDOW_UPDATE sid=2 +131072       (visitor body consumed)
t11  C→S  DATA|FIN     sid=2  last bytes of response
t12  S→C  FIN          sid=2                (visitor half-closed)
          stream 2 → Closed, tombstone for 5 s
t13  both PING/PONG every ~15 s while idle
```

### Appendix B — Design decision log (seed ADRs)

| ADR | Decision | Alternatives | Rationale |
|-----|----------|--------------|-----------|
| 0001 | Custom mux (QTP) | yamux, h2 | Learning goal; control over scheduling & window autotune; keep yamux/h2 as benchmark baselines |
| 0002 | 12-byte fixed header | varint headers (QUIC-like) | Simplicity, aligned parsing; overhead negligible vs. 16 KiB frames |
| 0003 | Credit-based per-stream + conn windows | TCP-like congestion control | Underlying TCP already does congestion control; mux needs only receiver-driven backpressure |
| 0004 | DRR scheduler, 16 KiB frames | FIFO / strict priority | Fairness with O(1) cost; bounded HOL latency |
| 0005 | Parse HTTP on the client tap, not the server | Server-side parsing | Privacy, lower server load, smaller attack surface |
| 0006 | Resume tunnels, not streams | Full stream resumption | Avoids reimplementing TCP-in-TCP; webhooks retry anyway |
| 0007 | HMAC challenge-response inside TLS | Bearer token in HELLO | Defense in depth; prevents replay and token exposure to TLS-terminating middleboxes |
| 0008 | Rust + tokio | Go | Depth on async/backpressure/ownership; Go noted as a viable alternative |

---

*End of document. Suggested next step: implement M1 and M2, then write `docs/protocol.md` from §3 before coding M3. Writing the spec first will expose ambiguities early.*
