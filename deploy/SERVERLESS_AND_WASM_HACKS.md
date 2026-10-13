# QuickTunnel Serverless, WASM & Edge Deployment Architecture

This document documents reverse-engineered, zero-cost, and non-traditional deployment patterns for QuickTunnel on serverless and edge platforms (Vercel, Cloudflare Workers, WebAssembly, and WebRTC).

---

## 1. The Serverless Challenge

Traditional reverse tunnel systems (like ngrok, FRP, or native QuickTunnel) require:
1. A long-lived, stateful process.
2. A raw TCP socket listener on an arbitrary port (e.g. `0.0.0.0:7000`).

Standard serverless platforms (e.g., Vercel, AWS Lambda) enforce:
- **Stateless execution**: Handlers are killed after 15–60 seconds.
- **HTTP/S ingress only**: Inbound connections can only arrive via HTTP/HTTPS on port 80/443.
- **No arbitrary inbound TCP listeners**: You cannot bind a raw `TcpListener` on port 7000.

Below are four engineering solutions to circumvent these limitations.

---

## 2. Architecture Patterns

### Pattern A: The Vercel "Suspended Promise" HTTP Relay (Pure Serverless)

Enables reverse tunneling through Vercel serverless functions without raw TCP sockets.

```
[ Visitor ]                              [ Vercel Edge Function ]                    [ Local Machine ]
     │                                              │                                        │
     │ 1. GET /api/users                            │                                        │
     │─────────────────────────────────────────────>│ (Holds visitor request open            │
     │                                              │  in a suspended Promise)               │
     │                                              │                                        │
     │                                              │ 2. Pushes request event over SSE       │
     │                                              │───────────────────────────────────────>│
     │                                              │                                        │ (Hits localhost:3000)
     │                                              │ 3. POST /tunnel/response               │
     │                                              │<───────────────────────────────────────│
     │ 4. Resolves Promise with response body       │
     │<─────────────────────────────────────────────│
```

#### How it Works:
1. **Long-Lived Ingress via SSE**: The local client connects to Vercel via a streaming Server-Sent Events endpoint (`GET /tunnel/stream`).
2. **Request Interception**: An incoming visitor request to `https://my-app.vercel.app/*` is assigned a unique transaction ID (ULID).
3. **Suspended Execution**: The Vercel function pushes the request metadata (method, headers, body) down the SSE stream and awaits an async event (e.g. via an in-memory queue or Upstash Redis pub/sub).
4. **Local Execution**: The client receives the event, forwards it to `http://localhost:3000`, captures the response, and POSTs it back to `/tunnel/response`.
5. **Visitor Unblock**: The suspended Promise resolves, writing the status code, headers, and body back to the visitor.

---

### Pattern B: Cloudflare Workers + WebSockets + Rust WASM

Cloudflare Workers supports long-lived WebSockets (Durable Objects / Hibernatable WebSockets) and native WebAssembly execution.

```
[ Visitor ] ──── HTTPS ────► [ Cloudflare Worker (WASM) ] ◄──── WebSocket ──── [ QuickTunnel Client ]
                              (Runs qt-proto in V8 isolate)                     (Your local machine)
```

#### How it Works:
1. **`qt-proto` in WebAssembly**: `qt-proto` is deliberately I/O-free and compiles directly to `wasm32-unknown-unknown` without operating system dependencies.
2. **Tunneling over WebSockets**: The client opens an outbound connection to `wss://tunnel.yourworker.dev/connect`. QuickTunnel QTP v1 binary frames are wrapped directly into WebSocket binary payloads (`OpCode::Binary`).
3. **Edge Multiplexing**: The Cloudflare Worker parses incoming HTTP visitor requests, frames them into QTP stream packets using the WASM module, and writes them down the WebSocket.
4. **Hibernation**: While idle, Cloudflare hibernates the WebSocket at 0 CPU cost.

---

### Pattern C: WebRTC DataChannels with Vercel Signaling (Direct P2P)

Establishes a direct peer-to-peer UDP connection between the client and visitors, bypassing all intermediary server bandwidth.

```
[ Visitor / Phone ]                                    [ Vercel ]                        [ Local Machine ]
         │                                                 │                                     │
         │ 1. Request SDP Offer                            │                                     │
         │────────────────────────────────────────────────>│ 2. Deliver Offer                    │
         │                                                 │────────────────────────────────────>│
         │                                                 │ 3. Return SDP Answer                │
         │ 4. Deliver Answer                               │<────────────────────────────────────│
         │<────────────────────────────────────────────────│                                     │
         │                                                                                       │
         │════════════════════ Direct P2P WebRTC DataChannel (UDP / STUN) ═══════════════════════│
         │                     (HTTP requests streamed directly over P2P)                        │
```

#### How it Works:
1. Vercel acts purely as a stateless **signaling mailbox** (exchanging SDP offer/answer tokens).
2. The browser and the local machine negotiate an encrypted WebRTC DataChannel via Google/Cloudflare public STUN servers.
3. Requests and responses flow directly over UDP. Server cost is $0.00 and latency is optimal peer-to-peer.

---

### Pattern D: Zero-Cost Container Edge Platforms

If you want native Rust performance with raw TCP listeners without managing a traditional VPS:

| Platform | Free Tier Capability | QuickTunnel Setup |
| :--- | :--- | :--- |
| **Koyeb** | Free nano container instance | Deploys `deploy/Dockerfile` directly with automated HTTPS edge proxy. |
| **Fly.io** | Free allowance with public IPv4/IPv6 | Runs `quicktunnel server` with native TCP port 7000 exposed globally. |
| **Oracle Cloud** | Always Free Tier (4 ARM cores, 24 GB RAM) | Permanent VM running native Docker or systemd service configurations. |

---

## 3. Comparison Matrix

| Metric | Vercel SSE Relay | Cloudflare Workers + WASM | WebRTC P2P | Free Container Edge |
| :--- | :--- | :--- | :--- | :--- |
| **Server Cost** | $0 (Vercel Free) | $0 (CF Free) | $0 (Signaling only)| $0 |
| **Latency Overhead** | ~50–100ms | ~15–25ms | ~0ms (P2P direct) | ~5–10ms |
| **Protocol Support** | HTTP only | HTTP + WebSockets | Any byte stream | HTTP + Raw TCP |
| **Code Changes** | Adapter proxy needed | WebSocket framing layer | WebRTC client needed | **Zero** (Native binary) |
