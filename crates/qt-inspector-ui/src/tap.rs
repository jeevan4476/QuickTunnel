//! Passive HTTP tap pipeline for capturing HTTP traffic and feeding InspectorStore.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::store::InspectorStore;

pub const MAX_BODY_CAPTURE_SIZE: usize = 1024 * 1024; // 1 MiB
pub const DEFAULT_TAP_CHANNEL_CAPACITY: usize = 1024;
const MAX_HEADERS: usize = 128;

#[derive(Debug)]
enum TapMessage {
    Request {
        id: String,
        visitor_ip: SocketAddr,
        raw_bytes: Vec<u8>,
        start_time: std::time::SystemTime,
    },
    RequestBodyChunk {
        id: String,
        chunk: Vec<u8>,
    },
    Response {
        id: String,
        raw_bytes: Vec<u8>,
        total_ms: u64,
        ttfb_ms: u64,
    },
}

/// Handle for sending tapped HTTP traffic into the background processing actor.
#[derive(Clone, Debug)]
pub struct HttpTapSender {
    tx: tokio::sync::mpsc::Sender<TapMessage>,
}

impl HttpTapSender {
    /// Create a new tap sender and spawn its background worker actor with default channel capacity.
    pub fn new(store: Arc<InspectorStore>) -> (Self, tokio::task::JoinHandle<()>) {
        Self::with_capacity(store, DEFAULT_TAP_CHANNEL_CAPACITY)
    }

    /// Create a tap sender with custom channel capacity and spawn its background worker actor.
    pub fn with_capacity(
        store: Arc<InspectorStore>,
        capacity: usize,
    ) -> (Self, tokio::task::JoinHandle<()>) {
        let (tx, rx) = tokio::sync::mpsc::channel(capacity.max(1));
        let actor = HttpTap { store, rx };
        let handle = tokio::spawn(actor.run());
        (Self { tx }, handle)
    }

    /// Tap an inbound HTTP request. Returns the request ID if successfully parsed and enqueued.
    /// Non-blocking: if channel capacity is exhausted or parsing fails, drops without blocking.
    pub fn tap_request(&self, visitor_ip: SocketAddr, raw_bytes: &[u8]) -> Option<String> {
        let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
        let mut req = httparse::Request::new(&mut headers);
        match req.parse(raw_bytes) {
            Ok(httparse::Status::Complete(_)) => {}
            _ => return None,
        }

        let id = ulid::Ulid::generate().to_string();
        let msg = TapMessage::Request {
            id: id.clone(),
            visitor_ip,
            raw_bytes: raw_bytes.to_vec(),
            start_time: std::time::SystemTime::now(),
        };

        match self.tx.try_send(msg) {
            Ok(_) => Some(id),
            Err(_) => None,
        }
    }

    /// Append request body chunk for an in-flight request.
    /// Non-blocking: drops capture if channel is full.
    pub fn tap_request_body_chunk(&self, id: String, chunk: &[u8]) {
        let msg = TapMessage::RequestBodyChunk {
            id,
            chunk: chunk.to_vec(),
        };
        let _ = self.tx.try_send(msg);
    }

    /// Tap an outbound HTTP response.
    /// Non-blocking: drops capture if channel is full.
    pub fn tap_response(&self, id: String, raw_bytes: &[u8], duration: Duration) {
        self.tap_response_with_ttfb(id, raw_bytes, duration, duration);
    }

    /// Tap an outbound HTTP response with distinct total duration and TTFB.
    /// Non-blocking: drops capture if channel is full.
    pub fn tap_response_with_ttfb(
        &self,
        id: String,
        raw_bytes: &[u8],
        total_duration: Duration,
        ttfb: Duration,
    ) {
        let msg = TapMessage::Response {
            id,
            raw_bytes: raw_bytes.to_vec(),
            total_ms: total_duration.as_millis() as u64,
            ttfb_ms: ttfb.as_millis() as u64,
        };
        let _ = self.tx.try_send(msg);
    }
}

/// Background actor consuming tapped HTTP messages and feeding InspectorStore.
pub struct HttpTap {
    store: Arc<InspectorStore>,
    rx: tokio::sync::mpsc::Receiver<TapMessage>,
}

impl HttpTap {
    /// Run the actor loop until all sender handles are dropped.
    pub async fn run(mut self) {
        while let Some(msg) = self.rx.recv().await {
            match msg {
                TapMessage::Request {
                    id,
                    visitor_ip,
                    raw_bytes,
                    start_time,
                } => {
                    if let Some(req) = parse_request(&id, visitor_ip, &raw_bytes, start_time) {
                        self.store.add_request(req);
                    }
                }
                TapMessage::RequestBodyChunk { id, chunk } => {
                    self.store.append_request_body(&id, &chunk);
                }
                TapMessage::Response {
                    id,
                    raw_bytes,
                    total_ms,
                    ttfb_ms,
                } => {
                    if let Some(resp) = parse_response(&raw_bytes) {
                        self.store.record_response(&id, resp, total_ms, ttfb_ms);
                    }
                }
            }
        }
    }
}

fn parse_request(
    id: &str,
    visitor_ip: SocketAddr,
    raw_bytes: &[u8],
    start_time: std::time::SystemTime,
) -> Option<crate::store::CapturedRequest> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut req = httparse::Request::new(&mut headers);
    let offset = match req.parse(raw_bytes) {
        Ok(httparse::Status::Complete(offset)) => offset,
        _ => return None,
    };

    let method = req.method.unwrap_or("GET").to_string();
    let path = req.path.unwrap_or("/").to_string();
    let http_version = match req.version {
        Some(0) => "HTTP/1.0".to_string(),
        Some(1) => "HTTP/1.1".to_string(),
        Some(v) => format!("HTTP/1.{v}"),
        None => "HTTP/1.1".to_string(),
    };

    let mut parsed_headers = Vec::with_capacity(req.headers.len());
    let mut content_length: Option<usize> = None;
    for h in req.headers {
        if h.name.eq_ignore_ascii_case("Content-Length") {
            if let Ok(val_str) = std::str::from_utf8(h.value) {
                if let Ok(cl) = val_str.trim().parse::<usize>() {
                    content_length = Some(cl);
                }
            }
        }
        parsed_headers.push(crate::store::HeaderPair {
            name: h.name.to_string(),
            value: String::from_utf8_lossy(h.value).into_owned(),
        });
    }

    let body_slice = &raw_bytes[offset..];
    let (body, body_size, body_truncated) = if let Some(cl) = content_length {
        if body_slice.len() < cl {
            let body_str = if body_slice.is_empty() {
                None
            } else {
                Some(
                    String::from_utf8_lossy(
                        &body_slice[..body_slice.len().min(MAX_BODY_CAPTURE_SIZE)],
                    )
                    .into_owned(),
                )
            };
            (body_str, cl, true)
        } else if cl > MAX_BODY_CAPTURE_SIZE {
            (
                Some(String::from_utf8_lossy(&body_slice[..MAX_BODY_CAPTURE_SIZE]).into_owned()),
                cl,
                true,
            )
        } else if cl == 0 && body_slice.is_empty() {
            (None, 0, false)
        } else {
            (
                Some(String::from_utf8_lossy(&body_slice[..cl]).into_owned()),
                cl,
                false,
            )
        }
    } else if body_slice.is_empty() {
        (None, 0, false)
    } else if body_slice.len() > MAX_BODY_CAPTURE_SIZE {
        (
            Some(String::from_utf8_lossy(&body_slice[..MAX_BODY_CAPTURE_SIZE]).into_owned()),
            body_slice.len(),
            true,
        )
    } else {
        (
            Some(String::from_utf8_lossy(body_slice).into_owned()),
            body_slice.len(),
            false,
        )
    };

    Some(crate::store::CapturedRequest {
        id: id.to_string(),
        visitor_ip: visitor_ip.ip().to_string(),
        request: crate::store::RequestDetails {
            method,
            path,
            http_version,
            headers: parsed_headers,
            body,
            body_size,
            body_truncated,
        },
        response: None,
        timing: crate::store::TimingDetails {
            start_time,
            ttfb_ms: 0,
            total_ms: 0,
        },
        is_replay: false,
        parent_id: None,
    })
}

fn parse_response(raw_bytes: &[u8]) -> Option<crate::store::ResponseDetails> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut resp = httparse::Response::new(&mut headers);
    let offset = match resp.parse(raw_bytes) {
        Ok(httparse::Status::Complete(offset)) => offset,
        _ => return None,
    };

    let status = resp.code.unwrap_or(200);
    let status_text = resp.reason.unwrap_or("OK").to_string();

    let mut parsed_headers = Vec::with_capacity(resp.headers.len());
    let mut content_length: Option<usize> = None;
    for h in resp.headers {
        if h.name.eq_ignore_ascii_case("Content-Length") {
            if let Ok(val_str) = std::str::from_utf8(h.value) {
                if let Ok(cl) = val_str.trim().parse::<usize>() {
                    content_length = Some(cl);
                }
            }
        }
        parsed_headers.push(crate::store::HeaderPair {
            name: h.name.to_string(),
            value: String::from_utf8_lossy(h.value).into_owned(),
        });
    }

    let body_slice = &raw_bytes[offset..];
    let (body, body_size, body_truncated) = if let Some(cl) = content_length {
        if body_slice.len() < cl {
            let body_str = if body_slice.is_empty() {
                None
            } else {
                Some(
                    String::from_utf8_lossy(
                        &body_slice[..body_slice.len().min(MAX_BODY_CAPTURE_SIZE)],
                    )
                    .into_owned(),
                )
            };
            (body_str, cl, true)
        } else if cl > MAX_BODY_CAPTURE_SIZE {
            (
                Some(String::from_utf8_lossy(&body_slice[..MAX_BODY_CAPTURE_SIZE]).into_owned()),
                cl,
                true,
            )
        } else if cl == 0 && body_slice.is_empty() {
            (None, 0, false)
        } else {
            (
                Some(String::from_utf8_lossy(&body_slice[..cl]).into_owned()),
                cl,
                false,
            )
        }
    } else if body_slice.is_empty() {
        (None, 0, false)
    } else if body_slice.len() > MAX_BODY_CAPTURE_SIZE {
        (
            Some(String::from_utf8_lossy(&body_slice[..MAX_BODY_CAPTURE_SIZE]).into_owned()),
            body_slice.len(),
            true,
        )
    } else {
        (
            Some(String::from_utf8_lossy(body_slice).into_owned()),
            body_slice.len(),
            false,
        )
    };

    Some(crate::store::ResponseDetails {
        status,
        status_text,
        headers: parsed_headers,
        body,
        body_size,
        body_truncated,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_http_tap_parse_get_request() {
        let store = Arc::new(InspectorStore::new(100, 1024 * 1024));
        let (tap, _handle) = HttpTapSender::new(store.clone());

        let raw_req =
            b"GET /hello?name=world HTTP/1.1\r\nHost: example.local\r\nUser-Agent: test\r\n\r\n";
        let visitor_ip: SocketAddr = "192.168.1.50:52341".parse().unwrap();
        let req_id = tap
            .tap_request(visitor_ip, raw_req)
            .expect("must parse request");

        tokio::time::sleep(Duration::from_millis(20)).await;
        let stored = store.get(&req_id).expect("must be in store");
        assert_eq!(stored.request.method, "GET");
        assert_eq!(stored.request.path, "/hello?name=world");
        assert_eq!(stored.visitor_ip, "192.168.1.50");
        assert_eq!(stored.request.body, None);
        assert_eq!(stored.request.body_size, 0);
        assert!(!stored.request.body_truncated);

        let raw_resp =
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello";
        tap.tap_response(req_id.clone(), raw_resp, Duration::from_millis(15));

        tokio::time::sleep(Duration::from_millis(20)).await;
        let updated = store.get(&req_id).expect("must be updated");
        let resp = updated.response.as_ref().unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.status_text, "OK");
        assert_eq!(resp.body.as_deref(), Some("hello"));
        assert_eq!(resp.body_size, 5);
        assert!(!resp.body_truncated);
        assert_eq!(updated.timing.total_ms, 15);
        assert_eq!(updated.timing.ttfb_ms, 15);
    }

    #[tokio::test]
    async fn test_http_tap_parse_post_request() {
        let store = Arc::new(InspectorStore::new(100, 1024 * 1024));
        let (tap, _handle) = HttpTapSender::new(store.clone());

        let payload = r#"{"name":"quicktunnel","active":true}"#;
        let raw_req = format!(
            "POST /api/v1/tunnels HTTP/1.1\r\nHost: api.example.local\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            payload.len(),
            payload
        );
        let visitor_ip: SocketAddr = "10.0.0.12:44332".parse().unwrap();
        let req_id = tap
            .tap_request(visitor_ip, raw_req.as_bytes())
            .expect("must parse POST request");

        tokio::time::sleep(Duration::from_millis(20)).await;
        let stored = store.get(&req_id).expect("must be in store");
        assert_eq!(stored.request.method, "POST");
        assert_eq!(stored.request.path, "/api/v1/tunnels");
        assert_eq!(stored.visitor_ip, "10.0.0.12");
        assert_eq!(stored.request.body.as_deref(), Some(payload));
        assert_eq!(stored.request.body_size, payload.len());
        assert!(!stored.request.body_truncated);

        let resp_payload = r#"{"status":"created","id":"tun-99"}"#;
        let raw_resp = format!(
            "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            resp_payload.len(),
            resp_payload
        );
        tap.tap_response(
            req_id.clone(),
            raw_resp.as_bytes(),
            Duration::from_millis(25),
        );

        tokio::time::sleep(Duration::from_millis(20)).await;
        let updated = store.get(&req_id).expect("must be updated");
        let resp = updated.response.as_ref().unwrap();
        assert_eq!(resp.status, 201);
        assert_eq!(resp.status_text, "Created");
        assert_eq!(resp.body.as_deref(), Some(resp_payload));
    }

    #[tokio::test]
    async fn test_http_tap_timing_calculation() {
        let store = Arc::new(InspectorStore::new(100, 1024 * 1024));
        let (tap, _handle) = HttpTapSender::new(store.clone());

        let raw_req = b"GET /fast HTTP/1.1\r\nHost: example.local\r\n\r\n";
        let visitor_ip: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let req_id = tap
            .tap_request(visitor_ip, raw_req)
            .expect("must parse request");

        let raw_resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        tap.tap_response_with_ttfb(
            req_id.clone(),
            raw_resp,
            Duration::from_millis(45),
            Duration::from_millis(12),
        );

        tokio::time::sleep(Duration::from_millis(20)).await;
        let updated = store.get(&req_id).expect("must be in store");
        assert_eq!(updated.timing.total_ms, 45);
        assert_eq!(updated.timing.ttfb_ms, 12);
    }

    #[tokio::test]
    async fn test_http_tap_body_truncation() {
        let store = Arc::new(InspectorStore::new(100, 10 * 1024 * 1024));
        let (tap, _handle) = HttpTapSender::new(store.clone());

        // Body exceeding 1 MiB (1,048,576 bytes)
        let large_size = 1024 * 1024 + 100;
        let mut large_req = Vec::from(
            format!(
                "POST /upload HTTP/1.1\r\nHost: example.local\r\nContent-Length: {}\r\n\r\n",
                large_size
            )
            .as_bytes(),
        );
        large_req.extend(vec![b'A'; large_size]);

        let visitor_ip: SocketAddr = "127.0.0.1:9090".parse().unwrap();
        let req_id = tap
            .tap_request(visitor_ip, &large_req)
            .expect("must parse large request");

        tokio::time::sleep(Duration::from_millis(50)).await;
        let stored = store.get(&req_id).expect("must be in store");
        assert!(
            stored.request.body_truncated,
            "request body must be marked truncated"
        );
        assert_eq!(stored.request.body_size, large_size);
        assert_eq!(stored.request.body.as_ref().unwrap().len(), 1024 * 1024);

        // Response exceeding 1 MiB
        let resp_size = 1024 * 1024 + 200;
        let mut large_resp = Vec::from(
            format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", resp_size).as_bytes(),
        );
        large_resp.extend(vec![b'B'; resp_size]);

        tap.tap_response(req_id.clone(), &large_resp, Duration::from_millis(30));

        tokio::time::sleep(Duration::from_millis(50)).await;
        let updated = store.get(&req_id).expect("must be in store");
        let resp = updated.response.as_ref().unwrap();
        assert!(
            resp.body_truncated,
            "response body must be marked truncated"
        );
        assert_eq!(resp.body_size, resp_size);
        assert_eq!(resp.body.as_ref().unwrap().len(), 1024 * 1024);
    }

    #[tokio::test]
    async fn test_http_tap_invalid_request_returns_none() {
        let store = Arc::new(InspectorStore::new(100, 1024 * 1024));
        let (tap, _handle) = HttpTapSender::new(store.clone());

        let invalid_req = b"THIS IS NOT HTTP AT ALL\r\n\r\n";
        let visitor_ip: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        assert!(tap.tap_request(visitor_ip, invalid_req).is_none());
    }

    #[tokio::test]
    async fn test_http_tap_non_blocking_channel_behavior() {
        let store = Arc::new(InspectorStore::new(100, 1024 * 1024));
        // Create tap with capacity 1
        let (tap, _handle) = HttpTapSender::with_capacity(store.clone(), 1);

        let visitor_ip: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let raw_req = b"GET /1 HTTP/1.1\r\nHost: ex.local\r\n\r\n";

        // First item enqueued successfully
        let _id1 = tap.tap_request(visitor_ip, raw_req);
        // Repeated fast enqueue without sleeping: should never block/hang even if channel fills up
        for _ in 0..100 {
            let _ = tap.tap_request(visitor_ip, raw_req);
            tap.tap_response(
                "dummy".into(),
                b"HTTP/1.1 200 OK\r\n\r\n",
                Duration::from_millis(1),
            );
        }
    }

    #[tokio::test]
    async fn test_http_tap_preserves_headers_casing_and_duplicates() {
        let store = Arc::new(InspectorStore::new(100, 1024 * 1024));
        let (tap, _handle) = HttpTapSender::new(store.clone());

        let raw_req = b"GET /cookies HTTP/1.1\r\nHost: example.local\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\nX-Custom-Header: TestVal\r\n\r\n";
        let visitor_ip: SocketAddr = "192.168.1.1:1234".parse().unwrap();
        let req_id = tap.tap_request(visitor_ip, raw_req).expect("must parse");

        tokio::time::sleep(Duration::from_millis(20)).await;
        let stored = store.get(&req_id).expect("must be in store");
        let headers = &stored.request.headers;
        assert_eq!(headers.len(), 4);
        assert_eq!(headers[0].name, "Host");
        assert_eq!(headers[1].name, "Set-Cookie");
        assert_eq!(headers[1].value, "a=1");
        assert_eq!(headers[2].name, "Set-Cookie");
        assert_eq!(headers[2].value, "b=2");
        assert_eq!(headers[3].name, "X-Custom-Header");
        assert_eq!(headers[3].value, "TestVal");
    }

    #[tokio::test]
    async fn test_http_tap_http_10_version_and_empty_response_body() {
        let store = Arc::new(InspectorStore::new(100, 1024 * 1024));
        let (tap, _handle) = HttpTapSender::new(store.clone());

        let raw_req = b"HEAD /status HTTP/1.0\r\nHost: example.local\r\n\r\n";
        let visitor_ip: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let req_id = tap.tap_request(visitor_ip, raw_req).expect("must parse");

        tokio::time::sleep(Duration::from_millis(20)).await;
        let stored = store.get(&req_id).expect("must be in store");
        assert_eq!(stored.request.method, "HEAD");
        assert_eq!(stored.request.http_version, "HTTP/1.0");

        // Response with 204 No Content (empty body)
        let raw_resp = b"HTTP/1.0 204 No Content\r\n\r\n";
        tap.tap_response(req_id.clone(), raw_resp, Duration::from_millis(5));

        tokio::time::sleep(Duration::from_millis(20)).await;
        let updated = store.get(&req_id).expect("must be updated");
        let resp = updated.response.as_ref().unwrap();
        assert_eq!(resp.status, 204);
        assert_eq!(resp.status_text, "No Content");
        assert_eq!(resp.body, None);
        assert_eq!(resp.body_size, 0);
        assert!(!resp.body_truncated);
    }

    #[tokio::test]
    async fn test_http_tap_invalid_response_handled_gracefully() {
        let store = Arc::new(InspectorStore::new(100, 1024 * 1024));
        let (tap, _handle) = HttpTapSender::new(store.clone());

        let raw_req = b"GET /hello HTTP/1.1\r\nHost: example.local\r\n\r\n";
        let visitor_ip: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let req_id = tap.tap_request(visitor_ip, raw_req).expect("must parse");

        // Send completely invalid response bytes
        tap.tap_response(
            req_id.clone(),
            b"GARBAGE NON-HTTP RESPONSE",
            Duration::from_millis(10),
        );

        tokio::time::sleep(Duration::from_millis(20)).await;
        let stored = store.get(&req_id).expect("must be in store");
        assert!(
            stored.response.is_none(),
            "invalid response should not be recorded"
        );
    }

    #[tokio::test]
    async fn test_http_tap_partial_body_and_chunk_streaming() {
        let store = Arc::new(InspectorStore::new(100, 1024 * 1024));
        let (tap, _handle) = HttpTapSender::new(store.clone());

        // Initial request buffer only has partial body (5 bytes out of 11)
        let raw_req =
            b"POST /stream HTTP/1.1\r\nHost: example.local\r\nContent-Length: 11\r\n\r\nhello";
        let visitor_ip: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let req_id = tap.tap_request(visitor_ip, raw_req).expect("must parse");

        tokio::time::sleep(Duration::from_millis(20)).await;
        let stored = store.get(&req_id).expect("must be in store");
        assert_eq!(stored.request.body_size, 11);
        assert_eq!(stored.request.body.as_deref(), Some("hello"));
        assert!(
            stored.request.body_truncated,
            "must be marked truncated initially"
        );

        // Stream remaining chunk
        tap.tap_request_body_chunk(req_id.clone(), b" world");
        tokio::time::sleep(Duration::from_millis(20)).await;

        let updated = store.get(&req_id).expect("must be in store");
        assert_eq!(updated.request.body_size, 11);
        assert_eq!(updated.request.body.as_deref(), Some("hello world"));
        assert!(
            !updated.request.body_truncated,
            "must no longer be truncated once full body arrives"
        );
    }
}
