//! In-memory ring buffer store for captured HTTP requests.

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::broadcast;

/// HTTP header name-value pair preserving original casing and duplicate keys.
pub const MAX_BODY_CAPTURE_SIZE: usize = 1024 * 1024; // 1 MiB

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HeaderPair {
    pub name: String,
    pub value: String,
}

impl HeaderPair {
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }
}

impl<N: Into<String>, V: Into<String>> From<(N, V)> for HeaderPair {
    fn from((name, value): (N, V)) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }
}

/// Request inspection details.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RequestDetails {
    pub method: String,
    pub path: String,
    pub http_version: String,
    pub headers: Vec<HeaderPair>,
    pub body: Option<String>,
    pub body_size: usize,
    pub body_truncated: bool,
}

/// Response inspection details.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResponseDetails {
    pub status: u16,
    pub status_text: String,
    pub headers: Vec<HeaderPair>,
    pub body: Option<String>,
    pub body_size: usize,
    pub body_truncated: bool,
}

/// Timing metrics for a captured HTTP transaction.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TimingDetails {
    pub start_time: SystemTime,
    pub ttfb_ms: u64,
    pub total_ms: u64,
}

impl Default for TimingDetails {
    fn default() -> Self {
        Self {
            start_time: SystemTime::now(),
            ttfb_ms: 0,
            total_ms: 0,
        }
    }
}

/// A captured HTTP transaction containing request, response, and timing information.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapturedRequest {
    pub id: String,
    pub visitor_ip: String,
    pub request: RequestDetails,
    pub response: Option<ResponseDetails>,
    pub timing: TimingDetails,
    pub is_replay: bool,
    pub parent_id: Option<String>,
}

impl CapturedRequest {
    /// Creates a mock captured request suitable for testing and development.
    pub fn new_mock(method: &str, path: &str) -> Self {
        Self {
            id: ulid::Ulid::generate().to_string(),
            visitor_ip: "127.0.0.1".to_string(),
            request: RequestDetails {
                method: method.to_string(),
                path: path.to_string(),
                http_version: "HTTP/1.1".to_string(),
                headers: Vec::new(),
                body: None,
                body_size: 0,
                body_truncated: false,
            },
            response: None,
            timing: TimingDetails::default(),
            is_replay: false,
            parent_id: None,
        }
    }

    /// Creates a replay clone of this request with a fresh ULID and parent reference.
    pub fn create_replay(&self) -> Self {
        Self {
            id: ulid::Ulid::generate().to_string(),
            visitor_ip: "127.0.0.1".to_string(),
            request: self.request.clone(),
            response: None,
            timing: TimingDetails::default(),
            is_replay: true,
            parent_id: Some(self.id.clone()),
        }
    }

    /// Estimates the memory usage in bytes of this request record.
    pub fn estimated_bytes(&self) -> usize {
        let mut bytes = std::mem::size_of::<Self>();
        bytes += self.id.len() + self.visitor_ip.len();
        if let Some(ref pid) = self.parent_id {
            bytes += pid.len();
        }
        bytes +=
            self.request.method.len() + self.request.path.len() + self.request.http_version.len();
        let req_body_len = self.request.body.as_ref().map_or(0, |b| b.len());
        bytes += req_body_len;
        for h in &self.request.headers {
            bytes += h.name.len() + h.value.len() + std::mem::size_of::<HeaderPair>();
        }
        if let Some(ref resp) = self.response {
            bytes += resp.status_text.len();
            let resp_body_len = resp.body.as_ref().map_or(0, |b| b.len());
            bytes += resp_body_len;
            for h in &resp.headers {
                bytes += h.name.len() + h.value.len() + std::mem::size_of::<HeaderPair>();
            }
        }
        bytes
    }
}

/// Internal storage state for the inspector ring buffer.
struct StoreInner {
    order: VecDeque<String>,
    map: HashMap<String, Arc<CapturedRequest>>,
    total_bytes: usize,
}

/// Thread-safe in-memory ring buffer store for captured HTTP transactions.
#[derive(Clone)]
pub struct InspectorStore {
    inner: Arc<RwLock<StoreInner>>,
    sender: broadcast::Sender<Arc<CapturedRequest>>,
    capacity: usize,
    max_memory_bytes: usize,
}

impl InspectorStore {
    /// Creates a new `InspectorStore` with maximum request count capacity and byte cap.
    pub fn new(capacity: usize, max_memory_bytes: usize) -> Self {
        let capacity = capacity.max(1);
        let max_memory_bytes = max_memory_bytes.max(1);
        let (sender, _) = broadcast::channel(1024);
        Self {
            inner: Arc::new(RwLock::new(StoreInner {
                order: VecDeque::with_capacity(capacity),
                map: HashMap::with_capacity(capacity),
                total_bytes: 0,
            })),
            sender,
            capacity,
            max_memory_bytes,
        }
    }

    /// Adds a captured request to the store, evicting the oldest entries if capacity or memory cap is exceeded.
    pub fn add_request(&self, mut req: CapturedRequest) -> Arc<CapturedRequest> {
        if req.id.is_empty() {
            req.id = ulid::Ulid::generate().to_string();
        }

        let req_bytes = req.estimated_bytes();
        let arc_req = Arc::new(req);

        let mut inner = self.inner.write();

        // If ID already exists in map, remove it first so re-adding an existing entry
        // does not prematurely evict an older item when at capacity.
        if let Some(existing) = inner.map.remove(&arc_req.id) {
            inner.total_bytes = inner.total_bytes.saturating_sub(existing.estimated_bytes());
            inner.order.retain(|id| id != &arc_req.id);
        }

        // Evict oldest until within count capacity
        while inner.order.len() >= self.capacity {
            if let Some(oldest_id) = inner.order.pop_front() {
                if let Some(removed) = inner.map.remove(&oldest_id) {
                    inner.total_bytes = inner.total_bytes.saturating_sub(removed.estimated_bytes());
                }
            }
        }

        // Evict oldest until adding this request won't exceed memory cap (unless store is empty)
        while !inner.order.is_empty()
            && inner.total_bytes.saturating_add(req_bytes) > self.max_memory_bytes
        {
            if let Some(oldest_id) = inner.order.pop_front() {
                if let Some(removed) = inner.map.remove(&oldest_id) {
                    inner.total_bytes = inner.total_bytes.saturating_sub(removed.estimated_bytes());
                }
            }
        }

        inner.order.push_back(arc_req.id.clone());
        inner.map.insert(arc_req.id.clone(), arc_req.clone());
        inner.total_bytes = inner.total_bytes.saturating_add(req_bytes);

        drop(inner);

        // Broadcast to live SSE subscribers (ignore error if no active receivers)
        let _ = self.sender.send(arc_req.clone());

        arc_req
    }

    /// Records response details and timing for an existing request in the store.
    pub fn record_response(
        &self,
        id: &str,
        resp: ResponseDetails,
        total_ms: u64,
        ttfb_ms: u64,
    ) -> Option<Arc<CapturedRequest>> {
        let mut inner = self.inner.write();

        let old_req = inner.map.get(id)?;
        let mut updated = (**old_req).clone();
        updated.response = Some(resp);
        updated.timing.total_ms = total_ms;
        updated.timing.ttfb_ms = ttfb_ms;

        let old_bytes = old_req.estimated_bytes();
        let new_bytes = updated.estimated_bytes();

        inner.total_bytes = inner
            .total_bytes
            .saturating_sub(old_bytes)
            .saturating_add(new_bytes);

        let arc_updated = Arc::new(updated);
        inner.map.insert(id.to_string(), arc_updated.clone());

        // Memory eviction check after updating payload size:
        // Evict older requests while over memory cap, keeping at least 1 request.
        while inner.order.len() > 1 && inner.total_bytes > self.max_memory_bytes {
            if let Some(oldest_id) = inner.order.pop_front() {
                if let Some(removed) = inner.map.remove(&oldest_id) {
                    inner.total_bytes = inner.total_bytes.saturating_sub(removed.estimated_bytes());
                }
            }
        }

        drop(inner);

        // Broadcast updated request to live subscribers
        let _ = self.sender.send(arc_updated.clone());

        Some(arc_updated)
    }

    /// Appends request body bytes for an in-flight request, up to `MAX_BODY_CAPTURE_SIZE`.
    pub fn append_request_body(&self, id: &str, chunk: &[u8]) -> Option<Arc<CapturedRequest>> {
        let mut inner = self.inner.write();
        let old_req = inner.map.get(id)?;
        let mut updated = (**old_req).clone();

        let old_bytes = old_req.estimated_bytes();

        let current_body_len = updated.request.body.as_ref().map_or(0, |b| b.len());
        if current_body_len < MAX_BODY_CAPTURE_SIZE {
            let to_take = chunk.len().min(MAX_BODY_CAPTURE_SIZE - current_body_len);
            let s = String::from_utf8_lossy(&chunk[..to_take]);
            if let Some(ref mut body) = updated.request.body {
                body.push_str(&s);
            } else {
                updated.request.body = Some(s.into_owned());
            }
        }

        let new_captured = updated.request.body.as_ref().map_or(0, |b| b.len());
        if updated.request.body_size < new_captured {
            updated.request.body_size = new_captured;
        }

        // If all expected content length has been received and is within MAX_BODY_CAPTURE_SIZE,
        // it is no longer truncated.
        if updated.request.body_size <= MAX_BODY_CAPTURE_SIZE
            && new_captured >= updated.request.body_size
        {
            updated.request.body_truncated = false;
        }

        let new_bytes = updated.estimated_bytes();
        inner.total_bytes = inner
            .total_bytes
            .saturating_sub(old_bytes)
            .saturating_add(new_bytes);

        let arc_updated = Arc::new(updated);
        inner.map.insert(id.to_string(), arc_updated.clone());
        drop(inner);

        let _ = self.sender.send(arc_updated.clone());
        Some(arc_updated)
    }

    /// Retrieves a captured request by ID.
    pub fn get(&self, id: &str) -> Option<Arc<CapturedRequest>> {
        let inner = self.inner.read();
        inner.map.get(id).cloned()
    }

    /// Lists up to `limit` captured requests ordered newest-first.
    pub fn list(&self, limit: usize) -> Vec<Arc<CapturedRequest>> {
        if limit == 0 {
            return Vec::new();
        }
        let inner = self.inner.read();
        inner
            .order
            .iter()
            .rev()
            .take(limit)
            .filter_map(|id| inner.map.get(id).cloned())
            .collect()
    }

    /// Subscribes to live captured request and response update events.
    pub fn subscribe(&self) -> broadcast::Receiver<Arc<CapturedRequest>> {
        self.sender.subscribe()
    }

    /// Clears all requests from the store.
    pub fn clear(&self) {
        let mut inner = self.inner.write();
        inner.order.clear();
        inner.map.clear();
        inner.total_bytes = 0;
    }

    /// Returns the number of requests currently stored.
    pub fn count(&self) -> usize {
        self.inner.read().map.len()
    }

    /// Returns true if the store contains no requests.
    pub fn is_empty(&self) -> bool {
        self.count() == 0
    }

    /// Returns the total estimated memory consumption in bytes.
    pub fn total_memory_bytes(&self) -> usize {
        self.inner.read().total_bytes
    }

    /// Returns the maximum capacity (number of requests).
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Returns the maximum memory bytes cap.
    pub fn max_memory_bytes(&self) -> usize {
        self.max_memory_bytes
    }
}

impl Default for InspectorStore {
    fn default() -> Self {
        Self::new(1000, 64 * 1024 * 1024)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_store_add_get_and_list() {
        let store = InspectorStore::new(10, 1024 * 1024);
        let req = CapturedRequest::new_mock("GET", "/api/ping");
        let added = store.add_request(req.clone());
        assert_eq!(store.count(), 1);
        assert!(!store.is_empty());

        let retrieved = store.get(&added.id).expect("must find request");
        assert_eq!(retrieved.request.path, "/api/ping");

        let list = store.list(10);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, added.id);

        assert!(store.get("non-existent-id").is_none());
        assert_eq!(store.list(0).len(), 0);
    }

    #[test]
    fn test_store_ring_buffer_eviction() {
        let store = InspectorStore::new(3, 1024 * 1024);
        let id1 = store
            .add_request(CapturedRequest::new_mock("GET", "/1"))
            .id
            .clone();
        let id2 = store
            .add_request(CapturedRequest::new_mock("GET", "/2"))
            .id
            .clone();
        let id3 = store
            .add_request(CapturedRequest::new_mock("GET", "/3"))
            .id
            .clone();
        let id4 = store
            .add_request(CapturedRequest::new_mock("GET", "/4"))
            .id
            .clone();

        assert_eq!(store.count(), 3);
        assert!(store.get(&id1).is_none(), "oldest request must be evicted");
        assert!(store.get(&id2).is_some());
        assert!(store.get(&id3).is_some());
        assert!(store.get(&id4).is_some());

        // Check newest-first ordering
        let list = store.list(10);
        assert_eq!(list.len(), 3);
        assert_eq!(list[0].id, id4);
        assert_eq!(list[1].id, id3);
        assert_eq!(list[2].id, id2);
    }

    #[test]
    fn test_store_memory_capacity_eviction() {
        // Create store with large item count capacity (100) but strict memory cap
        let mut r1 = CapturedRequest::new_mock("POST", "/data1");
        r1.request.body = Some("a".repeat(1000));
        r1.request.body_size = 1000;
        let r1_bytes = r1.estimated_bytes();

        let mut r2 = CapturedRequest::new_mock("POST", "/data2");
        r2.request.body = Some("b".repeat(1000));
        r2.request.body_size = 1000;
        let r2_bytes = r2.estimated_bytes();

        // Allow enough memory for roughly 1.5 requests so second request evicts first
        let max_memory = r1_bytes + 200;
        let store = InspectorStore::new(100, max_memory);

        let id1 = store.add_request(r1).id.clone();
        assert_eq!(store.count(), 1);
        assert!(store.get(&id1).is_some());

        let id2 = store.add_request(r2).id.clone();
        assert_eq!(store.count(), 1);
        assert!(
            store.get(&id1).is_none(),
            "id1 should be evicted due to memory cap"
        );
        assert!(store.get(&id2).is_some(), "id2 should remain in store");
        assert!(store.total_memory_bytes() <= max_memory);
        assert_eq!(store.total_memory_bytes(), r2_bytes);
    }

    #[test]
    fn test_store_record_response() {
        let store = InspectorStore::new(10, 1024 * 1024);
        let req = CapturedRequest::new_mock("GET", "/api/user");
        let added = store.add_request(req);
        assert!(added.response.is_none());

        let resp = ResponseDetails {
            status: 200,
            status_text: "OK".to_string(),
            headers: vec![HeaderPair::new("content-type", "application/json")],
            body: Some(r#"{"status":"ok"}"#.to_string()),
            body_size: 15,
            body_truncated: false,
        };

        let updated = store
            .record_response(&added.id, resp.clone(), 120, 45)
            .expect("should update existing request");

        assert_eq!(updated.timing.total_ms, 120);
        assert_eq!(updated.timing.ttfb_ms, 45);
        let resp_stored = updated
            .response
            .as_ref()
            .expect("response should be present");
        assert_eq!(resp_stored.status, 200);
        assert_eq!(resp_stored.status_text, "OK");
        assert_eq!(resp_stored.headers.len(), 1);
        assert_eq!(resp_stored.body.as_deref(), Some(r#"{"status":"ok"}"#));

        // Retrieve from store to ensure store has updated copy
        let retrieved = store.get(&added.id).expect("request must exist in store");
        assert_eq!(retrieved.timing.total_ms, 120);
        assert_eq!(retrieved.response.as_ref().unwrap().status, 200);

        // Recording on non-existent ID returns None
        assert!(store.record_response("unknown-id", resp, 50, 10).is_none());
    }

    #[test]
    fn test_store_record_response_triggers_memory_eviction() {
        let r1 = CapturedRequest::new_mock("GET", "/first");
        let r2 = CapturedRequest::new_mock("GET", "/second");
        let r1_bytes = r1.estimated_bytes();
        let r2_bytes = r2.estimated_bytes();

        let large_resp = ResponseDetails {
            status: 200,
            status_text: "OK".to_string(),
            headers: Vec::new(),
            body: Some("x".repeat(300)),
            body_size: 300,
            body_truncated: false,
        };

        // Size of r2 with the response attached
        let mut r2_with_resp = r2.clone();
        r2_with_resp.response = Some(large_resp.clone());
        let r2_with_resp_bytes = r2_with_resp.estimated_bytes();

        // Allow both r1 and r2 to fit initially, and allow r2_with_resp alone to fit,
        // but NOT both r1 and r2_with_resp.
        let max_memory = (r1_bytes + r2_bytes).max(r2_with_resp_bytes);
        let store = InspectorStore::new(10, max_memory);

        let id1 = store.add_request(r1).id.clone();
        let id2 = store.add_request(r2).id.clone();
        assert_eq!(store.count(), 2);

        store
            .record_response(&id2, large_resp, 100, 30)
            .expect("record response should succeed");

        assert!(store.total_memory_bytes() <= max_memory);
        assert!(
            store.get(&id1).is_none(),
            "id1 should be evicted due to memory pressure"
        );
        assert!(store.get(&id2).is_some());
    }

    #[tokio::test]
    async fn test_store_broadcast_subscription() {
        let store = InspectorStore::new(10, 1024 * 1024);
        let mut rx = store.subscribe();

        let req = CapturedRequest::new_mock("GET", "/live");
        let added = store.add_request(req);

        let event1 = rx.recv().await.expect("must receive add event");
        assert_eq!(event1.id, added.id);
        assert_eq!(event1.request.path, "/live");
        assert!(event1.response.is_none());

        let resp = ResponseDetails {
            status: 204,
            status_text: "No Content".to_string(),
            headers: Vec::new(),
            body: None,
            body_size: 0,
            body_truncated: false,
        };

        store.record_response(&added.id, resp, 80, 20);

        let event2 = rx.recv().await.expect("must receive response update event");
        assert_eq!(event2.id, added.id);
        assert_eq!(event2.response.as_ref().unwrap().status, 204);
        assert_eq!(event2.timing.total_ms, 80);
    }

    #[test]
    fn test_store_clear() {
        let store = InspectorStore::new(10, 1024 * 1024);
        let r1 = store.add_request(CapturedRequest::new_mock("GET", "/1"));
        let r2 = store.add_request(CapturedRequest::new_mock("GET", "/2"));
        assert_eq!(store.count(), 2);
        assert!(store.total_memory_bytes() > 0);

        store.clear();
        assert_eq!(store.count(), 0);
        assert!(store.is_empty());
        assert_eq!(store.total_memory_bytes(), 0);
        assert!(store.get(&r1.id).is_none());
        assert!(store.get(&r2.id).is_none());
        assert!(store.list(10).is_empty());
    }

    #[test]
    fn test_store_list_limit() {
        let store = InspectorStore::new(10, 1024 * 1024);
        let mut ids = Vec::new();
        for i in 0..5 {
            let req = store.add_request(CapturedRequest::new_mock("GET", &format!("/path/{}", i)));
            ids.push(req.id.clone());
        }

        let list_all = store.list(10);
        assert_eq!(list_all.len(), 5);
        assert_eq!(list_all[0].id, ids[4]); // newest
        assert_eq!(list_all[4].id, ids[0]); // oldest

        let list_part = store.list(2);
        assert_eq!(list_part.len(), 2);
        assert_eq!(list_part[0].id, ids[4]);
        assert_eq!(list_part[1].id, ids[3]);
    }

    #[test]
    fn test_store_add_request_with_empty_id_generates_ulid() {
        let store = InspectorStore::new(10, 1024 * 1024);
        let mut req = CapturedRequest::new_mock("GET", "/empty-id");
        req.id = String::new();

        let added = store.add_request(req);
        assert!(!added.id.is_empty());
        assert_eq!(added.id.len(), 26); // standard ULID length
        assert!(store.get(&added.id).is_some());
    }

    #[test]
    fn test_store_add_request_duplicate_id_replaces() {
        let store = InspectorStore::new(10, 1024 * 1024);
        let mut req1 = CapturedRequest::new_mock("GET", "/v1");
        req1.id = "fixed-id".to_string();
        store.add_request(req1);
        assert_eq!(store.count(), 1);

        let mut req2 = CapturedRequest::new_mock("GET", "/v2");
        req2.id = "fixed-id".to_string();
        store.add_request(req2);
        assert_eq!(store.count(), 1);

        let retrieved = store.get("fixed-id").unwrap();
        assert_eq!(retrieved.request.path, "/v2");
    }

    #[test]
    fn test_captured_request_create_replay() {
        let original = CapturedRequest::new_mock("POST", "/webhook");
        let replay = original.create_replay();

        assert_ne!(replay.id, original.id);
        assert!(replay.is_replay);
        assert_eq!(replay.parent_id, Some(original.id));
        assert_eq!(replay.request.method, "POST");
        assert_eq!(replay.request.path, "/webhook");
        assert!(replay.response.is_none());
    }

    #[test]
    fn test_header_pair_and_conversions() {
        let h1 = HeaderPair::new("Host", "example.com");
        assert_eq!(h1.name, "Host");
        assert_eq!(h1.value, "example.com");

        let h2: HeaderPair = ("Authorization", "Bearer token123").into();
        assert_eq!(h2.name, "Authorization");
        assert_eq!(h2.value, "Bearer token123");
    }

    #[test]
    fn test_timing_details_default() {
        let t = TimingDetails::default();
        assert_eq!(t.ttfb_ms, 0);
        assert_eq!(t.total_ms, 0);
    }

    #[test]
    fn test_default_inspector_store() {
        let store = InspectorStore::default();
        assert_eq!(store.capacity(), 1000);
        assert_eq!(store.max_memory_bytes(), 64 * 1024 * 1024);
        assert_eq!(store.count(), 0);
    }

    #[test]
    fn test_captured_request_serialization_roundtrip() {
        let mut req = CapturedRequest::new_mock("PUT", "/api/item");
        req.request
            .headers
            .push(HeaderPair::new("Content-Type", "application/json"));
        req.request.body = Some(r#"{"key":"val"}"#.to_string());
        req.request.body_size = 13;
        req.response = Some(ResponseDetails {
            status: 201,
            status_text: "Created".to_string(),
            headers: vec![HeaderPair::new("Location", "/api/item/1")],
            body: Some(r#"{"id":1}"#.to_string()),
            body_size: 8,
            body_truncated: false,
        });
        req.timing.ttfb_ms = 15;
        req.timing.total_ms = 42;

        let json = serde_json::to_string(&req).expect("must serialize");
        let deserialized: CapturedRequest = serde_json::from_str(&json).expect("must deserialize");

        assert_eq!(deserialized.id, req.id);
        assert_eq!(deserialized.request.method, "PUT");
        assert_eq!(deserialized.request.path, "/api/item");
        assert_eq!(deserialized.response.as_ref().unwrap().status, 201);
        assert_eq!(deserialized.timing.total_ms, 42);
        assert_eq!(deserialized.timing.ttfb_ms, 15);
    }

    #[test]
    fn test_estimated_bytes_full() {
        let mut req = CapturedRequest::new_mock("POST", "/test");
        req.parent_id = Some("parent-123".to_string());
        req.request.headers.push(HeaderPair::new("h1", "v1"));
        req.response = Some(ResponseDetails {
            status: 200,
            status_text: "OK".to_string(),
            headers: vec![HeaderPair::new("h2", "v2")],
            body: Some("resp-body".to_string()),
            body_size: 9,
            body_truncated: false,
        });
        assert!(req.estimated_bytes() > 0);
    }

    #[test]
    fn test_store_add_request_duplicate_id_at_capacity_no_premature_eviction() {
        let store = InspectorStore::new(2, 1024 * 1024);

        let mut req1 = CapturedRequest::new_mock("GET", "/first");
        req1.id = "req-1".to_string();
        store.add_request(req1);

        let mut req2 = CapturedRequest::new_mock("GET", "/second");
        req2.id = "req-2".to_string();
        store.add_request(req2);

        // Store is now at capacity 2: [req-1, req-2]
        assert_eq!(store.count(), 2);

        // Re-add req-1 with updated path
        let mut req1_updated = CapturedRequest::new_mock("GET", "/first-updated");
        req1_updated.id = "req-1".to_string();
        store.add_request(req1_updated);

        // Neither req-1 nor req-2 should be evicted!
        assert_eq!(store.count(), 2);
        assert!(store.get("req-1").is_some());
        assert!(store.get("req-2").is_some());
        assert_eq!(store.get("req-1").unwrap().request.path, "/first-updated");

        let list = store.list(10);
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].id, "req-1"); // re-added item becomes newest
        assert_eq!(list[1].id, "req-2");
    }

    #[test]
    fn test_estimated_bytes_truncated_payload() {
        let mut req = CapturedRequest::new_mock("POST", "/upload");
        // Simulated 100 MiB upload where body was truncated to 1 KiB
        req.request.body_size = 100 * 1024 * 1024;
        req.request.body = Some("x".repeat(1024));
        req.request.body_truncated = true;

        // Estimated bytes should reflect actual heap buffer (~1 KiB), NOT 100 MiB!
        let est = req.estimated_bytes();
        assert!(
            est < 5000,
            "estimated bytes ({est}) should reflect actual heap buffer, not wire body_size"
        );

        // Adding this to a store with small memory cap (e.g. 50 KiB) should NOT trigger 100 MiB eviction
        let store = InspectorStore::new(10, 50 * 1024);
        let id1 = store
            .add_request(CapturedRequest::new_mock("GET", "/existing"))
            .id
            .clone();
        store.add_request(req);

        // Both should remain in store
        assert_eq!(store.count(), 2);
        assert!(store.get(&id1).is_some());
    }

    #[test]
    fn test_store_append_request_body() {
        let store = InspectorStore::new(10, 1024 * 1024);
        let mut req = CapturedRequest::new_mock("POST", "/upload");
        req.request.body = Some("hello ".to_string());
        req.request.body_size = 11;
        req.request.body_truncated = true;

        let added = store.add_request(req);
        let id = added.id.clone();

        // Append remaining body bytes
        let updated = store
            .append_request_body(&id, b"world")
            .expect("must append body");
        assert_eq!(updated.request.body.as_deref(), Some("hello world"));
        assert_eq!(updated.request.body_size, 11);
        assert!(!updated.request.body_truncated);

        // Appending to non-existent ID returns None
        assert!(store.append_request_body("unknown", b"test").is_none());
    }
}
