//! Metrics collector

use qt_proto::FrameType;
use std::collections::HashMap;

pub struct MetricsCollector {
    frames_sent: HashMap<FrameType, u64>,
    frames_recv: HashMap<FrameType, u64>,
    bytes_sent: u64,
    bytes_recv: u64,
    errors: u64,
}

impl MetricsCollector {
    pub fn new() -> Self {
        MetricsCollector {
            frames_sent: HashMap::new(),
            frames_recv: HashMap::new(),
            bytes_sent: 0,
            bytes_recv: 0,
            errors: 0,
        }
    }

    pub fn record_sent(&mut self, frame_type: FrameType, bytes: usize) {
        *self.frames_sent.entry(frame_type).or_insert(0) += 1;
        self.bytes_sent += bytes as u64;
    }

    pub fn record_recv(&mut self, frame_type: FrameType, bytes: usize) {
        *self.frames_recv.entry(frame_type).or_insert(0) += 1;
        self.bytes_recv += bytes as u64;
    }

    pub fn record_error(&mut self) {
        self.errors += 1;
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_collector() {
        let mut collector = MetricsCollector::new();
        collector.record_sent(FrameType::Data, 100);
        collector.record_recv(FrameType::Data, 200);
        collector.record_error();

        assert_eq!(collector.bytes_sent, 100);
        assert_eq!(collector.bytes_recv, 200);
        assert_eq!(collector.errors, 1);
        assert_eq!(*collector.frames_sent.get(&FrameType::Data).unwrap(), 1);
        assert_eq!(*collector.frames_recv.get(&FrameType::Data).unwrap(), 1);

        let default_collector = MetricsCollector::default();
        assert_eq!(default_collector.bytes_sent, 0);
    }
}
