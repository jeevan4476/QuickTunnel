//! DRR Fair Scheduler with high-priority control lane

use qt_proto::Frame;
use std::collections::{HashMap, VecDeque};

/// Per-stream queue entry in DRR scheduler
struct StreamQueue {
    frames: VecDeque<Frame>,
    deficit: i64,
    priority_weight: u8,
}

/// DRR (Deficit Round Robin) scheduler with strict-priority control lane.
/// Control frames (PING, PONG, WINDOW_UPDATE, GOAWAY, RST, FIN) bypass data queues
/// to prevent flow control deadlocks.
pub struct DrrScheduler {
    control_queue: VecDeque<Frame>,
    stream_queues: HashMap<u32, StreamQueue>,
    active_streams: VecDeque<u32>,
    quantum: u32,
}

impl DrrScheduler {
    /// Create a new DRR scheduler with given quantum (bytes per turn).
    pub fn new(quantum: u32) -> Self {
        Self {
            control_queue: VecDeque::new(),
            stream_queues: HashMap::new(),
            active_streams: VecDeque::new(),
            quantum,
        }
    }

    /// Enqueue a control frame (strict priority - always dequeued first).
    pub fn enqueue_control(&mut self, frame: Frame) {
        self.control_queue.push_back(frame);
    }

    /// Enqueue a data frame for a stream with priority weight.
    pub fn enqueue_data(&mut self, frame: Frame, priority_weight: u8) {
        let stream_id = frame.header.stream_id;
        let queue = self
            .stream_queues
            .entry(stream_id)
            .or_insert_with(|| StreamQueue {
                frames: VecDeque::new(),
                deficit: 0,
                priority_weight,
            });
        queue.frames.push_back(frame);
        queue.priority_weight = priority_weight;

        // Add to active streams if not already there
        if !self.active_streams.contains(&stream_id) {
            self.active_streams.push_back(stream_id);
        }
    }

    /// Dequeue the next frame. Control frames are always returned first.
    /// Then DRR round-robin across active data streams.
    pub fn dequeue(&mut self) -> Option<Frame> {
        // Control lane has strict priority
        if let Some(frame) = self.control_queue.pop_front() {
            return Some(frame);
        }

        // DRR for data streams
        while !self.active_streams.is_empty() {
            let stream_id = self.active_streams[0];
            let queue = match self.stream_queues.get_mut(&stream_id) {
                Some(q) => q,
                None => {
                    self.active_streams.pop_front();
                    continue;
                }
            };

            if queue.frames.is_empty() {
                self.stream_queues.remove(&stream_id);
                self.active_streams.pop_front();
                continue;
            }

            let quantum_with_weight = self.quantum as i64 * queue.priority_weight as i64;
            queue.deficit += quantum_with_weight;

            let frame_len = queue.frames.front().unwrap().payload.len() as i64;
            if queue.deficit >= frame_len {
                let frame = queue.frames.pop_front().unwrap();
                queue.deficit -= frame_len;
                self.active_streams.rotate_left(1);

                if queue.frames.is_empty() {
                    self.stream_queues.remove(&stream_id);
                    if let Some(pos) = self.active_streams.iter().position(|&id| id == stream_id) {
                        self.active_streams.remove(pos);
                    }
                }

                return Some(frame);
            } else {
                // Not enough deficit this round; rotate to next stream
                self.active_streams.rotate_left(1);
            }
        }

        None
    }

    /// Get total number of queued frames
    pub fn len(&self) -> usize {
        self.control_queue.len()
            + self
                .stream_queues
                .values()
                .map(|q| q.frames.len())
                .sum::<usize>()
    }

    /// Check if scheduler is empty
    pub fn is_empty(&self) -> bool {
        self.control_queue.is_empty() && self.stream_queues.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use qt_proto::{Frame, FrameType};

    fn create_data_frame(stream_id: u32, size: usize, fin: bool) -> Frame {
        Frame::data(stream_id, Bytes::from(vec![0u8; size]), fin).unwrap()
    }

    fn create_ping() -> Frame {
        Frame::ping(42).unwrap()
    }

    fn create_window_update(stream_id: u32, increment: u32) -> Frame {
        Frame::window_update(stream_id, increment).unwrap()
    }

    fn create_rst(stream_id: u32, error_code: u32) -> Frame {
        Frame::rst(stream_id, error_code).unwrap()
    }

    fn create_goaway(stream_id: u32, error_code: u32) -> Frame {
        Frame::goaway(stream_id, error_code).unwrap()
    }

    #[test]
    fn test_control_priority_lane_bypasses_data() {
        let mut sched = DrrScheduler::new(16384);
        // Enqueue 10 large data frames on stream 1
        for _ in 0..10 {
            sched.enqueue_data(create_data_frame(1, 16384, false), 1);
        }

        // Enqueue a PING control frame
        sched.enqueue_control(create_ping());

        // Dequeue must return the control PING first
        let first = sched.dequeue().unwrap();
        assert_eq!(first.header.ty, FrameType::Ping);
    }

    #[test]
    fn test_control_priority_various_types() {
        let mut sched = DrrScheduler::new(16384);
        sched.enqueue_data(create_data_frame(1, 16384, false), 1);
        sched.enqueue_data(create_data_frame(2, 16384, false), 1);

        // Test all control frame types
        sched.enqueue_control(create_ping());
        assert_eq!(sched.dequeue().unwrap().header.ty, FrameType::Ping);

        sched.enqueue_control(create_window_update(0, 1000));
        assert_eq!(sched.dequeue().unwrap().header.ty, FrameType::WindowUpdate);

        sched.enqueue_control(create_rst(1, 1));
        assert_eq!(sched.dequeue().unwrap().header.ty, FrameType::Rst);

        sched.enqueue_control(create_goaway(0, 0));
        assert_eq!(sched.dequeue().unwrap().header.ty, FrameType::GoAway);
    }

    #[test]
    fn test_drr_fair_sharing_between_streams() {
        let mut sched = DrrScheduler::new(16384);
        // Stream 1: two 16K frames
        sched.enqueue_data(create_data_frame(1, 16384, false), 1);
        sched.enqueue_data(create_data_frame(1, 16384, false), 1);

        // Stream 2: two 16K frames
        sched.enqueue_data(create_data_frame(2, 16384, false), 1);
        sched.enqueue_data(create_data_frame(2, 16384, false), 1);

        // Under DRR, streams take turns round-robin
        assert_eq!(sched.dequeue().unwrap().header.stream_id, 1);
        assert_eq!(sched.dequeue().unwrap().header.stream_id, 2);
        assert_eq!(sched.dequeue().unwrap().header.stream_id, 1);
        assert_eq!(sched.dequeue().unwrap().header.stream_id, 2);
    }

    #[test]
    fn test_drr_with_different_frame_sizes() {
        let mut sched = DrrScheduler::new(16384);
        // Stream 1: one 8K frame
        sched.enqueue_data(create_data_frame(1, 8192, false), 1);
        // Stream 2: one 16K frame (equal to quantum)
        sched.enqueue_data(create_data_frame(2, 16384, false), 1);

        // Stream 1 sends first (8K < quantum)
        assert_eq!(sched.dequeue().unwrap().header.stream_id, 1);
        // Stream 2 sends next
        assert_eq!(sched.dequeue().unwrap().header.stream_id, 2);
    }

    #[test]
    fn test_drr_priority_weight() {
        let mut sched = DrrScheduler::new(16384);
        // Stream 1: weight 1 (quantum = 16K)
        sched.enqueue_data(create_data_frame(1, 8192, false), 1);
        sched.enqueue_data(create_data_frame(1, 8192, false), 1);
        // Stream 2: weight 2 (quantum = 32K)
        sched.enqueue_data(create_data_frame(2, 8192, false), 2);
        sched.enqueue_data(create_data_frame(2, 8192, false), 2);

        // Stream 2 gets more turns proportionally
        // But basic test just verifies both get served
        let mut counts = [0, 0, 0];
        for _ in 0..4 {
            let f = sched.dequeue().unwrap();
            counts[f.header.stream_id as usize] += 1;
        }
        assert!(counts[1] > 0);
        assert!(counts[2] > 0);
    }

    #[test]
    fn test_empty_scheduler() {
        let mut sched = DrrScheduler::new(16384);
        assert!(sched.is_empty());
        assert_eq!(sched.len(), 0);
        assert_eq!(sched.dequeue(), None);
    }

    #[test]
    fn test_stream_removed_when_empty() {
        let mut sched = DrrScheduler::new(16384);
        sched.enqueue_data(create_data_frame(1, 1000, false), 1);

        let _ = sched.dequeue();
        assert!(sched.is_empty());
        assert_eq!(sched.len(), 0);
    }

    #[test]
    fn test_len_counts_correctly() {
        let mut sched = DrrScheduler::new(16384);
        sched.enqueue_data(create_data_frame(1, 1000, false), 1);
        sched.enqueue_data(create_data_frame(2, 2000, false), 1);
        sched.enqueue_control(create_ping());
        assert_eq!(sched.len(), 3);

        let _ = sched.dequeue(); // control
        assert_eq!(sched.len(), 2);

        let _ = sched.dequeue(); // data stream 1
        assert_eq!(sched.len(), 1);
    }
}
