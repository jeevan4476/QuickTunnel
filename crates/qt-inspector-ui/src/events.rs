//! Event logger

use qt_proto::FrameType;
use std::time::Instant;

#[derive(Debug, Clone)]
pub enum Event {
    FrameSent {
        ty: FrameType,
        stream_id: u32,
        len: usize,
        at: Instant,
    },
    FrameRecv {
        ty: FrameType,
        stream_id: u32,
        len: usize,
        at: Instant,
    },
    Error {
        msg: String,
        at: Instant,
    },
    StateChange {
        stream_id: u32,
        from: String,
        to: String,
        at: Instant,
    },
}

pub struct EventLogger {
    events: Vec<Event>,
    max_events: usize,
}

impl EventLogger {
    pub fn new(max_events: usize) -> Self {
        EventLogger {
            events: Vec::with_capacity(max_events),
            max_events,
        }
    }

    pub fn log(&mut self, event: Event) {
        if self.events.len() >= self.max_events {
            self.events.remove(0);
        }
        self.events.push(event);
    }

    pub fn events(&self) -> &[Event] {
        &self.events
    }

    pub fn clear(&mut self) {
        self.events.clear();
    }
}

impl Default for EventLogger {
    fn default() -> Self {
        Self::new(10000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_logger() {
        let mut logger = EventLogger::new(2);
        assert!(logger.events().is_empty());

        logger.log(Event::FrameSent {
            ty: FrameType::Data,
            stream_id: 1,
            len: 10,
            at: Instant::now(),
        });
        logger.log(Event::FrameRecv {
            ty: FrameType::Data,
            stream_id: 1,
            len: 20,
            at: Instant::now(),
        });
        assert_eq!(logger.events().len(), 2);

        // Exceed max_events evicts oldest
        logger.log(Event::Error {
            msg: "err".to_string(),
            at: Instant::now(),
        });
        assert_eq!(logger.events().len(), 2);

        logger.log(Event::StateChange {
            stream_id: 1,
            from: "open".to_string(),
            to: "closed".to_string(),
            at: Instant::now(),
        });
        assert_eq!(logger.events().len(), 2);

        logger.clear();
        assert!(logger.events().is_empty());

        let default_logger = EventLogger::default();
        assert_eq!(default_logger.max_events, 10000);
    }
}
