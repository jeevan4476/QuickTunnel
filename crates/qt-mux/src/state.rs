//! Stream state machine and tombstone registry

use qt_proto::{FrameType, ProtoError, Result};
use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StreamState {
    Idle,
    Open,
    HalfClosedLocal,
    HalfClosedRemote,
    Closed,
}

pub struct StreamStateMachine {
    pub id: u32,
    pub is_local_initiator: bool,
    state: StreamState,
}

impl StreamStateMachine {
    pub fn new(id: u32, is_local_initiator: bool) -> Self {
        Self {
            id,
            is_local_initiator,
            state: StreamState::Idle,
        }
    }

    pub fn state(&self) -> StreamState {
        self.state
    }

    pub fn can_send_data(&self) -> bool {
        matches!(
            self.state,
            StreamState::Open | StreamState::HalfClosedRemote
        )
    }

    pub fn can_recv_data(&self) -> bool {
        matches!(self.state, StreamState::Open | StreamState::HalfClosedLocal)
    }

    pub fn transition_send(&mut self, ty: FrameType) -> Result<()> {
        match (self.state, ty) {
            (StreamState::Idle, FrameType::Open) => {
                self.state = StreamState::Open;
                Ok(())
            }
            (StreamState::Open, FrameType::Data | FrameType::WindowUpdate) => Ok(()),
            (StreamState::Open, FrameType::Fin) => {
                self.state = StreamState::HalfClosedLocal;
                Ok(())
            }
            (StreamState::HalfClosedRemote, FrameType::Data | FrameType::WindowUpdate) => Ok(()),
            (StreamState::HalfClosedRemote, FrameType::Fin) => {
                self.state = StreamState::Closed;
                Ok(())
            }
            (s, FrameType::Rst) if s != StreamState::Idle => {
                self.state = StreamState::Closed;
                Ok(())
            }
            (current, frame) => Err(ProtoError::ProtocolError(format!(
                "Invalid state transition: send {:?} in {:?}",
                frame, current
            ))),
        }
    }

    pub fn transition_recv(&mut self, ty: FrameType) -> Result<()> {
        match (self.state, ty) {
            (StreamState::Idle, FrameType::Open) => {
                self.state = StreamState::Open;
                Ok(())
            }
            (StreamState::Open, FrameType::Data | FrameType::WindowUpdate) => Ok(()),
            (StreamState::Open, FrameType::Fin) => {
                self.state = StreamState::HalfClosedRemote;
                Ok(())
            }
            (StreamState::HalfClosedLocal, FrameType::Data | FrameType::WindowUpdate) => Ok(()),
            (StreamState::HalfClosedLocal, FrameType::Fin) => {
                self.state = StreamState::Closed;
                Ok(())
            }
            (s, FrameType::Rst) if s != StreamState::Idle => {
                self.state = StreamState::Closed;
                Ok(())
            }
            (current, frame) => Err(ProtoError::ProtocolError(format!(
                "Invalid state transition: recv {:?} in {:?}",
                frame, current
            ))),
        }
    }
}

#[derive(Debug)]
pub struct TombstoneMap {
    tombstones: HashMap<u32, Instant>,
    ttl: Duration,
}

impl TombstoneMap {
    pub fn new(ttl: Duration) -> Self {
        Self {
            tombstones: HashMap::new(),
            ttl,
        }
    }

    pub fn insert(&mut self, stream_id: u32) {
        self.tombstones.insert(stream_id, Instant::now());
    }

    pub fn is_tombstoned(&self, stream_id: u32) -> bool {
        if let Some(&created) = self.tombstones.get(&stream_id) {
            created.elapsed() < self.ttl
        } else {
            false
        }
    }

    pub fn prune(&mut self) {
        let ttl = self.ttl;
        self.tombstones.retain(|_, created| created.elapsed() < ttl);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qt_proto::FrameType;
    use std::time::Duration;

    #[test]
    fn test_valid_lifecycle_local_close_first() {
        let mut sm = StreamStateMachine::new(1, true);
        assert_eq!(sm.state(), StreamState::Idle);

        sm.transition_send(FrameType::Open).unwrap();
        assert_eq!(sm.state(), StreamState::Open);
        assert!(sm.can_send_data());
        assert!(sm.can_recv_data());

        sm.transition_send(FrameType::Fin).unwrap();
        assert_eq!(sm.state(), StreamState::HalfClosedLocal);
        assert!(!sm.can_send_data());
        assert!(sm.can_recv_data());

        sm.transition_recv(FrameType::Fin).unwrap();
        assert_eq!(sm.state(), StreamState::Closed);
        assert!(!sm.can_send_data());
        assert!(!sm.can_recv_data());
    }

    #[test]
    fn test_valid_lifecycle_remote_close_first() {
        let mut sm = StreamStateMachine::new(2, false);
        sm.transition_recv(FrameType::Open).unwrap();
        assert_eq!(sm.state(), StreamState::Open);

        sm.transition_recv(FrameType::Fin).unwrap();
        assert_eq!(sm.state(), StreamState::HalfClosedRemote);
        assert!(sm.can_send_data());
        assert!(!sm.can_recv_data());

        sm.transition_send(FrameType::Fin).unwrap();
        assert_eq!(sm.state(), StreamState::Closed);
    }

    #[test]
    fn test_rst_from_open_and_half_closed() {
        let mut sm = StreamStateMachine::new(1, true);
        sm.transition_send(FrameType::Open).unwrap();
        sm.transition_recv(FrameType::Rst).unwrap();
        assert_eq!(sm.state(), StreamState::Closed);

        let mut sm2 = StreamStateMachine::new(3, true);
        sm2.transition_send(FrameType::Open).unwrap();
        sm2.transition_send(FrameType::Fin).unwrap();
        sm2.transition_send(FrameType::Rst).unwrap();
        assert_eq!(sm2.state(), StreamState::Closed);
    }

    #[test]
    fn test_invalid_transitions() {
        let mut sm = StreamStateMachine::new(1, true);
        // Cannot send DATA in Idle
        assert!(sm.transition_send(FrameType::Data).is_err());
        // Cannot send FIN in Idle
        assert!(sm.transition_send(FrameType::Fin).is_err());

        sm.transition_send(FrameType::Open).unwrap();
        sm.transition_send(FrameType::Fin).unwrap();
        // Cannot send DATA when HalfClosedLocal
        assert!(sm.transition_send(FrameType::Data).is_err());
    }

    #[test]
    fn test_tombstone_map_expiry() {
        let mut tombstones = TombstoneMap::new(Duration::from_millis(50));
        tombstones.insert(10);
        assert!(tombstones.is_tombstoned(10));
        assert!(!tombstones.is_tombstoned(20));

        std::thread::sleep(Duration::from_millis(60));
        tombstones.prune();
        assert!(!tombstones.is_tombstoned(10));
    }
}
