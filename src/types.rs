/// Call state for the currently active P2P call (if any).
#[derive(Debug, Clone, PartialEq)]
pub enum CallStatus {
    /// No active call.
    Idle,
    /// We initiated a call; waiting for the remote to answer.
    Calling,
    /// Incoming call; waiting for us to answer.
    Receiving,
    /// Call is established and audio is flowing.
    InCall,
    /// Call ended (by either side).
    Hangup,
}

/// Contact profile info exchanged with peers on every connection.
#[derive(Debug, Clone)]
pub struct ContactInfo {
    pub nickname:    String,
    pub info:        String,
    pub avatar:      Option<Vec<u8>>,
    pub update_time: u64,
}
