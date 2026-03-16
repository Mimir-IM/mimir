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
    pub update_time: i64,
}

// ── Yggdrasil peer info ───────────────────────────────────────────────────────

/// Current active Yggdrasil router peer and its quality metrics.
/// Returned by [`PeerNode::wait_for_peer_change`] for long-polling.
#[derive(Debug, Clone, PartialEq)]
pub struct YggPeerInfo {
    /// URI of the currently active peer, or `None` if no peer is connected.
    pub uri:      Option<String>,
    /// Last measured Yggdrasil routing cost (lower = better). 0 if unknown.
    pub cost:     u32,
    /// Accumulated failure count for this peer.
    pub failures: u32,
}

// ── Mediator types ────────────────────────────────────────────────────────────

/// A group chat message returned by `get_messages_since`.
#[derive(Debug, Clone)]
pub struct GroupMessage {
    pub message_id: i64,
    pub guid:       i64,
    pub timestamp:  i64,
    pub author:     Vec<u8>,
    pub data:       Vec<u8>,
}

/// Member entry returned by `get_members` (lightweight: pubkey + permissions + online status).
#[derive(Debug, Clone)]
pub struct GroupMember {
    pub pubkey:      Vec<u8>,
    pub permissions: u32,
    pub online:      bool,
    pub last_seen:   i64,
}

/// Member entry returned by `get_members_info` (includes encrypted profile blob).
#[derive(Debug, Clone)]
pub struct GroupMemberInfo {
    pub pubkey:         Vec<u8>,
    pub encrypted_info: Option<Vec<u8>>,
    pub timestamp:      i64,
}

/// File metadata returned by `FilesNode::file_info`.
#[derive(Debug, Clone)]
pub struct FileInfo {
    pub total_size: u64,
    pub message_guid: i64,
}

/// Opaque encrypted member info blob returned by `on_member_info_request`.
/// Kotlin encrypts the profile (nickname + info + avatar) with the chat shared key
/// and returns the ciphertext so Rust can send it to the mediator.
#[derive(Debug, Clone)]
pub struct MemberInfoData {
    pub encrypted_blob: Vec<u8>,
    pub timestamp:      i64,
}
