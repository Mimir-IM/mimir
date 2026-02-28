use crate::types::{CallStatus, ContactInfo, MemberInfoData};

/// Provides local user info and stores contact info received from peers.
/// All methods are called from Rust connection tasks — must return quickly.
pub trait InfoProvider: Send + Sync {
    /// Return our current contact info if updated after `since_time`, else None.
    fn get_my_info(&self, since_time: i64) -> Option<ContactInfo>;
    /// Return the last known update timestamp for a peer's contact info.
    fn get_contact_update_time(&self, pubkey: Vec<u8>) -> i64;
    /// Called when a peer sent us their updated contact info.
    fn update_contact_info(&self, pubkey: Vec<u8>, info: ContactInfo);
    /// Return the directory path where file attachments are stored.
    fn get_files_dir(&self) -> String;
}

/// Receives P2P networking events. All callbacks are invoked from Rust
/// connection tasks and must return quickly.
pub trait PeerEventListener: Send + Sync {
    /// Fired when the Yggdrasil overlay network goes online (first peer connects)
    /// or offline (last peer disconnects).  Use this to show the connectivity badge.
    fn on_connectivity_changed(&self, is_online: bool);
    fn on_peer_connected(&self, pubkey: Vec<u8>, address: String);
    fn on_peer_disconnected(&self, pubkey: Vec<u8>, address: String, dead_peer: bool);
    fn on_message_received(
        &self,
        pubkey: Vec<u8>,
        guid: i64,
        reply_to: i64,
        send_time: i64,
        edit_time: i64,
        msg_type: i32,
        data: Vec<u8>,
    );
    fn on_message_delivered(&self, pubkey: Vec<u8>, guid: i64);
    fn on_incoming_call(&self, pubkey: Vec<u8>);
    fn on_call_status_changed(&self, status: CallStatus, pubkey: Option<Vec<u8>>);
    fn on_call_packet(&self, pubkey: Vec<u8>, data: Vec<u8>);
}

/// Receives mediator (group-chat server) events.
/// All callbacks are invoked from Rust async tasks — must return quickly.
///
/// Note: encryption/decryption of message blobs is done by the caller (Kotlin/Swift).
/// Rust only handles the wire protocol; it passes encrypted bytes through unchanged.
pub trait MediatorEventListener: Send + Sync {
    /// Authenticated connection to this mediator established.
    fn on_connected(&self, mediator_pubkey: Vec<u8>);

    /// A group chat message arrived (data is the encrypted blob from the sender).
    fn on_push_message(
        &self,
        chat_id: i64,
        message_id: i64,
        guid: i64,
        timestamp: i64,
        author: Vec<u8>,
        data: Vec<u8>,
    );

    /// A mediator-generated system message arrived (always unencrypted).
    ///
    /// Body format: `[event_code(1)][event-specific bytes...]`
    /// event codes: SYS_USER_ADDED=0x01, SYS_USER_LEFT=0x03, SYS_USER_BANNED=0x04,
    ///              SYS_CHAT_DELETED=0x05, SYS_CHAT_INFO_CHANGE=0x06,
    ///              SYS_PERMS_CHANGED=0x07, SYS_MESSAGE_DELETED=0x08,
    ///              SYS_MEMBER_ONLINE=0x09
    fn on_system_message(&self, chat_id: i64, message_id: i64, guid: i64, timestamp: i64, body: Vec<u8>);

    /// A group chat invitation arrived.
    /// `encrypted_data` is the AES-wrapped shared key (to be decrypted by the recipient).
    fn on_push_invite(
        &self,
        invite_id: i64,
        chat_id: i64,
        from_pubkey: Vec<u8>,
        timestamp: i64,
        chat_name: String,
        chat_desc: String,
        chat_avatar: Option<Vec<u8>>,
        encrypted_data: Vec<u8>,
    );

    /// Mediator is asking us to (re-)send our member profile for a chat.
    ///
    /// Return `Some(MemberInfoData)` with the pre-encrypted blob + timestamp if an
    /// update is needed (i.e. our profile is newer than `last_update`), or `None`
    /// to tell the mediator nothing changed.
    fn on_member_info_request(&self, chat_id: i64, last_update: i64) -> Option<MemberInfoData>;

    /// Mediator broadcast: another member's encrypted profile was updated.
    fn on_member_info_update(&self, chat_id: i64, member_pubkey: Vec<u8>, encrypted_info: Option<Vec<u8>>, timestamp: i64);

    /// Mediator broadcast: a member came online or went offline.
    /// `timestamp` is Unix seconds.
    fn on_member_online_status_changed(&self, chat_id: i64, member_pubkey: Vec<u8>, is_online: bool, timestamp: i64);

    /// Connection to this mediator ended (error or explicit stop).
    fn on_disconnected(&self, mediator_pubkey: Vec<u8>);
}
