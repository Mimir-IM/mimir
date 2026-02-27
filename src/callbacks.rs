use crate::types::{CallStatus, ContactInfo};

/// Provides local user info and stores contact info received from peers.
/// All methods are called from Rust connection tasks — must return quickly.
pub trait InfoProvider: Send + Sync {
    /// Return our current contact info if updated after `since_time`, else None.
    fn get_my_info(&self, since_time: u64) -> Option<ContactInfo>;
    /// Return the last known update timestamp for a peer's contact info.
    fn get_contact_update_time(&self, pubkey: Vec<u8>) -> u64;
    /// Called when a peer sent us their updated contact info.
    fn update_contact_info(&self, pubkey: Vec<u8>, info: ContactInfo);
    /// Return the directory path where file attachments are stored.
    fn get_files_dir(&self) -> String;
}

/// Receives P2P networking events. All callbacks are invoked from Rust
/// connection tasks and must return quickly.
pub trait PeerEventListener: Send + Sync {
    fn on_peer_connected(&self, pubkey: Vec<u8>, address: String);
    fn on_peer_disconnected(&self, pubkey: Vec<u8>, address: String, dead_peer: bool);
    fn on_message_received(
        &self,
        pubkey:    Vec<u8>,
        guid:      u64,
        reply_to:  u64,
        send_time: u64,
        edit_time: u64,
        msg_type:  i32,
        data:      Vec<u8>,
    );
    fn on_message_delivered(&self, pubkey: Vec<u8>, guid: u64);
    fn on_incoming_call(&self, pubkey: Vec<u8>);
    fn on_call_status_changed(&self, status: CallStatus, pubkey: Option<Vec<u8>>);
    fn on_call_packet(&self, pubkey: Vec<u8>, data: Vec<u8>);
}
