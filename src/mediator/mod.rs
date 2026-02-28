//! Mediator-based group-chat networking.
//!
//! [`MediatorNode`] is the UniFFI-exported top-level object.  It shares the
//! Yggdrasil node from a [`PeerNode`] (same identity, same underlying network
//! connection) and manages connections to one or more mediator servers.

pub mod client;
pub mod manager;
pub mod protocol;

use std::sync::Arc;

use crate::peer::PeerNode;
use crate::types::{GroupMember, GroupMemberInfo, GroupMessage};
use crate::{MediatorEventListener, MimirError};
use manager::MediatorManager;

// ── MediatorNode ──────────────────────────────────────────────────────────────

/// Top-level mediator/group-chat node.
///
/// Shares the Yggdrasil identity with an existing `PeerNode` (same signing key,
/// same IPv6 address on the overlay network).  All connection, auth, and
/// protocol logic is handled internally; callers only call the public methods.
///
/// All methods are thread-safe and can be called from any thread.
pub struct MediatorNode {
    rt: Arc<tokio::runtime::Runtime>,
    sk: Arc<ed25519_dalek::SigningKey>,
    manager: Arc<MediatorManager>,
}

impl MediatorNode {
    /// Create a new `MediatorNode` that shares the Yggdrasil node from `peer_node`.
    ///
    /// * `peer_node`        – A running `PeerNode`; its Ygg node and runtime are reused.
    /// * `mediator_port`    – The TCP-level port number the mediator listens on.
    /// * `event_listener`   – Receives all mediator events (messages, invites, etc.).
    pub fn new(peer_node: Arc<PeerNode>, mediator_port: u16, event_listener: Box<dyn MediatorEventListener>) -> Result<Self, MimirError> {
        let ygg_node = peer_node.ygg_node();
        let rt = peer_node.runtime();
        let sk = peer_node.signing_key();

        let listener: Arc<dyn MediatorEventListener> = Arc::from(event_listener);
        let manager = Arc::new(MediatorManager::new(
            ygg_node,
            Arc::clone(&sk),
            mediator_port,
            listener,
        ));

        Ok(MediatorNode { rt, sk, manager })
    }

    // ── Connection management ─────────────────────────────────────────────────

    /// Dial `mediator_pubkey` and authenticate.
    ///
    /// Returns immediately (the actual connection happens asynchronously); the
    /// `on_connected` callback fires when authentication succeeds.  If already
    /// connected, this is a no-op.
    pub fn connect_to_mediator(&self, mediator_pubkey: Vec<u8>) -> Result<(), MimirError> {
        let key = to_key32(&mediator_pubkey)?;
        let mgr = Arc::clone(&self.manager);
        self.rt.spawn(async move {
            if let Err(e) = mgr.get_or_create(&key).await {
                log::error!("connect_to_mediator {}: {e}", hex::encode(key));
            }
        });
        Ok(())
    }

    /// Stop all mediator connections.
    pub fn stop(&self) {
        self.manager.stop_all();
    }

    // ── Group chat CRUD ───────────────────────────────────────────────────────

    /// Create a new group chat.  Includes proof-of-work (~1–5 seconds CPU).
    /// Returns the new chat ID assigned by the mediator.
    pub fn create_chat(&self, mediator_pubkey: Vec<u8>, name: String, description: String, avatar: Option<Vec<u8>>) -> Result<i64, MimirError> {
        let key = to_key32(&mediator_pubkey)?;
        let sk = Arc::clone(&self.sk);
        self.rt.block_on(async move {
            let client = self.manager.get_or_create(&key).await?;
            client.create_chat(
                &sk,
                &name,
                &description,
                avatar.as_deref(),
            ).await
        })
    }

    pub fn delete_chat(&self, mediator_pubkey: Vec<u8>, chat_id: i64) -> Result<(), MimirError> {
        let key = to_key32(&mediator_pubkey)?;
        self.rt.block_on(async move {
            let client = self.manager.get_or_create(&key).await?;
            client.delete_chat(chat_id).await
        })
    }

    pub fn update_chat_info(&self, mediator_pubkey: Vec<u8>, chat_id: i64, name: Option<String>, description: Option<String>, avatar: Option<Vec<u8>>) -> Result<(), MimirError> {
        let key = to_key32(&mediator_pubkey)?;
        self.rt.block_on(async move {
            let client = self.manager.get_or_create(&key).await?;
            client.update_chat_info(
                chat_id,
                name.as_deref(),
                description.as_deref(),
                avatar.as_deref(),
            ).await
        })
    }

    // ── Membership ────────────────────────────────────────────────────────────

    pub fn add_user(&self, mediator_pubkey: Vec<u8>, chat_id: i64, user_pubkey: Vec<u8>) -> Result<(), MimirError> {
        let key = to_key32(&mediator_pubkey)?;
        self.rt.block_on(async move {
            let client = self.manager.get_or_create(&key).await?;
            client.add_user(chat_id, &user_pubkey).await
        })
    }

    pub fn delete_user(&self, mediator_pubkey: Vec<u8>, chat_id: i64, user_pubkey: Vec<u8>) -> Result<(), MimirError> {
        let key = to_key32(&mediator_pubkey)?;
        self.rt.block_on(async move {
            let client = self.manager.get_or_create(&key).await?;
            client.delete_user(chat_id, &user_pubkey).await
        })
    }

    pub fn leave_chat(&self, mediator_pubkey: Vec<u8>, chat_id: i64) -> Result<(), MimirError> {
        let key = to_key32(&mediator_pubkey)?;
        self.rt.block_on(async move {
            let client = self.manager.get_or_create(&key).await?;
            client.leave_chat(chat_id).await
        })
    }

    pub fn change_member_status(&self, mediator_pubkey: Vec<u8>, chat_id: i64, user_pubkey: Vec<u8>, new_permissions: u8) -> Result<(), MimirError> {
        let key = to_key32(&mediator_pubkey)?;
        self.rt.block_on(async move {
            let client = self.manager.get_or_create(&key).await?;
            client.change_member_status(chat_id, &user_pubkey, new_permissions).await
        })
    }

    // ── Messages ──────────────────────────────────────────────────────────────

    /// Subscribe to push messages for `chat_id`.
    /// Returns the server's last message ID (use to fetch missed messages).
    pub fn subscribe(&self, mediator_pubkey: Vec<u8>, chat_id: i64) -> Result<i64, MimirError> {
        let key = to_key32(&mediator_pubkey)?;
        self.rt.block_on(async move {
            let client = self.manager.get_or_create(&key).await?;
            client.subscribe(chat_id).await
        })
    }

    /// Send an encrypted message blob.  Returns the server-assigned message ID.
    pub fn send_group_message(&self, mediator_pubkey: Vec<u8>, chat_id: i64, guid: i64, timestamp: i64, data: Vec<u8>) -> Result<i64, MimirError> {
        let key = to_key32(&mediator_pubkey)?;
        self.rt.block_on(async move {
            let client = self.manager.get_or_create(&key).await?;
            let (msg_id, _new_guid) = client.send_message(chat_id, guid, timestamp, &data).await?;
            Ok(msg_id)
        })
    }

    pub fn delete_message(&self, mediator_pubkey: Vec<u8>, chat_id: i64, message_id: i64) -> Result<(), MimirError> {
        let key = to_key32(&mediator_pubkey)?;
        self.rt.block_on(async move {
            let client = self.manager.get_or_create(&key).await?;
            client.delete_message(chat_id, message_id).await
        })
    }

    pub fn get_last_message_id(&self, mediator_pubkey: Vec<u8>, chat_id: i64) -> Result<i64, MimirError> {
        let key = to_key32(&mediator_pubkey)?;
        self.rt.block_on(async move {
            let client = self.manager.get_or_create(&key).await?;
            client.get_last_message_id(chat_id).await
        })
    }

    pub fn get_messages_since(&self, mediator_pubkey: Vec<u8>, chat_id: i64, since_id: i64, limit: u32) -> Result<Vec<GroupMessage>, MimirError> {
        let key = to_key32(&mediator_pubkey)?;
        self.rt.block_on(async move {
            let client = self.manager.get_or_create(&key).await?;
            client.get_messages_since(chat_id, since_id, limit).await
        })
    }

    // ── Invites ───────────────────────────────────────────────────────────────

    pub fn send_invite(&self, mediator_pubkey: Vec<u8>, chat_id: i64, recipient_pubkey: Vec<u8>, encrypted_data: Vec<u8>) -> Result<(), MimirError> {
        let key = to_key32(&mediator_pubkey)?;
        self.rt.block_on(async move {
            let client = self.manager.get_or_create(&key).await?;
            client.send_invite(chat_id, &recipient_pubkey, &encrypted_data).await
        })
    }

    pub fn respond_to_invite(&self, mediator_pubkey: Vec<u8>, chat_id: i64, invite_id: i64, accept: bool) -> Result<(), MimirError> {
        let key = to_key32(&mediator_pubkey)?;
        self.rt.block_on(async move {
            let client = self.manager.get_or_create(&key).await?;
            client.respond_to_invite(chat_id, invite_id, accept).await
        })
    }

    // ── Member info ───────────────────────────────────────────────────────────

    /// Push our encrypted profile blob to the mediator for `chat_id`.
    pub fn update_member_info(&self, mediator_pubkey: Vec<u8>, chat_id: i64, encrypted_blob: Vec<u8>, timestamp: i64) -> Result<(), MimirError> {
        let key = to_key32(&mediator_pubkey)?;
        self.rt.block_on(async move {
            let client = self.manager.get_or_create(&key).await?;
            client.update_member_info(chat_id, &encrypted_blob, timestamp).await
        })
    }

    pub fn get_members_info(&self, mediator_pubkey: Vec<u8>, chat_id: i64, since_timestamp: i64) -> Result<Vec<GroupMemberInfo>, MimirError> {
        let key = to_key32(&mediator_pubkey)?;
        self.rt.block_on(async move {
            let client = self.manager.get_or_create(&key).await?;
            client.get_members_info(chat_id, since_timestamp).await
        })
    }

    pub fn get_members(&self, mediator_pubkey: Vec<u8>, chat_id: i64) -> Result<Vec<GroupMember>, MimirError> {
        let key = to_key32(&mediator_pubkey)?;
        self.rt.block_on(async move {
            let client = self.manager.get_or_create(&key).await?;
            client.get_members(chat_id).await
        })
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn to_key32(v: &[u8]) -> Result<[u8; 32], MimirError> {
    v.try_into().map_err(|_| MimirError::Connection(
        format!("expected 32-byte mediator pubkey, got {} bytes", v.len())
    ))
}
