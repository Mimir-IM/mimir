//! Multi-mediator connection manager with automatic reconnection.
//!
//! Maintains a pool of [`MediatorClient`] instances (one per mediator public key)
//! and exponential-backoff reconnection.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use tokio::sync::broadcast;
use ygg_stream::AsyncNode;

use crate::{MimirError, MediatorEventListener};
use super::client::MediatorClient;

// ── Reconnection parameters ───────────────────────────────────────────────────

const BASE_DELAY: Duration = Duration::from_secs(2);
const MAX_DELAY: Duration = Duration::from_secs(120);
const MAX_ATTEMPTS: u32 = 300;

pub struct MediatorManager {
    node: Arc<AsyncNode>,
    sk: Arc<SigningKey>,
    port: u16,
    listener: Arc<dyn MediatorEventListener>,
    /// pubkey (hex) → live MediatorClient
    clients: Mutex<HashMap<String, MediatorClient>>,
    /// pubkey (hex) → reconnection attempt count
    attempts: Mutex<HashMap<String, u32>>,
    /// stop signal cancels all reconnect tasks
    stop_tx: broadcast::Sender<()>,
}

impl MediatorManager {
    pub fn new(node: Arc<AsyncNode>, sk: Arc<SigningKey>, port: u16, listener: Arc<dyn MediatorEventListener>) -> Self {
        let (stop_tx, _) = broadcast::channel::<()>(1);
        MediatorManager {
            node,
            sk,
            port,
            listener,
            clients: Mutex::new(HashMap::new()),
            attempts: Mutex::new(HashMap::new()),
            stop_tx,
        }
    }

    /// Return the running client for `mediator_pubkey`, creating it if needed.
    pub async fn get_or_create(self: &Arc<Self>, mediator_pubkey: &[u8; 32]) -> Result<MediatorClient, MimirError> {
        let hex = hex::encode(mediator_pubkey);

        // Check for live existing connection.
        {
            let map = self.clients.lock().unwrap();
            if let Some(client) = map.get(&hex) {
                return Ok(client.clone());
            }
        }

        self.do_connect(mediator_pubkey, &hex).await
    }

    async fn do_connect(self: &Arc<Self>, mediator_pubkey: &[u8; 32], hex: &str) -> Result<MediatorClient, MimirError> {
        // Wrap the user's listener so that on_disconnected also schedules reconnect.
        let wrapped: Arc<dyn MediatorEventListener> = Arc::new(ReconnectListener {
            inner: Arc::clone(&self.listener),
            manager: Arc::clone(self),
            pubkey: *mediator_pubkey,
        });

        let client = MediatorClient::connect(
            &self.node,
            *mediator_pubkey,
            self.port,
            Arc::clone(&self.sk),
            wrapped,
        ).await?;

        // Resubscribe to all chats the server knows we're in.
        match client.get_user_chats().await {
            Ok(chat_ids) => {
                for chat_id in chat_ids {
                    if let Err(e) = client.subscribe(chat_id).await {
                        log::warn!(
                            "mediator {}: auto-subscribe chat {chat_id} failed: {e}",
                            &hex[..8]
                        );
                    }
                }
            }
            Err(e) => log::warn!("mediator {}: get_user_chats failed: {e}", &hex[..8]),
        }

        self.clients.lock().unwrap().insert(hex.to_string(), client.clone());
        // Reset reconnect counter on successful connection.
        self.attempts.lock().unwrap().remove(hex);

        // Notify the app that the connection is fully ready (all chats subscribed).
        self.listener.on_connected(mediator_pubkey.to_vec());

        Ok(client)
    }

    /// Remove the client entry (called by ReconnectListener on disconnect).
    fn remove_client(&self, hex: &str) {
        self.clients.lock().unwrap().remove(hex);
    }

    /// Schedule a reconnection with exponential backoff.
    pub fn schedule_reconnect(self: &Arc<Self>, mediator_pubkey: [u8; 32]) {
        let hex = hex::encode(mediator_pubkey);

        let attempt = {
            let mut map = self.attempts.lock().unwrap();
            let count = map.entry(hex.clone()).or_insert(0);
            *count += 1;
            *count
        };

        if attempt > MAX_ATTEMPTS {
            log::warn!("mediator {}: max reconnection attempts reached", &hex[..8]);
            return;
        }

        let exponent = (attempt - 1).min(30) as u32;
        let delay = BASE_DELAY.saturating_mul(1u32 << exponent).min(MAX_DELAY);
        log::info!("mediator {}: reconnecting in {delay:?} (attempt {attempt})", &hex[..8]);

        let mgr = Arc::clone(self);
        let mut stop_rx = self.stop_tx.subscribe();
        tokio::spawn(async move {
            tokio::select! {
                biased;
                _ = stop_rx.recv() => { return; }
                _ = tokio::time::sleep(delay) => {}
            }

            if let Err(e) = mgr.do_connect(&mediator_pubkey, &hex).await {
                log::error!("mediator {}: reconnect failed: {e}", &hex[..8]);
                mgr.schedule_reconnect(mediator_pubkey);
            }
        });
    }

    /// Retrieve a live client (returns None if not connected).
    pub fn get(&self, mediator_pubkey: &[u8; 32]) -> Option<MediatorClient> {
        let hex = hex::encode(mediator_pubkey);
        self.clients.lock().unwrap().get(&hex).cloned()
    }

    /// Stop all connections and cancel all reconnect tasks.
    pub fn stop_all(&self) {
        let _ = self.stop_tx.send(());
        for client in self.clients.lock().unwrap().values() {
            client.stop();
        }
    }
}

// ── ReconnectListener ─────────────────────────────────────────────────────────
//
// Intercepts `on_disconnected` to remove the dead client entry and schedule
// a reconnect, then forwards every event to the real listener.

struct ReconnectListener {
    inner: Arc<dyn MediatorEventListener>,
    manager: Arc<MediatorManager>,
    pubkey: [u8; 32],
}

impl MediatorEventListener for ReconnectListener {
    fn on_connected(&self, mediator_pubkey: Vec<u8>) {
        self.inner.on_connected(mediator_pubkey);
    }

    fn on_push_message(
        &self, chat_id: i64, message_id: i64, guid: i64,
        timestamp: i64, author: Vec<u8>, data: Vec<u8>,
    ) {
        self.inner.on_push_message(chat_id, message_id, guid, timestamp, author, data);
    }

    fn on_system_message(
        &self, chat_id: i64, message_id: i64, guid: i64,
        timestamp: i64, body: Vec<u8>,
    ) {
        self.inner.on_system_message(chat_id, message_id, guid, timestamp, body);
    }

    fn on_push_invite(
        &self, invite_id: i64, chat_id: i64, from_pubkey: Vec<u8>,
        timestamp: i64, chat_name: String, chat_desc: String,
        chat_avatar: Option<Vec<u8>>, encrypted_data: Vec<u8>,
    ) {
        self.inner.on_push_invite(
            invite_id, chat_id, from_pubkey, timestamp,
            chat_name, chat_desc, chat_avatar, encrypted_data,
        );
    }

    fn on_member_info_request(&self, chat_id: i64, last_update: i64) -> Option<crate::types::MemberInfoData> {
        self.inner.on_member_info_request(chat_id, last_update)
    }

    fn on_member_info_update(
        &self, chat_id: i64, member_pubkey: Vec<u8>,
        encrypted_info: Option<Vec<u8>>, timestamp: i64,
    ) {
        self.inner.on_member_info_update(chat_id, member_pubkey, encrypted_info, timestamp);
    }

    fn on_member_online_status_changed(
        &self, chat_id: i64, member_pubkey: Vec<u8>,
        is_online: bool, timestamp: i64,
    ) {
        self.inner.on_member_online_status_changed(chat_id, member_pubkey, is_online, timestamp);
    }

    fn on_disconnected(&self, mediator_pubkey: Vec<u8>) {
        let hex = hex::encode(&mediator_pubkey);
        log::warn!("mediator {}: disconnected, scheduling reconnect", &hex[..8.min(hex.len())]);
        self.manager.remove_client(&hex);
        self.manager.schedule_reconnect(self.pubkey);
        self.inner.on_disconnected(mediator_pubkey);
    }
}
