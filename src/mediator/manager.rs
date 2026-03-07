//! Multi-mediator connection manager with automatic reconnection.
//!
//! Maintains a pool of [`MediatorClient`] instances (one per mediator public key)
//! and exponential-backoff reconnection.

use std::collections::{HashMap, HashSet};
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
    /// Per-key async mutex — serialises concurrent connect attempts for the same mediator.
    connecting: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    /// Chats the app explicitly subscribed to, merged with server list on reconnect.
    subscriptions: Mutex<HashMap<String, HashSet<i64>>>,
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
            connecting: Mutex::new(HashMap::new()),
            subscriptions: Mutex::new(HashMap::new()),
        }
    }

    /// Return the running client for `mediator_pubkey`, creating it if needed.
    ///
    /// Uses a per-key async mutex to prevent concurrent connection races: if two
    /// callers arrive simultaneously for the same mediator, only one connects and
    /// the other reuses the result.
    pub async fn get_or_create(self: &Arc<Self>, mediator_pubkey: &[u8; 32]) -> Result<MediatorClient, MimirError> {
        let hex = hex::encode(mediator_pubkey);

        // Fast path: live connection already exists.
        {
            let map = self.clients.lock().unwrap();
            if let Some(client) = map.get(&hex) {
                return Ok(client.clone());
            }
        }

        // Acquire a per-key async lock to serialize concurrent connect attempts.
        let key_lock = {
            let mut map = self.connecting.lock().unwrap();
            Arc::clone(map.entry(hex.clone())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))))
        };
        let _guard = key_lock.lock().await;

        // Double-check: another task may have connected while we were waiting.
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

        // Gather chats to resubscribe: locally-remembered (from explicit subscribe()
        // calls) merged with the server's membership list.
        let mut chat_ids: HashSet<i64> = self.subscriptions.lock().unwrap()
            .get(hex).cloned().unwrap_or_default();

        match client.get_user_chats().await {
            Ok(server_chats) => chat_ids.extend(server_chats),
            Err(e) => log::warn!("mediator {}: get_user_chats failed: {e}", &hex[..8]),
        }

        // Insert atomically while checking that the connection hasn't already died.
        {
            let mut map = self.clients.lock().unwrap();
            if client.is_disconnected() {
                // Reader/ping detected disconnect before we finished setup — retry.
                return Err(MimirError::Connection(
                    "connection dropped immediately after auth".into()
                ));
            }
            map.insert(hex.to_string(), client.clone());
        }

        // Reset reconnect counter on successful connection.
        self.attempts.lock().unwrap().remove(hex);

        // Notify the app FIRST — client is in the map so any mimir call from the
        // callback hits the fast path in get_or_create (no key-lock contention).
        // The app's onConnected handler typically subscribes to all its known chats,
        // which fires on_subscribed once per chat with the correct last_message_id.
        self.listener.on_connected(mediator_pubkey.to_vec());

        // Silently re-subscribe as a safety net (idempotent on the server).
        // We do NOT fire on_subscribed here — the app's onConnected already called
        // subscribe() for each chat, which fires on_subscribed with proper context.
        // Firing it again here would cause double syncMissedMessages runs.
        for chat_id in chat_ids {
            if let Err(e) = client.subscribe(chat_id).await {
                log::warn!("mediator {}: auto-subscribe chat {chat_id} failed: {e}", &hex[..8]);
            }
        }

        Ok(client)
    }

    /// Add `chat_id` to the persistent subscription registry for this mediator.
    /// Called after a successful explicit `subscribe()` so it survives reconnects.
    pub fn remember_subscription(&self, mediator_hex: &str, chat_id: i64) {
        self.subscriptions.lock().unwrap()
            .entry(mediator_hex.to_string())
            .or_insert_with(HashSet::new)
            .insert(chat_id);
    }

    /// Remove `chat_id` from the subscription registry (call after leave_chat).
    pub fn forget_subscription(&self, mediator_hex: &str, chat_id: i64) {
        let mut map = self.subscriptions.lock().unwrap();
        if let Some(set) = map.get_mut(mediator_hex) {
            set.remove(&chat_id);
        }
    }

    /// Remove the dead client entry.  Only removes if the stored client has its
    /// `disconnected` flag set — this prevents a stale reader from evicting a
    /// freshly-connected replacement client.  Returns `true` if removed.
    fn remove_client(&self, hex: &str) -> bool {
        let mut map = self.clients.lock().unwrap();
        if let Some(client) = map.get(hex) {
            if client.is_disconnected() {
                map.remove(hex);
                return true;
            }
        }
        false
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

            // Use get_or_create so the per-key lock prevents parallel reconnects.
            if let Err(e) = mgr.get_or_create(&mediator_pubkey).await {
                log::error!("mediator {}: reconnect failed: {e}", &hex[..8]);
                mgr.schedule_reconnect(mediator_pubkey);
            }
        });
    }

    /// Fire `on_subscribed` on the user listener (used by `MediatorNode::subscribe`).
    pub fn fire_subscribed(&self, mediator_pubkey: &[u8; 32], chat_id: i64, last_message_id: i64) {
        self.listener.on_subscribed(mediator_pubkey.to_vec(), chat_id, last_message_id);
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

// ── Helpers ───────────────────────────────────────────────────────────────────

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

    fn on_subscribed(&self, mediator_pubkey: Vec<u8>, chat_id: i64, last_message_id: i64) {
        self.inner.on_subscribed(mediator_pubkey, chat_id, last_message_id);
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
        chat_avatar: Option<Vec<u8>>, encrypted_data: Vec<u8>, mediator_pubkey: Vec<u8>,
    ) {
        self.inner.on_push_invite(
            invite_id, chat_id, from_pubkey, timestamp,
            chat_name, chat_desc, chat_avatar, encrypted_data, mediator_pubkey,
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
        // Only schedule a reconnect if we actually removed the dead client.
        // If remove_client returns false, a newer live client is already in the
        // map (stale reader firing late) — do not disrupt it.
        if self.manager.remove_client(&hex) {
            log::warn!("mediator {}: disconnected, scheduling reconnect", &hex[..8.min(hex.len())]);
            self.manager.schedule_reconnect(self.pubkey);
        } else {
            log::debug!("mediator {}: stale disconnect notification ignored", &hex[..8.min(hex.len())]);
        }
        self.inner.on_disconnected(mediator_pubkey);
    }
}
