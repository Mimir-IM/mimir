//! P2P peer management — [`PeerNode`] is the main UniFFI-exported object.

pub mod connection;
pub mod protocol;
pub mod resolver;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use ed25519_dalek::SigningKey;
use tokio::sync::{broadcast, mpsc};
use tokio::time::sleep;
use ygg_stream::AsyncNode;


use crate::{CallStatus, InfoProvider, MimirError, PeerEventListener};
use connection::{ConnContext, OutgoingCmd, run_inbound, run_outbound};
use resolver::Resolver;

// ── Peers map type alias ──────────────────────────────────────────────────────

type PeersMap = Mutex<HashMap<[u8; 32], mpsc::UnboundedSender<OutgoingCmd>>>;

// ── EventWrapper ──────────────────────────────────────────────────────────────
//
// Wraps the user-supplied PeerEventListener so that on_peer_disconnected also
// removes the peer's command sender from the shared peers map.

struct EventWrapper {
    inner: Arc<dyn PeerEventListener>,
    peers: Arc<PeersMap>,
}

impl PeerEventListener for EventWrapper {
    fn on_connectivity_changed(&self, is_online: bool) {
        self.inner.on_connectivity_changed(is_online);
    }

    fn on_peer_connected(&self, pubkey: Vec<u8>, address: String) {
        self.inner.on_peer_connected(pubkey, address);
    }

    fn on_peer_disconnected(&self, pubkey: Vec<u8>, address: String, dead_peer: bool) {
        if pubkey.len() == 32 {
            let key: [u8; 32] = pubkey.as_slice().try_into().unwrap();
            if let Ok(mut map) = self.peers.lock() {
                map.remove(&key);
            }
        }
        self.inner.on_peer_disconnected(pubkey, address, dead_peer);
    }

    fn on_message_received(&self,pubkey: Vec<u8>, guid: i64, reply_to: i64, send_time: i64, edit_time: i64, msg_type: i32, data: Vec<u8>) {
        self.inner
            .on_message_received(pubkey, guid, reply_to, send_time, edit_time, msg_type, data);
    }

    fn on_message_delivered(&self, pubkey: Vec<u8>, guid: i64) {
        self.inner.on_message_delivered(pubkey, guid);
    }

    fn on_incoming_call(&self, pubkey: Vec<u8>) {
        self.inner.on_incoming_call(pubkey);
    }

    fn on_call_status_changed(&self, status: CallStatus, pubkey: Option<Vec<u8>>) {
        self.inner.on_call_status_changed(status, pubkey);
    }

    fn on_call_packet(&self, pubkey: Vec<u8>, data: Vec<u8>) {
        self.inner.on_call_packet(pubkey, data);
    }
}

// ── Shared runtime state ──────────────────────────────────────────────────────

struct PeerState {
    our_pubkey: [u8; 32],
    signing_key: Arc<SigningKey>,
    node: Arc<AsyncNode>,
    peer_port: u16,
    client_id: i32,
    peers: Arc<PeersMap>,
    event_cb: Arc<dyn PeerEventListener>,
    info_cb: Arc<dyn InfoProvider>,
    resolver: Arc<Resolver>,
}

impl PeerState {
    fn make_ctx(&self) -> Arc<ConnContext> {
        Arc::new(ConnContext {
            signing_key: Arc::clone(&self.signing_key),
            our_pubkey: self.our_pubkey,
            client_id: self.client_id,
            event_cb: Arc::clone(&self.event_cb),
            info_cb: Arc::clone(&self.info_cb),
        })
    }

    fn register_peer(&self, key: [u8; 32], tx: mpsc::UnboundedSender<OutgoingCmd>) {
        if let Ok(mut map) = self.peers.lock() {
            map.insert(key, tx);
        }
    }

    fn send_cmd(&self, pubkey: &[u8; 32], cmd: OutgoingCmd) -> Result<(), MimirError> {
        let map = self
            .peers
            .lock()
            .map_err(|_| MimirError::Connection("peers lock poisoned".to_string()))?;
        match map.get(pubkey) {
            Some(tx) if !tx.is_closed() => {
                tx.send(cmd).map_err(|_| {
                    MimirError::Connection(format!("peer {} channel closed", hex::encode(pubkey)))
                })?;
                Ok(())
            }
            Some(_) => Err(MimirError::Connection(format!(
                "peer {} is disconnected",
                hex::encode(pubkey)
            ))),
            None => Err(MimirError::Connection(format!(
                "no connection to {}",
                hex::encode(pubkey)
            ))),
        }
    }
}

// ── PeerNode ──────────────────────────────────────────────────────────────────

/// Top-level P2P node.  One instance per app lifetime.
///
/// Starts a Yggdrasil node, an inbound-connection accept loop, and manages
/// all authenticated P2P connections to contacts.
pub struct PeerNode {
    rt: Arc<tokio::runtime::Runtime>,
    state: Arc<PeerState>,
    stop_tx: broadcast::Sender<()>,
    /// Guards against multiple concurrent announce loops.
    announce_started: AtomicBool,
    /// Wakes the announce loop from its inter-announcement sleep immediately.
    announce_notify: Arc<tokio::sync::Notify>,
}

impl PeerNode {
    /// Create and start the node.
    ///
    /// * `signing_key`    – 32-byte Ed25519 seed (private key).
    /// * `ygg_peers`      – Yggdrasil bootstrap peer URIs.
    /// * `peer_port`      – Port used for P2P connections (listen + outbound).
    /// * `event_listener` – Receives connection and message events.
    /// * `info_provider`  – Supplies and stores contact profile info.
    pub fn new(
        signing_key: Vec<u8>,
        ygg_peers: Vec<String>,
        peer_port: u16,
        trackers: Vec<String>,
        event_listener: Box<dyn PeerEventListener>,
        info_provider: Box<dyn InfoProvider>
    ) -> Result<Self, MimirError> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| MimirError::Connection(e.to_string()))?;

        // Start the Yggdrasil node (async, so block on it here).
        let node = rt
            .block_on(AsyncNode::new_with_key(&signing_key, ygg_peers))
            .map_err(|e| MimirError::Connection(e.to_string()))?;
        let node = Arc::new(node);

        // Derive signing key + our public key from the seed bytes.
        let key_bytes: [u8; 32] = signing_key.try_into().map_err(|_| {
            MimirError::Connection("signing_key must be exactly 32 bytes".to_string())
        })?;
        let sk = SigningKey::from_bytes(&key_bytes);
        let our_pubkey = crate::crypto::pubkey_of(&sk);

        let (stop_tx, _) = broadcast::channel::<()>(1);

        // Build shared state, wrapping the event listener so disconnection
        // events also remove the peer from the command-sender map.
        let peers: Arc<PeersMap> = Arc::new(Mutex::new(HashMap::new()));
        let event_listener: Arc<dyn PeerEventListener> = Arc::from(event_listener);
        let info_provider: Arc<dyn InfoProvider> = Arc::from(info_provider);
        let event_wrapper: Arc<dyn PeerEventListener> = Arc::new(EventWrapper {
            inner: event_listener,
            peers: Arc::clone(&peers),
        });
        let sk = Arc::new(sk);
        let resolver = Arc::new(Resolver::new(
            Arc::clone(&node),
            Arc::clone(&sk),
            peer_port,
            &trackers,
        ));
        let state = Arc::new(PeerState {
            our_pubkey,
            signing_key: Arc::clone(&sk),
            node: Arc::clone(&node),
            peer_port,
            client_id: 1,
            peers,
            event_cb: event_wrapper,
            info_cb: info_provider,
            resolver,
        });

        // Spawn the inbound-accept loop.
        {
            let state2 = Arc::clone(&state);
            let mut stop_rx = stop_tx.subscribe();
            rt.spawn(async move {
                loop {
                    tokio::select! {
                        biased;
                        _ = stop_rx.recv() => break,
                        conn_result = state2.node.accept(state2.peer_port) => {
                            match conn_result {
                                Ok(conn) => {
                                    let s = Arc::clone(&state2);
                                    tokio::spawn(async move {
                                        let ctx  = s.make_ctx();
                                        let conn = Arc::new(conn);
                                        if let Some((key, tx)) = run_inbound(conn, ctx).await {
                                            s.register_peer(key, tx);
                                        }
                                    });
                                }
                                Err(e) => {
                                    log::error!("Accept error: {}", e);
                                    break;
                                }
                            }
                        }
                    }
                }
            });
        }

        // Probe initial connectivity — subscribe_peer_events() misses events that
        // fired during AsyncNode::new_with_key's internal 1-second sleep.
        let initial_online = rt.block_on(state.node.count_active_peers()) > 0;
        if initial_online {
            state.event_cb.on_connectivity_changed(true);
        }

        // Spawn Yggdrasil peer-event monitor → fires on_connectivity_changed.
        //
        // On every event (including Lagged) we read the *actual* current peer
        // count rather than tracking a running delta.  This mirrors the
        // wait_peer_change pattern in ygg_stream and is immune to counter drift.
        {
            let cb      = Arc::clone(&state.event_cb);
            let node    = Arc::clone(&state.node);
            let mut rx  = state.node.subscribe_peer_events();
            let mut stop_rx = stop_tx.subscribe();
            rt.spawn(async move {
                let mut is_online = initial_online;
                loop {
                    tokio::select! {
                        biased;
                        _ = stop_rx.recv() => break,
                        result = rx.recv() => {
                            match result {
                                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {
                                    let now_online = node.count_active_peers().await > 0;
                                    if now_online != is_online {
                                        is_online = now_online;
                                        cb.on_connectivity_changed(now_online);
                                    }
                                }
                                Err(broadcast::error::RecvError::Closed) => break,
                            }
                        }
                    }
                }
            });
        }

        Ok(PeerNode {
            rt: Arc::new(rt),
            state,
            stop_tx,
            announce_started: AtomicBool::new(false),
            announce_notify: Arc::new(tokio::sync::Notify::new()),
        })
    }

    /// Our 32-byte Ed25519 public key (= Yggdrasil node identity).
    pub fn public_key(&self) -> Vec<u8> {
        self.state.our_pubkey.to_vec()
    }

    /// Queue a message for delivery to the peer identified by `pubkey`.
    ///
    /// The connection must already be established (`on_peer_connected` fired).
    pub fn send_message(&self, pubkey: Vec<u8>, guid: i64, reply_to: i64, send_time: i64, edit_time: i64, msg_type: i32, data: Vec<u8>) -> Result<(), MimirError> {
        let key = vec_to_key(&pubkey)?;
        self.state.send_cmd(
            &key,
            OutgoingCmd::Message {
                guid,
                reply_to,
                send_time,
                edit_time,
                msg_type,
                data,
            },
        )
    }

    /// Open an outbound connection to `pubkey`.
    ///
    /// Returns immediately; `on_peer_connected` fires when mutual auth
    /// completes.  No-op if the peer is already connected.
    pub fn connect_to_peer(&self, pubkey: Vec<u8>) -> Result<(), MimirError> {
        let key = vec_to_key(&pubkey)?;

        // Skip if there is already a live connection to this peer.
        {
            let map = self
                .state
                .peers
                .lock()
                .map_err(|_| MimirError::Connection("peers lock poisoned".to_string()))?;
            if let Some(tx) = map.get(&key) {
                if !tx.is_closed() {
                    return Ok(());
                }
            }
        }

        let state = Arc::clone(&self.state);
        self.rt.spawn(async move {
            // Resolve the permanent pubkey to ephemeral Yggdrasil routing key(s).
            // Try cached first; query trackers if cache is empty.
            let mut ephemeral_keys = state.resolver.get_cached(&key);
            if ephemeral_keys.is_empty() {
                ephemeral_keys = state.resolver.query_trackers(&key).await;
            }
            // Fall back to treating the permanent key as the routing key directly
            // (works when both keys are the same, i.e. single-key architecture).
            if ephemeral_keys.is_empty() {
                ephemeral_keys = vec![key];
            }

            for eph_key in ephemeral_keys {
                match state.node.connect(&eph_key, state.peer_port).await {
                    Ok(conn) => {
                        let ctx = state.make_ctx();
                        let conn = Arc::new(conn);
                        // Identify the peer by their permanent pubkey for auth + map key.
                        if let Some(tx) = run_outbound(conn, key, ctx).await {
                            state.register_peer(key, tx);
                        }
                        return; // connected successfully
                    }
                    Err(e) => {
                        log::warn!(
                            "connect_to_peer {}: eph {} failed: {}",
                            hex::encode(&key[..4]),
                            hex::encode(&eph_key[..4]),
                            e
                        );
                    }
                }
            }
            log::error!("connect_to_peer {}: all addresses exhausted", hex::encode(&key[..4]));
        });
        Ok(())
    }

    /// Close the connection to `pubkey` (if any).
    pub fn disconnect_peer(&self, pubkey: Vec<u8>) {
        if let Ok(key) = vec_to_key(&pubkey) {
            let _ = self.state.send_cmd(&key, OutgoingCmd::Disconnect);
        }
    }

    /// Initiate an outgoing call to `pubkey`.
    pub fn start_call(&self, pubkey: Vec<u8>) -> Result<(), MimirError> {
        let key = vec_to_key(&pubkey)?;
        self.state.send_cmd(&key, OutgoingCmd::StartCall)
    }

    /// Accept (`accept=true`) or reject (`accept=false`) an incoming call.
    pub fn answer_call(&self, pubkey: Vec<u8>, accept: bool) -> Result<(), MimirError> {
        let key = vec_to_key(&pubkey)?;
        self.state.send_cmd(&key, OutgoingCmd::AnswerCall(accept))
    }

    /// Hang up an active or ringing call.
    pub fn hangup_call(&self, pubkey: Vec<u8>) -> Result<(), MimirError> {
        let key = vec_to_key(&pubkey)?;
        self.state.send_cmd(&key, OutgoingCmd::HangupCall)
    }

    /// Send a raw call-packet to `pubkey` during an active call.
    pub fn send_call_packet(&self, pubkey: Vec<u8>, data: Vec<u8>) -> Result<(), MimirError> {
        let key = vec_to_key(&pubkey)?;
        self.state.send_cmd(&key, OutgoingCmd::CallPacket(data))
    }

    /// Yggdrasil peer-connection diagnostics, JSON-encoded.
    pub fn get_peers_json(&self) -> String {
        self.rt.block_on(self.state.node.get_peers_json())
    }

    /// Yggdrasil routing-path diagnostics, JSON-encoded.
    pub fn get_paths_json(&self) -> String {
        self.rt.block_on(self.state.node.get_paths_json())
    }

    /// Yggdrasil spanning-tree diagnostics, JSON-encoded.
    pub fn get_tree_json(&self) -> String {
        self.rt.block_on(self.state.node.get_tree_json())
    }

    /// Announce our current ephemeral Yggdrasil address to all configured trackers.
    ///
    /// Returns immediately.  The first call starts the background announce loop;
    /// every subsequent call wakes it from its inter-announcement sleep so it
    /// re-announces right away (useful after a network change or on app resume).
    pub fn announce_to_trackers(&self) {
        if self.announce_started.swap(true, Ordering::SeqCst) {
            // Loop already running — just kick it to re-announce immediately.
            self.announce_notify.notify_one();
            return;
        }

        let resolver = Arc::clone(&self.state.resolver);
        let node = self.ygg_node().clone();
        let notify = Arc::clone(&self.announce_notify);
        let mut stop_rx = self.stop_tx.subscribe();
        self.rt.spawn(async move {
            let pause = Duration::from_secs(60);
            loop {
                let delay = if node.count_active_peers().await > 0 {
                    match resolver.announce().await {
                        Ok(ttl) => Duration::from_secs(ttl as u64),
                        Err(_)  => pause,
                    }
                } else {
                    pause
                };

                tokio::select! {
                    biased;
                    _ = stop_rx.recv()    => break,
                    _ = notify.notified() => {}   // re-announce immediately
                    _ = sleep(delay)      => {}   // normal TTL expiry
                }
            }
        });
    }

    // ── Crate-internal accessors (used by MediatorNode) ──────────────────────

    pub(crate) fn ygg_node(&self) -> Arc<AsyncNode> {
        Arc::clone(&self.state.node)
    }

    pub(crate) fn runtime(&self) -> Arc<tokio::runtime::Runtime> {
        Arc::clone(&self.rt)
    }

    pub(crate) fn signing_key(&self) -> Arc<SigningKey> {
        Arc::clone(&self.state.signing_key)
    }

    /// Stop the node and close all connections.
    ///
    /// After this returns, no more events will be fired.
    pub fn stop(&self) {
        // Signal the accept loop to exit.
        let _ = self.stop_tx.send(());

        // Tell every peer connection to shut down.
        let keys: Vec<[u8; 32]> = self
            .state
            .peers
            .lock()
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default();
        for key in keys {
            let _ = self.state.send_cmd(&key, OutgoingCmd::Disconnect);
        }

        // Shut down the Yggdrasil node asynchronously (fire-and-forget).
        let node = Arc::clone(&self.state.node);
        self.rt.spawn(async move {
            node.close().await;
        });
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn vec_to_key(v: &[u8]) -> Result<[u8; 32], MimirError> {
    v.try_into().map_err(|_| {
        MimirError::Connection(format!("expected 32-byte pubkey, got {} bytes", v.len()))
    })
}
