//! P2P peer management — [`PeerNode`] is the main UniFFI-exported object.

pub mod connection;
pub mod data_stream;
pub mod protocol;
pub mod resolver;
pub mod ygg_selector;

use std::collections::HashMap;
use std::sync::Once;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use ed25519_dalek::SigningKey;
use rand::seq::SliceRandom;
use tokio::sync::{broadcast, mpsc};
use tokio::time::sleep;
use tracing::info;
use ygg_stream::AsyncNode;


use crate::{CallStatus, InfoProvider, MimirError, PeerEventListener};
use connection::{ConnContext, OutgoingCmd, run_inbound, run_outbound};
use data_stream::data_recv_task;
use protocol::{read_exact, STREAM_ROLE_CONTROL, STREAM_ROLE_DATA};
use resolver::Resolver;
use ygg_selector::{YggSelector, run_selector};

// ── Tracing initialisation ───────────────────────────────────────────────────

fn init_tracing() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;
        use tracing_subscriber::EnvFilter;

        let env_filter = EnvFilter::new(
            "ironwood=info,yggdrasil=info,ygg_stream=info,info"
        );

        #[cfg(target_os = "android")]
        {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(tracing_android::layer("Mimir").unwrap())
                .init();
        }
        #[cfg(not(target_os = "android"))]
        {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(tracing_subscriber::fmt::layer())
                .init();
        }
    });
}

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

    fn on_file_receive_progress(&self, pubkey: Vec<u8>, guid: i64, bytes_received: i64, total_bytes: i64) {
        self.inner.on_file_receive_progress(pubkey, guid, bytes_received, total_bytes);
    }

    fn on_file_send_progress(&self, pubkey: Vec<u8>, guid: i64, bytes_sent: i64, total_bytes: i64) {
        self.inner.on_file_send_progress(pubkey, guid, bytes_sent, total_bytes);
    }

    fn on_file_received(&self, pubkey: Vec<u8>, guid: i64, reply_to: i64, send_time: i64, edit_time: i64, msg_type: i32, meta_json: String, file_path: String) {
        self.inner.on_file_received(pubkey, guid, reply_to, send_time, edit_time, msg_type, meta_json, file_path);
    }

    fn on_contact_request(&self, pubkey: Vec<u8>, message: String, nickname: String, info: String, avatar: Option<Vec<u8>>) {
        self.inner.on_contact_request(pubkey, message, nickname, info, avatar);
    }

    fn on_contact_response(&self, pubkey: Vec<u8>, accepted: bool) {
        self.inner.on_contact_response(pubkey, accepted);
    }

    fn on_tracker_announce(&self, ok: bool, ttl: i32) {
        self.inner.on_tracker_announce(ok, ttl);
    }
}

// ── Shared runtime state ──────────────────────────────────────────────────────

struct PeerState {
    our_pubkey: [u8; 32],
    ephemeral_seed: [u8; 32],
    signing_key: Arc<SigningKey>,
    node: Arc<AsyncNode>,
    peer_port: u16,
    client_id: i32,
    peers: Arc<PeersMap>,
    event_cb: Arc<dyn PeerEventListener>,
    info_cb: Arc<dyn InfoProvider>,
    resolver: Arc<Resolver>,
    /// Maps ephemeral Yggdrasil routing key → permanent identity key.
    /// Used by the data-stream accept path to identify incoming data streams.
    eph_to_perm: Arc<Mutex<HashMap<[u8; 32], [u8; 32]>>>,
    /// Maps permanent peer key → control-stream write channel.
    /// Shared with data_recv_task so it can ACK large files over the control stream.
    ctrl_write_txs: Arc<Mutex<HashMap<[u8; 32], mpsc::UnboundedSender<Vec<u8>>>>>,
    /// Maps file name → declared size for pending file requests.
    /// Shared with data_recv_task to reject oversized responses.
    pending_file_sizes: Arc<Mutex<HashMap<String, i64>>>,
}

impl PeerState {
    fn make_ctx(&self) -> Arc<ConnContext> {
        Arc::new(ConnContext {
            signing_key: Arc::clone(&self.signing_key),
            our_pubkey: self.our_pubkey,
            client_id: self.client_id,
            event_cb: Arc::clone(&self.event_cb),
            info_cb: Arc::clone(&self.info_cb),
            node: Arc::clone(&self.node),
            peer_port: self.peer_port,
            eph_to_perm: Arc::clone(&self.eph_to_perm),
            ctrl_write_txs: Arc::clone(&self.ctrl_write_txs),
            pending_file_sizes: Arc::clone(&self.pending_file_sizes),
        })
    }

    fn register_peer(&self, key: [u8; 32], tx: mpsc::UnboundedSender<OutgoingCmd>) {
        if let Ok(mut map) = self.peers.lock() {
            // Tell the old connection it is being replaced so its message_loop
            // exits cleanly without firing a HANGUP callback.  The Android side
            // will retry the call (if any) on the new connection via onPeerConnected.
            if let Some(old_tx) = map.get(&key) {
                let _ = old_tx.send(OutgoingCmd::Replaced);
            }
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
    selector: Arc<YggSelector>,
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
        ephemeral_key: Option<Vec<u8>>,
        ygg_peers: Vec<String>,
        peer_port: u16,
        trackers: Vec<String>,
        event_listener: Box<dyn PeerEventListener>,
        info_provider: Box<dyn InfoProvider>
    ) -> Result<Self, MimirError> {
        init_tracing();

        info!("Starting Mimir node v{}", env!("CARGO_PKG_VERSION"));

        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| MimirError::Connection(e.to_string()))?;

        // Pick one peer at random as the initial connection; the selector
        // task takes over management after startup.  Handles empty lists too.
        let selector = Arc::new(YggSelector::new(ygg_peers.clone()));
        let initial_peers: Vec<String> = ygg_peers
            .choose(&mut rand::thread_rng())
            .cloned()
            .into_iter()
            .collect();
        if let Some(uri) = initial_peers.first() {
            *selector.active_uri.lock().unwrap() = Some(uri.clone());
        }

        // Derive permanent signing key + our identity pubkey from the seed bytes.
        let key_bytes: [u8; 32] = signing_key.try_into().map_err(|_| {
            MimirError::Connection("signing_key must be exactly 32 bytes".to_string())
        })?;
        let sk = SigningKey::from_bytes(&key_bytes);
        let our_pubkey = crate::crypto::pubkey_of(&sk);

        // Use the caller-supplied ephemeral key (so the app can persist the
        // Yggdrasil routing address across restarts), or generate a fresh one.
        let ephemeral_seed: [u8; 32] = match ephemeral_key {
            Some(k) => k.try_into().map_err(|_| {
                MimirError::Connection("ephemeral_key must be exactly 32 bytes".to_string())
            })?,
            None => rand::random(),
        };

        // Start the Yggdrasil node with the ephemeral key.
        let node = rt
            .block_on(AsyncNode::new_with_key(&ephemeral_seed, initial_peers))
            .map_err(|e| MimirError::Connection(e.to_string()))?;
        let node = Arc::new(node);

        // The node's public key is our current Yggdrasil routing address.
        let our_eph_pubkey: [u8; 32] = node.public_key().try_into()
            .map_err(|_| MimirError::Connection("unexpected ygg pubkey length".into()))?;

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
            our_eph_pubkey,
            &trackers,
        ));
        let eph_to_perm: Arc<Mutex<HashMap<[u8; 32], [u8; 32]>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let ctrl_write_txs: Arc<Mutex<HashMap<[u8; 32], mpsc::UnboundedSender<Vec<u8>>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let state = Arc::new(PeerState {
            our_pubkey,
            ephemeral_seed,
            signing_key: Arc::clone(&sk),
            node: Arc::clone(&node),
            peer_port,
            client_id: 1,
            peers,
            event_cb: event_wrapper,
            info_cb: info_provider,
            resolver,
            eph_to_perm,
            ctrl_write_txs,
            pending_file_sizes: Arc::new(Mutex::new(HashMap::new())),
        });

        // Spawn the inbound-accept loop.
        // Handles both control streams (role 0x00) and incoming data streams (role 0x01).
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
                                        let conn = Arc::new(conn);
                                        // Every new stream starts with a role byte.
                                        let role = match read_exact(&conn, 1).await {
                                            Ok(b) => b[0],
                                            Err(e) => {
                                                tracing::warn!("Accept: failed to read role byte: {}", e);
                                                return;
                                            }
                                        };
                                        match role {
                                            STREAM_ROLE_CONTROL => {
                                                let ctx = s.make_ctx();
                                                if let Some((key, tx)) = run_inbound(conn, ctx).await {
                                                    s.register_peer(key, tx);
                                                }
                                            }
                                            STREAM_ROLE_DATA => {
                                                // Identify the sender via the eph→perm map.
                                                let peer_eph: [u8; 32] = match conn.public_key().try_into() {
                                                    Ok(k) => k,
                                                    Err(_) => {
                                                        tracing::warn!("Accept data: unexpected eph key length");
                                                        return;
                                                    }
                                                };
                                                let perm_key = s.eph_to_perm
                                                    .lock().unwrap()
                                                    .get(&peer_eph)
                                                    .copied();
                                                match perm_key {
                                                    Some(pk) => {
                                                        let cb = Arc::clone(&s.event_cb);
                                                        let ic = Arc::clone(&s.info_cb);
                                                        let txs = Arc::clone(&s.ctrl_write_txs);
                                                        let pfs = Arc::clone(&s.pending_file_sizes);
                                                        tokio::spawn(data_recv_task(conn, pk, cb, ic, txs, pfs));
                                                    }
                                                    None => {
                                                        tracing::warn!("Accept data: unknown eph key {}, dropping",
                                                                   hex::encode(peer_eph));
                                                    }
                                                }
                                            }
                                            other => {
                                                tracing::warn!("Accept: unknown stream role {:#04x}, dropping", other);
                                            }
                                        }
                                    });
                                }
                                Err(e) => {
                                    tracing::error!("Accept error: {}", e);
                                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                                    // continue accepting — a single error must not kill the listener
                                }
                            }
                        }
                    }
                }
                tracing::error!("CRITICAL: accept loop exited");
            });
        }

        // Probe initial connectivity — subscribe_peer_events() misses events that
        // fired during AsyncNode::new_with_key's internal 1-second sleep.
        let initial_online = rt.block_on(state.node.count_active_peers()) > 0;
        if initial_online {
            state.event_cb.on_connectivity_changed(true);
        }

        // Spawn Yggdrasil peer-event monitor → fires on_connectivity_changed
        // and wakes the selector on every peer state change.
        //
        // On every event (including Lagged) we read the *actual* current peer
        // count rather than tracking a running delta.  This mirrors the
        // wait_peer_change pattern in ygg_stream and is immune to counter drift.
        {
            let cb       = Arc::clone(&state.event_cb);
            let node     = Arc::clone(&state.node);
            let sel      = Arc::clone(&selector);
            let mut rx   = state.node.subscribe_peer_events();
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
                                    sel.notify.notify_one();
                                }
                                Err(broadcast::error::RecvError::Closed) => break,
                            }
                        }
                    }
                }
                tracing::error!("CRITICAL: peer-event monitor exited");
            });
        }

        // Spawn the Yggdrasil peer selector task.
        {
            let sel     = Arc::clone(&selector);
            let node    = Arc::clone(&state.node);
            let stop_rx = stop_tx.subscribe();
            rt.spawn(async move {
                run_selector(sel, node, stop_rx).await;
                tracing::error!("CRITICAL: ygg_selector task exited");
            });
        }

        Ok(PeerNode {
            rt: Arc::new(rt),
            state,
            stop_tx,
            announce_started: AtomicBool::new(false),
            announce_notify: Arc::new(tokio::sync::Notify::new()),
            selector,
        })
    }

    /// Our 32-byte Ed25519 public key (= Yggdrasil node identity).
    pub fn public_key(&self) -> Vec<u8> {
        self.state.our_pubkey.to_vec()
    }

    /// The 32-byte ephemeral seed used for the Yggdrasil node.
    /// The app can persist this and pass it back on next start to keep the
    /// same routing address across restarts.
    pub fn ephemeral_key(&self) -> Vec<u8> {
        self.state.ephemeral_seed.to_vec()
    }

    /// Replace the list of managed Yggdrasil router peers (priority = slice order).
    ///
    /// Metrics (failure count, cost) are preserved for URIs that remain in the
    /// new list.  The selector will switch to the best available peer if the
    /// current one is no longer listed.
    pub fn set_ygg_peers(&self, peers: Vec<String>) {
        self.selector.set_peers(peers);
    }

    /// Inform the selector whether the device has general internet connectivity.
    ///
    /// Call with `true` when the OS reports the network is up, `false` when
    /// all interfaces go down.  While offline the selector suppresses peer
    /// switching and lets Yggdrasil's own reconnect loop handle recovery.
    pub fn set_network_online(&self, online: bool) {
        self.selector.set_network_online(online);
    }

    /// Block until the active Yggdrasil peer info changes, then return it.
    ///
    /// If no change occurs within `timeout_ms` milliseconds the current state
    /// is returned anyway.  Designed for a long-poll loop on the Kotlin side
    /// to keep the notification bar up to date without busy-waiting.
    pub fn wait_for_peer_info(&self, timeout_ms: u64) -> crate::YggPeerInfo {
        let mut rx       = self.selector.subscribe_peer_info();
        let node         = Arc::clone(&self.state.node);
        let selector     = Arc::clone(&self.selector);
        self.rt.block_on(async move {
            // Mark current value as seen, then wait for a change or timeout.
            rx.borrow_and_update();
            let _ = tokio::time::timeout(
                Duration::from_millis(timeout_ms),
                rx.changed(),
            )
            .await;

            // If the app signaled that the network is down, report offline
            // immediately — Yggdrasil's p.up may still be true while the TCP
            // socket lingers, so we can't rely on it alone.
            if !selector.is_network_online() {
                return crate::YggPeerInfo { uri: None, cost: 0, failures: 0 };
            }

            // Query actual live peer state — uri is None when no peer is up.
            match node.get_first_active_peer().await {
                Some((uri, cost)) => {
                    let failures = selector.failures_for(&uri);
                    crate::YggPeerInfo { uri: Some(uri), cost: cost as u32, failures }
                }
                None => crate::YggPeerInfo { uri: None, cost: 0, failures: 0 },
            }
        })
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
            let used_cache = !ephemeral_keys.is_empty();
            if !used_cache {
                ephemeral_keys = state.resolver.query_trackers(&key).await;
            }
            // Fall back to treating the permanent key as the routing key directly
            // (works when both keys are the same, i.e. single-key architecture).
            if ephemeral_keys.is_empty() {
                ephemeral_keys = vec![key];
            }

            for eph_key in &ephemeral_keys {
                match state.node.connect(eph_key, state.peer_port).await {
                    Ok(conn) => {
                        let ctx = state.make_ctx();
                        let conn = Arc::new(conn);
                        if let Some(tx) = run_outbound(conn, key, ctx).await {
                            state.register_peer(key, tx);
                        }
                        return; // connected successfully
                    }
                    Err(e) => {
                        tracing::warn!(
                            "connect_to_peer {}: eph {} failed: {}",
                            hex::encode(&key[..4]),
                            hex::encode(&eph_key[..4]),
                            e
                        );
                    }
                }
            }

            // All cached addresses failed — the peer likely restarted and got
            // a new ephemeral key.  Invalidate the stale cache, query trackers
            // for fresh addresses, and retry once.
            if used_cache {
                tracing::info!("connect_to_peer {}: cached addresses failed, querying trackers", hex::encode(&key[..4]));
                state.resolver.invalidate(&key);
                let fresh_keys = state.resolver.query_trackers(&key).await;
                // Only try keys we haven't already tried.
                let already_tried: std::collections::HashSet<[u8; 32]> =
                    ephemeral_keys.into_iter().collect();
                let new_keys: Vec<[u8; 32]> = fresh_keys
                    .into_iter()
                    .filter(|k| !already_tried.contains(k))
                    .collect();

                for eph_key in &new_keys {
                    match state.node.connect(eph_key, state.peer_port).await {
                        Ok(conn) => {
                            let ctx = state.make_ctx();
                            let conn = Arc::new(conn);
                            if let Some(tx) = run_outbound(conn, key, ctx).await {
                                state.register_peer(key, tx);
                            }
                            return;
                        }
                        Err(e) => {
                            tracing::warn!("connect_to_peer {}: fresh eph {} failed: {}", hex::encode(&key[..4]), hex::encode(&eph_key[..4]), e);
                        }
                    }
                }
            }

            tracing::error!("connect_to_peer {}: all addresses exhausted", hex::encode(&key[..4]));
        });
        Ok(())
    }

    /// Send a contact (friend) request to `pubkey` with an introductory message.
    pub fn send_contact_request(&self, pubkey: Vec<u8>, message: String) -> Result<(), MimirError> {
        let key = vec_to_key(&pubkey)?;
        self.state.send_cmd(&key, OutgoingCmd::ContactRequest { message })
    }

    /// Send a contact response (accept/reject) to `pubkey`.
    pub fn send_contact_response(&self, pubkey: Vec<u8>, accepted: bool) -> Result<(), MimirError> {
        let key = vec_to_key(&pubkey)?;
        self.state.send_cmd(&key, OutgoingCmd::ContactResponse { accepted })
    }

    /// Request a file from a connected peer.
    ///
    /// `name` is the random filename from the message metadata.
    /// `hash` is the SHA-256 hex hash for verification.
    /// The peer will stream the file back as a MSG_TYPE_FILE_RESPONSE
    /// delivered through `on_message_received`.
    pub fn request_file(&self, pubkey: Vec<u8>, guid: i64, name: String, hash: String, size: i64) -> Result<(), MimirError> {
        let key = vec_to_key(&pubkey)?;
        // Store the declared size so data_recv_task can reject oversized responses.
        if let Ok(mut map) = self.state.pending_file_sizes.lock() {
            map.insert(name.clone(), size);
        }
        self.state.send_cmd(&key, OutgoingCmd::FileRequest { guid, name, hash, size })
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

    /// Retry to connect to peers
    pub fn retry_peers_now(&self) {
        self.rt.block_on(self.state.node.retry_peers_now())
    }

    /// Add new peer to connect
    pub fn add_peer(&self, uri: String) {
        if let Err(e) = self.rt.block_on(self.state.node.add_peer(&uri)) {
            eprintln!("[mimir] add_peer({:?}) failed: {}", uri, e);
        }
    }

    /// Remove one of added peers
    pub fn remove_peer(&self, uri: String) {
        if let Err(e) = self.rt.block_on(self.state.node.remove_peer(&uri)) {
            eprintln!("[mimir] remove_peer({:?}) failed: {}", uri, e);
        }
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
        let event_cb = Arc::clone(&self.state.event_cb);
        self.rt.spawn(async move {
            let pause = Duration::from_secs(60);
            loop {
                let delay = if node.count_active_peers().await > 0 {
                    match resolver.announce().await {
                        Ok(ttl) => {
                            event_cb.on_tracker_announce(true, ttl as i32);
                            Duration::from_secs(ttl as u64)
                        }
                        Err(_) => {
                            event_cb.on_tracker_announce(false, 0);
                            pause
                        }
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
