//! Yggdrasil peer selector.
//!
//! Maintains exactly **one** active Yggdrasil router peer at a time.
//! Switches to the next-best peer when the current one fails, using
//! accumulated failure counts and measured routing cost to rank candidates.
//!
//! # Grace period
//!
//! When `count_active_peers()` drops to zero the selector waits 3 seconds
//! before declaring a failure.  This handles the race where Android reports
//! "network offline" slightly *after* the peer drops: if that callback
//! arrives during the grace window the peer is not penalised and Yggdrasil's
//! own reconnect loop is left to recover the connection.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rand::seq::SliceRandom;
use tokio::sync::{broadcast, watch, Notify};
use ygg_stream::AsyncNode;

use crate::YggPeerInfo;

// ── Constants ─────────────────────────────────────────────────────────────────

/// How long to wait after `count_active_peers` drops to 0 before treating
/// the current peer as dead and switching to the next-best.
const GRACE: Duration = Duration::from_secs(3);

/// Penalty added to a peer's score for each recorded failure.
/// Expressed in the same units as Yggdrasil's `cost` field (ms-equivalent),
/// so each failure counts as 200 ms of extra latency for ranking purposes.
const FAILURE_PENALTY: u32 = 200;

// ── PeerRecord ────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct PeerRecord {
    uri:      String,
    failures: u32,
    /// Last Yggdrasil routing cost reported for this peer (lower = better).
    /// Zero means "not yet measured".
    cost:     u32,
}

fn score(r: &PeerRecord) -> u32 {
    r.failures.saturating_mul(FAILURE_PENALTY).saturating_add(r.cost)
}

// ── YggSelector ───────────────────────────────────────────────────────────────

pub(super) struct YggSelector {
    peers:          Mutex<Vec<PeerRecord>>,
    pub(super) active_uri: Mutex<Option<String>>,
    /// Set by `set_peers` when the active peer is absent from the new list.
    /// Causes the selector loop to immediately switch to a random new peer.
    force_switch:   AtomicBool,
    network_online: AtomicBool,
    /// Wakes the selector task on any relevant state change.
    pub notify:     Notify,
    /// Publishes the current peer info whenever it changes.
    /// Consumed by `PeerNode::wait_for_peer_info` for long-polling.
    peer_info_tx:   watch::Sender<YggPeerInfo>,
}

impl YggSelector {
    pub fn new(uris: Vec<String>) -> Self {
        let peers = uris
            .into_iter()
            .map(|uri| PeerRecord { uri, failures: 0, cost: 0 })
            .collect();
        let (peer_info_tx, _) = watch::channel(YggPeerInfo { uri: None, cost: 0, failures: 0 });
        Self {
            peers:          Mutex::new(peers),
            active_uri:     Mutex::new(None),
            force_switch:   AtomicBool::new(false),
            // Optimistic default: assume the network is up until told otherwise.
            network_online: AtomicBool::new(true),
            notify:         Notify::new(),
            peer_info_tx,
        }
    }

    /// Subscribe to peer-info changes for long-polling.
    pub(super) fn subscribe_peer_info(&self) -> watch::Receiver<YggPeerInfo> {
        self.peer_info_tx.subscribe()
    }

    /// Replace the managed peer list, preserving accumulated metrics for URIs
    /// that remain in the new list.
    pub fn set_peers(&self, uris: Vec<String>) {
        let mut peers = self.peers.lock().unwrap();
        let old: HashMap<String, PeerRecord> = peers
            .drain(..)
            .map(|r| (r.uri.clone(), r))
            .collect();
        *peers = uris
            .into_iter()
            .map(|uri| {
                old.get(&uri)
                    .cloned()
                    .unwrap_or(PeerRecord { uri, failures: 0, cost: 0 })
            })
            .collect();

        // If the current active peer is no longer in the new list, request an
        // immediate switch to a random peer from the new list.
        let active = self.active_uri.lock().unwrap().clone();
        if let Some(ref uri) = active {
            if !peers.iter().any(|r| &r.uri == uri) {
                self.force_switch.store(true, Ordering::Relaxed);
            }
        }
        drop(peers);
        self.notify.notify_one();
    }

    /// Inform the selector whether the device has general internet connectivity.
    ///
    /// * `true`  – network is up; the selector will (re-)connect to the best peer.
    /// * `false` – network is down; reconnect attempts are suppressed.  The
    ///             current peer is kept registered in `AsyncNode` so Yggdrasil's
    ///             own reconnect loop can recover the session when the network
    ///             returns.
    pub fn set_network_online(&self, online: bool) {
        self.network_online.store(online, Ordering::Relaxed);
        self.notify.notify_one();
    }

    pub(super) fn is_network_online(&self) -> bool {
        self.network_online.load(Ordering::Relaxed)
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    pub(super) fn failures_for(&self, uri: &str) -> u32 {
        self.peers.lock().unwrap()
            .iter()
            .find(|r| r.uri == uri)
            .map(|r| r.failures)
            .unwrap_or(0)
    }

    fn pick_best(&self) -> Option<String> {
        let peers = self.peers.lock().unwrap();
        peers.iter().min_by_key(|r| score(r)).map(|r| r.uri.clone())
    }

    fn record_failure(&self, uri: &str) {
        let mut peers = self.peers.lock().unwrap();
        if let Some(r) = peers.iter_mut().find(|r| r.uri == uri) {
            r.failures = r.failures.saturating_add(1);
        }
    }

    /// Read the current active-peer state and publish it on the watch channel.
    fn publish_info(&self) {
        let uri = self.active_uri.lock().unwrap().clone();
        let (cost, failures) = uri.as_ref()
            .and_then(|u| {
                self.peers.lock().unwrap()
                    .iter()
                    .find(|r| &r.uri == u)
                    .map(|r| (r.cost, r.failures))
            })
            .unwrap_or((0, 0));
        self.peer_info_tx.send_replace(YggPeerInfo { uri, cost, failures });
    }

    async fn update_cost_from_node(&self, node: &AsyncNode) {
        let active = self.active_uri.lock().unwrap().clone();
        if let Some(ref uri) = active {
            if let Some((peer_uri, cost)) = node.get_first_active_peer().await {
                if &peer_uri == uri {
                    let mut peers = self.peers.lock().unwrap();
                    if let Some(r) = peers.iter_mut().find(|r| &r.uri == uri) {
                        r.cost = cost as u32;
                    }
                }
            }
        }
    }
}

// ── Selector task ─────────────────────────────────────────────────────────────

pub(super) async fn run_selector(selector: Arc<YggSelector>, node:     Arc<AsyncNode>, mut stop_rx: broadcast::Receiver<()>) {
    // Kick immediately so we add the first peer without waiting for an event.
    selector.notify.notify_one();

    loop {
        // ── Wait for something to act on ─────────────────────────────────────
        tokio::select! {
            biased;
            _ = stop_rx.recv() => break,
            _ = selector.notify.notified() => {}
        }

        // ── Forced switch: active peer was removed from the list ─────────────
        if selector.force_switch.swap(false, Ordering::Relaxed) {
            let prev = selector.active_uri.lock().unwrap().clone();
            if let Some(ref uri) = prev {
                let _ = node.remove_peer(uri).await;
            }
            let new_peer = selector.peers.lock().unwrap()
                .choose(&mut rand::thread_rng())
                .map(|r| r.uri.clone());
            match new_peer {
                Some(uri) => {
                    log::info!("[ygg_selector] peer list changed, switching to {:?}", uri);
                    let _ = node.add_peer(&uri).await;
                    *selector.active_uri.lock().unwrap() = Some(uri);
                }
                None => {
                    *selector.active_uri.lock().unwrap() = None;
                    log::warn!("[ygg_selector] peer list is now empty");
                }
            }
            selector.publish_info();
            continue;
        }

        let count = node.count_active_peers().await;
        if count > 0 {
            // Live connection — refresh cost measurement and go back to waiting.
            selector.update_cost_from_node(&node).await;
            selector.publish_info();
            continue;
        }

        if !selector.network_online.load(Ordering::Relaxed) {
            // Network is offline.  Keep the current peer registered (Yggdrasil
            // reconnects automatically) and wait for the next notification.
            // Publish so wait_for_peer_info wakes up promptly.
            selector.publish_info();
            continue;
        }

        // ── count == 0, network appears online ───────────────────────────────
        // Wait up to GRACE seconds before declaring the peer dead.
        // If the "offline" Android callback arrives within this window the
        // peer is not penalised.
        let grace_expired = tokio::select! {
            biased;
            _ = stop_rx.recv() => break,
            _ = selector.notify.notified() => false,    // interrupted
            _ = tokio::time::sleep(GRACE)   => true,    // grace elapsed
        };

        if !grace_expired {
            // Something changed during the grace window — re-evaluate.
            // Notify ourselves so the outer select! wakes immediately.
            selector.notify.notify_one();
            continue;
        }

        // ── Grace elapsed — check final state ────────────────────────────────
        let count = node.count_active_peers().await;
        if count > 0 {
            selector.update_cost_from_node(&node).await;
            selector.publish_info();
            continue;
        }
        if !selector.network_online.load(Ordering::Relaxed) {
            // Network went offline during the grace window — not the peer's fault.
            continue;
        }

        // ── Genuine peer failure — switch to the next-best ───────────────────
        let prev = selector.active_uri.lock().unwrap().clone();
        if let Some(ref uri) = prev {
            log::warn!("[ygg_selector] peer {:?} failed, switching", uri);
            selector.record_failure(uri);
            let _ = node.remove_peer(uri).await;
        }

        match selector.pick_best() {
            Some(best) => {
                log::info!("[ygg_selector] connecting to {:?}", best);
                let _ = node.add_peer(&best).await;
                *selector.active_uri.lock().unwrap() = Some(best);
            }
            None => {
                *selector.active_uri.lock().unwrap() = None;
                log::warn!("[ygg_selector] no peers configured");
            }
        }
        selector.publish_info();
    }
}