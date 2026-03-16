//! Tracker-based peer resolver.
//!
//! Implements the lightweight UDP-over-Yggdrasil tracker protocol used to map
//! a user's permanent Ed25519 pubkey to their current ephemeral Yggdrasil node
//! pubkey ("address").
//!
//! ## Protocol frame layout
//!
//! **Client → tracker (request):**
//! ```text
//! [VERSION:1][nonce:4 BE][CMD:1][payload...]
//! ```
//!
//! **Tracker → client (response):**
//! ```text
//! [nonce:4 BE][CMD:1][payload...]
//! ```
//!
//! ### CMD_GET_ADDRS (0x01) — resolve a permanent pubkey to ephemeral addr(s)
//! Request payload : `[permanent_pubkey:32]`
//! Response payload: `[count:1]` + count × `[eph_key:32][sig:64][priority:1][client_id:4 BE][ttl:8 BE]`
//! Signature       : `Ed25519_sign(permanent_sk, eph_key_bytes)` — verified client-side
//!
//! ### CMD_ANNOUNCE (0x00) — register our ephemeral addr with the tracker
//! Request payload : `[perm_pubkey:32][priority:1][client_id:4 BE][eph_addr:32][sig:64]`
//! Response payload: `[ttl:8 BE]`

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use ygg_stream::AsyncNode;

use crate::crypto::{sign, verify};

// ── Protocol constants ────────────────────────────────────────────────────────

const VERSION: u8 = 1;
const CMD_ANNOUNCE: u8 = 0x00;
const CMD_GET_ADDRS: u8 = 0x01;

/// How long to wait for a single tracker response.
const RECV_TIMEOUT_MS: i64 = 5_000;

/// Maximum number of received datagrams to scan when matching a nonce
/// (guards against stale/unrelated datagrams piling up).
const MAX_RECV_LOOPS: usize = 16;

// ── Tracker address ───────────────────────────────────────────────────────────

struct TrackerEntry {
    pubkey: [u8; 32],
    port: u16,
    latency_ms: u64,   // updated by ping; used to pick the fastest tracker
}

// ── Cache entry ───────────────────────────────────────────────────────────────

/// One cached ephemeral-key entry for a remote peer.
pub struct CachedPeer {
    pub addr: [u8; 32],
    pub priority: u8,
    pub client_id: u32,
    pub expires_at: Instant,
}

// ── Resolver ──────────────────────────────────────────────────────────────────

pub struct Resolver {
    node:       Arc<AsyncNode>,
    signing_key: Arc<SigningKey>,
    our_addr: [u8; 32],
    /// Tracker list (immutable after construction).
    trackers:   Vec<TrackerEntry>,
    /// permanent_pubkey → list of unexpired ephemeral addresses
    cache:      Mutex<HashMap<[u8; 32], Vec<CachedPeer>>>,
    /// Serializes send+receive operations so concurrent resolver requests don't
    /// steal each other's datagram responses.
    recv_lock:  tokio::sync::Mutex<()>,
}

impl Resolver {
    /// Create a new Resolver.
    ///
    /// * `tracker_strs`  – Tracker addresses in `"<hex32_pubkey>:<port>"` format.
    pub fn new(
        node: Arc<AsyncNode>,
        signing_key: Arc<SigningKey>,
        our_addr: [u8; 32],
        tracker_strs: &[String],
    ) -> Self {
        let trackers = tracker_strs.iter().filter_map(|s| parse_tracker(s)).collect();
        Resolver {
            node,
            signing_key,
            our_addr,
            trackers,
            cache:     Mutex::new(HashMap::new()),
            recv_lock: tokio::sync::Mutex::new(()),
        }
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /// Remove the cached entry for `permanent_pubkey` so the next resolution
    /// goes to the trackers.
    pub fn invalidate(&self, permanent_pubkey: &[u8; 32]) {
        self.cache.lock().unwrap().remove(permanent_pubkey);
    }

    /// Return unexpired cached ephemeral keys for `permanent_pubkey`, sorted
    /// by priority (highest first).
    pub fn get_cached(&self, permanent_pubkey: &[u8; 32]) -> Vec<[u8; 32]> {
        let now = Instant::now();
        let cache = self.cache.lock().unwrap();
        match cache.get(permanent_pubkey) {
            None => vec![],
            Some(entries) => {
                let mut valid: Vec<&CachedPeer> =
                    entries.iter().filter(|p| p.expires_at > now).collect();
                valid.sort_by(|a, b| b.priority.cmp(&a.priority));
                valid.iter().map(|p| p.addr).collect()
            }
        }
    }

    /// Query all configured trackers for `permanent_pubkey`.
    ///
    /// Trackers are tried in ascending latency order; returns as soon as the
    /// first tracker returns at least one result.  The cache is updated.
    pub async fn query_trackers(&self, permanent_pubkey: &[u8; 32]) -> Vec<[u8; 32]> {
        if self.trackers.is_empty() {
            return vec![];
        }

        // Serialise datagram operations globally so we don't race with
        // concurrent queries or announces.
        let _lock = self.recv_lock.lock().await;

        // Try trackers in latency order (initially all equal at 9999 ms).
        let mut indices: Vec<usize> = (0..self.trackers.len()).collect();
        indices.sort_by_key(|&i| self.trackers[i].latency_ms);

        for idx in indices {
            let tracker = &self.trackers[idx];
            match self.get_addrs_from(tracker, permanent_pubkey).await {
                Ok(peers) if !peers.is_empty() => {
                    let keys: Vec<[u8; 32]> = {
                        let mut sorted = peers.iter().collect::<Vec<_>>();
                        sorted.sort_by(|a, b| b.priority.cmp(&a.priority));
                        sorted.iter().map(|p| p.addr).collect()
                    };
                    self.cache.lock().unwrap().insert(*permanent_pubkey, peers);
                    return keys;
                }
                Ok(_) => {
                    tracing::debug!(
                        "resolver: tracker {} returned 0 peers for {}",
                        hex::encode(&tracker.pubkey[..4]),
                        hex::encode(&permanent_pubkey[..4])
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        "resolver: tracker {} failed: {e}",
                        hex::encode(&tracker.pubkey[..4])
                    );
                }
            }
        }
        vec![]
    }

    /// Announce our current ephemeral address (= `our_pubkey`) to all trackers.
    ///
    /// Fires-and-forgets from the caller's perspective — errors are only logged.
    pub async fn announce(&self) -> Result<i64, String> {
        if self.trackers.is_empty() {
            return Err(String::from("No useful trackers"));
        }

        let _lock = self.recv_lock.lock().await;

        // Sign our ephemeral key with our permanent signing key.
        let our_addr = self.our_addr;
        let sig = sign(&self.signing_key, &our_addr);
        let public_key  = self.signing_key.verifying_key().to_bytes();
        tracing::info!("Announcing addr {} for {}", hex::encode(&our_addr), hex::encode(&public_key[..8]));

        // Build announce frame:
        // [VERSION:1][nonce:4][CMD_ANNOUNCE:1]
        // [perm_pubkey:32][priority:1][client_id:4 BE][eph_addr:32][sig:64]
        let nonce = random_nonce();
        let mut frame = Vec::with_capacity(1 + 4 + 1 + 32 + 1 + 4 + 32 + 64);
        frame.push(VERSION);
        frame.extend_from_slice(&nonce);
        frame.push(CMD_ANNOUNCE);
        frame.extend_from_slice(&public_key);          // permanent pubkey
        frame.push(1u8);                        // priority
        frame.extend_from_slice(&1u32.to_be_bytes()); // client_id = 1
        frame.extend_from_slice(&our_addr);           // ephemeral addr
        frame.extend_from_slice(&sig);

        for tracker in &self.trackers {
            // Pre-register listener on tracker.port before sending so we don't miss
            // the response (tracker responds on the same port it listens on).
            let _ = self.node.recv_datagram_with_timeout(tracker.port, 1).await;

            if let Err(e) = self.node.send_datagram(&tracker.pubkey, tracker.port, &frame).await {
                tracing::warn!("resolver: announce send to {} failed: {e}", hex::encode(&tracker.pubkey[..4]));
                continue;
            }
            // Best-effort read of TTL response (not required for correctness).
            match self.recv_matching(&tracker.pubkey, &nonce, CMD_ANNOUNCE, tracker.port).await {
                Ok(payload) if payload.len() >= 8 => {
                    let ttl = i64::from_be_bytes(payload[..8].try_into().unwrap());
                    tracing::info!("resolver: announced to {}, TTL={ttl}s", hex::encode(&tracker.pubkey[..4]));
                    return Ok(ttl);
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::debug!("resolver: no announce ack from {}: {e}", hex::encode(&tracker.pubkey[..4]));
                }
            }
        }
        Err("announce failed".to_string())
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    async fn get_addrs_from(&self, tracker: &TrackerEntry, permanent_pubkey: &[u8; 32]) -> Result<Vec<CachedPeer>, String> {
        let nonce = random_nonce();

        // GET_ADDRS request: [VERSION:1][nonce:4][CMD_GET_ADDRS:1][permanent_pubkey:32]
        let mut frame = Vec::with_capacity(1 + 4 + 1 + 32);
        frame.push(VERSION);
        frame.extend_from_slice(&nonce);
        frame.push(CMD_GET_ADDRS);
        frame.extend_from_slice(permanent_pubkey);

        // Pre-register listener on tracker.port before sending so we don't miss
        // the response. The tracker has no source-port concept and responds on
        // the same port it listens on (tracker.port).
        let _ = self.node.recv_datagram_with_timeout(tracker.port, 1).await;

        let t0 = Instant::now();
        self.node
            .send_datagram(&tracker.pubkey, tracker.port, &frame)
            .await?;

        let payload = self.recv_matching(&tracker.pubkey, &nonce, CMD_GET_ADDRS, tracker.port).await?;
        let rtt_ms = t0.elapsed().as_millis() as u64;
        tracing::debug!("resolver: tracker {} RTT = {rtt_ms}ms", hex::encode(&tracker.pubkey[..4]));

        parse_get_addrs_response(&payload, permanent_pubkey)
    }

    /// Wait for a datagram from `expected_sender` whose payload starts with
    /// `[nonce:4][cmd:1]`.  Returns the payload after those 5 bytes.
    async fn recv_matching(&self, expected_sender: &[u8; 32], nonce: &[u8; 4], cmd: u8, port: u16) -> Result<Vec<u8>, String> {
        for _ in 0..MAX_RECV_LOOPS {
            let (data, sender) = self.node
                .recv_datagram_with_timeout(port, RECV_TIMEOUT_MS)
                .await
                .map_err(|e| {
                    tracing::warn!(
                        "resolver: recv_matching timed out waiting for cmd=0x{:02x} from {}",
                        cmd, hex::encode(&expected_sender[..4])
                    );
                    e
                })?;

            if sender.len() != 32 || sender.as_slice() != expected_sender.as_slice() {
                tracing::debug!(
                    "resolver: recv_matching: datagram from unexpected sender {}, discarding",
                    hex::encode(&sender[..sender.len().min(4)])
                );
                continue;
            }
            if data.len() < 5 {
                tracing::debug!("resolver: recv_matching: datagram too short ({} bytes)", data.len());
                continue;
            }
            if data[0..4] != *nonce {
                tracing::debug!("resolver: recv_matching: nonce mismatch, discarding stale datagram");
                continue;
            }
            if data[4] != cmd {
                tracing::debug!("resolver: recv_matching: cmd mismatch (got 0x{:02x}, want 0x{:02x})", data[4], cmd);
                continue;
            }
            return Ok(data[5..].to_vec());
        }
        Err("no matching response received".to_string())
    }
}

// ── Parsing ───────────────────────────────────────────────────────────────────

/// Parse a GET_ADDRS response payload:
/// `[count:1]` + count × `[eph_key:32][sig:64][priority:1][client_id:4 BE][ttl:8 BE]`
///
/// Each peer record is signature-verified against `permanent_pubkey`.
/// Invalid records are silently skipped.
fn parse_get_addrs_response(payload: &[u8], permanent_pubkey: &[u8; 32]) -> Result<Vec<CachedPeer>, String> {
    if payload.is_empty() {
        return Ok(vec![]);
    }

    let count = payload[0] as usize;
    const RECORD: usize = 32 + 64 + 1 + 4 + 8; // 109 bytes per peer

    if payload.len() < 1 + count * RECORD {
        return Err(format!(
            "GET_ADDRS: short payload ({} bytes for {count} peers)",
            payload.len()
        ));
    }

    let now    = Instant::now();
    let mut peers = Vec::with_capacity(count);
    let mut off = 1usize;

    for _ in 0..count {
        let eph_key:   [u8; 32] = payload[off..off+32].try_into().unwrap(); off += 32;
        let sig = &payload[off..off + 64];
        off += 64;
        let priority = payload[off];
        off += 1;
        let client_id = u32::from_be_bytes(payload[off..off + 4].try_into().unwrap());
        off += 4;
        let ttl_secs = u64::from_be_bytes(payload[off..off + 8].try_into().unwrap());
        off += 8;

        // Verify: sign(permanent_sk, eph_key) must match.
        if verify(permanent_pubkey, &eph_key, sig).is_err() {
            tracing::warn!("resolver: bad signature for peer eph={}", hex::encode(&eph_key[..4]));
            continue;
        }

        peers.push(CachedPeer {
            addr: eph_key,
            priority,
            client_id,
            expires_at: now + Duration::from_secs(ttl_secs),
        });
    }

    Ok(peers)
}

/// Parse `"<hex32>:<port>"` into a TrackerEntry.
fn parse_tracker(s: &str) -> Option<TrackerEntry> {
    let (hex_part, port_str) = s.rsplit_once(':')?;
    let port: u16 = port_str.parse().ok()?;
    let bytes = hex::decode(hex_part).ok()?;
    let pubkey: [u8; 32] = bytes.try_into().ok()?;
    Some(TrackerEntry { pubkey, port, latency_ms: 9_999 })
}

fn random_nonce() -> [u8; 4] {
    use rand::RngCore;
    let mut nonce = [0u8; 4];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn random_sk() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    /// Build a valid GET_ADDRS response payload for `count` peers, signed with
    /// the given permanent signing key.
    fn build_get_addrs_payload(
        permanent_sk: &SigningKey,
        peers: &[([u8; 32], u8, u32, u64)],  // (eph_key, priority, client_id, ttl)
    ) -> Vec<u8> {
        let mut payload = vec![peers.len() as u8];
        for (eph_key, priority, client_id, ttl) in peers {
            let sig = sign(permanent_sk, eph_key.as_slice());
            payload.extend_from_slice(eph_key);
            payload.extend_from_slice(&sig);
            payload.push(*priority);
            payload.extend_from_slice(&client_id.to_be_bytes());
            payload.extend_from_slice(&ttl.to_be_bytes());
        }
        payload
    }

    /// Spin up a minimal, unconnected Resolver (no peers, no trackers).
    async fn make_resolver() -> Resolver {
        let sk   = random_sk();
        let seed = sk.to_bytes();
        let node = Arc::new(
            AsyncNode::new_with_key(&seed, vec![])
                .await
                .expect("AsyncNode::new_with_key failed"),
        );
        let eph_addr: [u8; 32] = node.public_key().try_into().unwrap();
        Resolver::new(node, Arc::new(sk), eph_addr, &[])
    }

    // ── parse_tracker ─────────────────────────────────────────────────────────

    #[test]
    fn parse_tracker_valid() {
        let hex = "a".repeat(64); // 32 zero-ish bytes in hex
        let s   = format!("{hex}:9000");
        let entry = parse_tracker(&s).expect("should parse");
        assert_eq!(entry.port, 9000);
        assert_eq!(entry.pubkey.len(), 32);
    }

    #[test]
    fn parse_tracker_wrong_key_length() {
        // 30 bytes hex = 60 hex chars — too short
        let s = format!("{}:9000", "ab".repeat(30));
        assert!(parse_tracker(&s).is_none());
    }

    #[test]
    fn parse_tracker_bad_hex() {
        let s = format!("{}:9000", "zz".repeat(32));
        assert!(parse_tracker(&s).is_none());
    }

    #[test]
    fn parse_tracker_bad_port() {
        let hex = "aa".repeat(32);
        assert!(parse_tracker(&format!("{hex}:99999")).is_none()); // port > u16::MAX
        assert!(parse_tracker(&format!("{hex}:abc")).is_none());   // non-numeric
    }

    #[test]
    fn parse_tracker_missing_colon() {
        let hex = "aa".repeat(32);
        assert!(parse_tracker(&hex).is_none());
    }

    // ── parse_get_addrs_response ──────────────────────────────────────────────

    #[test]
    fn parse_get_addrs_empty_payload() {
        let permanent_pk = [0u8; 32];
        let peers = parse_get_addrs_response(&[], &permanent_pk).unwrap();
        assert!(peers.is_empty());
    }

    #[test]
    fn parse_get_addrs_zero_count() {
        let permanent_pk = [0u8; 32];
        let payload = vec![0u8]; // count = 0
        let peers = parse_get_addrs_response(&payload, &permanent_pk).unwrap();
        assert!(peers.is_empty());
    }

    #[test]
    fn parse_get_addrs_valid_single_record() {
        let sk            = random_sk();
        let permanent_pk  = sk.verifying_key().to_bytes();
        let eph_key       = [7u8; 32];
        let payload = build_get_addrs_payload(&sk, &[(eph_key, 5, 42, 300)]);

        let peers = parse_get_addrs_response(&payload, &permanent_pk).unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].addr, eph_key);
        assert_eq!(peers[0].priority, 5);
        assert_eq!(peers[0].client_id, 42);
        // TTL was 300 s; expires_at should be in the future
        assert!(peers[0].expires_at > Instant::now());
    }

    #[test]
    fn parse_get_addrs_multiple_records() {
        let sk           = random_sk();
        let permanent_pk = sk.verifying_key().to_bytes();
        let peers_in = [
            ([1u8; 32], 10u8, 1u32, 600u64),
            ([2u8; 32], 5,    2,    300),
        ];
        let payload = build_get_addrs_payload(&sk, &peers_in);

        let peers = parse_get_addrs_response(&payload, &permanent_pk).unwrap();
        assert_eq!(peers.len(), 2);
    }

    #[test]
    fn parse_get_addrs_bad_signature_is_skipped() {
        let sk            = random_sk();
        let attacker_sk   = random_sk();
        let permanent_pk  = sk.verifying_key().to_bytes();
        let eph_key       = [0xABu8; 32];

        // Signed by the wrong key — should fail verification and be skipped.
        let payload = build_get_addrs_payload(&attacker_sk, &[(eph_key, 1, 1, 60)]);

        let peers = parse_get_addrs_response(&payload, &permanent_pk).unwrap();
        assert!(peers.is_empty(), "bad-sig record must be dropped");
    }

    #[test]
    fn parse_get_addrs_short_payload_is_error() {
        // Declares 1 peer but provides 0 record bytes.
        let payload = [1u8]; // count=1, no record data
        let permanent_pk = [0u8; 32];
        assert!(parse_get_addrs_response(&payload, &permanent_pk).is_err());
    }

    // ── Cache behaviour ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn cache_is_empty_initially() {
        let resolver = make_resolver().await;
        assert!(resolver.get_cached(&[0u8; 32]).is_empty());
    }

    #[tokio::test]
    async fn cache_returns_inserted_key() {
        let resolver      = make_resolver().await;
        let permanent_key = [1u8; 32];
        let ephemeral_key = [2u8; 32];

        resolver.cache.lock().unwrap().insert(permanent_key, vec![CachedPeer {
            addr: ephemeral_key,
            priority:   1,
            client_id:  1,
            expires_at: Instant::now() + Duration::from_secs(300),
        }]);

        let result = resolver.get_cached(&permanent_key);
        assert_eq!(result, vec![ephemeral_key]);
    }

    #[tokio::test]
    async fn cache_excludes_expired_entries() {
        let resolver      = make_resolver().await;
        let permanent_key = [3u8; 32];
        let live_key      = [10u8; 32];
        let dead_key      = [11u8; 32];

        resolver.cache.lock().unwrap().insert(permanent_key, vec![
            CachedPeer {
                addr: live_key,
                priority:   1,
                client_id:  1,
                expires_at: Instant::now() + Duration::from_secs(300),
            },
            CachedPeer {
                addr: dead_key,
                priority:   2,
                client_id:  2,
                // Already expired — subtract from now to guarantee past.
                expires_at: Instant::now() - Duration::from_secs(1),
            },
        ]);

        let result = resolver.get_cached(&permanent_key);
        assert_eq!(result, vec![live_key], "expired entry must not appear");
    }

    #[tokio::test]
    async fn cache_sorted_by_priority_descending() {
        let resolver      = make_resolver().await;
        let permanent_key = [4u8; 32];
        let future        = Instant::now() + Duration::from_secs(300);

        resolver.cache.lock().unwrap().insert(permanent_key, vec![
            CachedPeer { addr: [1u8; 32], priority: 3, client_id: 1, expires_at: future },
            CachedPeer { addr: [2u8; 32], priority: 7, client_id: 2, expires_at: future },
            CachedPeer { addr: [3u8; 32], priority: 1, client_id: 3, expires_at: future },
        ]);

        let result = resolver.get_cached(&permanent_key);
        assert_eq!(result, vec![[2u8; 32], [1u8; 32], [3u8; 32]],
            "should be ordered priority 7 → 3 → 1");
    }
}
