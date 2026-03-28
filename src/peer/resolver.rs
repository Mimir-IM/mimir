//! Tracker-based peer resolver (V2 TLV protocol).
//!
//! Implements the lightweight UDP-over-Yggdrasil tracker protocol used to map
//! a user's permanent Ed25519 pubkey to their current ephemeral Yggdrasil node
//! pubkey ("address").
//!
//! ## Protocol frame layout (V2)
//!
//! **Client → tracker (request):**
//! ```text
//! [VERSION:1][nonce:4 BE][CMD:1][TLV payload...]
//! ```
//!
//! **Tracker → client (response):**
//! ```text
//! [nonce:4 BE][CMD:1][TLV payload...]
//! ```
//!
//! ### CMD_ANNOUNCE (0x00)
//! Request TLV : TAG_USER_PUB, TAG_NODE_PUB, TAG_SIGNATURE, TAG_PRIORITY, TAG_CLIENT_ID
//! Response TLV: TAG_TTL_SECS
//!
//! ### CMD_GET_ADDRS (0x01)
//! Request TLV : TAG_USER_PUB
//! Response TLV: TAG_COUNT, N × TAG_RECORD (each a nested TLV with
//!               TAG_NODE_PUB, TAG_SIGNATURE, TAG_PRIORITY, TAG_CLIENT_ID, TAG_EXPIRES_MS)

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use ygg_stream::AsyncNode;

use crate::crypto::{sign, verify};
use crate::tlv::*;

// ── Protocol constants ────────────────────────────────────────────────────────

const VERSION: u8 = 2;
const CMD_ANNOUNCE: u8 = 0x00;
const CMD_GET_ADDRS: u8 = 0x01;
const CMD_PING: u8 = 0x02;

/// How long to wait for a single tracker response.
const RECV_TIMEOUT_MS: i64 = 5_000;

/// Maximum number of received datagrams to scan when matching a nonce
/// (guards against stale/unrelated datagrams piling up).
const MAX_RECV_LOOPS: usize = 16;

// ── Tracker TLV tag constants ────────────────────────────────────────────────

const TAG_USER_PUB:   u8 = 0x01;
const TAG_NODE_PUB:   u8 = 0x02;
const TAG_SIGNATURE:  u8 = 0x03;
const TAG_PRIORITY:   u8 = 0x05;
const TAG_CLIENT_ID:  u8 = 0x06;
const TAG_TTL_SECS:   u8 = 0x07;
const TAG_EXPIRES_MS: u8 = 0x08;
const TAG_COUNT:      u8 = 0x0B;
const TAG_RECORD:     u8 = 0x0C;

// ── Tracker address ───────────────────────────────────────────────────────────

struct TrackerEntry {
    pubkey: [u8; 32],
    port: u16,
    latency_ms: AtomicU64,
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

    /// Query a responsive tracker for `permanent_pubkey`.
    ///
    /// Pings trackers to find a live one (priming the Yggdrasil route),
    /// then queries that single tracker.  Trackers sync with each other,
    /// so one responsive tracker is sufficient.
    pub async fn query_trackers(&self, permanent_pubkey: &[u8; 32]) -> Vec<[u8; 32]> {
        if self.trackers.is_empty() {
            return vec![];
        }

        // Serialise datagram operations globally so we don't race with
        // concurrent queries or announces.
        let _lock = self.recv_lock.lock().await;

        let idx = match self.pick_tracker().await {
            Some(i) => i,
            None => {
                tracing::warn!("resolver: no tracker responded to ping");
                return vec![];
            }
        };

        let tracker = &self.trackers[idx];
        match self.get_addrs_from(tracker, permanent_pubkey).await {
            Ok(peers) => {
                let keys: Vec<[u8; 32]> = {
                    let mut sorted = peers.iter().collect::<Vec<_>>();
                    sorted.sort_by(|a, b| b.priority.cmp(&a.priority));
                    sorted.iter().map(|p| p.addr).collect()
                };
                if !peers.is_empty() {
                    self.cache.lock().unwrap().insert(*permanent_pubkey, peers);
                }
                keys
            }
            Err(e) => {
                tracing::warn!(
                    "resolver: tracker {} query failed: {e}",
                    hex::encode(&tracker.pubkey[..4])
                );
                vec![]
            }
        }
    }

    /// Announce our current ephemeral address (= `our_pubkey`) to a tracker.
    ///
    /// Pings trackers to find a live one (priming the route), then announces
    /// to that single tracker.  Trackers sync with each other, so one is enough.
    pub async fn announce(&self) -> Result<i64, String> {
        if self.trackers.is_empty() {
            return Err(String::from("No useful trackers"));
        }

        let _lock = self.recv_lock.lock().await;

        let idx = match self.pick_tracker().await {
            Some(i) => i,
            None => return Err("no tracker responded to ping".to_string()),
        };
        let tracker = &self.trackers[idx];

        // Sign our ephemeral key with our permanent signing key.
        let our_addr = self.our_addr;
        let sig = sign(&self.signing_key, &our_addr);
        let public_key  = self.signing_key.verifying_key().to_bytes();
        tracing::info!("Announcing addr {} for {}", hex::encode(&our_addr), hex::encode(&public_key[..8]));

        // Build V2 TLV announce frame:
        // [VERSION:1][nonce:4][CMD_ANNOUNCE:1][TLV payload]
        let nonce = random_nonce();

        let mut tlv_payload = Vec::new();
        write_tlv(&mut tlv_payload, TAG_USER_PUB,  &public_key);
        write_tlv(&mut tlv_payload, TAG_NODE_PUB,  &our_addr);
        write_tlv(&mut tlv_payload, TAG_SIGNATURE, &sig);
        write_tlv_u8(&mut tlv_payload, TAG_PRIORITY, 1);
        write_tlv_u32(&mut tlv_payload, TAG_CLIENT_ID, 1);

        let mut frame = Vec::with_capacity(1 + 4 + 1 + tlv_payload.len());
        frame.push(VERSION);
        frame.extend_from_slice(&nonce);
        frame.push(CMD_ANNOUNCE);
        frame.extend_from_slice(&tlv_payload);

        // Pre-register listener so we don't miss the response.
        let _ = self.node.recv_datagram_with_timeout(tracker.port, 1).await;

        if let Err(e) = self.node.send_datagram(&tracker.pubkey, tracker.port, &frame).await {
            return Err(format!("announce send to {} failed: {e}", hex::encode(&tracker.pubkey[..4])));
        }

        match self.recv_matching(&tracker.pubkey, &nonce, CMD_ANNOUNCE, tracker.port).await {
            Ok(payload) => {
                let tlvs = parse_tlvs(&payload)
                    .map_err(|e| format!("announce response parse error: {e}"))?;
                let ttl = tlvs.get_u64(TAG_TTL_SECS)
                    .map_err(|e| format!("announce response missing TTL: {e}"))? as i64;
                tracing::info!("resolver: announced to {}, TTL={ttl}s", hex::encode(&tracker.pubkey[..4]));
                Ok(ttl)
            }
            Err(e) => Err(format!("no announce ack from {}: {e}", hex::encode(&tracker.pubkey[..4]))),
        }
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    /// Ping each tracker in order until one responds.  Returns the index of
    /// the first responsive tracker, or `None` if all are unreachable.
    ///
    /// The ping primes the Yggdrasil route and confirms the tracker is alive,
    /// so the caller can send the real request to that tracker only.
    async fn pick_tracker(&self) -> Option<usize> {
        // Try trackers in ascending latency order (fastest-known first).
        let mut indices: Vec<usize> = (0..self.trackers.len()).collect();
        indices.sort_by_key(|&i| self.trackers[i].latency_ms.load(Ordering::Relaxed));

        for i in indices {
            let tracker = &self.trackers[i];
            let nonce = random_nonce();
            let frame = [VERSION, nonce[0], nonce[1], nonce[2], nonce[3], CMD_PING];

            let _ = self.node.recv_datagram_with_timeout(tracker.port, 1).await;
            if self.node.send_datagram(&tracker.pubkey, tracker.port, &frame).await.is_err() {
                continue;
            }
            let t0 = Instant::now();
            if self.recv_matching(&tracker.pubkey, &nonce, CMD_PING, tracker.port).await.is_ok() {
                let rtt = t0.elapsed().as_millis() as u64;
                tracker.latency_ms.store(rtt, Ordering::Relaxed);
                tracing::debug!("resolver: tracker {} ping RTT = {rtt}ms", hex::encode(&tracker.pubkey[..4]));
                return Some(i);
            }
            let prev = tracker.latency_ms.load(Ordering::Relaxed);
            tracker.latency_ms.store(prev.saturating_add(25), Ordering::Relaxed);
            tracing::debug!("resolver: ping to tracker {} timed out (latency now {}ms)", hex::encode(&tracker.pubkey[..4]), prev + 25);
        }
        None
    }

    async fn get_addrs_from(&self, tracker: &TrackerEntry, permanent_pubkey: &[u8; 32]) -> Result<Vec<CachedPeer>, String> {
        let nonce = random_nonce();

        // GET_ADDRS V2 request: [VERSION:1][nonce:4][CMD_GET_ADDRS:1][TLV: TAG_USER_PUB]
        let mut tlv_payload = Vec::new();
        write_tlv(&mut tlv_payload, TAG_USER_PUB, permanent_pubkey);

        let mut frame = Vec::with_capacity(1 + 4 + 1 + tlv_payload.len());
        frame.push(VERSION);
        frame.extend_from_slice(&nonce);
        frame.push(CMD_GET_ADDRS);
        frame.extend_from_slice(&tlv_payload);

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

/// Parse a V2 GET_ADDRS response TLV payload:
/// - TAG_COUNT: number of records
/// - TAG_RECORD (repeated): nested TLV with TAG_NODE_PUB, TAG_SIGNATURE,
///   TAG_PRIORITY, TAG_CLIENT_ID, TAG_EXPIRES_MS
///
/// Each peer record is signature-verified against `permanent_pubkey`.
/// Invalid records are silently skipped.
fn parse_get_addrs_response(payload: &[u8], permanent_pubkey: &[u8; 32]) -> Result<Vec<CachedPeer>, String> {
    if payload.is_empty() {
        return Ok(vec![]);
    }

    let multi = parse_tlvs_multi(payload)
        .map_err(|e| format!("GET_ADDRS: TLV parse error: {e}"))?;

    // Extract count (single-value tag).
    let count = match multi.get(&TAG_COUNT) {
        Some(vals) if !vals.is_empty() => {
            if vals[0].len() != 1 {
                return Err("GET_ADDRS: TAG_COUNT must be 1 byte".into());
            }
            vals[0][0] as usize
        }
        _ => return Ok(vec![]),
    };

    if count == 0 {
        return Ok(vec![]);
    }

    let records = match multi.get(&TAG_RECORD) {
        Some(r) => r,
        None => return Err("GET_ADDRS: expected TAG_RECORD entries".into()),
    };

    if records.len() < count {
        return Err(format!(
            "GET_ADDRS: count={count} but only {} TAG_RECORD entries",
            records.len()
        ));
    }

    let now = Instant::now();
    let mut peers = Vec::with_capacity(count);

    for record_data in records.iter().take(count) {
        let inner = match parse_tlvs(record_data) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!("resolver: bad record TLV: {e}");
                continue;
            }
        };

        let node_pub = match inner.get_bytes(TAG_NODE_PUB) {
            Ok(b) if b.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(b);
                arr
            }
            _ => { continue; }
        };

        let sig = match inner.get_bytes(TAG_SIGNATURE) {
            Ok(b) if b.len() == 64 => b,
            _ => { continue; }
        };

        let priority = inner.get_u8(TAG_PRIORITY).unwrap_or(0);

        let client_id = match inner.get_u32(TAG_CLIENT_ID) {
            Ok(v) => v,
            Err(_) => { continue; }
        };

        let expires_ms = match inner.get_u64(TAG_EXPIRES_MS) {
            Ok(v) => v,
            Err(_) => { continue; }
        };

        // Verify: sign(permanent_sk, node_pub) must match.
        if verify(permanent_pubkey, &node_pub, sig).is_err() {
            tracing::warn!("resolver: bad signature for peer eph={}", hex::encode(&node_pub[..4]));
            continue;
        }

        peers.push(CachedPeer {
            addr: node_pub,
            priority,
            client_id,
            expires_at: now + Duration::from_millis(expires_ms),
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
    Some(TrackerEntry { pubkey, port, latency_ms: AtomicU64::new(50) })
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

    /// Build a valid V2 GET_ADDRS response TLV payload for the given peers.
    fn build_get_addrs_payload(
        permanent_sk: &SigningKey,
        peers: &[([u8; 32], u8, u32, u64)],  // (eph_key, priority, client_id, expires_ms)
    ) -> Vec<u8> {
        let mut payload = Vec::new();
        write_tlv_u8(&mut payload, TAG_COUNT, peers.len() as u8);

        for (eph_key, priority, client_id, expires_ms) in peers {
            let sig = sign(permanent_sk, eph_key.as_slice());
            let mut record = Vec::new();
            write_tlv(&mut record, TAG_NODE_PUB, eph_key);
            write_tlv(&mut record, TAG_SIGNATURE, &sig);
            write_tlv_u8(&mut record, TAG_PRIORITY, *priority);
            write_tlv_u32(&mut record, TAG_CLIENT_ID, *client_id);
            write_tlv_u64(&mut record, TAG_EXPIRES_MS, *expires_ms);
            write_tlv(&mut payload, TAG_RECORD, &record);
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

    // ── parse_get_addrs_response (V2 TLV) ───────────────────────────────────

    #[test]
    fn parse_get_addrs_empty_payload() {
        let permanent_pk = [0u8; 32];
        let peers = parse_get_addrs_response(&[], &permanent_pk).unwrap();
        assert!(peers.is_empty());
    }

    #[test]
    fn parse_get_addrs_zero_count() {
        let mut payload = Vec::new();
        write_tlv_u8(&mut payload, TAG_COUNT, 0);
        let permanent_pk = [0u8; 32];
        let peers = parse_get_addrs_response(&payload, &permanent_pk).unwrap();
        assert!(peers.is_empty());
    }

    #[test]
    fn parse_get_addrs_valid_single_record() {
        let sk            = random_sk();
        let permanent_pk  = sk.verifying_key().to_bytes();
        let eph_key       = [7u8; 32];
        let payload = build_get_addrs_payload(&sk, &[(eph_key, 5, 42, 300_000)]);

        let peers = parse_get_addrs_response(&payload, &permanent_pk).unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].addr, eph_key);
        assert_eq!(peers[0].priority, 5);
        assert_eq!(peers[0].client_id, 42);
        // expires_ms was 300_000 ms = 300 s; expires_at should be in the future
        assert!(peers[0].expires_at > Instant::now());
    }

    #[test]
    fn parse_get_addrs_multiple_records() {
        let sk           = random_sk();
        let permanent_pk = sk.verifying_key().to_bytes();
        let peers_in = [
            ([1u8; 32], 10u8, 1u32, 600_000u64),
            ([2u8; 32], 5,    2,    300_000),
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
        let payload = build_get_addrs_payload(&attacker_sk, &[(eph_key, 1, 1, 60_000)]);

        let peers = parse_get_addrs_response(&payload, &permanent_pk).unwrap();
        assert!(peers.is_empty(), "bad-sig record must be dropped");
    }

    #[test]
    fn parse_get_addrs_count_mismatch_is_error() {
        // Declares 2 peers via TAG_COUNT but only provides 1 TAG_RECORD.
        let sk = random_sk();
        let eph_key = [7u8; 32];
        let sig = sign(&sk, &eph_key);

        let mut payload = Vec::new();
        write_tlv_u8(&mut payload, TAG_COUNT, 2);
        // Only one record
        let mut record = Vec::new();
        write_tlv(&mut record, TAG_NODE_PUB, &eph_key);
        write_tlv(&mut record, TAG_SIGNATURE, &sig);
        write_tlv_u8(&mut record, TAG_PRIORITY, 1);
        write_tlv_u32(&mut record, TAG_CLIENT_ID, 1);
        write_tlv_u64(&mut record, TAG_EXPIRES_MS, 60_000);
        write_tlv(&mut payload, TAG_RECORD, &record);

        let permanent_pk = sk.verifying_key().to_bytes();
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
