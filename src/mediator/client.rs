//! Single authenticated connection to one mediator server.
//!
//! # Lifecycle
//! 1. `MediatorClient::connect()` dials the mediator node, sends the
//!    protocol selector bytes, runs the auth handshake, then spawns:
//!    - a **reader task** that continuously reads server frames and
//!      dispatches them to either pending request waiters or the event listener.
//!    - a **ping task** that sends keep-alive pings every 50 s.
//! 2. Callers send commands via `request()`, which is async-safe and
//!    can be called concurrently from multiple tasks.
//! 3. `stop()` cancels both background tasks and closes the connection.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey};
use tokio::sync::{broadcast, oneshot, Mutex};
use tokio::time;
use ygg_stream::{AsyncConn, AsyncNode};

use crate::types::{GroupMember, GroupMemberInfo, GroupMessage};
use crate::{MimirError, MediatorEventListener};
use super::protocol::*;

// ── Timeouts ──────────────────────────────────────────────────────────────────

/// Timeout for control/query operations (auth, ping, subscribe, get_*, …).
const REQ_TIMEOUT:  Duration = Duration::from_secs(15);
/// Longer timeout for data-write operations (send_message) where the server
/// may be busy but the request is genuinely processed — avoids false timeouts
/// that leave messages marked unsent locally even though they were delivered.
const SEND_TIMEOUT: Duration = Duration::from_secs(30);
const PING_INTERVAL: Duration = Duration::from_secs(50);

// ── Pending request map ───────────────────────────────────────────────────────

type PendingMap = Mutex<HashMap<u16, oneshot::Sender<Response>>>;

// ── MediatorClient ────────────────────────────────────────────────────────────

/// A live, authenticated connection to a single mediator server.
///
/// Cheap to clone — all state is behind `Arc`.
#[derive(Clone)]
pub struct MediatorClient {
    conn:             Arc<AsyncConn>,
    pending:          Arc<PendingMap>,
    write_mu:         Arc<Mutex<()>>,
    next_id:          Arc<AtomicU64>,
    last_activity_ms: Arc<AtomicU64>,
    stop_tx:          broadcast::Sender<()>,
    pub mediator_pubkey: [u8; 32],
    /// Set to true by whichever task (reader or ping) first detects disconnect.
    /// Prevents double `on_disconnected` calls and stale map removals.
    disconnected:     Arc<AtomicBool>,
}

impl MediatorClient {
    /// Dial `mediator_pubkey` on `port`, authenticate, and spawn background tasks.
    ///
    /// Returns the ready-to-use client or an error.
    pub async fn connect(node: &AsyncNode, mediator_pubkey: [u8; 32], port: u16, sk: Arc<SigningKey>, listener: Arc<dyn MediatorEventListener>) -> Result<Self, MimirError> {
        let conn = node.connect(&mediator_pubkey, port).await
            .map_err(|e| MimirError::Connection(e.to_string()))?;
        let conn = Arc::new(conn);

        // Handshake: send [VERSION][PROTO_CLIENT]
        conn.write(&[VERSION, PROTO_CLIENT]).await
            .map_err(|e| MimirError::Io(e))?;

        let (stop_tx, _) = broadcast::channel::<()>(1);
        let pending:  Arc<PendingMap> = Arc::new(Mutex::new(HashMap::new()));
        let write_mu: Arc<Mutex<()>>  = Arc::new(Mutex::new(()));
        let next_id      = Arc::new(AtomicU64::new(1));
        let last_ms      = Arc::new(AtomicU64::new(now_ms()));
        let disconnected = Arc::new(AtomicBool::new(false));

        let client = MediatorClient {
            conn:             Arc::clone(&conn),
            pending:          Arc::clone(&pending),
            write_mu:         Arc::clone(&write_mu),
            next_id:          Arc::clone(&next_id),
            last_activity_ms: Arc::clone(&last_ms),
            stop_tx:          stop_tx.clone(),
            mediator_pubkey,
            disconnected:     Arc::clone(&disconnected),
        };

        // Spawn reader task FIRST — authenticate() uses request() which waits on a
        // oneshot that is only fulfilled by the reader dispatching server responses.
        // Spawning after auth would cause every auth to time out.
        {
            let c        = client.clone();
            let listener = Arc::clone(&listener);
            let mut stop_rx = stop_tx.subscribe();
            tokio::spawn(async move {
                tokio::select! {
                    biased;
                    _ = stop_rx.recv() => {},
                    _ = c.reader_loop(listener.as_ref()) => {},
                }
                // Fail any still-waiting requests.
                let mut map = c.pending.lock().await;
                map.drain().for_each(|(_, tx)| { let _ = tx.send(Response {
                    status:  STATUS_ERR,
                    req_id:  0,
                    payload: b"connection closed".to_vec(),
                }); });
            });
        }

        // Authenticate now that the reader is running to process server responses.
        if let Err(e) = client.authenticate(&sk).await {
            client.stop(); // shut down the reader task we just spawned
            return Err(e);
        }

        // Spawn ping task (needs listener so it can fire on_disconnected on timeout).
        {
            let c           = client.clone();
            let listener    = Arc::clone(&listener);
            let mut stop_rx = stop_tx.subscribe();
            tokio::spawn(async move {
                tokio::select! {
                    biased;
                    _ = stop_rx.recv() => {},
                    _ = c.ping_loop(listener.as_ref()) => {},
                }
            });
        }

        Ok(client)
    }

    /// Stop the client: signal background tasks and close the connection.
    pub fn stop(&self) {
        let _ = self.stop_tx.send(());
    }

    // ── Public command methods ─────────────────────────────────────────────────

    /// `CMD_CREATE_CHAT` — includes proof-of-work (may take a few seconds).
    pub async fn create_chat(&self, sk: &SigningKey, name: &str, description: &str, avatar: Option<&[u8]>) -> Result<i64, MimirError> {
        let our_pubkey = crate::crypto::pubkey_of(sk);

        // GET_NONCE first.
        let nonce = self.get_nonce(&our_pubkey).await?;

        // Proof-of-work: find counter where sig(nonce||counter)[0]==0 && [1]==0.
        let (sig_bytes, counter) = tokio::task::spawn_blocking({
            let sk    = sk.clone();
            let nonce = nonce.clone();
            move || pow_find_sig(&sk, &nonce)
        }).await.map_err(|e| MimirError::Crypto(e.to_string()))??;

        let mut payload = Vec::new();
        write_tlv(&mut payload, TAG_PUBKEY,    &our_pubkey);
        write_tlv(&mut payload, TAG_NONCE,     &nonce);
        write_tlv(&mut payload, TAG_COUNTER,   &(counter as u32).to_be_bytes());
        write_tlv(&mut payload, TAG_SIGNATURE, &sig_bytes);
        write_tlv_str(&mut payload, TAG_CHAT_NAME, name);
        write_tlv_str(&mut payload, TAG_CHAT_DESC, description);
        if let Some(av) = avatar {
            write_tlv(&mut payload, TAG_CHAT_AVATAR, av);
        }

        let resp = self.request(CMD_CREATE_CHAT, &payload).await?;
        if resp.status != STATUS_OK {
            return Err(resp.into_error("createChat"));
        }
        let tlvs = parse_tlvs(&resp.payload)?;
        tlvs.get_i64(TAG_CHAT_ID)
    }

    pub async fn delete_chat(&self, chat_id: i64) -> Result<(), MimirError> {
        let mut p = Vec::new();
        write_tlv_i64(&mut p, TAG_CHAT_ID, chat_id);
        let resp = self.request(CMD_DELETE_CHAT, &p).await?;
        if resp.status != STATUS_OK { return Err(resp.into_error("deleteChat")); }
        Ok(())
    }

    pub async fn update_chat_info(&self, chat_id: i64, name: Option<&str>, desc: Option<&str>, avatar: Option<&[u8]>) -> Result<(), MimirError> {
        let mut p = Vec::new();
        write_tlv_i64(&mut p, TAG_CHAT_ID, chat_id);
        if let Some(n) = name   { write_tlv_str(&mut p, TAG_CHAT_NAME, n); }
        if let Some(d) = desc   { write_tlv_str(&mut p, TAG_CHAT_DESC, d); }
        if let Some(a) = avatar { write_tlv(&mut p, TAG_CHAT_AVATAR, a); }
        let resp = self.request(CMD_UPDATE_CHAT_INFO, &p).await?;
        if resp.status != STATUS_OK { return Err(resp.into_error("updateChatInfo")); }
        Ok(())
    }

    pub async fn add_user(&self, chat_id: i64, user_pubkey: &[u8]) -> Result<(), MimirError> {
        let mut p = Vec::new();
        write_tlv_i64(&mut p, TAG_CHAT_ID,     chat_id);
        write_tlv(&mut p,     TAG_USER_PUBKEY, user_pubkey);
        let resp = self.request(CMD_ADD_USER, &p).await?;
        if resp.status != STATUS_OK { return Err(resp.into_error("addUser")); }
        Ok(())
    }

    pub async fn delete_user(&self, chat_id: i64, user_pubkey: &[u8]) -> Result<(), MimirError> {
        let mut p = Vec::new();
        write_tlv_i64(&mut p, TAG_CHAT_ID,     chat_id);
        write_tlv(&mut p,     TAG_USER_PUBKEY, user_pubkey);
        let resp = self.request(CMD_DELETE_USER, &p).await?;
        if resp.status != STATUS_OK { return Err(resp.into_error("deleteUser")); }
        Ok(())
    }

    /// Returns the list of chat IDs this user is a member of on the server.
    /// Used internally after (re)connect to resubscribe to all chats.
    pub(super) async fn get_user_chats(&self) -> Result<Vec<i64>, MimirError> {
        let resp = self.request(CMD_GET_USER_CHATS, &[]).await?;
        if resp.status != STATUS_OK {
            return Err(resp.into_error("getUserChats"));
        }
        // Response is a flat TLV stream with repeated TAG_CHAT_ID fields.
        let mut chat_ids = Vec::new();
        let mut offset = 0;
        let p = &resp.payload;
        while offset < p.len() {
            let tag = p[offset]; offset += 1;
            let (len, consumed) = read_varint(p, offset)?;
            offset += consumed;
            let end = offset + len as usize;
            if end > p.len() {
                return Err(MimirError::Protocol("getUserChats: TLV overrun".into()));
            }
            if tag == TAG_CHAT_ID && len == 8 {
                chat_ids.push(i64::from_be_bytes(p[offset..end].try_into().unwrap()));
            }
            offset = end;
        }
        Ok(chat_ids)
    }

    pub async fn leave_chat(&self, chat_id: i64) -> Result<(), MimirError> {
        let mut p = Vec::new();
        write_tlv_i64(&mut p, TAG_CHAT_ID, chat_id);
        let resp = self.request(CMD_LEAVE_CHAT, &p).await?;
        if resp.status != STATUS_OK { return Err(resp.into_error("leaveChat")); }
        Ok(())
    }

    /// Returns the server's last message ID for the chat (used to detect missed messages).
    pub async fn subscribe(&self, chat_id: i64) -> Result<i64, MimirError> {
        let mut p = Vec::new();
        write_tlv_i64(&mut p, TAG_CHAT_ID, chat_id);
        let resp = self.request(CMD_SUBSCRIBE, &p).await?;
        if resp.status != STATUS_OK { return Err(resp.into_error("subscribe")); }
        let tlvs = parse_tlvs(&resp.payload)?;
        tlvs.get_i64(TAG_MESSAGE_ID)
    }

    /// Returns `(message_id, guid)`.
    pub async fn send_message(&self, chat_id: i64, guid: i64, timestamp: i64, data: &[u8]) -> Result<(i64, i64), MimirError> {
        let mut p = Vec::new();
        write_tlv_i64(&mut p, TAG_CHAT_ID,      chat_id);
        write_tlv_i64(&mut p, TAG_MESSAGE_GUID,  guid);
        write_tlv_i64(&mut p, TAG_TIMESTAMP,     timestamp);
        write_tlv(&mut p,     TAG_MESSAGE_BLOB,  data);
        let resp = self.request_timed(CMD_SEND_MESSAGE, &p, SEND_TIMEOUT).await?;
        if resp.status != STATUS_OK { return Err(resp.into_error("sendMessage")); }
        let tlvs = parse_tlvs(&resp.payload)?;
        let msg_id  = tlvs.get_i64(TAG_MESSAGE_ID)?;
        let new_guid = tlvs.opt_i64(TAG_MESSAGE_GUID).unwrap_or(guid);
        Ok((msg_id, new_guid))
    }

    pub async fn delete_message(&self, chat_id: i64, message_id: i64) -> Result<(), MimirError> {
        let mut p = Vec::new();
        write_tlv_i64(&mut p, TAG_CHAT_ID,    chat_id);
        write_tlv_i64(&mut p, TAG_MESSAGE_ID, message_id);
        let resp = self.request(CMD_DELETE_MESSAGE, &p).await?;
        if resp.status != STATUS_OK { return Err(resp.into_error("deleteMessage")); }
        Ok(())
    }

    pub async fn get_last_message_id(&self, chat_id: i64) -> Result<i64, MimirError> {
        let mut p = Vec::new();
        write_tlv_i64(&mut p, TAG_CHAT_ID, chat_id);
        let resp = self.request(CMD_GET_LAST_MESSAGE_ID, &p).await?;
        if resp.status != STATUS_OK { return Err(resp.into_error("getLastMessageId")); }
        let tlvs = parse_tlvs(&resp.payload)?;
        tlvs.get_i64(TAG_MESSAGE_ID)
    }

    pub async fn get_messages_since(&self, chat_id: i64, since_id: i64, limit: u32) -> Result<Vec<GroupMessage>, MimirError> {
        let mut p = Vec::new();
        write_tlv_i64(&mut p, TAG_CHAT_ID,  chat_id);
        write_tlv_i64(&mut p, TAG_SINCE_ID, since_id);
        write_tlv_u32(&mut p, TAG_LIMIT,    limit);
        let resp = self.request(CMD_GET_MESSAGES_SINCE, &p).await?;
        if resp.status != STATUS_OK { return Err(resp.into_error("getMessagesSince")); }
        parse_messages_list(&resp.payload)
    }

    pub async fn send_invite(&self, chat_id: i64, recipient: &[u8], encrypted_data: &[u8]) -> Result<(), MimirError> {
        let mut p = Vec::new();
        write_tlv_i64(&mut p, TAG_CHAT_ID,    chat_id);
        write_tlv(&mut p,     TAG_USER_PUBKEY, recipient);
        write_tlv(&mut p,     TAG_INVITE_DATA, encrypted_data);
        let resp = self.request(CMD_SEND_INVITE, &p).await?;
        if resp.status != STATUS_OK { return Err(resp.into_error("sendInvite")); }
        Ok(())
    }

    pub async fn respond_to_invite(&self, chat_id: i64, invite_id: i64, accept: bool) -> Result<(), MimirError> {
        let mut p = Vec::new();
        write_tlv_i64(&mut p, TAG_CHAT_ID,   chat_id);
        write_tlv_i64(&mut p, TAG_INVITE_ID, invite_id);
        write_tlv_u8(&mut p,  TAG_ACCEPTED,  accept as u8);
        let resp = self.request(CMD_INVITE_RESPONSE, &p).await?;
        if resp.status != STATUS_OK { return Err(resp.into_error("respondToInvite")); }
        Ok(())
    }

    pub async fn update_member_info(&self, chat_id: i64, encrypted_blob: &[u8], timestamp: i64) -> Result<(), MimirError> {
        let mut p = Vec::new();
        write_tlv_i64(&mut p, TAG_CHAT_ID,     chat_id);
        write_tlv(&mut p,     TAG_MEMBER_INFO, encrypted_blob);
        write_tlv_i64(&mut p, TAG_TIMESTAMP,   timestamp);
        let resp = self.request(CMD_UPDATE_MEMBER_INFO, &p).await?;
        if resp.status != STATUS_OK { return Err(resp.into_error("updateMemberInfo")); }
        Ok(())
    }

    pub async fn get_members_info(&self, chat_id: i64, since_timestamp: i64) -> Result<Vec<GroupMemberInfo>, MimirError> {
        let mut p = Vec::new();
        write_tlv_i64(&mut p, TAG_CHAT_ID,     chat_id);
        write_tlv_i64(&mut p, TAG_LAST_UPDATE, since_timestamp);
        let resp = self.request(CMD_GET_MEMBERS_INFO, &p).await?;
        if resp.status != STATUS_OK { return Err(resp.into_error("getMembersInfo")); }
        parse_members_info_list(&resp.payload)
    }

    pub async fn get_members(&self, chat_id: i64) -> Result<Vec<GroupMember>, MimirError> {
        let mut p = Vec::new();
        write_tlv_i64(&mut p, TAG_CHAT_ID, chat_id);
        let resp = self.request(CMD_GET_MEMBERS, &p).await?;
        if resp.status != STATUS_OK { return Err(resp.into_error("getMembers")); }
        parse_members_list(&resp.payload)
    }

    pub async fn change_member_status(&self, chat_id: i64, user_pubkey: &[u8], new_permissions: u8) -> Result<(), MimirError> {
        let mut p = Vec::new();
        write_tlv_i64(&mut p, TAG_CHAT_ID, chat_id);
        write_tlv(&mut p, TAG_USER_PUBKEY, user_pubkey);
        write_tlv_u8(&mut p, TAG_PERMS, new_permissions);
        let resp = self.request(CMD_CHANGE_MEMBER_STATUS, &p).await?;
        if resp.status != STATUS_OK { return Err(resp.into_error("changeMemberStatus")); }
        Ok(())
    }

    // ── Internal: auth ─────────────────────────────────────────────────────────

    async fn authenticate(&self, sk: &SigningKey) -> Result<(), MimirError> {
        let our_pubkey = crate::crypto::pubkey_of(sk);
        let nonce = self.get_nonce(&our_pubkey).await?;

        let sig = sk.sign(&nonce);

        let mut p = Vec::new();
        write_tlv(&mut p, TAG_PUBKEY,    &our_pubkey);
        write_tlv(&mut p, TAG_NONCE,     &nonce);
        write_tlv(&mut p, TAG_SIGNATURE, sig.to_bytes().as_ref());

        let resp = self.request(CMD_AUTH, &p).await?;
        if resp.status != STATUS_OK {
            return Err(MimirError::Auth(format!(
                "authentication rejected: {}", resp.error_string()
            )));
        }
        Ok(())
    }

    async fn get_nonce(&self, pubkey: &[u8]) -> Result<Vec<u8>, MimirError> {
        let mut p = Vec::new();
        write_tlv(&mut p, TAG_PUBKEY, pubkey);
        let resp = self.request(CMD_GET_NONCE, &p).await?;
        if resp.status != STATUS_OK {
            return Err(MimirError::Auth(format!(
                "getNonce failed: {}", resp.error_string()
            )));
        }
        let tlvs = parse_tlvs(&resp.payload)?;
        Ok(tlvs.get_bytes(TAG_NONCE)?.to_vec())
    }

    // ── Internal: request/response ─────────────────────────────────────────────

    /// Send a command and wait for the matching response (up to `REQ_TIMEOUT`).
    pub(super) async fn request(&self, cmd: u8, payload: &[u8]) -> Result<Response, MimirError> {
        self.request_timed(cmd, payload, REQ_TIMEOUT).await
    }

    /// Like `request()` but with a caller-specified timeout.
    ///
    /// The timeout covers both the write and the response wait so that a stalled
    /// send on a slow Yggdrasil link does not block indefinitely.  The header and
    /// payload are written as two separate calls under the same write mutex, avoiding
    /// a full allocation of a combined frame for large payloads (e.g. images).
    async fn request_timed(&self, cmd: u8, payload: &[u8], timeout_dur: Duration) -> Result<Response, MimirError> {
        // Allocate req_id: u16, skip 0 (reserved for push).
        let raw = self.next_id.fetch_add(1, Ordering::Relaxed);
        let req_id = ((raw % 0xFFFF) as u16) + 1; // range 1..=65535

        let (tx, rx) = oneshot::channel::<Response>();
        self.pending.lock().await.insert(req_id, tx);

        // Write header + payload, then wait for response — all under one timeout.
        let header = build_request_header(cmd, req_id, payload.len());
        let result = time::timeout(timeout_dur, async {
            {
                let _guard = self.write_mu.lock().await;
                self.conn.write(&header).await.map_err(|e| MimirError::Io(e))?;
                self.conn.write(payload).await.map_err(|e| MimirError::Io(e))?;
            }
            rx.await.map_err(|_| MimirError::Connection("connection closed during request".into()))
        }).await;

        match result {
            Ok(Ok(resp)) => Ok(resp),
            Ok(Err(e)) => {
                self.pending.lock().await.remove(&req_id);
                Err(e)
            }
            Err(_timeout) => {
                // Connection is stalled — close it so reader/ping detect failure.
                self.conn.close().await;
                self.pending.lock().await.remove(&req_id);
                Err(MimirError::Connection(format!(
                    "request cmd=0x{cmd:02x} timed out"
                )))
            }
        }
    }

    // ── Internal: reader loop ──────────────────────────────────────────────────

    async fn reader_loop(&self, listener: &dyn MediatorEventListener) {
        loop {
            let resp = match read_response(&self.conn).await {
                Ok(r)  => r,
                Err(e) => {
                    log::error!("mediator reader error: {e}");
                    // Use swap to ensure only one of reader/ping fires on_disconnected.
                    if !self.disconnected.swap(true, Ordering::SeqCst) {
                        listener.on_disconnected(self.mediator_pubkey.to_vec());
                    }
                    return;
                }
            };

            self.last_activity_ms.store(now_ms(), Ordering::Relaxed);

            // Dispatch push messages by their special req_id values.
            if resp.status == STATUS_OK {
                match resp.req_id as u16 {
                    PUSH_GOT_MESSAGE => {
                        self.handle_push_message(resp.payload, listener);
                        continue;
                    }
                    PUSH_GOT_INVITE => {
                        self.handle_push_invite(resp.payload, listener);
                        continue;
                    }
                    PUSH_REQUEST_MEMBER_INFO => {
                        self.handle_member_info_request(resp.payload, listener).await;
                        continue;
                    }
                    PUSH_GOT_MEMBER_INFO => {
                        self.handle_member_info_update(resp.payload, listener);
                        continue;
                    }
                    _ => {}
                }
            }

            // Normal response: complete the waiting oneshot.
            let mut map = self.pending.lock().await;
            if let Some(tx) = map.remove(&resp.req_id) {
                let _ = tx.send(resp);
            } else {
                log::warn!(
                    "mediator: unmatched response req_id={} status={}",
                    resp.req_id, resp.status
                );
            }
        }
    }

    fn handle_push_message(&self, payload: Vec<u8>, listener: &dyn MediatorEventListener) {
        let tlvs = match parse_tlvs(&payload) {
            Ok(t)  => t,
            Err(e) => { log::error!("push_message parse error: {e}"); return; }
        };
        let chat_id    = tlvs.get_i64(TAG_CHAT_ID).unwrap_or(0);
        let message_id = tlvs.get_i64(TAG_MESSAGE_ID).unwrap_or(0);
        let guid       = tlvs.get_i64(TAG_MESSAGE_GUID).unwrap_or(0);
        let timestamp  = tlvs.get_i64(TAG_TIMESTAMP).unwrap_or(0)
            .saturating_mul(1000); // seconds → milliseconds
        let author     = tlvs.opt_bytes(TAG_PUBKEY).unwrap_or_default();
        let data       = tlvs.opt_bytes(TAG_MESSAGE_BLOB).unwrap_or_default();

        // System messages have the mediator's pubkey as author.
        if author.as_slice() == self.mediator_pubkey.as_ref() {
            if data.first() == Some(&SYS_MEMBER_ONLINE) && data.len() >= 42 {
                // Parse: [event(1)][pubkey(32)][online(1)][timestamp(8)]
                let member_pubkey = data[1..33].to_vec();
                let is_online     = data[33] == 1;
                let ts_bytes: [u8; 8] = data[34..42].try_into().unwrap_or([0; 8]);
                let ts = i64::from_be_bytes(ts_bytes);
                listener.on_member_online_status_changed(chat_id, member_pubkey, is_online, ts);
            } else {
                listener.on_system_message(chat_id, message_id, guid, timestamp, data);
            }
        } else {
            listener.on_push_message(chat_id, message_id, guid, timestamp, author, data);
        }
    }

    fn handle_push_invite(&self, payload: Vec<u8>, listener: &dyn MediatorEventListener) {
        let tlvs = match parse_tlvs(&payload) {
            Ok(t)  => t,
            Err(e) => { log::error!("push_invite parse error: {e}"); return; }
        };
        let invite_id  = tlvs.get_i64(TAG_INVITE_ID).unwrap_or(0);
        let chat_id    = tlvs.get_i64(TAG_CHAT_ID).unwrap_or(0);
        let from       = tlvs.opt_bytes(TAG_PUBKEY).unwrap_or_default();
        let timestamp  = tlvs.get_i64(TAG_TIMESTAMP).unwrap_or(0)
            .saturating_mul(1000);
        let name       = String::from_utf8(
            tlvs.opt_bytes(TAG_CHAT_NAME).unwrap_or_default()
        ).unwrap_or_default();
        let desc       = String::from_utf8(
            tlvs.opt_bytes(TAG_CHAT_DESC).unwrap_or_default()
        ).unwrap_or_default();
        let avatar     = tlvs.opt_bytes(TAG_CHAT_AVATAR);
        let enc_data   = tlvs.opt_bytes(TAG_INVITE_DATA).unwrap_or_default();

        listener.on_push_invite(invite_id, chat_id, from, timestamp, name, desc, avatar, enc_data);
    }

    async fn handle_member_info_request(&self,payload:  Vec<u8>, listener: &dyn MediatorEventListener) {
        let tlvs = match parse_tlvs(&payload) {
            Ok(t)  => t,
            Err(e) => { log::error!("member_info_request parse error: {e}"); return; }
        };
        let chat_id     = tlvs.get_i64(TAG_CHAT_ID).unwrap_or(0);
        let last_update = tlvs.opt_i64(TAG_LAST_UPDATE).unwrap_or(0);

        if let Some(info) = listener.on_member_info_request(chat_id, last_update) {
            let self2 = self.clone();
            let info_clone = info.clone();
            tokio::spawn(async move {
                if let Err(e) = self2.update_member_info(
                    chat_id,
                    &info_clone.encrypted_blob,
                    info_clone.timestamp,
                ).await {
                    log::error!("update_member_info after request failed: {e}");
                }
            });
        }
    }

    fn handle_member_info_update(&self, payload: Vec<u8>, listener: &dyn MediatorEventListener) {
        let tlvs = match parse_tlvs(&payload) {
            Ok(t)  => t,
            Err(e) => { log::error!("member_info_update parse error: {e}"); return; }
        };
        let chat_id       = tlvs.get_i64(TAG_CHAT_ID).unwrap_or(0);
        let member_pubkey = tlvs.opt_bytes(TAG_USER_PUBKEY).unwrap_or_default();
        let encrypted     = tlvs.opt_bytes(TAG_MEMBER_INFO);
        let timestamp     = tlvs.get_i64(TAG_TIMESTAMP).unwrap_or(0);

        listener.on_member_info_update(chat_id, member_pubkey, encrypted, timestamp);
    }

    // ── Internal: ping loop ────────────────────────────────────────────────────

    async fn ping_loop(&self, listener: &dyn MediatorEventListener) {
        let mut interval = time::interval(PING_INTERVAL);
        interval.tick().await; // skip the immediate first tick
        loop {
            interval.tick().await;
            let elapsed = now_ms().saturating_sub(
                self.last_activity_ms.load(Ordering::Relaxed)
            );
            if elapsed >= PING_INTERVAL.as_millis() as u64 {
                if let Err(e) = self.request(CMD_PING, &[]).await {
                    log::error!("mediator ping failed: {e}");
                    // Zombie connection detected — notify and stop everything.
                    if !self.disconnected.swap(true, Ordering::SeqCst) {
                        listener.on_disconnected(self.mediator_pubkey.to_vec());
                    }
                    // Stop the reader task too (it may be blocked on a hung read).
                    let _ = self.stop_tx.send(());
                    return;
                }
            }
        }
    }

    /// Returns `true` if this client has been marked as disconnected.
    pub fn is_disconnected(&self) -> bool {
        self.disconnected.load(Ordering::SeqCst)
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Proof-of-work: find a counter such that `sign(sk, nonce||counter)[0]==0 && [1]==0`.
/// This is CPU-intensive (~32 k–64 k iterations on average).
fn pow_find_sig(sk: &SigningKey, nonce: &[u8]) -> Result<(Vec<u8>, u64), MimirError> {
    let mut msg = vec![0u8; nonce.len() + 4];
    msg[..nonce.len()].copy_from_slice(nonce);
    let mut counter: u32 = 0;
    loop {
        msg[nonce.len()..].copy_from_slice(&counter.to_be_bytes());
        let sig = sk.sign(&msg);
        let bytes = sig.to_bytes();
        if bytes[0] == 0 && bytes[1] == 0 {
            return Ok((bytes.to_vec(), counter as u64));
        }
        counter = counter.wrapping_add(1);
        if counter == 0 {
            return Err(MimirError::Crypto("POW exhausted all u32 values".into()));
        }
    }
}

// ── Response list parsers ─────────────────────────────────────────────────────

fn parse_messages_list(payload: &[u8]) -> Result<Vec<GroupMessage>, MimirError> {
    // Repeated TLV records: each record contains TAG_MESSAGE_ID, TAG_MESSAGE_GUID,
    // TAG_TIMESTAMP, TAG_PUBKEY, TAG_MESSAGE_BLOB.
    // The server sends them as a flat TLV stream; duplicate tags are ordered per message.
    // We parse by iterating until we have a complete record (keyed on MESSAGE_ID presence).
    let mut messages = Vec::new();
    let mut offset = 0;

    // Current record fields.
    let mut message_id: Option<i64> = None;
    let mut guid:       Option<i64> = None;
    let mut timestamp:  Option<i64> = None;
    let mut author:     Option<Vec<u8>> = None;
    let mut data:       Option<Vec<u8>> = None;

    macro_rules! flush {
        () => {
            if let Some(mid) = message_id.take() {
                messages.push(GroupMessage {
                    message_id: mid,
                    guid:       guid.take().unwrap_or(0),
                    timestamp:  timestamp.take().unwrap_or(0).saturating_mul(1000),
                    author:     author.take().unwrap_or_default(),
                    data:       data.take().unwrap_or_default(),
                });
            }
        };
    }

    while offset < payload.len() {
        let tag = payload[offset]; offset += 1;
        let (len, consumed) = read_varint(payload, offset)?;
        offset += consumed;
        let end = offset + len as usize;
        if end > payload.len() {
            return Err(MimirError::Protocol("message list: TLV overrun".into()));
        }
        let value = &payload[offset..end];
        offset = end;

        match tag {
            TAG_MESSAGE_ID => {
                // Start of a new record — flush previous if any.
                if message_id.is_some() { flush!(); }
                if value.len() == 8 {
                    message_id = Some(i64::from_be_bytes(value.try_into().unwrap()));
                }
            }
            TAG_MESSAGE_GUID => {
                if value.len() == 8 {
                    guid = Some(i64::from_be_bytes(value.try_into().unwrap()));
                }
            }
            TAG_TIMESTAMP => {
                if value.len() == 8 {
                    timestamp = Some(i64::from_be_bytes(value.try_into().unwrap()));
                }
            }
            TAG_PUBKEY => { author = Some(value.to_vec()); }
            TAG_MESSAGE_BLOB => { data = Some(value.to_vec()); }
            _ => {}
        }
    }
    flush!();
    Ok(messages)
}

fn parse_members_info_list(payload: &[u8]) -> Result<Vec<GroupMemberInfo>, MimirError> {
    let mut members = Vec::new();
    let mut offset = 0;

    let mut pubkey:    Option<Vec<u8>> = None;
    let mut enc_info:  Option<Vec<u8>> = None;
    let mut timestamp: Option<i64>     = None;

    macro_rules! flush {
        () => {
            if let Some(pk) = pubkey.take() {
                members.push(GroupMemberInfo {
                    pubkey:         pk,
                    encrypted_info: enc_info.take(),
                    timestamp:      timestamp.take().unwrap_or(0),
                });
            }
        };
    }

    while offset < payload.len() {
        let tag = payload[offset]; offset += 1;
        let (len, consumed) = read_varint(payload, offset)?;
        offset += consumed;
        let end = offset + len as usize;
        if end > payload.len() {
            return Err(MimirError::Protocol("members_info list: TLV overrun".into()));
        }
        let value = &payload[offset..end];
        offset = end;

        match tag {
            TAG_USER_PUBKEY => {
                if pubkey.is_some() { flush!(); }
                pubkey = Some(value.to_vec());
            }
            TAG_MEMBER_INFO => { enc_info  = Some(value.to_vec()); }
            TAG_TIMESTAMP   => {
                if value.len() == 8 {
                    timestamp = Some(i64::from_be_bytes(value.try_into().unwrap()));
                }
            }
            _ => {}
        }
    }
    flush!();
    Ok(members)
}

fn parse_members_list(payload: &[u8]) -> Result<Vec<GroupMember>, MimirError> {
    let mut members = Vec::new();
    let mut offset = 0;

    let mut pubkey:    Option<Vec<u8>> = None;
    let mut perms:     u32             = 0;
    let mut online:    bool            = false;
    let mut last_seen: i64             = 0;

    macro_rules! flush {
        () => {
            if let Some(pk) = pubkey.take() {
                members.push(GroupMember {
                    pubkey:      pk,
                    permissions: perms,
                    online,
                    last_seen,
                });
            }
        };
    }

    while offset < payload.len() {
        let tag = payload[offset]; offset += 1;
        let (len, consumed) = read_varint(payload, offset)?;
        offset += consumed;
        let end = offset + len as usize;
        if end > payload.len() {
            return Err(MimirError::Protocol("members list: TLV overrun".into()));
        }
        let value = &payload[offset..end];
        offset = end;

        match tag {
            TAG_USER_PUBKEY => {
                flush!();  // emit previous record if any
                pubkey    = Some(value.to_vec());
                perms     = 0;
                online    = false;
                last_seen = 0;
            }
            TAG_PERMS  => {
                if !value.is_empty() { perms = value[0] as u32; }
            }
            TAG_ONLINE => {
                if !value.is_empty() { online = value[0] == 1; }
            }
            TAG_LAST_SEEN => {
                if value.len() == 8 {
                    last_seen = i64::from_be_bytes(value.try_into().unwrap());
                }
            }
            _ => {}
        }
    }
    if pubkey.is_some() { flush!(); }
    Ok(members)
}
