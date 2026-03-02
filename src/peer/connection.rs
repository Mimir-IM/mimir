//! Per-peer async connection handler.
//!
//! Each P2P connection (inbound or outbound) is driven by a single tokio task
//! spawned from PeerManager.  The task:
//!   1. Runs the mutual-auth handshake (linear, no select! during auth).
//!   2. Registers an outgoing-command channel in the shared peers map.
//!   3. Enters the message loop: reader sub-task + writer sub-task +
//!      control loop that select!s between incoming frames, outgoing
//!      commands, and the keep-alive ping timer.
//!
//! # Keep-alive
//!   - Pings are sent every 60 s (or every 2 s during an active call).
//!   - If no pong arrives within 7 s of sending a ping the connection is
//!     declared dead and closed.
//!   - If no meaningful activity occurs for 10 minutes the connection is
//!     also closed.

use std::sync::Arc;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use rand::RngCore;
use tokio::sync::mpsc;
use ygg_stream::AsyncConn;

use crate::{
    CallStatus, ContactInfo, InfoProvider, MimirError, PeerEventListener,
};
use super::protocol::*;

// ── Timeouts / intervals ──────────────────────────────────────────────────────

const AUTH_TIMEOUT: Duration = Duration::from_secs(15);
const PING_INTERVAL: Duration = Duration::from_secs(50);
const CALL_PING_INTERVAL: Duration = Duration::from_millis(2000);
const PING_TIMEOUT: Duration = Duration::from_secs(7);
const IDLE_TIMEOUT: Duration = Duration::from_secs(600);      // 10 min — no call in progress
const CALL_IDLE_TIMEOUT: Duration = Duration::from_millis(3500); // InCall only: audio must flow
const CALL_WAIT_TIMEOUT: Duration = Duration::from_secs(60);  // Calling/Receiving: wait for answer

// ── Commands sent from PeerNode into a connection task ────────────────────────

pub enum OutgoingCmd {
    Message {
        guid: i64,
        reply_to: i64,
        send_time: i64,
        edit_time: i64,
        msg_type: i32,
        data: Vec<u8>,
    },
    StartCall,
    AnswerCall(bool),
    HangupCall,
    CallPacket(Vec<u8>),
    Disconnect,
    /// Sent by register_peer when a newer connection replaces this one.
    /// Causes the loop to exit cleanly WITHOUT firing the HANGUP callback,
    /// so the Android side can retry the call on the new connection.
    Replaced,
}

// ── Shared state passed into connection tasks ─────────────────────────────────

pub struct ConnContext {
    pub signing_key: Arc<SigningKey>,
    pub our_pubkey: [u8; 32],
    pub client_id: i32,
    pub event_cb: Arc<dyn PeerEventListener>,
    pub info_cb: Arc<dyn InfoProvider>,
}

// ── Entry points ──────────────────────────────────────────────────────────────

/// Drive an **inbound** connection to completion.
/// Returns the peer's pubkey and an outgoing-command sender on success.
pub async fn run_inbound(conn: Arc<AsyncConn>, ctx: Arc<ConnContext>) -> Option<([u8; 32], mpsc::UnboundedSender<OutgoingCmd>)> {
    let auth_result = tokio::time::timeout(
        AUTH_TIMEOUT,
        auth_inbound(&conn, &ctx),
    )
        .await;

    match auth_result {
        Ok(Ok(peer_key)) => {
            let (tx, rx) = mpsc::unbounded_channel();
            tokio::spawn(message_loop(conn, peer_key, rx, ctx));
            Some((peer_key, tx))
        }
        Ok(Err(e)) => {
            log::warn!("Inbound auth failed: {}", e);
            None
        }
        Err(_) => {
            log::warn!("Inbound auth timed out");
            None
        }
    }
}

/// Drive an **outbound** connection to completion.
/// Returns the outgoing-command sender on success.
pub async fn run_outbound(conn: Arc<AsyncConn>, peer_key: [u8; 32], ctx: Arc<ConnContext>) -> Option<mpsc::UnboundedSender<OutgoingCmd>> {
    let auth_result = tokio::time::timeout(
        AUTH_TIMEOUT,
        auth_outbound(&conn, &ctx, &peer_key),
    )
        .await;

    match auth_result {
        Ok(Ok(())) => {
            let (tx, rx) = mpsc::unbounded_channel();
            tokio::spawn(message_loop(conn, peer_key, rx, ctx));
            Some(tx)
        }
        Ok(Err(e)) => {
            log::warn!("Outbound auth to {} failed: {}", hex::encode(peer_key), e);
            None
        }
        Err(_) => {
            log::warn!("Outbound auth to {} timed out", hex::encode(peer_key));
            None
        }
    }
}

// ── Auth handshakes ───────────────────────────────────────────────────────────

/// Inbound mutual auth handshake.  Returns the peer's public key.
///
/// Flow (inbound perspective):
///   recv Hello  → send Challenge  → recv ChallengeAnswer → verify → send OK
///   recv Challenge2 → sign → send ChallengeAnswer2 → recv OK
async fn auth_inbound(conn: &AsyncConn, ctx: &ConnContext) -> Result<[u8; 32], MimirError> {
    // Step 1: receive Hello
    let header = read_header(conn).await?;
    if header.msg_type != MSG_TYPE_HELLO {
        return Err(MimirError::Auth(format!(
            "expected HELLO (1), got {}", header.msg_type
        )));
    }
    let hello = read_hello(conn, header.size > 80).await?;

    if hello.receiver != ctx.our_pubkey {
        return Err(MimirError::Auth("Hello is not addressed to us".to_string()));
    }

    // Step 2: challenge the client
    let challenge = random_bytes(32);
    write_challenge(conn, &challenge, MSG_TYPE_CHALLENGE).await?;

    // Step 3: receive and verify client's answer
    let header = read_header(conn).await?;
    if header.msg_type != MSG_TYPE_CHALLENGE_ANSWER {
        return Err(MimirError::Auth(format!(
            "expected CHALLENGE_ANSWER (3), got {}", header.msg_type
        )));
    }
    let answer = read_challenge_answer(conn).await?;
    crate::crypto::verify(&hello.pubkey, &challenge, &answer)?;

    // Step 4: send OK — client is authenticated
    write_ok(conn, 0).await?;

    // Step 5: receive Challenge2 from client (they now authenticate us)
    let header = read_header(conn).await?;
    if header.msg_type != MSG_TYPE_CHALLENGE2 {
        return Err(MimirError::Auth(format!(
            "expected CHALLENGE2 (4), got {}", header.msg_type
        )));
    }
    let challenge2 = read_challenge(conn).await?;

    // Step 6: sign and send our answer
    let answer2 = crate::crypto::sign(&ctx.signing_key, &challenge2);
    write_challenge_answer(conn, &answer2, MSG_TYPE_CHALLENGE_ANSWER2).await?;

    // Step 7: receive final OK from client
    let header = read_header(conn).await?;
    if header.msg_type != MSG_TYPE_OK {
        return Err(MimirError::Auth(format!(
            "expected OK (32767), got {}", header.msg_type
        )));
    }
    read_ok(conn).await?; // consume the id field

    Ok(hello.pubkey)
}

/// Outbound mutual auth handshake.
///
/// Flow (outbound perspective):
///   send Hello → recv Challenge → sign → send ChallengeAnswer → recv OK
///   send Challenge2 → recv ChallengeAnswer2 → verify → send OK
async fn auth_outbound(conn: &AsyncConn, ctx: &ConnContext, peer_key: &[u8; 32]) -> Result<(), MimirError> {
    // Step 1: send Hello
    write_hello(conn, &ctx.our_pubkey, peer_key, ctx.client_id).await?;

    // Step 2: receive Challenge from server
    let header = read_header(conn).await?;
    if header.msg_type != MSG_TYPE_CHALLENGE {
        return Err(MimirError::Auth(format!(
            "expected CHALLENGE (2), got {}", header.msg_type
        )));
    }
    let challenge = read_challenge(conn).await?;

    // Step 3: sign and send our answer
    let answer = crate::crypto::sign(&ctx.signing_key, &challenge);
    write_challenge_answer(conn, &answer, MSG_TYPE_CHALLENGE_ANSWER).await?;

    // Step 4: receive OK — server accepted us
    let header = read_header(conn).await?;
    if header.msg_type != MSG_TYPE_OK {
        return Err(MimirError::Auth(format!(
            "expected OK (32767), got {}", header.msg_type
        )));
    }
    read_ok(conn).await?; // consume the id field

    // Step 5: send Challenge2 to authenticate the server
    let challenge2 = random_bytes(32);
    write_challenge(conn, &challenge2, MSG_TYPE_CHALLENGE2).await?;

    // Step 6: receive server's ChallengeAnswer2
    let header = read_header(conn).await?;
    if header.msg_type != MSG_TYPE_CHALLENGE_ANSWER2 {
        return Err(MimirError::Auth(format!(
            "expected CHALLENGE_ANSWER2 (5), got {}", header.msg_type
        )));
    }
    let answer2 = read_challenge_answer(conn).await?;
    crate::crypto::verify(peer_key, &challenge2, &answer2)?;

    // Step 7: send final OK — server is authenticated
    write_ok(conn, 0).await?;

    Ok(())
}

// ── Message loop ──────────────────────────────────────────────────────────────

/// Post-auth message loop.  Runs until the connection dies or is explicitly
/// closed.
async fn message_loop(conn: Arc<AsyncConn>, peer_key: [u8; 32], mut cmd_rx: mpsc::UnboundedReceiver<OutgoingCmd>, ctx: Arc<ConnContext>) {
    let address = hex::encode(peer_key);
    ctx.event_cb.on_peer_connected(peer_key.to_vec(), address.clone());

    // Request peer's contact info once, right after auth.
    let since = ctx.info_cb.get_contact_update_time(peer_key.to_vec());
    let _ = write_info_request(&conn, since as i64).await;

    // The reader sub-task owns a clone of conn for reading.
    let (frame_tx, mut frame_rx) = mpsc::unbounded_channel::<IncomingFrame>();
    let (write_tx, write_rx) = mpsc::unbounded_channel::<Vec<u8>>();

    let read_conn = Arc::clone(&conn);
    let write_conn = Arc::clone(&conn);

    tokio::spawn(reader_task(read_conn, frame_tx));
    tokio::spawn(writer_task(write_conn, write_rx));

    // Control state
    let mut call_status = CallStatus::Idle;
    let mut last_activity = Instant::now();
    let mut last_ping_sent: Option<Instant> = None;
    let mut last_pong: Instant = Instant::now();
    let mut ping_interval = tokio::time::interval(PING_INTERVAL);
    ping_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let _ = ping_interval.tick().await; // consume the immediate first tick

    let mut dead_peer = false;

    'main: loop {
        // Dynamic ping interval and idle timeout based on call state.
        //
        // InCall:           3.5 s  — audio packets must flow (last_pong OR last_activity)
        // Calling/Receiving: 60 s  — waiting for answer; only pong counts (no audio yet)
        // No call:          10 min — normal keep-alive via last_activity
        //
        // Note: PING_TIMEOUT (7 s after unanswered ping) catches truly dead connections
        // well before CALL_WAIT_TIMEOUT fires, so 60 s is just a safety net.
        let is_in_call = matches!(call_status, CallStatus::Calling | CallStatus::InCall | CallStatus::Receiving);
        let (idle_timeout, last_act) = match call_status {
            CallStatus::InCall => (CALL_IDLE_TIMEOUT, last_pong.max(last_activity)),
            CallStatus::Calling | CallStatus::Receiving => (CALL_WAIT_TIMEOUT, last_pong),
            _ => (IDLE_TIMEOUT, last_activity),
        };
        let ping_deadline = if is_in_call { CALL_PING_INTERVAL } else { PING_INTERVAL };

        // Check timeouts before blocking
        let now = Instant::now();
        if now.duration_since(last_act) >= idle_timeout {
            log::info!("Peer {} idle timeout", &address);
            dead_peer = true;
            break 'main;
        }
        if let Some(sent) = last_ping_sent {
            if sent > last_pong && now.duration_since(sent) >= PING_TIMEOUT {
                log::warn!("Peer {} pong timeout", &address);
                dead_peer = true;
                break 'main;
            }
        }

        // Time until next ping
        let next_ping_at = last_ping_sent
            .map(|t| t + ping_deadline)
            .unwrap_or_else(|| now + ping_deadline);
        let until_ping = next_ping_at.saturating_duration_since(now);

        tokio::select! {
            // Incoming frame from the reader task
            frame = frame_rx.recv() => {
                match frame {
                    Some(f) => {
                        let is_keepalive = matches!(f, IncomingFrame::Ping | IncomingFrame::Pong);
                        if !is_keepalive {
                            last_activity = Instant::now();
                        }
                        if let Err(e) = handle_incoming(
                            f, &peer_key, &ctx, &write_tx, &mut call_status, &mut last_pong,
                        ).await {
                            log::error!("Error handling frame from {}: {}", &address, e);
                            break 'main;
                        }
                    }
                    None => {
                        // Reader task died — connection closed.
                        break 'main;
                    }
                }
            }

            // Outgoing command from PeerNode
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(OutgoingCmd::Disconnect) | None => break 'main,
                    Some(OutgoingCmd::Replaced) => {
                        // A newer connection to this peer has taken over.
                        // Exit cleanly without firing HANGUP so the Android side
                        // can retry the call on the new connection.
                        call_status = CallStatus::Idle;
                        break 'main;
                    }
                    Some(c) => {
                        if let Err(e) = handle_outgoing(
                            c, &write_tx, &mut call_status,
                            &ctx, &peer_key, &mut last_pong,
                        ).await {
                            log::error!("Error sending to {}: {}", &address, e);
                            break 'main;
                        }
                    }
                }
            }

            // Ping timer
            _ = tokio::time::sleep(until_ping) => {
                let frame = build_ping_frame();
                if write_tx.send(frame).is_err() { break 'main; }
                last_ping_sent = Some(Instant::now());
            }
        }
    }

    conn.close().await;

    // Notify call hangup if a call was in progress.
    if !matches!(call_status, CallStatus::Idle) {
        ctx.event_cb.on_call_status_changed(CallStatus::Hangup, Some(peer_key.to_vec()));
    }
    ctx.event_cb.on_peer_disconnected(peer_key.to_vec(), address, dead_peer);
}

// ── Incoming frame handling ───────────────────────────────────────────────────

/// Dispatch a fully-parsed incoming frame.
async fn handle_incoming(
    frame: IncomingFrame,
    peer_key: &[u8; 32],
    ctx: &ConnContext,
    write_tx: &mpsc::UnboundedSender<Vec<u8>>,
    call_status: &mut CallStatus,
    last_pong: &mut Instant,
) -> Result<(), MimirError> {
    match frame {
        IncomingFrame::Ping => {
            write_tx.send(build_pong_frame())
                .map_err(|_| MimirError::Io("write channel closed".to_string()))?;
        }

        IncomingFrame::Pong => {
            *last_pong = Instant::now();
        }

        IncomingFrame::Message(msg) => {
            // Acknowledge receipt.
            let ok = build_ok_frame(msg.guid);
            write_tx.send(ok)
                .map_err(|_| MimirError::Io("write channel closed".to_string()))?;

            ctx.event_cb.on_message_received(
                peer_key.to_vec(),
                msg.guid,
                msg.reply_to,
                msg.send_time,
                msg.edit_time,
                msg.msg_type,
                msg.data,
            );
        }

        IncomingFrame::Ok(id) => {
            if id != 0 {
                ctx.event_cb.on_message_delivered(peer_key.to_vec(), id);
            }
        }

        IncomingFrame::InfoRequest(since) => {
            let info = ctx.info_cb.get_my_info(since);
            if let Some(i) = info {
                let resp = InfoResponse {
                    time: i.update_time as i64,
                    nickname: i.nickname,
                    info: i.info,
                    avatar: i.avatar,
                };
                // Serialize and queue the write.
                let bytes = encode_info_response(&resp)?;
                write_tx.send(bytes)
                    .map_err(|_| MimirError::Io("write channel closed".to_string()))?;
            }
        }

        IncomingFrame::InfoResponse(r) => {
            ctx.info_cb.update_contact_info(peer_key.to_vec(), ContactInfo {
                nickname: r.nickname,
                info: r.info,
                avatar: r.avatar,
                update_time: r.time,
            });
        }

        IncomingFrame::CallOffer(_offer) => {
            if matches!(*call_status, CallStatus::Idle) {
                *call_status = CallStatus::Receiving;
                // Reset so CALL_IDLE_TIMEOUT counts from when the call arrives.
                *last_pong = Instant::now();
                ctx.event_cb.on_incoming_call(peer_key.to_vec());
            }
        }

        IncomingFrame::CallAnswer(ok, _err) => {
            if matches!(*call_status, CallStatus::Calling) {
                if ok {
                    *call_status = CallStatus::InCall;
                    ctx.event_cb.on_call_status_changed(CallStatus::InCall, Some(peer_key.to_vec()));
                } else {
                    *call_status = CallStatus::Idle;
                    ctx.event_cb.on_call_status_changed(CallStatus::Hangup, Some(peer_key.to_vec()));
                }
            }
        }

        IncomingFrame::CallHangup => {
            *call_status = CallStatus::Idle;
            ctx.event_cb.on_call_status_changed(CallStatus::Hangup, Some(peer_key.to_vec()));
        }

        IncomingFrame::CallPacket(data) => {
            ctx.event_cb.on_call_packet(peer_key.to_vec(), data);
        }

        IncomingFrame::Unknown(msg_type, size) => {
            log::debug!("Unknown message type {} ({} bytes) from {}", msg_type, size, hex::encode(peer_key));
        }
    }
    Ok(())
}

// ── Outgoing command handling ─────────────────────────────────────────────────

async fn handle_outgoing(
    cmd: OutgoingCmd,
    write_tx: &mpsc::UnboundedSender<Vec<u8>>,
    call_status: &mut CallStatus,
    ctx: &ConnContext,
    peer_key: &[u8; 32],
    last_pong: &mut Instant,
) -> Result<(), MimirError> {
    match cmd {
        OutgoingCmd::Message { guid, reply_to, send_time, edit_time, msg_type, data } => {
            let msg = P2pMessage { guid, reply_to, send_time, edit_time, msg_type, data };
            let bytes = encode_message(&msg)?;
            write_tx.send(bytes)
                .map_err(|_| MimirError::Io("write channel closed".to_string()))?;
        }

        OutgoingCmd::StartCall => {
            if matches!(*call_status, CallStatus::Idle) {
                let offer = CallOffer {
                    mime_type: "audio/aac".to_string(),
                    sample_rate: 44100,
                    channel_count: 1,
                };
                let bytes = encode_call_offer(&offer)?;
                write_tx.send(bytes)
                    .map_err(|_| MimirError::Io("write channel closed".to_string()))?;
                *call_status = CallStatus::Calling;
                // Reset so CALL_IDLE_TIMEOUT counts from when the call is initiated,
                // not from whenever the last pong happened to arrive.
                *last_pong = Instant::now();
                ctx.event_cb.on_call_status_changed(CallStatus::Calling, Some(peer_key.to_vec()));
            }
        }

        OutgoingCmd::AnswerCall(accept) => {
            if matches!(*call_status, CallStatus::Receiving) {
                let bytes = encode_call_answer(accept, "")?;
                write_tx.send(bytes)
                    .map_err(|_| MimirError::Io("write channel closed".to_string()))?;
                if accept {
                    *call_status = CallStatus::InCall;
                    // Reset so CALL_IDLE_TIMEOUT counts from call acceptance.
                    *last_pong = Instant::now();
                    ctx.event_cb.on_call_status_changed(CallStatus::InCall, Some(peer_key.to_vec()));
                } else {
                    *call_status = CallStatus::Idle;
                    ctx.event_cb.on_call_status_changed(CallStatus::Hangup, Some(peer_key.to_vec()));
                }
            }
        }

        OutgoingCmd::HangupCall => {
            let bytes = encode_call_hangup()?;
            write_tx.send(bytes)
                .map_err(|_| MimirError::Io("write channel closed".to_string()))?;
            *call_status = CallStatus::Idle;
            ctx.event_cb.on_call_status_changed(CallStatus::Hangup, Some(peer_key.to_vec()));
        }

        OutgoingCmd::CallPacket(data) => {
            let bytes = encode_call_packet(&data)?;
            write_tx.send(bytes)
                .map_err(|_| MimirError::Io("write channel closed".to_string()))?;
        }

        OutgoingCmd::Disconnect | OutgoingCmd::Replaced => {
            // These are handled in the message_loop cmd branch before calling
            // handle_outgoing; they should never reach here.
        }
    }
    Ok(())
}

// ── Reader sub-task ───────────────────────────────────────────────────────────

/// Parsed, complete incoming frames passed from the reader task to the
/// control loop via an mpsc channel.
pub enum IncomingFrame {
    Ping,
    Pong,
    InfoRequest(i64),
    InfoResponse(InfoResponse),
    Message(P2pMessage),
    CallOffer(CallOffer),
    CallAnswer(bool, String),
    CallHangup,
    CallPacket(Vec<u8>),
    Ok(i64),
    Unknown(i32, i64),
}

/// Runs in its own tokio task.  Reads frames from the connection
/// indefinitely and forwards them to the control loop.  Exits when the
/// connection closes or the receiver is dropped.
async fn reader_task(
    conn: Arc<AsyncConn>,
    tx: mpsc::UnboundedSender<IncomingFrame>,
) {
    loop {
        let frame = match read_one_frame(&conn).await {
            Ok(f) => f,
            Err(e) => {
                log::info!("Reader task: connection closed ({})", e);
                break;
            }
        };
        if tx.send(frame).is_err() {
            break; // control loop gone
        }
    }
}

/// Read exactly one frame from the connection (header + body).
async fn read_one_frame(conn: &AsyncConn) -> Result<IncomingFrame, MimirError> {
    let header = read_header(conn).await?;
    let frame = match header.msg_type {
        MSG_TYPE_PING => IncomingFrame::Ping,
        MSG_TYPE_PONG => IncomingFrame::Pong,

        MSG_TYPE_INFO_REQUEST => {
            let since = read_info_request(conn).await?;
            IncomingFrame::InfoRequest(since)
        }

        MSG_TYPE_INFO_RESPONSE => {
            let r = read_info_response(conn).await?;
            IncomingFrame::InfoResponse(r)
        }

        MSG_TYPE_MESSAGE_TEXT => {
            let msg = read_message(conn).await?;
            IncomingFrame::Message(msg)
        }

        MSG_TYPE_OK => {
            let id = read_ok(conn).await?;
            IncomingFrame::Ok(id)
        }

        MSG_TYPE_CALL_OFFER => {
            let offer = read_call_offer(conn).await?;
            IncomingFrame::CallOffer(offer)
        }

        MSG_TYPE_CALL_ANSWER => {
            let (ok, err) = read_call_answer(conn).await?;
            IncomingFrame::CallAnswer(ok, err)
        }

        MSG_TYPE_CALL_HANG => IncomingFrame::CallHangup,

        MSG_TYPE_CALL_PACKET => {
            let data = read_call_packet(conn).await?;
            IncomingFrame::CallPacket(data)
        }

        other => {
            // Unknown type: discard the declared payload bytes.
            if header.size > 0 {
                discard(conn, header.size as usize).await?;
            }
            IncomingFrame::Unknown(other, header.size)
        }
    };
    Ok(frame)
}

// ── Writer sub-task ───────────────────────────────────────────────────────────

/// Runs in its own tokio task.  Drains the write channel and sends each
/// pre-serialized frame to the connection.  Exits when the channel closes
/// or a write fails.
async fn writer_task(conn: Arc<AsyncConn>, mut rx: mpsc::UnboundedReceiver<Vec<u8>>) {
    while let Some(bytes) = rx.recv().await {
        if let Err(e) = conn.write(&bytes).await {
            log::info!("Writer task: write failed ({})", e);
            break;
        }
    }
}

// ── Pre-serialisation helpers (avoid async for encode-only paths) ─────────────

fn build_ping_frame() -> Vec<u8> {
    build_header(MSG_TYPE_PING, 0).to_vec()
}

fn build_pong_frame() -> Vec<u8> {
    build_header(MSG_TYPE_PONG, 0).to_vec()
}

fn build_ok_frame(id: i64) -> Vec<u8> {
    let mut buf = vec![0u8; 24];
    buf[..16].copy_from_slice(&build_header(MSG_TYPE_OK, 8));
    buf[16..].copy_from_slice(&id.to_be_bytes());
    buf
}

fn encode_info_response(r: &InfoResponse) -> Result<Vec<u8>, MimirError> {
    let nick = r.nickname.as_bytes();
    let inf = r.info.as_bytes();
    let av = r.avatar.as_deref().unwrap_or(&[]);
    let payload_len = 8 + 4 + nick.len() + 4 + inf.len() + 4 + av.len();

    let mut buf = Vec::with_capacity(16 + payload_len);
    buf.extend_from_slice(&build_header(MSG_TYPE_INFO_RESPONSE, payload_len as i64));
    buf.extend_from_slice(&r.time.to_be_bytes());
    buf.extend_from_slice(&(nick.len() as i32).to_be_bytes());
    buf.extend_from_slice(nick);
    buf.extend_from_slice(&(inf.len() as i32).to_be_bytes());
    buf.extend_from_slice(inf);
    buf.extend_from_slice(&(av.len() as i32).to_be_bytes());
    buf.extend_from_slice(av);
    Ok(buf)
}

fn encode_message(msg: &P2pMessage) -> Result<Vec<u8>, MimirError> {
    let mut json = serde_json::json!({
        "guid":     msg.guid,
        "sendTime": msg.send_time,
        "type":     msg.msg_type,
    });
    if msg.reply_to != 0 { json["replyTo"] = serde_json::json!(msg.reply_to); }
    if msg.edit_time != 0 { json["editTime"] = serde_json::json!(msg.edit_time); }
    if !msg.data.is_empty() { json["payloadSize"] = serde_json::json!(msg.data.len()); }

    let json_bytes = json.to_string().into_bytes();
    let payload_len = 4 + json_bytes.len() + msg.data.len();

    let mut buf = Vec::with_capacity(16 + payload_len);
    buf.extend_from_slice(&build_header(MSG_TYPE_MESSAGE_TEXT, payload_len as i64));
    buf.extend_from_slice(&(json_bytes.len() as i32).to_be_bytes());
    buf.extend_from_slice(&json_bytes);
    buf.extend_from_slice(&msg.data);
    Ok(buf)
}

fn encode_call_offer(offer: &CallOffer) -> Result<Vec<u8>, MimirError> {
    let mime = offer.mime_type.as_bytes();
    let payload_len = 4 + mime.len() + 4 + 4;
    let mut buf = Vec::with_capacity(16 + payload_len);
    buf.extend_from_slice(&build_header(MSG_TYPE_CALL_OFFER, payload_len as i64));
    buf.extend_from_slice(&(mime.len() as i32).to_be_bytes());
    buf.extend_from_slice(mime);
    buf.extend_from_slice(&offer.sample_rate.to_be_bytes());
    buf.extend_from_slice(&offer.channel_count.to_be_bytes());
    Ok(buf)
}

fn encode_call_answer(ok: bool, error: &str) -> Result<Vec<u8>, MimirError> {
    let err_bytes = error.as_bytes();
    let payload_len = 1 + 4 + err_bytes.len();
    let mut buf = Vec::with_capacity(16 + payload_len);
    buf.extend_from_slice(&build_header(MSG_TYPE_CALL_ANSWER, payload_len as i64));
    buf.push(if ok { 1 } else { 0 });
    buf.extend_from_slice(&(err_bytes.len() as i32).to_be_bytes());
    buf.extend_from_slice(err_bytes);
    Ok(buf)
}

fn encode_call_hangup() -> Result<Vec<u8>, MimirError> {
    Ok(build_header(MSG_TYPE_CALL_HANG, 0).to_vec())
}

fn encode_call_packet(data: &[u8]) -> Result<Vec<u8>, MimirError> {
    let payload_len = 4 + data.len();
    let mut buf = Vec::with_capacity(16 + payload_len);
    buf.extend_from_slice(&build_header(MSG_TYPE_CALL_PACKET, payload_len as i64));
    buf.extend_from_slice(&(data.len() as i32).to_be_bytes());
    buf.extend_from_slice(data);
    Ok(buf)
}

// ── Misc helpers ──────────────────────────────────────────────────────────────

fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}
