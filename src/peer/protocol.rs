//! P2P wire protocol — read/write helpers that mirror Messages.kt exactly.
//!
//! Frame layout (all integers big-endian):
//!   [stream: i32][type: i32][size: i64]   ← 16-byte header
//!   [...type-specific payload...]
//!
//! Reading is done through `AsyncConn`'s `read(&mut buf)` method.  Because
//! each call may return fewer bytes than requested we loop internally until
//! the exact count is fulfilled — a safe pattern since all reads happen
//! inside a single dedicated task that is never select!-cancelled mid-frame.

use ygg_stream::AsyncConn;

use crate::error::MimirError;

// ── Message type constants ────────────────────────────────────────────────────

pub const MSG_TYPE_HELLO: i32            = 1;
pub const MSG_TYPE_CHALLENGE: i32        = 2;
pub const MSG_TYPE_CHALLENGE_ANSWER: i32 = 3;
pub const MSG_TYPE_CHALLENGE2: i32       = 4;
pub const MSG_TYPE_CHALLENGE_ANSWER2: i32 = 5;
pub const MSG_TYPE_INFO_REQUEST: i32     = 6;
pub const MSG_TYPE_INFO_RESPONSE: i32    = 7;
pub const MSG_TYPE_PING: i32             = 8;
pub const MSG_TYPE_PONG: i32             = 9;
pub const MSG_TYPE_MESSAGE_TEXT: i32     = 1000;
pub const MSG_TYPE_CALL_OFFER: i32       = 2000;
pub const MSG_TYPE_CALL_ANSWER: i32      = 2001;
pub const MSG_TYPE_CALL_HANG: i32        = 2002;
pub const MSG_TYPE_CALL_PACKET: i32      = 2003;
pub const MSG_TYPE_OK: i32               = 32767;

pub const PROTOCOL_VERSION: i32 = 1;

/// Role byte written as the very first byte of every new stream.
/// Tells the acceptor how to handle the stream.
pub const STREAM_ROLE_CONTROL: u8 = 0x00;
pub const STREAM_ROLE_DATA:    u8 = 0x01;

/// Maximum avatar size we are willing to receive (50 KiB).
const MAX_AVATAR_SIZE: usize = 50 * 1024;

// ── Parsed frame types ────────────────────────────────────────────────────────

pub struct Header {
    pub msg_type: i32,
    /// Payload size declared in the header (informational for some types).
    pub size: i64,
}

pub struct ClientHello {
    pub pubkey:    [u8; 32],
    pub receiver:  [u8; 32],
    pub client_id: i32,
    pub address:   Option<[u8; 32]>,
}

pub struct InfoResponse {
    pub time:     i64,
    pub nickname: String,
    pub info:     String,
    pub avatar:   Option<Vec<u8>>,
}

pub struct P2pMessage {
    pub guid:      i64,
    pub reply_to:  i64,
    pub send_time: i64,
    pub edit_time: i64,
    pub msg_type:  i32,
    pub data:      Vec<u8>,
}

pub struct CallOffer {
    pub mime_type:     String,
    pub sample_rate:   i32,
    pub channel_count: i32,
}

// ── Low-level I/O helpers ─────────────────────────────────────────────────────

/// Read exactly `n` bytes from the connection, blocking until done.
pub(crate) async fn read_exact(conn: &AsyncConn, n: usize) -> Result<Vec<u8>, MimirError> {
    let mut buf = vec![0u8; n];
    let mut pos = 0;
    while pos < n {
        let read = conn.read(&mut buf[pos..]).await
            .map_err(|e| MimirError::Io(e))?;
        if read == 0 {
            return Err(MimirError::Io("connection closed unexpectedly".to_string()));
        }
        pos += read;
    }
    Ok(buf)
}

/// Read a big-endian i32.
pub(crate) async fn read_i32(conn: &AsyncConn) -> Result<i32, MimirError> {
    let b = read_exact(conn, 4).await?;
    Ok(i32::from_be_bytes(b.try_into().unwrap()))
}

/// Read a big-endian i64.
pub(crate) async fn read_i64(conn: &AsyncConn) -> Result<i64, MimirError> {
    let b = read_exact(conn, 8).await?;
    Ok(i64::from_be_bytes(b.try_into().unwrap()))
}

/// Read a length-prefixed byte blob: [len: i32][bytes].
async fn read_blob_i32(conn: &AsyncConn) -> Result<Vec<u8>, MimirError> {
    let len = read_i32(conn).await?;
    if len < 0 {
        return Err(MimirError::Protocol(format!("negative blob length: {}", len)));
    }
    read_exact(conn, len as usize).await
}

/// Discard `n` bytes from the connection (e.g., oversized avatar or unknown frame).
pub async fn discard(conn: &AsyncConn, mut n: usize) -> Result<(), MimirError> {
    let mut scratch = vec![0u8; 8192];
    while n > 0 {
        let chunk = n.min(scratch.len());
        let read = conn.read(&mut scratch[..chunk]).await
            .map_err(|e| MimirError::Io(e))?;
        if read == 0 { break; }
        n -= read;
    }
    Ok(())
}

// ── Header ────────────────────────────────────────────────────────────────────

pub async fn read_header(conn: &AsyncConn) -> Result<Header, MimirError> {
    let b = read_exact(conn, 16).await?;
    // stream (4) — we ignore it; type (4); size (8)
    let msg_type = i32::from_be_bytes(b[4..8].try_into().unwrap());
    let size = i64::from_be_bytes(b[8..16].try_into().unwrap());
    Ok(Header { msg_type, size })
}

/// Build a 16-byte frame header.  Public so connection.rs can build frames
/// for the async write channel without going through async write helpers.
pub fn build_header(msg_type: i32, size: i64) -> [u8; 16] {
    let mut h = [0u8; 16];
    // stream = 0
    h[4..8].copy_from_slice(&msg_type.to_be_bytes());
    h[8..16].copy_from_slice(&size.to_be_bytes());
    h
}

// ── Hello ─────────────────────────────────────────────────────────────────────

/// Read the Hello payload (header already consumed).
/// `has_address` = header.size > 80 (matches the Kotlin `header.size > 80` check).
pub async fn read_hello(conn: &AsyncConn, has_address: bool) -> Result<ClientHello, MimirError> {
    // version (ignored for now)
    read_i32(conn).await?;

    let pk = read_blob_i32(conn).await?;
    if pk.len() != 32 {
        return Err(MimirError::Protocol(format!("hello pubkey must be 32 bytes, got {}", pk.len())));
    }
    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&pk);

    let recv = read_blob_i32(conn).await?;
    if recv.len() != 32 {
        return Err(MimirError::Protocol("hello receiver must be 32 bytes".to_string()));
    }
    let mut receiver = [0u8; 32];
    receiver.copy_from_slice(&recv);

    let client_id = read_i32(conn).await?;

    let address = if has_address {
        let addr = read_blob_i32(conn).await?;
        if addr.len() != 32 {
            return Err(MimirError::Protocol("hello address must be 32 bytes".to_string()));
        }
        let mut a = [0u8; 32];
        a.copy_from_slice(&addr);
        Some(a)
    } else {
        None
    };

    Ok(ClientHello { pubkey, receiver, client_id, address })
}

/// Write a Hello to the connection.
pub async fn write_hello(
    conn: &AsyncConn,
    our_pubkey: &[u8; 32],
    receiver: &[u8; 32],
    client_id: i32,
) -> Result<(), MimirError> {
    // version(4) + pk_size(4) + pk(32) + recv_size(4) + recv(32) + id(4) = 80
    let payload_size: i64 = 80;
    let mut buf = Vec::with_capacity(16 + 80);
    buf.extend_from_slice(&build_header(MSG_TYPE_HELLO, payload_size));
    buf.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    buf.extend_from_slice(&32i32.to_be_bytes());
    buf.extend_from_slice(our_pubkey);
    buf.extend_from_slice(&32i32.to_be_bytes());
    buf.extend_from_slice(receiver);
    buf.extend_from_slice(&client_id.to_be_bytes());
    conn.write(&buf).await.map_err(|e| MimirError::Io(e))?;
    Ok(())
}

// ── Challenge / ChallengeAnswer ───────────────────────────────────────────────

/// Read a Challenge or Challenge2 payload (header already consumed).
pub async fn read_challenge(conn: &AsyncConn) -> Result<Vec<u8>, MimirError> {
    read_blob_i32(conn).await
}

/// Write a Challenge or Challenge2.
pub async fn write_challenge(
    conn: &AsyncConn,
    data: &[u8],
    msg_type: i32,
) -> Result<(), MimirError> {
    let payload_size = 4 + data.len() as i64;
    let mut buf = Vec::with_capacity(16 + 4 + data.len());
    buf.extend_from_slice(&build_header(msg_type, payload_size));
    buf.extend_from_slice(&(data.len() as i32).to_be_bytes());
    buf.extend_from_slice(data);
    conn.write(&buf).await.map_err(|e| MimirError::Io(e))?;
    Ok(())
}

/// Read a ChallengeAnswer or ChallengeAnswer2 (same format as Challenge).
pub async fn read_challenge_answer(conn: &AsyncConn) -> Result<Vec<u8>, MimirError> {
    read_blob_i32(conn).await
}

/// Write a ChallengeAnswer or ChallengeAnswer2.
pub async fn write_challenge_answer(
    conn: &AsyncConn,
    data: &[u8],
    msg_type: i32,
) -> Result<(), MimirError> {
    write_challenge(conn, data, msg_type).await
}

// ── OK ────────────────────────────────────────────────────────────────────────

/// Read an OK payload (header already consumed). Returns the message id.
pub async fn read_ok(conn: &AsyncConn) -> Result<i64, MimirError> {
    read_i64(conn).await
}

/// Write an OK with the given message id.
pub async fn write_ok(conn: &AsyncConn, id: i64) -> Result<(), MimirError> {
    let mut buf = [0u8; 16 + 8];
    buf[..16].copy_from_slice(&build_header(MSG_TYPE_OK, 8));
    buf[16..].copy_from_slice(&id.to_be_bytes());
    conn.write(&buf).await.map_err(|e| MimirError::Io(e))?;
    Ok(())
}

// ── Ping / Pong ───────────────────────────────────────────────────────────────

pub async fn write_ping(conn: &AsyncConn) -> Result<(), MimirError> {
    conn.write(&build_header(MSG_TYPE_PING, 0))
        .await.map_err(|e| MimirError::Io(e))?;
    Ok(())
}

pub async fn write_pong(conn: &AsyncConn) -> Result<(), MimirError> {
    conn.write(&build_header(MSG_TYPE_PONG, 0))
        .await.map_err(|e| MimirError::Io(e))?;
    Ok(())
}

// ── Info request / response ───────────────────────────────────────────────────

/// Read the INFO_REQUEST payload (header consumed). Returns `since_time`.
pub async fn read_info_request(conn: &AsyncConn) -> Result<i64, MimirError> {
    read_i64(conn).await
}

pub async fn write_info_request(conn: &AsyncConn, since_time: i64) -> Result<(), MimirError> {
    let mut buf = [0u8; 16 + 8];
    buf[..16].copy_from_slice(&build_header(MSG_TYPE_INFO_REQUEST, 8));
    buf[16..].copy_from_slice(&since_time.to_be_bytes());
    conn.write(&buf).await.map_err(|e| MimirError::Io(e))?;
    Ok(())
}

/// Read an INFO_RESPONSE payload (header consumed).
pub async fn read_info_response(conn: &AsyncConn) -> Result<InfoResponse, MimirError> {
    let time = read_i64(conn).await?;

    let nick_bytes = read_blob_i32(conn).await?;
    let nickname = String::from_utf8(nick_bytes)
        .map_err(|e| MimirError::Protocol(e.to_string()))?;

    let info_bytes = read_blob_i32(conn).await?;
    let info = String::from_utf8(info_bytes)
        .map_err(|e| MimirError::Protocol(e.to_string()))?;

    let avatar_len = read_i32(conn).await? as usize;
    let avatar = if avatar_len == 0 {
        None
    } else if avatar_len <= MAX_AVATAR_SIZE {
        Some(read_exact(conn, avatar_len).await?)
    } else {
        // Too large — discard and ignore.
        discard(conn, avatar_len).await?;
        None
    };

    Ok(InfoResponse { time, nickname, info, avatar })
}

pub async fn write_info_response(conn: &AsyncConn, r: &InfoResponse) -> Result<(), MimirError> {
    let nick = r.nickname.as_bytes();
    let inf  = r.info.as_bytes();
    let av   = r.avatar.as_deref().unwrap_or(&[]);

    let payload_len = 8                    // time
        + 4 + nick.len()
        + 4 + inf.len()
        + 4 + av.len();

    let mut buf = Vec::with_capacity(16 + payload_len);
    buf.extend_from_slice(&build_header(MSG_TYPE_INFO_RESPONSE, payload_len as i64));
    buf.extend_from_slice(&r.time.to_be_bytes());
    buf.extend_from_slice(&(nick.len() as i32).to_be_bytes());
    buf.extend_from_slice(nick);
    buf.extend_from_slice(&(inf.len() as i32).to_be_bytes());
    buf.extend_from_slice(inf);
    buf.extend_from_slice(&(av.len() as i32).to_be_bytes());
    buf.extend_from_slice(av);
    conn.write(&buf).await.map_err(|e| MimirError::Io(e))?;
    Ok(())
}

// ── Text/file message ─────────────────────────────────────────────────────────

/// Read a MSG_TYPE_MESSAGE_TEXT payload (header consumed).
///
/// The JSON header carries `payloadSize`; we read exactly that many bytes as
/// the opaque payload and hand them back to the caller.  For file messages
/// (type 1 or 3) the payload is [metaJsonSize(4)][metaJson][fileBytes].
pub async fn read_message(conn: &AsyncConn) -> Result<P2pMessage, MimirError> {
    let json_bytes = read_blob_i32(conn).await?;

    let json: serde_json::Value = serde_json::from_slice(&json_bytes)
        .map_err(|e| MimirError::Protocol(format!("bad message JSON: {}", e)))?;

    let guid      = json["guid"]       .as_i64().unwrap_or(0);
    let reply_to  = json["replyTo"]    .as_i64().unwrap_or(0);
    let send_time = json["sendTime"]   .as_i64().unwrap_or(0);
    let edit_time = json["editTime"]   .as_i64().unwrap_or(0);
    let msg_type  = json["type"]       .as_i64().unwrap_or(0) as i32;
    let payload_size = json["payloadSize"].as_i64().unwrap_or(0) as usize;

    let data = if payload_size > 0 {
        read_exact(conn, payload_size).await?
    } else {
        vec![]
    };

    Ok(P2pMessage { guid, reply_to, send_time, edit_time, msg_type, data })
}

/// Write a message to the connection.
///
/// Callers are responsible for pre-assembling `data`:
///   - text (type 0, 2): raw content bytes
///   - file/image (type 1, 3): [metaJsonSize(4 BE)][metaJson][fileBytes]
///
/// The JSON envelope is built here; `payloadSize` is set to `data.len()`.
pub async fn write_message(conn: &AsyncConn, msg: &P2pMessage) -> Result<(), MimirError> {
    let mut json = serde_json::json!({
        "guid":     msg.guid,
        "sendTime": msg.send_time,
        "type":     msg.msg_type,
    });
    if msg.reply_to != 0 {
        json["replyTo"] = serde_json::json!(msg.reply_to);
    }
    if msg.edit_time != 0 {
        json["editTime"] = serde_json::json!(msg.edit_time);
    }
    if !msg.data.is_empty() {
        json["payloadSize"] = serde_json::json!(msg.data.len());
    }

    let json_bytes = json.to_string().into_bytes();
    // Header size field is not used by receiver for this message type,
    // but we set it to the total payload byte count for consistency.
    let payload_len = 4 + json_bytes.len() + msg.data.len();

    let mut buf = Vec::with_capacity(16 + payload_len);
    buf.extend_from_slice(&build_header(MSG_TYPE_MESSAGE_TEXT, payload_len as i64));
    buf.extend_from_slice(&(json_bytes.len() as i32).to_be_bytes());
    buf.extend_from_slice(&json_bytes);
    buf.extend_from_slice(&msg.data);
    conn.write(&buf).await.map_err(|e| MimirError::Io(e))?;
    Ok(())
}

// ── Call messages ─────────────────────────────────────────────────────────────

pub async fn read_call_offer(conn: &AsyncConn) -> Result<CallOffer, MimirError> {
    let mime_bytes = read_blob_i32(conn).await?;
    let mime_type = String::from_utf8(mime_bytes)
        .map_err(|e| MimirError::Protocol(e.to_string()))?;
    let sample_rate   = read_i32(conn).await?;
    let channel_count = read_i32(conn).await?;
    Ok(CallOffer { mime_type, sample_rate, channel_count })
}

pub async fn write_call_offer(conn: &AsyncConn, offer: &CallOffer) -> Result<(), MimirError> {
    let mime = offer.mime_type.as_bytes();
    let payload_len = 4 + mime.len() + 4 + 4;
    let mut buf = Vec::with_capacity(16 + payload_len);
    buf.extend_from_slice(&build_header(MSG_TYPE_CALL_OFFER, payload_len as i64));
    buf.extend_from_slice(&(mime.len() as i32).to_be_bytes());
    buf.extend_from_slice(mime);
    buf.extend_from_slice(&offer.sample_rate.to_be_bytes());
    buf.extend_from_slice(&offer.channel_count.to_be_bytes());
    conn.write(&buf).await.map_err(|e| MimirError::Io(e))?;
    Ok(())
}

/// Read a CALL_ANSWER payload. Returns (ok, error_string).
pub async fn read_call_answer(conn: &AsyncConn) -> Result<(bool, String), MimirError> {
    let ok_byte = read_exact(conn, 1).await?;
    let ok = ok_byte[0] != 0;
    let err_bytes = read_blob_i32(conn).await?;
    let error = String::from_utf8(err_bytes).unwrap_or_default();
    Ok((ok, error))
}

pub async fn write_call_answer(conn: &AsyncConn, ok: bool, error: &str) -> Result<(), MimirError> {
    let err_bytes = error.as_bytes();
    let payload_len = 1 + 4 + err_bytes.len();
    let mut buf = Vec::with_capacity(16 + payload_len);
    buf.extend_from_slice(&build_header(MSG_TYPE_CALL_ANSWER, payload_len as i64));
    buf.push(if ok { 1 } else { 0 });
    buf.extend_from_slice(&(err_bytes.len() as i32).to_be_bytes());
    buf.extend_from_slice(err_bytes);
    conn.write(&buf).await.map_err(|e| MimirError::Io(e))?;
    Ok(())
}

pub async fn write_call_hangup(conn: &AsyncConn) -> Result<(), MimirError> {
    conn.write(&build_header(MSG_TYPE_CALL_HANG, 0))
        .await.map_err(|e| MimirError::Io(e))?;
    Ok(())
}

/// Read a CALL_PACKET payload. Returns raw audio bytes.
pub async fn read_call_packet(conn: &AsyncConn) -> Result<Vec<u8>, MimirError> {
    read_blob_i32(conn).await
}

pub async fn write_call_packet(conn: &AsyncConn, data: &[u8]) -> Result<(), MimirError> {
    let payload_len = 4 + data.len();
    let mut buf = Vec::with_capacity(16 + payload_len);
    buf.extend_from_slice(&build_header(MSG_TYPE_CALL_PACKET, payload_len as i64));
    buf.extend_from_slice(&(data.len() as i32).to_be_bytes());
    buf.extend_from_slice(data);
    conn.write(&buf).await.map_err(|e| MimirError::Io(e))?;
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_header_encodes_type_and_size() {
        let h = build_header(MSG_TYPE_MESSAGE_TEXT, 1234i64);

        // stream field (bytes 0-3) must be zero
        assert_eq!(&h[0..4], &[0, 0, 0, 0]);

        // msg_type at bytes 4-7
        let msg_type = i32::from_be_bytes([h[4], h[5], h[6], h[7]]);
        assert_eq!(msg_type, MSG_TYPE_MESSAGE_TEXT);

        // size at bytes 8-15
        let size = i64::from_be_bytes(h[8..16].try_into().unwrap());
        assert_eq!(size, 1234i64);
    }

    #[test]
    fn build_header_zero_size() {
        let h = build_header(MSG_TYPE_PING, 0);
        let size = i64::from_be_bytes(h[8..16].try_into().unwrap());
        assert_eq!(size, 0);
    }

    #[test]
    fn build_header_all_known_types_roundtrip() {
        let types = [
            MSG_TYPE_HELLO, MSG_TYPE_CHALLENGE, MSG_TYPE_CHALLENGE_ANSWER,
            MSG_TYPE_CHALLENGE2, MSG_TYPE_CHALLENGE_ANSWER2,
            MSG_TYPE_INFO_REQUEST, MSG_TYPE_INFO_RESPONSE,
            MSG_TYPE_PING, MSG_TYPE_PONG,
            MSG_TYPE_MESSAGE_TEXT, MSG_TYPE_OK,
        ];
        for &t in &types {
            let h = build_header(t, 0);
            assert_eq!(i32::from_be_bytes([h[4], h[5], h[6], h[7]]), t);
        }
    }
}