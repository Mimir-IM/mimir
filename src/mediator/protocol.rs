//! Mediator wire protocol — constants, frame helpers.
//!
//! Frame layout (client → server):
//!   After the initial `[VERSION][PROTO_CLIENT]` handshake byte pair:
//!   `[cmd:1][reqId:2 BE][payloadLen:4 BE][payload]`
//!
//! Frame layout (server → client):
//!   `[status:1][reqId:2 BE][payloadLen:4 BE][payload]`
//!
//! Push messages are regular server frames with `status=OK` and a special
//! `reqId` value that matches one of the PUSH_* constants below.

use std::sync::atomic::{AtomicU64, Ordering};

use ygg_stream::AsyncConn;

use crate::MimirError;

// Re-export shared TLV encode/decode so existing `use crate::mediator::protocol::*` works.
pub use crate::tlv::*;

// ── Protocol constants ────────────────────────────────────────────────────────

pub const VERSION:      u8 = 0x01;
pub const PROTO_CLIENT: u8 = 0x00;

pub const STATUS_OK:   u8 = 0x00;
pub const STATUS_ERR:  u8 = 0x01;
pub const STATUS_PUSH: u8 = 0x02;

// ── Command codes (client → server) ──────────────────────────────────────────

pub const CMD_GET_NONCE:            u8 = 0x01;
pub const CMD_AUTH:                 u8 = 0x02;
pub const CMD_PING:                 u8 = 0x03;

pub const CMD_CREATE_CHAT:          u8 = 0x10;
pub const CMD_DELETE_CHAT:          u8 = 0x11;
pub const CMD_UPDATE_CHAT_INFO:     u8 = 0x12;

pub const CMD_ADD_USER:             u8 = 0x20;
pub const CMD_DELETE_USER:          u8 = 0x21;
pub const CMD_LEAVE_CHAT:           u8 = 0x22;
pub const CMD_GET_USER_CHATS:       u8 = 0x23;

pub const CMD_SEND_MESSAGE:         u8 = 0x30;
pub const CMD_DELETE_MESSAGE:       u8 = 0x31;
pub const CMD_GET_LAST_MESSAGE_ID:  u8 = 0x33;
pub const CMD_SUBSCRIBE:            u8 = 0x35;
pub const CMD_GET_MESSAGES_SINCE:   u8 = 0x36;

pub const CMD_SEND_INVITE:          u8 = 0x40;
pub const CMD_INVITE_RESPONSE:      u8 = 0x42;

pub const CMD_UPDATE_MEMBER_INFO:   u8 = 0x50;
pub const CMD_GET_MEMBERS_INFO:     u8 = 0x52;
pub const CMD_GET_MEMBERS:          u8 = 0x53;
pub const CMD_CHANGE_MEMBER_STATUS: u8 = 0x55;

// ── Push "command" IDs (appear in reqId field of server-initiated frames) ─────

/// Server push: new group message.
pub const PUSH_GOT_MESSAGE:          u16 = 0x0032;
/// Server push: new invite.
pub const PUSH_GOT_INVITE:           u16 = 0x0041;
/// Server push: mediator requests our member-info for a chat.
pub const PUSH_REQUEST_MEMBER_INFO:  u16 = 0x0051;
/// Server push: another member's info was updated.
pub const PUSH_GOT_MEMBER_INFO:      u16 = 0x0054;

// ── System event codes (body[0] of system messages) ──────────────────────────

pub const SYS_USER_ADDED:       u8 = 0x01;
pub const SYS_USER_ENTERED:     u8 = 0x02; // reserved
pub const SYS_USER_LEFT:        u8 = 0x03;
pub const SYS_USER_BANNED:      u8 = 0x04;
pub const SYS_CHAT_DELETED:     u8 = 0x05;
pub const SYS_CHAT_INFO_CHANGE: u8 = 0x06;
pub const SYS_PERMS_CHANGED:    u8 = 0x07;
pub const SYS_MESSAGE_DELETED:  u8 = 0x08;
pub const SYS_MEMBER_ONLINE:    u8 = 0x09;

// ── TLV tag constants ─────────────────────────────────────────────────────────

pub const TAG_PUBKEY:      u8 = 0x01;
pub const TAG_SIGNATURE:   u8 = 0x02;
pub const TAG_NONCE:       u8 = 0x03;
pub const TAG_COUNTER:     u8 = 0x04;

pub const TAG_CHAT_ID:     u8 = 0x10;
pub const TAG_MESSAGE_ID:  u8 = 0x11;
pub const TAG_MESSAGE_GUID:u8 = 0x12;
pub const TAG_INVITE_ID:   u8 = 0x13;
pub const TAG_SINCE_ID:    u8 = 0x14;
pub const TAG_USER_PUBKEY: u8 = 0x15;

pub const TAG_CHAT_NAME:   u8 = 0x20;
pub const TAG_CHAT_DESC:   u8 = 0x21;
pub const TAG_CHAT_AVATAR: u8 = 0x22;
pub const TAG_MESSAGE_BLOB:u8 = 0x23;
pub const TAG_MEMBER_INFO: u8 = 0x24;
pub const TAG_INVITE_DATA: u8 = 0x25;

pub const TAG_LIMIT:       u8 = 0x30;
pub const TAG_COUNT:       u8 = 0x31;
pub const TAG_TIMESTAMP:   u8 = 0x32;
pub const TAG_PERMS:       u8 = 0x33;
pub const TAG_ONLINE:      u8 = 0x34;
pub const TAG_ACCEPTED:    u8 = 0x35;
pub const TAG_LAST_UPDATE: u8 = 0x36;
pub const TAG_LAST_SEEN:   u8 = 0x37;

// ── Files server TLV tags ───────────────────────────────────────────────────
pub const TAG_FILE_HASH:  u8 = 0x40;
pub const TAG_OFFSET:     u8 = 0x41;
pub const TAG_TOTAL_SIZE: u8 = 0x42;
pub const TAG_CHUNK_DATA: u8 = 0x43;

// ── Files server command codes ──────────────────────────────────────────────
pub const CMD_FILE_UPLOAD:   u8 = 0x10;
pub const CMD_FILE_DOWNLOAD: u8 = 0x11;
pub const CMD_FILE_INFO:     u8 = 0x12;

// ── Frame building ────────────────────────────────────────────────────────────

/// Build a client-request frame: `[cmd:1][reqId:2 BE][payloadLen:4 BE][payload]`.
pub fn build_request_frame(cmd: u8, req_id: u16, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(7 + payload.len());
    frame.push(cmd);
    frame.extend_from_slice(&req_id.to_be_bytes());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// Build just the 7-byte request header without copying the payload.
///
/// Use together with a separate `conn.write(payload)` under the same write
/// mutex to avoid allocating a full copy of large payloads.
pub fn build_request_header(cmd: u8, req_id: u16, payload_len: usize) -> [u8; 7] {
    let mut h = [0u8; 7];
    h[0] = cmd;
    h[1..3].copy_from_slice(&req_id.to_be_bytes());
    h[3..7].copy_from_slice(&(payload_len as u32).to_be_bytes());
    h
}

// ── Frame reading (async) ─────────────────────────────────────────────────────

pub struct Response {
    pub status:  u8,
    pub req_id:  u16,
    pub payload: Vec<u8>,
}

impl Response {
    /// Extract the error string from a STATUS_ERR payload (`[len:2 BE][utf8...]`).
    pub fn error_string(&self) -> String {
        if self.status != STATUS_ERR || self.payload.len() < 2 {
            return String::new();
        }
        let len = u16::from_be_bytes([self.payload[0], self.payload[1]]) as usize;
        if self.payload.len() < 2 + len {
            return String::new();
        }
        String::from_utf8_lossy(&self.payload[2..2 + len]).into_owned()
    }

    pub fn into_error(self, prefix: &str) -> MimirError {
        MimirError::Protocol(format!("{prefix}: {}", self.error_string()))
    }
}

/// Read exactly `buf.len()` bytes from `conn`, looping over partial reads.
/// Updates `activity` with the current timestamp after every successful read
/// so the caller's ping loop sees the connection as alive during large reads.
async fn read_exact(conn: &AsyncConn, buf: &mut [u8], activity: &AtomicU64) -> Result<(), MimirError> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = conn.read(&mut buf[filled..]).await
            .map_err(|e| MimirError::Io(e))?;
        if n == 0 {
            return Err(MimirError::Io("connection closed (EOF)".into()));
        }
        filled += n;
        activity.store(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            Ordering::Relaxed,
        );
    }
    Ok(())
}

/// Read one response frame from the connection.
/// Returns an error on I/O failure or if the payload is unreasonably large.
/// `activity` is updated after every partial read so the ping loop does not
/// fire while a large response payload is being received.
pub async fn read_response(conn: &AsyncConn, activity: &AtomicU64) -> Result<Response, MimirError> {
    // header: [status:1][reqId:2][payloadLen:4]
    let mut hdr = [0u8; 7];
    read_exact(conn, &mut hdr, activity).await?;

    let status  = hdr[0];
    let req_id  = u16::from_be_bytes([hdr[1], hdr[2]]);
    let pay_len = u32::from_be_bytes([hdr[3], hdr[4], hdr[5], hdr[6]]) as usize;

    const MAX_PAYLOAD: usize = 50 * 1024 * 1024; // 50 MB
    if pay_len > MAX_PAYLOAD {
        return Err(MimirError::Protocol(format!(
            "payload length {pay_len} exceeds limit"
        )));
    }

    let mut payload = vec![0u8; pay_len];
    if pay_len > 0 {
        read_exact(conn, &mut payload, activity).await?;
    }

    Ok(Response { status, req_id, payload })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── build_request_frame ───────────────────────────────────────────────────

    #[test]
    fn build_request_frame_layout() {
        let payload = b"payload";
        let frame = build_request_frame(CMD_PING, 0x0042, payload);

        assert_eq!(frame[0], CMD_PING);
        assert_eq!(u16::from_be_bytes([frame[1], frame[2]]), 0x0042u16);
        assert_eq!(
            u32::from_be_bytes([frame[3], frame[4], frame[5], frame[6]]),
            payload.len() as u32
        );
        assert_eq!(&frame[7..], payload);
    }

    #[test]
    fn build_request_frame_empty_payload() {
        let frame = build_request_frame(CMD_AUTH, 1, &[]);
        assert_eq!(frame.len(), 7);
        assert_eq!(u32::from_be_bytes([frame[3], frame[4], frame[5], frame[6]]), 0);
    }

    // ── Response::error_string ────────────────────────────────────────────────

    #[test]
    fn error_string_from_ok_status_is_empty() {
        let r = Response { status: STATUS_OK, req_id: 1, payload: b"anything".to_vec() };
        assert_eq!(r.error_string(), "");
    }

    #[test]
    fn error_string_short_payload_is_empty() {
        let r = Response { status: STATUS_ERR, req_id: 1, payload: vec![0] };
        assert_eq!(r.error_string(), "");
    }

    #[test]
    fn error_string_parses_correctly() {
        let msg = b"chat not found";
        let mut payload = Vec::new();
        payload.extend_from_slice(&(msg.len() as u16).to_be_bytes());
        payload.extend_from_slice(msg);

        let r = Response { status: STATUS_ERR, req_id: 2, payload };
        assert_eq!(r.error_string(), "chat not found");
    }
}
