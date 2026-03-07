//! Mediator wire protocol — constants, TLV encoding, frame helpers.
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

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use ygg_stream::AsyncConn;

use crate::MimirError;

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

// ── Varint (protobuf-style, up to 4 bytes for u32) ───────────────────────────

/// Append a variable-length unsigned integer to `buf`.
pub fn write_varint(buf: &mut Vec<u8>, mut v: u32) {
    loop {
        if v < 0x80 {
            buf.push(v as u8);
            break;
        }
        buf.push(((v & 0x7F) | 0x80) as u8);
        v >>= 7;
    }
}

/// Decode a varint from `data[offset..]`.
/// Returns `(value, bytes_consumed)` or an error.
pub fn read_varint(data: &[u8], offset: usize) -> Result<(u32, usize), MimirError> {
    let mut result: u32 = 0;
    let mut shift = 0u32;
    let mut i = offset;
    for _ in 0..4 {
        if i >= data.len() {
            return Err(MimirError::Protocol("varint: unexpected end of data".into()));
        }
        let b = data[i] as u32;
        i += 1;
        result |= (b & 0x7F) << shift;
        if b & 0x80 == 0 {
            return Ok((result, i - offset));
        }
        shift += 7;
    }
    Err(MimirError::Protocol("varint: overflow (> 4 bytes)".into()))
}

// ── TLV encoding ──────────────────────────────────────────────────────────────

pub fn write_tlv(buf: &mut Vec<u8>, tag: u8, value: &[u8]) {
    buf.push(tag);
    write_varint(buf, value.len() as u32);
    buf.extend_from_slice(value);
}

pub fn write_tlv_u64(buf: &mut Vec<u8>, tag: u8, v: u64) {
    write_tlv(buf, tag, &v.to_be_bytes());
}

pub fn write_tlv_i64(buf: &mut Vec<u8>, tag: u8, v: i64) {
    write_tlv(buf, tag, &v.to_be_bytes());
}

pub fn write_tlv_u32(buf: &mut Vec<u8>, tag: u8, v: u32) {
    write_tlv(buf, tag, &v.to_be_bytes());
}

pub fn write_tlv_u8(buf: &mut Vec<u8>, tag: u8, v: u8) {
    write_tlv(buf, tag, &[v]);
}

pub fn write_tlv_str(buf: &mut Vec<u8>, tag: u8, s: &str) {
    write_tlv(buf, tag, s.as_bytes());
}

// ── TLV decoding ──────────────────────────────────────────────────────────────

/// Parse all TLV fields from `data` into a map of `tag -> value bytes`.
pub fn parse_tlvs(data: &[u8]) -> Result<HashMap<u8, Vec<u8>>, MimirError> {
    let mut map = HashMap::new();
    let mut offset = 0;
    while offset < data.len() {
        let tag = data[offset];
        offset += 1;
        let (len, consumed) = read_varint(data, offset)?;
        offset += consumed;
        let end = offset + len as usize;
        if end > data.len() {
            return Err(MimirError::Protocol(format!(
                "TLV tag 0x{tag:02x}: length {len} exceeds data bounds"
            )));
        }
        map.insert(tag, data[offset..end].to_vec());
        offset = end;
    }
    Ok(map)
}

/// Extension trait for the TLV map.
pub trait TlvExt {
    fn get_u64(&self, tag: u8) -> Result<u64, MimirError>;
    fn get_u32(&self, tag: u8) -> Result<u32, MimirError>;
    fn get_bytes(&self, tag: u8) -> Result<&[u8], MimirError>;
    fn get_str(&self, tag: u8) -> Result<String, MimirError>;
    fn opt_bytes(&self, tag: u8) -> Option<Vec<u8>>;
    fn opt_u64(&self, tag: u8) -> Option<u64>;
    fn get_i64(&self, tag: u8) -> Result<i64, MimirError>;
    fn opt_i64(&self, tag: u8) -> Option<i64>;
}

impl TlvExt for HashMap<u8, Vec<u8>> {
    fn get_bytes(&self, tag: u8) -> Result<&[u8], MimirError> {
        self.get(&tag).map(|v| v.as_slice()).ok_or_else(|| {
            MimirError::Protocol(format!("missing required TLV tag 0x{tag:02x}"))
        })
    }

    fn get_u64(&self, tag: u8) -> Result<u64, MimirError> {
        let b = self.get_bytes(tag)?;
        if b.len() != 8 {
            return Err(MimirError::Protocol(format!(
                "TLV 0x{tag:02x}: expected 8 bytes, got {}", b.len()
            )));
        }
        Ok(u64::from_be_bytes(b.try_into().unwrap()))
    }

    fn get_i64(&self, tag: u8) -> Result<i64, MimirError> {
        let b = self.get_bytes(tag)?;
        if b.len() != 8 {
            return Err(MimirError::Protocol(format!(
                "TLV 0x{tag:02x}: expected 8 bytes, got {}", b.len()
            )));
        }
        Ok(i64::from_be_bytes(b.try_into().unwrap()))
    }

    fn get_u32(&self, tag: u8) -> Result<u32, MimirError> {
        let b = self.get_bytes(tag)?;
        if b.len() != 4 {
            return Err(MimirError::Protocol(format!(
                "TLV 0x{tag:02x}: expected 4 bytes, got {}", b.len()
            )));
        }
        Ok(u32::from_be_bytes(b.try_into().unwrap()))
    }

    fn get_str(&self, tag: u8) -> Result<String, MimirError> {
        let b = self.get_bytes(tag)?;
        String::from_utf8(b.to_vec())
            .map_err(|e| MimirError::Protocol(format!("TLV 0x{tag:02x}: invalid UTF-8: {e}")))
    }

    fn opt_bytes(&self, tag: u8) -> Option<Vec<u8>> {
        self.get(&tag).cloned()
    }

    fn opt_u64(&self, tag: u8) -> Option<u64> {
        let b = self.get(&tag)?;
        if b.len() == 8 {
            Some(u64::from_be_bytes(b.as_slice().try_into().ok()?))
        } else {
            None
        }
    }

    fn opt_i64(&self, tag: u8) -> Option<i64> {
        let b = self.get(&tag)?;
        if b.len() == 8 {
            Some(i64::from_be_bytes(b.as_slice().try_into().ok()?))
        } else {
            None
        }
    }
}

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

    // ── Varint ────────────────────────────────────────────────────────────────

    fn varint_roundtrip(v: u32) -> u32 {
        let mut buf = Vec::new();
        write_varint(&mut buf, v);
        let (decoded, _) = read_varint(&buf, 0).unwrap();
        decoded
    }

    #[test]
    fn varint_single_byte_values() {
        for v in [0u32, 1, 63, 127] {
            let mut buf = Vec::new();
            write_varint(&mut buf, v);
            assert_eq!(buf.len(), 1, "value {v} should encode to 1 byte");
            assert_eq!(varint_roundtrip(v), v);
        }
    }

    #[test]
    fn varint_multi_byte_values() {
        // The implementation uses up to 4 continuation bytes → max 28-bit value.
        // Values above 268_435_455 (0x0FFF_FFFF) cannot be encoded.
        for v in [128u32, 255, 300, 16_383, 16_384, 2_097_151, 268_435_455] {
            assert_eq!(varint_roundtrip(v), v, "roundtrip failed for {v}");
        }
    }

    #[test]
    fn varint_max_representable_value() {
        // 4 varint bytes encode at most 4 × 7 = 28 bits → 268_435_455.
        let mut buf = Vec::new();
        write_varint(&mut buf, 268_435_455);
        assert_eq!(buf.len(), 4);
        let (v, _) = read_varint(&buf, 0).unwrap();
        assert_eq!(v, 268_435_455);
    }

    #[test]
    fn varint_bytes_consumed() {
        let mut buf = Vec::new();
        write_varint(&mut buf, 128); // needs 2 bytes
        let (val, consumed) = read_varint(&buf, 0).unwrap();
        assert_eq!(val, 128);
        assert_eq!(consumed, 2);
    }

    #[test]
    fn varint_overflow_is_error() {
        // A 5-byte varint (more than 4 bytes of data) must be rejected.
        let bad = [0x80u8, 0x80, 0x80, 0x80, 0x01]; // would decode >32 bits
        assert!(read_varint(&bad, 0).is_err());
    }

    #[test]
    fn varint_empty_data_is_error() {
        assert!(read_varint(&[], 0).is_err());
    }

    // ── TLV ───────────────────────────────────────────────────────────────────

    #[test]
    fn tlv_single_field_roundtrip() {
        let mut buf = Vec::new();
        write_tlv(&mut buf, 0x10, b"hello");

        let map = parse_tlvs(&buf).unwrap();
        assert_eq!(map.get(&0x10).unwrap(), b"hello");
    }

    #[test]
    fn tlv_multiple_fields_roundtrip() {
        let mut buf = Vec::new();
        write_tlv(&mut buf, TAG_CHAT_ID, &42u64.to_be_bytes());
        write_tlv(&mut buf, TAG_MESSAGE_ID, &7u64.to_be_bytes());
        write_tlv_str(&mut buf, TAG_CHAT_NAME, "test-chat");

        let map = parse_tlvs(&buf).unwrap();
        assert_eq!(map.get_u64(TAG_CHAT_ID).unwrap(), 42u64);
        assert_eq!(map.get_u64(TAG_MESSAGE_ID).unwrap(), 7u64);
        assert_eq!(map.get_str(TAG_CHAT_NAME).unwrap(), "test-chat");
    }

    #[test]
    fn tlv_u64_roundtrip() {
        let mut buf = Vec::new();
        write_tlv_u64(&mut buf, 0x20, u64::MAX);
        let map = parse_tlvs(&buf).unwrap();
        assert_eq!(map.get_u64(0x20).unwrap(), u64::MAX);
    }

    #[test]
    fn tlv_u32_roundtrip() {
        let mut buf = Vec::new();
        write_tlv_u32(&mut buf, 0x30, u32::MAX);
        let map = parse_tlvs(&buf).unwrap();
        assert_eq!(map.get_u32(0x30).unwrap(), u32::MAX);
    }

    #[test]
    fn tlv_missing_tag_is_error() {
        let buf = Vec::new();
        let map = parse_tlvs(&buf).unwrap();
        assert!(map.get_u64(TAG_CHAT_ID).is_err());
    }

    #[test]
    fn tlv_opt_bytes_returns_none_for_missing_tag() {
        let map = parse_tlvs(&[]).unwrap();
        assert!(map.opt_bytes(0x99).is_none());
    }

    #[test]
    fn tlv_length_overflow_is_error() {
        // Tag 0x01, length claims 100 bytes but only 2 are present.
        let bad = [0x01u8, 100, 0xAA, 0xBB];
        assert!(parse_tlvs(&bad).is_err());
    }

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
