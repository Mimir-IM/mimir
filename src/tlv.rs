//! Shared TLV (Tag-Length-Value) encoding/decoding and varint helpers.
//!
//! Used by both the mediator protocol and the tracker/resolver protocol.
//! Tag constants are protocol-specific and live in the respective modules.

use std::collections::HashMap;

use crate::MimirError;

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
/// If a tag appears more than once, only the last value is kept.
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

/// Parse all TLV fields, collecting **all** values per tag (for repeated tags
/// like `TAG_RECORD` in GET_ADDRS responses).
pub fn parse_tlvs_multi(data: &[u8]) -> Result<HashMap<u8, Vec<Vec<u8>>>, MimirError> {
    let mut map: HashMap<u8, Vec<Vec<u8>>> = HashMap::new();
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
        map.entry(tag).or_default().push(data[offset..end].to_vec());
        offset = end;
    }
    Ok(map)
}

/// Extension trait for the TLV map.
pub trait TlvExt {
    fn get_u64(&self, tag: u8) -> Result<u64, MimirError>;
    fn get_u32(&self, tag: u8) -> Result<u32, MimirError>;
    fn get_u8(&self, tag: u8) -> Result<u8, MimirError>;
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

    fn get_u8(&self, tag: u8) -> Result<u8, MimirError> {
        let b = self.get_bytes(tag)?;
        if b.len() != 1 {
            return Err(MimirError::Protocol(format!(
                "TLV 0x{tag:02x}: expected 1 byte, got {}", b.len()
            )));
        }
        Ok(b[0])
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
        for v in [128u32, 255, 300, 16_383, 16_384, 2_097_151, 268_435_455] {
            assert_eq!(varint_roundtrip(v), v, "roundtrip failed for {v}");
        }
    }

    #[test]
    fn varint_max_representable_value() {
        let mut buf = Vec::new();
        write_varint(&mut buf, 268_435_455);
        assert_eq!(buf.len(), 4);
        let (v, _) = read_varint(&buf, 0).unwrap();
        assert_eq!(v, 268_435_455);
    }

    #[test]
    fn varint_bytes_consumed() {
        let mut buf = Vec::new();
        write_varint(&mut buf, 128);
        let (val, consumed) = read_varint(&buf, 0).unwrap();
        assert_eq!(val, 128);
        assert_eq!(consumed, 2);
    }

    #[test]
    fn varint_overflow_is_error() {
        let bad = [0x80u8, 0x80, 0x80, 0x80, 0x01];
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
        write_tlv(&mut buf, 0x10, &42u64.to_be_bytes());
        write_tlv(&mut buf, 0x11, &7u64.to_be_bytes());
        write_tlv_str(&mut buf, 0x20, "test-chat");

        let map = parse_tlvs(&buf).unwrap();
        assert_eq!(map.get_u64(0x10).unwrap(), 42u64);
        assert_eq!(map.get_u64(0x11).unwrap(), 7u64);
        assert_eq!(map.get_str(0x20).unwrap(), "test-chat");
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
    fn tlv_u8_roundtrip() {
        let mut buf = Vec::new();
        write_tlv_u8(&mut buf, 0x40, 0xAB);
        let map = parse_tlvs(&buf).unwrap();
        assert_eq!(map.get_u8(0x40).unwrap(), 0xAB);
    }

    #[test]
    fn tlv_missing_tag_is_error() {
        let map = parse_tlvs(&[]).unwrap();
        assert!(map.get_u64(0x10).is_err());
    }

    #[test]
    fn tlv_opt_bytes_returns_none_for_missing_tag() {
        let map = parse_tlvs(&[]).unwrap();
        assert!(map.opt_bytes(0x99).is_none());
    }

    #[test]
    fn tlv_length_overflow_is_error() {
        let bad = [0x01u8, 100, 0xAA, 0xBB];
        assert!(parse_tlvs(&bad).is_err());
    }

    // ── parse_tlvs_multi ─────────────────────────────────────────────────────

    #[test]
    fn tlvs_multi_collects_repeated_tags() {
        let mut buf = Vec::new();
        write_tlv(&mut buf, 0x0C, b"record1");
        write_tlv(&mut buf, 0x0C, b"record2");
        write_tlv(&mut buf, 0x0B, &[3u8]); // a single-value tag

        let map = parse_tlvs_multi(&buf).unwrap();
        let records = map.get(&0x0C).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0], b"record1");
        assert_eq!(records[1], b"record2");
        assert_eq!(map.get(&0x0B).unwrap().len(), 1);
    }
}
