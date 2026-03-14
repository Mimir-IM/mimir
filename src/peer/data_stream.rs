//! Persistent data stream for large file/image transfers.
//!
//! Each peer pair has one data stream per direction:
//!   - A *send* data stream opened by this peer to the remote (writes file frames)
//!   - A *recv* data stream opened by the remote to us  (reads file frames, fires callbacks)
//!
//! Wire format — one frame per file, back-to-back on the stream:
//!   [guid      : i64]
//!   [reply_to  : i64]
//!   [send_time : i64]
//!   [edit_time : i64]
//!   [msg_type  : i32]
//!   [data_size : i64]   ← byte count of the `data` blob
//!   [data      : bytes] ← [metaJsonSize(4 BE)][metaJson][fileBytes]
//!
//! For FILE_RESPONSE frames, file bytes are streamed directly to a temp file
//! on disk to avoid holding the entire file in memory.  The Kotlin/Swift layer
//! receives a file path via `on_file_received` instead of raw bytes.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use ygg_stream::AsyncConn;

use crate::{InfoProvider, PeerEventListener};
use super::protocol::{build_header, read_exact, read_i32, read_i64, MSG_TYPE_OK, MSG_TYPE_FILE_RESPONSE};

/// Encode a single file transfer frame for the persistent data stream.
pub fn encode_data_frame(
    guid: i64,
    reply_to: i64,
    send_time: i64,
    edit_time: i64,
    msg_type: i32,
    data: &[u8],
) -> Vec<u8> {
    // 8+8+8+8+4+8 = 44 bytes header
    let mut buf = Vec::with_capacity(44 + data.len());
    buf.extend_from_slice(&guid.to_be_bytes());
    buf.extend_from_slice(&reply_to.to_be_bytes());
    buf.extend_from_slice(&send_time.to_be_bytes());
    buf.extend_from_slice(&edit_time.to_be_bytes());
    buf.extend_from_slice(&msg_type.to_be_bytes());
    buf.extend_from_slice(&(data.len() as i64).to_be_bytes());
    buf.extend_from_slice(data);
    buf
}

/// Runs in its own tokio task.  Reads file frames from the remote peer's
/// send-data stream indefinitely and fires callbacks for each one.
///
/// For FILE_RESPONSE frames, file bytes are streamed directly to a temp file
/// and delivered via `on_file_received`.  All other frame types are buffered
/// in memory and delivered via `on_message_received` as before.
///
/// After each successful receive it sends `MSG_TYPE_OK(guid)` back over the
/// control stream so the sender's `on_message_delivered` fires.
/// Exits when the stream closes or a read error occurs.
pub async fn data_recv_task(
    conn: Arc<AsyncConn>,
    peer_key: [u8; 32],
    event_cb: Arc<dyn PeerEventListener>,
    info_cb: Arc<dyn InfoProvider>,
    ctrl_write_txs: Arc<Mutex<HashMap<[u8; 32], mpsc::UnboundedSender<Vec<u8>>>>>,
    pending_file_sizes: Arc<Mutex<HashMap<String, i64>>>,
) {
    let address = hex::encode(peer_key);
    loop {
        // ── Read frame header ──────────────────────────────────────────────
        let guid = match read_i64(&conn).await {
            Ok(v) => v,
            Err(e) => {
                tracing::info!("Data recv from {}: stream closed ({})", &address, e);
                break;
            }
        };
        let reply_to = match read_i64(&conn).await {
            Ok(v) => v,
            Err(e) => { tracing::info!("Data recv from {}: ({})", &address, e); break; }
        };
        let send_time = match read_i64(&conn).await {
            Ok(v) => v,
            Err(e) => { tracing::info!("Data recv from {}: ({})", &address, e); break; }
        };
        let edit_time = match read_i64(&conn).await {
            Ok(v) => v,
            Err(e) => { tracing::info!("Data recv from {}: ({})", &address, e); break; }
        };
        let msg_type = match read_i32(&conn).await {
            Ok(v) => v,
            Err(e) => { tracing::info!("Data recv from {}: ({})", &address, e); break; }
        };
        let data_size = match read_i64(&conn).await {
            Ok(v) => v,
            Err(e) => { tracing::info!("Data recv from {}: ({})", &address, e); break; }
        };

        if data_size < 0 || data_size > 512 * 1024 * 1024 {
            tracing::warn!("Data recv from {}: implausible data_size {}", &address, data_size);
            break;
        }

        // ── For FILE_RESPONSE, check against declared size from original request ──
        if msg_type == MSG_TYPE_FILE_RESPONSE {
            const META_OVERHEAD: i64 = 256;
            if let Ok(map) = pending_file_sizes.lock() {
                if !map.is_empty() {
                    let max_expected = map.values().copied().max().unwrap_or(0);
                    if max_expected > 0 && data_size > max_expected + META_OVERHEAD {
                        tracing::warn!(
                            "Data recv from {}: FILE_RESPONSE size {} exceeds max expected {} + overhead, aborting stream",
                            &address, data_size, max_expected
                        );
                        break;
                    }
                }
            }
        }

        // ── FILE_RESPONSE: stream to disk ────────────────────────────────────
        if msg_type == MSG_TYPE_FILE_RESPONSE {
            let delivered = recv_file_to_disk(
                &conn, &peer_key, &address, guid, reply_to, send_time, edit_time,
                msg_type, data_size, &event_cb, &info_cb, &pending_file_sizes,
            ).await;

            match delivered {
                FileRecvResult::Ok => { /* delivered successfully */ }
                FileRecvResult::Discarded => { /* size mismatch, skip ACK */ continue; }
                FileRecvResult::StreamError => { return; }
                FileRecvResult::DiskError => { continue; }
            }
        } else {
            // ── Non-file frames: buffer in memory (small payloads) ────────────
            let total = data_size as usize;
            let mut data: Vec<u8> = Vec::with_capacity(total);

            while data.len() < total {
                let want = (total - data.len()).min(65536);
                match read_exact(&conn, want).await {
                    Ok(chunk) => {
                        data.extend_from_slice(&chunk);
                        event_cb.on_file_receive_progress(
                            peer_key.to_vec(),
                            guid,
                            data.len() as i64,
                            data_size,
                        );
                    }
                    Err(e) => {
                        tracing::info!("Data recv from {}: read error ({})", &address, e);
                        return;
                    }
                }
            }

            event_cb.on_message_received(
                peer_key.to_vec(),
                guid, reply_to, send_time, edit_time, msg_type,
                data,
            );
        }

        // ── Acknowledge receipt over the control stream ─────────────────────
        let mut ok_frame = vec![0u8; 24];
        ok_frame[..16].copy_from_slice(&build_header(MSG_TYPE_OK, 8));
        ok_frame[16..].copy_from_slice(&guid.to_be_bytes());
        if let Ok(map) = ctrl_write_txs.lock() {
            if let Some(tx) = map.get(&peer_key) {
                let _ = tx.send(ok_frame);
            } else {
                tracing::warn!("Data recv from {}: no control write channel for ACK", &address);
            }
        }
    }
}

enum FileRecvResult {
    /// File received and delivered via on_file_received.
    Ok,
    /// Size mismatch — data consumed but not delivered.
    Discarded,
    /// Network read error — caller should abort the stream.
    StreamError,
    /// Disk I/O error — data consumed, file cleaned up, but not delivered.
    DiskError,
}

/// Read a FILE_RESPONSE frame by streaming file bytes directly to a temp file.
///
/// 1. Read the meta JSON prefix (small, stays in memory).
/// 2. Stream remaining file bytes to a temp file in 64 KiB chunks.
/// 3. Validate size against pending_file_sizes.
/// 4. Call on_file_received with the file path.
async fn recv_file_to_disk(
    conn: &Arc<AsyncConn>,
    peer_key: &[u8; 32],
    address: &str,
    guid: i64,
    reply_to: i64,
    send_time: i64,
    edit_time: i64,
    msg_type: i32,
    data_size: i64,
    event_cb: &Arc<dyn PeerEventListener>,
    info_cb: &Arc<dyn InfoProvider>,
    pending_file_sizes: &Arc<Mutex<HashMap<String, i64>>>,
) -> FileRecvResult {
    // ── Read 4-byte meta JSON length prefix ──────────────────────────────
    let meta_len_bytes = match read_exact(conn, 4).await {
        ::core::result::Result::Ok(b) => b,
        Err(e) => {
            tracing::info!("Data recv from {}: meta len read error ({})", address, e);
            return FileRecvResult::StreamError;
        }
    };
    let meta_len = u32::from_be_bytes([
        meta_len_bytes[0], meta_len_bytes[1], meta_len_bytes[2], meta_len_bytes[3],
    ]) as usize;

    // ── Read meta JSON ───────────────────────────────────────────────────
    let meta_bytes = match read_exact(conn, meta_len).await {
        ::core::result::Result::Ok(b) => b,
        Err(e) => {
            tracing::info!("Data recv from {}: meta read error ({})", address, e);
            return FileRecvResult::StreamError;
        }
    };
    let meta_str = match std::str::from_utf8(&meta_bytes) {
        ::core::result::Result::Ok(s) => s.to_string(),
        Err(_) => {
            tracing::warn!("Data recv from {}: meta JSON is not valid UTF-8", address);
            // Consume remaining bytes so the stream stays in sync.
            let remaining = data_size - 4 - meta_len as i64;
            if remaining > 0 {
                let _ = consume_bytes(conn, remaining as usize).await;
            }
            return FileRecvResult::Discarded;
        }
    };

    // File bytes remaining in the stream.
    let file_size = data_size - 4 - meta_len as i64;

    // ── Validate against pending request size before writing to disk ─────
    let file_name = serde_json::from_str::<serde_json::Value>(&meta_str)
        .ok()
        .and_then(|v| v.get("name").and_then(|n| n.as_str()).map(|s| s.to_string()));

    if let Some(ref name) = file_name {
        let expected = pending_file_sizes.lock().ok()
            .and_then(|map| map.get(name).copied());
        if let Some(expected_size) = expected {
            if expected_size > 0 && file_size != expected_size {
                tracing::warn!(
                    "Data recv from {}: FILE_RESPONSE for '{}' actual size {} != declared {}, discarding",
                    address, name, file_size, expected_size
                );
                // Consume the file bytes so the stream stays in sync.
                if file_size > 0 {
                    let _ = consume_bytes(conn, file_size as usize).await;
                }
                pending_file_sizes.lock().ok().map(|mut map| map.remove(name.as_str()));
                return FileRecvResult::Discarded;
            }
        }
    }

    // ── Create temp file ─────────────────────────────────────────────────
    let files_dir = info_cb.get_files_dir();
    if let Err(e) = tokio::fs::create_dir_all(&files_dir).await {
        tracing::warn!("Data recv from {}: cannot create files dir {}: {}", address, &files_dir, e);
        // Consume bytes so the stream stays in sync.
        if file_size > 0 {
            let _ = consume_bytes(conn, file_size as usize).await;
        }
        return FileRecvResult::DiskError;
    }
    let temp_name = format!(".recv_{}.tmp", guid);
    let temp_path = format!("{}/{}", &files_dir, &temp_name);

    let mut file = match tokio::fs::File::create(&temp_path).await {
        ::core::result::Result::Ok(f) => f,
        Err(e) => {
            tracing::warn!("Data recv from {}: cannot create temp file {}: {}", address, &temp_path, e);
            if file_size > 0 {
                let _ = consume_bytes(conn, file_size as usize).await;
            }
            return FileRecvResult::DiskError;
        }
    };

    // ── Stream chunks to disk ────────────────────────────────────────────
    let mut bytes_written: i64 = 0;
    let header_size = 4 + meta_len as i64; // already consumed from data_size

    while bytes_written < file_size {
        let want = ((file_size - bytes_written) as usize).min(65536);
        match read_exact(conn, want).await {
            ::core::result::Result::Ok(chunk) => {
                if let Err(e) = file.write_all(&chunk).await {
                    tracing::warn!("Data recv from {}: disk write error: {}", address, e);
                    drop(file);
                    let _ = tokio::fs::remove_file(&temp_path).await;
                    // Consume remaining bytes to keep stream in sync.
                    let remaining = file_size - bytes_written - chunk.len() as i64;
                    if remaining > 0 {
                        let _ = consume_bytes(conn, remaining as usize).await;
                    }
                    return FileRecvResult::DiskError;
                }
                bytes_written += chunk.len() as i64;
                event_cb.on_file_receive_progress(
                    peer_key.to_vec(),
                    guid,
                    header_size + bytes_written, // total progress including meta header
                    data_size,
                );
            }
            Err(e) => {
                tracing::info!("Data recv from {}: read error ({})", address, e);
                drop(file);
                let _ = tokio::fs::remove_file(&temp_path).await;
                return FileRecvResult::StreamError;
            }
        }
    }

    if let Err(e) = file.flush().await {
        tracing::warn!("Data recv from {}: flush error: {}", address, e);
        drop(file);
        let _ = tokio::fs::remove_file(&temp_path).await;
        return FileRecvResult::DiskError;
    }
    drop(file);

    // ── Remove from pending sizes ────────────────────────────────────────
    if let Some(ref name) = file_name {
        pending_file_sizes.lock().ok().map(|mut map| map.remove(name.as_str()));
    }

    // ── Deliver via on_file_received ─────────────────────────────────────
    event_cb.on_file_received(
        peer_key.to_vec(),
        guid, reply_to, send_time, edit_time, msg_type,
        meta_str,
        temp_path,
    );

    FileRecvResult::Ok
}

/// Consume and discard `count` bytes from the stream to keep it in sync.
async fn consume_bytes(conn: &Arc<AsyncConn>, count: usize) -> Result<(), String> {
    let mut consumed = 0;
    while consumed < count {
        let want = (count - consumed).min(65536);
        match read_exact(conn, want).await {
            ::core::result::Result::Ok(chunk) => consumed += chunk.len(),
            Err(e) => return Err(e.to_string()),
        }
    }
    ::core::result::Result::Ok(())
}