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
//! The format of `data` is identical to the inline file format delivered via
//! `on_message_received`, so the Kotlin/Swift layer needs no changes.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::sync::mpsc;
use ygg_stream::AsyncConn;

use crate::PeerEventListener;
use super::protocol::{build_header, read_exact, read_i32, read_i64, MSG_TYPE_OK};

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
/// send-data stream indefinitely and fires `on_message_received` for each one.
/// After each successful receive it sends `MSG_TYPE_OK(guid)` back over the
/// control stream so the sender's `on_message_delivered` fires.
/// Exits when the stream closes or a read error occurs.
pub async fn data_recv_task(
    conn: Arc<AsyncConn>,
    peer_key: [u8; 32],
    event_cb: Arc<dyn PeerEventListener>,
    ctrl_write_txs: Arc<Mutex<HashMap<[u8; 32], mpsc::UnboundedSender<Vec<u8>>>>>,
) {
    let address = hex::encode(peer_key);
    loop {
        // ── Read frame header ──────────────────────────────────────────────
        let guid = match read_i64(&conn).await {
            Ok(v) => v,
            Err(e) => {
                log::info!("Data recv from {}: stream closed ({})", &address, e);
                break;
            }
        };
        let reply_to = match read_i64(&conn).await {
            Ok(v) => v,
            Err(e) => { log::info!("Data recv from {}: ({})", &address, e); break; }
        };
        let send_time = match read_i64(&conn).await {
            Ok(v) => v,
            Err(e) => { log::info!("Data recv from {}: ({})", &address, e); break; }
        };
        let edit_time = match read_i64(&conn).await {
            Ok(v) => v,
            Err(e) => { log::info!("Data recv from {}: ({})", &address, e); break; }
        };
        let msg_type = match read_i32(&conn).await {
            Ok(v) => v,
            Err(e) => { log::info!("Data recv from {}: ({})", &address, e); break; }
        };
        let data_size = match read_i64(&conn).await {
            Ok(v) => v,
            Err(e) => { log::info!("Data recv from {}: ({})", &address, e); break; }
        };

        if data_size < 0 || data_size > 512 * 1024 * 1024 {
            log::warn!("Data recv from {}: implausible data_size {}", &address, data_size);
            break;
        }

        // ── Read data in 64 KiB chunks, reporting progress ─────────────────
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
                    log::info!("Data recv from {}: read error ({})", &address, e);
                    return;
                }
            }
        }

        // ── Deliver the complete file ───────────────────────────────────────
        event_cb.on_message_received(
            peer_key.to_vec(),
            guid,
            reply_to,
            send_time,
            edit_time,
            msg_type,
            data,
        );

        // ── Acknowledge receipt over the control stream ─────────────────────
        // Mirrors the inline-message OK path in handle_incoming so the sender's
        // on_message_delivered callback fires.
        let mut ok_frame = vec![0u8; 24];
        ok_frame[..16].copy_from_slice(&build_header(MSG_TYPE_OK, 8));
        ok_frame[16..].copy_from_slice(&guid.to_be_bytes());
        if let Ok(map) = ctrl_write_txs.lock() {
            if let Some(tx) = map.get(&peer_key) {
                let _ = tx.send(ok_frame);
            } else {
                log::warn!("Data recv from {}: no control write channel for ACK", &address);
            }
        }
    }
}
