//! Single authenticated connection to a files server.
//!
//! Simplified version of `MediatorClient` — no push messages, no subscriptions,
//! no reconnect manager. Only request/response commands.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey};
use tokio::sync::{broadcast, mpsc, oneshot, Mutex};
use tokio::time;
use ygg_stream::{AsyncConn, AsyncNode};

use crate::MimirError;
use crate::mediator::protocol::*;

// ── Timeouts ──────────────────────────────────────────────────────────────────

const REQ_TIMEOUT: Duration = Duration::from_secs(15);
const UPLOAD_TIMEOUT: Duration = Duration::from_secs(60);
/// Close the connection after this much idle time (no requests sent/received).
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

// ── Pending request map ───────────────────────────────────────────────────────

type PendingMap = Mutex<HashMap<u16, oneshot::Sender<Response>>>;
type StreamingMap = Mutex<HashMap<u16, mpsc::Sender<Response>>>;

/// Handle for a streaming download in progress.
/// Automatically removes itself from the streaming map when dropped.
pub struct StreamingDownload {
    rx: mpsc::Receiver<Response>,
    req_id: u16,
    streaming: Arc<StreamingMap>,
}

impl Drop for StreamingDownload {
    fn drop(&mut self) {
        let streaming = Arc::clone(&self.streaming);
        let req_id = self.req_id;
        // Spawn cleanup since we can't await in Drop
        tokio::spawn(async move {
            streaming.lock().await.remove(&req_id);
        });
    }
}

// ── FilesClient ───────────────────────────────────────────────────────────────

/// A live, authenticated connection to a files server.
#[derive(Clone)]
pub struct FilesClient {
    conn:             Arc<AsyncConn>,
    pending:          Arc<PendingMap>,
    streaming:        Arc<StreamingMap>,
    write_mu:         Arc<Mutex<()>>,
    next_id:          Arc<AtomicU64>,
    last_activity_ms: Arc<AtomicU64>,
    stop_tx:          broadcast::Sender<()>,
    disconnected:     Arc<AtomicBool>,
}

impl FilesClient {
    /// Dial `server_pubkey` on `port`, authenticate, and spawn background tasks.
    pub async fn connect(node: &AsyncNode, server_pubkey: [u8; 32], port: u16, sk: &SigningKey) -> Result<Self, MimirError> {
        let conn = node.connect(&server_pubkey, port).await
            .map_err(|e| MimirError::Connection(e.to_string()))?;
        let conn = Arc::new(conn);

        // Handshake: send [VERSION][PROTO_CLIENT]
        conn.write(&[VERSION, PROTO_CLIENT]).await
            .map_err(|e| MimirError::Io(e))?;

        let (stop_tx, _) = broadcast::channel::<()>(1);
        let pending:  Arc<PendingMap>   = Arc::new(Mutex::new(HashMap::new()));
        let streaming: Arc<StreamingMap> = Arc::new(Mutex::new(HashMap::new()));
        let write_mu: Arc<Mutex<()>>    = Arc::new(Mutex::new(()));
        let next_id      = Arc::new(AtomicU64::new(1));
        let last_ms      = Arc::new(AtomicU64::new(now_ms()));
        let disconnected = Arc::new(AtomicBool::new(false));

        let client = FilesClient {
            conn:             Arc::clone(&conn),
            pending:          Arc::clone(&pending),
            streaming:        Arc::clone(&streaming),
            write_mu:         Arc::clone(&write_mu),
            next_id:          Arc::clone(&next_id),
            last_activity_ms: Arc::clone(&last_ms),
            stop_tx:          stop_tx.clone(),
            disconnected:     Arc::clone(&disconnected),
        };

        // Spawn reader task first (authenticate uses request which needs it).
        {
            let c = client.clone();
            let mut stop_rx = stop_tx.subscribe();
            tokio::spawn(async move {
                tokio::select! {
                    biased;
                    _ = stop_rx.recv() => {},
                    _ = c.reader_loop() => {},
                }
                let mut map = c.pending.lock().await;
                map.drain().for_each(|(_, tx)| {
                    let _ = tx.send(Response {
                        status:  STATUS_ERR,
                        req_id:  0,
                        payload: b"connection closed".to_vec(),
                    });
                });
                c.streaming.lock().await.clear();
            });
        }

        // Authenticate.
        if let Err(e) = client.authenticate(sk).await {
            client.stop();
            return Err(e);
        }

        // Spawn idle-timeout task: close connection after IDLE_TIMEOUT of inactivity.
        {
            let c = client.clone();
            let mut stop_rx = stop_tx.subscribe();
            tokio::spawn(async move {
                tokio::select! {
                    biased;
                    _ = stop_rx.recv() => {},
                    _ = c.idle_timeout_loop() => {},
                }
            });
        }

        Ok(client)
    }

    /// Stop the client: signal background tasks and close the connection.
    pub fn stop(&self) {
        let _ = self.stop_tx.send(());
    }

    /// Returns `true` if this client has been marked as disconnected.
    pub fn is_disconnected(&self) -> bool {
        self.disconnected.load(Ordering::SeqCst)
    }

    // ── File operations ───────────────────────────────────────────────────────

    /// Query file metadata. Returns `(total_size, message_guid)`.
    pub async fn file_info(&self, hash: &[u8; 32]) -> Result<(u64, i64), MimirError> {
        let mut p = Vec::new();
        write_tlv(&mut p, TAG_FILE_HASH, hash);
        let resp = self.request(CMD_FILE_INFO, &p).await?;
        if resp.status != STATUS_OK {
            return Err(resp.into_error("fileInfo"));
        }
        let tlvs = parse_tlvs(&resp.payload)?;
        let total = tlvs.get_u64(TAG_TOTAL_SIZE)?;
        let guid = tlvs.get_i64(TAG_MESSAGE_GUID)?;
        Ok((total, guid))
    }

    /// Upload a chunk of file data.
    pub async fn upload_chunk(
        &self,
        hash: &[u8; 32],
        guid: i64,
        offset: u64,
        total_size: u64,
        chunk_data: &[u8],
    ) -> Result<(), MimirError> {
        let mut p = Vec::with_capacity(32 + 8 + 8 + 8 + chunk_data.len() + 32);
        write_tlv(&mut p, TAG_FILE_HASH, hash);
        write_tlv_i64(&mut p, TAG_MESSAGE_GUID, guid);
        write_tlv_u64(&mut p, TAG_OFFSET, offset);
        write_tlv_u64(&mut p, TAG_TOTAL_SIZE, total_size);
        write_tlv(&mut p, TAG_CHUNK_DATA, chunk_data);
        let resp = self.request_timed(CMD_FILE_UPLOAD, &p, UPLOAD_TIMEOUT).await?;
        if resp.status != STATUS_OK {
            return Err(resp.into_error("uploadChunk"));
        }
        Ok(())
    }

    /// Download a chunk of file data. Returns `(chunk_bytes, offset, total_size)`.
    pub async fn download_chunk(
        &self,
        hash: &[u8; 32],
        guid: i64,
        offset: u64,
        limit: u64,
    ) -> Result<(Vec<u8>, u64, u64), MimirError> {
        let mut p = Vec::new();
        write_tlv(&mut p, TAG_FILE_HASH, hash);
        write_tlv_i64(&mut p, TAG_MESSAGE_GUID, guid);
        write_tlv_u64(&mut p, TAG_OFFSET, offset);
        write_tlv_u64(&mut p, TAG_TOTAL_SIZE, limit);
        let resp = self.request_timed(CMD_FILE_DOWNLOAD, &p, UPLOAD_TIMEOUT).await?;
        if resp.status != STATUS_OK {
            return Err(resp.into_error("downloadChunk"));
        }
        let tlvs = parse_tlvs(&resp.payload)?;
        let resp_offset = tlvs.get_u64(TAG_OFFSET)?;
        let total = tlvs.get_u64(TAG_TOTAL_SIZE)?;
        let data = tlvs.opt_bytes(TAG_CHUNK_DATA).unwrap_or_default();
        Ok((data, resp_offset, total))
    }

    /// Start a streaming download: send one CMD_DOWNLOAD request and return
    /// a receiver that delivers response frames as they arrive from the server.
    /// Call `download_streaming_next()` in a loop to read chunks.
    pub async fn download_streaming_start(
        &self,
        hash: &[u8; 32],
        guid: i64,
        start_offset: u64,
    ) -> Result<StreamingDownload, MimirError> {
        let raw = self.next_id.fetch_add(1, Ordering::Relaxed);
        let req_id = ((raw % 0xFFFF) as u16) + 1;

        // Register in streaming map so the reader delivers all frames.
        let (tx, rx) = mpsc::channel::<Response>(16);
        self.streaming.lock().await.insert(req_id, tx);

        // Build and send the request (limit = u32::MAX → server streams entire file).
        let mut p = Vec::new();
        write_tlv(&mut p, TAG_FILE_HASH, hash);
        write_tlv_i64(&mut p, TAG_MESSAGE_GUID, guid);
        write_tlv_u64(&mut p, TAG_OFFSET, start_offset);
        write_tlv_u32(&mut p, TAG_LIMIT, u32::MAX);

        let header = build_request_header(CMD_FILE_DOWNLOAD, req_id, p.len());
        let send_result = async {
            let _guard = self.write_mu.lock().await;
            self.conn.write(&header).await?;
            self.conn.write(&p).await?;
            Ok::<(), String>(())
        }.await;

        if let Err(e) = send_result {
            self.streaming.lock().await.remove(&req_id);
            return Err(MimirError::Io(e));
        }

        Ok(StreamingDownload { rx, req_id, streaming: Arc::clone(&self.streaming) })
    }

    /// Read the next chunk from a streaming download.
    /// Returns `(offset, chunk_data, total_size)`.
    /// When `offset + chunk_data.len() >= total_size`, the download is complete.
    pub async fn download_streaming_next(
        &self,
        dl: &mut StreamingDownload,
    ) -> Result<(u64, Vec<u8>, u64), MimirError> {
        let resp = match time::timeout(UPLOAD_TIMEOUT, dl.rx.recv()).await {
            Ok(Some(resp)) => resp,
            Ok(None) => return Err(MimirError::Connection("files: stream closed during download".into())),
            Err(_) => {
                self.conn.abort().await;
                return Err(MimirError::Connection("files: streaming download timed out".into()));
            }
        };

        if resp.status != STATUS_OK {
            return Err(resp.into_error("downloadStream"));
        }

        let tlvs = parse_tlvs(&resp.payload)?;
        let chunk_data = tlvs.opt_bytes(TAG_CHUNK_DATA).unwrap_or_default();
        let chunk_offset = tlvs.get_u64(TAG_OFFSET)?;
        let total_size = tlvs.get_u64(TAG_TOTAL_SIZE)?;

        Ok((chunk_offset, chunk_data, total_size))
    }

    // ── Internal: auth ────────────────────────────────────────────────────────

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
                "files auth rejected: {}", resp.error_string()
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
                "files getNonce failed: {}", resp.error_string()
            )));
        }
        let tlvs = parse_tlvs(&resp.payload)?;
        Ok(tlvs.get_bytes(TAG_NONCE)?.to_vec())
    }

    // ── Internal: request/response ────────────────────────────────────────────

    async fn request(&self, cmd: u8, payload: &[u8]) -> Result<Response, MimirError> {
        self.request_timed(cmd, payload, REQ_TIMEOUT).await
    }

    async fn request_timed(
        &self,
        cmd: u8,
        payload: &[u8],
        timeout_dur: Duration,
    ) -> Result<Response, MimirError> {
        let raw = self.next_id.fetch_add(1, Ordering::Relaxed);
        let req_id = ((raw % 0xFFFF) as u16) + 1;

        let (tx, rx) = oneshot::channel::<Response>();
        self.pending.lock().await.insert(req_id, tx);

        const CHUNK: usize = 64 * 1024;
        const CHUNK_TIMEOUT: Duration = Duration::from_secs(10);

        let header = build_request_header(cmd, req_id, payload.len());
        let write_err: Option<MimirError> = async {
            let _guard = self.write_mu.lock().await;
            if let Err(e) = self.conn.write(&header).await {
                return Some(MimirError::Io(e));
            }
            let mut offset = 0;
            while offset < payload.len() {
                let end = (offset + CHUNK).min(payload.len());
                match time::timeout(CHUNK_TIMEOUT, self.conn.write(&payload[offset..end])).await {
                    Ok(Ok(_))  => {}
                    Ok(Err(e)) => return Some(MimirError::Io(e)),
                    Err(_)     => return Some(MimirError::Connection(
                        format!("files request cmd=0x{cmd:02x}: chunk write timed out")
                    )),
                }
                self.last_activity_ms.store(now_ms(), Ordering::Relaxed);
                offset = end;
            }
            None
        }.await;

        if let Some(e) = write_err {
            self.conn.abort().await;
            self.pending.lock().await.remove(&req_id);
            return Err(e);
        }

        match time::timeout(timeout_dur, rx).await {
            Ok(Ok(resp)) => Ok(resp),
            Ok(Err(_)) => {
                self.pending.lock().await.remove(&req_id);
                Err(MimirError::Connection("files: connection closed during request".into()))
            }
            Err(_) => {
                self.conn.abort().await;
                self.pending.lock().await.remove(&req_id);
                Err(MimirError::Connection(format!(
                    "files request cmd=0x{cmd:02x} timed out"
                )))
            }
        }
    }

    // ── Internal: reader loop ─────────────────────────────────────────────────

    async fn reader_loop(&self) {
        loop {
            let resp = match read_response(&self.conn, &self.last_activity_ms).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!("files reader error: {e}");
                    self.disconnected.store(true, Ordering::SeqCst);
                    return;
                }
            };

            // Dispatch: check streaming map first (multi-frame), then pending (oneshot).
            // Clone the sender and drop the lock BEFORE the async send to avoid
            // holding the mutex across an await point (which would block all
            // other response dispatching if the channel is full).
            {
                let maybe_tx = {
                    let smap = self.streaming.lock().await;
                    smap.get(&resp.req_id).cloned()
                };
                if let Some(tx) = maybe_tx {
                    let _ = tx.send(resp).await;
                    continue;
                }
            }
            let mut map = self.pending.lock().await;
            if let Some(tx) = map.remove(&resp.req_id) {
                let _ = tx.send(resp);
            } else {
                tracing::warn!(
                    "files: unmatched response req_id={} status={}",
                    resp.req_id, resp.status
                );
            }
        }
    }

    // ── Internal: idle timeout ───────────────────────────────────────────────

    /// Closes the connection after [`IDLE_TIMEOUT`] of no activity.
    async fn idle_timeout_loop(&self) {
        let check = Duration::from_secs(5);
        let mut interval = time::interval(check);
        interval.tick().await; // skip immediate first tick
        loop {
            interval.tick().await;
            let elapsed = now_ms().saturating_sub(
                self.last_activity_ms.load(Ordering::Relaxed)
            );
            if elapsed >= IDLE_TIMEOUT.as_millis() as u64 {
                tracing::debug!("files: closing idle connection");
                self.disconnected.store(true, Ordering::SeqCst);
                let _ = self.stop_tx.send(());
                return;
            }
        }
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
