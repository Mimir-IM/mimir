//! File server client — upload and download encrypted files.
//!
//! [`FilesNode`] is the UniFFI-exported top-level object. It shares the
//! Yggdrasil node from a [`PeerNode`] and manages cached connections to
//! one or more file servers.

pub mod client;
pub mod crypto;

use std::collections::HashMap;
use std::sync::Arc;

use sha2::{Sha256, Digest};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use ygg_stream::AsyncNode;

use crate::peer::PeerNode;
use crate::types::FileInfo;
use crate::{FilesEventListener, MimirError};
use client::FilesClient;

/// 1 MB upload/download chunk size.
const CHUNK_SIZE: usize = 1024 * 1024;

// ── FilesNode ─────────────────────────────────────────────────────────────────

/// Top-level file server client node.
///
/// Shares the Yggdrasil identity with an existing `PeerNode`.
/// All methods are thread-safe.
pub struct FilesNode {
    rt:       Arc<tokio::runtime::Runtime>,
    sk:       Arc<ed25519_dalek::SigningKey>,
    node:     Arc<AsyncNode>,
    port:     u16,
    listener: Arc<dyn FilesEventListener>,
    /// Cached connections by server pubkey.
    clients:  Mutex<HashMap<[u8; 32], FilesClient>>,
}

impl FilesNode {
    pub fn new(
        peer_node: Arc<PeerNode>,
        files_port: u16,
        event_listener: Box<dyn FilesEventListener>,
    ) -> Result<Self, MimirError> {
        let node = peer_node.ygg_node();
        let rt = peer_node.runtime();
        let sk = peer_node.signing_key();
        let listener: Arc<dyn FilesEventListener> = Arc::from(event_listener);

        Ok(FilesNode {
            rt,
            sk,
            node,
            port: files_port,
            listener,
            clients: Mutex::new(HashMap::new()),
        })
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /// Upload a file to the server. Returns the 32-byte SHA-256 hash of the encrypted file.
    ///
    /// 1. Encrypt file to temp
    /// 2. SHA-256 the encrypted temp file
    /// 3. Upload in 1 MB chunks
    /// 4. Clean up temp file
    pub fn upload_file(
        &self,
        server_pubkey: Vec<u8>,
        file_path: String,
        message_guid: i64,
        encryption_key: Vec<u8>,
    ) -> Result<Vec<u8>, MimirError> {
        let key = to_key32(&server_pubkey)?;
        let enc_key = to_key32(&encryption_key)
            .map_err(|_| MimirError::Crypto("encryption key must be 32 bytes".into()))?;

        self.rt.block_on(async {
            let temp_path = format!("{}.enc.tmp", file_path);

            // Step 1: Encrypt
            let enc_size = crypto::encrypt_file(&file_path, &temp_path, &enc_key).await?;

            // Step 2–4: Hash, upload, cleanup (with cleanup on error)
            let result = self.hash_and_upload(&key, &temp_path, enc_size, message_guid).await;

            // Always clean up temp file
            let _ = tokio::fs::remove_file(&temp_path).await;

            match result {
                Ok(hash) => {
                    self.listener.on_upload_complete(hash.to_vec());
                    Ok(hash.to_vec())
                }
                Err(e) => {
                    self.listener.on_upload_error(Vec::new(), e.to_string());
                    Err(e)
                }
            }
        })
    }

    /// Download a file from the server and decrypt it to `dest_path`.
    pub fn download_file(
        &self,
        server_pubkey: Vec<u8>,
        file_hash: Vec<u8>,
        message_guid: i64,
        dest_path: String,
        encryption_key: Vec<u8>,
    ) -> Result<(), MimirError> {
        let key = to_key32(&server_pubkey)?;
        let hash = to_key32(&file_hash)
            .map_err(|_| MimirError::Protocol("file hash must be 32 bytes".into()))?;
        let enc_key = to_key32(&encryption_key)
            .map_err(|_| MimirError::Crypto("encryption key must be 32 bytes".into()))?;

        self.rt.block_on(async {
            let temp_path = format!("{}.enc.tmp", dest_path);

            let result = self.download_and_decrypt(
                &key, &hash, message_guid, &temp_path, &dest_path, &enc_key,
            ).await;

            // Always clean up temp file
            let _ = tokio::fs::remove_file(&temp_path).await;

            match result {
                Ok(()) => {
                    self.listener.on_download_complete(file_hash, dest_path);
                    Ok(())
                }
                Err(e) => {
                    self.listener.on_download_error(file_hash, e.to_string());
                    Err(e)
                }
            }
        })
    }

    /// Query file metadata from the server.
    pub fn file_info(
        &self,
        server_pubkey: Vec<u8>,
        file_hash: Vec<u8>,
    ) -> Result<FileInfo, MimirError> {
        let key = to_key32(&server_pubkey)?;
        let hash = to_key32(&file_hash)
            .map_err(|_| MimirError::Protocol("file hash must be 32 bytes".into()))?;

        self.rt.block_on(async {
            let client = self.get_or_connect(&key).await?;
            let (total_size, message_guid) = client.file_info(&hash).await?;
            Ok(FileInfo { total_size, message_guid })
        })
    }

    /// Stop all cached client connections.
    pub fn stop(&self) {
        let clients = self.clients.blocking_lock();
        for (_, client) in clients.iter() {
            client.stop();
        }
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    async fn get_or_connect(&self, server_pubkey: &[u8; 32]) -> Result<FilesClient, MimirError> {
        let mut clients = self.clients.lock().await;

        // Return cached client if still connected.
        if let Some(c) = clients.get(server_pubkey) {
            if !c.is_disconnected() {
                return Ok(c.clone());
            }
            // Stale — remove and reconnect.
            clients.remove(server_pubkey);
        }

        let client = FilesClient::connect(
            &self.node,
            *server_pubkey,
            self.port,
            &self.sk,
        ).await?;

        clients.insert(*server_pubkey, client.clone());
        Ok(client)
    }

    /// Hash the encrypted file, then upload it in chunks.
    async fn hash_and_upload(
        &self,
        server_pubkey: &[u8; 32],
        enc_path: &str,
        enc_size: u64,
        message_guid: i64,
    ) -> Result<[u8; 32], MimirError> {
        // SHA-256 the encrypted file
        let hash = sha256_file(enc_path).await?;

        // Get client
        let client = self.get_or_connect(server_pubkey).await?;

        // Upload in chunks
        let mut f = File::open(enc_path).await
            .map_err(|e| MimirError::Io(format!("open encrypted file: {e}")))?;
        let mut buf = vec![0u8; CHUNK_SIZE];
        let mut offset: u64 = 0;

        loop {
            let n = read_full_buf(&mut f, &mut buf).await?;
            if n == 0 {
                break;
            }
            client.upload_chunk(&hash, message_guid, offset, enc_size, &buf[..n]).await?;
            offset += n as u64;
            self.listener.on_upload_progress(hash.to_vec(), offset, enc_size);
        }

        Ok(hash)
    }

    /// Download encrypted file, verify hash, decrypt to dest.
    async fn download_and_decrypt(
        &self,
        server_pubkey: &[u8; 32],
        hash: &[u8; 32],
        message_guid: i64,
        temp_path: &str,
        dest_path: &str,
        enc_key: &[u8; 32],
    ) -> Result<(), MimirError> {
        let client = self.get_or_connect(server_pubkey).await?;

        // Get total size
        let (total_size, _guid) = client.file_info(hash).await?;

        // Download to temp file
        let mut f = File::create(temp_path).await
            .map_err(|e| MimirError::Io(format!("create temp file: {e}")))?;
        let mut offset: u64 = 0;

        while offset < total_size {
            let (chunk, _resp_offset, _total) = client.download_chunk(
                hash, message_guid, offset, CHUNK_SIZE as u64,
            ).await?;
            if chunk.is_empty() {
                break;
            }
            f.write_all(&chunk).await
                .map_err(|e| MimirError::Io(format!("write temp file: {e}")))?;
            offset += chunk.len() as u64;
            self.listener.on_download_progress(hash.to_vec(), offset, total_size);
        }

        f.flush().await.map_err(|e| MimirError::Io(format!("flush: {e}")))?;
        drop(f);

        // Verify SHA-256
        let actual_hash = sha256_file(temp_path).await?;
        if actual_hash != *hash {
            return Err(MimirError::Crypto("downloaded file hash mismatch".into()));
        }

        // Decrypt
        crypto::decrypt_file(temp_path, dest_path, enc_key).await?;

        Ok(())
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn to_key32(v: &[u8]) -> Result<[u8; 32], MimirError> {
    v.try_into().map_err(|_| MimirError::Connection(
        format!("expected 32 bytes, got {} bytes", v.len())
    ))
}

/// Compute SHA-256 of a file using 64 KB streaming reads.
async fn sha256_file(path: &str) -> Result<[u8; 32], MimirError> {
    let mut f = File::open(path).await
        .map_err(|e| MimirError::Io(format!("open for hash: {e}")))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf).await
            .map_err(|e| MimirError::Io(format!("read for hash: {e}")))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().into())
}

/// Read up to `buf.len()` bytes, looping until EOF or buffer full.
async fn read_full_buf(file: &mut File, buf: &mut [u8]) -> Result<usize, MimirError> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = file.read(&mut buf[filled..]).await
            .map_err(|e| MimirError::Io(format!("read: {e}")))?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    Ok(filled)
}
