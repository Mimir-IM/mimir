//! Streaming file encryption/decryption using ChaCha20-Poly1305.
//!
//! Files are processed in 1 MB plaintext chunks. Each chunk produces
//! `chunk_len + 16` bytes of ciphertext (the 16-byte Poly1305 tag is appended).
//! The nonce for chunk `i` is the chunk index encoded as little-endian u96.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::MimirError;

/// 1 MB plaintext chunk size.
const CHUNK_SIZE: usize = 1024 * 1024;
/// Each encrypted chunk is CHUNK_SIZE + 16 (Poly1305 tag), except the last.
const ENC_CHUNK_SIZE: usize = CHUNK_SIZE + 16;

/// Build the 12-byte nonce for chunk `index` (little-endian u96).
fn chunk_nonce(index: u64) -> Nonce {
    let mut n = [0u8; 12];
    n[..8].copy_from_slice(&index.to_le_bytes());
    *Nonce::from_slice(&n)
}

/// Encrypt `src_path` to `dst_path` using streaming ChaCha20-Poly1305.
/// Returns the total encrypted file size.
pub async fn encrypt_file(src_path: &str, dst_path: &str, key: &[u8; 32]) -> Result<u64, MimirError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let mut src = File::open(src_path).await
        .map_err(|e| MimirError::Io(format!("open source: {e}")))?;
    let mut dst = File::create(dst_path).await
        .map_err(|e| MimirError::Io(format!("create dest: {e}")))?;

    let mut buf = vec![0u8; CHUNK_SIZE];
    let mut chunk_idx: u64 = 0;
    let mut total_written: u64 = 0;

    loop {
        let n = read_full(&mut src, &mut buf).await?;
        if n == 0 {
            break;
        }
        let nonce = chunk_nonce(chunk_idx);
        let ct = cipher.encrypt(&nonce, &buf[..n])
            .map_err(|e| MimirError::Crypto(format!("encrypt chunk {chunk_idx}: {e}")))?;
        dst.write_all(&ct).await
            .map_err(|e| MimirError::Io(format!("write encrypted chunk: {e}")))?;
        total_written += ct.len() as u64;
        chunk_idx += 1;
    }

    dst.flush().await.map_err(|e| MimirError::Io(format!("flush: {e}")))?;
    Ok(total_written)
}

/// Decrypt `src_path` to `dst_path` using streaming ChaCha20-Poly1305.
pub async fn decrypt_file(src_path: &str, dst_path: &str, key: &[u8; 32]) -> Result<(), MimirError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let mut src = File::open(src_path).await
        .map_err(|e| MimirError::Io(format!("open source: {e}")))?;
    let mut dst = File::create(dst_path).await
        .map_err(|e| MimirError::Io(format!("create dest: {e}")))?;

    let mut buf = vec![0u8; ENC_CHUNK_SIZE];
    let mut chunk_idx: u64 = 0;

    loop {
        let n = read_full(&mut src, &mut buf).await?;
        if n == 0 {
            break;
        }
        if n < 17 {
            return Err(MimirError::Crypto(format!(
                "encrypted chunk {chunk_idx} too small ({n} bytes)"
            )));
        }
        let nonce = chunk_nonce(chunk_idx);
        let pt = cipher.decrypt(&nonce, &buf[..n])
            .map_err(|e| MimirError::Crypto(format!("decrypt chunk {chunk_idx}: {e}")))?;
        dst.write_all(&pt).await
            .map_err(|e| MimirError::Io(format!("write decrypted chunk: {e}")))?;
        chunk_idx += 1;
    }

    dst.flush().await.map_err(|e| MimirError::Io(format!("flush: {e}")))?;
    Ok(())
}

/// Read up to `buf.len()` bytes, looping until EOF or buffer full.
async fn read_full(file: &mut File, buf: &mut [u8]) -> Result<usize, MimirError> {
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
