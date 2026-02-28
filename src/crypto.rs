use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chacha20poly1305::aead::{Aead, KeyInit};
use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{Signature, SigningKey, Signer, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::{Digest, Sha256, Sha512};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};

use crate::error::MimirError;

// ── Ed25519 helpers ───────────────────────────────────────────────────────────

/// Sign `message` with `key`. Returns a 64-byte Ed25519 signature.
pub fn sign(key: &SigningKey, message: &[u8]) -> Vec<u8> {
    key.sign(message).to_bytes().to_vec()
}

/// Verify that `signature` is a valid Ed25519 signature of `message` by the
/// holder of `pubkey`.
pub fn verify(pubkey: &[u8; 32], message: &[u8], signature: &[u8]) -> Result<(), MimirError> {
    let vk = VerifyingKey::from_bytes(pubkey)
        .map_err(|e| MimirError::Crypto(e.to_string()))?;

    let sig_bytes: [u8; 64] = signature
        .try_into()
        .map_err(|_| MimirError::Crypto(format!("expected 64-byte signature, got {}", signature.len())))?;

    vk.verify(message, &Signature::from_bytes(&sig_bytes))
        .map_err(|e| MimirError::Crypto(e.to_string()))
}

/// Derive the 32-byte Ed25519 public key from a signing key.
pub fn pubkey_of(key: &SigningKey) -> [u8; 32] {
    key.verifying_key().to_bytes()
}

// ── Group chat crypto ─────────────────────────────────────────────────────────

/// Generate a random 32-byte shared key for a new group chat.
pub fn generate_shared_key() -> Vec<u8> {
    let mut key = vec![0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key);
    key
}

/// Encrypt `plaintext` with `shared_key` using ChaCha20-Poly1305.
///
/// Output format: `[nonce(12)][ciphertext][tag(16)]`
pub fn encrypt_message(plaintext: Vec<u8>, shared_key: Vec<u8>) -> Result<Vec<u8>, MimirError> {
    let key = key32(&shared_key, "shared_key")?;

    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce);

    let ct_with_tag = chacha20_poly1305_encrypt(&key, &nonce, &plaintext);

    let mut out = Vec::with_capacity(12 + ct_with_tag.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct_with_tag);
    Ok(out)
}

/// Decrypt a message encrypted by [`encrypt_message`].
///
/// Input format: `[nonce(12)][ciphertext][tag(16)]`
pub fn decrypt_message(encrypted: Vec<u8>, shared_key: Vec<u8>) -> Result<Vec<u8>, MimirError> {
    if encrypted.len() < 12 + 16 {
        return Err(MimirError::Crypto(format!(
            "encrypted message too short: {} bytes", encrypted.len()
        )));
    }
    let key = key32(&shared_key, "shared_key")?;

    let nonce: [u8; 12] = encrypted[..12].try_into().unwrap();
    let ct_with_tag = &encrypted[12..];

    chacha20_poly1305_decrypt(&key, &nonce, ct_with_tag)
}

/// Encrypt `shared_key` for `recipient_ed25519_pubkey` using ECIES.
///
/// Algorithm:
/// 1. Ephemeral X25519 keypair
/// 2. Recipient Ed25519 pubkey → X25519
/// 3. X25519 ECDH → shared secret
/// 4. HKDF-SHA256(shared_secret, info="group-invite-key") → 32-byte enc key
/// 5. ChaCha20-Poly1305(enc_key, nonce, shared_key)
///
/// Output format: `[eph_pubkey(32)][nonce(12)][ciphertext][tag(16)]`
pub fn encrypt_shared_key(
    shared_key:               Vec<u8>,
    recipient_ed25519_pubkey: Vec<u8>,
) -> Result<Vec<u8>, MimirError> {
    if shared_key.len() != 32 {
        return Err(MimirError::Crypto(format!(
            "shared_key must be 32 bytes, got {}", shared_key.len()
        )));
    }
    let recipient_pk32 = key32(&recipient_ed25519_pubkey, "recipient_ed25519_pubkey")?;

    // Recipient Ed25519 → X25519 public key
    let recipient_x25519_bytes = ed25519_pubkey_to_x25519(&recipient_pk32)?;
    let recipient_x25519 = X25519PublicKey::from(recipient_x25519_bytes);

    // Ephemeral X25519 keypair
    let eph_secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
    let eph_public  = X25519PublicKey::from(&eph_secret);

    // ECDH + HKDF
    let shared_secret = eph_secret.diffie_hellman(&recipient_x25519);
    let enc_key = hkdf_sha256(shared_secret.as_bytes(), b"group-invite-key");

    // Random nonce
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce);

    // Encrypt
    let ct_with_tag = chacha20_poly1305_encrypt(&enc_key, &nonce, &shared_key);

    let mut out = Vec::with_capacity(32 + 12 + ct_with_tag.len());
    out.extend_from_slice(eph_public.as_bytes());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct_with_tag);
    Ok(out)
}

/// Decrypt a shared key encrypted by [`encrypt_shared_key`].
///
/// `seed` is the 32-byte Ed25519 signing-key seed of the recipient.
///
/// Input format: `[eph_pubkey(32)][nonce(12)][ciphertext][tag(16)]`
pub fn decrypt_shared_key(encrypted: Vec<u8>, seed: Vec<u8>) -> Result<Vec<u8>, MimirError> {
    // minimum: 32 (eph_pub) + 12 (nonce) + 32 (ciphertext) + 16 (tag) = 92
    if encrypted.len() < 32 + 12 + 16 {
        return Err(MimirError::Crypto(format!(
            "encrypted_shared_key too short: {} bytes", encrypted.len()
        )));
    }
    let seed32 = key32(&seed, "seed")?;

    let eph_pub_bytes: [u8; 32] = encrypted[..32].try_into().unwrap();
    let nonce:         [u8; 12] = encrypted[32..44].try_into().unwrap();
    let ct_with_tag = &encrypted[44..];

    // Our Ed25519 seed → X25519 private key
    let our_x25519_bytes = ed25519_seed_to_x25519(&seed32);
    let our_secret = StaticSecret::from(our_x25519_bytes);

    // ECDH + HKDF
    let eph_public = X25519PublicKey::from(eph_pub_bytes);
    let shared_secret = our_secret.diffie_hellman(&eph_public);
    let enc_key = hkdf_sha256(shared_secret.as_bytes(), b"group-invite-key");

    chacha20_poly1305_decrypt(&enc_key, &nonce, ct_with_tag)
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// ChaCha20-Poly1305 (RFC 8439 AEAD) encryption.  Returns `ciphertext || tag(16)`.
fn chacha20_poly1305_encrypt(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> Vec<u8> {
    ChaCha20Poly1305::new(Key::from_slice(key))
        .encrypt(Nonce::from_slice(nonce), plaintext)
        .expect("ChaCha20Poly1305 encrypt")
}

/// ChaCha20-Poly1305 (RFC 8439 AEAD) decryption.
/// `ciphertext_with_tag` = `ciphertext || tag(16)`.
fn chacha20_poly1305_decrypt(
    key:                 &[u8; 32],
    nonce:               &[u8; 12],
    ciphertext_with_tag: &[u8],
) -> Result<Vec<u8>, MimirError> {
    ChaCha20Poly1305::new(Key::from_slice(key))
        .decrypt(Nonce::from_slice(nonce), ciphertext_with_tag)
        .map_err(|_| MimirError::Crypto("MAC verification failed".into()))
}

/// Convert an Ed25519 public key to an X25519 public key.
///
/// Maps the Edwards y-coordinate to the Montgomery u-coordinate:
/// `u = (1 + y) / (1 - y) mod p`
fn ed25519_pubkey_to_x25519(pubkey: &[u8; 32]) -> Result<[u8; 32], MimirError> {
    let compressed = CompressedEdwardsY(*pubkey);
    let point = compressed.decompress()
        .ok_or_else(|| MimirError::Crypto("invalid Ed25519 public key".into()))?;
    Ok(point.to_montgomery().to_bytes())
}

/// Convert an Ed25519 seed (32-byte private key) to an X25519 private key.
///
/// Per RFC 8032 / RFC 7748:
/// 1. SHA-512(seed) → 64 bytes
/// 2. Take first 32 bytes
/// 3. Apply RFC 7748 clamping
fn ed25519_seed_to_x25519(seed: &[u8; 32]) -> [u8; 32] {
    let hash = Sha512::digest(seed);
    let mut key = [0u8; 32];
    key.copy_from_slice(&hash[..32]);
    // RFC 7748 clamping
    key[0]  &= 248;
    key[31] &= 127;
    key[31] |= 64;
    key
}

/// HKDF-SHA256 with no salt.  Returns 32 bytes of output keying material.
fn hkdf_sha256(ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm).expect("HKDF expand failed");
    okm
}

/// Convert a byte slice to a 32-byte array, returning a descriptive error.
fn key32<'a>(b: &'a [u8], name: &str) -> Result<[u8; 32], MimirError> {
    b.try_into().map_err(|_| MimirError::Crypto(
        format!("{name} must be 32 bytes, got {}", b.len())
    ))
}
