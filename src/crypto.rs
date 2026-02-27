use ed25519_dalek::{Signature, SigningKey, Signer, Verifier, VerifyingKey};

use crate::error::MimirError;

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