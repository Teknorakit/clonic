//! AES-256-GCM encryption/decryption with per-message HKDF-SHA3-256 keys.
//!
//! Derives a 32-byte key from the shared secret and a caller-provided context
//! string using HKDF-SHA3-256. Nonce must be 12 bytes (96-bit GCM nonce).

use alloc::vec::Vec;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use sha3::Sha3_256;

use crate::error::Error;

/// Encrypt plaintext with AES-256-GCM using a key derived via HKDF-SHA3-256.
pub fn encrypt(
    shared_secret: &[u8; 32],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    context: &[u8],
) -> Result<Vec<u8>, Error> {
    if nonce.len() != 12 {
        return Err(Error::InvalidNonceLength);
    }
    if context.len() > 256 {
        return Err(Error::InvalidKeyLength);
    }

    let hkdf = Hkdf::<Sha3_256>::new(Some(context), shared_secret);
    let mut key = [0u8; 32];
    hkdf.expand(b"ZCP-aes-256-gcm", &mut key)
        .map_err(|_| Error::InvalidKeyLength)?;

    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| Error::InvalidKeyLength)?;
    let nonce = Nonce::from_slice(nonce);
    cipher
        .encrypt(nonce, Payload { msg: plaintext, aad })
        .map_err(|_| Error::MacVerificationFailed)
}

/// Encrypt using header bytes as AAD.
pub fn encrypt_with_header_aad(
    shared_secret: &[u8; 32],
    nonce: &[u8],
    header_bytes: &[u8],
    plaintext: &[u8],
    context: &[u8],
) -> Result<Vec<u8>, Error> {
    encrypt(shared_secret, nonce, header_bytes, plaintext, context)
}

/// Decrypt using header bytes as AAD.
pub fn decrypt_with_header_aad(
    shared_secret: &[u8; 32],
    nonce: &[u8],
    header_bytes: &[u8],
    ciphertext: &[u8],
    context: &[u8],
) -> Result<Vec<u8>, Error> {
    decrypt(shared_secret, nonce, header_bytes, ciphertext, context)
}

/// Decrypt ciphertext (ciphertext||tag) with AES-256-GCM using HKDF-SHA3-256 key.
pub fn decrypt(
    shared_secret: &[u8; 32],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    context: &[u8],
) -> Result<Vec<u8>, Error> {
    if nonce.len() != 12 {
        return Err(Error::InvalidNonceLength);
    }
    if context.len() > 256 {
        return Err(Error::InvalidKeyLength);
    }
    if ciphertext.len() < 16 {
        return Err(Error::InvalidCiphertextLength);
    }

    let hkdf = Hkdf::<Sha3_256>::new(Some(context), shared_secret);
    let mut key = [0u8; 32];
    hkdf.expand(b"ZCP-aes-256-gcm", &mut key)
        .map_err(|_| Error::InvalidKeyLength)?;

    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| Error::InvalidKeyLength)?;
    let nonce = Nonce::from_slice(nonce);
    cipher
        .decrypt(nonce, Payload { msg: ciphertext, aad })
        .map_err(|_| Error::MacVerificationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::{OsRng, RngCore};

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let mut shared = [0u8; 32];
        OsRng.fill_bytes(&mut shared);
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);

        let aad = b"header-as-aad";
        let plaintext = b"zcp-aes-256-gcm";
        let ctx = b"ZCP-v0x01-AES-256-GCM";

        let ct = encrypt(&shared, &nonce_bytes, aad, plaintext, ctx).unwrap();
        let pt = decrypt(&shared, &nonce_bytes, aad, &ct, ctx).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn encrypt_decrypt_header_aad_roundtrip() {
        let mut shared = [0u8; 32];
        OsRng.fill_bytes(&mut shared);
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);

        // Simulated header bytes (e.g., ZCP envelope header)
        let header = b"ZCP-HEADER-BYTES";
        let plaintext = b"zcp-header-aad-payload";
        let ctx = b"ZCP-v0x01-AES-256-GCM";

        let ct = encrypt_with_header_aad(&shared, &nonce_bytes, header, plaintext, ctx).unwrap();
        let pt = decrypt_with_header_aad(&shared, &nonce_bytes, header, &ct, ctx).unwrap();
        assert_eq!(pt, plaintext);
    }
}
