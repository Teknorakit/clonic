//! Key Encapsulation Mechanism (KEM) implementations for ZCP.
//!
//! Implements Suite 0x01 (PQ Hybrid: ML-KEM-768 + X25519) and Suite 0x02 (Classical: X25519).
//!
//! Per MANIFESTO.md Section 6.1:
//! - **PQ Hybrid:** `session_key = HKDF-SHA3-256(X25519_shared || ML-KEM-768_shared, context)`
//! - **Classical:** `session_key = HKDF-SHA3-256(X25519_shared, context)`

use crate::error::Error;
use hkdf::Hkdf;
use pqcrypto::kem::kyber768;
use pqcrypto::kem::kyber768::{
    Ciphertext as MlCiphertext, PublicKey as MlPublicKey, SecretKey as MlSecretKey,
};
use pqcrypto::traits::kem::{
    Ciphertext, PublicKey as TraitPublicKey, SecretKey as TraitSecretKey, SharedSecret,
};
use rand_core::OsRng;
use sha3::Sha3_256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// KEM keypair for key exchange.
///
/// Automatically zeroizes secret key material on drop.
#[derive(Debug)]
pub struct KemKeypair {
    /// Public key (32 bytes for X25519, 1184 bytes for ML-KEM-768)
    pub public_key: alloc::vec::Vec<u8>,
    /// Secret key (32 bytes for X25519, 2400 bytes for ML-KEM-768)
    /// Automatically zeroized on drop.
    pub secret_key: alloc::vec::Vec<u8>,
}

impl Drop for KemKeypair {
    fn drop(&mut self) {
        self.secret_key.zeroize();
    }
}

/// KEM encapsulation result: shared secret + encapsulated key.
#[derive(Debug, Clone)]
pub struct KemEncapsulation {
    /// Shared secret (32 bytes)
    pub shared_secret: [u8; 32],
    /// Encapsulated key (32 bytes for X25519, 1088 bytes for ML-KEM-768)
    pub encapsulated_key: alloc::vec::Vec<u8>,
}

/// Suite 0x01 (PQ Hybrid) KEM: ML-KEM-768 + X25519 with HKDF-SHA3-256.
#[cfg(feature = "alloc")]
pub struct PqHybridKem;

#[cfg(feature = "alloc")]
impl PqHybridKem {
    /// Generate a new PQ Hybrid keypair.
    ///
    /// Returns (X25519 keypair, ML-KEM-768 keypair).
    pub fn keygen() -> Result<(KemKeypair, KemKeypair), Error> {
        // X25519 keypair
        let x_secret = StaticSecret::random_from_rng(OsRng);
        let x_public = PublicKey::from(&x_secret);

        let x_kp = KemKeypair {
            public_key: Vec::from(x_public.as_bytes()),
            secret_key: Vec::from(x_secret.to_bytes()),
        };

        // ML-KEM-768 keypair
        let (ml_pk, ml_sk) = kyber768::keypair();
        let ml_kp = KemKeypair {
            public_key: Vec::from(ml_pk.as_bytes()),
            secret_key: Vec::from(ml_sk.as_bytes()),
        };

        Ok((x_kp, ml_kp))
    }

    /// Encapsulate: generate shared secret and encapsulated key.
    ///
    /// Combines X25519 and ML-KEM-768 encapsulations:
    /// 1. X25519 encapsulation → x25519_shared (32 bytes)
    /// 2. ML-KEM-768 encapsulation → ml_kem_shared (32 bytes)
    /// 3. Hybrid KEM: `session_key = HKDF-SHA3-256(x25519_shared || ml_kem_shared, context)`
    ///
    /// # Arguments
    /// - `x25519_pk`: X25519 public key (32 bytes)
    /// - `ml_kem_pk`: ML-KEM-768 public key (1184 bytes)
    /// - `context`: Domain separation string (e.g., "ZCP-v0x01-KEM")
    ///
    /// # Returns
    /// Shared secret (32 bytes) and combined encapsulated key (1088 + 32 = 1120 bytes)
    pub fn encapsulate(
        x25519_pk: &[u8; 32],
        ml_kem_pk: &[u8],
        context: &[u8],
    ) -> Result<KemEncapsulation, Error> {
        // Validate inputs
        if ml_kem_pk.len() != kyber768::public_key_bytes() {
            return Err(Error::InvalidKeyLength);
        }
        if context.is_empty() || context.len() > 256 {
            return Err(Error::InvalidKeyLength);
        }
        // X25519 ephemeral encapsulation
        let eph_secret = StaticSecret::random_from_rng(OsRng);
        let eph_public = PublicKey::from(&eph_secret);
        let recipient_public = PublicKey::from(*x25519_pk);
        let x25519_shared = eph_secret.diffie_hellman(&recipient_public);

        // ML-KEM-768 encapsulation
        let ml_pk = MlPublicKey::from_bytes(ml_kem_pk);
        // kyber768::encapsulate returns (SharedSecret, Ciphertext)
        let (ml_shared, ml_ct) = kyber768::encapsulate(ml_pk);

        // Combine shared secrets via HKDF-SHA3-256
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(x25519_shared.as_bytes());
        combined[32..].copy_from_slice(ml_shared.as_bytes());
        let hkdf = Hkdf::<Sha3_256>::new(Some(context), &combined);
        let mut session_key = [0u8; 32];
        hkdf.expand(b"ZCP-hybrid-kem", &mut session_key)
            .map_err(|_| Error::InvalidKeyLength)?;

        // Combined encapsulated key: ML-KEM ciphertext || X25519 ephemeral public key
        let mut enc = Vec::with_capacity(ml_ct.as_bytes().len() + 32);
        enc.extend_from_slice(ml_ct.as_bytes());
        enc.extend_from_slice(eph_public.as_bytes());

        Ok(KemEncapsulation {
            shared_secret: session_key,
            encapsulated_key: enc,
        })
    }

    /// Decapsulate: recover shared secret from encapsulated key.
    ///
    /// # Arguments
    /// - `_x25519_sk`: X25519 secret key (32 bytes)
    /// - `_ml_kem_sk`: ML-KEM-768 secret key (2400 bytes)
    /// - `_encapsulated_key`: Combined encapsulated key (1120 bytes)
    /// - `_context`: Domain separation string (must match encapsulation context)
    ///
    /// # Returns
    /// Shared secret (32 bytes)
    pub fn decapsulate(
        x25519_sk: &[u8; 32],
        ml_kem_sk: &[u8],
        encapsulated_key: &[u8],
        context: &[u8],
    ) -> Result<[u8; 32], Error> {
        if ml_kem_sk.len() != kyber768::secret_key_bytes() {
            return Err(Error::InvalidKeyLength);
        }
        if encapsulated_key.len() != kyber768::ciphertext_bytes() + 32 {
            return Err(Error::InvalidCiphertextLength);
        }
        if context.is_empty() || context.len() > 256 {
            return Err(Error::InvalidKeyLength);
        }

        let (ml_ct_bytes, x25519_eph_bytes) =
            encapsulated_key.split_at(kyber768::ciphertext_bytes());

        // X25519 shared secret
        let eph_public = PublicKey::from(
            <[u8; 32]>::try_from(x25519_eph_bytes).map_err(|_| Error::InvalidCiphertextLength)?,
        );
        let secret = StaticSecret::from(*x25519_sk);
        let x25519_shared = secret.diffie_hellman(&eph_public);

        // ML-KEM decapsulation
        let ml_ct = MlCiphertext::from_bytes(ml_ct_bytes);
        let ml_sk = MlSecretKey::from_bytes(ml_kem_sk);
        let ml_shared = kyber768::decapsulate(ml_ct, ml_sk);

        // Combine with HKDF-SHA3-256
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(x25519_shared.as_bytes());
        combined[32..].copy_from_slice(ml_shared.as_bytes());
        let hkdf = Hkdf::<Sha3_256>::new(Some(context), &combined);
        let mut session_key = [0u8; 32];
        hkdf.expand(b"ZCP-hybrid-kem", &mut session_key)
            .map_err(|_| Error::InvalidKeyLength)?;

        Ok(session_key)
    }
}

/// Suite 0x02 (Classical) KEM: X25519 with HKDF-SHA3-256.
#[cfg(feature = "alloc")]
pub struct ClassicalKem;

#[cfg(feature = "alloc")]
impl ClassicalKem {
    /// Generate a new X25519 keypair using cryptographically secure randomness.
    pub fn keygen() -> Result<KemKeypair, Error> {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);

        Ok(KemKeypair {
            public_key: Vec::from(public.as_bytes()),
            secret_key: Vec::from(secret.to_bytes()),
        })
    }

    /// Encapsulate: generate shared secret and encapsulated key.
    ///
    /// Uses ephemeral X25519 keypair to derive shared secret via HKDF-SHA3-256.
    ///
    /// # Arguments
    /// - `public_key`: X25519 public key (32 bytes)
    /// - `context`: Domain separation string (e.g., "ZCP-v0x02-KEM")
    ///
    /// # Returns
    /// Shared secret (32 bytes) and encapsulated key (32 bytes, the ephemeral public key)
    pub fn encapsulate(public_key: &[u8; 32], context: &[u8]) -> Result<KemEncapsulation, Error> {
        // Validate context length
        if context.is_empty() || context.len() > 256 {
            return Err(Error::InvalidKeyLength);
        }

        // Generate ephemeral keypair with cryptographically secure randomness
        let ephemeral_secret = StaticSecret::random_from_rng(OsRng);
        let ephemeral_public = PublicKey::from(&ephemeral_secret);

        // Perform X25519 key exchange
        let recipient_public = PublicKey::from(*public_key);
        let shared_secret_bytes = ephemeral_secret.diffie_hellman(&recipient_public);

        // Derive session key using HKDF-SHA3-256(shared_secret, context)
        let hkdf = Hkdf::<Sha3_256>::new(Some(context), shared_secret_bytes.as_bytes());
        let mut session_key = [0u8; 32];
        hkdf.expand(b"ZCP-session-key", &mut session_key)
            .map_err(|_| Error::InvalidKeyLength)?;

        Ok(KemEncapsulation {
            shared_secret: session_key,
            encapsulated_key: Vec::from(ephemeral_public.as_bytes()),
        })
    }

    /// Decapsulate: recover shared secret from encapsulated key.
    ///
    /// # Arguments
    /// - `secret_key`: X25519 secret key (32 bytes)
    /// - `encapsulated_key`: Encapsulated key (32 bytes, ephemeral public key)
    /// - `context`: Domain separation string (must match encapsulation context)
    ///
    /// # Returns
    /// Shared secret (32 bytes)
    pub fn decapsulate(
        secret_key: &[u8; 32],
        encapsulated_key: &[u8],
        context: &[u8],
    ) -> Result<[u8; 32], Error> {
        if encapsulated_key.len() != 32 {
            return Err(Error::InvalidCiphertextLength);
        }

        // Parse encapsulated key as ephemeral public key
        let ephemeral_bytes =
            <[u8; 32]>::try_from(encapsulated_key).map_err(|_| Error::InvalidCiphertextLength)?;
        let ephemeral_public = PublicKey::from(ephemeral_bytes);

        // Perform X25519 key exchange
        let secret = StaticSecret::from(*secret_key);
        let shared_secret_bytes = secret.diffie_hellman(&ephemeral_public);

        // Derive session key using HKDF-SHA3-256(shared_secret, context)
        let hkdf = Hkdf::<Sha3_256>::new(Some(context), shared_secret_bytes.as_bytes());
        let mut session_key = [0u8; 32];
        hkdf.expand(b"ZCP-session-key", &mut session_key)
            .map_err(|_| Error::InvalidKeyLength)?;

        Ok(session_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "alloc")]
    fn pq_hybrid_kem_placeholder() {
        // Happy-path roundtrip
        let (x_kp, ml_kp) = PqHybridKem::keygen().unwrap();
        let context = b"ZCP-v0x01-KEM";

        let enc = PqHybridKem::encapsulate(
            &<[u8; 32]>::try_from(&x_kp.public_key[..]).unwrap(),
            &ml_kp.public_key,
            context,
        )
        .unwrap();

        let session = PqHybridKem::decapsulate(
            &<[u8; 32]>::try_from(&x_kp.secret_key[..]).unwrap(),
            &ml_kp.secret_key,
            &enc.encapsulated_key,
            context,
        )
        .unwrap();

        assert_eq!(session, enc.shared_secret);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn classical_kem_placeholder() {
        // TODO: Add real KEM tests once implementation is complete
        // - Test keygen produces valid X25519 keypair
        // - Test encapsulate/decapsulate roundtrip
        // - Test HKDF-SHA3-256 derivation
    }
}
