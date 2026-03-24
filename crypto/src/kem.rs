//! Key Encapsulation Mechanism (KEM) implementations for ZCP.
//!
//! Implements Suite 0x01 (PQ Hybrid: ML-KEM-768 + X25519) and Suite 0x02 (Classical: X25519).
//!
//! Per MANIFESTO.md Section 6.1:
//! - **PQ Hybrid:** `session_key = HKDF-SHA3-256(X25519_shared || ML-KEM-768_shared, context)`
//! - **Classical:** `session_key = HKDF-SHA3-256(X25519_shared, context)`

use crate::error::Error;
use hkdf::Hkdf;
// TODO: Replace pqcrypto with no_std compatible alternative
// use pqcrypto::kem::kyber768;
// use pqcrypto::kem::kyber768::{
//     Ciphertext as MlCiphertext, PublicKey as MlPublicKey, SecretKey as MlSecretKey,
// };
// use pqcrypto::traits::kem::{
//     Ciphertext, PublicKey as TraitPublicKey, SecretKey as TraitSecretKey, SharedSecret,
// };
#[cfg(feature = "getrandom")]
use rand_core::OsRng;
use sha3::Sha3_256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
#[allow(unused_imports)]
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
    ///
    /// # Warning
    /// The ML-KEM-768 portion is currently a placeholder implementation that returns
    /// empty vectors. This will be replaced with a proper ML-KEM-768 implementation
    /// when a no_std compatible library is available.
    pub fn keygen() -> Result<(KemKeypair, KemKeypair), Error> {
        #[cfg(feature = "getrandom")]
        {
            // X25519 keypair
            let x_secret = StaticSecret::random_from_rng(OsRng);
            let x_public = PublicKey::from(&x_secret);

            let x_kp = KemKeypair {
                public_key: Vec::from(x_public.as_bytes()),
                secret_key: Vec::from(x_secret.to_bytes()),
            };

            // TODO: Implement ML-KEM-768 keypair with no_std compatible library
            // For now, return a placeholder
            let ml_kp = KemKeypair {
                public_key: Vec::new(), // Placeholder
                secret_key: Vec::new(), // Placeholder
            };

            Ok((x_kp, ml_kp))
        }
        #[cfg(not(feature = "getrandom"))]
        {
            // No randomness source available
            Err(Error::NoRandomnessSource)
        }
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
        _x25519_pk: &[u8; 32],
        _ml_kem_pk: &[u8],
        _context: &[u8],
    ) -> Result<KemEncapsulation, Error> {
        // TODO: Implement with no_std compatible ML-KEM library
        Err(Error::InvalidKeyLength) // Placeholder error
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
        _x25519_sk: &[u8; 32],
        _ml_kem_sk: &[u8],
        _encapsulated_key: &[u8],
        _context: &[u8],
    ) -> Result<[u8; 32], Error> {
        // TODO: Implement with no_std compatible ML-KEM library
        Err(Error::InvalidKeyLength) // Placeholder error
    }
}

/// Suite 0x02 (Classical) KEM: X25519 with HKDF-SHA3-256.
#[cfg(feature = "alloc")]
pub struct ClassicalKem;

#[cfg(feature = "alloc")]
impl ClassicalKem {
    /// Generate a new X25519 keypair using cryptographically secure randomness.
    pub fn keygen() -> Result<KemKeypair, Error> {
        #[cfg(feature = "getrandom")]
        {
            let secret = StaticSecret::random_from_rng(OsRng);
            let public = PublicKey::from(&secret);

            Ok(KemKeypair {
                public_key: Vec::from(public.as_bytes()),
                secret_key: Vec::from(secret.to_bytes()),
            })
        }
        #[cfg(not(feature = "getrandom"))]
        {
            // No randomness source available
            Err(Error::NoRandomnessSource)
        }
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
    pub fn encapsulate(_public_key: &[u8; 32], _context: &[u8]) -> Result<KemEncapsulation, Error> {
        #[cfg(feature = "getrandom")]
        {
            // Validate context length
            if _context.is_empty() || _context.len() > 256 {
                return Err(Error::InvalidKeyLength);
            }

            // Generate ephemeral keypair with cryptographically secure randomness
            let ephemeral_secret = StaticSecret::random_from_rng(OsRng);
            let ephemeral_public = PublicKey::from(&ephemeral_secret);

            // Perform X25519 key exchange
            let recipient_public = PublicKey::from(*_public_key);
            let shared_secret_bytes = ephemeral_secret.diffie_hellman(&recipient_public);

            // Derive session key using HKDF-SHA3-256(shared_secret, context)
            let hkdf = Hkdf::<Sha3_256>::new(Some(_context), shared_secret_bytes.as_bytes());
            let mut session_key = [0u8; 32];
            hkdf.expand(b"ZCP-session-key", &mut session_key)
                .map_err(|_| Error::InvalidKeyLength)?;

            Ok(KemEncapsulation {
                shared_secret: session_key,
                encapsulated_key: Vec::from(ephemeral_public.as_bytes()),
            })
        }
        #[cfg(not(feature = "getrandom"))]
        {
            // No randomness source available
            Err(Error::NoRandomnessSource)
        }
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
    use crate::error::Error;

    #[test]
    #[cfg(feature = "alloc")]
    fn pq_hybrid_kem_placeholder_errors() {
        // Test that placeholder functions return expected errors until ML-KEM-768 is implemented
        let (x_kp, ml_kp) = PqHybridKem::keygen().unwrap();
        let context = b"ZCP-v0x01-KEM";

        // Verify encapsulate returns placeholder error
        let enc_result = PqHybridKem::encapsulate(
            &<[u8; 32]>::try_from(&x_kp.public_key[..]).unwrap(),
            &ml_kp.public_key,
            context,
        );
        assert!(matches!(enc_result, Err(Error::InvalidKeyLength)));

        // Verify decapsulate returns placeholder error
        let dec_result = PqHybridKem::decapsulate(
            &<[u8; 32]>::try_from(&x_kp.secret_key[..]).unwrap(),
            &ml_kp.secret_key,
            &[], // Empty encapsulated key for testing
            context,
        );
        assert!(matches!(dec_result, Err(Error::InvalidKeyLength)));
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn classical_kem_roundtrip() {
        let kp = ClassicalKem::keygen().unwrap();
        let context = b"ZCP-v0x02-KEM";

        let enc = ClassicalKem::encapsulate(
            &<[u8; 32]>::try_from(kp.public_key.as_slice()).unwrap(),
            context,
        )
        .unwrap();
        let dec = ClassicalKem::decapsulate(
            &<[u8; 32]>::try_from(kp.secret_key.as_slice()).unwrap(),
            &enc.encapsulated_key,
            context,
        )
        .unwrap();

        assert_eq!(dec, enc.shared_secret);
    }
}
