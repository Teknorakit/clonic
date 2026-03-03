//! Cryptographic suite implementations for ZCP.
//!
//! Defines Suite 0x01 (PQ Hybrid) and Suite 0x02 (Classical) per MANIFESTO.md Section 4.4.

use crate::error::Error;

/// Cryptographic suite identifier (from ZCP envelope offset 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoSuite {
    /// Suite 0x01: PQ Hybrid (ML-KEM-768 + X25519, ML-DSA-65 + Ed25519, AES-256-GCM)
    PqHybrid = 0x01,
    /// Suite 0x02: Classical (X25519, Ed25519, AES-256-GCM)
    Classical = 0x02,
}

impl CryptoSuite {
    /// Parse suite from byte (ZCP envelope crypto_suite field).
    pub fn from_byte(b: u8) -> Result<Self, Error> {
        match b {
            0x01 => Ok(CryptoSuite::PqHybrid),
            0x02 => Ok(CryptoSuite::Classical),
            _ => Err(Error::UnsupportedSuite),
        }
    }

    /// Return suite as byte.
    pub fn as_byte(self) -> u8 {
        self as u8
    }

    /// Return suite name.
    pub fn name(self) -> &'static str {
        match self {
            CryptoSuite::PqHybrid => "PQ Hybrid (ML-KEM-768 + X25519, ML-DSA-65 + Ed25519)",
            CryptoSuite::Classical => "Classical (X25519, Ed25519)",
        }
    }

    /// Return recommended use case.
    pub fn recommended_for(self) -> &'static str {
        match self {
            CryptoSuite::PqHybrid => "Full nodes (Linux/servers, 1-4 GB RAM)",
            CryptoSuite::Classical => "Edge devices (ESP32, nRF52, 256 KB-4 MB RAM)",
        }
    }
}

/// Key exchange (KEM) output: shared secret + encapsulated key.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone)]
pub struct KemOutput {
    /// Shared secret (32 bytes for X25519, combined with ML-KEM-768 for PQ Hybrid)
    pub shared_secret: [u8; 32],
    /// Encapsulated key (1088 bytes for ML-KEM-768, 32 bytes for X25519)
    pub encapsulated_key: alloc::vec::Vec<u8>,
}

/// Signature output: signature bytes.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone)]
pub struct SignatureOutput {
    /// Signature bytes (114 bytes for ML-DSA-65, 64 bytes for Ed25519)
    pub signature: alloc::vec::Vec<u8>,
}

#[cfg(feature = "alloc")]
mod alloc_support {
    use alloc::vec::Vec;

    /// Per-message key derivation using HKDF-SHA3-256.
    ///
    /// Derives a symmetric key from a shared secret using HKDF-SHA3-256 with
    /// ZCP-specific context binding. Used for AES-256-GCM encryption.
    ///
    /// # Arguments
    /// - `shared_secret`: 32-byte shared secret from KEM
    /// - `context`: Domain separation string (e.g., "ZCP-v0x01-AES-256-GCM")
    ///
    /// # Returns
    /// 32-byte AES-256-GCM key
    pub fn derive_symmetric_key(shared_secret: &[u8; 32], context: &[u8]) -> [u8; 32] {
        // TODO: Implement HKDF-SHA3-256 derivation
        // For now, placeholder
        let mut key = [0u8; 32];
        key.copy_from_slice(&shared_secret[..32]);
        key
    }

    /// Hybrid KEM for Suite 0x01: combine X25519 and ML-KEM-768 shared secrets.
    ///
    /// Per MANIFESTO.md Section 6.1:
    /// `session_key = HKDF-SHA3-256(X25519_shared || ML-KEM-768_shared, context)`
    ///
    /// # Arguments
    /// - `x25519_shared`: 32-byte X25519 shared secret
    /// - `ml_kem_shared`: 32-byte ML-KEM-768 shared secret
    /// - `context`: Domain separation string
    ///
    /// # Returns
    /// 32-byte session key
    pub fn hybrid_kem_combine(
        x25519_shared: &[u8; 32],
        ml_kem_shared: &[u8; 32],
        context: &[u8],
    ) -> [u8; 32] {
        // TODO: Implement HKDF-SHA3-256(X25519_shared || ML-KEM-768_shared, context)
        // For now, placeholder XOR
        let mut result = [0u8; 32];
        for i in 0..32 {
            result[i] = x25519_shared[i] ^ ml_kem_shared[i];
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suite_from_byte_pq_hybrid() {
        assert_eq!(CryptoSuite::from_byte(0x01).unwrap(), CryptoSuite::PqHybrid);
    }

    #[test]
    fn suite_from_byte_classical() {
        assert_eq!(CryptoSuite::from_byte(0x02).unwrap(), CryptoSuite::Classical);
    }

    #[test]
    fn suite_from_byte_invalid() {
        assert_eq!(
            CryptoSuite::from_byte(0xFF),
            Err(Error::UnsupportedSuite)
        );
    }

    #[test]
    fn suite_as_byte() {
        assert_eq!(CryptoSuite::PqHybrid.as_byte(), 0x01);
        assert_eq!(CryptoSuite::Classical.as_byte(), 0x02);
    }

    #[test]
    fn suite_name() {
        assert!(CryptoSuite::PqHybrid.name().contains("ML-KEM-768"));
        assert!(CryptoSuite::Classical.name().contains("X25519"));
    }
}
