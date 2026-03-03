//! Crypto suite identifiers.
//!
//! ZCP supports multiple cryptographic profiles to accommodate the full
//! spectrum from constrained embedded devices (ESP32, 256 KB RAM) to
//! full Linux servers with post-quantum capabilities.
//!
//! The `crypto_suite` byte in the envelope header tells the receiver
//! which key exchange, signature, and symmetric algorithms were used
//! to produce the encrypted payload and MAC. This crate does NOT
//! perform any cryptography — it only identifies which suite is in use.
//!
//! ## Defined Suites
//!
//! | ID | Name | KE | Sig | Symmetric | Target |
//! |----|------|----|-----|-----------|--------|
//! | 0x01 | PQ Hybrid | ML-KEM-768 + X25519 | ML-DSA-65 + Ed25519 | AES-256-GCM | Full ZCP nodes |
//! | 0x02 | Classical | X25519 | Ed25519 | AES-256-GCM | Constrained edge devices |
//!
//! ## Negotiation
//!
//! Suite negotiation happens at the session layer (above `clonic`).
//! A full node receiving a `Classical` envelope from an ESP32 knows
//! to use X25519-only decryption. A constrained device receiving a
//! `PqHybrid` envelope it cannot decrypt should respond with an error
//! carrying its own supported suite list.

/// Cryptographic suite identifier carried in the ZCP envelope header.
///
/// This tells the receiver how to interpret the encrypted payload and MAC.
/// The actual crypto operations are performed by the consuming
/// implementation, not by `clonic`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum CryptoSuite {
    /// Post-quantum hybrid: ML-KEM-768 + X25519 key exchange,
    /// ML-DSA-65 + Ed25519 signatures, AES-256-GCM symmetric.
    ///
    /// Used on Linux devices with >= 1 GB RAM.
    /// Provides defense against both classical and quantum-era attacks.
    PqHybrid = 0x01,

    /// Classical-only: X25519 key exchange, Ed25519 signatures,
    /// AES-256-GCM symmetric.
    ///
    /// Used on constrained devices (ESP32, STM32, nRF52).
    /// ML-KEM/ML-DSA are too expensive for sub-MHz microcontrollers.
    Classical = 0x02,
}

impl CryptoSuite {
    /// Try to interpret a raw byte as a known crypto suite.
    pub const fn from_byte(b: u8) -> Option<CryptoSuite> {
        match b {
            0x01 => Some(CryptoSuite::PqHybrid),
            0x02 => Some(CryptoSuite::Classical),
            _ => None,
        }
    }

    /// Return the raw byte representation.
    pub const fn as_byte(self) -> u8 {
        self as u8
    }

    /// Whether this suite includes post-quantum key exchange.
    pub const fn is_post_quantum(self) -> bool {
        match self {
            CryptoSuite::PqHybrid => true,
            CryptoSuite::Classical => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_variants_roundtrip() {
        let suites = [CryptoSuite::PqHybrid, CryptoSuite::Classical];
        for s in suites {
            assert_eq!(
                CryptoSuite::from_byte(s.as_byte()),
                Some(s),
                "roundtrip failed for {:?}",
                s
            );
        }
    }

    #[test]
    fn byte_values_are_stable() {
        assert_eq!(CryptoSuite::PqHybrid.as_byte(), 0x01);
        assert_eq!(CryptoSuite::Classical.as_byte(), 0x02);
    }

    #[test]
    fn from_byte_unknown() {
        assert_eq!(CryptoSuite::from_byte(0x00), None);
        assert_eq!(CryptoSuite::from_byte(0x03), None);
        assert_eq!(CryptoSuite::from_byte(0xFF), None);
    }

    #[test]
    fn post_quantum_flag() {
        assert!(CryptoSuite::PqHybrid.is_post_quantum());
        assert!(!CryptoSuite::Classical.is_post_quantum());
    }
}
