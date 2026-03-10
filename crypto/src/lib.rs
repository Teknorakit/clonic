//! # clonic-crypto
//!
//! Post-quantum hybrid cryptography for the Zone Coordination Protocol (ZCP).
//!
//! This crate implements the cryptographic suites defined in the ZCP protocol specification:
//! - **Suite 0x01 (PQ Hybrid):** ML-KEM-768 + X25519 for key exchange, ML-DSA-65 + Ed25519 for signatures, AES-256-GCM for encryption
//! - **Suite 0x02 (Classical):** X25519 for key exchange, Ed25519 for signatures, AES-256-GCM for encryption
//!
//! All cryptographic operations use per-message HKDF-SHA3-256 derived keys and are designed to be
//! crypto-agile, allowing algorithm rotation without breaking wire compatibility.
//!
//! ## Feature Flags
//!
//! | Feature | Default | Effect |
//! |---------|---------|--------|
//! | `alloc` | off | Enables heap allocation for key material |
//! | `std`   | off | Implies `alloc`, adds `std::error::Error` impls |
//! | `serde` | off | `Serialize`/`Deserialize` on public types (implies `alloc`) |

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(unsafe_code)]
#![warn(missing_docs, clippy::all)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod error;
pub mod suite;

#[cfg(feature = "alloc")]
pub mod aead;
#[cfg(feature = "alloc")]
pub mod kem;
#[cfg(feature = "alloc")]
pub mod sign;

pub use error::Error;
pub use suite::CryptoSuite;

#[cfg(feature = "alloc")]
pub use suite::{KemOutput, SignatureOutput};

#[cfg(feature = "alloc")]
pub use aead::{decrypt, encrypt};
#[cfg(feature = "alloc")]
pub use aead::{decrypt_with_header_aad, encrypt_with_header_aad};
#[cfg(feature = "alloc")]
pub use kem::{ClassicalKem, KemEncapsulation, KemKeypair, PqHybridKem};
#[cfg(feature = "alloc")]
pub use sign::{ClassicalSigKeypair, HybridSigKeypair};
