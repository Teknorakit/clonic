//! # clonic-identity
//!
//! Device identity and provisioning for the Zone Coordination Protocol (ZCP).
//!
//! This crate implements:
//! - **Device Identity:** Ed25519-based device identification (32-byte public key = sender_device_id)
//! - **Certificate Chain:** Offline-capable root → server → device trust model with trust decay by depth
//! - **Provisioning Messages:** REQUEST (0x30), CERT (0x31), REVOKE (0x32) per ZCP message type ranges
//! - **Key Rotation:** Mechanism for rotating device keys without losing identity
//! - **Secure Key Storage:** Abstraction for filesystem, TPM, and secure enclave backends
//!
//! ## Design
//!
//! Device provisioning follows an offline-first model:
//! 1. Root admin generates a certificate chain (root → server → device)
//! 2. Each certificate is signed by its parent and includes trust decay metadata
//! 3. Devices verify certificates without requiring network access to a CA
//! 4. Key rotation is performed locally with signed rotation certificates
//!
//! ## Feature Flags
//!
//! | Feature | Default | Effect |
//! |---------|---------|--------|
//! | `alloc` | off | Enables heap allocation for certificates |
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

#[cfg(feature = "alloc")]
pub mod cert;
pub mod error;
pub mod provisioning;

#[cfg(feature = "alloc")]
pub use cert::*;
pub use error::Error;
pub use provisioning::{DeviceIdentity, ProvisioningMessage, ProvisioningMessageType};
