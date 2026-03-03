//! # clonic-transport
//!
//! Transport abstraction layer for the Zone Coordination Protocol (ZCP).
//!
//! This crate defines the `Transport` trait and framing protocol for ZCP messages
//! over various physical transports (TCP, BLE, LoRaWAN, etc.).
//!
//! ## Two-Phase Framing
//!
//! ZCP uses a two-phase framing pattern per README.md:
//! 1. Read exactly 42 bytes (ZCP header)
//! 2. Call `peek_frame_length` to extract total frame size
//! 3. Read remaining payload + 16-byte MAC
//! 4. Parse complete envelope
//!
//! ## Feature Flags
//!
//! | Feature | Default | Effect |
//! |---------|---------|--------|
//! | `alloc` | off | Enables heap allocation for buffers |
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
pub mod framing;

pub use error::Error;
pub use framing::TransportFraming;
