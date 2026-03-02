//! # clonic
//!
//! Wire protocol types and codec for the **Zone Coordination Protocol (ZCP)**.
//!
//! This crate defines the ZCP envelope format — the binary framing that every ZCP
//! message uses on the wire. It is deliberately minimal: types, constants, encode,
//! decode. No crypto, no transport, no business logic.
//!
//! ## Why "clonic"?
//!
//! In neurology, a *tonic-clonic* seizure involves two phases: sustained contraction
//! (tonic) followed by rapid rhythmic pulses across the nervous system (clonic).
//! [`tonic`](https://crates.io/crates/tonic) is already the Rust ecosystem's gRPC
//! framework — sustained connections. `clonic` completes the pair: rapid, rhythmic
//! coordination pulses across a distributed device mesh. The fleet *is* the nervous
//! system.
//!
//! ## Design Analogy
//!
//! `clonic` is to ZCP what the [`http`](https://crates.io/crates/http) crate
//! is to Hyper: it defines `Request`, `Response`, `StatusCode` — but doesn't open
//! sockets. Any ZCP implementation builds actual networking on top.
//!
//! ## Consumers
//!
//! | Consumer | Environment | Crypto | Notes |
//! |----------|-------------|--------|-------|
//! | Consumer | Environment | Crypto | Notes |
//! |----------|-------------|--------|-------|
//! | Full nodes | Linux (RPi/server, 1–4 GB RAM) | Full PQ hybrid | CRDT sync, Raft consensus, libp2p |
//! | Edge devices | Bare-metal/RTOS (ESP32, 256 KB–4 MB) | Classical only | Minimal ZCP speaker |
//! | Third parties | Any | Any supported suite | Anyone who wants to speak ZCP |
//!
//! ## Envelope Layout (v0x01)
//!
//! ```text
//! Offset  Size  Field
//! ──────────────────────────────────────
//! 0       1     version            Protocol version (0x01)
//! 1       1     msg_type           Message type discriminant
//! 2       1     crypto_suite       Crypto profile identifier
//! 3       1     flags              Bit flags (see Flags)
//! 4       32    sender_device_id   Ed25519 public key
//! 36      2     residency_tag      ISO 3166-1 numeric, big-endian
//! 38      4     payload_length     Payload byte count, big-endian
//! ──────────────────────────────────────  42 bytes fixed header
//! 42      var   payload            Encrypted (opaque to this crate)
//! 42+N    16    mac                AES-256-GCM authentication tag
//! ```
//!
//! All multi-byte integers are **big-endian** (network byte order).
//!
//! ## Feature Flags
//!
//! | Feature | Default | Effect |
//! |---------|---------|--------|
//! | `alloc` | off | Enables `Vec`-backed payload in `Envelope` |
//! | `std`   | off | Implies `alloc`, adds `std::error::Error` impls |
//! | `serde` | off | `Serialize`/`Deserialize` on public types (implies `alloc`) |
//!
//! The core encode/decode API works on `&[u8]` slices and requires only `core`.

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(unsafe_code)]
#![warn(missing_docs, clippy::all)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod crypto_suite;
pub mod decode;
pub mod encode;
pub mod envelope;
pub mod error;
pub mod msg_type;
pub mod residency;
pub mod version;

// Re-export primary types at crate root for ergonomics.
pub use crypto_suite::CryptoSuite;
#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
pub use envelope::Envelope;
pub use envelope::{EnvelopeRef, Flags, HEADER_SIZE, MAC_SIZE, MIN_FRAME_SIZE};
pub use error::Error;
pub use msg_type::MsgType;
pub use residency::ResidencyTag;
pub use version::Version;
