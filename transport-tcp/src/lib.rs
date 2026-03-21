//! # clonic-transport-tcp
//!
//! TCP/IP transport implementation for the Zone Coordination Protocol (ZCP).
//!
//! Provides async TCP transport with:
//! - Tokio-based async/await runtime
//! - TLS support for encrypted channels
//! - Connection pooling and keepalive
//! - Backpressure and flow control
//!
//! ## Feature Flags
//!
//! | Feature | Default | Effect |
//! |---------|---------|--------|
//! | `std`   | on      | Enables tokio and full TCP implementation |

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(unsafe_code)]
#![warn(missing_docs, clippy::all)]

#[cfg(feature = "std")]
pub mod flow;

#[cfg(feature = "std")]
pub mod framing;

#[cfg(feature = "std")]
pub mod pool;

#[cfg(feature = "std")]
pub mod tcp;

#[cfg(feature = "tls")]
pub mod tls;

#[cfg(feature = "std")]
pub use tcp::TcpTransport;

#[cfg(feature = "std")]
pub use flow::{BackpressureHandler, FlowControlConfig, FlowControlMetrics};

#[cfg(feature = "std")]
pub use framing::{FrameReader, FrameWriter};

#[cfg(feature = "std")]
pub use pool::{KeepaliveConfig, PoolConfig};

#[cfg(feature = "tls")]
pub use tls::{TlsConfig, TlsConnectorWrapper};
