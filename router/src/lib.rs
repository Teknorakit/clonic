//! # clonic-router
//!
//! Zone enforcement routing for the Zone Coordination Protocol (ZCP).
//!
//! This crate implements the routing layer that enforces data residency
//! policies at the network level. It validates residency tags, maintains
//! peer registries, and applies routing policies to prevent unauthorized
//! data exfiltration.
//!
//! ## Architecture
//!
//! ```text
//! ZCP Envelope → Router → Transport → Network
//!     ↓               ↓           ↓
//!   Residency      Zone        Physical
//!   Tag Check      Policy       Layer
//! ```
//!
//! ## Features
//!
//! - **Peer Registry**: Maps device IDs to zone locations
//! - **Zone Validation**: Enforces residency tag compliance per hop
//! - **Policy Engine**: Allowlists, denylists, cross-border agreements
//! - **Zone-Aware Routing**: Selects paths respecting data sovereignty
//! - **Violation Logging**: Records all policy violations
//! - **Configuration**: TOML-based zone and policy definitions
//! - **Metrics**: Prometheus integration for monitoring
//!
//! ## Feature Flags
//!
//! | Feature | Default | Effect |
//! |---------|---------|--------|
//! | `std`   | on      | Standard library support |
//! | `alloc` | on      | Heap allocation support |
//! | `serde` | off     | Serialization support |
//! | `config`| off     | TOML configuration parsing |
//! | `metrics`| off    | Prometheus metrics |

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(unsafe_code)]
#![warn(missing_docs, clippy::all)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod config;
pub mod policy;
pub mod registry;
pub mod router;
pub mod violation;

// Re-export primary types for ergonomics
#[cfg(feature = "alloc")]
pub use config::{RouterConfig, ZoneConfig};
#[cfg(feature = "alloc")]
pub use policy::{PolicyEngine, RoutingDecision};
#[cfg(feature = "alloc")]
pub use registry::{PeerInfo, PeerRegistry};
pub use router::{Router, RouterError};
#[cfg(feature = "alloc")]
pub use violation::{Violation, ViolationLogger};
