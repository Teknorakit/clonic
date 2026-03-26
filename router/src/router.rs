//! Main router implementation for zone enforcement.
//!
//! Coordinates peer registry, policy engine, and transport layer
//! to provide zone-aware routing with residency tag enforcement.

#[cfg(feature = "alloc")]
use crate::{
    policy::{PolicyEngine, RoutingDecision},
    registry::{PeerInfo, PeerRegistry},
    violation::{Violation, ViolationLogger, ViolationType},
};
#[cfg(feature = "alloc")]
use alloc::{boxed::Box, format, string::String, string::ToString};
use clonic_core::{EnvelopeRef, ResidencyTag};
use clonic_transport::transport::Transport;
use thiserror::Error;

/// Main router for zone enforcement and message routing.
pub struct Router {
    /// Local zone where this router is located
    local_zone: ResidencyTag,
    /// Local device ID
    local_device_id: [u8; 32],
    /// Peer registry for zone mapping
    #[cfg(feature = "alloc")]
    peer_registry: PeerRegistry,
    /// Policy engine for zone validation
    #[cfg(feature = "alloc")]
    policy_engine: PolicyEngine,
    /// Violation logger
    #[cfg(feature = "alloc")]
    violation_logger: ViolationLogger,
    /// Transport for message sending
    transport: Option<Box<dyn Transport>>,
}

/// Errors that can occur in the router.
#[derive(Debug, Error)]
pub enum RouterError {
    /// Transport not configured
    #[error("Transport not configured")]
    NoTransport,
    /// Invalid envelope format
    #[error("Invalid envelope format: {0}")]
    InvalidEnvelope(String),
    /// Zone policy violation
    #[error("Zone policy violation: {reason}")]
    PolicyViolation {
        /// Human-readable reason for the policy violation
        reason: String,
    },
    /// Peer not found
    #[error("Peer not found")]
    PeerNotFound,
    /// Transport error
    #[error("Transport error: {0}")]
    TransportError(String),
    /// Registry error
    #[error("Registry error: {0}")]
    RegistryError(String),
}

impl Router {
    /// Create a new router.
    pub fn new(local_zone: ResidencyTag, local_device_id: [u8; 32]) -> Self {
        Self {
            local_zone,
            local_device_id,
            #[cfg(feature = "alloc")]
            peer_registry: PeerRegistry::new(crate::registry::RegistryConfig::default()),
            #[cfg(feature = "alloc")]
            policy_engine: PolicyEngine::new(),
            #[cfg(feature = "alloc")]
            violation_logger: ViolationLogger::new(),
            transport: None,
        }
    }

    /// Set the transport for message sending.
    pub fn set_transport(&mut self, transport: Box<dyn Transport>) {
        self.transport = Some(transport);
    }

    /// Get the local zone.
    pub fn local_zone(&self) -> ResidencyTag {
        self.local_zone
    }

    /// Get the local device ID.
    pub fn local_device_id(&self) -> &[u8; 32] {
        &self.local_device_id
    }

    /// Route a message to its destination.
    pub fn route_message(&mut self, envelope: EnvelopeRef<'_>) -> Result<(), RouterError> {
        // Extract residency tag from envelope
        let residency_tag = envelope.residency_tag();

        // Get sender device ID
        let mut sender_device_id = [0u8; 32];
        sender_device_id.copy_from_slice(envelope.sender_device_id());

        // Validate residency tag compliance
        self.validate_residency(residency_tag, sender_device_id)?;

        // For now, accept the message locally (no forwarding)
        // In a full implementation, this would parse the payload to get destination
        // and determine if forwarding is needed
        tracing::debug!("Message accepted locally - forwarding not yet implemented");
        Ok(())
    }

    /// Validate residency tag compliance.
    #[cfg(feature = "alloc")]
    fn validate_residency(
        &mut self,
        residency_tag: ResidencyTag,
        sender_id: [u8; 32],
    ) -> Result<(), RouterError> {
        // Check if sender is allowed to send data with this residency tag
        if let Some(sender_info) = self.peer_registry.get_peer(&sender_id) {
            let (decision, reason) =
                self.policy_engine
                    .route_message(sender_info.zone, self.local_zone, "zcp_message");

            match decision {
                RoutingDecision::Allow => {
                    // Log successful validation
                    tracing::debug!("Residency validation passed: {:?}", reason);
                    Ok(())
                }
                RoutingDecision::Deny => {
                    // Log violation
                    let violation = Violation {
                        timestamp: self.get_current_timestamp(),
                        violation_type: ViolationType::ResidencyViolation,
                        source_device: sender_id,
                        source_zone: sender_info.zone,
                        dest_zone: self.local_zone,
                        residency_tag,
                        reason: format!("Policy denied: {:?}", reason),
                    };

                    self.violation_logger.log_violation(violation);

                    Err(RouterError::PolicyViolation {
                        reason: format!("Policy denied: {:?}", reason),
                    })
                }
                RoutingDecision::RouteVia(_) => {
                    // For now, treat as denied - would need to implement routing via intermediary
                    Err(RouterError::PolicyViolation {
                        reason: "Routing via intermediary not implemented".to_string(),
                    })
                }
            }
        } else {
            // Unknown sender - log as violation
            let violation = Violation {
                timestamp: self.get_current_timestamp(),
                violation_type: ViolationType::UnknownSender,
                source_device: sender_id,
                source_zone: ResidencyTag::GLOBAL, // Unknown
                dest_zone: self.local_zone,
                residency_tag,
                reason: "Unknown sender device".to_string(),
            };

            self.violation_logger.log_violation(violation);

            Err(RouterError::PeerNotFound)
        }
    }

    /// Select the next hop for message forwarding.
    #[cfg(feature = "alloc")]
    #[allow(dead_code)]
    fn select_next_hop(&self, _envelope: EnvelopeRef<'_>) -> Result<[u8; 32], RouterError> {
        // For now, implement simple forwarding
        // In a full implementation, this would use zone-aware routing tables

        // Get destination from envelope (would need to parse payload)
        // For now, just return an error to indicate not implemented
        Err(RouterError::PolicyViolation {
            reason: "Next hop selection not implemented".to_string(),
        })
    }

    /// Forward a message to the next hop.
    #[allow(dead_code)]
    fn forward_message(
        &mut self,
        envelope: EnvelopeRef<'_>,
        next_hop: [u8; 32],
    ) -> Result<(), RouterError> {
        if let Some(transport) = &mut self.transport {
            // Convert envelope to bytes and send
            let frame_bytes = envelope.as_bytes();

            transport
                .send(frame_bytes)
                .map_err(|e| RouterError::TransportError(format!("{:?}", e)))?;

            tracing::debug!("Message forwarded to next hop: {:?}", next_hop);
            Ok(())
        } else {
            Err(RouterError::NoTransport)
        }
    }

    /// Process an incoming message.
    pub fn process_incoming(&mut self, frame: &[u8]) -> Result<(), RouterError> {
        // Parse envelope
        let envelope = EnvelopeRef::parse(frame)
            .map_err(|e| RouterError::InvalidEnvelope(format!("{:?}", e)))?;

        // For now, process all messages locally
        // In a full implementation, this would:
        // 1. Parse the payload to extract destination device ID
        // 2. Check if the message is destined for this router
        // 3. If not for us, either forward or reject based on policy

        tracing::debug!(
            "Processing incoming message from {:?}",
            envelope.sender_device_id()
        );

        // Route the message
        self.route_message(envelope)
    }

    /// Register a peer with the router.
    #[cfg(feature = "alloc")]
    pub fn register_peer(&mut self, peer: PeerInfo) -> Result<(), RouterError> {
        self.peer_registry
            .register_peer(peer.clone())
            .map_err(|e| RouterError::RegistryError(format!("{:?}", e)))?;

        tracing::info!("Registered peer: {:?}", peer.device_id);
        Ok(())
    }

    /// Get peer registry reference.
    #[cfg(feature = "alloc")]
    pub fn peer_registry(&self) -> &PeerRegistry {
        &self.peer_registry
    }

    /// Get peer registry mutable reference.
    #[cfg(feature = "alloc")]
    pub fn peer_registry_mut(&mut self) -> &mut PeerRegistry {
        &mut self.peer_registry
    }

    /// Get policy engine reference.
    #[cfg(feature = "alloc")]
    pub fn policy_engine(&self) -> &PolicyEngine {
        &self.policy_engine
    }

    /// Get policy engine mutable reference.
    #[cfg(feature = "alloc")]
    pub fn policy_engine_mut(&mut self) -> &mut PolicyEngine {
        &mut self.policy_engine
    }

    /// Get violation logger reference.
    #[cfg(feature = "alloc")]
    pub fn violation_logger(&self) -> &ViolationLogger {
        &self.violation_logger
    }

    /// Get violation logger mutable reference.
    #[cfg(feature = "alloc")]
    pub fn violation_logger_mut(&mut self) -> &mut ViolationLogger {
        &mut self.violation_logger
    }

    /// Get current timestamp with proper error handling.
    #[cfg(feature = "std")]
    fn get_current_timestamp(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_else(|_| {
                tracing::warn!("System time is before UNIX epoch - using timestamp 0");
                std::time::Duration::from_secs(0)
            })
            .as_secs()
    }

    #[cfg(not(feature = "std"))]
    fn get_current_timestamp(&self) -> u64 {
        // In no_std environments, we can't get system time
        // This would need to be provided by the runtime
        0
    }

    /// Perform maintenance tasks (prune inactive peers, etc.).
    #[cfg(feature = "alloc")]
    pub fn maintenance(&mut self) {
        let current_time = self.get_current_timestamp();

        // Update policy engine time
        self.policy_engine.set_current_time(current_time);

        // Prune inactive peers
        let pruned = self.peer_registry.prune_inactive(current_time);
        if pruned > 0 {
            tracing::info!("Pruned {} inactive peers", pruned);
        }
    }
}

impl Default for Router {
    fn default() -> Self {
        Self::new(ResidencyTag::GLOBAL, [0u8; 32])
    }
}

#[cfg(feature = "alloc")]
impl core::fmt::Debug for Router {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Router")
            .field("local_zone", &self.local_zone)
            .field("local_device_id", &hex::encode(self.local_device_id))
            .field("peer_count", &self.peer_registry.peer_count())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "alloc")]
    use alloc::{string::ToString, vec, vec::Vec};
    use clonic_transport::transport::MockTransport;

    #[test]
    fn test_router_creation() {
        let router = Router::new(ResidencyTag::INDONESIA, [1u8; 32]);

        assert_eq!(router.local_zone(), ResidencyTag::INDONESIA);
        assert_eq!(router.local_device_id(), &[1u8; 32]);
    }

    #[test]
    fn test_transport_set() {
        let mut router = Router::new(ResidencyTag::INDONESIA, [1u8; 32]);
        let transport = Box::new(MockTransport::with_incoming(Vec::new()));

        router.set_transport(transport);
        // Transport is now set - would test actual forwarding in integration tests
    }

    #[test]
    fn test_peer_registration() {
        #[cfg(feature = "alloc")]
        {
            let mut router = Router::new(ResidencyTag::INDONESIA, [1u8; 32]);

            let peer = PeerInfo {
                device_id: [2u8; 32],
                zone: ResidencyTag::MALAYSIA,
                address: crate::registry::PeerAddress::Tcp("127.0.0.1:8080".to_string()),
                last_seen: 12345,
                metadata: crate::registry::PeerMetadata {
                    version: "1.0.0".to_string(),
                    crypto_suites: vec![1],
                    max_payload: 1024,
                    peer_type: crate::registry::PeerType::FullNode,
                    attributes: alloc::collections::BTreeMap::new(),
                },
            };

            assert!(router.register_peer(peer).is_ok());
            assert_eq!(router.peer_registry().peer_count(), 1);
        }
    }

    #[test]
    fn test_invalid_envelope() {
        let mut router = Router::new(ResidencyTag::INDONESIA, [1u8; 32]);

        let invalid_frame = &[0u8; 10]; // Too short for ZCP envelope

        let result = router.process_incoming(invalid_frame);
        assert!(matches!(result, Err(RouterError::InvalidEnvelope(_))));
    }
}
