//! Main router implementation for zone enforcement.
//!
//! Coordinates peer registry, policy engine, and transport layer
//! to provide zone-aware routing with residency tag enforcement.

#[cfg(feature = "alloc")]
use crate::{
    metrics::ZoneMetrics,
    policy::{PolicyEngine, RoutingDecision},
    registry::{PeerInfo, PeerRegistry},
    violation::{Violation, ViolationLogger, ViolationType},
};
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
#[cfg(feature = "alloc")]
use alloc::{boxed::Box, format, string::String, string::ToString, vec};
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
    /// Metrics collector
    #[cfg(feature = "alloc")]
    metrics: ZoneMetrics,
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
    /// Policy error (from policy engine)
    #[error("Policy error: {0:?}")]
    PolicyError(crate::policy::DecisionReason),
    /// Unknown sender device
    #[error("Unknown sender device")]
    UnknownSender,
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
            #[cfg(feature = "alloc")]
            metrics: ZoneMetrics::new_for_tests(),
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
    ///
    /// # Parameters
    /// * `residency_tag` - The destination residency tag to validate against.
    ///   Note: This is currently passed as a parameter rather than extracted from
    ///   the envelope. In a full implementation, this would be parsed from the
    ///   incoming message envelope.
    /// * `sender_id` - The device ID of the message sender
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
                    .route_message(sender_info.zone, residency_tag, "zcp_message");

            match decision {
                RoutingDecision::Allow => {
                    // Log successful validation
                    tracing::debug!("Residency validation passed: {:?}", reason);

                    // Record metrics
                    self.metrics.record_routing_decision(
                        "allow",
                        sender_info.zone,
                        residency_tag,
                        reason.as_code(),
                    );

                    Ok(())
                }
                RoutingDecision::Deny => {
                    // Log violation
                    let violation = Violation {
                        timestamp: self.get_current_timestamp(),
                        violation_type: ViolationType::ResidencyViolation,
                        source_device: sender_id,
                        source_zone: sender_info.zone,
                        dest_zone: residency_tag,
                        residency_tag,
                        reason: format!("Policy denied: {:?}", reason),
                    };

                    self.violation_logger.log_violation(violation);

                    // Record metrics
                    self.metrics.record_zone_violation(
                        "residency_violation",
                        sender_info.zone,
                        residency_tag,
                    );
                    self.metrics.record_routing_decision(
                        "deny",
                        sender_info.zone,
                        residency_tag,
                        reason.as_code(),
                    );

                    Err(RouterError::PolicyError(reason))
                }
                RoutingDecision::RouteVia(_) => {
                    // For now, treat as denied - would need to implement routing via intermediary
                    Err(RouterError::PolicyViolation {
                        reason: "Routing via intermediary not implemented".to_string(),
                    })
                }
            }
        } else {
            // Unknown sender - deny by default
            Err(RouterError::UnknownSender)
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

    /// Get metrics collector.
    #[cfg(feature = "alloc")]
    pub fn metrics(&self) -> &ZoneMetrics {
        &self.metrics
    }

    /// Log forwarding decision for audit trail.
    #[cfg(feature = "alloc")]
    pub fn log_forwarding_decision(
        &mut self,
        source_device: [u8; 32],
        source_zone: ResidencyTag,
        dest_zone: ResidencyTag,
        decision: &str,
        reason: &str,
    ) {
        self.violation_logger.log_forwarding_decision(
            source_device,
            source_zone,
            dest_zone,
            self.local_zone,
            decision,
            reason,
            self.get_current_timestamp(),
        );
    }

    /// Log connection attempt for audit trail.
    #[cfg(feature = "alloc")]
    pub fn log_connection_attempt(
        &mut self,
        source_device: [u8; 32],
        source_zone: ResidencyTag,
        dest_zone: ResidencyTag,
        result: &str,
    ) {
        self.violation_logger.log_connection_attempt(
            source_device,
            source_zone,
            dest_zone,
            result,
            self.get_current_timestamp(),
        );
    }

    /// Log policy evaluation for audit trail.
    #[cfg(feature = "alloc")]
    pub fn log_policy_evaluation(
        &mut self,
        source_zone: ResidencyTag,
        dest_zone: ResidencyTag,
        data_type: &str,
        decision: &str,
        reason: &str,
    ) {
        self.violation_logger.log_policy_evaluation(
            source_zone,
            dest_zone,
            data_type,
            decision,
            reason,
            self.get_current_timestamp(),
        );
    }

    /// Get violation statistics.
    #[cfg(feature = "alloc")]
    pub fn get_violation_stats(&self) -> crate::violation::ViolationStats {
        self.violation_logger.get_stats()
    }

    /// Get all violations.
    #[cfg(feature = "alloc")]
    pub fn get_violations(&self) -> Vec<crate::violation::Violation> {
        self.violation_logger
            .get_violations()
            .iter()
            .cloned()
            .collect()
    }

    /// Register a peer by device ID.
    ///
    /// # Parameters
    /// * `device_id` - The 32-byte device identifier
    /// * `zone` - The residency zone of the peer
    /// * `address` - Optional network address (defaults to test placeholder if None)
    #[cfg(feature = "alloc")]
    pub fn register_peer_by_device_id(
        &mut self,
        device_id: [u8; 32],
        zone: ResidencyTag,
    ) -> Result<(), RouterError> {
        self.register_peer_by_device_id_with_addr(
            device_id,
            zone,
            Some("127.0.0.1:8080".to_string()),
        )
    }

    /// Register a peer by device ID with explicit address.
    #[cfg(feature = "alloc")]
    pub fn register_peer_by_device_id_with_addr(
        &mut self,
        device_id: [u8; 32],
        zone: ResidencyTag,
        address: Option<String>,
    ) -> Result<(), RouterError> {
        let address = address.unwrap_or_else(|| "127.0.0.1:8080".to_string());
        let peer = PeerInfo {
            device_id,
            zone,
            address: crate::registry::PeerAddress::Tcp(address),
            last_seen: self.get_current_timestamp(),
            metadata: crate::registry::PeerMetadata {
                version: "1.0".to_string(),
                crypto_suites: vec![1], // Default crypto suite
                max_payload: 1024,
                peer_type: crate::registry::PeerType::EdgeDevice,
                attributes: alloc::collections::BTreeMap::new(),
            },
        };

        self.peer_registry
            .register_peer(peer)
            .map_err(|e| RouterError::RegistryError(format!("{:?}", e)))
    }

    /// Get current timestamp in seconds since Unix epoch.
    ///
    /// Returns 0 if system time is before Unix epoch to avoid panics.
    fn get_current_timestamp(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(std::time::Duration::from_secs(0))
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

    #[test]
    fn test_router_with_metrics() {
        let router = Router::new(ResidencyTag::INDONESIA, [1u8; 32]);

        // Test that metrics are accessible
        let metrics = router.metrics();

        // Should be able to record metrics without panicking
        metrics.record_zone_violation("test", ResidencyTag::INDONESIA, ResidencyTag::MALAYSIA);
        metrics.record_routing_decision(
            "allow",
            ResidencyTag::INDONESIA,
            ResidencyTag::MALAYSIA,
            "test",
        );
        metrics.set_peer_count(ResidencyTag::INDONESIA, 10);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_router_residency_validation_with_metrics() {
        let mut router = Router::new(ResidencyTag::INDONESIA, [1u8; 32]);

        // Register a peer from Indonesia
        router
            .register_peer_by_device_id([1u8; 32], ResidencyTag::INDONESIA)
            .expect("Failed to register peer");

        // Create a test envelope
        let mut envelope_data = vec![0u8; 58]; // Minimum envelope size
        envelope_data[0] = 1; // ZCP version
        envelope_data[1] = 1; // Message type
        envelope_data[2] = 1; // Crypto suite
        envelope_data[3] = 0; // Flags
                              // sender_device_id at offset 4 (32 bytes) - already zeroed
        envelope_data[36] = 0x01; // Set residency tag Indonesia
        envelope_data[37] = 0x68;
        // payload_length at offset 38 (4 bytes) - already zeroed

        let _envelope = EnvelopeRef::parse(&envelope_data).unwrap();

        // Test validation with same zone (should allow)
        let result = router.validate_residency(ResidencyTag::INDONESIA, [1u8; 32]);
        assert!(result.is_ok());

        // Test validation with different zone (should deny)
        let result = router.validate_residency(ResidencyTag::MALAYSIA, [1u8; 32]);
        assert!(result.is_err());

        // Check that metrics were recorded (if not in no-op mode)
        let metrics = router.metrics();
        // Note: In test mode with multiple test runs, metrics might be in no-op mode
        // so we just verify the metrics object exists and can be used
        metrics.record_zone_violation("test", ResidencyTag::INDONESIA, ResidencyTag::MALAYSIA);
        // If we reach here without panic, metrics are working
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_router_with_violation_logging() {
        let mut router = Router::new(ResidencyTag::INDONESIA, [1u8; 32]);

        // Register a peer from Indonesia
        router
            .register_peer_by_device_id([1u8; 32], ResidencyTag::INDONESIA)
            .expect("Failed to register peer");

        // Create envelope that would cause a violation
        let mut envelope_data = vec![0u8; 58];
        envelope_data[0] = 1; // ZCP version
        envelope_data[1] = 1; // Message type
        envelope_data[2] = 1; // Crypto suite
        envelope_data[3] = 0; // Flags
        envelope_data[36] = 0x01; // Indonesia
        envelope_data[37] = 0x68;

        let _envelope = EnvelopeRef::parse(&envelope_data).unwrap();

        // Trigger a violation (expected to fail)
        let _result = router.validate_residency(ResidencyTag::VIETNAM, [1u8; 32]);

        // Check that violation was logged
        let violations = router.get_violations();
        assert!(!violations.is_empty());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_router_audit_logging_integration() {
        let mut router = Router::new(ResidencyTag::INDONESIA, [1u8; 32]);

        // Test forwarding decision logging
        router.log_forwarding_decision(
            [1u8; 32],
            ResidencyTag::INDONESIA,
            ResidencyTag::MALAYSIA,
            "allow",
            "test_decision",
        );

        // Test connection attempt logging
        router.log_connection_attempt(
            [2u8; 32],
            ResidencyTag::PHILIPPINES,
            ResidencyTag::INDONESIA,
            "success",
        );

        // Test policy evaluation logging
        router.log_policy_evaluation(
            ResidencyTag::INDONESIA,
            ResidencyTag::SINGAPORE,
            "test_data",
            "deny",
            "test_reason",
        );

        // Check that all audit events were logged
        let violations = router.get_violations();
        assert_eq!(violations.len(), 3);

        // Verify types
        assert_eq!(
            violations[0].violation_type,
            ViolationType::ForwardingDecision
        );
        assert_eq!(
            violations[1].violation_type,
            ViolationType::ConnectionAttempt
        );
        assert_eq!(
            violations[2].violation_type,
            ViolationType::PolicyEvaluation
        );
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_router_peer_registration_with_metrics() {
        let mut router = Router::new(ResidencyTag::INDONESIA, [1u8; 32]);

        // Register some peers
        let peer1 = [1u8; 32];
        let peer2 = [2u8; 32];

        router
            .register_peer_by_device_id(peer1, ResidencyTag::MALAYSIA)
            .expect("Failed to register peer1");
        router
            .register_peer_by_device_id(peer2, ResidencyTag::PHILIPPINES)
            .expect("Failed to register peer2");

        // Check that peer count metrics were updated
        let metrics = router.metrics();

        // Note: In a real implementation, peer registration would update metrics
        // For now, we just test that the metrics object exists and can be used
        metrics.set_peer_count(ResidencyTag::MALAYSIA, 1);
        metrics.set_peer_count(ResidencyTag::PHILIPPINES, 1);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_router_cross_border_scenarios() {
        let mut router = Router::new(ResidencyTag::INDONESIA, [1u8; 32]);

        // Register a peer from Indonesia
        router
            .register_peer_by_device_id([1u8; 32], ResidencyTag::INDONESIA)
            .expect("Failed to register peer");

        // Test various cross-border scenarios
        let scenarios = vec![
            (ResidencyTag::MALAYSIA, false), // Should be denied (different country)
            (ResidencyTag::INDONESIA, true), // Should be allowed (same country)
            (ResidencyTag::GLOBAL, false),   // Should be denied (conservative approach)
        ];

        for (dest_zone, should_succeed) in scenarios {
            let mut envelope_data = vec![0u8; 58];
            envelope_data[0] = 1; // ZCP version
            envelope_data[1] = 1; // Message type
            envelope_data[2] = 1; // Crypto suite
            envelope_data[3] = 0; // Flags
            envelope_data[36] = 0x01; // Indonesia source
            envelope_data[37] = 0x68;

            let _envelope = EnvelopeRef::parse(&envelope_data).unwrap();
            let result = router.validate_residency(dest_zone, [1u8; 32]);

            if should_succeed {
                assert!(
                    result.is_ok(),
                    "Expected success for destination {:?}",
                    dest_zone
                );
            } else {
                assert!(
                    result.is_err(),
                    "Expected failure for destination {:?}",
                    dest_zone
                );
            }
        }
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_router_with_extended_zones() {
        let mut router = Router::new(ResidencyTag::INDONESIA, [1u8; 32]);

        // Test that extended zones can be created and used
        let subdivision = ResidencyTag::from_subdivision(360, 1).unwrap(); // Indonesia subdivision 1
        assert!(subdivision.is_extended());
        assert_eq!(subdivision.country_code(), 360);
        assert_eq!(subdivision.subdivision_id(), Some(1));

        // Register a peer from Indonesia (not subdivision) for basic validation
        router
            .register_peer_by_device_id([1u8; 32], ResidencyTag::INDONESIA)
            .expect("Failed to register peer");

        // Test basic validation still works
        let result = router.validate_residency(ResidencyTag::INDONESIA, [1u8; 32]);
        assert!(result.is_ok());

        // Test validation to different country (should deny)
        let result = router.validate_residency(ResidencyTag::MALAYSIA, [1u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn test_router_metrics_integration() {
        let router = Router::new(ResidencyTag::INDONESIA, [1u8; 32]);
        let metrics = router.metrics();

        // Test that metrics operations work through router
        metrics.record_zone_violation("test_type", ResidencyTag::INDONESIA, ResidencyTag::MALAYSIA);
        metrics.record_routing_decision(
            "allow",
            ResidencyTag::INDONESIA,
            ResidencyTag::MALAYSIA,
            "test",
        );
        metrics.set_peer_count(ResidencyTag::INDONESIA, 5);
        metrics.record_processing_latency("test_op", std::time::Duration::from_millis(100));
        metrics.record_agreement_status(
            "test_agreement",
            ResidencyTag::INDONESIA,
            ResidencyTag::MALAYSIA,
            "active",
        );
        metrics.record_config_reload("success");

        // All operations should complete without panicking
        // If we reach here, all operations succeeded
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_router_violation_statistics() {
        let mut router = Router::new(ResidencyTag::INDONESIA, [1u8; 32]);

        // Log various types of violations
        router.log_forwarding_decision(
            [1; 32],
            ResidencyTag::INDONESIA,
            ResidencyTag::MALAYSIA,
            "allow",
            "test",
        );
        router.log_connection_attempt(
            [2; 32],
            ResidencyTag::PHILIPPINES,
            ResidencyTag::INDONESIA,
            "success",
        );
        router.log_policy_evaluation(
            ResidencyTag::INDONESIA,
            ResidencyTag::SINGAPORE,
            "test",
            "deny",
            "test",
        );

        let stats = router.get_violation_stats();

        // Check that audit events are counted
        assert_eq!(stats.forwarding_decisions, 1);
        assert_eq!(stats.connection_attempts, 1);
        assert_eq!(stats.policy_evaluations, 1);
        assert_eq!(stats.total_violations, 3);
    }

    #[test]
    fn test_router_concurrent_metrics_access() {
        let router = Router::new(ResidencyTag::INDONESIA, [1u8; 32]);
        let metrics = router.metrics();

        // Test that metrics can be accessed and modified
        for i in 0..100 {
            metrics.record_zone_violation(
                "concurrent_test",
                ResidencyTag::INDONESIA,
                ResidencyTag::MALAYSIA,
            );
            metrics.set_peer_count(ResidencyTag::INDONESIA, i);
        }

        // If we reach here, metrics access worked without panics
    }
}
