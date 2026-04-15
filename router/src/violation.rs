//! Violation logging and audit trail for zone enforcement.
//!
//! Records all policy violations and routing decisions for
//! compliance auditing and security monitoring.

#[cfg(feature = "alloc")]
use alloc::collections::VecDeque;
#[cfg(feature = "alloc")]
use alloc::{format, string::String, vec::Vec};
use clonic_core::ResidencyTag;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "std")]
use std::eprintln;

/// Type of zone policy violation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ViolationType {
    /// Data residency violation
    ResidencyViolation,
    /// Unknown sender device
    UnknownSender,
    /// Invalid envelope format
    InvalidEnvelope,
    /// Transport error
    TransportError,
    /// Policy configuration error
    PolicyError,
    /// Forwarding decision (for audit trail)
    ForwardingDecision,
    /// Connection attempt
    ConnectionAttempt,
    /// Policy evaluation
    PolicyEvaluation,
    /// Invalid residency tag
    InvalidResidencyTag,
    /// Unauthorized cross-border data transfer
    UnauthorizedCrossBorder,
    /// Data exfiltration attempt
    DataExfiltration,
    /// Transport layer violation
    TransportViolation,
}

/// A recorded policy violation.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Violation {
    /// Timestamp when the violation occurred
    pub timestamp: u64,
    /// Type of violation
    pub violation_type: ViolationType,
    /// Source device ID
    pub source_device: [u8; 32],
    /// Source zone
    pub source_zone: ResidencyTag,
    /// Destination zone
    pub dest_zone: ResidencyTag,
    /// Residency tag from the message
    pub residency_tag: ResidencyTag,
    /// Human-readable reason
    pub reason: String,
}

/// Logger for policy violations and routing decisions.
#[derive(Debug)]
#[cfg(feature = "alloc")]
pub struct ViolationLogger {
    /// In-memory violation log
    violations: VecDeque<Violation>,
    /// Maximum number of violations to keep in memory
    max_violations: usize,
    /// Whether to log to stderr
    log_to_stderr: bool,
    /// Whether to log to file (if configured)
    log_to_file: bool,
    /// File path for logging (if enabled)
    log_file_path: Option<String>,
}

#[cfg(feature = "alloc")]
impl ViolationLogger {
    /// Create a new violation logger.
    pub fn new() -> Self {
        Self {
            violations: VecDeque::new(),
            max_violations: 10000,
            log_to_stderr: true,
            log_to_file: false,
            log_file_path: None,
        }
    }

    /// Set maximum violations to keep in memory.
    pub fn set_max_violations(&mut self, max: usize) {
        self.max_violations = max;
        if self.violations.len() > max {
            // Keep the most recent violations (remove from front)
            let excess = self.violations.len() - max;
            self.violations.drain(0..excess);
            tracing::debug!(
                "Truncated {} old violations to maintain max of {}",
                excess,
                max
            );
        }
    }

    /// Enable/disable stderr logging.
    pub fn set_log_to_stderr(&mut self, enabled: bool) {
        self.log_to_stderr = enabled;
    }

    /// Enable file logging with specified path.
    ///
    /// TODO: Implement actual file I/O with log rotation and size limits.
    /// Current implementation only logs to stderr with file path prefix.
    /// For production use, this should:
    /// - Write to actual files with proper locking
    /// - Implement log rotation (by size or time)
    /// - Handle disk full scenarios gracefully
    pub fn set_log_file(&mut self, path: String) {
        self.log_file_path = Some(path);
        self.log_to_file = true;
    }

    /// Log a policy violation.
    pub fn log_violation(&mut self, violation: Violation) {
        // Add to in-memory log
        self.violations.push_back(violation.clone());

        // Trim if over limit
        if self.violations.len() > self.max_violations {
            self.violations.pop_front();
        }

        // Log to stderr if enabled
        if self.log_to_stderr {
            eprintln!("VIOLATION: {}", self.format_violation(&violation));
        }

        // Log to file if enabled
        if self.log_to_file {
            if let Some(path) = &self.log_file_path {
                // In a real implementation, this would write to file
                // For now, just log to stderr
                eprintln!("FILE LOG [{}]: {}", path, self.format_violation(&violation));
            }
        }
    }

    /// Log a forwarding decision for audit purposes.
    #[cfg(feature = "alloc")]
    #[allow(clippy::too_many_arguments)]
    pub fn log_forwarding_decision(
        &mut self,
        source_device: [u8; 32],
        source_zone: ResidencyTag,
        dest_zone: ResidencyTag,
        residency_tag: ResidencyTag,
        decision: &str,
        reason: &str,
        timestamp: u64,
    ) {
        let violation = Violation {
            timestamp,
            violation_type: ViolationType::ForwardingDecision,
            source_device,
            source_zone,
            dest_zone,
            residency_tag,
            reason: format!("Decision: {} - Reason: {}", decision, reason),
        };

        self.log_violation(violation);
    }

    /// Log a connection attempt.
    #[cfg(feature = "alloc")]
    pub fn log_connection_attempt(
        &mut self,
        source_device: [u8; 32],
        source_zone: ResidencyTag,
        dest_zone: ResidencyTag,
        result: &str,
        timestamp: u64,
    ) {
        let violation = Violation {
            timestamp,
            violation_type: ViolationType::ConnectionAttempt,
            source_device,
            source_zone,
            dest_zone,
            residency_tag: ResidencyTag::GLOBAL, // Not applicable for connections
            reason: format!("Connection result: {}", result),
        };

        self.log_violation(violation);
    }

    /// Log a policy evaluation.
    #[cfg(feature = "alloc")]
    pub fn log_policy_evaluation(
        &mut self,
        source_zone: ResidencyTag,
        dest_zone: ResidencyTag,
        data_type: &str,
        decision: &str,
        reason: &str,
        timestamp: u64,
    ) {
        let violation = Violation {
            timestamp,
            violation_type: ViolationType::PolicyEvaluation,
            source_device: [0u8; 32], // Not applicable for policy evaluations
            source_zone,
            dest_zone,
            residency_tag: ResidencyTag::GLOBAL, // Not applicable
            reason: format!(
                "Data: {} - Decision: {} - Reason: {}",
                data_type, decision, reason
            ),
        };

        self.log_violation(violation);
    }

    /// Get all violations.
    pub fn get_violations(&self) -> &VecDeque<Violation> {
        &self.violations
    }

    /// Get violations by type.
    pub fn get_violations_by_type(&self, violation_type: ViolationType) -> Vec<&Violation> {
        self.violations
            .iter()
            .filter(|v| v.violation_type == violation_type)
            .collect()
    }

    /// Get violations by source device.
    pub fn get_violations_by_source(&self, source_device: &[u8; 32]) -> Vec<&Violation> {
        self.violations
            .iter()
            .filter(|v| v.source_device == *source_device)
            .collect()
    }

    /// Get violations by zone.
    pub fn get_violations_by_zone(&self, zone: ResidencyTag) -> Vec<&Violation> {
        self.violations
            .iter()
            .filter(|v| v.source_zone == zone || v.dest_zone == zone)
            .collect()
    }

    /// Get violations in a time range.
    pub fn get_violations_in_range(&self, start: u64, end: u64) -> Vec<&Violation> {
        self.violations
            .iter()
            .filter(|v| v.timestamp >= start && v.timestamp <= end)
            .collect()
    }

    /// Clear all violations.
    pub fn clear_violations(&mut self) {
        self.violations.clear();
    }

    /// Get violation statistics.
    pub fn get_stats(&self) -> ViolationStats {
        let mut stats = ViolationStats::default();

        for violation in &self.violations {
            stats.total_violations += 1;

            match violation.violation_type {
                ViolationType::ResidencyViolation => stats.residency_violations += 1,
                ViolationType::UnknownSender => stats.unknown_sender_violations += 1,
                ViolationType::InvalidEnvelope => stats.invalid_envelope_violations += 1,
                ViolationType::TransportError => stats.transport_errors += 1,
                ViolationType::PolicyError => stats.policy_errors += 1,
                ViolationType::ForwardingDecision => stats.forwarding_decisions += 1,
                ViolationType::ConnectionAttempt => stats.connection_attempts += 1,
                ViolationType::PolicyEvaluation => stats.policy_evaluations += 1,
                ViolationType::InvalidResidencyTag => stats.invalid_tag_violations += 1,
                ViolationType::UnauthorizedCrossBorder => stats.cross_border_violations += 1,
                ViolationType::DataExfiltration => stats.exfiltration_violations += 1,
                ViolationType::TransportViolation => stats.transport_violations += 1,
            }
        }

        if !self.violations.is_empty() {
            stats.oldest_violation = self.violations[0].timestamp;
            stats.newest_violation = self.violations[self.violations.len() - 1].timestamp;
        }

        stats
    }

    /// Format a violation for logging.
    fn format_violation(&self, violation: &Violation) -> String {
        format!(
            "[{}] {} from {:?} ({}) to {:?} - {}",
            violation.timestamp,
            match violation.violation_type {
                ViolationType::ResidencyViolation => "RESIDENCY_VIOLATION",
                ViolationType::UnknownSender => "UNKNOWN_SENDER",
                ViolationType::InvalidEnvelope => "INVALID_ENVELOPE",
                ViolationType::TransportError => "TRANSPORT_ERROR",
                ViolationType::PolicyError => "POLICY_ERROR",
                ViolationType::ForwardingDecision => "FORWARDING_DECISION",
                ViolationType::ConnectionAttempt => "CONNECTION_ATTEMPT",
                ViolationType::PolicyEvaluation => "POLICY_EVALUATION",
                ViolationType::InvalidResidencyTag => "INVALID_TAG",
                ViolationType::UnauthorizedCrossBorder => "UNAUTHORIZED_CROSS_BORDER",
                ViolationType::DataExfiltration => "DATA_EXFILTRATION",
                ViolationType::TransportViolation => "TRANSPORT_VIOLATION",
            },
            hex::encode(violation.source_device),
            violation.source_zone,
            violation.dest_zone,
            violation.reason
        )
    }
}

impl Default for ViolationLogger {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about violations.
#[derive(Debug, Default, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ViolationStats {
    /// Total number of violations
    pub total_violations: u64,
    /// Residency violations
    pub residency_violations: u64,
    /// Unknown sender violations
    pub unknown_sender_violations: u64,
    /// Invalid envelope violations
    pub invalid_envelope_violations: u64,
    /// Transport errors
    pub transport_errors: u64,
    /// Policy errors
    pub policy_errors: u64,
    /// Forwarding decisions (audit)
    pub forwarding_decisions: u64,
    /// Connection attempts (audit)
    pub connection_attempts: u64,
    /// Policy evaluations (audit)
    pub policy_evaluations: u64,
    /// Invalid tag violations
    pub invalid_tag_violations: u64,
    /// Cross-border violations
    pub cross_border_violations: u64,
    /// Exfiltration violations
    pub exfiltration_violations: u64,
    /// Transport violations
    pub transport_violations: u64,
    /// Oldest violation timestamp
    pub oldest_violation: u64,
    /// Newest violation timestamp
    pub newest_violation: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "alloc")]
    use alloc::{string::ToString, vec};

    #[test]
    fn test_violation_logging() {
        #[cfg(feature = "alloc")]
        {
            let mut logger = ViolationLogger::new();

            let violation = Violation {
                timestamp: 12345,
                violation_type: ViolationType::ResidencyViolation,
                source_device: [1u8; 32],
                source_zone: ResidencyTag::INDONESIA,
                dest_zone: ResidencyTag::MALAYSIA,
                residency_tag: ResidencyTag::INDONESIA,
                reason: "Policy denied cross-border transfer".to_string(),
            };

            logger.log_violation(violation.clone());

            let violations = logger.get_violations();
            assert_eq!(violations.len(), 1);
            assert_eq!(
                violations[0].violation_type,
                ViolationType::ResidencyViolation
            );
            assert_eq!(violations[0].source_device, [1u8; 32]);
        }
    }

    #[test]
    fn test_violation_filtering() {
        #[cfg(feature = "alloc")]
        {
            let mut logger = ViolationLogger::new();

            // Add violations of different types
            logger.log_violation(Violation {
                timestamp: 1000,
                violation_type: ViolationType::ResidencyViolation,
                source_device: [1u8; 32],
                source_zone: ResidencyTag::INDONESIA,
                dest_zone: ResidencyTag::MALAYSIA,
                residency_tag: ResidencyTag::INDONESIA,
                reason: "Test violation 1".to_string(),
            });

            logger.log_violation(Violation {
                timestamp: 2000,
                violation_type: ViolationType::UnknownSender,
                source_device: [2u8; 32],
                source_zone: ResidencyTag::GLOBAL,
                dest_zone: ResidencyTag::INDONESIA,
                residency_tag: ResidencyTag::GLOBAL,
                reason: "Test violation 2".to_string(),
            });

            // Test filtering by type
            let residency_violations =
                logger.get_violations_by_type(ViolationType::ResidencyViolation);
            assert_eq!(residency_violations.len(), 1);

            let unknown_violations = logger.get_violations_by_type(ViolationType::UnknownSender);
            assert_eq!(unknown_violations.len(), 1);

            // Test filtering by source
            let source1_violations = logger.get_violations_by_source(&[1u8; 32]);
            assert_eq!(source1_violations.len(), 1);

            // Test filtering by time range
            let range_violations = logger.get_violations_in_range(1500, 2500);
            assert_eq!(range_violations.len(), 1);
        }
    }

    #[test]
    fn test_violation_stats() {
        #[cfg(feature = "alloc")]
        {
            let mut logger = ViolationLogger::new();

            // Add some violations
            logger.log_violation(Violation {
                timestamp: 1000,
                violation_type: ViolationType::ResidencyViolation,
                source_device: [1u8; 32],
                source_zone: ResidencyTag::INDONESIA,
                dest_zone: ResidencyTag::MALAYSIA,
                residency_tag: ResidencyTag::INDONESIA,
                reason: "Test violation 1".to_string(),
            });

            logger.log_violation(Violation {
                timestamp: 2000,
                violation_type: ViolationType::UnknownSender,
                source_device: [2u8; 32],
                source_zone: ResidencyTag::GLOBAL,
                dest_zone: ResidencyTag::INDONESIA,
                residency_tag: ResidencyTag::GLOBAL,
                reason: "Test violation 2".to_string(),
            });

            let stats = logger.get_stats();
            assert_eq!(stats.total_violations, 2);
            assert_eq!(stats.residency_violations, 1);
            assert_eq!(stats.unknown_sender_violations, 1);
            assert_eq!(stats.oldest_violation, 1000);
            assert_eq!(stats.newest_violation, 2000);
        }
    }

    #[test]
    fn test_max_violations_limit() {
        #[cfg(feature = "alloc")]
        {
            let mut logger = ViolationLogger::new();
            logger.set_max_violations(2);

            // Add 3 violations
            for i in 0..3 {
                logger.log_violation(Violation {
                    timestamp: i as u64,
                    violation_type: ViolationType::ResidencyViolation,
                    source_device: [i as u8; 32],
                    source_zone: ResidencyTag::INDONESIA,
                    dest_zone: ResidencyTag::MALAYSIA,
                    residency_tag: ResidencyTag::INDONESIA,
                    reason: format!("Test violation {}", i),
                });
            }

            // Should only keep the last 2
            assert_eq!(logger.get_violations().len(), 2);
            assert_eq!(logger.get_violations()[0].timestamp, 1);
            assert_eq!(logger.get_violations()[1].timestamp, 2);
        }
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_audit_logging_forwarding_decisions() {
        let mut logger = ViolationLogger::new();

        let source_device = [1u8; 32];
        let timestamp = 1234567890;

        // Test various forwarding decisions
        logger.log_forwarding_decision(
            source_device,
            ResidencyTag::INDONESIA,
            ResidencyTag::MALAYSIA,
            ResidencyTag::INDONESIA,
            "allow",
            "policy_allowed",
            timestamp,
        );

        logger.log_forwarding_decision(
            source_device,
            ResidencyTag::INDONESIA,
            ResidencyTag::VIETNAM,
            ResidencyTag::INDONESIA,
            "deny",
            "cross_border_denied",
            timestamp + 1,
        );

        let violations = logger.get_violations();
        assert_eq!(violations.len(), 2);

        // Check first violation (allow)
        let first_violation = &violations[0];
        assert_eq!(
            first_violation.violation_type,
            ViolationType::ForwardingDecision
        );
        assert_eq!(first_violation.source_zone, ResidencyTag::INDONESIA);
        assert_eq!(first_violation.dest_zone, ResidencyTag::MALAYSIA);
        assert!(first_violation.reason.contains("Decision: allow"));
        assert!(first_violation.reason.contains("Reason: policy_allowed"));

        // Check second violation (deny)
        let second_violation = &violations[1];
        assert_eq!(
            second_violation.violation_type,
            ViolationType::ForwardingDecision
        );
        assert_eq!(second_violation.source_zone, ResidencyTag::INDONESIA);
        assert_eq!(second_violation.dest_zone, ResidencyTag::VIETNAM);
        assert!(second_violation.reason.contains("Decision: deny"));
        assert!(second_violation
            .reason
            .contains("Reason: cross_border_denied"));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_audit_logging_connection_attempts() {
        let mut logger = ViolationLogger::new();

        let source_device = [2u8; 32];
        let timestamp = 1234567890;

        // Test various connection results
        logger.log_connection_attempt(
            source_device,
            ResidencyTag::PHILIPPINES,
            ResidencyTag::INDONESIA,
            "success",
            timestamp,
        );

        logger.log_connection_attempt(
            source_device,
            ResidencyTag::PHILIPPINES,
            ResidencyTag::VIETNAM,
            "denied",
            timestamp + 1,
        );

        logger.log_connection_attempt(
            source_device,
            ResidencyTag::PHILIPPINES,
            ResidencyTag::SINGAPORE,
            "timeout",
            timestamp + 2,
        );

        let violations = logger.get_violations();
        assert_eq!(violations.len(), 3);

        for (i, violation) in violations.iter().enumerate() {
            assert_eq!(violation.violation_type, ViolationType::ConnectionAttempt);
            assert_eq!(violation.source_zone, ResidencyTag::PHILIPPINES);
            assert_eq!(violation.residency_tag, ResidencyTag::GLOBAL); // Not applicable for connections
            assert!(violation.reason.contains("Connection result:"));

            let expected_results = ["success", "denied", "timeout"];
            assert!(violation.reason.contains(expected_results[i]));
        }
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_audit_logging_policy_evaluations() {
        let mut logger = ViolationLogger::new();

        let timestamp = 1234567890;

        // Test various policy evaluations
        logger.log_policy_evaluation(
            ResidencyTag::INDONESIA,
            ResidencyTag::MALAYSIA,
            "zcp_message",
            "allow",
            "same_zone_allowed",
            timestamp,
        );

        logger.log_policy_evaluation(
            ResidencyTag::INDONESIA,
            ResidencyTag::VIETNAM,
            "zcp_control",
            "deny",
            "no_agreement",
            timestamp + 1,
        );

        logger.log_policy_evaluation(
            ResidencyTag::SINGAPORE,
            ResidencyTag::PHILIPPINES,
            "zcp_data",
            "allow",
            "agreement_active",
            timestamp + 2,
        );

        let violations = logger.get_violations();
        assert_eq!(violations.len(), 3);

        for violation in violations.iter() {
            assert_eq!(violation.violation_type, ViolationType::PolicyEvaluation);
            assert_eq!(violation.source_device, [0u8; 32]); // Not applicable for policy evaluations
            assert_eq!(violation.residency_tag, ResidencyTag::GLOBAL); // Not applicable
            assert!(violation.reason.contains("Data:"));
            assert!(violation.reason.contains("Decision:"));
            assert!(violation.reason.contains("Reason:"));
        }

        // Check specific content
        let first_violation = &violations[0];
        assert!(first_violation.reason.contains("Data: zcp_message"));
        assert!(first_violation.reason.contains("Decision: allow"));
        assert!(first_violation.reason.contains("Reason: same_zone_allowed"));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_audit_logging_mixed_types() {
        let mut logger = ViolationLogger::new();

        let source_device = [3u8; 32];
        let timestamp = 1234567890;

        // Mix different audit logging types
        logger.log_forwarding_decision(
            source_device,
            ResidencyTag::INDONESIA,
            ResidencyTag::MALAYSIA,
            ResidencyTag::INDONESIA,
            "allow",
            "test",
            timestamp,
        );

        logger.log_connection_attempt(
            source_device,
            ResidencyTag::INDONESIA,
            ResidencyTag::VIETNAM,
            "success",
            timestamp + 1,
        );

        logger.log_policy_evaluation(
            ResidencyTag::INDONESIA,
            ResidencyTag::SINGAPORE,
            "test_data",
            "deny",
            "policy_denied",
            timestamp + 2,
        );

        // Also add a traditional violation
        let traditional_violation = Violation {
            timestamp: timestamp + 3,
            violation_type: ViolationType::ResidencyViolation,
            source_device,
            source_zone: ResidencyTag::INDONESIA,
            dest_zone: ResidencyTag::PHILIPPINES,
            residency_tag: ResidencyTag::INDONESIA,
            reason: "Traditional violation".to_string(),
        };
        logger.log_violation(traditional_violation);

        let violations = logger.get_violations();
        assert_eq!(violations.len(), 4);

        // Verify each type
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
        assert_eq!(
            violations[3].violation_type,
            ViolationType::ResidencyViolation
        );
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_audit_logging_statistics() {
        let mut logger = ViolationLogger::new();

        // Log various audit events
        for i in 0..5 {
            logger.log_forwarding_decision(
                [i; 32],
                ResidencyTag::INDONESIA,
                ResidencyTag::MALAYSIA,
                ResidencyTag::INDONESIA,
                "allow",
                "test",
                i as u64,
            );
        }

        for i in 0..3 {
            logger.log_connection_attempt(
                [i + 5; 32],
                ResidencyTag::PHILIPPINES,
                ResidencyTag::VIETNAM,
                "success",
                i as u64,
            );
        }

        for i in 0..2 {
            logger.log_policy_evaluation(
                ResidencyTag::SINGAPORE,
                ResidencyTag::MALAYSIA,
                "test_data",
                "deny",
                "test",
                i as u64,
            );
        }

        let stats = logger.get_stats();

        // Check that audit events are counted
        assert_eq!(stats.forwarding_decisions, 5);
        assert_eq!(stats.connection_attempts, 3);
        assert_eq!(stats.policy_evaluations, 2);
        assert_eq!(stats.total_violations, 10); // 5 + 3 + 2
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_audit_logging_filtering() {
        let mut logger = ViolationLogger::new();

        // Log various types of violations
        logger.log_forwarding_decision(
            [1; 32],
            ResidencyTag::INDONESIA,
            ResidencyTag::MALAYSIA,
            ResidencyTag::INDONESIA,
            "allow",
            "test",
            1,
        );

        logger.log_connection_attempt(
            [2; 32],
            ResidencyTag::PHILIPPINES,
            ResidencyTag::VIETNAM,
            "success",
            2,
        );

        logger.log_violation(Violation {
            timestamp: 3,
            violation_type: ViolationType::ResidencyViolation,
            source_device: [3; 32],
            source_zone: ResidencyTag::SINGAPORE,
            dest_zone: ResidencyTag::MALAYSIA,
            residency_tag: ResidencyTag::SINGAPORE,
            reason: "Test".to_string(),
        });

        // Test filtering by audit types
        let forwarding_decisions = logger.get_violations_by_type(ViolationType::ForwardingDecision);
        assert_eq!(forwarding_decisions.len(), 1);

        let connection_attempts = logger.get_violations_by_type(ViolationType::ConnectionAttempt);
        assert_eq!(connection_attempts.len(), 1);

        let residency_violations = logger.get_violations_by_type(ViolationType::ResidencyViolation);
        assert_eq!(residency_violations.len(), 1);

        let policy_evaluations = logger.get_violations_by_type(ViolationType::PolicyEvaluation);
        assert_eq!(policy_evaluations.len(), 0); // None logged
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_audit_logging_edge_cases() {
        let mut logger = ViolationLogger::new();

        // Test with global zone
        logger.log_forwarding_decision(
            [1; 32],
            ResidencyTag::GLOBAL,
            ResidencyTag::INDONESIA,
            ResidencyTag::GLOBAL,
            "allow",
            "test forwarding",
            1234567890,
        );
        let long_decision = "very_long_decision_for_testing".repeat(5);
        let long_reason = "very_long_reason_for_testing".repeat(10);
        logger.log_policy_evaluation(
            ResidencyTag::INDONESIA,
            ResidencyTag::MALAYSIA,
            &long_decision,
            &long_decision,
            &long_reason,
            1234567892,
        );

        let violations = logger.get_violations();
        assert_eq!(violations.len(), 2);

        // Verify all were logged without panicking
        for violation in violations.iter() {
            assert!(!violation.reason.is_empty());
        }
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_audit_logging_with_limits() {
        let mut logger = ViolationLogger::new();
        logger.set_max_violations(5);

        // Log more violations than the limit
        for i in 0..10 {
            logger.log_forwarding_decision(
                [i; 32],
                ResidencyTag::INDONESIA,
                ResidencyTag::MALAYSIA,
                ResidencyTag::INDONESIA,
                "allow",
                "test",
                i as u64,
            );
        }

        let violations = logger.get_violations();
        assert_eq!(violations.len(), 5); // Should be limited to 5

        // Should contain the most recent violations (timestamps 5-9)
        for (i, violation) in violations.iter().enumerate() {
            assert_eq!(violation.timestamp, (i + 5) as u64);
        }
    }

    #[test]
    fn test_violation_type_audit_variants() {
        // Test that all new audit-related variants exist
        let audit_types = vec![
            ViolationType::ForwardingDecision,
            ViolationType::ConnectionAttempt,
            ViolationType::PolicyEvaluation,
            ViolationType::InvalidResidencyTag,
            ViolationType::UnauthorizedCrossBorder,
            ViolationType::DataExfiltration,
            ViolationType::TransportViolation,
        ];

        for violation_type in audit_types {
            // Just verify they can be created and compared
            assert_eq!(violation_type, violation_type);
        }
    }
}
