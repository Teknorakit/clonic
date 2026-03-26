//! Violation logging and audit trail for zone enforcement.
//!
//! Records all policy violations and routing decisions for
//! compliance auditing and security monitoring.

#[cfg(feature = "alloc")]
use alloc::{format, string::String, vec::Vec};
use clonic_core::ResidencyTag;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "std")]
use std::eprintln;

/// Types of violations that can occur.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ViolationType {
    /// Data residency policy violation
    ResidencyViolation,
    /// Unknown sender device
    UnknownSender,
    /// Invalid residency tag
    InvalidResidencyTag,
    /// Cross-border data transfer without agreement
    UnauthorizedCrossBorder,
    /// Data exfiltration attempt
    DataExfiltration,
    /// Policy configuration error
    PolicyError,
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
    violations: Vec<Violation>,
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
            violations: Vec::new(),
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
    pub fn set_log_file(&mut self, path: String) {
        self.log_file_path = Some(path);
        self.log_to_file = true;
    }

    /// Log a policy violation.
    pub fn log_violation(&mut self, violation: Violation) {
        // Add to in-memory log
        self.violations.push(violation.clone());

        // Trim if over limit
        if self.violations.len() > self.max_violations {
            self.violations.remove(0);
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

    /// Get all violations.
    pub fn get_violations(&self) -> &[Violation] {
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
                ViolationType::InvalidResidencyTag => stats.invalid_tag_violations += 1,
                ViolationType::UnauthorizedCrossBorder => stats.cross_border_violations += 1,
                ViolationType::DataExfiltration => stats.exfiltration_violations += 1,
                ViolationType::PolicyError => stats.policy_errors += 1,
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
                ViolationType::InvalidResidencyTag => "INVALID_TAG",
                ViolationType::UnauthorizedCrossBorder => "UNAUTHORIZED_CROSS_BORDER",
                ViolationType::DataExfiltration => "DATA_EXFILTRATION",
                ViolationType::PolicyError => "POLICY_ERROR",
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
    /// Invalid tag violations
    pub invalid_tag_violations: u64,
    /// Cross-border violations
    pub cross_border_violations: u64,
    /// Exfiltration violations
    pub exfiltration_violations: u64,
    /// Policy errors
    pub policy_errors: u64,
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
    use alloc::string::ToString;

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
}
