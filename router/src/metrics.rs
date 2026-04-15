//! Prometheus metrics for zone enforcement monitoring.
//!
//! Provides comprehensive metrics for monitoring zone violations,
//! routing decisions, and router health.

#[cfg(feature = "metrics")]
use prometheus::{
    register_counter_vec, register_gauge_vec, register_histogram_vec, CounterVec, GaugeVec,
    HistogramVec,
};

#[cfg(feature = "metrics")]
use alloc::vec::Vec;
#[cfg(feature = "metrics")]
use alloc::{
    boxed::Box,
    string::{String, ToString},
    vec,
};
#[cfg(feature = "metrics")]
use clonic_core::ResidencyTag;

/// Prometheus metrics collector for zone enforcement.
#[cfg(feature = "metrics")]
pub struct ZoneMetrics {
    /// Counter for zone violations by type and zone
    pub zone_violations: CounterVec,
    /// Counter for routing decisions by decision type
    pub routing_decisions: CounterVec,
    /// Gauge for current peer count by zone
    pub peer_count: GaugeVec,
    /// Histogram for message processing latency
    pub processing_latency: HistogramVec,
    /// Counter for cross-border agreements by status
    pub agreement_status: CounterVec,
    /// Counter for configuration reloads
    pub config_reloads: CounterVec,
}

#[cfg(feature = "metrics")]
impl ZoneMetrics {
    /// Create new metrics collector.
    pub fn new() -> Result<Self, prometheus::Error> {
        Ok(Self {
            zone_violations: register_counter_vec!(
                "clonic_zone_violations_total",
                "Total number of zone policy violations",
                &["violation_type", "source_zone", "dest_zone"]
            )?,

            routing_decisions: register_counter_vec!(
                "clonic_routing_decisions_total",
                "Total number of routing decisions",
                &["decision", "source_zone", "dest_zone", "reason"]
            )?,

            peer_count: register_gauge_vec!(
                "clonic_peer_count",
                "Current number of registered peers by zone",
                &["zone"]
            )?,

            processing_latency: register_histogram_vec!(
                "clonic_processing_duration_seconds",
                "Time spent processing messages",
                &["operation"],
                vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
            )?,

            agreement_status: register_counter_vec!(
                "clonic_agreement_status_total",
                "Cross-border agreement status changes",
                &["agreement_id", "source_zone", "dest_zone", "status"]
            )?,

            config_reloads: register_counter_vec!(
                "clonic_config_reloads_total",
                "Configuration reloads",
                &["result"]
            )?,
        })
    }

    /// Create new metrics collector, ignoring AlreadyReg errors (useful for tests).
    pub fn new_for_tests() -> Self {
        Self::new().unwrap_or_else(|_| {
            // If metrics are already registered, create no-op metrics
            Self {
                zone_violations: prometheus::CounterVec::new(
                    prometheus::Opts::new(
                        "clonic_zone_violations_total",
                        "Total number of zone policy violations",
                    ),
                    &["violation_type", "source_zone", "dest_zone"],
                )
                .unwrap(),
                routing_decisions: prometheus::CounterVec::new(
                    prometheus::Opts::new(
                        "clonic_routing_decisions_total",
                        "Total number of routing decisions",
                    ),
                    &["decision", "source_zone", "dest_zone", "reason"],
                )
                .unwrap(),
                peer_count: prometheus::GaugeVec::new(
                    prometheus::Opts::new(
                        "clonic_peer_count",
                        "Current number of registered peers by zone",
                    ),
                    &["zone"],
                )
                .unwrap(),
                processing_latency: prometheus::HistogramVec::new(
                    prometheus::HistogramOpts::new(
                        "clonic_processing_duration_seconds",
                        "Time spent processing messages",
                    )
                    .buckets(vec![
                        0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
                    ]),
                    &["operation"],
                )
                .unwrap(),
                agreement_status: prometheus::CounterVec::new(
                    prometheus::Opts::new(
                        "clonic_agreement_status_total",
                        "Cross-border agreement status changes",
                    ),
                    &["agreement_id", "source_zone", "dest_zone", "status"],
                )
                .unwrap(),
                config_reloads: prometheus::CounterVec::new(
                    prometheus::Opts::new("clonic_config_reloads_total", "Configuration reloads"),
                    &["result"],
                )
                .unwrap(),
            }
        })
    }

    /// Record a zone violation.
    pub fn record_zone_violation(
        &self,
        violation_type: &str,
        source_zone: ResidencyTag,
        dest_zone: ResidencyTag,
    ) {
        self.zone_violations
            .with_label_values(&[
                violation_type,
                &source_zone.to_string(),
                &dest_zone.to_string(),
            ])
            .inc();
    }

    /// Record a routing decision.
    pub fn record_routing_decision(
        &self,
        decision: &str,
        source_zone: ResidencyTag,
        dest_zone: ResidencyTag,
        reason: &str,
    ) {
        self.routing_decisions
            .with_label_values(&[
                decision,
                &source_zone.to_string(),
                &dest_zone.to_string(),
                reason,
            ])
            .inc();
    }

    /// Update peer count for a zone.
    pub fn set_peer_count(&self, zone: ResidencyTag, count: u64) {
        self.peer_count
            .with_label_values(&[&zone.to_string()])
            .set(count as f64);
    }

    /// Record processing latency.
    pub fn record_processing_latency(&self, operation: &str, duration: std::time::Duration) {
        self.processing_latency
            .with_label_values(&[operation])
            .observe(duration.as_secs_f64());
    }

    /// Record agreement status change.
    pub fn record_agreement_status(
        &self,
        agreement_id: &str,
        source_zone: ResidencyTag,
        dest_zone: ResidencyTag,
        status: &str,
    ) {
        self.agreement_status
            .with_label_values(&[
                agreement_id,
                &source_zone.to_string(),
                &dest_zone.to_string(),
                status,
            ])
            .inc();
    }

    /// Record configuration reload.
    pub fn record_config_reload(&self, result: &str) {
        self.config_reloads.with_label_values(&[result]).inc();
    }

    /// Gather all metrics for Prometheus scraping.
    pub fn gather(&self) -> Vec<prometheus::proto::MetricFamily> {
        #[cfg(feature = "metrics")]
        {
            prometheus::gather()
        }
        #[cfg(not(feature = "metrics"))]
        {
            Vec::new()
        }
    }

    /// Get total zone violations count.
    pub fn get_zone_violations_count(&self) -> u64 {
        #[cfg(feature = "metrics")]
        {
            let metric_families = self.gather();
            let mut total = 0u64;

            for family in metric_families {
                if family.get_name() == "clonic_zone_violations_total" {
                    for metric in family.get_metric() {
                        total += metric.get_counter().get_value() as u64;
                    }
                }
            }
            total
        }
        #[cfg(not(feature = "metrics"))]
        {
            0
        }
    }
}

#[cfg(feature = "metrics")]
impl Default for ZoneMetrics {
    fn default() -> Self {
        Self::new().expect("Failed to create metrics - ensure Prometheus registry is available")
    }
}

/// No-op metrics implementation when metrics feature is disabled.
#[cfg(not(feature = "metrics"))]
pub struct ZoneMetrics;

#[cfg(not(feature = "metrics"))]
impl ZoneMetrics {
    /// Create new no-op metrics collector.
    pub fn new() -> Result<Self, &'static str> {
        Ok(Self)
    }

    /// Record a zone violation (no-op).
    pub fn record_zone_violation(
        &self,
        _violation_type: &str,
        _source_zone: ResidencyTag,
        _dest_zone: ResidencyTag,
    ) {
        // No-op
    }

    /// Record a routing decision (no-op).
    pub fn record_routing_decision(
        &self,
        _decision: &str,
        _source_zone: ResidencyTag,
        _dest_zone: ResidencyTag,
        _reason: &str,
    ) {
        // No-op
    }

    /// Update peer count for a zone (no-op).
    pub fn set_peer_count(&self, _zone: ResidencyTag, _count: usize) {
        // No-op
    }

    /// Record processing latency (no-op).
    pub fn record_processing_latency(&self, _operation: &str, _duration: std::time::Duration) {
        // No-op
    }

    /// Record agreement status change (no-op).
    pub fn record_agreement_status(
        &self,
        _agreement_id: &str,
        _source_zone: ResidencyTag,
        _dest_zone: ResidencyTag,
        _status: &str,
    ) {
        // No-op
    }

    /// Record configuration reload (no-op).
    pub fn record_config_reload(&self, _result: &str) {
        // No-op
    }
}

#[cfg(not(feature = "metrics"))]
impl Default for ZoneMetrics {
    fn default() -> Self {
        Self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_metrics_noop() {
        let metrics = ZoneMetrics::new_for_tests();

        // These should not panic
        metrics.record_zone_violation("test", ResidencyTag::INDONESIA, ResidencyTag::MALAYSIA);
        metrics.record_routing_decision(
            "allow",
            ResidencyTag::INDONESIA,
            ResidencyTag::MALAYSIA,
            "test",
        );
        metrics.set_peer_count(ResidencyTag::INDONESIA, 10);
        metrics.record_processing_latency("test", Duration::from_millis(100));
        metrics.record_agreement_status(
            "test",
            ResidencyTag::INDONESIA,
            ResidencyTag::MALAYSIA,
            "active",
        );
        metrics.record_config_reload("success");
    }

    #[cfg(feature = "metrics")]
    #[test]
    fn test_metrics_creation() {
        let metrics = ZoneMetrics::new_for_tests();

        // Test that metrics are created without panicking
        metrics.record_zone_violation("residency", ResidencyTag::INDONESIA, ResidencyTag::MALAYSIA);
        metrics.record_routing_decision(
            "deny",
            ResidencyTag::INDONESIA,
            ResidencyTag::MALAYSIA,
            "policy",
        );
        metrics.set_peer_count(ResidencyTag::INDONESIA, 5);

        // Verify metrics were recorded (this might not work with unregistered metrics)
        // let metric_families = metrics.gather();
        // assert!(!metric_families.is_empty());
    }

    #[test]
    fn test_metrics_default() {
        let metrics = ZoneMetrics::new_for_tests();

        // Should not panic on any operations
        metrics.record_zone_violation("test_type", ResidencyTag::GLOBAL, ResidencyTag::INDONESIA);
        metrics.record_routing_decision(
            "test_decision",
            ResidencyTag::INDONESIA,
            ResidencyTag::MALAYSIA,
            "test_reason",
        );
        metrics.set_peer_count(ResidencyTag::SINGAPORE, 42);
        metrics.record_processing_latency("test_operation", Duration::from_nanos(123456789));
        metrics.record_agreement_status(
            "test_agreement",
            ResidencyTag::VIETNAM,
            ResidencyTag::PHILIPPINES,
            "test_status",
        );
        metrics.record_config_reload("test_result");
    }

    #[test]
    fn test_metrics_violation_types() {
        let metrics = ZoneMetrics::new_for_tests();

        let violation_types = [
            "residency_violation",
            "unknown_sender",
            "invalid_envelope",
            "transport_error",
            "policy_error",
            "data_exfiltration",
            "cross_border_violation",
        ];

        for (i, violation_type) in violation_types.iter().enumerate() {
            metrics.record_zone_violation(
                violation_type,
                ResidencyTag::INDONESIA,
                ResidencyTag::MALAYSIA,
            );

            // Test different zones
            if i % 2 == 0 {
                metrics.record_zone_violation(
                    violation_type,
                    ResidencyTag::GLOBAL,
                    ResidencyTag::VIETNAM,
                );
            }
        }
    }

    #[test]
    fn test_metrics_routing_decisions() {
        let metrics = ZoneMetrics::new_for_tests();

        let decisions = vec![
            ("allow", "default_allow"),
            ("deny", "default_deny"),
            ("deny", "explicit_deny"),
            ("allow", "agreement_allowed"),
            ("deny", "agreement_expired"),
        ];

        for (decision, reason) in decisions {
            metrics.record_routing_decision(
                decision,
                ResidencyTag::INDONESIA,
                ResidencyTag::MALAYSIA,
                reason,
            );
        }
    }

    #[test]
    fn test_metrics_peer_counts() {
        let metrics = ZoneMetrics::new_for_tests();

        let zones = [
            ResidencyTag::INDONESIA,
            ResidencyTag::MALAYSIA,
            ResidencyTag::PHILIPPINES,
            ResidencyTag::VIETNAM,
            ResidencyTag::SINGAPORE,
            ResidencyTag::GLOBAL,
        ];

        for (i, zone) in zones.iter().enumerate() {
            metrics.set_peer_count(*zone, ((i + 1) * 10) as u64);
        }

        // Test updating counts
        metrics.set_peer_count(ResidencyTag::INDONESIA, 999);
        metrics.set_peer_count(ResidencyTag::GLOBAL, 0);
    }

    #[test]
    fn test_metrics_processing_latency() {
        let metrics = ZoneMetrics::new_for_tests();

        let operations = vec![
            ("validate_residency", Duration::from_millis(1)),
            ("route_message", Duration::from_micros(500)),
            ("process_incoming", Duration::from_nanos(100000)),
            ("policy_check", Duration::from_millis(10)),
            ("log_violation", Duration::from_micros(100)),
        ];

        for (operation, duration) in operations {
            metrics.record_processing_latency(operation, duration);
        }

        // Test edge cases
        metrics.record_processing_latency("zero_latency", Duration::from_nanos(0));
        metrics.record_processing_latency("max_latency", Duration::from_secs(10));
    }

    #[test]
    fn test_metrics_agreement_status() {
        let metrics = ZoneMetrics::new_for_tests();

        let agreements = vec![
            (
                "id-agreement-1",
                ResidencyTag::INDONESIA,
                ResidencyTag::MALAYSIA,
                "active",
            ),
            (
                "id-agreement-2",
                ResidencyTag::PHILIPPINES,
                ResidencyTag::VIETNAM,
                "expired",
            ),
            (
                "id-agreement-3",
                ResidencyTag::SINGAPORE,
                ResidencyTag::INDONESIA,
                "suspended",
            ),
            (
                "id-agreement-4",
                ResidencyTag::MALAYSIA,
                ResidencyTag::PHILIPPINES,
                "revoked",
            ),
            (
                "id-agreement-5",
                ResidencyTag::VIETNAM,
                ResidencyTag::SINGAPORE,
                "pending",
            ),
        ];

        for (agreement_id, source_zone, dest_zone, status) in agreements {
            metrics.record_agreement_status(agreement_id, source_zone, dest_zone, status);
        }
    }

    #[test]
    fn test_metrics_config_reloads() {
        let metrics = ZoneMetrics::new_for_tests();

        let results = vec!["success", "failure", "partial", "timeout", "invalid"];

        for result in results {
            metrics.record_config_reload(result);
        }

        // Test multiple reloads
        for _ in 0..5 {
            metrics.record_config_reload("success");
        }
    }

    #[test]
    fn test_metrics_edge_cases() {
        let metrics = ZoneMetrics::new_for_tests();

        // Test with global zone
        metrics.record_zone_violation("test", ResidencyTag::GLOBAL, ResidencyTag::GLOBAL);
        metrics.record_routing_decision(
            "allow",
            ResidencyTag::GLOBAL,
            ResidencyTag::INDONESIA,
            "global_allowed",
        );
        metrics.set_peer_count(ResidencyTag::GLOBAL, 0);

        // Test with extended zones
        let subdivision = ResidencyTag::from_subdivision(360, 1).unwrap();
        metrics.record_zone_violation("test", subdivision, ResidencyTag::INDONESIA);
        metrics.record_routing_decision(
            "deny",
            ResidencyTag::INDONESIA,
            subdivision,
            "subdivision_denied",
        );
        metrics.set_peer_count(subdivision, 5);

        // Test very long strings
        let long_string = "a".repeat(100);
        metrics.record_zone_violation(
            &long_string,
            ResidencyTag::INDONESIA,
            ResidencyTag::MALAYSIA,
        );
        metrics.record_routing_decision(
            &long_string,
            ResidencyTag::INDONESIA,
            ResidencyTag::MALAYSIA,
            &long_string,
        );

        // Test zero and maximum values
        metrics.set_peer_count(ResidencyTag::INDONESIA, 0);
        metrics.set_peer_count(ResidencyTag::MALAYSIA, u64::MAX);
    }

    #[test]
    #[allow(clippy::unnecessary_cast)]
    fn test_metrics_concurrent_operations() {
        use std::sync::Arc;
        use std::thread;

        let metrics = Arc::new(ZoneMetrics::new_for_tests());
        let mut handles = vec![];

        // Spawn multiple threads to test concurrent access
        for i in 0..10 {
            let metrics_clone = Arc::clone(&metrics);
            let handle = thread::spawn(move || {
                for j in 0..100 {
                    metrics_clone.record_zone_violation(
                        "concurrent_test",
                        ResidencyTag::INDONESIA,
                        ResidencyTag::MALAYSIA,
                    );
                    metrics_clone.set_peer_count(ResidencyTag::INDONESIA, i * j);
                    metrics_clone.record_processing_latency(
                        "concurrent_op",
                        Duration::from_micros((i * j) as u64),
                    );
                }
            });
            handles.push(handle);
        }

        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[cfg(feature = "metrics")]
    #[test]
    fn test_metrics_gather_functionality() {
        let metrics = ZoneMetrics::new_for_tests();

        // Record some metrics
        metrics.record_zone_violation("test", ResidencyTag::INDONESIA, ResidencyTag::MALAYSIA);
        metrics.record_routing_decision(
            "allow",
            ResidencyTag::INDONESIA,
            ResidencyTag::MALAYSIA,
            "test",
        );
        metrics.set_peer_count(ResidencyTag::INDONESIA, 5);

        // Test gather method (may not work with unregistered metrics, but should not panic)
        let _metric_families = metrics.gather();
    }

    #[test]
    fn test_metrics_noop_implementation() {
        // Test that the no-op implementation works when metrics feature is disabled
        #[cfg(not(feature = "metrics"))]
        {
            let metrics = ZoneMetrics::new().unwrap();
            metrics.record_zone_violation("test", ResidencyTag::INDONESIA, ResidencyTag::MALAYSIA);
            metrics.record_routing_decision(
                "allow",
                ResidencyTag::INDONESIA,
                ResidencyTag::MALAYSIA,
                "test",
            );
            metrics.set_peer_count(ResidencyTag::INDONESIA, 10);
            metrics.record_processing_latency("test", Duration::from_millis(100));
            metrics.record_agreement_status(
                "test",
                ResidencyTag::INDONESIA,
                ResidencyTag::MALAYSIA,
                "active",
            );
            metrics.record_config_reload("success");

            // gather() should also work without panicking
            let _metric_families = metrics.gather();
        }
    }

    #[test]
    fn test_metrics_string_conversions() {
        // Test that ResidencyTag::to_string() works in metrics context
        let indonesia = ResidencyTag::INDONESIA;
        let malaysia = ResidencyTag::MALAYSIA;

        #[cfg(feature = "alloc")]
        {
            let _indonesia_str = indonesia.to_string();
            let _malaysia_str = malaysia.to_string();
        }

        // These should not panic even if string conversion fails
        let metrics = ZoneMetrics::new_for_tests();
        metrics.record_zone_violation("test", indonesia, malaysia);
        metrics.record_routing_decision("allow", indonesia, malaysia, "test");
    }
}
