//! Backpressure and flow control for TCP transport.
//!
//! Provides:
//! - Send/receive buffer size configuration
//! - Backpressure handling with configurable thresholds
//! - Flow control metrics and monitoring

/// Flow control configuration for TCP transport.
#[derive(Clone, Debug)]
pub struct FlowControlConfig {
    /// Send buffer size in bytes.
    pub send_buffer_size: usize,
    /// Receive buffer size in bytes.
    pub recv_buffer_size: usize,
    /// High watermark for send buffer (triggers backpressure).
    pub send_high_watermark: usize,
    /// Low watermark for send buffer (clears backpressure).
    pub send_low_watermark: usize,
    /// Maximum frame size in bytes.
    pub max_frame_size: usize,
}

impl Default for FlowControlConfig {
    fn default() -> Self {
        Self {
            send_buffer_size: 65536,
            recv_buffer_size: 65536,
            send_high_watermark: 52428,
            send_low_watermark: 26214,
            max_frame_size: 65535,
        }
    }
}

impl FlowControlConfig {
    /// Create a new flow control configuration.
    pub fn new(send_buf: usize, recv_buf: usize) -> Self {
        let high = (send_buf as f64 * 0.8) as usize;
        let low = (send_buf as f64 * 0.4) as usize;

        Self {
            send_buffer_size: send_buf,
            recv_buffer_size: recv_buf,
            send_high_watermark: high,
            send_low_watermark: low,
            max_frame_size: 65535,
        }
    }

    /// Set custom watermarks.
    pub fn with_watermarks(mut self, high: usize, low: usize) -> Self {
        self.send_high_watermark = high;
        self.send_low_watermark = low;
        self
    }

    /// Set maximum frame size.
    pub fn with_max_frame_size(mut self, size: usize) -> Self {
        self.max_frame_size = size;
        self
    }

    /// Validate configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.send_low_watermark >= self.send_high_watermark {
            return Err("low watermark must be less than high watermark".to_string());
        }
        if self.send_high_watermark > self.send_buffer_size {
            return Err("high watermark must not exceed send buffer size".to_string());
        }
        if self.max_frame_size == 0 {
            return Err("max frame size must be greater than 0".to_string());
        }
        Ok(())
    }
}

/// Flow control metrics for monitoring TCP transport performance.
#[derive(Default)]
pub struct FlowControlMetrics {
    /// Current send buffer usage in bytes.
    pub send_buffer_used: usize,
    /// Current receive buffer usage in bytes.
    pub recv_buffer_used: usize,
    /// Whether backpressure is currently active.
    pub backpressure_active: bool,
    /// Total bytes sent.
    pub total_sent: u64,
    /// Total bytes received.
    pub total_received: u64,
    /// Number of backpressure events.
    pub backpressure_events: u64,
}

impl FlowControlMetrics {
    /// Create new flow control metrics.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record sent bytes.
    pub fn record_sent(&mut self, bytes: usize) {
        self.total_sent += bytes as u64;
    }

    /// Record received bytes.
    pub fn record_received(&mut self, bytes: usize) {
        self.total_received += bytes as u64;
    }

    /// Update send buffer usage.
    pub fn update_send_buffer(&mut self, used: usize) {
        self.send_buffer_used = used;
    }

    /// Update receive buffer usage.
    pub fn update_recv_buffer(&mut self, used: usize) {
        self.recv_buffer_used = used;
    }

    /// Record backpressure event.
    pub fn record_backpressure(&mut self) {
        self.backpressure_events += 1;
        self.backpressure_active = true;
    }

    /// Clear backpressure.
    pub fn clear_backpressure(&mut self) {
        self.backpressure_active = false;
    }

    /// Get send buffer utilization percentage.
    pub fn send_utilization(&self, config: &FlowControlConfig) -> f64 {
        (self.send_buffer_used as f64 / config.send_buffer_size as f64) * 100.0
    }

    /// Get receive buffer utilization percentage.
    pub fn recv_utilization(&self, config: &FlowControlConfig) -> f64 {
        (self.recv_buffer_used as f64 / config.recv_buffer_size as f64) * 100.0
    }
}

/// Backpressure handler for flow control.
pub struct BackpressureHandler {
    config: FlowControlConfig,
    metrics: FlowControlMetrics,
}

impl BackpressureHandler {
    /// Create a new backpressure handler.
    pub fn new(config: FlowControlConfig) -> Result<Self, String> {
        config.validate()?;
        Ok(Self {
            config,
            metrics: FlowControlMetrics::new(),
        })
    }

    /// Check if backpressure should be applied.
    pub fn should_apply_backpressure(&self) -> bool {
        self.metrics.send_buffer_used >= self.config.send_high_watermark
    }

    /// Check if backpressure should be cleared.
    pub fn should_clear_backpressure(&self) -> bool {
        self.metrics.send_buffer_used <= self.config.send_low_watermark
    }

    /// Update metrics and return backpressure state.
    pub fn update(&mut self, send_used: usize, recv_used: usize) -> bool {
        self.metrics.update_send_buffer(send_used);
        self.metrics.update_recv_buffer(recv_used);

        if self.should_apply_backpressure() && !self.metrics.backpressure_active {
            self.metrics.record_backpressure();
            true
        } else if self.should_clear_backpressure() && self.metrics.backpressure_active {
            self.metrics.clear_backpressure();
            false
        } else {
            self.metrics.backpressure_active
        }
    }

    /// Get current metrics.
    pub fn metrics(&self) -> &FlowControlMetrics {
        &self.metrics
    }

    /// Get mutable metrics.
    pub fn metrics_mut(&mut self) -> &mut FlowControlMetrics {
        &mut self.metrics
    }

    /// Get configuration.
    pub fn config(&self) -> &FlowControlConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flow_control_config_default() {
        let cfg = FlowControlConfig::default();
        assert_eq!(cfg.send_buffer_size, 65536);
        assert_eq!(cfg.recv_buffer_size, 65536);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_flow_control_config_custom() {
        let cfg = FlowControlConfig::new(32768, 32768);
        assert_eq!(cfg.send_buffer_size, 32768);
        assert_eq!(cfg.recv_buffer_size, 32768);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_flow_control_config_watermarks() {
        let cfg = FlowControlConfig::new(10000, 10000).with_watermarks(8000, 2000);
        assert_eq!(cfg.send_high_watermark, 8000);
        assert_eq!(cfg.send_low_watermark, 2000);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_flow_control_config_invalid_watermarks() {
        let cfg = FlowControlConfig::new(10000, 10000).with_watermarks(2000, 8000);
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_flow_control_config_invalid_high_watermark() {
        let cfg = FlowControlConfig::new(10000, 10000).with_watermarks(15000, 5000);
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_flow_control_metrics_default() {
        let metrics = FlowControlMetrics::new();
        assert_eq!(metrics.send_buffer_used, 0);
        assert_eq!(metrics.total_sent, 0);
        assert!(!metrics.backpressure_active);
    }

    #[test]
    fn test_flow_control_metrics_record() {
        let mut metrics = FlowControlMetrics::new();
        metrics.record_sent(1000);
        metrics.record_received(500);
        assert_eq!(metrics.total_sent, 1000);
        assert_eq!(metrics.total_received, 500);
    }

    #[test]
    fn test_flow_control_metrics_utilization() {
        let cfg = FlowControlConfig::new(10000, 10000);
        let mut metrics = FlowControlMetrics::new();
        metrics.update_send_buffer(5000);
        assert_eq!(metrics.send_utilization(&cfg), 50.0);
    }

    #[test]
    fn test_backpressure_handler_creation() {
        let cfg = FlowControlConfig::default();
        let handler = BackpressureHandler::new(cfg);
        assert!(handler.is_ok());
    }

    #[test]
    fn test_backpressure_handler_apply() {
        let cfg = FlowControlConfig::new(10000, 10000).with_watermarks(8000, 2000);
        let mut handler = BackpressureHandler::new(cfg).unwrap();

        // Below high watermark
        assert!(!handler.update(7000, 0));
        assert!(!handler.metrics().backpressure_active);

        // Above high watermark
        assert!(handler.update(8500, 0));
        assert!(handler.metrics().backpressure_active);
        assert_eq!(handler.metrics().backpressure_events, 1);
    }

    #[test]
    fn test_backpressure_handler_clear() {
        let cfg = FlowControlConfig::new(10000, 10000).with_watermarks(8000, 2000);
        let mut handler = BackpressureHandler::new(cfg).unwrap();

        // Apply backpressure
        handler.update(8500, 0);
        assert!(handler.metrics().backpressure_active);

        // Clear backpressure
        assert!(!handler.update(1500, 0));
        assert!(!handler.metrics().backpressure_active);
    }
}
