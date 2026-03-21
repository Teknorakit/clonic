//! Connection pooling and keepalive for TCP transport.
//!
//! Provides:
//! - Connection pooling with configurable pool size
//! - TCP keepalive settings
//! - Connection reuse and lifecycle management

use std::time::Duration;

/// TCP keepalive configuration.
#[derive(Clone, Debug, Copy)]
pub struct KeepaliveConfig {
    /// Enable TCP keepalive.
    pub enabled: bool,
    /// Time before first keepalive probe (seconds).
    pub idle_secs: u32,
    /// Interval between keepalive probes (seconds).
    pub interval_secs: u32,
    /// Number of failed probes before closing connection.
    pub retries: u32,
}

impl Default for KeepaliveConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            idle_secs: 60,
            interval_secs: 10,
            retries: 5,
        }
    }
}

impl KeepaliveConfig {
    /// Create a new keepalive configuration.
    pub const fn new(idle_secs: u32, interval_secs: u32, retries: u32) -> Self {
        Self {
            enabled: true,
            idle_secs,
            interval_secs,
            retries,
        }
    }

    /// Disable keepalive.
    pub const fn disabled() -> Self {
        Self {
            enabled: false,
            idle_secs: 0,
            interval_secs: 0,
            retries: 0,
        }
    }

    /// Get idle duration.
    pub fn idle_duration(&self) -> Duration {
        Duration::from_secs(self.idle_secs as u64)
    }

    /// Get interval duration.
    pub fn interval_duration(&self) -> Duration {
        Duration::from_secs(self.interval_secs as u64)
    }
}

/// Connection pool configuration.
#[derive(Clone, Debug)]
pub struct PoolConfig {
    /// Maximum number of connections in the pool.
    pub max_connections: usize,
    /// Connection idle timeout (seconds).
    pub idle_timeout_secs: u32,
    /// TCP keepalive configuration.
    pub keepalive: KeepaliveConfig,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_connections: 10,
            idle_timeout_secs: 300,
            keepalive: KeepaliveConfig::default(),
        }
    }
}

impl PoolConfig {
    /// Create a new pool configuration.
    pub fn new(max_connections: usize) -> Self {
        Self {
            max_connections,
            idle_timeout_secs: 300,
            keepalive: KeepaliveConfig::default(),
        }
    }

    /// Set idle timeout.
    pub fn with_idle_timeout(mut self, secs: u32) -> Self {
        self.idle_timeout_secs = secs;
        self
    }

    /// Set keepalive configuration.
    pub fn with_keepalive(mut self, keepalive: KeepaliveConfig) -> Self {
        self.keepalive = keepalive;
        self
    }

    /// Get idle timeout duration.
    pub fn idle_timeout_duration(&self) -> Duration {
        Duration::from_secs(self.idle_timeout_secs as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keepalive_config_default() {
        let cfg = KeepaliveConfig::default();
        assert!(cfg.enabled);
        assert_eq!(cfg.idle_secs, 60);
        assert_eq!(cfg.interval_secs, 10);
        assert_eq!(cfg.retries, 5);
    }

    #[test]
    fn test_keepalive_config_disabled() {
        let cfg = KeepaliveConfig::disabled();
        assert!(!cfg.enabled);
        assert_eq!(cfg.idle_secs, 0);
    }

    #[test]
    fn test_keepalive_config_custom() {
        let cfg = KeepaliveConfig::new(120, 20, 3);
        assert!(cfg.enabled);
        assert_eq!(cfg.idle_secs, 120);
        assert_eq!(cfg.interval_secs, 20);
        assert_eq!(cfg.retries, 3);
    }

    #[test]
    fn test_keepalive_durations() {
        let cfg = KeepaliveConfig::new(60, 10, 5);
        assert_eq!(cfg.idle_duration(), Duration::from_secs(60));
        assert_eq!(cfg.interval_duration(), Duration::from_secs(10));
    }

    #[test]
    fn test_pool_config_default() {
        let cfg = PoolConfig::default();
        assert_eq!(cfg.max_connections, 10);
        assert_eq!(cfg.idle_timeout_secs, 300);
        assert!(cfg.keepalive.enabled);
    }

    #[test]
    fn test_pool_config_custom() {
        let cfg = PoolConfig::new(20)
            .with_idle_timeout(600)
            .with_keepalive(KeepaliveConfig::disabled());
        assert_eq!(cfg.max_connections, 20);
        assert_eq!(cfg.idle_timeout_secs, 600);
        assert!(!cfg.keepalive.enabled);
    }

    #[test]
    fn test_pool_config_idle_timeout_duration() {
        let cfg = PoolConfig::new(10).with_idle_timeout(120);
        assert_eq!(cfg.idle_timeout_duration(), Duration::from_secs(120));
    }
}
