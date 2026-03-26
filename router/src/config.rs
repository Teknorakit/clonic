//! Configuration support for zone policies and router settings.
//!
//! Provides TOML-based configuration for zones, policies,
//! and router behavior.

#[cfg(feature = "alloc")]
use alloc::{collections::BTreeMap, format, string::String, string::ToString, vec::Vec};
#[cfg(feature = "config")]
use clonic_core::ResidencyTag;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Main router configuration.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RouterConfig {
    /// Local zone configuration
    pub local_zone: ZoneConfig,
    /// Peer registry configuration
    pub peer_registry: PeerRegistryConfig,
    /// Policy engine configuration
    pub policy_engine: PolicyEngineConfig,
    /// Violation logging configuration
    pub violation_logging: ViolationLoggingConfig,
    /// Transport configuration
    pub transport: TransportConfig,
}

/// Configuration for a specific zone.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ZoneConfig {
    /// Zone identifier (ISO 3166-1 numeric or name)
    pub zone: String,
    /// Human-readable zone name
    pub name: String,
    /// Zone description
    pub description: String,
    /// Whether this is the local zone
    pub local: bool,
    /// Zone-specific policies
    pub policies: Vec<ZonePolicyConfig>,
}

/// Zone policy configuration.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ZonePolicyConfig {
    /// Policy name
    pub name: String,
    /// Policy description
    pub description: String,
    /// Allowed destination zones
    pub allowlist: Vec<String>,
    /// Denied destination zones
    pub denylist: Vec<String>,
    /// Default action for unspecified zones
    pub default_action: String, // "allow", "deny", "require_agreement"
    /// Cross-border agreements
    pub agreements: Vec<AgreementConfig>,
}

/// Cross-border agreement configuration.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AgreementConfig {
    /// Agreement name
    pub name: String,
    /// Source zone
    pub source_zone: String,
    /// Destination zone
    pub dest_zone: String,
    /// Agreement type
    pub agreement_type: String, // "full", "oneway", "limited", "emergency"
    /// Expiration timestamp (0 = no expiration)
    pub expires_at: u64,
    /// Allowed data types
    pub allowed_data_types: Vec<String>,
    /// Required intermediary zones
    pub required_intermediaries: Vec<String>,
}

/// Peer registry configuration.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PeerRegistryConfig {
    /// Maximum number of peers
    pub max_peers: usize,
    /// Peer timeout in seconds
    pub peer_timeout_secs: u64,
    /// Whether to auto-prune inactive peers
    pub auto_prune: bool,
    /// Static peer definitions
    pub static_peers: Vec<StaticPeerConfig>,
}

/// Static peer configuration.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct StaticPeerConfig {
    /// Device ID (hex string)
    pub device_id: String,
    /// Zone
    pub zone: String,
    /// Address
    pub address: String,
    /// Peer type
    pub peer_type: String, // "full_node", "edge_device", "gateway", "mobile"
    /// Metadata
    pub metadata: BTreeMap<String, String>,
}

/// Policy engine configuration.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PolicyEngineConfig {
    /// Whether to enable strict mode
    pub strict_mode: bool,
    /// Default policy for unknown zones
    pub default_unknown_policy: String, // "allow", "deny"
    /// Whether to cache policy decisions
    pub cache_decisions: bool,
    /// Cache TTL in seconds
    pub cache_ttl_secs: u64,
}

/// Violation logging configuration.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ViolationLoggingConfig {
    /// Whether to enable logging
    pub enabled: bool,
    /// Maximum violations to keep in memory
    pub max_violations: usize,
    /// Whether to log to stderr
    pub log_to_stderr: bool,
    /// Log file path (optional)
    pub log_file: Option<String>,
    /// Log level
    pub log_level: String, // "debug", "info", "warn", "error"
}

/// Transport configuration.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TransportConfig {
    /// Transport type
    pub transport_type: String, // "tcp", "ble", "lorawan"
    /// Transport-specific settings
    pub settings: BTreeMap<String, String>,
}

impl Default for RouterConfig {
    fn default() -> Self {
        Self {
            local_zone: ZoneConfig {
                zone: "360".to_string(), // Indonesia
                name: "Indonesia".to_string(),
                description: "Indonesia data residency zone".to_string(),
                local: true,
                policies: Vec::new(),
            },
            peer_registry: PeerRegistryConfig::default(),
            policy_engine: PolicyEngineConfig::default(),
            violation_logging: ViolationLoggingConfig::default(),
            transport: TransportConfig::default(),
        }
    }
}

impl Default for PeerRegistryConfig {
    fn default() -> Self {
        Self {
            max_peers: 10000,
            peer_timeout_secs: 3600,
            auto_prune: true,
            static_peers: Vec::new(),
        }
    }
}

impl Default for PolicyEngineConfig {
    fn default() -> Self {
        Self {
            strict_mode: true,
            default_unknown_policy: "deny".to_string(),
            cache_decisions: true,
            cache_ttl_secs: 300, // 5 minutes
        }
    }
}

impl Default for ViolationLoggingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_violations: 10000,
            log_to_stderr: true,
            log_file: None,
            log_level: "info".to_string(),
        }
    }
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            transport_type: "tcp".to_string(),
            settings: {
                let mut map = BTreeMap::new();
                map.insert("host".to_string(), "127.0.0.1".to_string());
                map.insert("port".to_string(), "8080".to_string());
                map
            },
        }
    }
}

#[cfg(feature = "config")]
impl RouterConfig {
    /// Load configuration from TOML string.
    pub fn from_toml(toml_str: &str) -> Result<Self, ConfigError> {
        toml::from_str(toml_str).map_err(|e| ConfigError::ParseError(e.to_string()))
    }

    /// Load configuration from TOML file.
    pub fn from_file(path: &str) -> Result<Self, ConfigError> {
        let content =
            std::fs::read_to_string(path).map_err(|e| ConfigError::IoError(e.to_string()))?;
        Self::from_toml(&content)
    }

    /// Save configuration to TOML string.
    pub fn to_toml(&self) -> Result<String, ConfigError> {
        toml::to_string_pretty(self).map_err(|e| ConfigError::SerializeError(e.to_string()))
    }

    /// Save configuration to TOML file.
    pub fn to_file(&self, path: &str) -> Result<(), ConfigError> {
        let toml_str = self.to_toml()?;
        std::fs::write(path, toml_str).map_err(|e| ConfigError::IoError(e.to_string()))?;
        Ok(())
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Validate local zone
        if self.local_zone.zone.is_empty() {
            return Err(ConfigError::ValidationError(
                "Local zone cannot be empty".to_string(),
            ));
        }

        // Validate zone format
        if self.parse_zone(&self.local_zone.zone).is_err() {
            return Err(ConfigError::ValidationError(format!(
                "Invalid zone format: {}",
                self.local_zone.zone
            )));
        }

        // Validate policies
        for policy in &self.local_zone.policies {
            if policy.name.is_empty() {
                return Err(ConfigError::ValidationError(
                    "Policy name cannot be empty".to_string(),
                ));
            }

            if !matches!(
                policy.default_action.as_str(),
                "allow" | "deny" | "require_agreement"
            ) {
                return Err(ConfigError::ValidationError(format!(
                    "Invalid default action: {}",
                    policy.default_action
                )));
            }
        }

        Ok(())
    }

    /// Parse zone string to ResidencyTag.
    pub fn parse_zone(&self, zone_str: &str) -> Result<ResidencyTag, ConfigError> {
        match zone_str {
            "GLOBAL" => Ok(ResidencyTag::GLOBAL),
            "INDONESIA" => Ok(ResidencyTag::INDONESIA),
            "MALAYSIA" => Ok(ResidencyTag::MALAYSIA),
            "PHILIPPINES" => Ok(ResidencyTag::PHILIPPINES),
            "VIETNAM" => Ok(ResidencyTag::VIETNAM),
            "SINGAPORE" => Ok(ResidencyTag::SINGAPORE),
            _ => {
                // Try to parse as numeric code
                if let Ok(code) = zone_str.parse::<u16>() {
                    ResidencyTag::from_country_code(code).ok_or_else(|| {
                        ConfigError::ValidationError(format!("Invalid country code: {}", code))
                    })
                } else {
                    Err(ConfigError::ValidationError(format!(
                        "Unknown zone: {}",
                        zone_str
                    )))
                }
            }
        }
    }
}

/// Configuration errors.
#[derive(Debug, Clone)]
pub enum ConfigError {
    /// Parse error
    ParseError(String),
    /// Serialize error
    SerializeError(String),
    /// I/O error
    IoError(String),
    /// Validation error
    ValidationError(String),
}

impl core::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ConfigError::ParseError(msg) => write!(f, "Parse error: {}", msg),
            ConfigError::SerializeError(msg) => write!(f, "Serialize error: {}", msg),
            ConfigError::IoError(msg) => write!(f, "I/O error: {}", msg),
            ConfigError::ValidationError(msg) => write!(f, "Validation error: {}", msg),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ConfigError {}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "alloc")]
    use alloc::string::ToString;

    #[cfg(feature = "config")]
    use super::RouterConfig;

    #[test]
    fn test_default_config() {
        let config = RouterConfig::default();

        assert_eq!(config.local_zone.zone, "360");
        assert_eq!(config.local_zone.name, "Indonesia");
        assert!(config.local_zone.local);
        assert_eq!(config.peer_registry.max_peers, 10000);
        assert!(config.policy_engine.strict_mode);
        assert!(config.violation_logging.enabled);
    }

    #[cfg(feature = "config")]
    #[test]
    fn test_toml_serialization() {
        let config = RouterConfig::default();

        let toml_str = config.to_toml().unwrap();
        assert!(!toml_str.is_empty());

        let parsed = RouterConfig::from_toml(&toml_str).unwrap();
        assert_eq!(parsed.local_zone.zone, config.local_zone.zone);
        assert_eq!(parsed.local_zone.name, config.local_zone.name);
    }

    #[cfg(feature = "config")]
    #[test]
    fn test_zone_parsing() {
        let config = RouterConfig::default();

        // Test named zones
        assert_eq!(config.parse_zone("GLOBAL").unwrap(), ResidencyTag::GLOBAL);
        assert_eq!(
            config.parse_zone("INDONESIA").unwrap(),
            ResidencyTag::INDONESIA
        );

        // Test numeric codes
        assert_eq!(config.parse_zone("360").unwrap(), ResidencyTag::INDONESIA);
        assert_eq!(config.parse_zone("458").unwrap(), ResidencyTag::MALAYSIA);

        // Test invalid zone
        assert!(config.parse_zone("INVALID").is_err());
        assert!(config.parse_zone("99999").is_err());
    }

    #[test]
    fn test_config_validation() {
        let config = RouterConfig::default();
        assert!(config.validate().is_ok());

        // Test invalid config
        let mut invalid_config = config.clone();
        invalid_config.local_zone.zone = "".to_string();
        assert!(invalid_config.validate().is_err());
    }
}
