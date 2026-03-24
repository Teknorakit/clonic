# Zone Configuration Cookbook

This guide provides practical examples and patterns for configuring zones in the Zone Coordination Protocol (ZCP).

## Overview

Zones define geographical and organizational boundaries for data residency. Each zone has specific policies that govern how data can flow between devices and across zone boundaries.

## Zone Configuration Basics

### Zone Definition
```rust
use clonic_core::ResidencyTag;

pub struct ZoneConfig {
    pub zone_id: u16,
    pub name: String,
    pub residency_tag: ResidencyTag,
    pub max_chain_depth: u8,
    pub certificate_expiry_days: u32,
    pub allowed_device_types: Vec<DeviceType>,
    pub cross_zone_policies: Vec<CrossZonePolicy>,
    pub enforcement: EnforcementLevel,
}

pub enum EnforcementLevel {
    Strict,    // Block all violations
    Warning,   // Log violations but allow
    Permissive, // Allow with minimal logging
}
```

### ISO 3166-1 Country Codes
```rust
// Indonesia (Zone 360)
let indonesia_zone = ZoneConfig {
    zone_id: 360,
    name: "Indonesia".to_string(),
    residency_tag: ResidencyTag::from_country_code(360)?,
    max_chain_depth: 2,
    certificate_expiry_days: 365,
    allowed_device_types: vec![
        DeviceType::Server,
        DeviceType::IoTSensor,
        DeviceType::Mobile,
    ],
    cross_zone_policies: vec![],
    enforcement: EnforcementLevel::Strict,
};

// Singapore (Zone 702) 
let singapore_zone = ZoneConfig {
    zone_id: 702,
    name: "Singapore".to_string(),
    residency_tag: ResidencyTag::from_country_code(702)?,
    max_chain_depth: 2,
    certificate_expiry_days: 730,
    allowed_device_types: vec![
        DeviceType::Server,
        DeviceType::Gateway,
        DeviceType::Mobile,
    ],
    cross_zone_policies: vec![
        CrossZonePolicy {
            target_zone: 360, // Indonesia
            allowed_data_types: vec![
                DataType::SensorReadings,
                DataType::AggregatedMetrics,
            ],
            require_mutual_auth: true,
            audit_logging: true,
        },
    ],
    enforcement: EnforcementLevel::Strict,
};
```

## Common Zone Patterns

### 1. National Zone (Strict Enforcement)
```rust
pub fn create_national_zone(country_code: u16, country_name: &str) -> ZoneConfig {
    ZoneConfig {
        zone_id: country_code,
        name: country_name.to_string(),
        residency_tag: ResidencyTag::from_country_code(country_code)
            .expect("Invalid country code"),
        max_chain_depth: 2, // Root → Server → Device
        certificate_expiry_days: 365,
        allowed_device_types: vec![
            DeviceType::Server,
            DeviceType::IoTSensor,
            DeviceType::Gateway,
            DeviceType::Mobile,
        ],
        cross_zone_policies: vec![],
        enforcement: EnforcementLevel::Strict,
    }
}
```

### 2. Regional Economic Zone
```rust
pub fn create_economic_zone(zone_id: u16, name: &str, member_countries: &[u16]) -> ZoneConfig {
    let mut cross_zone_policies = Vec::new();
    
    // Allow data flow between member states
    for &country in member_countries {
        if country != zone_id {
            cross_zone_policies.push(CrossZonePolicy {
                target_zone: country,
                allowed_data_types: vec![
                    DataType::BusinessData,
                    DataType::FinancialTransactions,
                    DataType::SupplyChain,
                ],
                require_mutual_auth: true,
                audit_logging: true,
            });
        }
    }
    
    ZoneConfig {
        zone_id,
        name: name.to_string(),
        residency_tag: ResidencyTag::from_country_code(zone_id)
            .expect("Invalid country code"),
        max_chain_depth: 3, // Allow deeper delegation
        certificate_expiry_days: 730,
        allowed_device_types: vec![
            DeviceType::Server,
            DeviceType::Gateway,
            DeviceType::Mobile,
            DeviceType::IoTSensor,
        ],
        cross_zone_policies,
        enforcement: EnforcementLevel::Warning,
    }
}
```

### 3. Special Administrative Zone
```rust
pub fn create_administrative_zone(zone_id: u16, name: &str) -> ZoneConfig {
    ZoneConfig {
        zone_id,
        name: name.to_string(),
        residency_tag: ResidencyTag::from_country_code(zone_id)
            .expect("Invalid country code"),
        max_chain_depth: 1, // Only root → server
        certificate_expiry_days: 180, // Shorter expiry for admin zones
        allowed_device_types: vec![
            DeviceType::Server,
            DeviceType::Gateway,
        ],
        cross_zone_policies: vec![
            CrossZonePolicy {
                target_zone: 360, // Indonesia
                allowed_data_types: vec![
                    DataType::AdministrativeData,
                    DataType::AuditLogs,
                ],
                require_mutual_auth: true,
                audit_logging: true,
            },
        ],
        enforcement: EnforcementLevel::Strict,
    }
}
```

## Cross-Zone Data Policies

### Data Type Classifications
```rust
#[derive(Debug, Clone, PartialEq)]
pub enum DataType {
    // Personal Data
    PersonalIdentifiable,
    BiometricData,
    HealthData,
    FinancialData,
    
    // Business Data
    BusinessData,
    SupplyChain,
    CustomerData,
    AnalyticsData,
    
    // Operational Data
    SensorReadings,
    SystemLogs,
    AuditLogs,
    Metrics,
    
    // Public Data
    PublicAnnouncements,
    AggregatedMetrics,
    WeatherData,
}
```

### Policy Templates

#### Personal Data Protection
```rust
pub fn personal_data_policy(target_zone: u16) -> CrossZonePolicy {
    CrossZonePolicy {
        target_zone,
        allowed_data_types: vec![
            DataType::PersonalIdentifiable,
            DataType::BiometricData,
            DataType::HealthData,
        ],
        require_mutual_auth: true,
        audit_logging: true,
    }
}
```

#### Research Collaboration
```rust
pub fn research_collaboration_policy(target_zone: u16) -> CrossZonePolicy {
    CrossZonePolicy {
        target_zone,
        allowed_data_types: vec![
            DataType::SensorReadings,
            DataType::AnalyticsData,
            DataType::AggregatedMetrics,
        ],
        require_mutual_auth: false,
        audit_logging: true,
    }
}
```

#### Supply Chain Integration
```rust
pub fn supply_chain_policy(target_zone: u16) -> CrossZonePolicy {
    CrossZonePolicy {
        target_zone,
        allowed_data_types: vec![
            DataType::BusinessData,
            DataType::SupplyChain,
            DataType::CustomerData,
        ],
        require_mutual_auth: true,
        audit_logging: true,
    }
}
```

## Device Type Configuration

### Device Types and Capabilities
```rust
#[derive(Debug, Clone, PartialEq)]
pub enum DeviceType {
    // Infrastructure
    Server,
    Gateway,
    Router,
    
    // Endpoints
    IoTSensor,
    Mobile,
    Desktop,
    
    // Specialized
    MedicalDevice,
    IndustrialController,
    FinancialTerminal,
}

impl DeviceType {
    pub fn max_certificate_depth(&self) -> u8 {
        match self {
            DeviceType::Server => 3,        // Can issue device certificates
            DeviceType::Gateway => 2,       // Can issue device certificates
            DeviceType::Router => 1,        // Leaf node only
            DeviceType::IoTSensor => 1,     // Leaf node only
            DeviceType::Mobile => 1,        // Leaf node only
            DeviceType::Desktop => 1,       // Leaf node only
            DeviceType::MedicalDevice => 1,  // Leaf node only
            DeviceType::IndustrialController => 1,
            DeviceType::FinancialTerminal => 1,
        }
    }
    
    pub fn required_features(&self) -> Vec<Feature> {
        match self {
            DeviceType::Server => vec![Feature::HighAvailability, Feature::AuditLogging],
            DeviceType::Gateway => vec![Feature::PacketFiltering, Feature::RateLimiting],
            DeviceType::IoTSensor => vec![Feature::LowPower, Feature::SecureBoot],
            DeviceType::Mobile => vec![Feature::SecureStorage, Feature::RemoteWipe],
            _ => vec![],
        }
    }
}
```

## Enforcement Configuration

### Enforcement Levels
```rust
#[derive(Debug, Clone, PartialEq)]
pub enum EnforcementLevel {
    Strict {
        block_violations: bool,
        alert_threshold: u32,
        auto_revocation: bool,
    },
    Warning {
        log_violations: bool,
        alert_threshold: u64,
        grace_period_hours: u32,
    },
    Permissive {
        audit_only: bool,
        reporting_interval: Duration,
    },
}
```

### Violation Handling
```rust
pub struct ZoneEnforcer {
    config: ZoneConfig,
    violation_log: Vec<PolicyViolation>,
    metrics: EnforcementMetrics,
}

impl ZoneEnforcer {
    pub fn new(config: ZoneConfig) -> Self {
        Self {
            config,
            violation_log: Vec::new(),
            metrics: EnforcementMetrics::default(),
        }
    }
    
    pub fn check_cross_zone_transfer(
        &mut self,
        source_zone: u16,
        target_zone: u16,
        data_type: DataType,
    ) -> EnforcementResult {
        if source_zone == target_zone {
            return EnforcementResult::Allowed;
        }
        
        // Find applicable policy
        let policy = self.config.cross_zone_policies
            .iter()
            .find(|p| p.target_zone == target_zone);
        
        match policy {
            Some(policy) if policy.allowed_data_types.contains(&data_type) => {
                self.handle_allowed_transfer(source_zone, target_zone, data_type)
            }
            Some(_) => {
                self.handle_violation(source_zone, target_zone, data_type)
            }
            None => {
                self.handle_default_policy(source_zone, target_zone, data_type)
            }
        }
    }
    
    fn handle_allowed_transfer(
        &mut self,
        source_zone: u16,
        target_zone: u16,
        data_type: DataType,
    ) -> EnforcementResult {
        // Log successful transfer
        self.metrics.successful_transfers += 1;
        
        EnforcementResult::Allowed
    }
    
    fn handle_violation(
        &mut self,
        source_zone: u16,
        target_zone: u16,
        data_type: DataType,
    ) -> EnforcementResult {
        let violation = PolicyViolation {
            timestamp: current_unix_timestamp(),
            source_zone,
            target_zone,
            data_type,
            violation_type: ViolationType::UnauthorizedTransfer,
        };
        
        self.violation_log.push(violation.clone());
        
        match &self.config.enforcement {
            EnforcementLevel::Strict { block_violations, .. } => {
                if *block_violations {
                    EnforcementResult::Blocked(violation)
                } else {
                    EnforcementResult::AllowedWithWarning(violation)
                }
            }
            EnforcementLevel::Warning { .. } => {
                EnforcementResult::AllowedWithWarning(violation)
            }
            EnforcementLevel::Permissive { .. } => {
                EnforcementResult::Allowed
            }
        }
    }
}
```

## Configuration Examples

### ASEAN Economic Community
```rust
pub fn create_asean_zone() -> ZoneConfig {
    let member_states = vec![360, 702, 458, 704, 418]; // Indonesia, Singapore, Myanmar, Laos, Thailand
    
    ZoneConfig {
        zone_id: 999, // Special ASEAN zone ID
        name: "ASEAN Economic Community".to_string(),
        residency_tag: ResidencyTag::from_country_code(999)
            .expect("Invalid country code"),
        max_chain_depth: 3,
        certificate_expiry_days: 1095, // 3 years
        allowed_device_types: vec![
            DeviceType::Server,
            DeviceType::Gateway,
            DeviceType::Mobile,
            DeviceType::IoTSensor,
        ],
        cross_zone_policies: member_states.iter().map(|&country| {
            CrossZonePolicy {
                target_zone: country,
                allowed_data_types: vec![
                    DataType::BusinessData,
                    DataType::SupplyChain,
                    DataType::CustomerData,
                ],
                require_mutual_auth: true,
                audit_logging: true,
            }
        }).collect(),
        enforcement: EnforcementLevel::Warning,
    }
}
```

### Healthcare Data Zone
```rust
pub fn create_healthcare_zone(country_code: u16) -> ZoneConfig {
    ZoneConfig {
        zone_id: country_code,
        name: format!("Healthcare Zone - {}", country_code),
        residency_tag: ResidencyTag::from_country_code(country_code)
            .expect("Invalid country code"),
        max_chain_depth: 2,
        certificate_expiry_days: 730,
        allowed_device_types: vec![
            DeviceType::Server,
            DeviceType::Gateway,
            DeviceType::MedicalDevice,
            DeviceType::Mobile,
        ],
        cross_zone_policies: vec![
            // Allow medical research collaboration
            CrossZonePolicy {
                target_zone: 360, // Indonesia
                allowed_data_types: vec![
                    DataType::HealthData,
                    DataType::AnalyticsData,
                    DataType::AggregatedMetrics,
                ],
                require_mutual_auth: true,
                audit_logging: true,
            },
        ],
        enforcement: EnforcementLevel::Strict {
            block_violations: true,
            alert_threshold: 10,
            auto_revocation: true,
        },
    }
}
```

### Financial Services Zone
```rust
pub fn create_financial_zone(country_code: u16) -> ZoneConfig {
    ZoneConfig {
        zone_id: country_code,
        name: format!("Financial Services Zone - {}", country_code),
        residency_tag: ResidencyTag::from_country_code(country_code)
            .expect("Invalid country code"),
        max_chain_depth: 2,
        certificate_expiry_days: 90, // Short expiry for financial
        allowed_device_types: vec![
            DeviceType::Server,
            DeviceType::Gateway,
            DeviceType::FinancialTerminal,
            DeviceType::Mobile,
        ],
        cross_zone_policies: vec![
            // Inter-bank transactions
            CrossZonePolicy {
                target_zone: 702, // Singapore
                allowed_data_types: vec![
                    DataType::FinancialTransactions,
                    DataType::BusinessData,
                ],
                require_mutual_auth: true,
                audit_logging: true,
            },
        ],
        enforcement: EnforcementLevel::Strict {
            block_violations: true,
            alert_threshold: 5,
            auto_revocation: true,
        },
    }
}
```

## Migration and Updates

### Zone Configuration Updates
```rust
pub struct ZoneConfigManager {
    configs: HashMap<u16, ZoneConfig>,
    version: u64,
}

impl ZoneConfigManager {
    pub fn update_zone_config(
        &mut self,
        zone_id: u16,
        new_config: ZoneConfig,
    ) -> Result<(), ConfigError> {
        // Validate new configuration
        self.validate_config(&new_config)?;
        
        // Create migration plan
        let migration = MigrationPlan::new(
            &self.configs[&zone_id],
            &new_config,
        );
        
        // Apply migration
        migration.execute(self)?;
        
        // Update configuration
        self.configs.insert(zone_id, new_config);
        self.version += 1;
        
        Ok(())
    }
    
    fn validate_config(&self, config: &ZoneConfig) -> Result<(), ConfigError> {
        // Validate residency tag
        if !config.residency_tag.is_valid() {
            return Err(ConfigError::InvalidResidencyTag);
        }
        
        // Validate chain depth
        if config.max_chain_depth > 5 {
            return Err(ConfigError::ChainDepthTooHigh);
        }
        
        // Validate cross-zone policies
        for policy in &config.cross_zone_policies {
            if policy.target_zone == config.zone_id {
                return Err(ConfigError::SelfReferencingPolicy);
            }
        }
        
        Ok(())
    }
}
```

### Migration Strategies
```rust
pub struct MigrationPlan {
    zone_id: u16,
    old_config: ZoneConfig,
    new_config: ZoneConfig,
    changes: Vec<ConfigChange>,
}

impl MigrationPlan {
    pub fn new(old_config: &ZoneConfig, new_config: &ZoneConfig) -> Self {
        let mut changes = Vec::new();
        
        // Detect changes
        if old_config.max_chain_depth != new_config.max_chain_depth {
            changes.push(ConfigChange::ChainDepthChanged {
                old: old_config.max_chain_depth,
                new: new_config.max_chain_depth,
            });
        }
        
        if old_config.enforcement != new_config.enforcement {
            changes.push(ConfigChange::EnforcementChanged {
                old: old_config.enforcement.clone(),
                new: new_config.enforcement.clone(),
            });
        }
        
        Self {
            zone_id: old_config.zone_id,
            old_config: old_config.clone(),
            new_config: new_config.clone(),
            changes,
        }
    }
    
    pub fn execute(&self, manager: &mut ZoneConfigManager) -> Result<(), ConfigError> {
        for change in &self.changes {
            match change {
                ConfigChange::ChainDepthChanged { old, new } => {
                    if new < *old {
                        // Reducing chain depth requires certificate reissuance
                        manager.revoke_deep_certificates(self.zone_id, *new)?;
                    }
                }
                ConfigChange::EnforcementChanged { old, new } => {
                    // Update enforcement policies
                    manager.update_enforcement_policies(self.zone_id, new)?;
                }
            }
        }
        
        Ok(())
    }
}
```

## Best Practices

### Zone Design Principles
1. **Clear Boundaries**: Zones should have clear geographical or organizational boundaries
2. **Minimal Overlap**: Avoid excessive cross-zone policies that create complexity
3. **Regular Review**: Review and update zone configurations quarterly
4. **Documentation**: Maintain clear documentation for zone policies and exceptions

### Security Considerations
1. **Principle of Least Privilege**: Only allow necessary data flows
2. **Defense in Depth**: Multiple layers of validation and enforcement
3. **Transparency**: Clear audit trails for all cross-zone data transfers
4. **Incident Response**: Procedures for handling policy violations

### Performance Optimization
1. **Policy Caching**: Cache frequently accessed policy decisions
2. **Batch Validation**: Validate multiple transfers together when possible
3. **Async Enforcement**: Use non-blocking enforcement for high-traffic zones
4. **Resource Limits**: Set appropriate limits on policy evaluation

## Troubleshooting

### Common Configuration Issues

#### Invalid Residency Tags
```bash
# Validate country codes
curl -s "https://restcountries.com/v3.1/alpha/ID" | jq ".alpha2Code"
```

#### Chain Depth Conflicts
```rust
// Check certificate chain depth
fn validate_certificate_chain(cert: &Certificate, max_depth: u8) -> bool {
    cert.chain_depth <= max_depth
}
```

#### Cross-Zone Policy Loops
```rust
// Detect circular policies
fn detect_policy_loops(configs: &[ZoneConfig]) -> Vec<PolicyLoop> {
    // Implement cycle detection algorithm
    todo!()
}
```

### Debug Tools

```rust
// Enable zone configuration debugging
env_logger::init_from_env(
    EnvLogger::default().filter_level(log::LevelFilter::Debug)
);

// Zone configuration validation
let validation_result = zone_config.validate();
println!("Zone validation: {:?}", validation_result);

// Policy evaluation tracing
let enforcement_result = enforcer.check_cross_zone_transfer(360, 702, DataType::BusinessData);
println!("Enforcement result: {:?}", enforcement_result);
```

## References

- [ISO 3166-1 Country Codes](https://www.iso.org/iso-3161-country-codes.html)
- [ASEAN Digital Data Governance Framework](https://asean.org/)
- [Indonesia PP 71/2019](https://kominfo.go.id/)
- [Singapore PDPA](https://www.pdpc.gov.sg/)
- [GDPR Article 44-49](https://gdpr.eu/)
