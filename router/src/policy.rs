//! Zone validation and routing policy engine.
//!
//! Enforces data residency policies and makes routing decisions
//! based on zone compliance and cross-border agreements.

#[cfg(feature = "alloc")]
use alloc::{
    collections::BTreeMap, collections::BTreeSet, string::String, string::ToString, vec::Vec,
};
use clonic_core::ResidencyTag;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Result of a routing decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum RoutingDecision {
    /// Allow routing to the destination
    Allow,
    /// Deny routing - policy violation
    Deny,
    /// Route through specific intermediary
    RouteVia([u8; 32]),
}

/// Reason for a routing decision.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum DecisionReason {
    /// Same zone - allowed
    SameZone,
    /// Global data - allowed anywhere
    GlobalData,
    /// Explicit allowlist match
    Allowlisted,
    /// Explicit denylist match
    Denylisted,
    /// Cross-border agreement allows
    CrossBorderAgreement,
    /// No cross-border agreement - denied
    NoAgreement,
    /// Default action allows
    DefaultAllow,
    /// Default action denies
    DefaultDeny,
    /// Expired cross-border agreement
    ExpiredAgreement,
    /// Destination zone unknown
    UnknownDestination,
    /// Source zone unknown
    UnknownSource,
    /// Policy error
    PolicyError(String),
}

impl DecisionReason {
    /// Returns a stable string code for metric labeling.
    ///
    /// Unlike `Debug`, this provides consistent, stable identifiers
    /// that won't change if enum variant names are refactored.
    pub fn as_code(&self) -> &'static str {
        match self {
            DecisionReason::SameZone => "same_zone",
            DecisionReason::GlobalData => "global_data",
            DecisionReason::Allowlisted => "allowlisted",
            DecisionReason::Denylisted => "denylisted",
            DecisionReason::CrossBorderAgreement => "cross_border_agreement",
            DecisionReason::NoAgreement => "no_agreement",
            DecisionReason::DefaultAllow => "default_allow",
            DecisionReason::DefaultDeny => "default_deny",
            DecisionReason::ExpiredAgreement => "expired_agreement",
            DecisionReason::UnknownDestination => "unknown_destination",
            DecisionReason::UnknownSource => "unknown_source",
            DecisionReason::PolicyError(_) => "policy_error",
        }
    }
}

/// Cross-border agreement between zones.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CrossBorderAgreement {
    /// Source zone
    pub source_zone: ResidencyTag,
    /// Destination zone
    pub dest_zone: ResidencyTag,
    /// Agreement type
    pub agreement_type: AgreementType,
    /// Expiration timestamp (0 = no expiration)
    pub expires_at: u64,
    /// Data types allowed
    pub allowed_data_types: BTreeSet<String>,
    /// Required intermediary zones
    pub required_intermediaries: Vec<ResidencyTag>,
}

/// Types of cross-border agreements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum AgreementType {
    /// Full bidirectional data sharing
    Full,
    /// One-way data flow
    OneWay,
    /// Limited to specific data types
    Limited,
    /// Emergency/exceptional circumstances only
    Emergency,
}

/// Zone policy configuration.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ZonePolicy {
    /// Zone this policy applies to
    pub zone: ResidencyTag,
    /// Explicitly allowed destination zones (using raw u16)
    pub allowlist: BTreeSet<u16>,
    /// Explicitly denied destination zones (using raw u16)
    pub denylist: BTreeSet<u16>,
    /// Cross-border agreements
    pub agreements: Vec<CrossBorderAgreement>,
    /// Default action for unspecified zones
    pub default_action: DefaultAction,
    /// Whether to log all routing decisions
    pub log_decisions: bool,
}

/// Default action for unspecified zones.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum DefaultAction {
    /// Allow by default
    Allow,
    /// Deny by default (most secure)
    Deny,
    /// Require explicit agreement
    RequireAgreement,
}

/// Policy engine for zone validation and routing decisions.
#[derive(Debug)]
#[cfg(feature = "alloc")]
pub struct PolicyEngine {
    /// Zone policies indexed by zone (using raw u16 as key)
    policies: BTreeMap<u16, ZonePolicy>,
    /// Global cross-border agreements
    global_agreements: Vec<CrossBorderAgreement>,
    /// Current timestamp for agreement validation
    current_time: u64,
}

#[cfg(feature = "alloc")]
impl PolicyEngine {
    /// Create a new policy engine.
    pub fn new() -> Self {
        Self {
            policies: BTreeMap::new(),
            global_agreements: Vec::new(),
            current_time: 0,
        }
    }

    /// Set the current time (for agreement expiration).
    pub fn set_current_time(&mut self, time: u64) {
        self.current_time = time;
    }

    /// Add a zone policy.
    pub fn add_zone_policy(&mut self, policy: ZonePolicy) {
        self.policies.insert(policy.zone.raw(), policy);
    }

    /// Add a global cross-border agreement.
    pub fn add_global_agreement(&mut self, agreement: CrossBorderAgreement) {
        self.global_agreements.push(agreement);
    }

    /// Make a routing decision for a message.
    pub fn route_message(
        &self,
        source_zone: ResidencyTag,
        dest_zone: ResidencyTag,
        data_type: &str,
    ) -> (RoutingDecision, DecisionReason) {
        // Check if source zone has a policy
        let source_policy = self.policies.get(&source_zone.raw());

        // Global data can go anywhere
        if source_zone.is_global() {
            return (RoutingDecision::Allow, DecisionReason::GlobalData);
        }

        // Same zone is always allowed
        if source_zone == dest_zone {
            return (RoutingDecision::Allow, DecisionReason::SameZone);
        }

        // Check explicit denylist first
        if let Some(policy) = source_policy {
            if policy.denylist.contains(&dest_zone.raw()) {
                return (RoutingDecision::Deny, DecisionReason::Denylisted);
            }

            // Check explicit allowlist
            if policy.allowlist.contains(&dest_zone.raw()) {
                return (RoutingDecision::Allow, DecisionReason::Allowlisted);
            }
        }

        // Check cross-border agreements
        if let Some(agreement) = self.find_agreement(source_zone, dest_zone, data_type) {
            if self.is_agreement_valid(agreement) {
                if agreement.required_intermediaries.is_empty() {
                    return (RoutingDecision::Allow, DecisionReason::CrossBorderAgreement);
                } else {
                    // For now, deny if intermediaries are required
                    // In a full implementation, we'd select an appropriate intermediary
                    return (
                        RoutingDecision::Deny,
                        DecisionReason::PolicyError(
                            "Required intermediaries not implemented".to_string(),
                        ),
                    );
                }
            } else {
                return (RoutingDecision::Deny, DecisionReason::ExpiredAgreement);
            }
        }

        // Apply default action
        if let Some(policy) = source_policy {
            match policy.default_action {
                DefaultAction::Allow => (RoutingDecision::Allow, DecisionReason::DefaultAllow),
                DefaultAction::Deny => (RoutingDecision::Deny, DecisionReason::DefaultDeny),
                DefaultAction::RequireAgreement => {
                    (RoutingDecision::Deny, DecisionReason::NoAgreement)
                }
            }
        } else {
            // No policy - default to deny for security
            (
                RoutingDecision::Deny,
                DecisionReason::PolicyError("No policy found for source zone".to_string()),
            )
        }
    }

    /// Validate a zone-to-zone connection.
    pub fn validate_connection(&self, local_zone: ResidencyTag, remote_zone: ResidencyTag) -> bool {
        let (_, reason) = self.route_message(local_zone, remote_zone, "connection");
        matches!(
            reason,
            DecisionReason::SameZone
                | DecisionReason::GlobalData
                | DecisionReason::Allowlisted
                | DecisionReason::CrossBorderAgreement
        )
    }

    /// Get all zones that a source zone can communicate with.
    pub fn reachable_zones(&self, source_zone: ResidencyTag, data_type: &str) -> Vec<ResidencyTag> {
        let mut reachable = Vec::new();

        // Add same zone
        reachable.push(source_zone);

        // Global zone can reach everywhere
        if source_zone.is_global() {
            // Add all zones from policies
            for zone_raw in self.policies.keys() {
                if let Some(zone) = ResidencyTag::from_country_code(*zone_raw) {
                    reachable.push(zone);
                }
            }
            return reachable;
        }

        // Check allowlist
        if let Some(policy) = self.policies.get(&source_zone.raw()) {
            for zone_raw in &policy.allowlist {
                if let Some(zone) = ResidencyTag::from_country_code(*zone_raw) {
                    reachable.push(zone);
                }
            }
        }

        // Check agreements
        for agreement in &self.global_agreements {
            if agreement.source_zone == source_zone
                && agreement.allowed_data_types.contains(data_type)
                && self.is_agreement_valid(agreement)
            {
                reachable.push(agreement.dest_zone);
            }
        }

        reachable
    }

    /// Find a cross-border agreement between zones.
    fn find_agreement(
        &self,
        source: ResidencyTag,
        dest: ResidencyTag,
        data_type: &str,
    ) -> Option<&CrossBorderAgreement> {
        // Check zone-specific agreements first
        if let Some(policy) = self.policies.get(&source.raw()) {
            for agreement in &policy.agreements {
                if agreement.source_zone == source
                    && agreement.dest_zone == dest
                    && agreement.allowed_data_types.contains(data_type)
                {
                    return Some(agreement);
                }
            }
        }

        // Check global agreements
        #[allow(clippy::manual_find)]
        self.global_agreements
            .iter()
            .find(|agreement| {
                agreement.source_zone == source
                    && agreement.dest_zone == dest
                    && agreement.allowed_data_types.contains(data_type)
            })
            .map(|v| v as _)
    }

    /// Check if an agreement is currently valid.
    fn is_agreement_valid(&self, agreement: &CrossBorderAgreement) -> bool {
        agreement.expires_at == 0 || agreement.expires_at > self.current_time
    }

    /// Get all policies.
    pub fn policies(&self) -> &BTreeMap<u16, ZonePolicy> {
        &self.policies
    }

    /// Get policy for a specific zone.
    pub fn get_policy(&self, zone: ResidencyTag) -> Option<&ZonePolicy> {
        self.policies.get(&zone.raw())
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "alloc")]
    use alloc::string::ToString;

    #[test]
    fn test_same_zone_allowed() {
        let engine = PolicyEngine::new();
        let (decision, reason) = engine.route_message(
            ResidencyTag::INDONESIA,
            ResidencyTag::INDONESIA,
            "test_data",
        );

        assert_eq!(decision, RoutingDecision::Allow);
        assert_eq!(reason, DecisionReason::SameZone);
    }

    #[test]
    fn test_global_data_allowed() {
        let engine = PolicyEngine::new();
        let (decision, reason) =
            engine.route_message(ResidencyTag::GLOBAL, ResidencyTag::INDONESIA, "test_data");

        assert_eq!(decision, RoutingDecision::Allow);
        assert_eq!(reason, DecisionReason::GlobalData);
    }

    #[test]
    fn test_allowlist_denylist() {
        let mut engine = PolicyEngine::new();

        let policy = ZonePolicy {
            zone: ResidencyTag::INDONESIA,
            allowlist: {
                let mut set = BTreeSet::new();
                set.insert(ResidencyTag::MALAYSIA.raw());
                set
            },
            denylist: {
                let mut set = BTreeSet::new();
                set.insert(ResidencyTag::SINGAPORE.raw());
                set
            },
            agreements: Vec::new(),
            default_action: DefaultAction::Deny,
            log_decisions: false,
        };

        engine.add_zone_policy(policy);

        // Allowlisted zone should be allowed
        let (decision, reason) =
            engine.route_message(ResidencyTag::INDONESIA, ResidencyTag::MALAYSIA, "test_data");
        assert_eq!(decision, RoutingDecision::Allow);
        assert_eq!(reason, DecisionReason::Allowlisted);

        // Denylisted zone should be denied
        let (decision, reason) = engine.route_message(
            ResidencyTag::INDONESIA,
            ResidencyTag::SINGAPORE,
            "test_data",
        );
        assert_eq!(decision, RoutingDecision::Deny);
        assert_eq!(reason, DecisionReason::Denylisted);

        // Unknown zone should be denied (default action)
        let (decision, reason) =
            engine.route_message(ResidencyTag::INDONESIA, ResidencyTag::VIETNAM, "test_data");
        assert_eq!(decision, RoutingDecision::Deny);
        assert_eq!(reason, DecisionReason::DefaultDeny);
    }

    #[test]
    fn test_cross_border_agreement() {
        let mut engine = PolicyEngine::new();

        let agreement = CrossBorderAgreement {
            source_zone: ResidencyTag::INDONESIA,
            dest_zone: ResidencyTag::MALAYSIA,
            agreement_type: AgreementType::Full,
            expires_at: 0, // No expiration
            allowed_data_types: {
                let mut set = BTreeSet::new();
                set.insert("test_data".to_string());
                set
            },
            required_intermediaries: Vec::new(),
        };

        engine.add_global_agreement(agreement);

        let (decision, reason) =
            engine.route_message(ResidencyTag::INDONESIA, ResidencyTag::MALAYSIA, "test_data");

        assert_eq!(decision, RoutingDecision::Allow);
        assert_eq!(reason, DecisionReason::CrossBorderAgreement);
    }

    #[test]
    fn test_agreement_expiration() {
        let mut engine = PolicyEngine::new();
        engine.set_current_time(1000);

        let agreement = CrossBorderAgreement {
            source_zone: ResidencyTag::INDONESIA,
            dest_zone: ResidencyTag::MALAYSIA,
            agreement_type: AgreementType::Full,
            expires_at: 500, // Expired
            allowed_data_types: {
                let mut set = BTreeSet::new();
                set.insert("test_data".to_string());
                set
            },
            required_intermediaries: Vec::new(),
        };

        engine.add_global_agreement(agreement);

        let (decision, reason) =
            engine.route_message(ResidencyTag::INDONESIA, ResidencyTag::MALAYSIA, "test_data");

        assert_eq!(decision, RoutingDecision::Deny);
        assert_eq!(reason, DecisionReason::ExpiredAgreement);
    }

    #[test]
    fn test_reachable_zones() {
        let mut engine = PolicyEngine::new();

        let policy = ZonePolicy {
            zone: ResidencyTag::INDONESIA,
            allowlist: {
                let mut set = BTreeSet::new();
                set.insert(ResidencyTag::MALAYSIA.raw());
                set
            },
            denylist: BTreeSet::new(),
            agreements: Vec::new(),
            default_action: DefaultAction::Deny,
            log_decisions: false,
        };

        engine.add_zone_policy(policy);

        let reachable = engine.reachable_zones(ResidencyTag::INDONESIA, "test_data");

        assert!(reachable.contains(&ResidencyTag::INDONESIA)); // Same zone
        assert!(reachable.contains(&ResidencyTag::MALAYSIA)); // Allowlisted
        assert!(!reachable.contains(&ResidencyTag::SINGAPORE)); // Not allowed
    }
}
