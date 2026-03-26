//! Peer registry for zone-aware routing.
//!
//! Maps device IDs to their zone locations and maintains the
//! routing topology for zone enforcement.

#[cfg(feature = "alloc")]
use alloc::{collections::BTreeMap, string::String, string::ToString, vec::Vec};
use clonic_core::ResidencyTag;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Information about a peer in the network.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PeerInfo {
    /// Unique device identifier (Ed25519 public key)
    pub device_id: [u8; 32],
    /// Zone where this peer is physically located
    pub zone: ResidencyTag,
    /// Peer address information
    pub address: PeerAddress,
    /// Last seen timestamp
    pub last_seen: u64,
    /// Peer capabilities and metadata
    pub metadata: PeerMetadata,
}

/// Network address information for a peer.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum PeerAddress {
    /// TCP address (host:port)
    Tcp(String),
    /// BLE address
    Ble([u8; 6]),
    /// LoRaWAN device ID
    LoRaWAN([u8; 8]),
    /// Custom address format
    Custom(Vec<u8>),
}

/// Peer metadata and capabilities.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PeerMetadata {
    /// Peer version
    pub version: String,
    /// Supported crypto suites
    pub crypto_suites: Vec<u8>,
    /// Maximum payload size
    pub max_payload: usize,
    /// Peer type (full node, edge device, etc.)
    pub peer_type: PeerType,
    /// Additional key-value metadata
    pub attributes: BTreeMap<String, String>,
}

/// Types of peers in the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum PeerType {
    /// Full node with routing capabilities
    FullNode,
    /// Edge device with minimal capabilities
    EdgeDevice,
    /// Gateway device
    Gateway,
    /// Mobile device
    Mobile,
}

/// Registry of peers with zone mapping.
#[derive(Debug)]
#[cfg(feature = "alloc")]
pub struct PeerRegistry {
    /// Map of device_id -> PeerInfo
    peers: BTreeMap<[u8; 32], PeerInfo>,
    /// Zone-based peer index for fast lookup (using raw u16 as key)
    zone_index: BTreeMap<u16, Vec<[u8; 32]>>,
    /// Configuration settings
    config: RegistryConfig,
}

/// Configuration for the peer registry.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RegistryConfig {
    /// Maximum number of peers to track
    pub max_peers: usize,
    /// Peer timeout in seconds
    pub peer_timeout_secs: u64,
    /// Whether to automatically prune inactive peers
    pub auto_prune: bool,
}

impl Default for RegistryConfig {
    fn default() -> Self {
        Self {
            max_peers: 10000,
            peer_timeout_secs: 3600, // 1 hour
            auto_prune: true,
        }
    }
}

#[cfg(feature = "alloc")]
impl PeerRegistry {
    /// Create a new peer registry.
    pub fn new(config: RegistryConfig) -> Self {
        Self {
            peers: BTreeMap::new(),
            zone_index: BTreeMap::new(),
            config,
        }
    }

    /// Register a new peer.
    pub fn register_peer(&mut self, peer: PeerInfo) -> Result<(), RegistryError> {
        if self.peers.len() >= self.config.max_peers {
            return Err(RegistryError::RegistryFull);
        }

        // Validate peer information
        if peer.device_id == [0u8; 32] {
            return Err(RegistryError::InvalidPeer(
                "Device ID cannot be all zeros".to_string(),
            ));
        }

        let device_id = peer.device_id;
        let old_zone = self.peers.get(&device_id).map(|p| p.zone);
        let new_zone = peer.zone;

        // Update peer registry
        self.peers.insert(device_id, peer.clone());

        // Update zone index - only if zone changed or new peer
        if old_zone != Some(new_zone) {
            if let Some(old_zone) = old_zone {
                self.remove_from_zone_index(&device_id, old_zone.raw());
            }
            self.add_to_zone_index(&device_id, new_zone.raw());
        }

        tracing::debug!("Registered peer: {:?} in zone {:?}", device_id, new_zone);
        Ok(())
    }

    /// Unregister a peer.
    pub fn unregister_peer(&mut self, device_id: &[u8; 32]) -> Option<PeerInfo> {
        if let Some(peer) = self.peers.remove(device_id) {
            self.remove_from_zone_index(device_id, peer.zone.raw());
            tracing::debug!("Unregistered peer: {:?}", device_id);
            Some(peer)
        } else {
            None
        }
    }

    /// Get peer information.
    pub fn get_peer(&self, device_id: &[u8; 32]) -> Option<&PeerInfo> {
        self.peers.get(device_id)
    }

    /// Get all peers in a specific zone.
    pub fn get_peers_in_zone(&self, zone: ResidencyTag) -> Vec<&PeerInfo> {
        if let Some(device_ids) = self.zone_index.get(&zone.raw()) {
            device_ids
                .iter()
                .filter_map(|id| self.peers.get(id))
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Find peers that can route to a destination zone.
    pub fn find_routers_to_zone(&self, dest_zone: ResidencyTag) -> Vec<&PeerInfo> {
        self.peers
            .values()
            .filter(|peer| {
                peer.metadata.peer_type == PeerType::FullNode
                    && (peer.zone == dest_zone || peer.zone == ResidencyTag::GLOBAL)
            })
            .collect()
    }

    /// Update peer last seen timestamp.
    pub fn update_last_seen(&mut self, device_id: &[u8; 32], timestamp: u64) -> bool {
        if let Some(peer) = self.peers.get_mut(device_id) {
            peer.last_seen = timestamp;
            true
        } else {
            false
        }
    }

    /// Prune inactive peers based on timeout.
    pub fn prune_inactive(&mut self, current_time: u64) -> usize {
        if !self.config.auto_prune {
            return 0;
        }

        let timeout = self.config.peer_timeout_secs;
        let mut to_remove = Vec::new();

        for (device_id, peer) in &self.peers {
            // Use explicit comparison to handle clock skew properly
            if peer.last_seen + timeout < current_time {
                to_remove.push(*device_id);
            }
        }

        let removed = to_remove.len();
        for device_id in to_remove {
            self.unregister_peer(&device_id);
        }

        if removed > 0 {
            tracing::debug!("Pruned {} inactive peers", removed);
        }

        removed
    }

    /// Get the number of registered peers.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Get all peers.
    pub fn all_peers(&self) -> Vec<&PeerInfo> {
        self.peers.values().collect()
    }

    /// Add peer to zone index.
    fn add_to_zone_index(&mut self, device_id: &[u8; 32], zone_raw: u16) {
        let peers = self.zone_index.entry(zone_raw).or_default();
        if !peers.contains(device_id) {
            peers.push(*device_id);
        }
    }

    /// Remove peer from zone index.
    fn remove_from_zone_index(&mut self, device_id: &[u8; 32], zone_raw: u16) {
        if let Some(peers) = self.zone_index.get_mut(&zone_raw) {
            peers.retain(|id| id != device_id);
            if peers.is_empty() {
                self.zone_index.remove(&zone_raw);
            }
        }
    }
}

/// Errors that can occur in the peer registry.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum RegistryError {
    /// Registry is at maximum capacity
    RegistryFull,
    /// Invalid peer information
    InvalidPeer(String),
    /// Peer already exists
    PeerExists,
    /// Peer not found
    PeerNotFound,
}

impl core::fmt::Display for RegistryError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RegistryError::RegistryFull => write!(f, "Peer registry is full"),
            RegistryError::InvalidPeer(msg) => write!(f, "Invalid peer: {}", msg),
            RegistryError::PeerExists => write!(f, "Peer already exists"),
            RegistryError::PeerNotFound => write!(f, "Peer not found"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for RegistryError {}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "alloc")]
    use alloc::{string::ToString, vec};

    #[test]
    fn test_peer_registry_basic() {
        let config = RegistryConfig::default();
        let mut registry = PeerRegistry::new(config);

        let device_id = [1u8; 32];
        let peer = PeerInfo {
            device_id,
            zone: ResidencyTag::INDONESIA,
            address: PeerAddress::Tcp("127.0.0.1:8080".to_string()),
            last_seen: 12345,
            metadata: PeerMetadata {
                version: "1.0.0".to_string(),
                crypto_suites: vec![1, 2],
                max_payload: 1024,
                peer_type: PeerType::FullNode,
                attributes: BTreeMap::new(),
            },
        };

        assert!(registry.register_peer(peer.clone()).is_ok());
        assert_eq!(registry.peer_count(), 1);

        let retrieved = registry.get_peer(&device_id).unwrap();
        assert_eq!(retrieved.zone, ResidencyTag::INDONESIA);
        assert_eq!(retrieved.device_id, device_id);
    }

    #[test]
    fn test_zone_indexing() {
        let config = RegistryConfig::default();
        let mut registry = PeerRegistry::new(config);

        // Add peers in different zones
        let peer1 = PeerInfo {
            device_id: [1u8; 32],
            zone: ResidencyTag::INDONESIA,
            address: PeerAddress::Tcp("127.0.0.1:8080".to_string()),
            last_seen: 12345,
            metadata: PeerMetadata {
                version: "1.0.0".to_string(),
                crypto_suites: vec![1],
                max_payload: 1024,
                peer_type: PeerType::FullNode,
                attributes: BTreeMap::new(),
            },
        };

        let peer2 = PeerInfo {
            device_id: [2u8; 32],
            zone: ResidencyTag::MALAYSIA,
            address: PeerAddress::Tcp("127.0.0.1:8081".to_string()),
            last_seen: 12345,
            metadata: PeerMetadata {
                version: "1.0.0".to_string(),
                crypto_suites: vec![1],
                max_payload: 1024,
                peer_type: PeerType::FullNode,
                attributes: BTreeMap::new(),
            },
        };

        registry.register_peer(peer1).unwrap();
        registry.register_peer(peer2).unwrap();

        let indonesia_peers = registry.get_peers_in_zone(ResidencyTag::INDONESIA);
        assert_eq!(indonesia_peers.len(), 1);
        assert_eq!(indonesia_peers[0].zone, ResidencyTag::INDONESIA);

        let malaysia_peers = registry.get_peers_in_zone(ResidencyTag::MALAYSIA);
        assert_eq!(malaysia_peers.len(), 1);
        assert_eq!(malaysia_peers[0].zone, ResidencyTag::MALAYSIA);
    }

    #[test]
    fn test_find_routers_to_zone() {
        let config = RegistryConfig::default();
        let mut registry = PeerRegistry::new(config);

        // Add a full node in Indonesia
        let router = PeerInfo {
            device_id: [1u8; 32],
            zone: ResidencyTag::INDONESIA,
            address: PeerAddress::Tcp("127.0.0.1:8080".to_string()),
            last_seen: 12345,
            metadata: PeerMetadata {
                version: "1.0.0".to_string(),
                crypto_suites: vec![1],
                max_payload: 1024,
                peer_type: PeerType::FullNode,
                attributes: BTreeMap::new(),
            },
        };

        // Add an edge device in Indonesia
        let edge = PeerInfo {
            device_id: [2u8; 32],
            zone: ResidencyTag::INDONESIA,
            address: PeerAddress::Tcp("127.0.0.1:8081".to_string()),
            last_seen: 12345,
            metadata: PeerMetadata {
                version: "1.0.0".to_string(),
                crypto_suites: vec![1],
                max_payload: 512,
                peer_type: PeerType::EdgeDevice,
                attributes: BTreeMap::new(),
            },
        };

        registry.register_peer(router).unwrap();
        registry.register_peer(edge).unwrap();

        let routers = registry.find_routers_to_zone(ResidencyTag::INDONESIA);
        assert_eq!(routers.len(), 1);
        assert_eq!(routers[0].metadata.peer_type, PeerType::FullNode);
    }
}
