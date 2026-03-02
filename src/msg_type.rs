//! ZCP message type discriminants.
//!
//! Message types are grouped by function:
//!
//! - `0x01–0x0F`: Core operations (task routing, CRDT sync, device orchestration)
//! - `0x10–0x1F`: DHT operations (Kademlia find/get/put)
//! - `0x20–0x2F`: Gossip operations (broadcast, subscribe)
//! - `0x30–0x3F`: Provisioning operations (device onboarding, revocation)
//! - `0x40–0x4F`: Heartbeat / health (reserved)
//! - `0xF0–0xFF`: Vendor extensions (reserved for third-party use)

/// ZCP message types carried in the wire protocol envelope.
///
/// Ranges are pre-allocated for forward compatibility. Unknown values
/// within an allocated range should be treated as unsupported (not invalid)
/// by receivers — this allows newer senders to introduce sub-types without
/// breaking older receivers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum MsgType {
    // ── Core operations (0x01–0x0F) ──────────────────────

    /// Route an IntentfulTask to a target device or device group.
    TaskRoute = 0x01,

    /// CRDT sync: delta state replication between peers.
    SyncCrdt = 0x02,

    /// Device orchestration: fleet management commands.
    DeviceOrch = 0x03,

    // ── DHT operations (0x10–0x1F) ───────────────────────

    /// Kademlia FIND_NODE.
    DhtFindNode = 0x10,

    /// Kademlia GET_VALUE.
    DhtGetValue = 0x11,

    /// Kademlia PUT_VALUE.
    DhtPutValue = 0x12,

    // ── Gossip operations (0x20–0x2F) ────────────────────

    /// GossipSub broadcast message.
    GossipBroadcast = 0x20,

    /// GossipSub topic subscription.
    GossipSubscribe = 0x21,

    // ── Provisioning operations (0x30–0x3F) ──────────────

    /// Device provisioning request (child → parent).
    ProvisionRequest = 0x30,

    /// Provisioning certificate delivery (parent → child).
    ProvisionCert = 0x31,

    /// Device revocation (any admin → fleet).
    ProvisionRevoke = 0x32,
}

impl MsgType {
    /// Try to interpret a raw byte as a known message type.
    ///
    /// Returns `None` for unknown values. Callers should decide whether
    /// unknown types are an error (strict parsing) or should be forwarded
    /// (relay mode).
    pub const fn from_byte(b: u8) -> Option<MsgType> {
        match b {
            0x01 => Some(MsgType::TaskRoute),
            0x02 => Some(MsgType::SyncCrdt),
            0x03 => Some(MsgType::DeviceOrch),
            0x10 => Some(MsgType::DhtFindNode),
            0x11 => Some(MsgType::DhtGetValue),
            0x12 => Some(MsgType::DhtPutValue),
            0x20 => Some(MsgType::GossipBroadcast),
            0x21 => Some(MsgType::GossipSubscribe),
            0x30 => Some(MsgType::ProvisionRequest),
            0x31 => Some(MsgType::ProvisionCert),
            0x32 => Some(MsgType::ProvisionRevoke),
            _ => None,
        }
    }

    /// Return the raw byte representation.
    pub const fn as_byte(self) -> u8 {
        self as u8
    }

    /// Which functional range does this byte fall into?
    ///
    /// Useful for relay nodes that want to forward unknown sub-types
    /// within a known range without understanding them.
    pub const fn range_of(b: u8) -> MsgRange {
        match b {
            0x01..=0x0F => MsgRange::Core,
            0x10..=0x1F => MsgRange::Dht,
            0x20..=0x2F => MsgRange::Gossip,
            0x30..=0x3F => MsgRange::Provisioning,
            0x40..=0x4F => MsgRange::Heartbeat,
            0xF0..=0xFF => MsgRange::Vendor,
            _ => MsgRange::Unknown,
        }
    }
}

/// Functional range that a message type byte belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MsgRange {
    /// Core operations (task routing, CRDT sync, device orchestration).
    Core,
    /// Kademlia DHT operations.
    Dht,
    /// GossipSub operations.
    Gossip,
    /// Device provisioning / revocation.
    Provisioning,
    /// Heartbeat / health monitoring (reserved).
    Heartbeat,
    /// Vendor extensions (0xF0–0xFF).
    Vendor,
    /// Unallocated range.
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── from_byte / as_byte roundtrip ────────────────────

    #[test]
    fn all_variants_roundtrip() {
        let variants = [
            MsgType::TaskRoute,
            MsgType::SyncCrdt,
            MsgType::DeviceOrch,
            MsgType::DhtFindNode,
            MsgType::DhtGetValue,
            MsgType::DhtPutValue,
            MsgType::GossipBroadcast,
            MsgType::GossipSubscribe,
            MsgType::ProvisionRequest,
            MsgType::ProvisionCert,
            MsgType::ProvisionRevoke,
        ];
        for v in variants {
            assert_eq!(
                MsgType::from_byte(v.as_byte()),
                Some(v),
                "roundtrip failed for {:?}",
                v
            );
        }
    }

    // ── Wire format byte stability ───────────────────────

    #[test]
    fn byte_values_are_stable() {
        // Wire format contract: these bytes must never change
        assert_eq!(MsgType::TaskRoute.as_byte(), 0x01);
        assert_eq!(MsgType::SyncCrdt.as_byte(), 0x02);
        assert_eq!(MsgType::DeviceOrch.as_byte(), 0x03);
        assert_eq!(MsgType::DhtFindNode.as_byte(), 0x10);
        assert_eq!(MsgType::DhtGetValue.as_byte(), 0x11);
        assert_eq!(MsgType::DhtPutValue.as_byte(), 0x12);
        assert_eq!(MsgType::GossipBroadcast.as_byte(), 0x20);
        assert_eq!(MsgType::GossipSubscribe.as_byte(), 0x21);
        assert_eq!(MsgType::ProvisionRequest.as_byte(), 0x30);
        assert_eq!(MsgType::ProvisionCert.as_byte(), 0x31);
        assert_eq!(MsgType::ProvisionRevoke.as_byte(), 0x32);
    }

    // ── Unknown bytes ────────────────────────────────────

    #[test]
    fn from_byte_returns_none_for_unknown() {
        assert_eq!(MsgType::from_byte(0x00), None);
        assert_eq!(MsgType::from_byte(0x04), None); // in Core range but undefined
        assert_eq!(MsgType::from_byte(0x13), None); // in DHT range but undefined
        assert_eq!(MsgType::from_byte(0x80), None);
        assert_eq!(MsgType::from_byte(0xFF), None);
    }

    // ── Range classification ─────────────────────────────

    #[test]
    fn range_boundaries() {
        // Core: 0x01–0x0F
        assert_eq!(MsgType::range_of(0x01), MsgRange::Core);
        assert_eq!(MsgType::range_of(0x0F), MsgRange::Core);

        // DHT: 0x10–0x1F
        assert_eq!(MsgType::range_of(0x10), MsgRange::Dht);
        assert_eq!(MsgType::range_of(0x1F), MsgRange::Dht);

        // Gossip: 0x20–0x2F
        assert_eq!(MsgType::range_of(0x20), MsgRange::Gossip);
        assert_eq!(MsgType::range_of(0x2F), MsgRange::Gossip);

        // Provisioning: 0x30–0x3F
        assert_eq!(MsgType::range_of(0x30), MsgRange::Provisioning);
        assert_eq!(MsgType::range_of(0x3F), MsgRange::Provisioning);

        // Heartbeat: 0x40–0x4F
        assert_eq!(MsgType::range_of(0x40), MsgRange::Heartbeat);
        assert_eq!(MsgType::range_of(0x4F), MsgRange::Heartbeat);

        // Vendor: 0xF0–0xFF
        assert_eq!(MsgType::range_of(0xF0), MsgRange::Vendor);
        assert_eq!(MsgType::range_of(0xFF), MsgRange::Vendor);
    }

    #[test]
    fn gaps_are_unknown() {
        // Between allocated ranges
        assert_eq!(MsgType::range_of(0x00), MsgRange::Unknown);
        assert_eq!(MsgType::range_of(0x50), MsgRange::Unknown);
        assert_eq!(MsgType::range_of(0x80), MsgRange::Unknown);
        assert_eq!(MsgType::range_of(0xEF), MsgRange::Unknown);
    }

    #[test]
    fn defined_variants_in_correct_range() {
        assert_eq!(MsgType::range_of(MsgType::TaskRoute.as_byte()), MsgRange::Core);
        assert_eq!(MsgType::range_of(MsgType::SyncCrdt.as_byte()), MsgRange::Core);
        assert_eq!(MsgType::range_of(MsgType::DeviceOrch.as_byte()), MsgRange::Core);
        assert_eq!(MsgType::range_of(MsgType::DhtFindNode.as_byte()), MsgRange::Dht);
        assert_eq!(MsgType::range_of(MsgType::DhtGetValue.as_byte()), MsgRange::Dht);
        assert_eq!(MsgType::range_of(MsgType::DhtPutValue.as_byte()), MsgRange::Dht);
        assert_eq!(MsgType::range_of(MsgType::GossipBroadcast.as_byte()), MsgRange::Gossip);
        assert_eq!(MsgType::range_of(MsgType::GossipSubscribe.as_byte()), MsgRange::Gossip);
        assert_eq!(MsgType::range_of(MsgType::ProvisionRequest.as_byte()), MsgRange::Provisioning);
        assert_eq!(MsgType::range_of(MsgType::ProvisionCert.as_byte()), MsgRange::Provisioning);
        assert_eq!(MsgType::range_of(MsgType::ProvisionRevoke.as_byte()), MsgRange::Provisioning);
    }
}
