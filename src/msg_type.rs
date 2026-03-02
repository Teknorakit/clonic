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
