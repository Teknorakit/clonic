//! Transport configuration types (alloc-only).

use alloc::string::String;

/// TCP configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpConfig {
    /// Hostname or IP.
    pub host: String,
    /// TCP port.
    pub port: u16,
}

/// BLE configuration (UUID-based).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BleConfig {
    /// Service UUID.
    pub service_uuid: String,
    /// Characteristic UUID.
    pub characteristic_uuid: String,
}

/// LoRa configuration (simplified).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoRaConfig {
    /// Region code (e.g., "EU868").
    pub region: String,
    /// Frequency in Hz.
    pub frequency_hz: u32,
}

/// Unified transport configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportConfig {
    /// TCP/IP configuration.
    Tcp(TcpConfig),
    /// BLE configuration.
    Ble(BleConfig),
    /// LoRa configuration.
    LoRa(LoRaConfig),
}
