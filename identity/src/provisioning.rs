//! Device provisioning and identity management.
//!
//! Implements provisioning messages (REQUEST, CERT, REVOKE) per ZCP message type ranges (0x30-0x3F).

use crate::error::Error;

/// Device identity: 32-byte Ed25519 public key (ZCP envelope sender_device_id at offset 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceIdentity {
    /// Ed25519 public key (32 bytes)
    pub public_key: [u8; 32],
}

impl DeviceIdentity {
    /// Create device identity from 32-byte public key.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        DeviceIdentity {
            public_key: *bytes,
        }
    }

    /// Return public key as bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.public_key
    }
}

/// Provisioning message type (ZCP message type range 0x30-0x3F).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvisioningMessageType {
    /// REQUEST (0x30): Device requests provisioning certificate
    Request = 0x30,
    /// CERT (0x31): Server issues provisioning certificate
    Certificate = 0x31,
    /// REVOKE (0x32): Server revokes a certificate
    Revoke = 0x32,
}

impl ProvisioningMessageType {
    /// Parse from byte.
    pub fn from_byte(b: u8) -> Result<Self, Error> {
        match b {
            0x30 => Ok(ProvisioningMessageType::Request),
            0x31 => Ok(ProvisioningMessageType::Certificate),
            0x32 => Ok(ProvisioningMessageType::Revoke),
            _ => Err(Error::InvalidProvisioningMessage),
        }
    }

    /// Return as byte.
    pub fn as_byte(self) -> u8 {
        self as u8
    }
}

/// Provisioning message payload.
///
/// Carries certificate chain data, device identity, and trust metadata.
#[derive(Debug, Clone)]
pub struct ProvisioningMessage {
    /// Message type (REQUEST, CERT, or REVOKE)
    pub msg_type: ProvisioningMessageType,
    /// Device identity (32-byte Ed25519 public key)
    pub device_identity: DeviceIdentity,
    /// Certificate chain depth (0 = root, 1 = server, 2+ = device)
    pub chain_depth: u8,
    /// Trust decay: maximum depth below this certificate (0 = leaf, no further delegation)
    pub max_depth: u8,
    /// Payload (certificate bytes, signature, revocation reason, etc.)
    #[cfg(feature = "alloc")]
    pub payload: alloc::vec::Vec<u8>,
}

#[cfg(feature = "alloc")]
impl ProvisioningMessage {
    /// Create new provisioning message.
    pub fn new(
        msg_type: ProvisioningMessageType,
        device_identity: DeviceIdentity,
        chain_depth: u8,
        max_depth: u8,
        payload: alloc::vec::Vec<u8>,
    ) -> Self {
        ProvisioningMessage {
            msg_type,
            device_identity,
            chain_depth,
            max_depth,
            payload,
        }
    }

    /// Validate certificate trust decay: ensure chain_depth <= max_depth.
    pub fn validate_trust_decay(&self) -> Result<(), Error> {
        if self.chain_depth > self.max_depth {
            return Err(Error::CertificateExpired);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_identity_from_bytes() {
        let key = [0x42u8; 32];
        let id = DeviceIdentity::from_bytes(&key);
        assert_eq!(id.as_bytes(), &key);
    }

    #[test]
    fn provisioning_message_type_request() {
        assert_eq!(
            ProvisioningMessageType::from_byte(0x30).unwrap(),
            ProvisioningMessageType::Request
        );
    }

    #[test]
    fn provisioning_message_type_certificate() {
        assert_eq!(
            ProvisioningMessageType::from_byte(0x31).unwrap(),
            ProvisioningMessageType::Certificate
        );
    }

    #[test]
    fn provisioning_message_type_revoke() {
        assert_eq!(
            ProvisioningMessageType::from_byte(0x32).unwrap(),
            ProvisioningMessageType::Revoke
        );
    }

    #[test]
    fn provisioning_message_type_invalid() {
        assert_eq!(
            ProvisioningMessageType::from_byte(0xFF),
            Err(Error::InvalidProvisioningMessage)
        );
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn validate_trust_decay_valid() {
        let msg = ProvisioningMessage::new(
            ProvisioningMessageType::Certificate,
            DeviceIdentity::from_bytes(&[0u8; 32]),
            1,
            2,
            alloc::vec![],
        );
        assert!(msg.validate_trust_decay().is_ok());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn validate_trust_decay_invalid() {
        let msg = ProvisioningMessage::new(
            ProvisioningMessageType::Certificate,
            DeviceIdentity::from_bytes(&[0u8; 32]),
            3,
            2,
            alloc::vec![],
        );
        assert_eq!(msg.validate_trust_decay(), Err(Error::CertificateExpired));
    }
}
