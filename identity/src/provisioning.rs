//! Device provisioning and identity management.
//!
//! Implements provisioning messages (REQUEST, CERT, REVOKE) per ZCP message type ranges (0x30-0x3F).
//! Supports offline-capable certificate chains with trust decay by depth.

use crate::error::Error;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// Device identity: 32-byte Ed25519 public key (ZCP envelope sender_device_id at offset 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceIdentity {
    /// Ed25519 public key (32 bytes)
    pub public_key: [u8; 32],
}

impl DeviceIdentity {
    /// Create device identity from 32-byte public key.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        DeviceIdentity { public_key: *bytes }
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

/// Certificate in an offline-capable chain (root → server → device).
///
/// Each certificate is signed by its parent and includes trust decay metadata.
/// Devices can verify certificates without network access to a CA.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(feature = "alloc")]
pub struct Certificate {
    /// Subject identity (32-byte Ed25519 public key)
    pub subject: DeviceIdentity,
    /// Issuer identity (32-byte Ed25519 public key, or same as subject for self-signed root)
    pub issuer: DeviceIdentity,
    /// Chain depth (0 = root, 1 = server, 2+ = device)
    pub chain_depth: u8,
    /// Maximum depth below this certificate (0 = leaf, no further delegation)
    pub max_depth: u8,
    /// Certificate validity: not-before timestamp (seconds since epoch)
    pub not_before: u64,
    /// Certificate validity: not-after timestamp (seconds since epoch)
    pub not_after: u64,
    /// Ed25519 signature over certificate bytes (64 bytes)
    pub signature: [u8; 64],
}

#[cfg(feature = "alloc")]
impl Certificate {
    /// Create a new certificate.
    pub fn new(
        subject: DeviceIdentity,
        issuer: DeviceIdentity,
        chain_depth: u8,
        max_depth: u8,
        not_before: u64,
        not_after: u64,
        signature: [u8; 64],
    ) -> Self {
        Certificate {
            subject,
            issuer,
            chain_depth,
            max_depth,
            not_before,
            not_after,
            signature,
        }
    }

    /// Serialize certificate to wire format.
    ///
    /// Format (wire order, big-endian):
    /// - subject (32 bytes)
    /// - issuer (32 bytes)
    /// - chain_depth (1 byte)
    /// - max_depth (1 byte)
    /// - not_before (8 bytes, u64 big-endian)
    /// - not_after (8 bytes, u64 big-endian)
    /// - signature (64 bytes)
    ///   Total: 146 bytes
    pub fn encode_to_vec(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(146);
        buf.extend_from_slice(self.subject.as_bytes());
        buf.extend_from_slice(self.issuer.as_bytes());
        buf.push(self.chain_depth);
        buf.push(self.max_depth);
        buf.extend_from_slice(&self.not_before.to_be_bytes());
        buf.extend_from_slice(&self.not_after.to_be_bytes());
        buf.extend_from_slice(&self.signature);
        buf
    }

    /// Deserialize certificate from wire format.
    pub fn decode_from_slice(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < 146 {
            return Err(Error::BufferTooSmall);
        }

        let subject = DeviceIdentity::from_bytes(
            &<[u8; 32]>::try_from(&buf[0..32]).map_err(|_| Error::InvalidCertificate)?,
        );
        let issuer = DeviceIdentity::from_bytes(
            &<[u8; 32]>::try_from(&buf[32..64]).map_err(|_| Error::InvalidCertificate)?,
        );
        let chain_depth = buf[64];
        let max_depth = buf[65];
        let not_before = u64::from_be_bytes(
            <[u8; 8]>::try_from(&buf[66..74]).map_err(|_| Error::InvalidCertificate)?,
        );
        let not_after = u64::from_be_bytes(
            <[u8; 8]>::try_from(&buf[74..82]).map_err(|_| Error::InvalidCertificate)?,
        );
        let signature =
            <[u8; 64]>::try_from(&buf[82..146]).map_err(|_| Error::InvalidCertificate)?;

        Ok(Certificate {
            subject,
            issuer,
            chain_depth,
            max_depth,
            not_before,
            not_after,
            signature,
        })
    }

    /// Validate certificate trust decay: ensure chain_depth <= max_depth.
    pub fn validate_trust_decay(&self) -> Result<(), Error> {
        if self.chain_depth > self.max_depth {
            return Err(Error::CertificateExpired);
        }
        Ok(())
    }

    /// Validate certificate time bounds against current timestamp.
    pub fn validate_time_bounds(&self, current_time: u64) -> Result<(), Error> {
        if current_time < self.not_before || current_time > self.not_after {
            return Err(Error::CertificateExpired);
        }
        Ok(())
    }

    /// Get the bytes that were signed (for signature verification).
    ///
    /// Signed data includes all fields except the signature itself.
    pub fn get_signed_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(82);
        buf.extend_from_slice(self.subject.as_bytes());
        buf.extend_from_slice(self.issuer.as_bytes());
        buf.push(self.chain_depth);
        buf.push(self.max_depth);
        buf.extend_from_slice(&self.not_before.to_be_bytes());
        buf.extend_from_slice(&self.not_after.to_be_bytes());
        buf
    }

    /// Sign a certificate with an Ed25519 private key.
    ///
    /// Creates a new certificate with the signature computed over all fields except the signature itself.
    pub fn sign(
        subject: DeviceIdentity,
        issuer: DeviceIdentity,
        chain_depth: u8,
        max_depth: u8,
        not_before: u64,
        not_after: u64,
        signing_key: &SigningKey,
    ) -> Result<Self, Error> {
        let mut buf = Vec::with_capacity(82);
        buf.extend_from_slice(subject.as_bytes());
        buf.extend_from_slice(issuer.as_bytes());
        buf.push(chain_depth);
        buf.push(max_depth);
        buf.extend_from_slice(&not_before.to_be_bytes());
        buf.extend_from_slice(&not_after.to_be_bytes());

        let signature = signing_key.sign(&buf);
        let sig_bytes: [u8; 64] = signature.to_bytes();

        Ok(Certificate {
            subject,
            issuer,
            chain_depth,
            max_depth,
            not_before,
            not_after,
            signature: sig_bytes,
        })
    }

    /// Verify the certificate signature using the issuer's public key.
    ///
    /// Returns `Ok(())` if the signature is valid, or an error if verification fails.
    pub fn verify_signature(&self) -> Result<(), Error> {
        let verifying_key = VerifyingKey::from_bytes(self.issuer.as_bytes())
            .map_err(|_| Error::CertificateSignatureInvalid)?;

        let signature = Signature::from_bytes(&self.signature);

        let signed_bytes = self.get_signed_bytes();
        verifying_key
            .verify(&signed_bytes, &signature)
            .map_err(|_| Error::CertificateSignatureInvalid)?;

        Ok(())
    }

    /// Calculate trust decay score based on chain depth.
    ///
    /// Returns a score from 0 to 100 representing trust level:
    /// - Depth 0 (root): 100 (full trust)
    /// - Depth 1 (server): 75 (high trust)
    /// - Depth 2 (device): 50 (medium trust)
    /// - Depth 3+: 25 (low trust)
    ///
    /// This is a simple linear decay model. More sophisticated models could
    /// incorporate additional factors like certificate age or issuer reputation.
    pub fn trust_decay_score(&self) -> u8 {
        match self.chain_depth {
            0 => 100,
            1 => 75,
            2 => 50,
            _ => 25,
        }
    }

    /// Check if certificate trust is acceptable given a minimum trust threshold.
    ///
    /// Returns `Ok(())` if the trust decay score meets or exceeds the threshold,
    /// or an error if trust is insufficient.
    pub fn validate_trust_threshold(&self, min_trust: u8) -> Result<(), Error> {
        if self.trust_decay_score() >= min_trust {
            Ok(())
        } else {
            Err(Error::CertificateExpired)
        }
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

    #[test]
    #[cfg(feature = "alloc")]
    fn certificate_encode_decode_roundtrip() {
        let subject = DeviceIdentity::from_bytes(&[0x01u8; 32]);
        let issuer = DeviceIdentity::from_bytes(&[0x02u8; 32]);
        let signature = [0x03u8; 64];

        let cert = Certificate::new(subject, issuer, 1, 2, 1000, 2000, signature);
        let encoded = cert.encode_to_vec();

        assert_eq!(encoded.len(), 146);

        let decoded = Certificate::decode_from_slice(&encoded).unwrap();
        assert_eq!(decoded.subject, subject);
        assert_eq!(decoded.issuer, issuer);
        assert_eq!(decoded.chain_depth, 1);
        assert_eq!(decoded.max_depth, 2);
        assert_eq!(decoded.not_before, 1000);
        assert_eq!(decoded.not_after, 2000);
        assert_eq!(decoded.signature, signature);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn certificate_validate_trust_decay_valid() {
        let cert = Certificate::new(
            DeviceIdentity::from_bytes(&[0u8; 32]),
            DeviceIdentity::from_bytes(&[1u8; 32]),
            1,
            2,
            1000,
            2000,
            [0u8; 64],
        );
        assert!(cert.validate_trust_decay().is_ok());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn certificate_validate_trust_decay_invalid() {
        let cert = Certificate::new(
            DeviceIdentity::from_bytes(&[0u8; 32]),
            DeviceIdentity::from_bytes(&[1u8; 32]),
            3,
            2,
            1000,
            2000,
            [0u8; 64],
        );
        assert_eq!(cert.validate_trust_decay(), Err(Error::CertificateExpired));
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn certificate_validate_time_bounds_valid() {
        let cert = Certificate::new(
            DeviceIdentity::from_bytes(&[0u8; 32]),
            DeviceIdentity::from_bytes(&[1u8; 32]),
            0,
            2,
            1000,
            2000,
            [0u8; 64],
        );
        assert!(cert.validate_time_bounds(1500).is_ok());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn certificate_validate_time_bounds_before() {
        let cert = Certificate::new(
            DeviceIdentity::from_bytes(&[0u8; 32]),
            DeviceIdentity::from_bytes(&[1u8; 32]),
            0,
            2,
            1000,
            2000,
            [0u8; 64],
        );
        assert_eq!(
            cert.validate_time_bounds(999),
            Err(Error::CertificateExpired)
        );
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn certificate_validate_time_bounds_after() {
        let cert = Certificate::new(
            DeviceIdentity::from_bytes(&[0u8; 32]),
            DeviceIdentity::from_bytes(&[1u8; 32]),
            0,
            2,
            1000,
            2000,
            [0u8; 64],
        );
        assert_eq!(
            cert.validate_time_bounds(2001),
            Err(Error::CertificateExpired)
        );
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn certificate_get_signed_bytes() {
        let subject = DeviceIdentity::from_bytes(&[0x01u8; 32]);
        let issuer = DeviceIdentity::from_bytes(&[0x02u8; 32]);
        let cert = Certificate::new(subject, issuer, 1, 2, 1000, 2000, [0x03u8; 64]);

        let signed_bytes = cert.get_signed_bytes();
        assert_eq!(signed_bytes.len(), 82);

        assert_eq!(&signed_bytes[0..32], subject.as_bytes());
        assert_eq!(&signed_bytes[32..64], issuer.as_bytes());
        assert_eq!(signed_bytes[64], 1);
        assert_eq!(signed_bytes[65], 2);
        assert_eq!(
            u64::from_be_bytes([
                signed_bytes[66],
                signed_bytes[67],
                signed_bytes[68],
                signed_bytes[69],
                signed_bytes[70],
                signed_bytes[71],
                signed_bytes[72],
                signed_bytes[73]
            ]),
            1000
        );
        assert_eq!(
            u64::from_be_bytes([
                signed_bytes[74],
                signed_bytes[75],
                signed_bytes[76],
                signed_bytes[77],
                signed_bytes[78],
                signed_bytes[79],
                signed_bytes[80],
                signed_bytes[81]
            ]),
            2000
        );
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn certificate_decode_buffer_too_small() {
        let buf = [0u8; 145];
        assert_eq!(
            Certificate::decode_from_slice(&buf),
            Err(Error::BufferTooSmall)
        );
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn certificate_root_self_signed() {
        let root_key = DeviceIdentity::from_bytes(&[0xFFu8; 32]);
        let cert = Certificate::new(root_key, root_key, 0, 2, 1000, 2000, [0u8; 64]);

        assert_eq!(cert.subject, cert.issuer);
        assert_eq!(cert.chain_depth, 0);
        assert!(cert.validate_trust_decay().is_ok());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn certificate_chain_root_server_device() {
        let root_key = DeviceIdentity::from_bytes(&[0x01u8; 32]);
        let server_key = DeviceIdentity::from_bytes(&[0x02u8; 32]);
        let device_key = DeviceIdentity::from_bytes(&[0x03u8; 32]);

        let root_cert = Certificate::new(root_key, root_key, 0, 2, 1000, 3000, [0u8; 64]);
        let server_cert = Certificate::new(server_key, root_key, 1, 2, 1000, 2500, [0u8; 64]);
        let device_cert = Certificate::new(device_key, server_key, 2, 2, 1000, 2000, [0u8; 64]);

        assert!(root_cert.validate_trust_decay().is_ok());
        assert!(server_cert.validate_trust_decay().is_ok());
        assert!(device_cert.validate_trust_decay().is_ok());

        assert_eq!(root_cert.chain_depth, 0);
        assert_eq!(server_cert.chain_depth, 1);
        assert_eq!(device_cert.chain_depth, 2);

        assert_eq!(root_cert.max_depth, 2);
        assert_eq!(server_cert.max_depth, 2);
        assert_eq!(device_cert.max_depth, 2);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn certificate_sign_and_verify() {
        use ed25519_dalek::SigningKey;

        let signing_key = SigningKey::from_bytes(&[0x42u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let issuer = DeviceIdentity::from_bytes(verifying_key.as_bytes());
        let subject = DeviceIdentity::from_bytes(&[0x01u8; 32]);

        let cert = Certificate::sign(subject, issuer, 0, 2, 1000, 2000, &signing_key)
            .expect("Failed to sign certificate");

        assert_eq!(cert.subject, subject);
        assert_eq!(cert.issuer, issuer);
        assert_eq!(cert.chain_depth, 0);
        assert_eq!(cert.max_depth, 2);
        assert_eq!(cert.not_before, 1000);
        assert_eq!(cert.not_after, 2000);

        assert!(cert.verify_signature().is_ok());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn certificate_verify_invalid_signature() {
        use ed25519_dalek::SigningKey;

        let signing_key = SigningKey::from_bytes(&[0x42u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let issuer = DeviceIdentity::from_bytes(verifying_key.as_bytes());
        let subject = DeviceIdentity::from_bytes(&[0x01u8; 32]);

        let mut cert = Certificate::sign(subject, issuer, 0, 2, 1000, 2000, &signing_key)
            .expect("Failed to sign certificate");

        cert.signature[0] ^= 0xFF;

        assert_eq!(
            cert.verify_signature(),
            Err(Error::CertificateSignatureInvalid)
        );
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn certificate_sign_and_verify_chain() {
        use ed25519_dalek::SigningKey;

        let root_signing_key = SigningKey::from_bytes(&[0x01u8; 32]);
        let root_verifying_key = root_signing_key.verifying_key();
        let root_identity = DeviceIdentity::from_bytes(root_verifying_key.as_bytes());

        let server_signing_key = SigningKey::from_bytes(&[0x02u8; 32]);
        let server_verifying_key = server_signing_key.verifying_key();
        let server_identity = DeviceIdentity::from_bytes(server_verifying_key.as_bytes());

        let device_signing_key = SigningKey::from_bytes(&[0x03u8; 32]);
        let device_verifying_key = device_signing_key.verifying_key();
        let device_identity = DeviceIdentity::from_bytes(device_verifying_key.as_bytes());

        let root_cert = Certificate::sign(
            root_identity,
            root_identity,
            0,
            2,
            1000,
            3000,
            &root_signing_key,
        )
        .expect("Failed to sign root certificate");

        let server_cert = Certificate::sign(
            server_identity,
            root_identity,
            1,
            2,
            1000,
            2500,
            &root_signing_key,
        )
        .expect("Failed to sign server certificate");

        let device_cert = Certificate::sign(
            device_identity,
            server_identity,
            2,
            2,
            1000,
            2000,
            &server_signing_key,
        )
        .expect("Failed to sign device certificate");

        assert!(root_cert.verify_signature().is_ok());
        assert!(server_cert.verify_signature().is_ok());
        assert!(device_cert.verify_signature().is_ok());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn certificate_trust_decay_score_root() {
        let cert = Certificate::new(
            DeviceIdentity::from_bytes(&[0u8; 32]),
            DeviceIdentity::from_bytes(&[1u8; 32]),
            0,
            2,
            1000,
            2000,
            [0u8; 64],
        );
        assert_eq!(cert.trust_decay_score(), 100);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn certificate_trust_decay_score_server() {
        let cert = Certificate::new(
            DeviceIdentity::from_bytes(&[0u8; 32]),
            DeviceIdentity::from_bytes(&[1u8; 32]),
            1,
            2,
            1000,
            2000,
            [0u8; 64],
        );
        assert_eq!(cert.trust_decay_score(), 75);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn certificate_trust_decay_score_device() {
        let cert = Certificate::new(
            DeviceIdentity::from_bytes(&[0u8; 32]),
            DeviceIdentity::from_bytes(&[1u8; 32]),
            2,
            2,
            1000,
            2000,
            [0u8; 64],
        );
        assert_eq!(cert.trust_decay_score(), 50);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn certificate_trust_decay_score_deep() {
        let cert = Certificate::new(
            DeviceIdentity::from_bytes(&[0u8; 32]),
            DeviceIdentity::from_bytes(&[1u8; 32]),
            5,
            5,
            1000,
            2000,
            [0u8; 64],
        );
        assert_eq!(cert.trust_decay_score(), 25);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn certificate_validate_trust_threshold_pass() {
        let cert = Certificate::new(
            DeviceIdentity::from_bytes(&[0u8; 32]),
            DeviceIdentity::from_bytes(&[1u8; 32]),
            1,
            2,
            1000,
            2000,
            [0u8; 64],
        );
        assert!(cert.validate_trust_threshold(75).is_ok());
        assert!(cert.validate_trust_threshold(50).is_ok());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn certificate_validate_trust_threshold_fail() {
        let cert = Certificate::new(
            DeviceIdentity::from_bytes(&[0u8; 32]),
            DeviceIdentity::from_bytes(&[1u8; 32]),
            2,
            2,
            1000,
            2000,
            [0u8; 64],
        );
        assert_eq!(
            cert.validate_trust_threshold(75),
            Err(Error::CertificateExpired)
        );
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn certificate_trust_decay_chain_validation() {
        let root_cert = Certificate::new(
            DeviceIdentity::from_bytes(&[0x01u8; 32]),
            DeviceIdentity::from_bytes(&[0x01u8; 32]),
            0,
            2,
            1000,
            3000,
            [0u8; 64],
        );

        let server_cert = Certificate::new(
            DeviceIdentity::from_bytes(&[0x02u8; 32]),
            DeviceIdentity::from_bytes(&[0x01u8; 32]),
            1,
            2,
            1000,
            2500,
            [0u8; 64],
        );

        let device_cert = Certificate::new(
            DeviceIdentity::from_bytes(&[0x03u8; 32]),
            DeviceIdentity::from_bytes(&[0x02u8; 32]),
            2,
            2,
            1000,
            2000,
            [0u8; 64],
        );

        assert_eq!(root_cert.trust_decay_score(), 100);
        assert_eq!(server_cert.trust_decay_score(), 75);
        assert_eq!(device_cert.trust_decay_score(), 50);

        assert!(root_cert.validate_trust_threshold(100).is_ok());
        assert!(server_cert.validate_trust_threshold(75).is_ok());
        assert!(device_cert.validate_trust_threshold(50).is_ok());

        assert!(root_cert.validate_trust_threshold(101).is_err());
        assert!(server_cert.validate_trust_threshold(76).is_err());
        assert!(device_cert.validate_trust_threshold(51).is_err());
    }
}
