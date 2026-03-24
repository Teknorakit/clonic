//! Simple offline-capable certificate and CRL format for ZCP provisioning.
//!
//! Layout is intentionally compact and deterministic for signing:
//! - subject_role: u8 (0=root,1=server,2=device)
//! - issuer_role: u8
//! - subject_public_key: \[u8;32\] (Ed25519)
//! - not_before: u64 (unix seconds, LE)
//! - not_after: u64  (unix seconds, LE)
//! - max_depth: u8   (delegation depth allowed)
//! - body = concat above fields
//! - signature: 64-byte Ed25519 over body

use crate::error::Error;
use crate::provisioning::DeviceIdentity;
use alloc::vec::Vec;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

/// Certificate subject/issuer role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertRole {
    /// Root authority
    Root = 0,
    /// Provisioning server
    Server = 1,
    /// Device leaf
    Device = 2,
}

impl CertRole {
    /// Parse from a discriminant byte.
    pub fn from_byte(b: u8) -> Result<Self, Error> {
        match b {
            0 => Ok(CertRole::Root),
            1 => Ok(CertRole::Server),
            2 => Ok(CertRole::Device),
            _ => Err(Error::InvalidProvisioningMessage),
        }
    }

    /// Return the discriminant byte.
    pub fn as_byte(self) -> u8 {
        self as u8
    }
}

/// Compact Ed25519 certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    /// Role of the subject (leaf)
    pub subject_role: CertRole,
    /// Role of the issuer (parent)
    pub issuer_role: CertRole,
    /// Subject public key
    pub subject: DeviceIdentity,
    /// Not-before timestamp (unix seconds, LE)
    pub not_before: u64,
    /// Not-after timestamp (unix seconds, LE)
    pub not_after: u64,
    /// Delegation depth allowed
    pub max_depth: u8,
    /// Ed25519 signature over body
    pub signature: [u8; 64],
}

impl Certificate {
    /// Build an unsigned certificate.
    pub fn new_unsigned(
        subject_role: CertRole,
        issuer_role: CertRole,
        subject: DeviceIdentity,
        not_before: u64,
        not_after: u64,
        max_depth: u8,
    ) -> Self {
        Self {
            subject_role,
            issuer_role,
            subject,
            not_before,
            not_after,
            max_depth,
            signature: [0u8; 64],
        }
    }

    /// Deterministic body used for signing.
    pub fn body(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 1 + 32 + 8 + 8 + 1);
        out.push(self.subject_role.as_byte());
        out.push(self.issuer_role.as_byte());
        out.extend_from_slice(self.subject.as_bytes());
        out.extend_from_slice(&self.not_before.to_le_bytes());
        out.extend_from_slice(&self.not_after.to_le_bytes());
        out.push(self.max_depth);
        out
    }

    /// Sign with issuer signing key.
    pub fn sign(mut self, issuer_sk: &SigningKey) -> Self {
        let sig: Signature = issuer_sk.sign(&self.body());
        self.signature = sig.to_bytes();
        self
    }

    /// Verify signature and validity window.
    pub fn verify(&self, issuer_pk: &VerifyingKey, now: u64) -> Result<(), Error> {
        if now < self.not_before || now > self.not_after {
            return Err(Error::CertificateExpired);
        }
        let sig = Signature::from_bytes(&self.signature);
        issuer_pk
            .verify_strict(&self.body(), &sig)
            .map_err(|_| Error::CertificateSignatureInvalid)
    }

    /// Serialize to body || signature.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.body();
        out.extend_from_slice(&self.signature);
        out
    }

    /// Parse from serialized bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != 1 + 1 + 32 + 8 + 8 + 1 + 64 {
            return Err(Error::InvalidCertificate);
        }
        let subject_role = CertRole::from_byte(bytes[0])?;
        let issuer_role = CertRole::from_byte(bytes[1])?;
        let subject_bytes =
            <[u8; 32]>::try_from(&bytes[2..34]).map_err(|_| Error::InvalidCertificate)?;
        let subject = DeviceIdentity::from_bytes(&subject_bytes);
        let not_before = u64::from_le_bytes(
            <[u8; 8]>::try_from(&bytes[34..42]).map_err(|_| Error::InvalidCertificate)?,
        );
        let not_after = u64::from_le_bytes(
            <[u8; 8]>::try_from(&bytes[42..50]).map_err(|_| Error::InvalidCertificate)?,
        );
        let max_depth = bytes[50];
        let signature =
            <[u8; 64]>::try_from(&bytes[51..]).map_err(|_| Error::InvalidCertificate)?;

        Ok(Self {
            subject_role,
            issuer_role,
            subject,
            not_before,
            not_after,
            max_depth,
            signature,
        })
    }
}

/// Ordered certificate chain root→server→device.
#[derive(Debug, Clone)]
pub struct CertificateChain {
    /// Chain in order (root first)
    pub certificates: Vec<Certificate>,
}

impl CertificateChain {
    /// Create a new chain.
    pub fn new(certificates: Vec<Certificate>) -> Self {
        Self { certificates }
    }

    /// Verify signatures, order, and depth constraints.
    pub fn verify(&self, now: u64) -> Result<(), Error> {
        if self.certificates.is_empty() {
            return Err(Error::InvalidCertificate);
        }
        for window in self.certificates.windows(2) {
            let issuer = &window[0];
            let subject = &window[1];

            // depth check
            if subject.max_depth < issuer.max_depth.saturating_sub(1) {
                return Err(Error::CertificateExpired);
            }
            let issuer_pk = VerifyingKey::from_bytes(issuer.subject.as_bytes())
                .map_err(|_| Error::CertificateSignatureInvalid)?;
            subject.verify(&issuer_pk, now)?;
        }
        Ok(())
    }
}

/// Certificate revocation list (CRL).
#[derive(Debug, Clone)]
pub struct Crl {
    /// Issuer public key
    pub issuer: DeviceIdentity,
    /// Revoked device public keys
    pub revoked: Vec<[u8; 32]>,
    /// Ed25519 signature
    pub signature: [u8; 64],
}

impl Crl {
    /// Deterministic body for signing/verification.
    fn body(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 2 + self.revoked.len() * 32);
        out.extend_from_slice(self.issuer.as_bytes());
        out.extend_from_slice(&(self.revoked.len() as u16).to_le_bytes());
        for r in &self.revoked {
            out.extend_from_slice(r);
        }
        out
    }

    /// Sign CRL with issuer key.
    pub fn sign(mut self, issuer_sk: &SigningKey) -> Self {
        let sig = issuer_sk.sign(&self.body());
        self.signature = sig.to_bytes();
        self
    }

    /// Verify CRL signature.
    pub fn verify(&self, issuer_pk: &VerifyingKey) -> Result<(), Error> {
        let sig = Signature::from_bytes(&self.signature);
        issuer_pk
            .verify_strict(&self.body(), &sig)
            .map_err(|_| Error::CertificateSignatureInvalid)
    }
}

/// Rotation certificate: binds a new device key to an old one.
/// Binds old device key to new device key.
#[derive(Debug, Clone)]
pub struct RotationCertificate {
    /// Old device identity
    pub old_device: DeviceIdentity,
    /// New device identity
    pub new_device: DeviceIdentity,
    /// Signature by issuer
    pub signature: [u8; 64],
}

impl RotationCertificate {
    /// Deterministic body for signing/verification.
    fn body(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(self.old_device.as_bytes());
        out.extend_from_slice(self.new_device.as_bytes());
        out
    }

    /// Sign rotation certificate.
    pub fn sign(mut self, issuer_sk: &SigningKey) -> Self {
        let sig = issuer_sk.sign(&self.body());
        self.signature = sig.to_bytes();
        self
    }

    /// Verify rotation certificate signature.
    pub fn verify(&self, issuer_pk: &VerifyingKey) -> Result<(), Error> {
        let sig = Signature::from_bytes(&self.signature);
        issuer_pk
            .verify_strict(&self.body(), &sig)
            .map_err(|_| Error::CertificateSignatureInvalid)
    }
}

/// Secure key storage abstraction (pluggable backends).
pub trait KeyStore {
    /// Fetch signing key bytes for a device identity.
    fn load_signing_key(&self, id: &DeviceIdentity) -> Result<[u8; 32], Error>;
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "getrandom")]
    use super::*;
    #[cfg(feature = "getrandom")]
    use alloc::vec;
    #[cfg(feature = "getrandom")]
    use rand_core::{OsRng, RngCore};

    #[cfg(feature = "getrandom")]
    fn gen_signing_key() -> SigningKey {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        SigningKey::from_bytes(&seed)
    }

    #[test]
    #[cfg(feature = "getrandom")]
    fn certificate_roundtrip_and_verify() {
        let issuer_sk = gen_signing_key();
        let issuer_vk = VerifyingKey::from(&issuer_sk);
        let subject_sk = gen_signing_key();
        let subject_vk = VerifyingKey::from(&subject_sk);
        let subject_id = DeviceIdentity::from_bytes(&subject_vk.to_bytes());

        let cert =
            Certificate::new_unsigned(CertRole::Server, CertRole::Root, subject_id, 0, u64::MAX, 1)
                .sign(&issuer_sk);

        let enc = cert.encode();
        let dec = Certificate::decode(&enc).unwrap();
        dec.verify(&issuer_vk, 1).unwrap();
    }

    #[test]
    #[cfg(feature = "getrandom")]
    fn crl_sign_verify() {
        let issuer_sk = gen_signing_key();
        let issuer_vk = VerifyingKey::from(&issuer_sk);
        let revoked = vec![[0xAAu8; 32], [0xBBu8; 32]];
        let crl = Crl {
            issuer: DeviceIdentity::from_bytes(&issuer_vk.to_bytes()),
            revoked,
            signature: [0u8; 64],
        }
        .sign(&issuer_sk);
        crl.verify(&issuer_vk).unwrap();
    }

    #[test]
    #[cfg(feature = "getrandom")]
    fn rotation_cert_sign_verify() {
        let issuer_sk = gen_signing_key();
        let issuer_vk = VerifyingKey::from(&issuer_sk);
        let old_id = DeviceIdentity::from_bytes(&gen_signing_key().verifying_key().to_bytes());
        let new_id = DeviceIdentity::from_bytes(&gen_signing_key().verifying_key().to_bytes());
        let rc = RotationCertificate {
            old_device: old_id,
            new_device: new_id,
            signature: [0u8; 64],
        }
        .sign(&issuer_sk);
        rc.verify(&issuer_vk).unwrap();
    }
}
