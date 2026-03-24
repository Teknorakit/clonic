//! Signature primitives for ZCP suites.
//! Suite 0x01: ML-DSA-65 + Ed25519 hybrid (concatenated signatures).
//! Suite 0x02: Ed25519 only.

use alloc::vec::Vec;
use ed25519_dalek::Signer;
use ed25519_dalek::{Signature as EdSignature, SigningKey, VerifyingKey};
#[cfg(feature = "getrandom")]
use rand_core::{OsRng, RngCore};
use zeroize::Zeroize;

use crate::Error;

/// Hybrid signature keypair for Suite 0x01 (ML-DSA-65 + Ed25519).
/// Note: ML-DSA-65 support requires pqcrypto with sign feature enabled.
/// For now, this is Ed25519-only; ML-DSA-65 will be added when pqcrypto sign module is available.
#[derive(Debug)]
pub struct HybridSigKeypair {
    /// Ed25519 public key (32 bytes)
    pub ed_public: [u8; 32],
    /// Ed25519 secret key (32 bytes)
    pub ed_secret: [u8; 32],
}

impl Drop for HybridSigKeypair {
    fn drop(&mut self) {
        self.ed_secret.zeroize();
    }
}

impl HybridSigKeypair {
    /// Generate a new hybrid signature keypair (currently Ed25519 only).
    pub fn keygen() -> Result<Self, Error> {
        #[cfg(feature = "getrandom")]
        {
            let mut ed_seed = [0u8; 32];
            OsRng.fill_bytes(&mut ed_seed);
            let ed_sk = SigningKey::from_bytes(&ed_seed);
            let ed_vk = VerifyingKey::from(&ed_sk);

            let keypair = HybridSigKeypair {
                ed_public: ed_vk.to_bytes(),
                ed_secret: ed_seed,
            };

            // Zeroize the temporary seed after use
            ed_seed.zeroize();

            Ok(keypair)
        }
        #[cfg(not(feature = "getrandom"))]
        {
            // No randomness source available
            Err(Error::NoRandomnessSource)
        }
    }

    /// Sign a message with Ed25519 (ML-DSA-65 placeholder).
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let ed_sk = SigningKey::from_bytes(&self.ed_secret);
        let ed_sig: EdSignature = ed_sk.sign(message);
        Ok(ed_sig.to_bytes().to_vec())
    }

    /// Verify an Ed25519 signature (ML-DSA-65 placeholder).
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Error> {
        if signature.len() != 64 {
            return Err(Error::InvalidSignature);
        }
        let ed_vk =
            VerifyingKey::from_bytes(&self.ed_public).map_err(|_| Error::InvalidSignature)?;
        let ed_sig_bytes: [u8; 64] = signature.try_into().map_err(|_| Error::InvalidSignature)?;
        let ed_sig = EdSignature::from_bytes(&ed_sig_bytes);
        ed_vk
            .verify_strict(message, &ed_sig)
            .map_err(|_| Error::InvalidSignature)
    }
}

/// Classical signature keypair for Suite 0x02 (Ed25519 only).
#[derive(Debug)]
pub struct ClassicalSigKeypair {
    /// Ed25519 public key (32 bytes)
    pub ed_public: [u8; 32],
    /// Ed25519 secret key (32 bytes)
    pub ed_secret: [u8; 32],
}

impl Drop for ClassicalSigKeypair {
    fn drop(&mut self) {
        self.ed_secret.zeroize();
    }
}

impl ClassicalSigKeypair {
    /// Generate a new Ed25519 signature keypair.
    pub fn keygen() -> Result<Self, Error> {
        #[cfg(feature = "getrandom")]
        {
            let mut ed_seed = [0u8; 32];
            OsRng.fill_bytes(&mut ed_seed);
            let ed_sk = SigningKey::from_bytes(&ed_seed);
            let ed_vk = VerifyingKey::from(&ed_sk);

            let keypair = Self {
                ed_public: ed_vk.to_bytes(),
                ed_secret: ed_seed,
            };

            // Zeroize the temporary seed after use
            ed_seed.zeroize();

            Ok(keypair)
        }
        #[cfg(not(feature = "getrandom"))]
        {
            // No randomness source available
            Err(Error::NoRandomnessSource)
        }
    }

    /// Sign a message with Ed25519.
    pub fn sign(&self, message: &[u8]) -> Result<[u8; 64], Error> {
        let ed_sk = SigningKey::from_bytes(&self.ed_secret);
        Ok(ed_sk.sign(message).to_bytes())
    }

    /// Verify an Ed25519 signature.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Error> {
        if signature.len() != 64 {
            return Err(Error::InvalidSignature);
        }
        let ed_vk =
            VerifyingKey::from_bytes(&self.ed_public).map_err(|_| Error::InvalidSignature)?;
        let ed_sig_bytes: [u8; 64] = signature.try_into().map_err(|_| Error::InvalidSignature)?;
        let ed_sig = EdSignature::from_bytes(&ed_sig_bytes);
        ed_vk
            .verify_strict(message, &ed_sig)
            .map_err(|_| Error::InvalidSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "getrandom")]
    fn hybrid_sign_verify_roundtrip() {
        let kp = HybridSigKeypair::keygen().unwrap();
        let msg = b"zcp-hybrid-signature";
        let sig = kp.sign(msg).unwrap();
        kp.verify(msg, &sig).unwrap();
    }

    #[test]
    #[cfg(feature = "getrandom")]
    fn classical_sign_verify_roundtrip() {
        let kp = ClassicalSigKeypair::keygen().unwrap();
        let msg = b"zcp-classical-signature";
        let sig = kp.sign(msg).unwrap();
        kp.verify(msg, &sig).unwrap();
    }
}
