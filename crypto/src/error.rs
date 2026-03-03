//! Error types for cryptographic operations.

/// Cryptographic operation errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Invalid key material length
    InvalidKeyLength,
    /// Invalid nonce/IV length
    InvalidNonceLength,
    /// Invalid ciphertext length
    InvalidCiphertextLength,
    /// MAC verification failed (tamper detected)
    MacVerificationFailed,
    /// Invalid signature
    InvalidSignature,
    /// Unsupported crypto suite
    UnsupportedSuite,
    /// Buffer too small for operation
    BufferTooSmall,
}

#[cfg(feature = "std")]
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidKeyLength => write!(f, "invalid key length"),
            Error::InvalidNonceLength => write!(f, "invalid nonce length"),
            Error::InvalidCiphertextLength => write!(f, "invalid ciphertext length"),
            Error::MacVerificationFailed => write!(f, "MAC verification failed"),
            Error::InvalidSignature => write!(f, "invalid signature"),
            Error::UnsupportedSuite => write!(f, "unsupported crypto suite"),
            Error::BufferTooSmall => write!(f, "buffer too small"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
