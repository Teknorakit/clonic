//! Error types for identity and provisioning operations.

/// Identity and provisioning operation errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Invalid device identity (public key)
    InvalidDeviceIdentity,
    /// Invalid certificate format
    InvalidCertificate,
    /// Certificate signature verification failed
    CertificateSignatureInvalid,
    /// Certificate has expired or trust has decayed beyond acceptable depth
    CertificateExpired,
    /// Invalid provisioning message format
    InvalidProvisioningMessage,
    /// Key rotation failed
    KeyRotationFailed,
    /// Secure key storage error
    KeyStorageError,
    /// Buffer too small for operation
    BufferTooSmall,
}

#[cfg(feature = "std")]
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidDeviceIdentity => write!(f, "invalid device identity"),
            Error::InvalidCertificate => write!(f, "invalid certificate format"),
            Error::CertificateSignatureInvalid => write!(f, "certificate signature invalid"),
            Error::CertificateExpired => write!(f, "certificate expired or trust decayed"),
            Error::InvalidProvisioningMessage => write!(f, "invalid provisioning message"),
            Error::KeyRotationFailed => write!(f, "key rotation failed"),
            Error::KeyStorageError => write!(f, "key storage error"),
            Error::BufferTooSmall => write!(f, "buffer too small"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
