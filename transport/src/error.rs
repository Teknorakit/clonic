//! Error types for transport operations.

/// Transport operation errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Connection failed
    ConnectionFailed,
    /// Connection closed
    ConnectionClosed,
    /// Send operation failed
    SendFailed,
    /// Receive operation failed
    ReceiveFailed,
    /// Invalid frame format
    InvalidFrame,
    /// Buffer too small for operation
    BufferTooSmall,
    /// Timeout waiting for data
    Timeout,
    /// Transport not initialized
    NotInitialized,
}

#[cfg(feature = "std")]
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::ConnectionFailed => write!(f, "connection failed"),
            Error::ConnectionClosed => write!(f, "connection closed"),
            Error::SendFailed => write!(f, "send failed"),
            Error::ReceiveFailed => write!(f, "receive failed"),
            Error::InvalidFrame => write!(f, "invalid frame format"),
            Error::BufferTooSmall => write!(f, "buffer too small"),
            Error::Timeout => write!(f, "timeout"),
            Error::NotInitialized => write!(f, "transport not initialized"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
