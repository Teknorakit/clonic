//! Error types for ZCP envelope parsing and validation.

/// Errors that can occur during ZCP envelope encoding or decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Input buffer is too short to contain the expected data.
    BufferTooShort {
        /// Minimum bytes needed.
        need: usize,
        /// Bytes actually available.
        have: usize,
    },

    /// Buffer contains extra bytes after the complete envelope.
    TrailingBytes {
        /// Expected total frame size.
        expected: usize,
        /// Actual buffer size.
        actual: usize,
    },

    /// Unknown protocol version byte.
    UnknownVersion(u8),

    /// Unknown message type byte (not in any allocated range).
    UnknownMsgType(u8),

    /// Unknown crypto suite identifier.
    UnknownCryptoSuite(u8),

    /// Payload exceeds maximum encodable size (> u32::MAX bytes).
    PayloadTooLarge(usize),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::BufferTooShort { need, have } => {
                write!(f, "buffer too short: need {need} bytes, have {have}")
            }
            Error::TrailingBytes { expected, actual } => {
                write!(f, "trailing bytes: expected {expected}, got {actual}")
            }
            Error::UnknownVersion(v) => {
                write!(f, "unknown protocol version: 0x{v:02x}")
            }
            Error::UnknownMsgType(t) => {
                write!(f, "unknown message type: 0x{t:02x}")
            }
            Error::UnknownCryptoSuite(s) => {
                write!(f, "unknown crypto suite: 0x{s:02x}")
            }
            Error::PayloadTooLarge(len) => {
                write!(f, "payload too large: {len} bytes (max {})", u32::MAX)
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
