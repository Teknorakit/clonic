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

#[cfg(test)]
mod tests {
    use super::*;

    // We need Write trait for no_std formatting tests
    struct FmtBuf {
        buf: [u8; 128],
        len: usize,
    }

    impl FmtBuf {
        fn new() -> Self {
            FmtBuf {
                buf: [0; 128],
                len: 0,
            }
        }
        fn as_str(&self) -> &str {
            core::str::from_utf8(&self.buf[..self.len]).unwrap()
        }
    }

    impl core::fmt::Write for FmtBuf {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            let bytes = s.as_bytes();
            let end = self.len + bytes.len();
            if end > self.buf.len() {
                return Err(core::fmt::Error);
            }
            self.buf[self.len..end].copy_from_slice(bytes);
            self.len = end;
            Ok(())
        }
    }

    fn display(e: &Error) -> FmtBuf {
        let mut buf = FmtBuf::new();
        core::fmt::Write::write_fmt(&mut buf, format_args!("{e}")).unwrap();
        buf
    }

    #[test]
    fn display_buffer_too_short() {
        let e = Error::BufferTooShort { need: 58, have: 10 };
        assert_eq!(
            display(&e).as_str(),
            "buffer too short: need 58 bytes, have 10"
        );
    }

    #[test]
    fn display_trailing_bytes() {
        let e = Error::TrailingBytes {
            expected: 58,
            actual: 60,
        };
        assert_eq!(display(&e).as_str(), "trailing bytes: expected 58, got 60");
    }

    #[test]
    fn display_unknown_version() {
        let e = Error::UnknownVersion(0xFF);
        assert_eq!(display(&e).as_str(), "unknown protocol version: 0xff");
    }

    #[test]
    fn display_unknown_msg_type() {
        let e = Error::UnknownMsgType(0x80);
        assert_eq!(display(&e).as_str(), "unknown message type: 0x80");
    }

    #[test]
    fn display_unknown_crypto_suite() {
        let e = Error::UnknownCryptoSuite(0x03);
        assert_eq!(display(&e).as_str(), "unknown crypto suite: 0x03");
    }

    #[test]
    fn display_payload_too_large() {
        let e = Error::PayloadTooLarge(5_000_000_000);
        let s = display(&e);
        assert!(s
            .as_str()
            .starts_with("payload too large: 5000000000 bytes"));
    }

    #[test]
    fn errors_are_eq() {
        assert_eq!(
            Error::BufferTooShort { need: 42, have: 10 },
            Error::BufferTooShort { need: 42, have: 10 },
        );
        assert_ne!(Error::UnknownVersion(0x01), Error::UnknownVersion(0x02),);
    }

    #[test]
    fn errors_are_clone() {
        let e = Error::UnknownVersion(0xFF);
        let e2 = e.clone();
        assert_eq!(e, e2);
    }
}
