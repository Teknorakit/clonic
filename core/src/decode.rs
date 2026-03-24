//! Decode ZCP envelopes from wire bytes.
//!
//! The primary decode path is [`EnvelopeRef::parse`] (zero-copy, no_std).
//! This module provides additional convenience functions for common
//! decode patterns.

use crate::envelope::{EnvelopeRef, HEADER_SIZE, MAC_SIZE};
use crate::error::Error;

/// Peek at the header of a frame without fully parsing the envelope.
///
/// This is useful for transport framing: read the first [`HEADER_SIZE`]
/// bytes from the wire, call this to learn the total frame length, then
/// read the remaining bytes before calling [`EnvelopeRef::parse`].
///
/// Returns `(payload_length, total_frame_length)`.
pub fn peek_frame_length(header: &[u8]) -> Result<(u32, usize), Error> {
    if header.len() < HEADER_SIZE {
        return Err(Error::BufferTooShort {
            need: HEADER_SIZE,
            have: header.len(),
        });
    }

    let pl_bytes: [u8; 4] = [header[38], header[39], header[40], header[41]];
    let payload_len = u32::from_be_bytes(pl_bytes);
    let total = HEADER_SIZE + payload_len as usize + MAC_SIZE;

    Ok((payload_len, total))
}

/// Parse a complete envelope from a byte buffer (zero-copy).
///
/// This is a re-export of [`EnvelopeRef::parse`] for module-level access.
pub fn parse(buf: &[u8]) -> Result<EnvelopeRef<'_>, Error> {
    EnvelopeRef::parse(buf)
}

/// Parse an owned envelope from wire bytes (requires `alloc`).
///
/// Re-export of [`crate::envelope::Envelope::from_bytes`].
#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
pub fn parse_owned(buf: &[u8]) -> Result<crate::envelope::Envelope, Error> {
    crate::envelope::Envelope::from_bytes(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peek_frame_length_empty() {
        assert!(matches!(
            peek_frame_length(&[]),
            Err(Error::BufferTooShort { need: 42, have: 0 })
        ));
    }

    #[test]
    fn peek_frame_length_short() {
        assert!(matches!(
            peek_frame_length(&[0u8; 41]),
            Err(Error::BufferTooShort { need: 42, have: 41 })
        ));
    }

    #[test]
    fn peek_frame_length_zero_payload() {
        let mut header = [0u8; 42];
        header[0] = 0x01;
        header[38..42].copy_from_slice(&0u32.to_be_bytes());

        let (pl, total) = peek_frame_length(&header).unwrap();
        assert_eq!(pl, 0);
        assert_eq!(total, HEADER_SIZE + MAC_SIZE);
    }

    #[test]
    fn peek_frame_length_large_payload() {
        let mut header = [0u8; 42];
        header[0] = 0x01;
        header[38..42].copy_from_slice(&1_000_000u32.to_be_bytes());

        let (pl, total) = peek_frame_length(&header).unwrap();
        assert_eq!(pl, 1_000_000);
        assert_eq!(total, HEADER_SIZE + 1_000_000 + MAC_SIZE);
    }

    #[test]
    fn peek_accepts_longer_buffer() {
        // peek only reads first 42 bytes, ignores the rest
        let mut buf = [0u8; 1024];
        buf[0] = 0x01;
        buf[38..42].copy_from_slice(&100u32.to_be_bytes());

        let (pl, _) = peek_frame_length(&buf).unwrap();
        assert_eq!(pl, 100);
    }

    #[test]
    fn parse_delegates_to_envelope_ref() {
        // Build a minimal valid frame
        let mut frame = [0u8; 58]; // header + 0 payload + MAC
        frame[0] = 0x01; // version
        frame[1] = 0x01; // TaskRoute
        frame[2] = 0x01; // PqHybrid
                         // payload_length = 0 (already zeros)
                         // MAC = last 16 bytes (already zeros)

        let env = parse(&frame).unwrap();
        assert_eq!(env.version(), crate::version::Version::V1);
    }
}
