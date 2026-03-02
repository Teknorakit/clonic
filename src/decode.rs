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
/// Re-export of [`Envelope::from_bytes`].
#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
pub fn parse_owned(buf: &[u8]) -> Result<crate::envelope::Envelope, Error> {
    crate::envelope::Envelope::from_bytes(buf)
}
