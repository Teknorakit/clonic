//! Encode a ZCP envelope to wire bytes.
//!
//! Two encoding paths:
//!
//! - [`encode_to_slice`] — write into a caller-provided `&mut [u8]`.
//!   Works on `no_std` with no allocator. Returns the number of bytes
//!   written.
//!
//! - [`encode_to_vec`] — allocate and return a `Vec<u8>`.
//!   Requires the `alloc` feature.

use crate::crypto_suite::CryptoSuite;
use crate::envelope::{Flags, HEADER_SIZE, MAC_SIZE};
use crate::error::Error;
use crate::msg_type::MsgType;
use crate::residency::ResidencyTag;
use crate::version::Version;

/// Parameters for encoding a single ZCP envelope.
///
/// This is a "view" struct — it borrows the payload and device ID rather
/// than owning them, so it works without allocation.
pub struct EnvelopeFields<'a> {
    /// Protocol version.
    pub version: Version,
    /// Message type.
    pub msg_type: MsgType,
    /// Crypto suite.
    pub crypto_suite: CryptoSuite,
    /// Flags.
    pub flags: Flags,
    /// 32-byte sender device identity.
    pub sender_device_id: &'a [u8; 32],
    /// Residency zone tag.
    pub residency_tag: ResidencyTag,
    /// Encrypted payload (opaque bytes).
    pub payload: &'a [u8],
    /// 16-byte GCM authentication tag.
    pub mac: &'a [u8; 16],
}

/// Encode an envelope into a pre-allocated byte slice.
///
/// Returns the total number of bytes written (always
/// `HEADER_SIZE + payload.len() + MAC_SIZE`).
///
/// # Errors
///
/// Returns [`Error::BufferTooShort`] if `dst` is too small.
/// Returns [`Error::PayloadTooLarge`] if `payload.len() > u32::MAX`.
pub fn encode_to_slice(fields: &EnvelopeFields<'_>, dst: &mut [u8]) -> Result<usize, Error> {
    let payload_len = fields.payload.len();

    if payload_len > u32::MAX as usize {
        return Err(Error::PayloadTooLarge(payload_len));
    }

    let total = HEADER_SIZE + payload_len + MAC_SIZE;

    if dst.len() < total {
        return Err(Error::BufferTooShort {
            need: total,
            have: dst.len(),
        });
    }

    // ── Header (42 bytes) ────────────────────────────────
    dst[0] = fields.version.as_byte();
    dst[1] = fields.msg_type.as_byte();
    dst[2] = fields.crypto_suite.as_byte();
    dst[3] = fields.flags.as_byte();
    dst[4..36].copy_from_slice(fields.sender_device_id);

    let res_bytes = fields.residency_tag.to_be_bytes();
    dst[36] = res_bytes[0];
    dst[37] = res_bytes[1];

    let pl_bytes = (payload_len as u32).to_be_bytes();
    dst[38] = pl_bytes[0];
    dst[39] = pl_bytes[1];
    dst[40] = pl_bytes[2];
    dst[41] = pl_bytes[3];

    // ── Payload ──────────────────────────────────────────
    dst[HEADER_SIZE..HEADER_SIZE + payload_len].copy_from_slice(fields.payload);

    // ── MAC ──────────────────────────────────────────────
    let mac_start = HEADER_SIZE + payload_len;
    dst[mac_start..mac_start + MAC_SIZE].copy_from_slice(fields.mac);

    Ok(total)
}

/// Encode an envelope and return an owned `Vec<u8>`.
///
/// Convenience wrapper around [`encode_to_slice`].
#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
pub fn encode_to_vec(envelope: &crate::envelope::Envelope) -> alloc::vec::Vec<u8> {
    let total = HEADER_SIZE + envelope.payload.len() + MAC_SIZE;
    let mut buf = alloc::vec![0u8; total];

    let fields = EnvelopeFields {
        version: envelope.version,
        msg_type: envelope.msg_type,
        crypto_suite: envelope.crypto_suite,
        flags: envelope.flags,
        sender_device_id: &envelope.sender_device_id,
        residency_tag: envelope.residency_tag,
        payload: &envelope.payload,
        mac: &envelope.mac,
    };

    encode_to_slice(&fields, &mut buf).expect("pre-allocated buffer is exactly the right size");
    buf
}
