//! ZCP envelope — the fundamental unit of ZCP wire communication.
//!
//! Two representations are provided:
//!
//! - [`EnvelopeRef`] — zero-copy view over a byte buffer. Works on `no_std`
//!   with no allocator. This is what constrained devices (ESP32) use.
//!
//! - [`Envelope`] — owned, heap-allocated envelope. Requires the `alloc`
//!   feature. This is what ZluidrOS uses for building outbound messages.
//!
//! Both share the same 42-byte header layout.

use crate::crypto_suite::CryptoSuite;
use crate::error::Error;
use crate::msg_type::MsgType;
use crate::residency::ResidencyTag;
use crate::version::Version;

/// Fixed header size in bytes.
///
/// ```text
/// 1 (version) + 1 (msg_type) + 1 (crypto_suite) + 1 (flags)
/// + 32 (sender_device_id) + 2 (residency_tag) + 4 (payload_length)
/// = 42 bytes
/// ```
pub const HEADER_SIZE: usize = 42;

/// AES-256-GCM authentication tag size.
pub const MAC_SIZE: usize = 16;

/// Minimum valid frame: header + zero-length payload + MAC.
pub const MIN_FRAME_SIZE: usize = HEADER_SIZE + MAC_SIZE;

// ── Header field offsets ─────────────────────────────────────────────

const OFF_VERSION: usize = 0;
const OFF_MSG_TYPE: usize = 1;
const OFF_CRYPTO_SUITE: usize = 2;
const OFF_FLAGS: usize = 3;
const OFF_SENDER_ID: usize = 4;
const OFF_SENDER_ID_END: usize = 36;
const OFF_RESIDENCY: usize = 36;
const OFF_PAYLOAD_LEN: usize = 38;

// ── Flags ────────────────────────────────────────────────────────────

/// Bit flags in the envelope header.
///
/// Bits 0–1 are defined; bits 2–7 are reserved and **must be zero**
/// in v0x01 envelopes. Receivers should ignore unknown flags from
/// higher protocol versions (forward compatibility).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Flags(u8);

impl Flags {
    /// No flags set.
    pub const NONE: Flags = Flags(0);

    /// Bit 0: Payload is compressed (algorithm TBD — likely LZ4 or zstd).
    pub const COMPRESSED: u8 = 0b0000_0001;

    /// Bit 1: This envelope is a fragment of a larger message.
    /// Fragment reassembly metadata is in the payload prefix.
    pub const FRAGMENTED: u8 = 0b0000_0010;

    /// Create flags from a raw byte.
    pub const fn from_byte(b: u8) -> Flags {
        Flags(b)
    }

    /// The raw byte value.
    pub const fn as_byte(self) -> u8 {
        self.0
    }

    /// Check whether a specific flag bit is set.
    pub const fn has(self, flag: u8) -> bool {
        self.0 & flag != 0
    }

    /// Set a flag bit, returning the new flags.
    pub const fn with(self, flag: u8) -> Flags {
        Flags(self.0 | flag)
    }

    /// Clear a flag bit, returning the new flags.
    pub const fn without(self, flag: u8) -> Flags {
        Flags(self.0 & !flag)
    }

    /// Whether any reserved bits (2–7) are set.
    /// V1 receivers should warn on this but not reject.
    pub const fn has_unknown_bits(self) -> bool {
        self.0 & 0b1111_1100 != 0
    }
}

// ── EnvelopeRef (zero-copy, no_std) ──────────────────────────────────

/// Zero-copy view over a ZCP envelope in a byte buffer.
///
/// This is the primary type for constrained devices. It borrows the
/// underlying buffer and provides accessor methods for each header field
/// plus slices into the payload and MAC regions.
///
/// No heap allocation. No copying. Just pointer arithmetic.
///
/// # Validation
///
/// [`EnvelopeRef::parse`] validates:
/// - Buffer is at least [`MIN_FRAME_SIZE`] bytes
/// - `version` is known
/// - `msg_type` is known (strict) or in a known range (lenient)
/// - `crypto_suite` is known
/// - `payload_length` matches actual remaining bytes
///
/// It does **not** verify the MAC — that requires the crypto layer.
#[derive(Clone, Copy)]
pub struct EnvelopeRef<'a> {
    buf: &'a [u8],
    /// Cached payload length to avoid repeated BE decoding.
    payload_len: u32,
}

impl<'a> EnvelopeRef<'a> {
    /// Parse a ZCP envelope from a byte buffer.
    ///
    /// The buffer must contain exactly one complete envelope (header +
    /// payload + MAC). Use [`EnvelopeRef::frame_length`] to determine
    /// how many bytes to read from the transport before calling this.
    pub fn parse(buf: &'a [u8]) -> Result<Self, Error> {
        if buf.len() < MIN_FRAME_SIZE {
            return Err(Error::BufferTooShort {
                need: MIN_FRAME_SIZE,
                have: buf.len(),
            });
        }

        // Version
        if Version::from_byte(buf[OFF_VERSION]).is_none() {
            return Err(Error::UnknownVersion(buf[OFF_VERSION]));
        }

        // Message type — lenient: accept if in a known range
        if MsgType::from_byte(buf[OFF_MSG_TYPE]).is_none() {
            // Check if it's at least in a known range (relay-friendly)
            let range = MsgType::range_of(buf[OFF_MSG_TYPE]);
            if matches!(range, crate::msg_type::MsgRange::Unknown) {
                return Err(Error::UnknownMsgType(buf[OFF_MSG_TYPE]));
            }
        }

        // Crypto suite
        if CryptoSuite::from_byte(buf[OFF_CRYPTO_SUITE]).is_none() {
            return Err(Error::UnknownCryptoSuite(buf[OFF_CRYPTO_SUITE]));
        }

        // Payload length
        let pl_bytes: [u8; 4] = [
            buf[OFF_PAYLOAD_LEN],
            buf[OFF_PAYLOAD_LEN + 1],
            buf[OFF_PAYLOAD_LEN + 2],
            buf[OFF_PAYLOAD_LEN + 3],
        ];
        let payload_len = u32::from_be_bytes(pl_bytes);
        let expected = HEADER_SIZE + payload_len as usize + MAC_SIZE;

        if buf.len() < expected {
            return Err(Error::BufferTooShort {
                need: expected,
                have: buf.len(),
            });
        }

        if buf.len() > expected {
            return Err(Error::TrailingBytes {
                expected,
                actual: buf.len(),
            });
        }

        Ok(EnvelopeRef { buf, payload_len })
    }

    /// Calculate the total frame size from just the header bytes.
    ///
    /// Useful for transport framing: read 42 bytes, extract payload_length,
    /// then read the remaining `payload_length + 16` bytes.
    ///
    /// Returns `None` if the buffer is shorter than [`HEADER_SIZE`].
    pub fn frame_length(header: &[u8]) -> Option<usize> {
        if header.len() < HEADER_SIZE {
            return None;
        }
        let pl_bytes: [u8; 4] = [
            header[OFF_PAYLOAD_LEN],
            header[OFF_PAYLOAD_LEN + 1],
            header[OFF_PAYLOAD_LEN + 2],
            header[OFF_PAYLOAD_LEN + 3],
        ];
        let payload_len = u32::from_be_bytes(pl_bytes) as usize;
        Some(HEADER_SIZE + payload_len + MAC_SIZE)
    }

    // ── Field accessors ──────────────────────────────────

    /// Protocol version.
    pub fn version(&self) -> Version {
        // Already validated in parse()
        Version::from_byte(self.buf[OFF_VERSION]).unwrap()
    }

    /// Message type. Returns `None` for unknown-but-in-range types.
    pub fn msg_type(&self) -> Option<MsgType> {
        MsgType::from_byte(self.buf[OFF_MSG_TYPE])
    }

    /// Raw message type byte (useful when `msg_type()` returns `None`).
    pub fn msg_type_raw(&self) -> u8 {
        self.buf[OFF_MSG_TYPE]
    }

    /// Crypto suite used for the payload.
    pub fn crypto_suite(&self) -> CryptoSuite {
        CryptoSuite::from_byte(self.buf[OFF_CRYPTO_SUITE]).unwrap()
    }

    /// Flags byte.
    pub fn flags(&self) -> Flags {
        Flags::from_byte(self.buf[OFF_FLAGS])
    }

    /// The 32-byte sender device identity (Ed25519 public key).
    pub fn sender_device_id(&self) -> &[u8; 32] {
        self.buf[OFF_SENDER_ID..OFF_SENDER_ID_END]
            .try_into()
            .unwrap()
    }

    /// Data residency zone tag.
    pub fn residency_tag(&self) -> ResidencyTag {
        let bytes: [u8; 2] = [self.buf[OFF_RESIDENCY], self.buf[OFF_RESIDENCY + 1]];
        ResidencyTag::from_be_bytes(bytes)
    }

    /// Payload length in bytes.
    pub fn payload_length(&self) -> u32 {
        self.payload_len
    }

    /// The encrypted payload bytes (opaque to this crate).
    pub fn payload(&self) -> &[u8] {
        let start = HEADER_SIZE;
        let end = start + self.payload_len as usize;
        &self.buf[start..end]
    }

    /// The 16-byte AES-256-GCM authentication tag.
    pub fn mac(&self) -> &[u8; 16] {
        let start = HEADER_SIZE + self.payload_len as usize;
        self.buf[start..start + MAC_SIZE].try_into().unwrap()
    }

    /// The complete header bytes (first 42 bytes).
    ///
    /// Useful as AAD (Additional Authenticated Data) for GCM verification.
    pub fn header_bytes(&self) -> &[u8] {
        &self.buf[..HEADER_SIZE]
    }

    /// The entire raw frame.
    pub fn as_bytes(&self) -> &[u8] {
        self.buf
    }
}

impl<'a> core::fmt::Debug for EnvelopeRef<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EnvelopeRef")
            .field("version", &self.version())
            .field("msg_type", &self.msg_type())
            .field("crypto_suite", &self.crypto_suite())
            .field("flags", &self.flags())
            .field("sender_device_id", &hex_short(self.sender_device_id()))
            .field("residency_tag", &self.residency_tag())
            .field("payload_length", &self.payload_len)
            .finish()
    }
}

// ── Envelope (owned, requires alloc) ─────────────────────────────────

/// Owned ZCP envelope with heap-allocated payload.
///
/// Used by ZluidrOS for constructing outbound envelopes. Provides a
/// builder-style API for setting header fields and attaching a payload.
///
/// To convert to wire bytes, use [`crate::encode::encode`] or the
/// [`Envelope::to_bytes`] convenience method.
#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Envelope {
    /// Protocol version.
    pub version: Version,
    /// Message type.
    pub msg_type: MsgType,
    /// Crypto suite used for the payload.
    pub crypto_suite: CryptoSuite,
    /// Flags.
    pub flags: Flags,
    /// 32-byte sender device identity (Ed25519 public key).
    pub sender_device_id: [u8; 32],
    /// Data residency zone.
    pub residency_tag: ResidencyTag,
    /// Encrypted payload (opaque).
    pub payload: alloc::vec::Vec<u8>,
    /// 16-byte GCM authentication tag.
    pub mac: [u8; 16],
}

#[cfg(feature = "alloc")]
impl Envelope {
    /// Create a new envelope with the current protocol version.
    pub fn new(
        msg_type: MsgType,
        crypto_suite: CryptoSuite,
        sender_device_id: [u8; 32],
        residency_tag: ResidencyTag,
        payload: alloc::vec::Vec<u8>,
        mac: [u8; 16],
    ) -> Self {
        Self {
            version: Version::CURRENT,
            msg_type,
            crypto_suite,
            flags: Flags::NONE,
            sender_device_id,
            residency_tag,
            payload,
            mac,
        }
    }

    /// Set the flags byte.
    pub fn with_flags(mut self, flags: Flags) -> Self {
        self.flags = flags;
        self
    }

    /// Encode this envelope to wire bytes.
    ///
    /// Convenience wrapper around [`crate::encode::encode_to_vec`].
    pub fn to_bytes(&self) -> alloc::vec::Vec<u8> {
        crate::encode::encode_to_vec(self)
    }

    /// Parse an owned envelope from wire bytes.
    ///
    /// Convenience wrapper: parses with [`EnvelopeRef`] then copies
    /// the payload to the heap.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, Error> {
        let r = EnvelopeRef::parse(buf)?;
        Ok(Envelope {
            version: r.version(),
            msg_type: r.msg_type().ok_or(Error::UnknownMsgType(r.msg_type_raw()))?,
            crypto_suite: r.crypto_suite(),
            flags: r.flags(),
            sender_device_id: *r.sender_device_id(),
            residency_tag: r.residency_tag(),
            payload: alloc::vec::Vec::from(r.payload()),
            mac: *r.mac(),
        })
    }
}

// ── Helpers ──────────────────────────────────────────────────────────

/// Format first/last 4 bytes of a 32-byte key for debug output.
struct HexShort<'a>(&'a [u8; 32]);

fn hex_short(key: &[u8; 32]) -> HexShort<'_> {
    HexShort(key)
}

impl core::fmt::Debug for HexShort<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{:02x}{:02x}{:02x}{:02x}..{:02x}{:02x}{:02x}{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3],
            self.0[28], self.0[29], self.0[30], self.0[31],
        )
    }
}
