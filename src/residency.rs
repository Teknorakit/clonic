//! Data residency zone tags (ADR-004, ADR-010).
//!
//! Every ZCP message carries a 2-byte residency tag that declares where
//! the payload data is allowed to exist. The ZCP routing layer (above
//! this crate) **refuses to forward** messages to peers outside the
//! allowed zone. This is architectural enforcement — application bugs
//! cannot accidentally exfiltrate regulated data.
//!
//! ## Encoding
//!
//! The 2-byte tag uses ISO 3166-1 **numeric** codes in big-endian:
//!
//! ```text
//! Bit 15 (high bit): Extension flag
//!   0 = country-level zone (ISO 3166-1 numeric in bits 0–14)
//!   1 = extended format follows (ISO 3166-2 subdivision, reserved)
//!
//! Bits 0–14: ISO 3166-1 numeric country code (0–999)
//! ```
//!
//! Special values:
//! - `0x0000` = `Global` — no residency restriction
//! - `0x0168` (360) = Indonesia
//! - `0x8000` bit set = extended (future province-level, per ADR-010)

/// A 2-byte data residency zone tag.
///
/// Carried in every ZCP envelope. The routing layer uses this to enforce
/// data sovereignty at the network level.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ResidencyTag(u16);

impl ResidencyTag {
    /// No residency restriction — data may travel anywhere.
    pub const GLOBAL: ResidencyTag = ResidencyTag(0);

    /// Indonesia (ISO 3166-1 numeric 360).
    /// PP 71/2019, GR 82/2012 regulated data.
    pub const INDONESIA: ResidencyTag = ResidencyTag(360);

    /// Malaysia (ISO 3166-1 numeric 458).
    pub const MALAYSIA: ResidencyTag = ResidencyTag(458);

    /// Philippines (ISO 3166-1 numeric 608).
    pub const PHILIPPINES: ResidencyTag = ResidencyTag(608);

    /// Vietnam (ISO 3166-1 numeric 704).
    pub const VIETNAM: ResidencyTag = ResidencyTag(704);

    /// Singapore (ISO 3166-1 numeric 702).
    pub const SINGAPORE: ResidencyTag = ResidencyTag(702);

    /// The extension flag bit (bit 15).
    const EXTENSION_BIT: u16 = 0x8000;

    /// Create a country-level residency tag from an ISO 3166-1 numeric code.
    ///
    /// Returns `None` if the code exceeds 14 bits (> 16383), which would
    /// collide with the extension flag. In practice, ISO 3166-1 numeric
    /// codes are 0–999, so this is generous.
    pub const fn from_country_code(code: u16) -> Option<ResidencyTag> {
        if code & Self::EXTENSION_BIT != 0 {
            None // Would collide with extension flag
        } else {
            Some(ResidencyTag(code))
        }
    }

    /// Create a tag from raw big-endian wire bytes.
    pub const fn from_be_bytes(bytes: [u8; 2]) -> ResidencyTag {
        ResidencyTag(u16::from_be_bytes(bytes))
    }

    /// Encode to big-endian wire bytes.
    pub const fn to_be_bytes(self) -> [u8; 2] {
        self.0.to_be_bytes()
    }

    /// The raw u16 value (host byte order).
    pub const fn raw(self) -> u16 {
        self.0
    }

    /// Whether the extension flag (bit 15) is set.
    ///
    /// When set, the tag encodes a sub-national zone (ISO 3166-2).
    /// This is reserved for future use per ADR-010.
    pub const fn is_extended(self) -> bool {
        self.0 & Self::EXTENSION_BIT != 0
    }

    /// Extract the country code (bits 0–14), ignoring the extension flag.
    pub const fn country_code(self) -> u16 {
        self.0 & !Self::EXTENSION_BIT
    }

    /// Whether this is the unrestricted global zone.
    pub const fn is_global(self) -> bool {
        self.0 == 0
    }

    /// Check if a destination zone is compatible with this tag.
    ///
    /// - `Global` data can go anywhere.
    /// - Country-level data can only go to the same country or `Global`.
    ///
    /// This is a simplified check. The full routing policy (multi-zone
    /// allowlists, cross-border agreements) lives in the ZCP routing layer.
    pub const fn allows_destination(self, dest: ResidencyTag) -> bool {
        if self.is_global() {
            true
        } else if dest.is_global() {
            // Country-restricted data going to a "global" peer is allowed
            // only if the peer is physically in the same country.
            // This crate can't know that — return false to be safe.
            // The routing layer has geographic awareness and overrides.
            false
        } else {
            self.country_code() == dest.country_code()
        }
    }
}

impl core::fmt::Debug for ResidencyTag {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::GLOBAL => write!(f, "ResidencyTag::GLOBAL"),
            Self::INDONESIA => write!(f, "ResidencyTag::INDONESIA"),
            Self::MALAYSIA => write!(f, "ResidencyTag::MALAYSIA"),
            Self::PHILIPPINES => write!(f, "ResidencyTag::PHILIPPINES"),
            Self::VIETNAM => write!(f, "ResidencyTag::VIETNAM"),
            Self::SINGAPORE => write!(f, "ResidencyTag::SINGAPORE"),
            tag if tag.is_extended() => {
                write!(f, "ResidencyTag::Extended({})", tag.country_code())
            }
            tag => write!(f, "ResidencyTag({})", tag.raw()),
        }
    }
}

impl core::fmt::Display for ResidencyTag {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.is_global() {
            write!(f, "GLOBAL")
        } else if self.is_extended() {
            write!(f, "EXT:{}", self.country_code())
        } else {
            // ISO 3166-1 numeric codes are zero-padded to 3 digits
            write!(f, "{:03}", self.raw())
        }
    }
}
