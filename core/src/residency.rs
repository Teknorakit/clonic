//! Data residency zone tags.
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
//!   0 = country-level zone (ISO 3166-1 numeric in bits 0-14)
//!   1 = extended format follows (ISO 3166-2 subdivision, reserved)
//!
//! Bits 0-14: ISO 3166-1 numeric country code (0-999)
//! ```
//!
//! Special values:
//! - `0x0000` = `Global` — no residency restriction
//! - `0x0168` (360) = Indonesia
//! - `0x8000` bit set = extended (future province-level)

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
    /// codes are 0-999, so this is generous.
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
    /// This is reserved for future use.
    pub const fn is_extended(self) -> bool {
        self.0 & Self::EXTENSION_BIT != 0
    }

    /// Extract the country code (bits 0-14), ignoring the extension flag.
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
            write!(f, "{:03}", self.raw())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Constants ────────────────────────────────────────

    #[test]
    fn constant_values_match_iso3166() {
        assert_eq!(ResidencyTag::GLOBAL.raw(), 0);
        assert_eq!(ResidencyTag::INDONESIA.raw(), 360);
        assert_eq!(ResidencyTag::MALAYSIA.raw(), 458);
        assert_eq!(ResidencyTag::PHILIPPINES.raw(), 608);
        assert_eq!(ResidencyTag::VIETNAM.raw(), 704);
        assert_eq!(ResidencyTag::SINGAPORE.raw(), 702);
    }

    // ── Construction ─────────────────────────────────────

    #[test]
    fn from_country_code_valid() {
        let tag = ResidencyTag::from_country_code(360).unwrap();
        assert_eq!(tag, ResidencyTag::INDONESIA);
    }

    #[test]
    fn from_country_code_zero_is_global() {
        let tag = ResidencyTag::from_country_code(0).unwrap();
        assert_eq!(tag, ResidencyTag::GLOBAL);
        assert!(tag.is_global());
    }

    #[test]
    fn from_country_code_max_valid() {
        // Largest value without hitting extension bit
        let tag = ResidencyTag::from_country_code(0x7FFF).unwrap();
        assert_eq!(tag.raw(), 0x7FFF);
        assert!(!tag.is_extended());
    }

    #[test]
    fn from_country_code_rejects_extension_bit() {
        assert!(ResidencyTag::from_country_code(0x8000).is_none());
        assert!(ResidencyTag::from_country_code(0x8001).is_none());
        assert!(ResidencyTag::from_country_code(0xFFFF).is_none());
    }

    // ── Wire encoding ────────────────────────────────────

    #[test]
    fn be_bytes_roundtrip() {
        let tags = [
            ResidencyTag::GLOBAL,
            ResidencyTag::INDONESIA,
            ResidencyTag::MALAYSIA,
            ResidencyTag::PHILIPPINES,
            ResidencyTag::VIETNAM,
            ResidencyTag::SINGAPORE,
        ];
        for tag in tags {
            let bytes = tag.to_be_bytes();
            let reconstructed = ResidencyTag::from_be_bytes(bytes);
            assert_eq!(reconstructed, tag, "BE roundtrip failed for {tag:?}");
        }
    }

    #[test]
    fn indonesia_be_bytes() {
        // 360 = 0x0168 → [0x01, 0x68] big-endian
        let bytes = ResidencyTag::INDONESIA.to_be_bytes();
        assert_eq!(bytes, [0x01, 0x68]);
    }

    #[test]
    fn global_be_bytes() {
        let bytes = ResidencyTag::GLOBAL.to_be_bytes();
        assert_eq!(bytes, [0x00, 0x00]);
    }

    // ── Extension bit ────────────────────────────────────

    #[test]
    fn extension_flag_detection() {
        let normal = ResidencyTag::from_be_bytes([0x01, 0x68]); // 360
        assert!(!normal.is_extended());

        let extended = ResidencyTag::from_be_bytes([0x81, 0x68]); // 360 + extension
        assert!(extended.is_extended());
    }

    #[test]
    fn country_code_strips_extension_bit() {
        let extended = ResidencyTag::from_be_bytes([0x81, 0x68]);
        assert!(extended.is_extended());
        assert_eq!(extended.country_code(), 360); // Indonesia code preserved
    }

    #[test]
    fn non_extended_country_code_unchanged() {
        assert_eq!(ResidencyTag::INDONESIA.country_code(), 360);
        assert_eq!(ResidencyTag::GLOBAL.country_code(), 0);
    }

    // ── Global detection ─────────────────────────────────

    #[test]
    fn is_global() {
        assert!(ResidencyTag::GLOBAL.is_global());
        assert!(!ResidencyTag::INDONESIA.is_global());
        assert!(!ResidencyTag::MALAYSIA.is_global());

        // Extension bit set with code 0 is NOT global (it's extended)
        let extended_zero = ResidencyTag::from_be_bytes([0x80, 0x00]);
        assert!(!extended_zero.is_global());
    }

    // ── Zone enforcement ─────────────────────────────────

    #[test]
    fn global_allows_any_destination() {
        assert!(ResidencyTag::GLOBAL.allows_destination(ResidencyTag::INDONESIA));
        assert!(ResidencyTag::GLOBAL.allows_destination(ResidencyTag::MALAYSIA));
        assert!(ResidencyTag::GLOBAL.allows_destination(ResidencyTag::GLOBAL));
    }

    #[test]
    fn same_country_allows() {
        assert!(ResidencyTag::INDONESIA.allows_destination(ResidencyTag::INDONESIA));
        assert!(ResidencyTag::MALAYSIA.allows_destination(ResidencyTag::MALAYSIA));
    }

    #[test]
    fn different_country_denies() {
        assert!(!ResidencyTag::INDONESIA.allows_destination(ResidencyTag::MALAYSIA));
        assert!(!ResidencyTag::MALAYSIA.allows_destination(ResidencyTag::INDONESIA));
        assert!(!ResidencyTag::INDONESIA.allows_destination(ResidencyTag::SINGAPORE));
        assert!(!ResidencyTag::VIETNAM.allows_destination(ResidencyTag::PHILIPPINES));
    }

    #[test]
    fn country_to_global_is_denied_by_default() {
        // Conservative: country-restricted data should not go to a
        // "global" peer without the routing layer's geographic check.
        assert!(!ResidencyTag::INDONESIA.allows_destination(ResidencyTag::GLOBAL));
        assert!(!ResidencyTag::MALAYSIA.allows_destination(ResidencyTag::GLOBAL));
    }

    // ── Display / Debug ──────────────────────────────────

    #[test]
    fn display_formatting() {
        let mut buf = heapless_fmt(ResidencyTag::GLOBAL);
        assert_eq!(buf.as_str(), "GLOBAL");

        buf = heapless_fmt(ResidencyTag::INDONESIA);
        assert_eq!(buf.as_str(), "360");

        // Zero-padded to 3 digits
        let tag7 = ResidencyTag::from_country_code(7).unwrap();
        buf = heapless_fmt(tag7);
        assert_eq!(buf.as_str(), "007");

        // Extended
        let ext = ResidencyTag::from_be_bytes([0x81, 0x68]);
        buf = heapless_fmt(ext);
        assert_eq!(buf.as_str(), "EXT:360");
    }

    #[test]
    fn debug_named_constants() {
        let dbg = format_debug(ResidencyTag::INDONESIA);
        assert_eq!(dbg.as_str(), "ResidencyTag::INDONESIA");

        let dbg = format_debug(ResidencyTag::GLOBAL);
        assert_eq!(dbg.as_str(), "ResidencyTag::GLOBAL");
    }

    #[test]
    fn debug_unknown_code() {
        let tag = ResidencyTag::from_country_code(999).unwrap();
        let dbg = format_debug(tag);
        assert_eq!(dbg.as_str(), "ResidencyTag(999)");
    }

    #[test]
    fn debug_extended() {
        let ext = ResidencyTag::from_be_bytes([0x81, 0x68]);
        let dbg = format_debug(ext);
        assert_eq!(dbg.as_str(), "ResidencyTag::Extended(360)");
    }

    // ── Test helpers (no alloc needed) ───────────────────

    fn heapless_fmt(tag: ResidencyTag) -> FmtBuf {
        let mut buf = FmtBuf::new();
        core::fmt::Write::write_fmt(&mut buf, format_args!("{tag}")).unwrap();
        buf
    }

    fn format_debug(tag: ResidencyTag) -> FmtBuf {
        let mut buf = FmtBuf::new();
        core::fmt::Write::write_fmt(&mut buf, format_args!("{tag:?}")).unwrap();
        buf
    }

    /// Tiny fixed-size string buffer for no_std-compatible formatting tests.
    struct FmtBuf {
        buf: [u8; 64],
        len: usize,
    }

    impl FmtBuf {
        fn new() -> Self {
            FmtBuf {
                buf: [0; 64],
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
}
