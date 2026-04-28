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

/// Zone registry with ISO 3166-1 country codes and metadata.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct ZoneInfo {
    /// ISO 3166-1 numeric country code
    pub country_code: u16,
    /// ISO 3166-1 alpha-2 code (e.g., "ID")
    pub alpha2: &'static str,
    /// ISO 3166-1 alpha-3 code (e.g., "IDN")
    pub alpha3: &'static str,
    /// Full country name
    pub name: &'static str,
    /// Whether this zone has data residency regulations
    pub has_residency_laws: bool,
    /// Data protection regulation names (if any)
    pub regulations: &'static [&'static str],
}

/// Comprehensive zone registry for ISO 3166-1 countries.
#[cfg(feature = "zone-registry")]
pub static ZONE_REGISTRY: once_cell::sync::Lazy<alloc::collections::BTreeMap<u16, ZoneInfo>> =
    once_cell::sync::Lazy::new(|| {
        let mut registry = alloc::collections::BTreeMap::new();

        // Southeast Asian countries with data residency laws
        registry.insert(
            360,
            ZoneInfo {
                country_code: 360,
                alpha2: "ID",
                alpha3: "IDN",
                name: "Indonesia",
                has_residency_laws: true,
                regulations: &["PP 71/2019", "GR 82/2012"],
            },
        );

        registry.insert(
            458,
            ZoneInfo {
                country_code: 458,
                alpha2: "MY",
                alpha3: "MYS",
                name: "Malaysia",
                has_residency_laws: true,
                regulations: &["PDPA 2010"],
            },
        );

        registry.insert(
            608,
            ZoneInfo {
                country_code: 608,
                alpha2: "PH",
                alpha3: "PHL",
                name: "Philippines",
                has_residency_laws: true,
                regulations: &["Data Privacy Act 2012"],
            },
        );

        registry.insert(
            704,
            ZoneInfo {
                country_code: 704,
                alpha2: "VN",
                alpha3: "VNM",
                name: "Vietnam",
                has_residency_laws: true,
                regulations: &["Cybersecurity Law 2018"],
            },
        );

        registry.insert(
            702,
            ZoneInfo {
                country_code: 702,
                alpha2: "SG",
                alpha3: "SGP",
                name: "Singapore",
                has_residency_laws: true,
                regulations: &["PDPA 2012"],
            },
        );

        // Other major countries
        registry.insert(
            840,
            ZoneInfo {
                country_code: 840,
                alpha2: "US",
                alpha3: "USA",
                name: "United States",
                has_residency_laws: false,
                regulations: &[],
            },
        );

        registry.insert(
            826,
            ZoneInfo {
                country_code: 826,
                alpha2: "GB",
                alpha3: "GBR",
                name: "United Kingdom",
                has_residency_laws: true,
                regulations: &["UK GDPR"],
            },
        );

        registry.insert(
            276,
            ZoneInfo {
                country_code: 276,
                alpha2: "DE",
                alpha3: "DEU",
                name: "Germany",
                has_residency_laws: true,
                regulations: &["GDPR"],
            },
        );

        registry.insert(
            250,
            ZoneInfo {
                country_code: 250,
                alpha2: "FR",
                alpha3: "FRA",
                name: "France",
                has_residency_laws: true,
                regulations: &["GDPR"],
            },
        );

        registry.insert(
            380,
            ZoneInfo {
                country_code: 380,
                alpha2: "IT",
                alpha3: "ITA",
                name: "Italy",
                has_residency_laws: true,
                regulations: &["GDPR"],
            },
        );

        registry.insert(
            124,
            ZoneInfo {
                country_code: 124,
                alpha2: "CA",
                alpha3: "CAN",
                name: "Canada",
                has_residency_laws: true,
                regulations: &["PIPEDA", "PIPEDA Alberta"],
            },
        );

        registry.insert(
            36,
            ZoneInfo {
                country_code: 36,
                alpha2: "AU",
                alpha3: "AUS",
                name: "Australia",
                has_residency_laws: true,
                regulations: &["Privacy Act 1988"],
            },
        );

        registry.insert(
            392,
            ZoneInfo {
                country_code: 392,
                alpha2: "JP",
                alpha3: "JPN",
                name: "Japan",
                has_residency_laws: true,
                regulations: &["APPI 2017"],
            },
        );

        registry.insert(
            410,
            ZoneInfo {
                country_code: 410,
                alpha2: "KR",
                alpha3: "KOR",
                name: "South Korea",
                has_residency_laws: true,
                regulations: &["PIPA"],
            },
        );

        registry.insert(
            156,
            ZoneInfo {
                country_code: 156,
                alpha2: "CN",
                alpha3: "CHN",
                name: "China",
                has_residency_laws: true,
                regulations: &["Cybersecurity Law", "Data Security Law"],
            },
        );

        registry.insert(
            356,
            ZoneInfo {
                country_code: 356,
                alpha2: "IN",
                alpha3: "IND",
                name: "India",
                has_residency_laws: true,
                regulations: &["Data Protection Bill 2023"],
            },
        );

        registry
    });

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

    /// Create a residency tag from an ISO 3166-1 numeric country code.
    ///
    /// Returns `None` if the code exceeds 14 bits (> 16383), which would
    /// collide with the extension flag. In practice, ISO 3166-1 numeric
    /// codes are 0-999, so this is generous.
    pub const fn from_country_code(code: u16) -> Option<ResidencyTag> {
        // Check extension bit and ensure value fits in 14 bits
        if code & Self::EXTENSION_BIT != 0 || code > 0x7FFF {
            None
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
    ///
    /// For extended zones (subdivisions), the country code is stored in bits 6-19,
    /// so we need to shift right by 6 bits after masking out the extension flag.
    pub const fn country_code(self) -> u16 {
        if self.is_extended() {
            // For extended zones, country code is shifted right by 6 bits
            (self.0 & !Self::EXTENSION_BIT) >> 6
        } else {
            self.0
        }
    }

    /// Whether this is the unrestricted global zone.
    pub const fn is_global(self) -> bool {
        self.0 == 0
    }

    /// Get zone information from the registry.
    #[cfg(feature = "zone-registry")]
    pub fn zone_info(self) -> Option<&'static ZoneInfo> {
        ZONE_REGISTRY.get(&self.country_code())
    }

    /// Check if this zone has data residency regulations.
    #[cfg(feature = "zone-registry")]
    pub fn has_residency_laws(self) -> bool {
        self.zone_info()
            .map(|info| info.has_residency_laws)
            .unwrap_or(false)
    }

    /// Get the regulations for this zone.
    #[cfg(feature = "zone-registry")]
    pub fn regulations(self) -> &'static [&'static str] {
        self.zone_info().map(|info| info.regulations).unwrap_or(&[])
    }

    /// Get the country name for this zone.
    #[cfg(feature = "zone-registry")]
    pub fn country_name(self) -> Option<&'static str> {
        self.zone_info().map(|info| info.name)
    }

    /// Get the alpha-2 country code for this zone.
    #[cfg(feature = "zone-registry")]
    pub fn alpha2(self) -> Option<&'static str> {
        self.zone_info().map(|info| info.alpha2)
    }

    /// Get the alpha-3 country code for this zone.
    #[cfg(feature = "zone-registry")]
    pub fn alpha3(self) -> Option<&'static str> {
        self.zone_info().map(|info| info.alpha3)
    }

    /// Create a subdivision tag.
    ///
    /// The format is: 0x8000 | (country_code << 6) | subdivision_id
    /// where subdivision_id is 0-63 (6 bits for ISO 3166-2)
    ///
    /// Returns None if country_code exceeds the maximum value (511) that can
    /// be encoded in the 14-bit space available for subdivisions.
    ///
    /// Note: subdivision_id values greater than 63 will be silently masked/wrapped
    /// to fit in 6 bits (e.g., 64 becomes 0, 127 becomes 63).
    pub const fn from_subdivision(country_code: u16, subdivision_id: u8) -> Option<ResidencyTag> {
        // Validate country code fits in 14 bits after shift
        if country_code > 511 {
            return None;
        }
        let country_part = (country_code & 0x3FFF) << 6; // 14 bits for country
        let subdivision_part = (subdivision_id & 0x3F) as u16; // 6 bits for subdivision (wraps if > 63)
        Some(ResidencyTag(
            Self::EXTENSION_BIT | country_part | subdivision_part,
        ))
    }

    /// Extract the subdivision ID from an extended tag.
    ///
    /// Returns None if this is not an extended tag.
    /// Note: subdivision_id == Some(0) is a valid (though possibly unused) subdivision.
    pub const fn subdivision_id(self) -> Option<u8> {
        if self.is_extended() {
            Some((self.0 & 0x3F) as u8)
        } else {
            None
        }
    }

    /// Check if this tag is compatible with another zone.
    ///
    /// Two zones are compatible if:
    /// - Either is global
    /// - Both are the same country
    /// - The source zone allows data to flow to the destination zone
    pub fn compatible_with(self, other: ResidencyTag) -> bool {
        self.is_global() || other.is_global() || self.country_code() == other.country_code()
    }

    /// Check if a destination zone is compatible with this tag.
    ///
    /// - `Global` data can go anywhere.
    /// - Country-level data can only go to the same country (conservative approach).
    ///
    /// This is a simplified check. The full routing policy (multi-zone
    /// allowlists, cross-border agreements) lives in the ZCP routing layer.
    pub const fn allows_destination(self, dest: ResidencyTag) -> bool {
        if self.is_global() {
            true
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
                if let Some(sub_id) = tag.subdivision_id() {
                    write!(
                        f,
                        "ResidencyTag::Extended({}, {})",
                        tag.country_code(),
                        sub_id
                    )
                } else {
                    write!(f, "ResidencyTag::Extended({})", tag.country_code())
                }
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
            if let Some(sub_id) = self.subdivision_id() {
                write!(f, "EXT:{}-{}", self.country_code(), sub_id)
            } else {
                write!(f, "EXT:{}", self.country_code())
            }
        } else {
            write!(f, "{:03}", self.raw())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "alloc")]
    use alloc::{format, string::ToString, vec};

    #[test]
    fn be_bytes_roundtrip() {
        assert_eq!(
            ResidencyTag::from_be_bytes([0x01, 0x68]),
            ResidencyTag::INDONESIA
        );
        assert_eq!(ResidencyTag::INDONESIA.to_be_bytes(), [0x01, 0x68]);
    }

    #[test]
    fn constant_values_match_iso3166() {
        assert_eq!(ResidencyTag::INDONESIA.raw(), 360);
        assert_eq!(ResidencyTag::MALAYSIA.raw(), 458);
        assert_eq!(ResidencyTag::PHILIPPINES.raw(), 608);
        assert_eq!(ResidencyTag::VIETNAM.raw(), 704);
        assert_eq!(ResidencyTag::SINGAPORE.raw(), 702);
    }

    #[cfg(feature = "zone-registry")]
    #[test]
    fn test_zone_registry_lookup() {
        let indonesia = ResidencyTag::INDONESIA;
        let zone_info = indonesia.zone_info().unwrap();

        assert_eq!(zone_info.country_code, 360);
        assert_eq!(zone_info.alpha2, "ID");
        assert_eq!(zone_info.alpha3, "IDN");
        assert_eq!(zone_info.name, "Indonesia");
        assert!(zone_info.has_residency_laws);
        assert!(!zone_info.regulations.is_empty());
    }

    #[cfg(feature = "zone-registry")]
    #[test]
    fn test_zone_info_methods() {
        let indonesia = ResidencyTag::INDONESIA;
        let global = ResidencyTag::GLOBAL;

        assert_eq!(indonesia.country_name(), Some("Indonesia"));
        assert_eq!(indonesia.alpha2(), Some("ID"));
        assert_eq!(indonesia.alpha3(), Some("IDN"));
        assert!(indonesia.has_residency_laws());
        assert!(!indonesia.regulations().is_empty());

        assert_eq!(global.country_name(), None);
        assert_eq!(global.alpha2(), None);
        assert_eq!(global.alpha3(), None);
        assert!(!global.has_residency_laws());
        assert!(global.regulations().is_empty());
    }

    #[cfg(feature = "zone-registry")]
    #[test]
    fn test_unknown_zone() {
        let unknown = ResidencyTag(999); // Non-existent country code
        assert!(unknown.zone_info().is_none());
        assert!(unknown.country_name().is_none());
        assert!(unknown.alpha2().is_none());
        assert!(unknown.alpha3().is_none());
        assert!(!unknown.has_residency_laws());
        assert!(unknown.regulations().is_empty());
    }

    #[test]
    fn test_subdivision_creation() {
        let subdivision = ResidencyTag::from_subdivision(360, 1).unwrap(); // Indonesia, subdivision 1
        assert!(subdivision.is_extended());
        assert_eq!(subdivision.subdivision_id(), Some(1));
        assert_eq!(subdivision.country_code(), 360);
        assert_eq!(subdivision.raw(), 0x8000 | (360 << 6) | 1);
    }

    #[test]
    fn test_subdivision_extraction() {
        let subdivision = ResidencyTag::from_subdivision(458, 5).unwrap(); // Malaysia, subdivision 5
        assert_eq!(subdivision.subdivision_id(), Some(5));

        let country = ResidencyTag::MALAYSIA;
        assert_eq!(country.subdivision_id(), None);
    }

    #[test]
    fn test_extension_bit() {
        let country = ResidencyTag::INDONESIA;
        let subdivision = ResidencyTag::from_subdivision(360, 1).unwrap();

        assert!(!country.is_extended());
        assert!(subdivision.is_extended());

        // Extension bit should be 0x8000
        assert_eq!(subdivision.raw() & 0x8000, 0x8000);
        assert_eq!(country.raw() & 0x8000, 0);
    }

    #[cfg(feature = "zone-registry")]
    #[test]
    fn test_residency_laws_detection() {
        // Countries with residency laws
        assert!(ResidencyTag::INDONESIA.has_residency_laws());
        assert!(ResidencyTag::MALAYSIA.has_residency_laws());
        assert!(ResidencyTag::PHILIPPINES.has_residency_laws());
        assert!(ResidencyTag::VIETNAM.has_residency_laws());
        assert!(ResidencyTag::SINGAPORE.has_residency_laws());

        // Countries without specific residency laws (in our simplified model)
        assert!(!ResidencyTag::from_be_bytes([0x03, 0x48]).has_residency_laws());
        // USA (840)
    }

    #[cfg(feature = "zone-registry")]
    #[test]
    fn test_regulations_content() {
        let indonesia = ResidencyTag::INDONESIA;
        let regulations = indonesia.regulations();

        assert!(!regulations.is_empty());
        assert!(regulations.contains(&"PP 71/2019"));
        assert!(regulations.contains(&"GR 82/2012"));
    }

    #[test]
    fn test_country_code_extraction() {
        let country = ResidencyTag::INDONESIA;
        let subdivision = ResidencyTag::from_subdivision(360, 2).unwrap();

        assert_eq!(country.country_code(), 360);
        assert_eq!(subdivision.country_code(), 360); // Should ignore extension bit
    }

    #[test]
    fn test_display_formatting() {
        #[cfg(feature = "alloc")]
        {
            assert_eq!(ResidencyTag::GLOBAL.to_string(), "GLOBAL");
            assert_eq!(ResidencyTag::INDONESIA.to_string(), "360");

            let subdivision = ResidencyTag::from_subdivision(360, 1).unwrap();
            assert_eq!(subdivision.to_string(), "EXT:360-1");
        }
    }

    #[test]
    fn test_edge_cases() {
        // Test zero value (Global)
        assert_eq!(
            ResidencyTag::from_be_bytes([0x00, 0x00]),
            ResidencyTag::GLOBAL
        );

        // Test maximum valid country code (without extension bit)
        let max_country = ResidencyTag::from_be_bytes([0x3F, 0xFF]); // 16383
        assert_eq!(max_country.country_code(), 16383);
        assert!(!max_country.is_extended());

        // Test subdivision boundaries
        let max_subdivision = ResidencyTag::from_subdivision(0, 63).unwrap(); // Max subdivision ID
        assert_eq!(max_subdivision.subdivision_id(), Some(63));

        // Test subdivision ID overflow (should wrap to 6 bits)
        let overflow_subdivision = ResidencyTag::from_subdivision(360, 128).unwrap(); // 128 > 63
        assert_eq!(overflow_subdivision.subdivision_id(), Some(0)); // Should wrap to 0
    }

    #[cfg(feature = "zone-registry")]
    #[test]
    fn test_zone_registry_completeness() {
        // Test that all our constants exist in the registry
        let constants = vec![
            (ResidencyTag::INDONESIA, "Indonesia"),
            (ResidencyTag::MALAYSIA, "Malaysia"),
            (ResidencyTag::PHILIPPINES, "Philippines"),
            (ResidencyTag::VIETNAM, "Vietnam"),
            (ResidencyTag::SINGAPORE, "Singapore"),
        ];

        for (tag, expected_name) in constants {
            let zone_info = tag.zone_info();
            assert!(zone_info.is_some(), "Zone info missing for {:?}", tag);
            assert_eq!(zone_info.unwrap().name, expected_name);
        }
    }

    #[cfg(feature = "zone-registry")]
    #[test]
    fn test_zone_registry_se_asia_focus() {
        // Test Southeast Asian countries specifically
        let sea_countries = vec![
            ResidencyTag::INDONESIA,
            ResidencyTag::MALAYSIA,
            ResidencyTag::PHILIPPINES,
            ResidencyTag::VIETNAM,
            ResidencyTag::SINGAPORE,
        ];

        for country in sea_countries {
            let zone_info = country.zone_info().unwrap();
            assert!(
                zone_info.has_residency_laws,
                "SEA country {} should have residency laws",
                zone_info.name
            );
            assert!(
                !zone_info.regulations.is_empty(),
                "SEA country {} should have regulations",
                zone_info.name
            );
        }
    }

    // ── Construction ─────────────────────────────────────

    #[test]
    fn from_country_code_valid() {
        let tag = ResidencyTag::from_country_code(360).unwrap();
        assert_eq!(tag, ResidencyTag::INDONESIA);
    }

    #[test]
    fn test_edge_cases_and_error_handling() {
        // Test with maximum values
        let max_country = ResidencyTag::from_be_bytes([0x3F, 0xFF]);
        assert_eq!(max_country.country_code(), 16383);
        assert!(!max_country.is_extended());

        // Test with extension bit set to maximum valid country code
        let max_extended = ResidencyTag::from_subdivision(511, 63).unwrap();
        assert!(max_extended.is_extended());
        assert_eq!(max_extended.country_code(), 511);
        assert_eq!(max_extended.subdivision_id(), Some(63));

        // Test boundary conditions
        assert_eq!(
            ResidencyTag::from_be_bytes([0x00, 0x00]),
            ResidencyTag::GLOBAL
        );
        assert_eq!(ResidencyTag::from_be_bytes([0x80, 0x00]).country_code(), 0); // Extended global
        assert_eq!(
            ResidencyTag::from_be_bytes([0x80, 0x00]).subdivision_id(),
            Some(0)
        );

        // Test invalid country codes
        assert!(ResidencyTag::from_country_code(0x8000).is_none()); // Extension bit set
        assert!(ResidencyTag::from_country_code(0xFFFF).is_none()); // Extension bit set
    }

    #[test]
    fn test_bit_manipulation_edge_cases() {
        // Test that subdivision preserves country code
        let country = ResidencyTag::from_be_bytes([0x01, 0x68]); // Indonesia
        let extended = ResidencyTag::from_subdivision(360, 1).unwrap(); // Indonesia subdivision

        assert_eq!(country.country_code(), extended.country_code());
        assert!(!country.is_extended());
        assert!(extended.is_extended());

        // Test that subdivision ID is correctly masked
        let subdivision1 = ResidencyTag::from_subdivision(0, 0).unwrap(); // subdivision 0 of global
        let subdivision63 = ResidencyTag::from_subdivision(0, 63).unwrap(); // subdivision 63 of global

        assert_eq!(subdivision1.subdivision_id(), Some(0));
        assert_eq!(subdivision63.subdivision_id(), Some(63));
    }

    #[test]
    fn test_compatibility_edge_cases() {
        // Test global compatibility
        assert!(ResidencyTag::GLOBAL.compatible_with(ResidencyTag::INDONESIA));
        assert!(ResidencyTag::INDONESIA.compatible_with(ResidencyTag::GLOBAL));
        assert!(ResidencyTag::GLOBAL.compatible_with(ResidencyTag::GLOBAL));

        // Test same zone compatibility
        assert!(ResidencyTag::INDONESIA.compatible_with(ResidencyTag::INDONESIA));
        assert!(ResidencyTag::MALAYSIA.compatible_with(ResidencyTag::MALAYSIA));

        // Test different zone incompatibility
        assert!(!ResidencyTag::INDONESIA.compatible_with(ResidencyTag::MALAYSIA));
        assert!(!ResidencyTag::MALAYSIA.compatible_with(ResidencyTag::VIETNAM));

        // Test extended zone compatibility
        let subdivision = ResidencyTag::from_subdivision(360, 1).unwrap();
        assert!(subdivision.compatible_with(ResidencyTag::INDONESIA)); // Same country
        assert!(!subdivision.compatible_with(ResidencyTag::MALAYSIA)); // Different country
        assert!(ResidencyTag::INDONESIA.compatible_with(subdivision)); // Reverse should also work
    }

    #[test]
    fn test_allows_destination_edge_cases() {
        // Global should allow any destination
        assert!(ResidencyTag::GLOBAL.allows_destination(ResidencyTag::INDONESIA));
        assert!(ResidencyTag::GLOBAL.allows_destination(ResidencyTag::MALAYSIA));
        assert!(ResidencyTag::GLOBAL.allows_destination(ResidencyTag::GLOBAL));

        // Country should only allow same country (conservative)
        assert!(ResidencyTag::INDONESIA.allows_destination(ResidencyTag::INDONESIA));
        assert!(!ResidencyTag::INDONESIA.allows_destination(ResidencyTag::MALAYSIA));
        assert!(!ResidencyTag::INDONESIA.allows_destination(ResidencyTag::GLOBAL)); // Conservative

        // Extended zones should follow same rules as their country
        let subdivision = ResidencyTag::from_subdivision(360, 1).unwrap();
        assert_eq!(subdivision.country_code(), 360);
        assert_eq!(ResidencyTag::INDONESIA.country_code(), 360);
        assert!(subdivision.allows_destination(ResidencyTag::INDONESIA));
        assert!(!subdivision.allows_destination(ResidencyTag::MALAYSIA));
        assert!(!subdivision.allows_destination(ResidencyTag::GLOBAL));
    }

    #[test]
    fn test_zone_registry_error_handling() {
        #[cfg(feature = "zone-registry")]
        {
            // Test with non-existent country codes
            let unknown1 = ResidencyTag(9999);
            let unknown2 = ResidencyTag(16383); // Maximum valid but probably not in registry

            assert_eq!(unknown1.zone_info(), None);
            assert_eq!(unknown1.country_name(), None);
            assert_eq!(unknown1.alpha2(), None);
            assert_eq!(unknown1.alpha3(), None);
            assert!(!unknown1.has_residency_laws());
            assert!(unknown1.regulations().is_empty());

            // Even if the country code is valid, if it's not in registry it should return None
            assert_eq!(unknown2.zone_info(), None);
        }
    }

    #[test]
    fn test_display_edge_cases() {
        #[cfg(feature = "alloc")]
        {
            // Test global display
            assert_eq!(ResidencyTag::GLOBAL.to_string(), "GLOBAL");

            // Test country display - plain numeric code format
            assert_eq!(ResidencyTag::INDONESIA.to_string(), "360");
            assert_eq!(ResidencyTag::MALAYSIA.to_string(), "458");

            // Test extended display - uses EXT:code-sub format
            let subdivision = ResidencyTag::from_subdivision(360, 1).unwrap();
            assert_eq!(subdivision.to_string(), "EXT:360-1");

            let subdivision63 = ResidencyTag::from_subdivision(458, 63).unwrap();
            assert_eq!(subdivision63.to_string(), "EXT:458-63");

            // Test edge case: extended with subdivision 0
            let subdivision0 = ResidencyTag::from_subdivision(360, 0).unwrap();
            assert_eq!(subdivision0.to_string(), "EXT:360-0");
        }
    }

    #[test]
    fn test_debug_edge_cases() {
        #[cfg(feature = "alloc")]
        {
            let debug_global = format!("{:?}", ResidencyTag::GLOBAL);
            let debug_indonesia = format!("{:?}", ResidencyTag::INDONESIA);
            let debug_unknown = format!("{:?}", ResidencyTag(9999));

            assert!(debug_global.contains("GLOBAL"));
            assert!(debug_indonesia.contains("INDONESIA"));
            assert!(debug_unknown.contains("9999"));
        }
    }

    #[test]
    fn test_from_subdivision_edge_cases() {
        // Test subdivision ID boundaries
        let subdivision0 = ResidencyTag::from_subdivision(360, 0).unwrap();
        let subdivision63 = ResidencyTag::from_subdivision(360, 63).unwrap();

        assert_eq!(subdivision0.subdivision_id(), Some(0));
        assert_eq!(subdivision63.subdivision_id(), Some(63));

        // Test subdivision ID overflow (should wrap)
        let subdivision64 = ResidencyTag::from_subdivision(360, 64).unwrap();
        let subdivision127 = ResidencyTag::from_subdivision(360, 127).unwrap();

        assert_eq!(subdivision64.subdivision_id(), Some(0)); // 64 % 64 = 0
        assert_eq!(subdivision127.subdivision_id(), Some(63)); // 127 % 64 = 63

        // Test with maximum valid country code for subdivision (limited by bit space)
        let max_country_subdivision = ResidencyTag::from_subdivision(511, 31).unwrap();
        assert_eq!(max_country_subdivision.country_code(), 511);
        assert_eq!(max_country_subdivision.subdivision_id(), Some(31));

        // Test with country code 0 (global)
        let global_subdivision = ResidencyTag::from_subdivision(0, 15).unwrap();
        assert_eq!(global_subdivision.country_code(), 0);
        assert_eq!(global_subdivision.subdivision_id(), Some(15));
        assert!(global_subdivision.is_extended());

        // Test invalid country code (too large for subdivision)
        assert!(ResidencyTag::from_subdivision(512, 0).is_none()); // Country code too large
    }

    #[test]
    fn test_constant_values_edge_cases() {
        // Verify all constants have correct values
        assert_eq!(ResidencyTag::GLOBAL.raw(), 0);
        assert_eq!(ResidencyTag::INDONESIA.raw(), 360);
        assert_eq!(ResidencyTag::MALAYSIA.raw(), 458);
        assert_eq!(ResidencyTag::PHILIPPINES.raw(), 608);
        assert_eq!(ResidencyTag::VIETNAM.raw(), 704);
        assert_eq!(ResidencyTag::SINGAPORE.raw(), 702);

        // Verify none have extension bit set
        assert!(!ResidencyTag::GLOBAL.is_extended());
        assert!(!ResidencyTag::INDONESIA.is_extended());
        assert!(!ResidencyTag::MALAYSIA.is_extended());
        assert!(!ResidencyTag::PHILIPPINES.is_extended());
        assert!(!ResidencyTag::VIETNAM.is_extended());
        assert!(!ResidencyTag::SINGAPORE.is_extended());

        // Verify country code extraction works for all
        assert_eq!(ResidencyTag::GLOBAL.country_code(), 0);
        assert_eq!(ResidencyTag::INDONESIA.country_code(), 360);
        assert_eq!(ResidencyTag::MALAYSIA.country_code(), 458);
        assert_eq!(ResidencyTag::PHILIPPINES.country_code(), 608);
        assert_eq!(ResidencyTag::VIETNAM.country_code(), 704);
        assert_eq!(ResidencyTag::SINGAPORE.country_code(), 702);
    }

    #[test]
    fn test_byte_conversion_edge_cases() {
        // Test round-trip conversion for all constants
        #[cfg(feature = "alloc")]
        {
            let constants = vec![
                ResidencyTag::GLOBAL,
                ResidencyTag::INDONESIA,
                ResidencyTag::MALAYSIA,
                ResidencyTag::PHILIPPINES,
                ResidencyTag::VIETNAM,
                ResidencyTag::SINGAPORE,
            ];

            for constant in constants {
                let bytes: [u8; 2] = (constant as ResidencyTag).to_be_bytes();
                let reconstructed = ResidencyTag::from_be_bytes(bytes);
                assert_eq!(constant, reconstructed);
            }

            // Test round-trip for extended zones
            let subdivisions = vec![
                ResidencyTag::from_subdivision(360, 0).unwrap(),
                ResidencyTag::from_subdivision(360, 31).unwrap(),
                ResidencyTag::from_subdivision(360, 63).unwrap(),
                ResidencyTag::from_subdivision(458, 15).unwrap(),
            ];

            for subdivision in subdivisions {
                let bytes: [u8; 2] = (subdivision as ResidencyTag).to_be_bytes();
                let reconstructed = ResidencyTag::from_be_bytes(bytes);
                assert_eq!(subdivision, reconstructed);
            }
        }
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
    fn be_bytes_roundtrip_extended() {
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
        // Test with a proper subdivision encoding
        let subdivision = ResidencyTag::from_subdivision(360, 1).unwrap();
        assert!(subdivision.is_extended());
        assert_eq!(subdivision.country_code(), 360); // Indonesia code preserved
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
        let ext = ResidencyTag::from_subdivision(360, 1).unwrap();
        buf = heapless_fmt(ext);
        assert_eq!(buf.as_str(), "EXT:360-1");
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
        let ext = ResidencyTag::from_subdivision(360, 1).unwrap();
        let dbg = format_debug(ext);
        assert_eq!(dbg.as_str(), "ResidencyTag::Extended(360, 1)");
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
