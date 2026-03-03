//! Protocol version identifier.
//!
//! ZCP uses a single-byte version field. `clonic 0.x` and `1.x` always
//! produce and consume `V1` (0x01) envelopes. New wire versions will be
//! introduced via new major crate versions.

/// Known ZCP protocol versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum Version {
    /// ZCP v1 — initial protocol version.
    V1 = 0x01,
}

impl Version {
    /// The current (and only) protocol version produced by this crate.
    pub const CURRENT: Version = Version::V1;

    /// Try to interpret a raw byte as a known protocol version.
    pub const fn from_byte(b: u8) -> Option<Version> {
        match b {
            0x01 => Some(Version::V1),
            _ => None,
        }
    }

    /// Return the raw byte representation.
    pub const fn as_byte(self) -> u8 {
        self as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_is_v1() {
        assert_eq!(Version::CURRENT, Version::V1);
        assert_eq!(Version::CURRENT.as_byte(), 0x01);
    }

    #[test]
    fn from_byte_known() {
        assert_eq!(Version::from_byte(0x01), Some(Version::V1));
    }

    #[test]
    fn from_byte_unknown() {
        assert_eq!(Version::from_byte(0x00), None);
        assert_eq!(Version::from_byte(0x02), None);
        assert_eq!(Version::from_byte(0xFF), None);
    }

    #[test]
    fn roundtrip_all_variants() {
        let versions = [Version::V1];
        for v in versions {
            assert_eq!(Version::from_byte(v.as_byte()), Some(v));
        }
    }

    #[test]
    fn byte_stability() {
        // Wire format contract: these bytes must never change
        assert_eq!(Version::V1.as_byte(), 0x01);
    }
}
