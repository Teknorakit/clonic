//! Tests for clonic-core encode/decode roundtrip and validation.
//!
//! Run with: `cargo test --features alloc`
//! Proptest: `cargo test --features alloc -- --include-ignored`

#[cfg(feature = "alloc")]
mod tests {
    extern crate alloc;

    use clonic_core::decode::peek_frame_length;
    use clonic_core::encode::{encode_to_slice, EnvelopeFields};
    use clonic_core::envelope::{HEADER_SIZE, MAC_SIZE, MIN_FRAME_SIZE};
    use clonic_core::*;

    // ── Helpers ──────────────────────────────────────────

    fn test_device_id() -> [u8; 32] {
        let mut id = [0u8; 32];
        for (i, b) in id.iter_mut().enumerate() {
            *b = i as u8;
        }
        id
    }

    fn test_mac() -> [u8; 16] {
        [0xAA; 16]
    }

    // ── Basic roundtrip ──────────────────────────────────

    #[test]
    fn roundtrip_empty_payload() {
        let env = Envelope::new(
            MsgType::TaskRoute,
            CryptoSuite::PqHybrid,
            test_device_id(),
            ResidencyTag::INDONESIA,
            alloc::vec![],
            test_mac(),
        );

        let bytes = env.to_bytes();
        assert_eq!(bytes.len(), MIN_FRAME_SIZE);

        let parsed = Envelope::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, env);
    }

    #[test]
    fn roundtrip_with_payload() {
        let payload = alloc::vec![0x42; 256];
        let env = Envelope::new(
            MsgType::SyncCrdt,
            CryptoSuite::Classical,
            test_device_id(),
            ResidencyTag::GLOBAL,
            payload.clone(),
            test_mac(),
        );

        let bytes = env.to_bytes();
        assert_eq!(bytes.len(), HEADER_SIZE + 256 + MAC_SIZE);

        let parsed = Envelope::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.payload, payload);
        assert_eq!(parsed.msg_type, MsgType::SyncCrdt);
        assert_eq!(parsed.crypto_suite, CryptoSuite::Classical);
        assert_eq!(parsed.residency_tag, ResidencyTag::GLOBAL);
    }

    #[test]
    fn roundtrip_with_flags() {
        let env = Envelope::new(
            MsgType::DeviceOrch,
            CryptoSuite::PqHybrid,
            test_device_id(),
            ResidencyTag::INDONESIA,
            alloc::vec![1, 2, 3],
            test_mac(),
        )
        .with_flags(Flags::from_byte(Flags::COMPRESSED | Flags::FRAGMENTED));

        let bytes = env.to_bytes();
        let parsed = Envelope::from_bytes(&bytes).unwrap();
        assert!(parsed.flags.has(Flags::COMPRESSED));
        assert!(parsed.flags.has(Flags::FRAGMENTED));
    }

    // ── Zero-copy parsing ────────────────────────────────

    #[test]
    fn envelope_ref_accessors() {
        let env = Envelope::new(
            MsgType::ProvisionCert,
            CryptoSuite::PqHybrid,
            test_device_id(),
            ResidencyTag::INDONESIA,
            alloc::vec![0xDE, 0xAD],
            test_mac(),
        );
        let bytes = env.to_bytes();

        let r = EnvelopeRef::parse(&bytes).unwrap();
        assert_eq!(r.version(), Version::V1);
        assert_eq!(r.msg_type(), Some(MsgType::ProvisionCert));
        assert_eq!(r.crypto_suite(), CryptoSuite::PqHybrid);
        assert_eq!(r.residency_tag(), ResidencyTag::INDONESIA);
        assert_eq!(r.payload_length(), 2);
        assert_eq!(r.payload(), &[0xDE, 0xAD]);
        assert_eq!(r.mac(), &test_mac());
        assert_eq!(r.sender_device_id(), &test_device_id());
        assert_eq!(r.header_bytes().len(), HEADER_SIZE);
    }

    // ── Framing ──────────────────────────────────────────

    #[test]
    fn peek_frame_length_works() {
        let env = Envelope::new(
            MsgType::TaskRoute,
            CryptoSuite::Classical,
            test_device_id(),
            ResidencyTag::GLOBAL,
            alloc::vec![0u8; 1000],
            test_mac(),
        );
        let bytes = env.to_bytes();

        let (pl, total) = peek_frame_length(&bytes[..HEADER_SIZE]).unwrap();
        assert_eq!(pl, 1000);
        assert_eq!(total, HEADER_SIZE + 1000 + MAC_SIZE);
        assert_eq!(total, bytes.len());
    }

    // ── encode_to_slice ──────────────────────────────────

    #[test]
    fn encode_to_slice_works() {
        let dev_id = test_device_id();
        let mac = test_mac();
        let payload = [0x55u8; 10];

        let fields = EnvelopeFields {
            version: Version::CURRENT,
            msg_type: MsgType::GossipBroadcast,
            crypto_suite: CryptoSuite::Classical,
            flags: Flags::NONE,
            sender_device_id: &dev_id,
            residency_tag: ResidencyTag::INDONESIA,
            payload: &payload,
            mac: &mac,
        };

        let mut buf = [0u8; 256];
        let n = encode_to_slice(&fields, &mut buf).unwrap();
        assert_eq!(n, HEADER_SIZE + 10 + MAC_SIZE);

        let r = EnvelopeRef::parse(&buf[..n]).unwrap();
        assert_eq!(r.msg_type(), Some(MsgType::GossipBroadcast));
        assert_eq!(r.payload(), &payload);
    }

    #[test]
    fn encode_to_slice_buffer_too_short() {
        let dev_id = test_device_id();
        let mac = test_mac();
        let fields = EnvelopeFields {
            version: Version::CURRENT,
            msg_type: MsgType::TaskRoute,
            crypto_suite: CryptoSuite::PqHybrid,
            flags: Flags::NONE,
            sender_device_id: &dev_id,
            residency_tag: ResidencyTag::GLOBAL,
            payload: &[0u8; 100],
            mac: &mac,
        };

        let mut tiny = [0u8; 10];
        assert!(encode_to_slice(&fields, &mut tiny).is_err());
    }

    // ── Validation errors ────────────────────────────────

    #[test]
    fn reject_unknown_version() {
        let env = Envelope::new(
            MsgType::TaskRoute,
            CryptoSuite::PqHybrid,
            test_device_id(),
            ResidencyTag::GLOBAL,
            alloc::vec![],
            test_mac(),
        );
        let mut bytes = env.to_bytes();
        bytes[0] = 0xFF; // corrupt version

        assert!(matches!(
            EnvelopeRef::parse(&bytes),
            Err(Error::UnknownVersion(0xFF))
        ));
    }

    #[test]
    fn reject_unknown_msg_type_outside_ranges() {
        let env = Envelope::new(
            MsgType::TaskRoute,
            CryptoSuite::PqHybrid,
            test_device_id(),
            ResidencyTag::GLOBAL,
            alloc::vec![],
            test_mac(),
        );
        let mut bytes = env.to_bytes();
        bytes[1] = 0x80; // not in any allocated range

        assert!(matches!(
            EnvelopeRef::parse(&bytes),
            Err(Error::UnknownMsgType(0x80))
        ));
    }

    #[test]
    fn accept_unknown_msg_type_within_range() {
        // 0x04 is within Core range (0x01–0x0F) but not a defined variant
        let env = Envelope::new(
            MsgType::TaskRoute,
            CryptoSuite::PqHybrid,
            test_device_id(),
            ResidencyTag::GLOBAL,
            alloc::vec![],
            test_mac(),
        );
        let mut bytes = env.to_bytes();
        bytes[1] = 0x04; // unknown but in Core range

        let r = EnvelopeRef::parse(&bytes).unwrap();
        assert_eq!(r.msg_type(), None); // unknown variant
        assert_eq!(r.msg_type_raw(), 0x04);
    }

    #[test]
    fn reject_unknown_crypto_suite() {
        let env = Envelope::new(
            MsgType::TaskRoute,
            CryptoSuite::PqHybrid,
            test_device_id(),
            ResidencyTag::GLOBAL,
            alloc::vec![],
            test_mac(),
        );
        let mut bytes = env.to_bytes();
        bytes[2] = 0xFF; // unknown suite

        assert!(matches!(
            EnvelopeRef::parse(&bytes),
            Err(Error::UnknownCryptoSuite(0xFF))
        ));
    }

    #[test]
    fn reject_truncated_frame() {
        let env = Envelope::new(
            MsgType::TaskRoute,
            CryptoSuite::PqHybrid,
            test_device_id(),
            ResidencyTag::GLOBAL,
            alloc::vec![0u8; 100],
            test_mac(),
        );
        let bytes = env.to_bytes();

        // Truncate: give header + partial payload
        assert!(EnvelopeRef::parse(&bytes[..50]).is_err());
    }

    #[test]
    fn reject_trailing_bytes() {
        let env = Envelope::new(
            MsgType::TaskRoute,
            CryptoSuite::PqHybrid,
            test_device_id(),
            ResidencyTag::GLOBAL,
            alloc::vec![],
            test_mac(),
        );
        let mut bytes = env.to_bytes();
        bytes.push(0xFF); // trailing garbage

        assert!(matches!(
            EnvelopeRef::parse(&bytes),
            Err(Error::TrailingBytes { .. })
        ));
    }

    // ── Residency tag ────────────────────────────────────

    #[test]
    fn residency_tag_constants() {
        assert_eq!(ResidencyTag::INDONESIA.raw(), 360);
        assert_eq!(ResidencyTag::GLOBAL.raw(), 0);
        assert!(ResidencyTag::GLOBAL.is_global());
        assert!(!ResidencyTag::INDONESIA.is_global());
        assert!(!ResidencyTag::INDONESIA.is_extended());
    }

    #[test]
    fn residency_extension_bit() {
        // Manually set extension bit
        let tag = ResidencyTag::from_be_bytes(0x8168u16.to_be_bytes());
        assert!(tag.is_extended());
        assert_eq!(tag.country_code(), 360); // Indonesia
    }

    #[test]
    fn residency_allows_destination() {
        assert!(ResidencyTag::GLOBAL.allows_destination(ResidencyTag::INDONESIA));
        assert!(ResidencyTag::INDONESIA.allows_destination(ResidencyTag::INDONESIA));
        assert!(!ResidencyTag::INDONESIA.allows_destination(ResidencyTag::MALAYSIA));
        assert!(!ResidencyTag::INDONESIA.allows_destination(ResidencyTag::GLOBAL));
    }

    // ── Big-endian encoding ──────────────────────────────

    #[test]
    fn payload_length_is_big_endian() {
        let env = Envelope::new(
            MsgType::TaskRoute,
            CryptoSuite::PqHybrid,
            test_device_id(),
            ResidencyTag::GLOBAL,
            alloc::vec![0u8; 0x0100], // 256 bytes
            test_mac(),
        );
        let bytes = env.to_bytes();

        // payload_length at offset 38–41, big-endian
        assert_eq!(bytes[38], 0x00);
        assert_eq!(bytes[39], 0x00);
        assert_eq!(bytes[40], 0x01);
        assert_eq!(bytes[41], 0x00);
    }

    #[test]
    fn residency_tag_is_big_endian() {
        let env = Envelope::new(
            MsgType::TaskRoute,
            CryptoSuite::PqHybrid,
            test_device_id(),
            ResidencyTag::INDONESIA, // 360 = 0x0168
            alloc::vec![],
            test_mac(),
        );
        let bytes = env.to_bytes();

        // residency_tag at offset 36–37, big-endian
        assert_eq!(bytes[36], 0x01);
        assert_eq!(bytes[37], 0x68);
    }

    // ── MsgType ranges ───────────────────────────────────

    #[test]
    fn msg_type_ranges() {
        use clonic_core::msg_type::MsgRange;

        assert_eq!(MsgType::range_of(0x01), MsgRange::Core);
        assert_eq!(MsgType::range_of(0x0F), MsgRange::Core);
        assert_eq!(MsgType::range_of(0x10), MsgRange::Dht);
        assert_eq!(MsgType::range_of(0x20), MsgRange::Gossip);
        assert_eq!(MsgType::range_of(0x30), MsgRange::Provisioning);
        assert_eq!(MsgType::range_of(0x40), MsgRange::Heartbeat);
        assert_eq!(MsgType::range_of(0xF0), MsgRange::Vendor);
        assert_eq!(MsgType::range_of(0x80), MsgRange::Unknown);
    }
}

// ── Proptest roundtrip ───────────────────────────────────────────────

#[cfg(all(test, feature = "alloc"))]
mod proptest_roundtrip {
    extern crate alloc;

    use clonic_core::envelope::Flags;
    use clonic_core::msg_type::MsgType;
    use clonic_core::{CryptoSuite, Envelope, ResidencyTag, Version};
    use proptest::prelude::*;

    fn arb_msg_type() -> impl Strategy<Value = MsgType> {
        prop_oneof![
            Just(MsgType::TaskRoute),
            Just(MsgType::SyncCrdt),
            Just(MsgType::DeviceOrch),
            Just(MsgType::DhtFindNode),
            Just(MsgType::DhtGetValue),
            Just(MsgType::DhtPutValue),
            Just(MsgType::GossipBroadcast),
            Just(MsgType::GossipSubscribe),
            Just(MsgType::ProvisionRequest),
            Just(MsgType::ProvisionCert),
            Just(MsgType::ProvisionRevoke),
        ]
    }

    fn arb_crypto_suite() -> impl Strategy<Value = CryptoSuite> {
        prop_oneof![Just(CryptoSuite::PqHybrid), Just(CryptoSuite::Classical),]
    }

    fn arb_residency() -> impl Strategy<Value = ResidencyTag> {
        (0u16..999).prop_map(|code| ResidencyTag::from_country_code(code).unwrap())
    }

    proptest! {
        #[test]
        fn encode_decode_roundtrip(
            msg_type in arb_msg_type(),
            crypto_suite in arb_crypto_suite(),
            flags_byte in 0u8..=3, // only defined bits
            device_id in prop::array::uniform32(any::<u8>()),
            residency in arb_residency(),
            payload in prop::collection::vec(any::<u8>(), 0..4096),
            mac in prop::array::uniform16(any::<u8>()),
        ) {
            let env = Envelope::new(
                msg_type,
                crypto_suite,
                device_id,
                residency,
                payload.clone(),
                mac,
            ).with_flags(Flags::from_byte(flags_byte));

            let bytes = env.to_bytes();
            let parsed = Envelope::from_bytes(&bytes).unwrap();

            prop_assert_eq!(parsed.version, Version::V1);
            prop_assert_eq!(parsed.msg_type, msg_type);
            prop_assert_eq!(parsed.crypto_suite, crypto_suite);
            prop_assert_eq!(parsed.flags, Flags::from_byte(flags_byte));
            prop_assert_eq!(parsed.sender_device_id, device_id);
            prop_assert_eq!(parsed.residency_tag, residency);
            prop_assert_eq!(parsed.payload, payload);
            prop_assert_eq!(parsed.mac, mac);
        }
    }
}
