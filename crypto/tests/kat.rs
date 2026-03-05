//! Known-Answer Tests (KATs) for cryptographic primitives.
//!
//! Uses published test vectors from RFCs and NIST to validate correctness.

use clonic_crypto::{decrypt, encrypt};
use hkdf::Hkdf;
use sha3::Sha3_256;
use x25519_dalek::{PublicKey, StaticSecret};

#[test]
fn x25519_rfc7748_test_vector_1() {
    // RFC 7748 Section 6.1 - Test vector 1
    let scalar_bytes = hex::decode("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
        .unwrap();
    let basepoint_bytes =
        hex::decode("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c").unwrap();

    let scalar: [u8; 32] = scalar_bytes.try_into().unwrap();
    let basepoint: [u8; 32] = basepoint_bytes.try_into().unwrap();

    let secret = StaticSecret::from(scalar);
    let public = PublicKey::from(basepoint);
    let shared = secret.diffie_hellman(&public);

    let expected =
        hex::decode("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552").unwrap();
    assert_eq!(shared.as_bytes(), expected.as_slice());
}

#[test]
fn x25519_rfc7748_test_vector_2() {
    // RFC 7748 Section 6.1 - Test vector 2
    let scalar_bytes = hex::decode("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d")
        .unwrap();
    let basepoint_bytes =
        hex::decode("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493").unwrap();

    let scalar: [u8; 32] = scalar_bytes.try_into().unwrap();
    let basepoint: [u8; 32] = basepoint_bytes.try_into().unwrap();

    let secret = StaticSecret::from(scalar);
    let public = PublicKey::from(basepoint);
    let shared = secret.diffie_hellman(&public);

    let expected =
        hex::decode("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957").unwrap();
    assert_eq!(shared.as_bytes(), expected.as_slice());
}

#[test]
fn hkdf_sha3_256_test_vector() {
    // Test vector for HKDF-SHA3-256 with known inputs
    // Using RFC 5869 style test with SHA3-256
    let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
    let salt = hex::decode("000102030405060708090a0b0c").unwrap();
    let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();

    let hkdf = Hkdf::<Sha3_256>::new(Some(&salt), &ikm);
    let mut okm = [0u8; 42];
    hkdf.expand(&info, &mut okm).unwrap();

    // Expected output computed from this implementation (pinned for regression testing)
    let expected = [
        12, 81, 96, 80, 29, 101, 2, 29, 234, 242, 193, 79, 90, 188, 224, 76, 91, 210, 99,
        90, 188, 238, 186, 97, 194, 237, 182, 232, 237, 114, 103, 73, 0, 85, 119, 40, 242,
        201, 242, 196, 193, 121,
    ];
    assert_eq!(&okm[..], expected.as_slice());
}

#[test]
fn aes_256_gcm_nist_sp800_38d_vector() {
    // NIST SP 800-38D AES-256-GCM test vector (cross-implementation)
    // Key, IV, AAD, PT, CT, TAG from the specification (GCM-AES256 test case)
    let key = hex::decode(
        "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
    )
    .unwrap();
    let nonce = hex::decode("cafebabefacedbaddecaf888").unwrap();
    let aad = hex::decode("feedfacedeadbeeffeedfacedeadbeefabaddad2").unwrap();
    let plaintext = hex::decode(
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
         1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
    )
    .unwrap();
    // Expected is ciphertext || tag (matches SP800-38D test case values)
    let expected_ct = hex::decode(
        "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1a\
         a8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f66276fc6e\
         ce0f4e1768cddf8853bb2d551b",
    )
    .unwrap();

    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes256Gcm, Nonce};

    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
    let nonce_arr = Nonce::from_slice(&nonce);
    let ciphertext = cipher
        .encrypt(
            nonce_arr,
            Payload {
                msg: &plaintext,
                aad: &aad,
            },
        )
        .unwrap();

    assert_eq!(ciphertext, expected_ct);
}

#[test]
fn aes_256_gcm_with_hkdf_roundtrip() {
    // Test our encrypt/decrypt with HKDF-derived key
    let shared_secret = [0x42u8; 32];
    let nonce = hex::decode("cafabd9672ca6c79a2fbdc22").unwrap();
    let aad = b"additional-data";
    let plaintext = b"test-plaintext-for-aes-gcm";
    let context = b"ZCP-test-context";

    let ciphertext = encrypt(&shared_secret, &nonce, aad, plaintext, context).unwrap();
    let decrypted = decrypt(&shared_secret, &nonce, aad, &ciphertext, context).unwrap();

    assert_eq!(decrypted, plaintext);
}
