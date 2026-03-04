# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- CHANGELOG.md

## [0.1.2] - 2026-03-02

### Fixed
- docs.rs build: added explicit `targets = ["x86_64-unknown-linux-gnu"]` to resolve no_std build failures

## [0.1.1] - 2026-03-02

### Added
- Comprehensive README.md with usage examples and design rationale
- Updated lib.rs documentation with feature flags and consumer matrix
- Unit tests for crypto_suite module (4 tests)
- Feature-gated alloc tests in encode module

## [0.1.0] - 2026-03-02

Initial public release of the Zone Coordination Protocol (ZCP) wire codec.

### Added
- 42-byte ZCP envelope with native data residency zone tag at offset 36
- `EnvelopeRef` — zero-copy parser for `no_std` / bare-metal targets
- `Envelope` — owned builder type (requires `alloc` feature)
- `encode_to_slice` — encode into caller-provided buffer, no allocator needed
- `encode_to_vec` — convenience encoding with heap allocation (`alloc`)
- `peek_frame_length` — two-phase transport framing from header bytes
- `ResidencyTag` — ISO 3166-1 numeric zone codes with extension bit for future sub-national zones
- `MsgType` — 11 message types across 6 functional ranges with relay-friendly `MsgRange` classification
- `CryptoSuite` — PQ Hybrid (0x01) and Classical (0x02) profile identifiers
- `Flags` — compressed and fragmented bit flags with reserved-bit detection
- `Version` — protocol version V1 (0x01)
- Feature flags: `alloc`, `std`, `serde`
- 93 tests: 73 unit tests across all modules + 20 integration/proptest roundtrips
- CI: `no_std` cross-compile (thumbv7em, riscv32imc), musl targets, clippy, rustfmt, docs

### Protocol
- Wire format: ZCP v0x01
- Byte order: big-endian (network byte order)
- Fixed overhead: 58 bytes (42 header + 16 MAC)
- Crypto suites: PQ Hybrid (ML-KEM-768 + X25519, ML-DSA-65 + Ed25519, AES-256-GCM), Classical (X25519, Ed25519, AES-256-GCM)
- Residency tag: 2 bytes, ISO 3166-1 numeric, bit 15 reserved for extension

[Unreleased]: https://github.com/Teknorakit/clonic/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/Teknorakit/clonic/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/Teknorakit/clonic/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/Teknorakit/clonic/releases/tag/v0.1.0