# TODO

Checklist for the `clonic` monorepo — the ZCP wire protocol, cryptography, identity, and transport layer.

> **Scope boundary:** `clonic` is the shared vocabulary layer (like the `http` crate for Hyper).
> It defines envelope format, crypto suites, device identity, transport abstractions, and zone routing primitives.
> Higher-level concerns live in their own repos:
>
> | Responsibility | Repo | NOT clonic |
> |---|---|---|
> | CRDT sync, Raft consensus, gossip, fleet orchestration | [ZluidrOS](https://github.com/Zluidr/ZluidrOS) (`zluidr-sync`, `zluidr-raft`, `zluidr-zcp`) | ✗ |
> | Edge firmware SDK, sensor HAL, offline buffer, board support | [ZluidrEdge SDK](https://github.com/Zluidr/zluidredge-sdk) (`edge-core`, `edge-transport`) | ✗ |
> | Full OS daemon (`zcpd`), CLI/TUI, Alpine packaging | [ZluidrOS](https://github.com/Zluidr/ZluidrOS) (`zluidr-daemon`, `zluidr-cli`) | ✗ |
> | GingerNet privacy tunnel (`gingerd`) | [ZluidrOS](https://github.com/Zluidr/ZluidrOS) (`gingerd/`) | ✗ |

---

## Protocol Constraints (Must Respect)
- ✅ Wire format: 42-byte header + variable payload + 16-byte MAC = 58 bytes overhead
- ✅ Big-endian byte order (network order) for all multi-byte integers
- ✅ Residency tag at offset 36 (2 bytes, ISO 3166-1 numeric)
- ✅ Extension bit (bit 15) reserved for sub-national zones
- ✅ `sender_device_id` at offset 4 (4-byte aligned for ARM zero-copy)
- ✅ Message type ranges: Core (0x01-0x0F), DHT (0x10-0x1F), Gossip (0x20-0x2F), Provisioning (0x30-0x3F), Heartbeat (0x40-0x4F), Vendor (0xF0-0xFF)
- ✅ Crypto suites: 0x01 (PQ Hybrid), 0x02 (Classical)
- ✅ Two-phase framing: read 42B header, peek length, read payload+MAC

---

## `clonic-core` — Wire Codec (v0.1.2, published to crates.io)

### Complete ✅
- [x] 42-byte ZCP envelope with residency tag at offset 36
- [x] `EnvelopeRef` — zero-copy parser for `no_std` / bare-metal
- [x] `Envelope` — owned builder type (requires `alloc`)
- [x] `encode_to_slice` / `encode_to_vec`
- [x] `peek_frame_length` — two-phase transport framing
- [x] `ResidencyTag` — ISO 3166-1 numeric with extension bit
- [x] `MsgType` — 11 types across 6 ranges, `MsgRange` classification
- [x] `CryptoSuite` — PQ Hybrid (0x01) + Classical (0x02) identifiers
- [x] `Flags` — compressed, fragmented, reserved-bit detection
- [x] `Version` — V1 (0x01)
- [x] Feature flags: `alloc`, `std`, `serde`
- [x] 93 tests (73 unit + 20 proptest roundtrips)
- [x] CI: `no_std` cross-compile (thumbv7em, riscv32imc), musl, clippy, docs
- [x] docs.rs metadata fix (v0.1.2)

### Remaining
- [x] Add Heartbeat message types (0x40–0x4F range)
- [x] Consider adding `payload_max` const and validation in `encode_to_slice`
- [x] Extend proptest coverage to fuzz unknown-but-in-range message types

---

## `clonic-crypto` — Cryptography (v0.1.2, scaffold)

### Complete ✅
- [x] Crate scaffold with `no_std` support
- [x] `CryptoSuite` enum with `from_byte`/`as_byte`/`name`/`recommended_for`
- [x] Suite 0x02 (Classical) KEM — X25519 keygen (`OsRng` CSPRNG)
- [x] Suite 0x02 (Classical) KEM — encapsulate (ephemeral X25519 + HKDF-SHA3-256)
- [x] Suite 0x02 (Classical) KEM — decapsulate (X25519 DH + HKDF-SHA3-256)
- [x] Input validation (context length bounds, encapsulated key length)
- [x] Secret key zeroization on drop (`zeroize` crate)
- [x] Hybrid KEM combiner function (`hybrid_kem_combine` via HKDF-SHA3-256)

### Stubbed (framework exists, implementation returns placeholder errors)
- [ ] Suite 0x01 (PQ Hybrid) KEM — `PqHybridKem::keygen()` → returns `Err(BufferTooSmall)`
- [ ] Suite 0x01 (PQ Hybrid) KEM — `PqHybridKem::encapsulate()` → input validation only, no actual encapsulation
- [ ] Suite 0x01 (PQ Hybrid) KEM — `PqHybridKem::decapsulate()` → returns `Err(BufferTooSmall)`
- [ ] `derive_symmetric_key()` in `suite.rs` → copies shared_secret verbatim (no actual HKDF)

### Not Started
- [ ] Suite 0x01 PQ Hybrid: integrate ML-KEM-768 (evaluate `pqcrypto` vs `ml-kem` crate)
- [ ] Suite 0x01 signatures: ML-DSA-65 + Ed25519 hybrid
- [ ] Suite 0x02 signatures: Ed25519 sign/verify
- [ ] AES-256-GCM encrypt/decrypt with per-message HKDF-SHA3-256-derived keys
- [ ] Header-as-AAD: encrypt payload with header bytes as GCM additional authenticated data
- [ ] Crypto KATs (known-answer tests) for X25519, HKDF, AES-256-GCM
- [ ] Cross-implementation validation (test vectors from NIST / RFC 7748 / RFC 7539)
- [ ] Fix `derive_symmetric_key` to use actual HKDF-SHA3-256 derivation
- [ ] Real tests for Classical KEM encapsulate/decapsulate roundtrip (currently placeholder `#[test]` with empty body)
- [ ] Document suite selection guidelines

---

## `clonic-identity` — Device Identity & Provisioning (v0.1.2, scaffold)

### Complete ✅
- [x] Crate scaffold with `no_std` support
- [x] `DeviceIdentity` — 32-byte Ed25519 public key wrapper
- [x] `ProvisioningMessageType` — REQUEST (0x30), CERT (0x31), REVOKE (0x32)
- [x] `ProvisioningMessage` — payload struct with chain depth + trust decay validation
- [x] Basic trust decay validation (`chain_depth <= max_depth`)

### Not Started
- [ ] Offline-capable certificate chain format (root → server → device)
- [ ] Certificate serialization/deserialization (wire format for CERT payloads)
- [ ] Ed25519 signature generation and verification for certificates
- [ ] Trust decay scoring by depth (not just boolean validation)
- [ ] Certificate revocation list (CRL) format and checking
- [ ] Key rotation mechanism (signed rotation certificates)
- [ ] Secure key storage abstraction trait (filesystem, TPM, secure enclave backends)
- [ ] `edge-provision-cli` tool for device onboarding (or move to ZluidrEdge SDK)
- [ ] Document provisioning workflow and security model

---

## `clonic-transport` — Transport Abstraction (v0.1.2, scaffold)

### Complete ✅
- [x] Crate scaffold with `no_std` support
- [x] `TransportFraming::peek_frame_length` — extract payload length from 42B header
- [x] `TransportFraming::validate_frame_size`
- [x] Framing constants (`HEADER_SIZE`, `MAC_SIZE`, `MIN_FRAME_SIZE`)
- [x] Error types for transport operations

### Not Started
- [ ] Define `Transport` trait (`send`, `recv`, `connect`, `disconnect`, error handling)
- [ ] Connection lifecycle management (reconnect, backoff)
- [ ] Transport-specific configuration types (TCP port, BLE UUID, LoRa params)
- [ ] Transport registry / selector for multi-transport nodes
- [ ] Transport adapter test harness (mock transport for unit testing)

---

## `clonic-transport-tcp` — TCP Transport (v0.1.2, empty scaffold)

### Complete ✅
- [x] Crate scaffold with tokio dependency

### Stubbed
- [ ] `TcpTransport` — currently an empty struct with no functionality

### Not Started
- [ ] Implement `Transport` trait for TCP (async, tokio-based)
- [ ] Two-phase framing over TCP streams (read 42B → peek → read remainder)
- [ ] TLS wrapper (rustls or native-tls)
- [ ] Connection pooling and keepalive
- [ ] Backpressure and flow control
- [ ] TCP-specific benchmarks (throughput, latency)
- [ ] Cross-platform testing (Linux, macOS, Windows)

---

## `clonic-router` — Zone Enforcement Routing (not yet created)

> This crate belongs in clonic — it's the enforcement layer for the residency tag that clonic defines.

- [ ] Create `clonic-router` crate
- [ ] Peer registry (device_id → zone mapping)
- [ ] Zone validation per hop (extract tag, check destination, enforce)
- [ ] Routing policy engine (allowlists, denylists, cross-border agreements)
- [ ] Zone-aware routing table and path selection
- [ ] Violation logging and sender notification
- [ ] Zone configuration format (TOML)
- [ ] ISO 3166-1 zone registry with sub-national support (extension bit)
- [ ] Prometheus metrics for zone violations
- [ ] Zone policy CLI tool
- [ ] Zone audit logging (all forwarding decisions)

---

## Cross-Cutting Concerns

### Testing
- [ ] Fuzz envelope parser (extend proptest with AFL/libFuzzer)
- [ ] Crypto KATs and cross-implementation validation
- [ ] Transport framing fuzz tests
- [ ] Zone enforcement bypass attempt tests
- [ ] Replay attack resistance tests
- [ ] MAC authentication tamper detection tests
- [ ] Key rotation procedure tests
- [ ] Benchmark envelope encode/decode (target: <100ms on ESP32)
- [ ] Benchmark crypto overhead (PQ Hybrid vs Classical)
- [ ] Profile memory usage per crate

### Documentation
- [ ] RFC-style protocol specification (standalone, not just manifesto)
- [ ] Full rustdoc for all public APIs across all crates
- [ ] Suite selection guidelines document
- [ ] Zone configuration cookbook
- [ ] Transport implementation guide (how to add a new transport)
- [ ] Provisioning workflow guide
- [ ] Wireshark dissector for ZCP envelopes (`zcpctl` or standalone)

### Compliance & Security Audit
- [ ] Map ZCP wire format to Indonesia PP 71/2019 + GR 82/2012 requirements
- [ ] Validate GDPR Article 44-49 alignment (EU cross-border transfers)
- [ ] Document India DPDP Act 2023 compliance model
- [ ] Document Vietnam Decree 13/2023 alignment
- [ ] ASEAN Digital Data Governance Framework alignment
- [ ] Engage cryptography audit firm (Trail of Bits, NCC Group) for `clonic-crypto`
- [ ] Code audit: all crypto, routing, and identity code
- [ ] Protocol formal verification (if feasible)
- [ ] Publish audit report

### Release
- [ ] Freeze wire protocol v0x01 format
- [ ] Publish all crates to crates.io (currently only `clonic-core`)
- [ ] Tag v1.0.0 releases
- [ ] Submit IETF RFC for ZCP wire format
- [ ] Language bindings: Python, Go, C (for third-party adoption)

---

## Explicitly OUT OF SCOPE for clonic

These items were in the previous TODO but belong in other repos:

| Item | Belongs In | Why |
|---|---|---|
| CRDT types (LWW-Register, OR-Set, PN-Counter, RGA) | ZluidrOS `zluidr-sync` | Coordination logic, not wire format |
| CRDT sync engine + erasure coding | ZluidrOS `zluidr-sync` | State replication above protocol layer |
| Raft consensus | ZluidrOS `zluidr-raft` | Consensus above protocol layer |
| Gossip protocol | ZluidrOS `zluidr-zcp` | Coordination above protocol layer |
| Task routing + intent language | ZluidrOS `zluidr-zcp` | Application-layer orchestration |
| Fleet device orchestration | ZluidrOS `zluidr-zcp` | Application-layer orchestration |
| Device health monitoring / heartbeat logic | ZluidrOS `zluidr-daemon` | clonic defines the msg type range; OS implements logic |
| `clonic-node` full binary | ZluidrOS `zluidr-daemon` (`zcpd`) | OS binary, not protocol library |
| `clonic-edge` SDK | [ZluidrEdge SDK](https://github.com/Zluidr/zluidredge-sdk) | Separate repo with own ADRs and architecture |
| Edge firmware examples (ESP32-C3, nRF52) | ZluidrEdge SDK `examples/` | Hardware-specific, not protocol |
| BLE transport for edge devices | ZluidrEdge SDK `edge-transport` | Edge-specific transport wrappers |
| LoRa transport for edge devices | ZluidrEdge SDK `edge-transport` | Edge-specific transport wrappers |
| Kubernetes / Helm / Terraform deployment | ZluidrOS `alpine/` | Infrastructure, not protocol |
| Pilot deployment | TeknoRakit operations | Business execution, not code |

> **Integration point:** ZluidrOS and ZluidrEdge SDK both depend on `clonic-core` (and eventually `clonic-crypto`, `clonic-identity`, `clonic-transport`) as upstream crates. The dependency flows one way: clonic → consumers. clonic never depends on ZluidrOS or ZluidrEdge SDK.

---

## Success Criteria (scoped to clonic)

**Wire Protocol:**
- [ ] 100% zone enforcement at routing layer (zero bypass in `clonic-router` tests)
- [ ] <100μs envelope encode/decode on x86_64 (benchmark)
- [ ] <100ms envelope encode/decode on ESP32 (via ZluidrEdge SDK integration test)
- [ ] Zero known cryptographic vulnerabilities in `clonic-crypto`

**Adoption:**
- [ ] All crates published to crates.io
- [ ] 3+ downstream consumers (ZluidrOS, ZluidrEdge SDK, at least one third-party)
- [ ] Accepted as IETF RFC (wire format specification)

**Compliance:**
- [ ] Pass third-party crypto audit
- [ ] Validated regulatory alignment documentation for 3+ jurisdictions

---

## Next Immediate Actions
1. [ ] Complete Classical KEM roundtrip tests (encapsulate → decapsulate, verify shared secret matches)
2. [ ] Fix `derive_symmetric_key` stub in `suite.rs` to use actual HKDF-SHA3-256
3. [ ] Implement AES-256-GCM encrypt/decrypt with header-as-AAD
4. [ ] Implement Ed25519 signatures (Suite 0x02)
5. [ ] Evaluate ML-KEM-768 crate options (`pqcrypto` vs `ml-kem`) for Suite 0x01
6. [ ] Define `Transport` trait in `clonic-transport`
7. [ ] Implement basic TCP transport (connect, send frame, recv frame)

---

*Document Version: 2.0*
*Last Updated: March 3, 2026*
*Status: Active — aligned with three-repo architecture*