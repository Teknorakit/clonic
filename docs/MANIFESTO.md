# Zone Coordination Protocol

**ZCP — Protocol Manifesto**

Version 0.1.0 — Draft — March 2026

Open Protocol Specification

---

> *"The first wire protocol with native data residency enforcement."*

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [The Problem: The Residency Enforcement Gap](#2-the-problem-the-residency-enforcement-gap)
3. [Zone Coordination Protocol: Overview](#3-zone-coordination-protocol-overview)
4. [Wire Format Specification](#4-wire-format-specification)
5. [Zone Enforcement Model](#5-zone-enforcement-model)
6. [Security Architecture](#6-security-architecture)
7. [Offline-First Synchronization](#7-offline-first-synchronization)
8. [Regulatory Alignment](#8-regulatory-alignment)
9. [Comparative Analysis](#9-comparative-analysis)
10. [Adoption Model](#10-adoption-model)
11. [Conclusion](#11-conclusion)

---

## 1. Executive Summary

Every major communication protocol in use today — TCP/IP, MQTT, CoAP, gRPC, AMQP, HTTP — is residency-blind. None carry any concept of where data is allowed to exist. Data residency enforcement is left entirely to infrastructure configuration, application logic, and legal agreements. One misconfigured cloud region, one errant API call, one rogue replication rule, and regulated data crosses a sovereign boundary in silence.

The Zone Coordination Protocol (ZCP) closes this gap. It is the first wire protocol that embeds data residency as a native, non-removable field in every message envelope. A 2-byte zone tag, cryptographically authenticated by the sender, travels with the payload from origin to destination. The routing layer refuses to forward messages whose zone tag does not match the destination's declared geographic boundary. Residency enforcement is architectural, not policy. A misconfigured application cannot accidentally exfiltrate regulated data because the protocol itself will not carry it.

ZCP is designed for distributed device coordination in environments where connectivity is intermittent, hardware is constrained, data sovereignty is regulated, and multiple transports (WiFi, BLE, LoRa, 4G) coexist. It provides CRDT-based offline-first synchronization, intent-based task routing, fleet device orchestration, and post-quantum cryptographic protection — all within a 42-byte envelope overhead that fits comfortably on microcontrollers with 256 KB of RAM.

The protocol is open, transport-agnostic, and published under the MIT license. The reference codec crate is called [`clonic`](https://github.com/teknorakit/clonic). ZCP is not tied to any operating system, cloud provider, or hardware platform.

---

## 2. The Problem: The Residency Enforcement Gap

### 2.1 Data Residency Is a Growing Global Requirement

Data sovereignty legislation is accelerating worldwide. Indonesia's PP 71/2019 and GR 82/2012 require certain data categories to remain within national borders. The European Union's GDPR restricts cross-border transfers of personal data. India's DPDP Act 2023 empowers the government to restrict data transfers to specific countries. Vietnam, Nigeria, Russia, China, Brazil, and Saudi Arabia all enforce some form of data localization. By 2025, over 100 countries have enacted or proposed data residency legislation.

For IoT deployments, distributed edge computing, healthcare systems, financial infrastructure, and government digital services, data residency compliance is not optional — it is a legal obligation with significant penalties for violation.

### 2.2 Every Existing Protocol Is Residency-Blind

No wire protocol in widespread use carries any metadata about where data is permitted to exist. The protocol layer — the one component that touches every byte in transit — is completely unaware of residency constraints.

| Protocol | Primary Use | Residency Awareness | Enforcement Mechanism |
|---|---|---|---|
| TCP/IP | Transport layer | None | None |
| MQTT | IoT pub/sub messaging | None | Broker region selection (config) |
| CoAP | Constrained IoT devices | None | None |
| HTTP/HTTPS | Web, APIs, REST | None | CDN/origin region (config) |
| gRPC | Service-to-service RPC | None | Endpoint URL (config) |
| AMQP | Message queuing | None | Broker location (config) |
| DDS/RTPS | Real-time pub/sub | None | Domain partitioning (config) |
| ZigBee/Z-Wave | Home/building automation | None | None |
| LoRaWAN | Long-range IoT | None | Network server region (config) |
| BLE | Short-range device mesh | None | None |

In every case, residency "enforcement" is accomplished by configuring infrastructure correctly: choosing the right AWS region, deploying the broker in Jakarta instead of Singapore, setting up the right firewall rules. The protocol itself carries no residency metadata and provides no enforcement mechanism.

### 2.3 Configuration-Based Enforcement Fails

Relying on configuration for data residency creates a fragile, audit-hostile compliance posture:

**Single point of failure.** One misconfigured replication rule, one cross-region database link, one developer pointing a staging environment at the wrong endpoint, and regulated data silently leaves the jurisdiction. The protocol will happily carry it.

**No audit trail.** When data crosses a boundary via a misconfigured protocol, there is no record in the wire format. The violation is invisible until discovered by external audit, by which point the damage is done.

**Defense-in-depth failure.** Security best practice demands multiple independent layers of enforcement. Today, data residency has exactly one layer: correct configuration. There is no protocol-level backstop.

**Scaling complexity.** As deployments grow from 10 devices to 10,000, maintaining correct configuration across every service, every broker, every API endpoint, every sync rule becomes exponentially harder. Each new component is a potential residency violation.

---

## 3. Zone Coordination Protocol: Overview

### 3.1 What ZCP Is

The Zone Coordination Protocol is an open wire protocol for distributed device coordination with native data residency enforcement. It provides:

**Zone-tagged messaging.** Every ZCP envelope carries a 2-byte residency zone tag, cryptographically bound to the message by the sender's signature. The routing layer refuses to forward messages to peers outside the declared zone.

**Offline-first synchronization.** CRDT-based state replication ensures devices continue operating during connectivity loss and converge automatically on reconnect, with zero data loss.

**Intent-based task routing.** Applications declare what should happen (an intent), not which device should do it. The protocol routes tasks based on device capabilities, connectivity, load, and zone constraints.

**Fleet device orchestration.** Multi-device coordination uses Raft consensus for critical operations and gossip protocols for lightweight state sharing, scaling from 2 to 200 devices.

**Post-quantum cryptography.** Hybrid PQ key exchange (ML-KEM-768 + X25519) and authentication (ML-DSA-65 + Ed25519) from day one, with crypto-agility for algorithm rotation.

**Transport agnosticism.** ZCP runs over any reliable or unreliable transport: TCP, BLE, WiFi Direct, LoRa, 4G, USB serial. The protocol adapts; applications don't change.

### 3.2 What ZCP Is Not

ZCP is not a transport protocol (it runs above transport), not a database (it coordinates state, not storage), not a blockchain (it anchors nothing on-chain), not tied to any operating system or cloud provider, and not an anonymity network (though it can integrate with one). It is a coordination protocol — the layer between transport and application that handles the mechanics of distributed device communication with sovereignty awareness.

### 3.3 Design Principles

> *"Residency is architectural, not policy. Offline-first is default, not fallback. Constrained devices are first-class citizens."*

1. **Residency at the wire level.** The zone tag is a mandatory, non-removable field in every envelope. There is no way to send a ZCP message without declaring its residency zone. This is the protocol's defining architectural contribution.

2. **Offline-first by design.** Every operation is designed to complete eventually, even without connectivity. No work is lost. No user is blocked.

3. **Constrained-device friendly.** The fixed 42-byte header is parseable with zero heap allocation. The reference codec runs on ESP32 (256 KB RAM) in `no_std` Rust.

4. **Crypto-agile.** All cryptographic algorithms are identified by a suite byte in the envelope. When standards evolve, ZCP rotates algorithms without breaking wire compatibility.

5. **Open and unencumbered.** MIT license. No patents. No CLA. The protocol specification and reference codec are freely available.

---

## 4. Wire Format Specification

### 4.1 Envelope Layout

Every ZCP message is wrapped in a fixed-format envelope. All multi-byte integers are big-endian (network byte order). The header is exactly 42 bytes, enabling efficient two-phase transport framing: read 42 bytes, extract `payload_length`, then read the remaining payload + MAC.

```
Offset  Size     Field              Description
──────────────────────────────────────────────────────────
0       1 byte   version            Protocol version (0x01 for ZCP v1)
1       1 byte   msg_type           Message type discriminant
2       1 byte   crypto_suite       Cryptographic profile identifier
3       1 byte   flags              Bit flags: compressed (0), fragmented (1)
4       32 bytes sender_device_id   Sender's Ed25519 public key
36      2 bytes  residency_tag      ISO 3166-1 numeric zone code
38      4 bytes  payload_length     Encrypted payload byte count
──────────────────────────────────────────────────────────  42 bytes header
42      variable payload            Encrypted payload (opaque to routing)
42+N    16 bytes mac                AES-256-GCM authentication tag
```

Total fixed overhead: 42 bytes (header) + 16 bytes (MAC) = 58 bytes per message. The `sender_device_id` field starts at offset 4, which is 4-byte aligned for zero-copy parsing on ARM architectures.

### 4.2 The Residency Tag (Offset 36, 2 bytes)

The residency tag is the architectural centerpiece of ZCP. It occupies 2 bytes in big-endian format:

- **Bit 15 (high bit):** Extension flag. When 0, bits 0–14 encode an ISO 3166-1 numeric country code. When 1, the tag uses an extended format for sub-national zones (ISO 3166-2 subdivisions, reserved for future use).
- **Bits 0–14:** ISO 3166-1 numeric country code (0–999 in practice). Special value `0x0000` indicates Global — no residency restriction.

Examples: Indonesia = 360 (`0x0168`), Malaysia = 458 (`0x01CA`), Philippines = 608 (`0x0260`), Global = 0 (`0x0000`).

The residency tag is authenticated as part of the envelope header, which serves as Additional Authenticated Data (AAD) in the AES-256-GCM encryption. Tampering with the zone tag invalidates the MAC, making zone spoofing cryptographically detectable.

### 4.3 Message Types

Message types are allocated in functional ranges for forward compatibility:

| Range | Category | Defined Types |
|---|---|---|
| `0x01`–`0x0F` | Core operations | TASK_ROUTE (0x01), SYNC_CRDT (0x02), DEVICE_ORCH (0x03) |
| `0x10`–`0x1F` | DHT operations | FIND_NODE (0x10), GET_VALUE (0x11), PUT_VALUE (0x12) |
| `0x20`–`0x2F` | Gossip operations | BROADCAST (0x20), SUBSCRIBE (0x21) |
| `0x30`–`0x3F` | Provisioning | REQUEST (0x30), CERT (0x31), REVOKE (0x32) |
| `0x40`–`0x4F` | Heartbeat | Reserved for health monitoring |
| `0xF0`–`0xFF` | Vendor extensions | Reserved for third-party use |

### 4.4 Crypto Suite Identifier

| ID | Name | Key Exchange | Signature | Symmetric |
|---|---|---|---|---|
| `0x01` | PQ Hybrid | ML-KEM-768 + X25519 | ML-DSA-65 + Ed25519 | AES-256-GCM |
| `0x02` | Classical | X25519 | Ed25519 | AES-256-GCM |

The PQ Hybrid suite follows the NIST-recommended migration strategy. The Classical suite is for devices where post-quantum algorithms are computationally infeasible.

---

## 5. Zone Enforcement Model

### 5.1 How Enforcement Works

ZCP zone enforcement operates at the routing layer — below the application, above the transport. When a ZCP node receives a message for forwarding:

1. Extract the `residency_tag` from the envelope header.
2. Look up the destination peer's declared zone (from the peer registry, populated during device provisioning).
3. If the `residency_tag` is Global (`0x0000`), forward unconditionally.
4. If the `residency_tag`'s country code does not match the destination's declared zone, **refuse to forward**. Log the violation. Notify the sender.
5. If the zones match, forward normally.

This check is performed by every ZCP node in the routing path, not just the origin. A multi-hop delivery is validated at each hop, providing defense-in-depth.

### 5.2 Why Wire-Level Enforcement Matters

| Property | Wire-Level (ZCP) | Config-Based (Status Quo) |
|---|---|---|
| Bypass resistance | Protocol refuses to carry the data | One misconfigured service bypasses all controls |
| Audit trail | Every packet carries its zone tag (signed) | No wire-level evidence of zone compliance |
| Defense-in-depth | Every routing hop validates independently | Single enforcement point (if any) |
| Application independence | Works regardless of app-layer correctness | Each application must implement its own checks |
| Fail-safe | Default deny: no tag = no forwarding | Default open: no config = data flows freely |

### 5.3 Zone Granularity Roadmap

ZCP v1 enforces country-level zones using ISO 3166-1 numeric codes. The extension bit (bit 15) reserves a path to sub-national zones (ISO 3166-2) for emerging requirements like province-level digital sovereignty.

---

## 6. Security Architecture

### 6.1 Post-Quantum Cryptography

ZCP adopts hybrid PQ crypto as a first-class design decision:

- **Key exchange:** `session_key = HKDF-SHA3-256(X25519_shared || ML-KEM-768_shared, context)`. Dual classical + PQ floor — neither failure mode is catastrophic.
- **Authentication:** ML-DSA-65 (FIPS 204) signatures with Ed25519 fallback.
- **Symmetric:** AES-256-GCM with per-message HKDF-derived keys. Quantum-resistant (128-bit effective security against Grover's algorithm).

### 6.2 Crypto-Agility

The `crypto_suite` byte enables algorithm rotation without wire format changes. New suites (e.g., HQC-based KEM) can be introduced without breaking existing deployments.

### 6.3 Device Identity and Provisioning

Devices are identified by their Ed25519 public key (the 32-byte `sender_device_id`). Provisioning uses an offline-capable certificate chain: root admin → server → device, with trust decaying by depth. No CA server, no blockchain, no network access required for identity verification.

---

## 7. Offline-First Synchronization

### 7.1 CRDT-Based State Replication

State replication uses CRDTs with mathematical convergence guarantees. Devices continue operating locally during disconnection and merge automatically on reconnect — zero data loss, zero human intervention.

### 7.2 Erasure Coding for Partial Transfer Recovery

Reed-Solomon erasure coding (k=4 of n=6, 4 KB chunks) ensures partial sync transfers are recoverable. If connectivity drops mid-transfer, the receiver reconstructs from any k-of-n chunks. Approximately 50% bandwidth overhead eliminates retransmission entirely.

### 7.3 Zone-Aware Sync

Offline-first sync respects zone boundaries. When a device reconnects, CRDT operations carry the zone tag of the originating data. Operations are partitioned by zone and routed only to zone-compatible peers. A device that roams across zones does not replicate zone-restricted data to the wrong jurisdiction.

---

## 8. Regulatory Alignment

| Jurisdiction | Regulation | Requirement | ZCP Alignment |
|---|---|---|---|
| Indonesia | PP 71/2019, GR 82/2012 | Strategic/restricted data stays in Indonesia | Zone tag 360; routing refuses non-ID forwarding |
| EU | GDPR Art. 44–49 | Transfers outside EU require safeguards | Per-member or EU-wide zone; protocol enforcement |
| India | DPDP Act 2023 | Government may restrict transfers | Configurable zone allowlists |
| Vietnam | Decree 13/2023 | Certain data must be stored in Vietnam | Zone tag 704; same model |
| ASEAN | Digital Data Governance Framework | Emerging regional standards | Zone model supports regional groupings |

ZCP does not replace legal compliance. It provides an architectural enforcement mechanism that makes accidental violations physically impossible at the protocol level.

---

## 9. Comparative Analysis

| Capability | MQTT | gRPC | CoAP | DDS/RTPS | ZCP |
|---|---|---|---|---|---|
| Data residency enforcement | None | None | None | None | **Native (wire-level)** |
| Offline-first sync | QoS 1–2 | None | Observe | Durability QoS | **CRDT + erasure coding** |
| Post-quantum crypto | None | None | None | None | **Hybrid PQ from day one** |
| Multi-transport | TCP | HTTP/2 | UDP | UDP multicast | **Any (WiFi, BLE, LoRa, 4G)** |
| Device orchestration | None | None | None | None | **Raft + gossip** |
| Constrained device support | Good | Poor | Excellent | Fair | **Excellent (42B header, no_std)** |
| Envelope overhead | 2–5 bytes | 9+ bytes | 4 bytes | 20+ bytes | 58 bytes (zone + crypto + MAC) |

ZCP's 58-byte envelope is larger than MQTT's minimal header, reflecting the zone tag, crypto suite, device identity, and GCM MAC. For regulated use cases, this overhead is negligible compared to the compliance guarantees.

---

## 10. Adoption Model

### 10.1 Open Protocol, Open Codec

ZCP is an open protocol specification. The reference codec is a Rust crate called **[clonic](https://github.com/teknorakit/clonic)**, published under the MIT license. It supports `no_std` (bare-metal), `alloc` (embedded Linux), and `std` (servers) via feature flags.

### 10.2 Implementation Tiers

| Tier | Environment | Crypto Suite | Capabilities |
|---|---|---|---|
| Edge | ESP32, STM32, nRF52 (256 KB–4 MB RAM) | Classical (0x02) | Envelope encode/decode, zone tagging, basic routing |
| Node | Raspberry Pi, servers (1–4 GB RAM) | PQ Hybrid (0x01) | Full ZCP: CRDT sync, Raft consensus, fleet orchestration |
| Gateway | Cloud VMs, datacenter servers | PQ Hybrid (0x01) | Full ZCP + cross-zone policy engine, audit logging |

### 10.3 Target Verticals

- **Healthcare:** Medical record transfer under data sovereignty regulations.
- **Warehouse and logistics:** Inventory management with zero data loss across connectivity gaps.
- **Government digital services:** Village-level administration with sovereign data guarantees.
- **Financial services:** Cross-border transaction audit trails with residency compliance.
- **Agricultural IoT:** Remote sensor networks respecting national data policies.

---

## 11. Conclusion

The Zone Coordination Protocol addresses a gap that has existed since the earliest days of networked computing: the complete absence of data residency awareness at the wire level. Every protocol we use today will happily carry regulated data across any boundary without hesitation, because none of them know that boundaries exist.

ZCP is a modest proposal with outsized implications: add 2 bytes to the envelope, and make every router in the path check them. The engineering is straightforward. The regulatory alignment is immediate. The compliance improvement is architectural rather than aspirational.

The protocol is open. The reference implementation is available. The wire format is specified. What remains is adoption — and the growing global pressure for data sovereignty suggests the timing is right.

---

*Zone Coordination Protocol — Manifesto v0.1.0 — March 2026 — Open Protocol Specification*
