# TODO

Checklist derived from ROADMAP.md to drive implementation.

## Protocol Constraints (Must Respect)
- ✅ Wire format: 42-byte header + variable payload + 16-byte MAC = 58 bytes overhead
- ✅ Big-endian byte order (network order) for all multi-byte integers
- ✅ Residency tag at offset 36 (2 bytes, ISO 3166-1 numeric)
- ✅ Extension bit (bit 15) reserved for sub-national zones
- ✅ `sender_device_id` at offset 4 (4-byte aligned for ARM zero-copy)
- ✅ Message type ranges: Core (0x01-0x0F), DHT (0x10-0x1F), Gossip (0x20-0x2F), Provisioning (0x30-0x3F), Heartbeat (0x40-0x4F), Vendor (0xF0-0xFF)
- ✅ Crypto suites: 0x01 (PQ Hybrid), 0x02 (Classical)
- ✅ Two-phase framing: read 42B header, peek length, read payload+MAC

## Phase 1: Cryptography Foundation
- [x] Create `clonic-crypto` crate (separate from `clonic-core` wire codec)
- [ ] Implement Suite 0x01 (PQ Hybrid): ML-KEM-768 + X25519 KEM with HKDF-SHA3-256
- [ ] Implement Suite 0x01 signatures: ML-DSA-65 + Ed25519
- [ ] Implement Suite 0x02 (Classical): X25519 KEM, Ed25519 signatures
- [ ] Implement AES-256-GCM with per-message HKDF-derived keys (both suites)
- [x] Add crypto-agility framework (suite registry, algorithm rotation)
- [ ] Write crypto KATs (known-answer tests) and cross-implementation validation
- [ ] Document suite selection guidelines (PQ Hybrid for nodes, Classical for edge)

- [x] Create `clonic-identity` crate
- [ ] Design offline-capable certificate chain (root → server → device, trust decay)
- [x] Implement Ed25519-based device identity (32-byte public key = sender_device_id)
- [x] Implement provisioning messages: REQUEST (0x30), CERT (0x31), REVOKE (0x32)
- [ ] Build certificate validation with trust decay by depth
- [ ] Implement key rotation mechanism
- [ ] Add secure key storage abstraction (filesystem, TPM, secure enclave)
- [ ] Build provisioning CLI tool for device onboarding
- [ ] Document provisioning workflow and security model

## Phase 2: Transport Layer
- [x] Create `clonic-transport` crate (core abstractions)
- [ ] Define `Transport` trait (send, recv, framing, error handling)
- [x] Implement two-phase framing (1: read 42B, 2: peek_frame_length, 3: read payload+MAC)
- [ ] Add connection lifecycle management (connect, disconnect, reconnect)
- [ ] Define transport-specific configuration (TCP ports, BLE UUIDs, LoRa params)
- [ ] Create transport registry for multi-transport nodes
- [ ] Write transport adapter tests

- [x] Create `clonic-transport-tcp` crate
- [ ] Implement TCP transport with async/await (tokio)
- [ ] Add TLS wrapper for encrypted TCP channels
- [ ] Implement connection pooling and keepalive
- [ ] Add backpressure and flow control
- [ ] Write TCP-specific benchmarks (throughput, latency)
- [ ] Test on Linux, macOS, Windows

- [ ] Create `clonic-transport-ble` crate (GATT characteristics for ZCP frames)
- [ ] Create `clonic-transport-lora` crate (LoRaWAN adapter)
- [ ] Implement WiFi Direct transport
- [ ] Add USB serial transport for development/debugging
- [ ] Test on ESP32, nRF52, STM32 targets
- [ ] Document transport selection matrix (range, power, bandwidth)

## Phase 3: Zone Enforcement Routing
- [ ] Create `clonic-router` crate
- [ ] Implement peer registry (device_id → zone)
- [ ] Enforce zone validation per hop with policy engine (allow/deny)
- [ ] Add zone-aware routing table and multi-hop forwarding
- [ ] Add violation logging, sender notification, Prometheus metrics
- [ ] Provide zone config format + ISO registry, sub-national support
- [ ] Build zone policy CLI and audit logging

## Phase 4: CRDT Synchronization
- [ ] Create `clonic-crdt` crate
- [ ] Implement LWW-Register (last-write-wins)
- [ ] Implement OR-Set (observed-remove set)
- [ ] Implement PN-Counter (positive-negative counter)
- [ ] Implement RGA (replicated growable array) for text
- [ ] Add vector clock / hybrid logical clock for causality
- [ ] Implement CRDT merge operations with conflict resolution
- [ ] Write CRDT convergence tests (concurrent updates, partition healing)

- [ ] Create `clonic-sync` crate (sync engine)
- [ ] Design SYNC_CRDT (0x02) message payload format
- [ ] Implement delta-state synchronization
- [ ] Add Reed-Solomon erasure coding (k=4 of n=6, 4KB chunks)
- [ ] Build partial transfer recovery (reconstruct from k-of-n chunks)
- [ ] Implement zone-aware sync (partition operations by zone)
- [ ] Add sync scheduling (periodic, on-reconnect, on-demand)
- [ ] Create sync conflict resolution strategies
- [ ] Write sync tests (offline operation, reconnect convergence)

## Phase 5: Task Routing & Orchestration
- [ ] Create `clonic-tasks` crate (task routing engine)
- [ ] Design TASK_ROUTE (0x01) message payload format
- [ ] Implement intent specification language (capabilities, constraints)
- [ ] Build device capability registry
- [ ] Create task routing algorithm (capability matching, load balancing)
- [ ] Add zone-aware task routing (respect residency constraints)
- [ ] Implement task lifecycle (pending, assigned, executing, completed, failed)
- [ ] Add task result collection and aggregation
- [ ] Write task routing tests

- [ ] Create `clonic-orch` crate (orchestration layer)
- [ ] Implement Raft consensus for critical operations
- [ ] Add leader election with zone awareness
- [ ] Build gossip protocol for lightweight state sharing
- [ ] Implement device health monitoring (heartbeat messages 0x40-0x4F)
- [ ] Create fleet topology discovery
- [ ] Add device role management (leader, follower, observer)
- [ ] Write orchestration tests (leader failover, network partition)

## Phase 6: Integration
- [ ] Build `clonic-node` binary (config, CLI, REST API, structured logging)
- [ ] Integrate crypto, transport, routing, sync, tasks
- [ ] Add systemd unit and deployment guide
- [ ] Build `clonic-edge` SDK (Classical suite, minimal routing/CRDT)
- [ ] Provide example firmware (ESP32-C3, nRF52) and footprint measurements

## Phase 7: Testing & Validation
- [ ] Build multi-node test harness (Docker Compose)
- [ ] Write cross-zone routing tests (enforcement validation)
- [ ] Test offline-first sync (disconnect, operate, reconnect)
- [ ] Validate CRDT convergence (concurrent updates, partition healing)
- [ ] Test task routing across heterogeneous fleet
- [ ] Simulate network partitions and healing
- [ ] Test crypto suite interoperability (PQ Hybrid ↔ Classical)
- [ ] Run long-duration stability tests (7+ days)

- [ ] Benchmark envelope encode/decode (target: <100ms on ESP32)
- [ ] Measure crypto overhead (PQ Hybrid vs Classical)
- [ ] Test routing throughput (messages/sec per node)
- [ ] Benchmark CRDT merge performance
- [ ] Measure sync bandwidth efficiency (target: <5% overhead with erasure coding)
- [ ] Profile memory usage (node vs edge)
- [ ] Test scalability (2 → 200 devices, target: <1s task routing)
- [ ] Document performance characteristics

- [ ] Conduct threat modeling (STRIDE analysis)
- [ ] Test zone enforcement bypass attempts
- [ ] Validate crypto implementation (known-answer tests)
- [ ] Extend existing envelope fuzzing (AFL, libFuzzer on top of proptest)
- [ ] Test replay attack resistance
- [ ] Validate MAC authentication (tamper detection)
- [ ] Test key rotation procedures
- [ ] Conduct penetration testing

## Phase 8: Documentation & Tooling
- [ ] Write RFC-style protocol spec and full rustdoc
- [ ] Integration guides, tutorials, troubleshooting, zone cookbook
- [ ] Build example apps (e.g., warehouse IoT, healthcare sync)
- [ ] Build `zcpctl` CLI, packet dissector, zone validator, cert manager
- [ ] Add Prometheus exporter + Grafana dashboards + runbooks

## Phase 9: Compliance & Security Audit
- [ ] Map ZCP to Indonesia PP 71/2019 + GR 82/2012 requirements
- [ ] Validate GDPR Article 44-49 alignment (EU cross-border transfers)
- [ ] Test India DPDP Act 2023 compliance
- [ ] Document Vietnam Decree 13/2023 alignment
- [ ] Review ASEAN Digital Data Governance Framework alignment
- [ ] Create compliance audit trail format
- [ ] Write compliance certification guide
- [ ] Engage legal review (data sovereignty experts)

- [ ] Engage cryptography audit firm (Trail of Bits, NCC Group)
- [ ] Conduct code audit (all crypto, routing, identity code)
- [ ] Perform protocol analysis (formal verification if possible)
- [ ] Test post-quantum crypto implementation
- [ ] Validate zone enforcement guarantees
- [ ] Review key management procedures
- [ ] Address audit findings
- [ ] Publish audit report

## Phase 10: Production Deployment
- [ ] Publish Kubernetes manifests + Helm charts
- [ ] Provide Terraform modules (AWS/GCP/Azure)
- [ ] Implement zero-downtime rollout + backup/DR procedures
- [ ] Add monitoring/alerting and incident response playbooks

## Phase 11: Release & Ecosystem
- [ ] Freeze wire protocol v0x01 and publish v1.0 crates
- [ ] Publish security audit report and release announcement
- [ ] Submit IETF RFC; conference talks
- [ ] Build community (org, chat), governance, contributor guide
- [ ] Language bindings (Python/Go/C) and platform integrations
- [ ] Certification program and developer summit

## Success Criteria (from ROADMAP.md)
**Technical:**
- [ ] 100% zone enforcement (zero bypass in testing)
- [ ] <100ms envelope encode/decode on ESP32
- [ ] 99.99% CRDT convergence in partition tests
- [ ] <5% bandwidth overhead from erasure coding
- [ ] Support 200+ device fleet with <1s task routing

**Adoption:**
- [ ] 3+ pilot deployments in different verticals
- [ ] 10+ third-party implementations
- [ ] 1000+ GitHub stars
- [ ] Accepted as IETF RFC

**Compliance:**
- [ ] Pass third-party security audit
- [ ] Validated compliance in 3+ jurisdictions
- [ ] Zero residency violations in production

## Next Immediate Actions
- [ ] Confirm scope for current cycle (phases to execute)
- [ ] Assemble team (Rust, embedded, security, DevOps, docs, compliance)
- [ ] Provision test hardware (ESP32, nRF52, Raspberry Pi fleet)
- [ ] Secure cloud resources (AWS/GCP for integration testing)
- [ ] Kick off `clonic-crypto` implementation (Phase 1.1)
- [ ] Select pilot vertical for deployment (healthcare, warehouse, or government)
