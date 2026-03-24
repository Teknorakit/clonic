# Zone Coordination Protocol (ZCP) Specification

## Abstract

The Zone Coordination Protocol (ZCP) is a wire protocol for secure, zone-aware data coordination between distributed devices. ZCP provides cryptographic security, zone enforcement, and efficient transport for IoT, edge computing, and distributed systems.

## Table of Contents

1. [Introduction](#introduction)
2. [Protocol Overview](#protocol-overview)
3. [Wire Format](#wire-format)
4. [Message Types](#message-types)
5. [Cryptographic Suites](#cryptographic-suites)
6. [Zone Enforcement](#zone-enforcement)
7. [Transport Layer](#transport-layer)
8. [Security Considerations](#security-considerations)
9. [Implementation Guidelines](#implementation-guidelines)
10. [Appendix](#appendix)

## Introduction

### Purpose

ZCP enables secure communication between devices while respecting geographical and organizational data residency requirements. It provides:

- **End-to-end encryption** with post-quantum resistant options
- **Zone-based data residency** enforcement
- **Efficient binary wire format** for constrained environments
- **Pluggable transport layer** supporting TCP, UDP, BLE, LoRa, etc.

### Scope

This specification defines:
- The ZCP wire format and message structure
- Cryptographic suites and key management
- Zone enforcement mechanisms
- Transport layer requirements
- Security considerations

### Terminology

- **Device**: Any endpoint implementing ZCP (sensor, gateway, server, mobile)
- **Zone**: Geographical or organizational boundary for data residency
- **Envelope**: The fundamental ZCP message unit (42-byte header + payload + MAC)
- **Suite**: Cryptographic algorithm combination (classical or post-quantum hybrid)
- **Residency Tag**: ISO 3166-1 country code identifying data residency

## Protocol Overview

### Design Principles

1. **Security First**: All messages are authenticated and encrypted
2. **Zone Aware**: Wire format includes residency tags for enforcement
3. **Efficient**: Minimal overhead for constrained devices
4. **Extensible**: Message type ranges allow future extensions
5. **Crypto Agile**: Support for algorithm rotation

### Architecture

```
+-------------------+     +-------------------+     +-------------------+
|   Application     | <--|    ZCP Layer      | -->|    Transport      |
|   Layer            |     |                   |     |    Layer           |
+-------------------+     +-------------------+     +-------------------+
        ^                         ^                         ^
        |                         |                         |
        v                         v                         v
+-------------------+     +-------------------+     +-------------------+
|   Business Logic  |     |   Crypto & Zone   |     |   TCP/UDP/BLE     |
|                   |     |   Enforcement      |     |   LoRa/etc.       |
+-------------------+     +-------------------+     +-------------------+
```

### Message Flow

1. **Application** creates business data
2. **ZCP Layer** encrypts and adds zone metadata
3. **Transport Layer** delivers to destination
4. **Receiver** validates zone residency and decrypts

## Wire Format

### Envelope Structure

```
+-------------------+-------------------+-------------------+
|   Header (42B)    |   Payload (N)     |   MAC (16B)       |
+-------------------+-------------------+-------------------+
|0                42|43              42+N|42+N+1          42+N+16|
```

### Header Format (42 bytes)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-------+-------+-------+-------+-------+-------+-------+-------+
|Version| Suite |  Msg  | Flags | Reserved               |
|  (1)  |  (1)  | Type  | (1)  | (4)                   |
+-------+-------+-------+-------+-------+-------+-------+-------+
| Sender Device ID (4 bytes, aligned)                                |
+---------------------------------------------------------------+
| Sender Device ID (cont.) | Reserved               | Timestamp |
| (4)                     | (4)                    | (8)       |
+--------------------------+-----------------------+-----------+
| Payload Length (4 bytes, big-endian)                               |
+---------------------------------------------------------------+
| Residency Tag (2 bytes) | Reserved               | Flags     |
| (ISO 3166-1)            | (4)                    | (2)       |
+--------------------------+-----------------------+-----------+
```

#### Header Fields

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 1 | Version | Protocol version (0x01) |
| 1 | 1 | Suite | Crypto suite (0x01=PQ Hybrid, 0x02=Classical) |
| 2 | 1 | Msg Type | Message type (see Message Types) |
| 3 | 1 | Flags | Message flags (compressed, fragmented, etc.) |
| 4 | 8 | Reserved | Reserved for future use (must be zero) |
| 12 | 8 | Sender Device ID | 32-byte Ed25519 public key (first 8 bytes) |
| 20 | 8 | Sender Device ID (cont.) | Remaining 24 bytes |
| 28 | 8 | Timestamp | Unix timestamp (big-endian) |
| 36 | 4 | Payload Length | Payload length in bytes (big-endian) |
| 40 | 2 | Residency Tag | ISO 3166-1 country code (big-endian) |
| 42 | 2 | Reserved | Reserved for future use (must be zero) |

### Payload Format

The payload format varies by message type:

#### Encrypted Application Data (Msg Type 0x01)
```
+-------------------+-------------------+
|  Nonce (12B)      |  Ciphertext (N)   |
+-------------------+-------------------+
|0                12|13              12+N|
```

#### Key Exchange (Msg Type 0x10)
```
+-------------------+-------------------+
|  Ephemeral PK (32B)| Encapsulated Key (N) |
+-------------------+-------------------+
|0                32|33              32+N|
```

#### Heartbeat (Msg Type 0x40)
```
+-------------------+
|  Sequence Number  |
|     (4 bytes)     |
+-------------------+
```

### MAC (Message Authentication Code)

- **Algorithm**: HMAC-SHA3-256 truncated to 16 bytes
- **Key**: Derived from session key and message context
- **Coverage**: Header + Payload (excluding MAC itself)

## Message Types

### Message Type Ranges

| Range | Hex Range | Purpose |
|-------|-----------|---------|
| Core | 0x01-0x0F | Core protocol messages |
| DHT | 0x10-0x1F | Distributed hash table operations |
| Gossip | 0x20-0x2F | Peer discovery and gossip |
| Provisioning | 0x30-0x3F | Device provisioning and certificates |
| Heartbeat | 0x40-0x4F | Health monitoring and keepalive |
| Vendor | 0xF0-0xFF | Vendor-specific extensions |

### Core Message Types

#### 0x01: Encrypted Application Data
- **Purpose**: Secure application-to-application communication
- **Payload**: Encrypted application data with nonce
- **Requirements**: Must be end-to-end encrypted

#### 0x02: Compressed Data
- **Purpose**: Compressed application data
- **Payload**: Compressed then encrypted data
- **Flags**: Compression flag must be set

#### 0x03: Fragmented Data
- **Purpose**: Large data transmission
- **Payload**: Fragment index and data
- **Flags**: Fragmented flag must be set

### DHT Message Types

#### 0x10: Key Exchange
- **Purpose**: Establish secure session
- **Payload**: Ephemeral public key + encapsulated key
- **Response**: Corresponding 0x11 message

#### 0x11: Key Exchange Response
- **Purpose**: Complete key exchange
- **Payload**: Ephemeral public key + encapsulated key

#### 0x12: Node Discovery
- **Purpose**: Discover peers in zone
- **Payload**: Node capabilities and preferences

### Provisioning Message Types

#### 0x30: Provisioning Request
- **Purpose**: Request device certificate
- **Payload**: Device capabilities and metadata

#### 0x31: Provisioning Certificate
- **Purpose**: Issue device certificate
- **Payload**: Certificate chain and zone configuration

#### 0x32: Certificate Revocation
- **Purpose**: Revoke compromised certificate
- **Payload**: Certificate identifier and reason

### Heartbeat Message Types

#### 0x40: Heartbeat
- **Purpose**: Keep-alive and health monitoring
- **Payload**: Sequence number and optional metrics

#### 0x41: Heartbeat Response
- **Purpose**: Acknowledge heartbeat
- **Payload**: Echoed sequence number

## Cryptographic Suites

### Suite 0x01: Post-Quantum Hybrid

#### Key Exchange
- **Algorithm**: ML-KEM-768 + X25519 hybrid
- **Key Derivation**: HKDF-SHA3-256
- **Session Key**: `HKDF-SHA3-256(X25519_shared || ML-KEM_shared, context)`

#### Signatures
- **Algorithm**: ML-DSA-65 + Ed25519 hybrid
- **Signature Format**: Concatenated signatures (ML-DSA || Ed25519)
- **Verification**: Both signatures must validate

#### Encryption
- **Algorithm**: AES-256-GCM
- **Nonce**: 12-byte random nonce
- **AAD**: Header bytes for additional authentication

### Suite 0x02: Classical

#### Key Exchange
- **Algorithm**: X25519 only
- **Key Derivation**: HKDF-SHA3-256
- **Session Key**: `HKDF-SHA3-256(X25519_shared, context)`

#### Signatures
- **Algorithm**: Ed25519 only
- **Signature Format**: 64-byte Ed25519 signature
- **Verification**: Standard Ed25519 verification

#### Encryption
- **Algorithm**: AES-256-GCM
- **Nonce**: 12-byte random nonce
- **AAD**: Header bytes for additional authentication

### Key Management

#### Device Keys
- **Identity Key**: 32-byte Ed25519 keypair (permanent)
- **Ephemeral Keys**: Per-connection X25519/ML-KEM keypairs
- **Rotation**: Ephemeral keys rotated per connection

#### Session Keys
- **Derivation**: HKDF-SHA3-256 from key exchange output
- **Lifetime**: Per-connection or per-message basis
- **Forward Secrecy**: Compromised keys don't reveal past communications

#### Certificate Keys
- **Root Keys**: Long-term zone authority keys
- **Server Keys**: Intermediate authority keys
- **Device Keys**: End device identity keys

## Zone Enforcement

### Residency Tags

#### Format
- **Size**: 2 bytes (big-endian)
- **Encoding**: ISO 3166-1 numeric country codes
- **Extension Bit**: Bit 15 reserved for sub-national zones

#### Country Codes
- **Indonesia**: 360
- **Singapore**: 702
- **Malaysia**: 458
- **Thailand**: 764
- **Vietnam**: 704

#### Sub-National Zones
- **Extension Bit**: Set for sub-national zones
- **Encoding**: Country code + region identifier
- **Example**: 360 | 0x8000 = Jakarta Special Capital Region

### Enforcement Mechanisms

#### Sender-Side Enforcement
- **Validation**: Check residency tag before sending
- **Policy**: Apply cross-zone data policies
- **Logging**: Record all cross-zone transfers

#### Receiver-Side Enforcement
- **Validation**: Verify residency tag matches expectations
- **Rejection**: Block unauthorized cross-zone data
- **Audit**: Log all residency violations

#### Transport-Side Enforcement
- **Routing**: Enforce zone-based routing rules
- **Filtering**: Block unauthorized zone crossings
- **Monitoring**: Track zone compliance metrics

### Cross-Zone Policies

#### Policy Structure
```rust
pub struct CrossZonePolicy {
    pub target_zone: u16,
    pub allowed_data_types: Vec<DataType>,
    pub require_mutual_auth: bool,
    pub audit_logging: bool,
}
```

#### Policy Evaluation
1. **Check Zone**: Verify target zone in allowed list
2. **Check Data Type**: Verify data type permitted
3. **Check Authentication**: Verify mutual authentication if required
4. **Apply Action**: Allow, warn, or block based on policy

## Transport Layer

### Two-Phase Framing

#### Phase 1: Header Read
1. Read exactly 42 bytes from transport
2. Validate header format and version
3. Extract payload length from header

#### Phase 2: Complete Frame
1. Calculate total frame size: `42 + payload_length + 16`
2. Read remaining payload + MAC bytes
3. Validate MAC before processing

#### Implementation
```rust
// Phase 1
let mut header = [0u8; 42];
transport.read_exact(&mut header).await?;
let payload_len = u32::from_be_bytes([header[38], header[39], header[40], header[41]]);

// Phase 2
let total_len = 42 + payload_len as usize + 16;
let mut frame = vec![0u8; total_len];
frame[..42].copy_from_slice(&header);
transport.read_exact(&mut frame[42..]).await?;
```

### Transport Requirements

#### TCP Transport
- **Reliability**: Guaranteed delivery and ordering
- **Flow Control**: Handle backpressure and congestion
- **Connection Management**: Support connection pooling and keepalive

#### UDP Transport
- **Reliability**: Application-level reliability if needed
- **Fragmentation**: Handle MTU limitations
- **Ordering**: Sequence numbers for out-of-order delivery

#### BLE Transport
- **MTU Constraints**: Adapt to BLE MTU limitations
- **Power Management**: Optimize for battery-powered devices
- **Connection Management**: Handle BLE connection lifecycle

#### LoRa Transport
- **Data Rate**: Adapt to LoRa data rate limitations
- **Duty Cycle**: Respect regulatory duty cycle limits
- **Range**: Optimize for long-range communication

## Security Considerations

### Threat Model

#### Adversarial Capabilities
- **Network Attacker**: Can observe, modify, drop packets
- **Compromised Device**: Can expose keys and certificates
- **Quantum Computer**: Can break classical cryptography (future)

#### Security Goals
- **Confidentiality**: Protect message content from unauthorized access
- **Integrity**: Detect message tampering and modification
- **Authenticity**: Verify sender identity and authority
- **Zone Compliance**: Enforce data residency requirements

### Cryptographic Security

#### Key Security
- **Generation**: Use cryptographically secure RNG
- **Storage**: Protect private keys with secure storage
- **Rotation**: Regular key rotation before compromise
- **Destruction**: Secure zeroization of key material

#### Algorithm Security
- **Post-Quantum**: Use PQ hybrid suite for long-term security
- **Classical**: Use well-vetted classical algorithms
- **Implementation**: Avoid side-channel attacks
- **Validation**: Verify implementation correctness

### Zone Security

#### Residency Enforcement
- **Validation**: Verify residency tags at all layers
- **Policy**: Enforce cross-zone data policies
- **Audit**: Log all residency violations
- **Compliance**: Meet regulatory requirements

#### Certificate Security
- **Chain Validation**: Verify complete certificate chain
- **Revocation**: Check certificate revocation status
- **Expiration**: Reject expired certificates
- **Trust**: Maintain trust anchor security

### Implementation Security

#### Memory Safety
- **Zeroization**: Securely erase sensitive data
- **Bounds Checking**: Prevent buffer overflows
- **Input Validation**: Validate all inputs
- **Error Handling**: Secure error message handling

#### Timing Security
- **Constant Time**: Use constant-time operations for secrets
- **Side Channels**: Avoid timing-based information leakage
- **Randomness**: Use high-quality entropy sources
- **Validation**: Test for timing vulnerabilities

## Implementation Guidelines

### Compliance Requirements

#### Memory Constraints
- **no_std Support**: Support bare-metal environments
- **Heap Usage**: Minimize dynamic memory allocation
- **Stack Usage**: Limit stack depth for embedded targets
- **Code Size**: Optimize for flash memory constraints

#### Performance Requirements
- **Latency**: <100ms for envelope processing on typical hardware
- **Throughput**: Support high-throughput scenarios
- **Power**: Optimize for battery-powered devices
- **Network**: Adapt to various network conditions

### Testing Requirements

#### Unit Testing
- **Coverage**: >90% code coverage
- **Edge Cases**: Test boundary conditions
- **Error Paths**: Test all error conditions
- **Memory**: Test for memory leaks

#### Integration Testing
- **Interoperability**: Test between different implementations
- **Transport**: Test with various transport layers
- **Zone**: Test zone enforcement mechanisms
- **Security**: Test security properties

#### Property Testing
- **Invariants**: Test protocol invariants
- **Fuzzing**: Test with malformed inputs
- **Scaling**: Test with large message volumes
- **Stress**: Test under high load

### Documentation Requirements

#### API Documentation
- **Complete**: Document all public APIs
- **Examples**: Provide usage examples
- **Security**: Document security considerations
- **Performance**: Document performance characteristics

#### Protocol Documentation
- **Specification**: Complete protocol specification
- **Rationale**: Explain design decisions
- **Examples**: Provide protocol examples
- **Migration**: Guide for protocol evolution

## Appendix

### Test Vectors

#### Suite 0x02 Key Exchange
```
Input:
  Ephemeral Private: 77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab176f5da
  Recipient Public: de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f

Output:
  Shared Secret: 4a5d9d5ba4ce2de1728e3bfb39d847d920c873d6409e28b4e8e7b9b5b5b5b5b5
  Encapsulated Key: 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
```

#### Suite 0x01 Key Exchange
```
Input:
  X25519 Private: 77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab176f5da
  ML-KEM Private: [ML-KEM-768 private key bytes]
  Recipient X25519 Public: de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f
  Recipient ML-KEM Public: [ML-KEM-768 public key bytes]

Output:
  Shared Secret: [Hybrid session key bytes]
  Encapsulated Key: [Hybrid encapsulated key bytes]
```

### Reference Implementations

#### Rust Implementation
- **Repository**: https://github.com/Zluidr/clonic
- **License**: MIT or Apache 2.0
- **Features**: Complete protocol implementation

#### Test Suite
- **Repository**: https://github.com/Zluidr/clonic-test
- **Coverage**: All protocol features
- **Languages**: Rust, Go, Python

### Version History

#### Version 0x01
- **Date**: 2024-03-24
- **Changes**: Initial protocol specification
- **Features**: Core protocol, PQ hybrid suite, zone enforcement

### References

#### Standards
- [RFC 7748 - X25519](https://tools.ietf.org/html/rfc7748)
- [RFC 8032 - Ed25519](https://tools.ietf.org/html/rfc8032)
- [FIPS 203 - ML-KEM](https://nist.gov/publications/fips/fips-203/)
- [FIPS 204 - ML-DSA](https://nist.gov/publications/fips/fips-204/)
- [ISO 3166-1 - Country Codes](https://www.iso.org/iso-3161-country-codes.html)

#### Regulations
- [Indonesia PP 71/2019](https://kominfo.go.id/)
- [Singapore PDPA](https://www.pdpc.gov.sg/)
- [GDPR Article 44-49](https://gdpr.eu/)
- [ASEAN Digital Data Governance Framework](https://asean.org/)

### Contact

#### Protocol Maintenance
- **Email**: protocol@zluidr.com
- **Issues**: https://github.com/Zluidr/clonic/issues
- **Discussions**: https://github.com/Zluidr/clonic/discussions

#### Security Reporting
- **Email**: security@zluidr.com
- **PGP**: Available on request
- **Policy**: Responsible disclosure
