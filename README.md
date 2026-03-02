# clonic

Wire protocol types and codec for the **Zone Coordination Protocol (ZCP)**.

`clonic` defines the binary envelope format that every ZCP message uses on the wire. It is deliberately minimal: types, constants, encode, decode. No crypto, no transport, no business logic.

Think of it like the [`http`](https://crates.io/crates/http) crate: it defines `Request` and `Response` but doesn't open sockets. ZluidrOS and ZluidrEdge SDK build actual networking on top.

## Why "clonic"?

In neurology, a **tonic-clonic** seizure involves two phases: sustained contraction (*tonic*) followed by rapid rhythmic pulses across the nervous system (*clonic*).

[`tonic`](https://crates.io/crates/tonic) is already the Rust ecosystem's gRPC framework — sustained connections. `clonic` completes the pair: rapid, rhythmic coordination pulses across a distributed device mesh. The fleet *is* the nervous system.

## Who Uses This

| Consumer | Environment | Notes |
|----------|-------------|-------|
| **ZluidrOS** | Linux (RPi/server, 1–4 GB RAM) | Full OS with CRDT sync, Raft, libp2p, PQ crypto |
| **ZluidrEdge SDK** | Bare-metal/RTOS (ESP32, STM32, nRF52) | Minimal ZCP speaker, classical crypto only |
| **Third parties** | Any | Anyone who wants to speak ZCP on the wire |

## Envelope Layout

```text
Offset  Size  Field              Description
───────────────────────────────────────────────────────
0       1     version            Protocol version (0x01)
1       1     msg_type           Message type discriminant
2       1     crypto_suite       Crypto profile (0x01=PQ, 0x02=classical)
3       1     flags              Bit flags (compressed, fragmented)
4       32    sender_device_id   Ed25519 public key
36      2     residency_tag      ISO 3166-1 numeric, big-endian
38      4     payload_length     Payload byte count, big-endian
────────────────────────────────────────────────────────  42 bytes
42      var   payload            Encrypted (opaque to this crate)
42+N    16    mac                AES-256-GCM authentication tag
```

All multi-byte integers are big-endian (network byte order).

## Usage

### `no_std` — Zero-copy parsing (ESP32, bare-metal)

```rust
use clonic::{EnvelopeRef, MsgType};

fn handle_frame(buf: &[u8]) {
    let env = EnvelopeRef::parse(buf).expect("valid envelope");

    match env.msg_type() {
        Some(MsgType::SyncCrdt) => {
            let payload = env.payload();
            let residency = env.residency_tag();
            // hand off to sync engine...
        }
        _ => { /* forward or drop */ }
    }
}
```

### `alloc` — Owned envelopes (ZluidrOS)

```rust
use clonic::{Envelope, MsgType, CryptoSuite, ResidencyTag};

let envelope = Envelope::new(
    MsgType::TaskRoute,
    CryptoSuite::PqHybrid,
    device_public_key,           // [u8; 32]
    ResidencyTag::INDONESIA,
    encrypted_payload,           // Vec<u8>
    gcm_tag,                     // [u8; 16]
);

let wire_bytes = envelope.to_bytes();
```

### Transport framing

```rust
use clonic::decode::peek_frame_length;
use clonic::envelope::HEADER_SIZE;

// Step 1: read exactly 42 bytes from the wire
let header_buf = read_exact(stream, HEADER_SIZE);

// Step 2: learn total frame size
let (_, total) = peek_frame_length(&header_buf).unwrap();

// Step 3: read remaining bytes
let mut frame = vec![0u8; total];
frame[..HEADER_SIZE].copy_from_slice(&header_buf);
read_exact(stream, &mut frame[HEADER_SIZE..]);

// Step 4: parse
let env = clonic::EnvelopeRef::parse(&frame).unwrap();
```

## Feature Flags

| Feature | Default | Effect |
|---------|---------|--------|
| `alloc` | off | `Vec`-backed `Envelope`, `encode_to_vec` |
| `std`   | off | `std::error::Error` impl (implies `alloc`) |
| `serde` | off | `Serialize`/`Deserialize` on all public types (implies `alloc`) |

## What This Crate Does NOT Do

- **No crypto** — consumers bring their own (PQ hybrid or classical). The crate defines where crypto fields sit in the envelope but performs no encryption.
- **No transport** — no TCP, BLE, LoRa, libp2p. Transport-agnostic by design.
- **No CRDT payloads** — the `payload` field is opaque bytes.
- **No business logic** — no task scheduling, no routing decisions.

## Repository Structure

```
clonic (MIT)            ← you are here
├──▶ zluidros           Full OS (stronger license)
├──▶ zluidros-edge-sdk  Embedded SDK (Apache-2.0)
└──▶ (third parties)    Anyone speaking ZCP
```

## License

MIT — maximum adoption, zero friction. The value capture is upstream in ZluidrOS and the SaaS/data layers, not at the protocol level.

## About

Part of the **ZluidrOS** ecosystem by PT Teknorakit Inovasi Indonesia.
ZluidrOS is a purpose-built operating system for distributed, AI-capable computing in resource-constrained, sovereignty-conscious environments.
