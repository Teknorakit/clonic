# clonic

Wire protocol types and codec for the **Zone Coordination Protocol (ZCP)**.

`clonic` defines the binary envelope format that every ZCP message uses on the wire. It is deliberately minimal: types, constants, encode, decode. No crypto, no transport, no business logic.

Think of it like the [`http`](https://crates.io/crates/http) crate: it defines `Request` and `Response` but doesn't open sockets. Networking stacks build on top.

## Why ZCP?

Every major communication protocol in use today — MQTT, CoAP, gRPC, AMQP, HTTP — is **residency-blind**. None carry any concept of where data is allowed to exist.

ZCP fixes this. Every envelope carries a 2-byte residency zone tag, cryptographically authenticated by the sender. The routing layer refuses to forward messages outside the declared zone. Data residency enforcement is architectural, not configuration.

Read the full [Protocol Manifesto](docs/MANIFESTO.md).

## Why "clonic"?

In neurology, a **tonic-clonic** seizure has two phases: sustained contraction (*tonic*) followed by rapid rhythmic pulses propagating across the nervous system (*clonic*).

[`tonic`](https://crates.io/crates/tonic) is the Rust ecosystem's gRPC framework — persistent channels, sustained connections, request-response between known endpoints. It holds the line open.

`clonic` is the other half: short, rhythmic coordination pulses rippling across a mesh of devices that may appear, disappear, and reconnect at any time. No persistent channel required. The fleet *is* the nervous system.

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

All multi-byte integers are big-endian (network byte order). Total fixed overhead: 58 bytes.

## Usage

### `no_std` — Zero-copy parsing (bare-metal, microcontrollers)

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

### `alloc` — Owned envelopes (Linux, servers)

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

## License

MIT — maximum adoption, zero friction.

## About

An open protocol by [PT Teknorakit Inovasi Indonesia](https://github.com/Teknorakit).