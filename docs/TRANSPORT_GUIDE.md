# Transport Implementation Guide

This guide explains how to implement new transports for the Zone Coordination Protocol (ZCP).

## Overview

ZCP transports handle the actual delivery of ZCP envelopes between devices. The transport layer is designed to be pluggable, allowing different underlying protocols (TCP, UDP, BLE, LoRa, etc.) to be used interchangeably.

## Architecture

### Transport Trait

All transports must implement the `Transport` trait:

```rust
pub trait Transport {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Connect to the transport
    async fn connect(&mut self) -> Result<(), Self::Error>;

    /// Send a ZCP envelope
    async fn send(&mut self, frame: &[u8]) -> Result<(), Self::Error>;

    /// Receive a ZCP envelope
    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error>;

    /// Disconnect from the transport
    async fn disconnect(&mut self) -> Result<(), Self::Error>;

    /// Check if transport is connected
    fn is_connected(&self) -> bool;
}
```

### Framing Layer

All transports must use the two-phase framing protocol:

1. **Phase 1**: Read 42-byte header
2. **Phase 2**: Extract payload length from header
3. **Phase 3**: Read remaining payload + MAC

```rust
use clonic_transport::TransportFraming;

// Phase 1: Read header
let mut header = [0u8; 42];
reader.read_exact(&mut header).await?;

// Phase 2: Get payload length
let payload_len = TransportFraming::peek_frame_length(&header)?.0;

// Phase 3: Read remainder
let total_len = 42 + payload_len as usize + 16; // +MAC
let mut remainder = vec![0u8; payload_len as usize + 16];
reader.read_exact(&mut remainder).await?;
```

## Implementation Steps

### 1. Create Transport Crate

```bash
cargo new clonic-transport-{protocol}
cd clonic-transport-{protocol}
```

### 2. Add Dependencies

```toml
[dependencies]
clonic-transport = { path = "../transport", version = "0.1.2" }
clonic-core = { path = "../core", version = "0.1.2" }
tokio = { version = "1", features = ["io-util"] }
```

### 3. Implement Transport Trait

```rust
use clonic_transport::{Transport, TransportFraming};
use clonic_core::error::Error;

pub struct {Protocol}Transport {
    // Protocol-specific fields
}

impl Transport for {Protocol}Transport {
    type Error = Error;

    async fn connect(&mut self) -> Result<(), Self::Error> {
        // Implement protocol-specific connection logic
        todo!()
    }

    async fn send(&mut self, frame: &[u8]) -> Result<(), Self::Error> {
        // Use two-phase framing
        self.send_frame(frame).await
    }

    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        // Use two-phase framing
        self.recv_frame(buf).await
    }

    async fn disconnect(&mut self) -> Result<(), Self::Error> {
        // Implement protocol-specific disconnection
        todo!()
    }

    fn is_connected(&self) -> bool {
        // Return connection status
        todo!()
    }
}
```

### 4. Implement Two-Phase Framing

```rust
impl {Protocol}Transport {
    async fn send_frame(&mut self, frame: &[u8]) -> Result<(), Error> {
        // Validate frame size
        TransportFraming::validate_frame_size(frame.len())?;

        // Send complete frame
        self.protocol_send(frame).await?;
        Ok(())
    }

    async fn recv_frame(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        // Phase 1: Read 42-byte header
        let mut header = [0u8; 42];
        let header_bytes = self.protocol_recv_exact(&mut header).await?;

        if header_bytes != 42 {
            return Err(Error::BufferTooSmall {
                need: 42,
                have: header_bytes,
            });
        }

        // Phase 2: Get payload length
        let (payload_len, total_len) = TransportFraming::peek_frame_length(&header)?;

        if buf.len() < total_len {
            return Err(Error::BufferTooSmall {
                need: total_len,
                have: buf.len(),
            });
        }

        // Phase 3: Read remainder
        let remainder_len = total_len - 42;
        let mut remainder = vec![0u8; remainder_len];
        let remainder_bytes = self.protocol_recv_exact(&mut remainder).await?;

        if remainder_bytes != remainder_len {
            return Err(Error::BufferTooSmall {
                need: remainder_len,
                have: remainder_bytes,
            });
        }

        // Assemble complete frame
        buf[..42].copy_from_slice(&header);
        buf[42..total_len].copy_from_slice(&remainder);

        Ok(total_len)
    }
}
```

### 5. Add Configuration

```rust
#[derive(Debug, Clone)]
pub struct {Protocol}Config {
    // Protocol-specific configuration
}

impl Default for {Protocol}Config {
    fn default() -> Self {
        Self {
            // Default values
        }
    }
}
```

### 6. Add Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use clonic_transport::Transport;

    #[tokio::test]
    async fn test_framing_roundtrip() {
        let mut transport = {Protocol}Transport::new(Default::default());

        // Test frame encoding/decoding
        let test_frame = b"test frame data";
        transport.connect().await.unwrap();

        transport.send(test_frame).await.unwrap();

        let mut recv_buf = [0u8; 1024];
        let len = transport.recv(&mut recv_buf).await.unwrap();

        assert_eq!(&recv_buf[..len], test_frame);
    }
}
```

## Example: UDP Transport

```rust
use std::net::SocketAddr;
use tokio::net::UdpSocket;

pub struct UdpTransport {
    socket: Option<UdpSocket>,
    remote_addr: SocketAddr,
    local_addr: SocketAddr,
}

impl UdpTransport {
    pub fn new(remote_addr: SocketAddr, local_addr: SocketAddr) -> Self {
        Self {
            socket: None,
            remote_addr,
            local_addr,
        }
    }

    async fn protocol_send(&mut self, data: &[u8]) -> Result<(), Error> {
        if let Some(socket) = &self.socket {
            socket.send_to(data, self.remote_addr).await
                .map_err(|_| Error::ConnectionFailed)?;
        }
        Ok(())
    }

    async fn protocol_recv_exact(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        if let Some(socket) = &self.socket {
            let (len, _) = socket.recv_from(buf).await
                .map_err(|_| Error::ConnectionFailed)?;
            Ok(len)
        } else {
            Err(Error::ConnectionFailed)
        }
    }
}

impl Transport for UdpTransport {
    type Error = Error;

    async fn connect(&mut self) -> Result<(), Self::Error> {
        let socket = UdpSocket::bind(self.local_addr).await
            .map_err(|_| Error::ConnectionFailed)?;
        self.socket = Some(socket);
        Ok(())
    }

    // ... implement other methods
}
```

## Best Practices

### Error Handling
- Use `clonic_core::error::Error` for transport-specific errors
- Map protocol-specific errors to ZCP errors
- Provide meaningful error messages

### Performance
- Use zero-copy operations where possible
- Buffer management for high-throughput scenarios
- Consider memory constraints for embedded targets

### Security
- Validate all incoming frames
- Implement proper connection lifecycle management
- Handle timeouts and connection failures gracefully

### Testing
- Test framing roundtrips
- Test connection lifecycle
- Test error conditions
- Test with different frame sizes

## Integration

### Add to Workspace

Update `Cargo.toml` in the workspace root:

```toml
[workspace]
members = [
    "core",
    "crypto",
    "identity",
    "transport",
    "transport-tcp",
    "transport-{protocol}",  # Add your transport
]
```

### Export from Transport Crate

Update `transport/src/lib.rs`:

```rust
#[cfg(feature = "{protocol}")]
pub use {protocol}_transport::{ProtocolTransport, ProtocolConfig};
```

## Existing Transport Examples

### TCP Transport (`clonic-transport-tcp`)
- Full implementation with TLS support
- Connection pooling and keepalive
- Backpressure and flow control
- Comprehensive test suite

### Key Lessons from TCP Implementation
- Use tokio for async operations
- Implement proper error handling
- Add comprehensive logging
- Support configuration options
- Provide benchmarks

## Testing Framework

### Mock Transport

Use the built-in mock transport for testing:

```rust
use clonic_transport::mock::MockTransport;

#[test]
fn test_with_mock() {
    let mut transport = MockTransport::new();
    transport.set_connect_result(Ok(()));
    transport.set_send_result(Ok(()));
    transport.set_recv_result(Ok(42));

    // Test your logic with predictable behavior
}
```

### Property-Based Testing

```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn test_framing_properties(frame in any::<Vec<u8>>()) {
        // Test framing invariants
        let valid = TransportFraming::validate_frame_size(frame.len());
        // ... property tests
    }
}
```

## Documentation Requirements

1. **Crate-level documentation**: Explain the transport protocol
2. **API documentation**: Document all public methods
3. **Examples**: Show common usage patterns
4. **Performance notes**: Include benchmarks
5. **Security considerations**: Document security properties

## Release Checklist

- [ ] All public APIs documented
- [ ] Comprehensive test suite
- [ ] Benchmarks included
- [ ] Error handling complete
- [ ] Integration tests pass
- [ ] Documentation examples work
- [ ] Added to workspace
- [ ] Published to crates.io

## Support

For questions about transport implementation:

1. Check existing implementations (`transport-tcp`)
2. Review the `Transport` trait documentation
3. Look at the framing utilities in `TransportFraming`
4. Join the Zluidr community discussions
