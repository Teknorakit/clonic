//! TCP transport implementation.

/// TCP transport for ZCP messages.
///
/// Handles async TCP connections with two-phase framing per ZCP spec.
pub struct TcpTransport {
    // TODO: Implement TCP transport with tokio
    // - Connection management
    // - Two-phase framing (read 42B, peek length, read payload+MAC)
    // - TLS support
    // - Connection pooling
    // - Keepalive and backpressure
}

impl TcpTransport {
    /// Create new TCP transport.
    pub fn new() -> Self {
        TcpTransport {}
    }
}

impl Default for TcpTransport {
    fn default() -> Self {
        Self::new()
    }
}
