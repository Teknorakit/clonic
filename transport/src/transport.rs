//! Transport trait and mock harness for ZCP transports.

use crate::error::Error;

/// Core transport abstraction for ZCP frames.
pub trait Transport {
    /// Establish connection (idempotent if already connected).
    fn connect(&mut self) -> Result<(), Error>;

    /// Disconnect and release resources.
    fn disconnect(&mut self) -> Result<(), Error>;

    /// Send a full ZCP frame.
    fn send(&mut self, frame: &[u8]) -> Result<(), Error>;

    /// Receive into caller-provided buffer, returning number of bytes written.
    fn recv(&mut self, buf: &mut [u8]) -> Result<usize, Error>;
}

/// Connection retry policy with linear backoff in milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionPolicy {
    /// Maximum connection attempts (including the first). 0 means no retries.
    pub max_attempts: u8,
    /// Backoff increment in milliseconds between retries.
    pub backoff_ms: u32,
}

impl ConnectionPolicy {
    /// Create a new policy.
    pub const fn new(max_attempts: u8, backoff_ms: u32) -> Self {
        Self {
            max_attempts,
            backoff_ms,
        }
    }
}

/// Attempt to connect with retries and backoff.
pub fn connect_with_backoff<T: Transport>(
    transport: &mut T,
    policy: ConnectionPolicy,
    mut on_backoff: impl FnMut(u32),
) -> Result<(), Error> {
    let attempts = if policy.max_attempts == 0 {
        1
    } else {
        policy.max_attempts as usize
    };
    for i in 0..attempts {
        match transport.connect() {
            Ok(()) => return Ok(()),
            Err(_e) if i + 1 < attempts => {
                let delay = policy.backoff_ms.saturating_mul((i as u32) + 1);
                on_backoff(delay);
            }
            Err(e) => return Err(e),
        }
    }
    Err(Error::ConnectionFailed)
}

#[cfg(feature = "alloc")]
mod mock {
    use super::Transport;
    use crate::error::Error;
    use alloc::vec::Vec;

    /// In-memory mock transport for unit testing.
    #[derive(Default)]
    pub struct MockTransport {
        connected: bool,
        incoming: Vec<Vec<u8>>, // frames to be delivered on recv
        /// Frames sent via `send` (for inspection in tests)
        pub sent: Vec<Vec<u8>>, // frames sent via send
        connect_failures_remaining: u8,
    }

    impl MockTransport {
        /// Seed incoming frames for recv() to consume (FIFO).
        pub fn with_incoming(frames: Vec<Vec<u8>>) -> Self {
            Self {
                connected: false,
                incoming: frames,
                sent: Vec::new(),
                connect_failures_remaining: 0,
            }
        }

        /// Force the next N `connect` calls to fail with `ConnectionFailed`.
        pub fn with_connect_failures(mut self, failures: u8) -> Self {
            self.connect_failures_remaining = failures;
            self
        }
    }

    impl Transport for MockTransport {
        fn connect(&mut self) -> Result<(), Error> {
            if self.connect_failures_remaining > 0 {
                self.connect_failures_remaining -= 1;
                return Err(Error::ConnectionFailed);
            }
            self.connected = true;
            Ok(())
        }

        fn disconnect(&mut self) -> Result<(), Error> {
            self.connected = false;
            Ok(())
        }

        fn send(&mut self, frame: &[u8]) -> Result<(), Error> {
            if !self.connected {
                return Err(Error::NotInitialized);
            }
            self.sent.push(frame.to_vec());
            Ok(())
        }

        fn recv(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
            if !self.connected {
                return Err(Error::NotInitialized);
            }
            if self.incoming.is_empty() {
                return Err(Error::ReceiveFailed);
            }
            let frame = self.incoming.remove(0); // FIFO
            if frame.len() > buf.len() {
                return Err(Error::BufferTooSmall);
            }
            buf[..frame.len()].copy_from_slice(&frame);
            Ok(frame.len())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::super::{connect_with_backoff, ConnectionPolicy};
        use super::*;
        use alloc::vec;

        #[test]
        fn mock_transport_send_recv() {
            let incoming = vec![b"frame-a".to_vec(), b"frame-b".to_vec()];
            let mut t = MockTransport::with_incoming(incoming);
            t.connect().unwrap();

            t.send(b"outgoing").unwrap();
            t.send(b"another").unwrap();
            assert_eq!(t.sent.len(), 2);

            let mut buf = [0u8; 16];
            let n1 = t.recv(&mut buf).unwrap();
            assert_eq!(&buf[..n1], b"frame-a");
            let n2 = t.recv(&mut buf).unwrap();
            assert_eq!(&buf[..n2], b"frame-b");
        }

        #[test]
        fn mock_transport_errors_when_disconnected() {
            let mut t = MockTransport::default();
            let mut buf = [0u8; 8];
            assert!(t.send(b"no").is_err());
            assert!(t.recv(&mut buf).is_err());
        }

        #[test]
        fn connect_with_backoff_retries_until_success() {
            let mut t = MockTransport::default().with_connect_failures(2);
            let mut delays = alloc::vec::Vec::new();
            let policy = ConnectionPolicy::new(3, 50);
            connect_with_backoff(&mut t, policy, |d| delays.push(d)).unwrap();
            assert_eq!(delays, alloc::vec![50, 100]);
            assert!(t.connected);
        }
    }
}

#[cfg(feature = "alloc")]
pub use mock::MockTransport;
