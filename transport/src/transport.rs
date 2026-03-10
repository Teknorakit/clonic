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
    }

    impl MockTransport {
        /// Seed incoming frames for recv() to consume (FIFO).
        pub fn with_incoming(frames: Vec<Vec<u8>>) -> Self {
            Self {
                connected: false,
                incoming: frames,
                sent: Vec::new(),
            }
        }
    }

    impl Transport for MockTransport {
        fn connect(&mut self) -> Result<(), Error> {
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
    }
}

#[cfg(feature = "alloc")]
pub use mock::MockTransport;
