//! TCP transport implementation.

use clonic_transport::config::TcpConfig;
use clonic_transport::transport::Transport;
use clonic_transport::Error;
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::runtime::Runtime;

/// TCP transport for ZCP messages (sync facade over tokio).
pub struct TcpTransport {
    cfg: TcpConfig,
    rt: Runtime,
    stream: Option<TcpStream>,
}

impl TcpTransport {
    /// Create new TCP transport from config.
    pub fn new(cfg: TcpConfig) -> Self {
        let rt = Runtime::new().expect("tokio runtime");
        Self {
            cfg,
            rt,
            stream: None,
        }
    }

    fn map_io_error(e: io::Error, send: bool) -> Error {
        match e.kind() {
            io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset => {
                if send {
                    Error::SendFailed
                } else {
                    Error::ReceiveFailed
                }
            }
            _ => {
                if send {
                    Error::SendFailed
                } else {
                    Error::ReceiveFailed
                }
            }
        }
    }
}

impl Transport for TcpTransport {
    fn connect(&mut self) -> Result<(), Error> {
        let addr = format!("{}:{}", self.cfg.host, self.cfg.port);
        let stream = self
            .rt
            .block_on(TcpStream::connect(addr))
            .map_err(|_| Error::ConnectionFailed)?;
        self.stream = Some(stream);
        Ok(())
    }

    fn disconnect(&mut self) -> Result<(), Error> {
        self.stream.take();
        Ok(())
    }

    fn send(&mut self, frame: &[u8]) -> Result<(), Error> {
        let stream = self.stream.as_mut().ok_or(Error::NotInitialized)?;
        self.rt
            .block_on(async {
                // Validate frame using two-phase framing protocol
                if frame.len() < 42 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "frame too short",
                    ));
                }

                let declared_len = u16::from_be_bytes([frame[0], frame[1]]) as usize;
                if declared_len != frame.len() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "frame length mismatch",
                    ));
                }

                // Write to TCP stream
                stream.write_all(frame).await?;
                stream.flush().await
            })
            .map_err(|e| Self::map_io_error(e, true))
    }

    fn recv(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        let stream = self.stream.as_mut().ok_or(Error::NotInitialized)?;
        self.rt
            .block_on(async {
                // Use two-phase framing for recv
                let mut frame_buf = Vec::new();
                let mut reader = tokio::io::BufReader::new(stream);

                // Read frame using two-phase protocol
                let frame_len = {
                    let mut header = [0u8; 42];
                    reader.read_exact(&mut header).await?;

                    // Peek frame length from header
                    let len = u16::from_be_bytes([header[0], header[1]]) as usize;
                    if len < 42 {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "invalid frame length",
                        ));
                    }

                    frame_buf.extend_from_slice(&header);
                    len
                };

                // Read remainder
                let remainder_len = frame_len - 42;
                let mut remainder = vec![0u8; remainder_len];
                reader.read_exact(&mut remainder).await?;
                frame_buf.extend_from_slice(&remainder);

                // Copy to caller's buffer
                let copy_len = std::cmp::min(buf.len(), frame_buf.len());
                buf[..copy_len].copy_from_slice(&frame_buf[..copy_len]);
                Ok(copy_len)
            })
            .map_err(|e| Self::map_io_error(e, false))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clonic_transport::Transport;
    use tokio::net::TcpListener;

    #[test]
    fn tcp_transport_send_recv_roundtrip() {
        let cfg = TcpConfig {
            host: "127.0.0.1".into(),
            port: 40124,
        };

        let rt = Runtime::new().unwrap();
        let listener = rt.block_on(TcpListener::bind("127.0.0.1:40124")).unwrap();

        // Spawn echo server
        rt.spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 1024];
            let n = socket.read(&mut buf).await.unwrap();
            socket.write_all(&buf[..n]).await.unwrap();
        });

        let mut client = TcpTransport::new(cfg);
        client.connect().unwrap();

        // Create a valid ZCP frame with 42-byte header + payload
        // Frame format: [2-byte length][40 bytes header][payload]
        let mut frame = vec![0u8; 42 + 5]; // 42-byte header + "hello"
        let frame_len = frame.len() as u16;
        frame[0] = (frame_len >> 8) as u8;
        frame[1] = frame_len as u8;
        frame[42..].copy_from_slice(b"hello");

        client.send(&frame).unwrap();
        let mut buf = [0u8; 256];
        let n = client.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], &frame[..]);
    }
}
