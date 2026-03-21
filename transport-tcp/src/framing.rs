//! Two-phase framing for ZCP messages over TCP.
//!
//! Per ZCP spec:
//! 1. Read 42-byte header
//! 2. Peek frame length from header
//! 3. Read remainder (payload + MAC)

use std::io::{self, Read, Write};

/// ZCP frame header size in bytes.
pub const HEADER_SIZE: usize = 42;

/// Maximum frame payload size (excluding header and MAC).
pub const MAX_PAYLOAD_SIZE: usize = 65535;

/// Frame length field offset in header (in bytes).
const FRAME_LEN_OFFSET: usize = 0;

/// Frame length field size (2 bytes, big-endian u16).
const FRAME_LEN_SIZE: usize = 2;

/// Two-phase frame reader for TCP streams.
pub struct FrameReader;

impl FrameReader {
    /// Read a complete ZCP frame from a stream.
    ///
    /// Returns the full frame (header + payload + MAC) or an error.
    pub fn read_frame<R: Read>(reader: &mut R, buf: &mut Vec<u8>) -> io::Result<usize> {
        buf.clear();

        // Phase 1: Read 42-byte header
        let mut header = [0u8; HEADER_SIZE];
        reader.read_exact(&mut header)?;
        buf.extend_from_slice(&header);

        // Phase 2: Peek frame length from header
        let frame_len = Self::peek_frame_length(&header)?;

        // Validate frame length
        if frame_len < HEADER_SIZE || frame_len > HEADER_SIZE + MAX_PAYLOAD_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid frame length",
            ));
        }

        // Phase 3: Read remainder (payload + MAC)
        let remainder_len = frame_len - HEADER_SIZE;
        let mut remainder = vec![0u8; remainder_len];
        reader.read_exact(&mut remainder)?;
        buf.extend_from_slice(&remainder);

        Ok(frame_len)
    }

    /// Peek the frame length from a 42-byte header.
    ///
    /// Frame length is stored in the first 2 bytes (big-endian u16).
    fn peek_frame_length(header: &[u8; HEADER_SIZE]) -> io::Result<usize> {
        if header.len() < FRAME_LEN_OFFSET + FRAME_LEN_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "header too short",
            ));
        }

        let len_bytes = [
            header[FRAME_LEN_OFFSET],
            header[FRAME_LEN_OFFSET + 1],
        ];
        Ok(u16::from_be_bytes(len_bytes) as usize)
    }
}

/// Two-phase frame writer for TCP streams.
pub struct FrameWriter;

impl FrameWriter {
    /// Write a complete ZCP frame to a stream.
    ///
    /// Frame must be at least HEADER_SIZE bytes and contain valid frame length in header.
    pub fn write_frame<W: Write>(writer: &mut W, frame: &[u8]) -> io::Result<()> {
        if frame.len() < HEADER_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "frame too short",
            ));
        }

        // Verify frame length matches actual data
        let declared_len = u16::from_be_bytes([frame[0], frame[1]]) as usize;
        if declared_len != frame.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "frame length mismatch",
            ));
        }

        writer.write_all(frame)?;
        writer.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_frame_reader_valid_frame() {
        let mut frame = vec![0u8; 100];
        // Set frame length to 100 (big-endian u16)
        frame[0] = 0;
        frame[1] = 100;

        let mut cursor = Cursor::new(frame);
        let mut buf = Vec::new();
        let len = FrameReader::read_frame(&mut cursor, &mut buf).unwrap();

        assert_eq!(len, 100);
        assert_eq!(buf.len(), 100);
        assert_eq!(buf[0], 0);
        assert_eq!(buf[1], 100);
    }

    #[test]
    fn test_frame_reader_minimum_frame() {
        let mut frame = vec![0u8; HEADER_SIZE];
        // Set frame length to HEADER_SIZE (big-endian u16)
        frame[0] = 0;
        frame[1] = HEADER_SIZE as u8;

        let mut cursor = Cursor::new(frame);
        let mut buf = Vec::new();
        let len = FrameReader::read_frame(&mut cursor, &mut buf).unwrap();

        assert_eq!(len, HEADER_SIZE);
        assert_eq!(buf.len(), HEADER_SIZE);
    }

    #[test]
    fn test_frame_reader_with_payload() {
        let mut frame = vec![0u8; HEADER_SIZE + 50];
        // Set frame length to HEADER_SIZE + 50 (big-endian u16)
        let total_len = HEADER_SIZE + 50;
        frame[0] = (total_len >> 8) as u8;
        frame[1] = total_len as u8;

        let mut cursor = Cursor::new(frame);
        let mut buf = Vec::new();
        let len = FrameReader::read_frame(&mut cursor, &mut buf).unwrap();

        assert_eq!(len, total_len);
        assert_eq!(buf.len(), total_len);
    }

    #[test]
    fn test_frame_reader_invalid_length() {
        let mut frame = vec![0u8; HEADER_SIZE];
        // Set frame length to 10 (too small)
        frame[0] = 0;
        frame[1] = 10;

        let mut cursor = Cursor::new(frame);
        let mut buf = Vec::new();
        let result = FrameReader::read_frame(&mut cursor, &mut buf);

        assert!(result.is_err());
    }

    #[test]
    fn test_frame_writer_valid_frame() {
        let mut frame = vec![0u8; 100];
        // Set frame length to 100 (big-endian u16)
        frame[0] = 0;
        frame[1] = 100;

        let mut output = Vec::new();
        FrameWriter::write_frame(&mut output, &frame).unwrap();

        assert_eq!(output, frame);
    }

    #[test]
    fn test_frame_writer_length_mismatch() {
        let mut frame = vec![0u8; 100];
        // Set frame length to 50 (mismatch)
        frame[0] = 0;
        frame[1] = 50;

        let mut output = Vec::new();
        let result = FrameWriter::write_frame(&mut output, &frame);

        assert!(result.is_err());
    }

    #[test]
    fn test_frame_writer_too_short() {
        let frame = vec![0u8; 10];

        let mut output = Vec::new();
        let result = FrameWriter::write_frame(&mut output, &frame);

        assert!(result.is_err());
    }
}
