//! Two-phase framing for ZCP messages.
//!
//! Implements the framing pattern from README.md:
//! 1. Read 42-byte header
//! 2. Peek frame length to get total size
//! 3. Read remaining payload + 16-byte MAC
//! 4. Parse envelope

use crate::error::Error;

/// Constants for ZCP framing (from clonic wire codec).
pub mod constants {
    /// ZCP header size (bytes)
    pub const HEADER_SIZE: usize = 42;
    /// ZCP MAC size (bytes)
    pub const MAC_SIZE: usize = 16;
    /// Minimum frame size (header + MAC, zero payload)
    pub const MIN_FRAME_SIZE: usize = HEADER_SIZE + MAC_SIZE;
}

/// Transport framing helper for ZCP messages.
pub struct TransportFraming;

impl TransportFraming {
    /// Extract payload length from 42-byte ZCP header.
    ///
    /// Payload length is stored at offset 38-41 (4 bytes, big-endian).
    ///
    /// # Arguments
    /// - `header`: Exactly 42 bytes of ZCP header
    ///
    /// # Returns
    /// (payload_length, total_frame_size)
    pub fn peek_frame_length(header: &[u8; constants::HEADER_SIZE]) -> Result<(u32, usize), Error> {
        if header.len() < 42 {
            return Err(Error::InvalidFrame);
        }

        // Payload length at offset 38-41, big-endian
        let payload_length = u32::from_be_bytes([
            header[38],
            header[39],
            header[40],
            header[41],
        ]);

        let total = constants::HEADER_SIZE + (payload_length as usize) + constants::MAC_SIZE;
        Ok((payload_length, total))
    }

    /// Validate frame size.
    pub fn validate_frame_size(size: usize) -> Result<(), Error> {
        if size < constants::MIN_FRAME_SIZE {
            return Err(Error::InvalidFrame);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peek_frame_length_zero_payload() {
        let mut header = [0u8; 42];
        // Payload length at offset 38-41: 0
        header[38] = 0;
        header[39] = 0;
        header[40] = 0;
        header[41] = 0;

        let (payload_len, total) = TransportFraming::peek_frame_length(&header).unwrap();
        assert_eq!(payload_len, 0);
        assert_eq!(total, constants::MIN_FRAME_SIZE);
    }

    #[test]
    fn peek_frame_length_256_bytes() {
        let mut header = [0u8; 42];
        // Payload length: 256 = 0x0100
        header[38] = 0x00;
        header[39] = 0x00;
        header[40] = 0x01;
        header[41] = 0x00;

        let (payload_len, total) = TransportFraming::peek_frame_length(&header).unwrap();
        assert_eq!(payload_len, 256);
        assert_eq!(total, 42 + 256 + 16);
    }

    #[test]
    fn validate_frame_size_valid() {
        assert!(TransportFraming::validate_frame_size(constants::MIN_FRAME_SIZE).is_ok());
        assert!(TransportFraming::validate_frame_size(1000).is_ok());
    }

    #[test]
    fn validate_frame_size_invalid() {
        assert!(TransportFraming::validate_frame_size(10).is_err());
    }
}
