//! Delta compression for bandwidth-efficient state synchronization.
//!
//! This module provides delta encoding to send only the bytes that changed
//! between two states, dramatically reducing bandwidth for game state updates.
//!
//! # Algorithm
//!
//! Uses run-length encoding of differences:
//! - Scans for changed byte ranges
//! - Encodes as: [offset:u16][length:u16][data...]
//! - Multiple ranges packed sequentially
//!
//! # Example
//!
//! ```rust,ignore
//! use fastnet::net::fast::delta::{DeltaEncoder, DeltaDecoder};
//!
//! let mut encoder = DeltaEncoder::new();
//! let old_state = [0u8; 1000];
//! let new_state = /* slightly modified */;
//!
//! // Encode delta (typically 10-50 bytes instead of 1000)
//! let delta = encoder.encode(&old_state, &new_state);
//!
//! // Decode on receiver
//! let mut decoder = DeltaDecoder::new();
//! let mut reconstructed = old_state.clone();
//! decoder.apply(&delta, &mut reconstructed);
//! assert_eq!(reconstructed, new_state);
//! ```
//!
//! # Performance
//!
//! - Typical compression: 80-95% for game state
//! - Zero allocations in hot path (uses fixed buffers)
//! - O(n) encoding/decoding time

/// Maximum size for delta-encoded data.
pub const DELTA_MAX_SIZE: usize = 4096;

/// Minimum run of identical bytes to skip (tuned for typical game state).
const MIN_SKIP_RUN: usize = 4;

/// Delta encoding header.
/// 
/// Layout:
/// - [0-1]: Base sequence number (u16 LE) - which state this delta is relative to
/// - [2-3]: Total ranges count (u16 LE)
#[derive(Debug, Clone, Copy)]
pub struct DeltaHeader {
    pub base_seq: u16,
    pub range_count: u16,
}

impl DeltaHeader {
    pub const SIZE: usize = 4;

    #[inline]
    pub fn write_to(&self, buf: &mut [u8]) {
        buf[0..2].copy_from_slice(&self.base_seq.to_le_bytes());
        buf[2..4].copy_from_slice(&self.range_count.to_le_bytes());
    }

    #[inline]
    pub fn read_from(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::SIZE {
            return None;
        }
        Some(Self {
            base_seq: u16::from_le_bytes([buf[0], buf[1]]),
            range_count: u16::from_le_bytes([buf[2], buf[3]]),
        })
    }
}

/// A range of changed bytes.
#[derive(Debug, Clone, Copy)]
struct DeltaRange {
    offset: u16,
    length: u16,
}

impl DeltaRange {
    const SIZE: usize = 4;

    #[inline]
    fn write_to(&self, buf: &mut [u8]) {
        buf[0..2].copy_from_slice(&self.offset.to_le_bytes());
        buf[2..4].copy_from_slice(&self.length.to_le_bytes());
    }

    #[inline]
    fn read_from(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::SIZE {
            return None;
        }
        Some(Self {
            offset: u16::from_le_bytes([buf[0], buf[1]]),
            length: u16::from_le_bytes([buf[2], buf[3]]),
        })
    }
}

/// Delta encoder with zero-allocation hot path.
pub struct DeltaEncoder {
    buffer: Box<[u8; DELTA_MAX_SIZE]>,
    sequence: u16,
}

impl DeltaEncoder {
    /// Create a new delta encoder.
    pub fn new() -> Self {
        Self {
            buffer: Box::new([0u8; DELTA_MAX_SIZE]),
            sequence: 0,
        }
    }

    /// Encode the difference between old and new state.
    ///
    /// Returns the encoded delta and its length, or None if delta would be
    /// larger than the full state (in which case, send full state).
    ///
    /// # Arguments
    ///
    /// * `old` - Previous state (known to receiver)
    /// * `new` - New state to encode
    ///
    /// # Returns
    ///
    /// `Some((data, len))` if delta is smaller than full state, `None` otherwise.
    pub fn encode<'a>(&'a mut self, old: &[u8], new: &[u8]) -> Option<(&'a [u8], usize)> {
        if old.len() != new.len() || old.len() > u16::MAX as usize {
            return None;
        }

        let state_len = old.len();
        let mut write_pos = DeltaHeader::SIZE;
        let mut range_count: u16 = 0;

        let mut i = 0;
        while i < state_len {
            // Skip identical bytes
            while i < state_len && old[i] == new[i] {
                i += 1;
            }

            if i >= state_len {
                break;
            }

            // Found difference, scan for end of changed region
            let start = i;
            let mut end = i + 1;
            
            // Extend while different OR short identical runs (to coalesce nearby changes)
            while end < state_len {
                if old[end] != new[end] {
                    end += 1;
                } else {
                    // Check if there's another difference soon
                    let mut skip_end = end;
                    while skip_end < state_len && skip_end - end < MIN_SKIP_RUN && old[skip_end] == new[skip_end] {
                        skip_end += 1;
                    }
                    if skip_end < state_len && old[skip_end] != new[skip_end] {
                        // Coalesce
                        end = skip_end + 1;
                    } else {
                        break;
                    }
                }
            }

            let range_len = end - start;
            
            // Check if we have space
            let needed = DeltaRange::SIZE + range_len;
            if write_pos + needed > DELTA_MAX_SIZE {
                return None; // Delta too large
            }

            // Write range header
            let range = DeltaRange {
                offset: start as u16,
                length: range_len as u16,
            };
            range.write_to(&mut self.buffer[write_pos..]);
            write_pos += DeltaRange::SIZE;

            // Write changed data
            self.buffer[write_pos..write_pos + range_len].copy_from_slice(&new[start..end]);
            write_pos += range_len;

            range_count += 1;
            i = end;
        }

        // No changes?
        if range_count == 0 {
            return Some((&self.buffer[..DeltaHeader::SIZE], DeltaHeader::SIZE));
        }

        // Delta larger than full state? Send full state instead
        if write_pos >= state_len {
            return None;
        }

        // Write header
        let header = DeltaHeader {
            base_seq: self.sequence,
            range_count,
        };
        header.write_to(&mut self.buffer[..]);

        self.sequence = self.sequence.wrapping_add(1);

        Some((&self.buffer[..write_pos], write_pos))
    }

    /// Encode full state (when delta would be too large).
    ///
    /// Returns encoded data with a special marker indicating full state.
    pub fn encode_full<'a>(&'a mut self, state: &[u8]) -> Option<(&'a [u8], usize)> {
        if state.len() + DeltaHeader::SIZE > DELTA_MAX_SIZE {
            return None;
        }

        // Use range_count = 0xFFFF as marker for full state
        let header = DeltaHeader {
            base_seq: self.sequence,
            range_count: 0xFFFF,
        };
        header.write_to(&mut self.buffer[..]);

        self.buffer[DeltaHeader::SIZE..DeltaHeader::SIZE + state.len()].copy_from_slice(state);
        
        self.sequence = self.sequence.wrapping_add(1);

        let total = DeltaHeader::SIZE + state.len();
        Some((&self.buffer[..total], total))
    }

    /// Get current sequence number.
    #[inline]
    pub fn sequence(&self) -> u16 {
        self.sequence
    }

    /// Reset sequence counter.
    pub fn reset(&mut self) {
        self.sequence = 0;
    }
}

impl Default for DeltaEncoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Delta decoder that applies deltas to reconstruct state.
pub struct DeltaDecoder {
    last_applied_seq: u16,
}

impl DeltaDecoder {
    /// Create a new decoder.
    pub fn new() -> Self {
        Self {
            last_applied_seq: 0,
        }
    }

    /// Apply a delta to the current state.
    ///
    /// # Arguments
    ///
    /// * `delta` - Encoded delta data
    /// * `state` - State buffer to modify in-place
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, `Err` with description on failure.
    pub fn apply(&mut self, delta: &[u8], state: &mut [u8]) -> Result<(), &'static str> {
        let header = DeltaHeader::read_from(delta).ok_or("Invalid delta header")?;
        
        // Full state marker
        if header.range_count == 0xFFFF {
            let data = &delta[DeltaHeader::SIZE..];
            if data.len() != state.len() {
                return Err("Full state size mismatch");
            }
            state.copy_from_slice(data);
            self.last_applied_seq = header.base_seq;
            return Ok(());
        }

        let mut read_pos = DeltaHeader::SIZE;

        for _ in 0..header.range_count {
            if read_pos + DeltaRange::SIZE > delta.len() {
                return Err("Truncated delta range header");
            }

            let range = DeltaRange::read_from(&delta[read_pos..]).ok_or("Invalid range")?;
            read_pos += DeltaRange::SIZE;

            let offset = range.offset as usize;
            let length = range.length as usize;

            if offset + length > state.len() {
                return Err("Delta range exceeds state bounds");
            }
            if read_pos + length > delta.len() {
                return Err("Truncated delta data");
            }

            state[offset..offset + length].copy_from_slice(&delta[read_pos..read_pos + length]);
            read_pos += length;
        }

        self.last_applied_seq = header.base_seq;
        Ok(())
    }

    /// Get last applied sequence number.
    #[inline]
    pub fn last_seq(&self) -> u16 {
        self.last_applied_seq
    }
}

impl Default for DeltaDecoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute compression ratio for a delta.
#[inline]
pub fn compression_ratio(original_size: usize, delta_size: usize) -> f32 {
    if original_size == 0 {
        return 0.0;
    }
    1.0 - (delta_size as f32 / original_size as f32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_delta_no_changes() {
        let mut encoder = DeltaEncoder::new();
        let mut decoder = DeltaDecoder::new();

        let state = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let (delta, len) = encoder.encode(&state, &state).unwrap();

        assert_eq!(len, DeltaHeader::SIZE); // Just header, no ranges

        let mut reconstructed = state;
        decoder.apply(&delta[..len], &mut reconstructed).unwrap();
        assert_eq!(reconstructed, state);
    }

    #[test]
    fn test_delta_single_byte_change() {
        let mut encoder = DeltaEncoder::new();
        let mut decoder = DeltaDecoder::new();

        let old = [0u8; 100];
        let mut new = old;
        new[50] = 0xFF;

        let (delta, len) = encoder.encode(&old, &new).unwrap();
        
        // Should be much smaller than 100 bytes
        assert!(len < 20);

        let mut reconstructed = old;
        decoder.apply(&delta[..len], &mut reconstructed).unwrap();
        assert_eq!(reconstructed, new);
    }

    #[test]
    fn test_delta_multiple_changes() {
        let mut encoder = DeltaEncoder::new();
        let mut decoder = DeltaDecoder::new();

        let old = [0u8; 200];
        let mut new = old;
        new[10..15].copy_from_slice(&[1, 2, 3, 4, 5]);
        new[100..105].copy_from_slice(&[6, 7, 8, 9, 10]);
        new[180..185].copy_from_slice(&[11, 12, 13, 14, 15]);

        let (delta, len) = encoder.encode(&old, &new).unwrap();
        
        // Much smaller than 200 bytes
        assert!(len < 50);
        
        let ratio = compression_ratio(200, len);
        assert!(ratio > 0.7); // At least 70% compression

        let mut reconstructed = old;
        decoder.apply(&delta[..len], &mut reconstructed).unwrap();
        assert_eq!(reconstructed, new);
    }

    #[test]
    fn test_delta_full_state_fallback() {
        let mut encoder = DeltaEncoder::new();
        let mut decoder = DeltaDecoder::new();

        // When everything changes, should return None
        let old = [0u8; 100];
        let new = [1u8; 100];

        let result = encoder.encode(&old, &new);
        assert!(result.is_none()); // Delta would be larger than state

        // Use full state encoding
        let (full, len) = encoder.encode_full(&new).unwrap();
        
        let mut reconstructed = old;
        decoder.apply(&full[..len], &mut reconstructed).unwrap();
        assert_eq!(reconstructed, new);
    }

    #[test]
    fn test_delta_header_roundtrip() {
        let header = DeltaHeader {
            base_seq: 12345,
            range_count: 42,
        };

        let mut buf = [0u8; DeltaHeader::SIZE];
        header.write_to(&mut buf);

        let parsed = DeltaHeader::read_from(&buf).unwrap();
        assert_eq!(parsed.base_seq, header.base_seq);
        assert_eq!(parsed.range_count, header.range_count);
    }

    #[test]
    fn test_delta_game_state_simulation() {
        let mut encoder = DeltaEncoder::new();
        let mut decoder = DeltaDecoder::new();

        // Simulate a game state: positions, health, etc.
        let old_state = vec![0u8; 1000];
        let mut new_state = old_state.clone();

        // Simulate player movement (position changes)
        new_state[0..12].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]); // pos
        new_state[100] = 95; // health changed

        let (delta, len) = encoder.encode(&old_state, &new_state).unwrap();
        
        let ratio = compression_ratio(1000, len);
        println!("Compression ratio: {:.1}%", ratio * 100.0);
        assert!(ratio > 0.9); // 90%+ compression

        let mut reconstructed = old_state.clone();
        decoder.apply(&delta[..len], &mut reconstructed).unwrap();
        assert_eq!(reconstructed, new_state);
    }
}
