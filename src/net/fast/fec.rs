//! Forward Error Correction (FEC) for packet loss recovery.
//!
//! This module implements XOR-based parity encoding to recover lost packets
//! without retransmission. Critical for live streaming and real-time games.
//!
//! # Algorithm
//!
//! For every N data packets, we generate 1 parity packet containing the XOR
//! of all N packets. If any single packet is lost, it can be recovered by
//! XORing the parity with all received packets.
//!
//! # Example
//!
//! ```rust,ignore
//! use fastnet::net::fast::fec::{FecEncoder, FecDecoder};
//!
//! // Encoder: Generate parity every 4 packets
//! let mut encoder = FecEncoder::new(4);
//! for packet in packets {
//!     if let Some(parity) = encoder.add_packet(&packet) {
//!         send(parity); // Send parity packet
//!     }
//!     send(packet);
//! }
//!
//! // Decoder: Recover lost packets
//! let mut decoder = FecDecoder::new(4);
//! for packet in received {
//!     decoder.add_packet(seq, &packet);
//! }
//! if let Some(recovered) = decoder.try_recover() {
//!     process(recovered);
//! }
//! ```
//!
//! # Performance
//!
//! - Overhead: 1/N extra packets (25% for N=4)
//! - Recovery: Can recover 1 lost packet per group
//! - Latency: Zero additional latency (parity computed inline)

use std::collections::HashMap;

/// Maximum packet size for FEC operations.
pub const FEC_MAX_PACKET_SIZE: usize = 1200;

/// Default group size (4 data packets + 1 parity).
pub const DEFAULT_GROUP_SIZE: u8 = 4;

/// FEC packet type marker (first byte of packet).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FecPacketType {
    /// Regular data packet.
    Data = 0,
    /// Parity packet for recovery.
    Parity = 1,
}

impl FecPacketType {
    #[inline]
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Data),
            1 => Some(Self::Parity),
            _ => None,
        }
    }
}

/// FEC header prepended to each packet.
///
/// Layout (4 bytes):
/// - [0]: Packet type (0=data, 1=parity)
/// - [1]: Group size (N)
/// - [2-3]: Group ID (u16 LE)
#[derive(Debug, Clone, Copy)]
pub struct FecHeader {
    pub packet_type: FecPacketType,
    pub group_size: u8,
    pub group_id: u16,
    pub packet_index: u8, // 0..N-1 for data, N for parity
}

impl FecHeader {
    pub const SIZE: usize = 5;

    #[inline]
    pub fn write_to(&self, buf: &mut [u8]) {
        buf[0] = self.packet_type as u8;
        buf[1] = self.group_size;
        buf[2..4].copy_from_slice(&self.group_id.to_le_bytes());
        buf[4] = self.packet_index;
    }

    #[inline]
    pub fn read_from(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::SIZE {
            return None;
        }
        Some(Self {
            packet_type: FecPacketType::from_byte(buf[0])?,
            group_size: buf[1],
            group_id: u16::from_le_bytes([buf[2], buf[3]]),
            packet_index: buf[4],
        })
    }
}

/// FEC encoder that generates parity packets.
///
/// Zero-copy design: operates on fixed buffers.
pub struct FecEncoder {
    group_size: u8,
    current_group: u16,
    packets_in_group: u8,
    parity_buf: Box<[u8; FEC_MAX_PACKET_SIZE]>,
    max_len: usize,
}

impl FecEncoder {
    /// Create a new encoder with the specified group size.
    ///
    /// # Arguments
    ///
    /// * `group_size` - Number of data packets per parity packet (2-16)
    pub fn new(group_size: u8) -> Self {
        let group_size = group_size.clamp(2, 16);
        Self {
            group_size,
            current_group: 0,
            packets_in_group: 0,
            parity_buf: Box::new([0u8; FEC_MAX_PACKET_SIZE]),
            max_len: 0,
        }
    }

    /// Add a data packet and optionally receive the parity packet.
    ///
    /// Returns `Some((header, parity_len))` when the group is complete.
    /// Use `get_parity()` to access the parity data.
    #[inline]
    pub fn add_packet(&mut self, data: &[u8]) -> Option<(FecHeader, usize)> {
        let len = data.len().min(FEC_MAX_PACKET_SIZE);
        
        // XOR into parity buffer
        for i in 0..len {
            self.parity_buf[i] ^= data[i];
        }
        self.max_len = self.max_len.max(len);
        self.packets_in_group += 1;

        // Group complete?
        if self.packets_in_group >= self.group_size {
            let header = FecHeader {
                packet_type: FecPacketType::Parity,
                group_size: self.group_size,
                group_id: self.current_group,
                packet_index: self.group_size,
            };
            
            let parity_len = self.max_len;
            
            // Reset counters for next group
            self.packets_in_group = 0;
            self.current_group = self.current_group.wrapping_add(1);
            self.max_len = 0;
            
            Some((header, parity_len))
        } else {
            None
        }
    }

    /// Get the current parity buffer. Call after `add_packet` returns `Some`.
    /// The buffer will be cleared on next `add_packet` call.
    #[inline]
    pub fn get_parity(&self) -> &[u8] {
        &self.parity_buf[..]
    }

    /// Clear the parity buffer after sending. Must be called before next group.
    #[inline]
    pub fn clear_parity(&mut self, len: usize) {
        for i in 0..len.min(FEC_MAX_PACKET_SIZE) {
            self.parity_buf[i] = 0;
        }
    }

    /// Get the header for a data packet.
    #[inline]
    pub fn data_header(&self, packet_index: u8) -> FecHeader {
        FecHeader {
            packet_type: FecPacketType::Data,
            group_size: self.group_size,
            group_id: self.current_group,
            packet_index,
        }
    }

    /// Current packet index within the group.
    #[inline]
    pub fn current_index(&self) -> u8 {
        self.packets_in_group
    }

    /// Current group ID.
    #[inline]
    pub fn current_group(&self) -> u16 {
        self.current_group
    }
}

/// State for a single FEC group being decoded.
struct FecGroup {
    group_size: u8,
    received: u8, // Bitmask of received packets
    packets: Vec<Option<Vec<u8>>>, // Received packet data
    parity: Option<Vec<u8>>,
    max_len: usize,
}

impl FecGroup {
    fn new(group_size: u8) -> Self {
        Self {
            group_size,
            received: 0,
            packets: vec![None; group_size as usize],
            parity: None,
            max_len: 0,
        }
    }

    /// Check if we have all data packets.
    fn is_complete(&self) -> bool {
        let mask = (1u8 << self.group_size) - 1;
        (self.received & mask) == mask
    }

    /// Check if we can recover a missing packet.
    fn can_recover(&self) -> bool {
        if self.parity.is_none() {
            return false;
        }
        // Count missing packets
        let mask = (1u8 << self.group_size) - 1;
        let missing = (self.received & mask) ^ mask;
        missing.count_ones() == 1
    }

    /// Find the index of the missing packet.
    fn missing_index(&self) -> Option<u8> {
        let mask = (1u8 << self.group_size) - 1;
        let missing = (self.received & mask) ^ mask;
        if missing.count_ones() == 1 {
            Some(missing.trailing_zeros() as u8)
        } else {
            None
        }
    }
}

/// FEC decoder that recovers lost packets.
pub struct FecDecoder {
    group_size: u8,
    groups: HashMap<u16, FecGroup>,
    recovery_buf: Box<[u8; FEC_MAX_PACKET_SIZE]>,
    /// Maximum groups to track (prevents memory exhaustion).
    max_groups: usize,
}

impl FecDecoder {
    /// Create a new decoder.
    pub fn new(group_size: u8) -> Self {
        Self {
            group_size: group_size.clamp(2, 16),
            groups: HashMap::with_capacity(16),
            recovery_buf: Box::new([0u8; FEC_MAX_PACKET_SIZE]),
            max_groups: 64,
        }
    }

    /// Add a received packet (data or parity).
    ///
    /// Returns recovered packet data if recovery was possible.
    pub fn add_packet(&mut self, header: &FecHeader, data: &[u8]) -> Option<(u8, Vec<u8>)> {
        // Evict old groups if too many
        if self.groups.len() >= self.max_groups {
            self.evict_oldest();
        }

        let group = self.groups
            .entry(header.group_id)
            .or_insert_with(|| FecGroup::new(header.group_size));

        match header.packet_type {
            FecPacketType::Data => {
                if header.packet_index < group.group_size {
                    let idx = header.packet_index as usize;
                    if group.packets[idx].is_none() {
                        group.packets[idx] = Some(data.to_vec());
                        group.received |= 1 << header.packet_index;
                        group.max_len = group.max_len.max(data.len());
                    }
                }
            }
            FecPacketType::Parity => {
                if group.parity.is_none() {
                    group.parity = Some(data.to_vec());
                    group.max_len = group.max_len.max(data.len());
                }
            }
        }

        // Try recovery
        self.try_recover(header.group_id)
    }

    /// Attempt to recover a missing packet from a group.
    fn try_recover(&mut self, group_id: u16) -> Option<(u8, Vec<u8>)> {
        let group = self.groups.get(&group_id)?;
        
        if group.is_complete() {
            // All packets received, cleanup
            self.groups.remove(&group_id);
            return None;
        }

        if !group.can_recover() {
            return None;
        }

        let missing_idx = group.missing_index()?;
        let parity = group.parity.as_ref()?;

        // XOR all received packets with parity to recover missing
        self.recovery_buf[..group.max_len].copy_from_slice(&parity[..group.max_len.min(parity.len())]);
        
        for (i, pkt) in group.packets.iter().enumerate() {
            if i as u8 == missing_idx {
                continue;
            }
            if let Some(data) = pkt {
                for j in 0..data.len().min(group.max_len) {
                    self.recovery_buf[j] ^= data[j];
                }
            }
        }

        let recovered = self.recovery_buf[..group.max_len].to_vec();
        
        // Cleanup
        self.groups.remove(&group_id);
        
        Some((missing_idx, recovered))
    }

    /// Evict oldest groups to prevent unbounded memory growth.
    fn evict_oldest(&mut self) {
        if let Some(&oldest) = self.groups.keys().min() {
            self.groups.remove(&oldest);
        }
    }

    /// Clear all tracked groups.
    pub fn clear(&mut self) {
        self.groups.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fec_no_loss() {
        let mut encoder = FecEncoder::new(4);
        let mut decoder = FecDecoder::new(4);

        let packets: Vec<Vec<u8>> = (0..4)
            .map(|i| vec![i as u8; 100])
            .collect();

        for (i, pkt) in packets.iter().enumerate() {
            let header = encoder.data_header(i as u8);
            let recovered = decoder.add_packet(&header, pkt);
            assert!(recovered.is_none()); // No recovery needed

            if let Some((parity_header, parity_len)) = encoder.add_packet(pkt) {
                let parity_data = encoder.get_parity()[..parity_len].to_vec();
                encoder.clear_parity(parity_len);
                decoder.add_packet(&parity_header, &parity_data);
            }
        }
    }

    #[test]
    fn test_fec_single_loss_recovery() {
        let mut encoder = FecEncoder::new(4);
        let mut decoder = FecDecoder::new(4);

        let packets: Vec<Vec<u8>> = (0..4)
            .map(|i| vec![i as u8 + 1; 50])
            .collect();

        let lost_index = 2;

        // Encode and collect parity
        let mut parity_header = None;
        let mut parity_data = None;
        
        for pkt in packets.iter() {
            if let Some((h, len)) = encoder.add_packet(pkt) {
                parity_header = Some(h);
                parity_data = Some(encoder.get_parity()[..len].to_vec());
                encoder.clear_parity(len);
            }
        }

        // Decode: simulate losing packet 2
        for (i, pkt) in packets.iter().enumerate() {
            if i == lost_index {
                continue; // Lost!
            }
            let header = FecHeader {
                packet_type: FecPacketType::Data,
                group_size: 4,
                group_id: 0,
                packet_index: i as u8,
            };
            decoder.add_packet(&header, pkt);
        }

        // Add parity and expect recovery
        if let (Some(h), Some(d)) = (parity_header, parity_data) {
            let recovered = decoder.add_packet(&h, &d);
            assert!(recovered.is_some());
            let (idx, data) = recovered.unwrap();
            assert_eq!(idx, lost_index as u8);
            assert_eq!(data, packets[lost_index]);
        }
    }

    #[test]
    fn test_fec_header_roundtrip() {
        let header = FecHeader {
            packet_type: FecPacketType::Parity,
            group_size: 8,
            group_id: 12345,
            packet_index: 7,
        };

        let mut buf = [0u8; FecHeader::SIZE];
        header.write_to(&mut buf);

        let parsed = FecHeader::read_from(&buf).unwrap();
        assert_eq!(parsed.packet_type, header.packet_type);
        assert_eq!(parsed.group_size, header.group_size);
        assert_eq!(parsed.group_id, header.group_id);
        assert_eq!(parsed.packet_index, header.packet_index);
    }

    #[test]
    fn test_fec_multiple_groups() {
        let mut encoder = FecEncoder::new(2);
        let mut decoder = FecDecoder::new(2);

        // Group 1
        let p1 = vec![1u8; 10];
        let p2 = vec![2u8; 10];
        
        let h1 = encoder.data_header(0);
        decoder.add_packet(&h1, &p1);
        encoder.add_packet(&p1);
        
        let h2 = encoder.data_header(1);
        let (parity_h, parity_len) = encoder.add_packet(&p2).unwrap();
        let parity_d = encoder.get_parity()[..parity_len].to_vec();
        encoder.clear_parity(parity_len);
        decoder.add_packet(&h2, &p2);
        decoder.add_packet(&parity_h, &parity_d);

        // Group 2
        let p3 = vec![3u8; 10];
        let p4 = vec![4u8; 10];
        
        let _h3 = encoder.data_header(0);
        encoder.add_packet(&p3);
        // Simulate loss of p3
        
        let h4 = encoder.data_header(1);
        let (parity_h2, parity_len2) = encoder.add_packet(&p4).unwrap();
        let parity_d2 = encoder.get_parity()[..parity_len2].to_vec();
        encoder.clear_parity(parity_len2);
        decoder.add_packet(&h4, &p4);
        
        // Should recover p3
        let recovered = decoder.add_packet(&parity_h2, &parity_d2);
        assert!(recovered.is_some());
        let (idx, data) = recovered.unwrap();
        assert_eq!(idx, 0);
        assert_eq!(data, p3);
    }
}
