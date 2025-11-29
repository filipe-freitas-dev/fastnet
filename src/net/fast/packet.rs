//! Packet format and constants for the Rift protocol.
//!
//! # Packet Structure
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    Encrypted Packet                         │
//! ├────────────┬────────────────────────────────────────────────┤
//! │   Nonce    │              Ciphertext + Tag                  │
//! │  (8 bytes) │           (Header + Payload + 16)              │
//! └────────────┴────────────────────────────────────────────────┘
//!
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    Packet Header (12 bytes)                 │
//! ├──────────┬──────────┬──────────────┬───────┬───────┬────────┤
//! │ Sequence │   Ack    │ Ack Bitfield │ Flags │Channel│Fragment│
//! │ (2 bytes)│(2 bytes) │  (4 bytes)   │  (1)  │  (1)  │  (2)   │
//! └──────────┴──────────┴──────────────┴───────┴───────┴────────┘
//! ```

use std::io;

/// Maximum size of a single UDP packet (MTU-safe).
pub const MAX_PACKET_SIZE: usize = 1200;

/// Size of the packet header in bytes.
pub const HEADER_SIZE: usize = 12;

/// Maximum payload size per packet.
pub const MAX_PAYLOAD_SIZE: usize = MAX_PACKET_SIZE - HEADER_SIZE;

/// Maximum fragment payload size (with fragment header).
pub const MAX_FRAGMENT_SIZE: usize = MAX_PAYLOAD_SIZE - 4;

/// Packet flags indicating packet type and reliability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketFlag {
    None = 0,
    Reliable = 1 << 0,
    Fragment = 1 << 1,
    Connect = 1 << 2,
    ConnectAck = 1 << 3,
    Disconnect = 1 << 4,
    Ping = 1 << 5,
    Pong = 1 << 6,
}

#[derive(Clone, Copy, Debug)]
pub struct PacketHeader {
    pub sequence: u16,
    pub ack: u16,
    pub ack_bitfield: u32,
    pub flags: u8,
    pub channel: u8,
    pub fragment_id: u8,
    pub fragment_count: u8,
}

impl PacketHeader {
    #[inline]
    pub fn new(sequence: u16, channel: u8, flags: u8) -> Self {
        Self {
            sequence,
            ack: 0,
            ack_bitfield: 0,
            flags,
            channel,
            fragment_id: 0,
            fragment_count: 0,
        }
    }

    #[inline]
    pub fn is_reliable(&self) -> bool {
        self.flags & PacketFlag::Reliable as u8 != 0
    }

    #[inline]
    pub fn is_fragment(&self) -> bool {
        self.flags & PacketFlag::Fragment as u8 != 0
    }

    #[inline]
    pub fn is_connect(&self) -> bool {
        self.flags & PacketFlag::Connect as u8 != 0
    }

    #[inline]
    pub fn is_connect_ack(&self) -> bool {
        self.flags & PacketFlag::ConnectAck as u8 != 0
    }

    #[inline]
    pub fn is_disconnect(&self) -> bool {
        self.flags & PacketFlag::Disconnect as u8 != 0
    }

    #[inline]
    pub fn is_ping(&self) -> bool {
        self.flags & PacketFlag::Ping as u8 != 0
    }

    #[inline]
    pub fn is_pong(&self) -> bool {
        self.flags & PacketFlag::Pong as u8 != 0
    }

    #[inline]
    pub fn write_to(&self, buf: &mut [u8]) {
        buf[0..2].copy_from_slice(&self.sequence.to_le_bytes());
        buf[2..4].copy_from_slice(&self.ack.to_le_bytes());
        buf[4..8].copy_from_slice(&self.ack_bitfield.to_le_bytes());
        buf[8] = self.flags;
        buf[9] = self.channel;
        buf[10] = self.fragment_id;
        buf[11] = self.fragment_count;
    }

    #[inline]
    pub fn read_from(buf: &[u8]) -> io::Result<Self> {
        if buf.len() < HEADER_SIZE {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Packet too small"));
        }
        Ok(Self {
            sequence: u16::from_le_bytes([buf[0], buf[1]]),
            ack: u16::from_le_bytes([buf[2], buf[3]]),
            ack_bitfield: u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
            flags: buf[8],
            channel: buf[9],
            fragment_id: buf[10],
            fragment_count: buf[11],
        })
    }
}

pub struct PacketWriter<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl<'a> PacketWriter<'a> {
    #[inline]
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, len: HEADER_SIZE }
    }

    #[inline]
    pub fn header_mut(&mut self) -> &mut [u8] {
        &mut self.buf[..HEADER_SIZE]
    }

    #[inline]
    pub fn write_header(&mut self, header: &PacketHeader) {
        header.write_to(&mut self.buf[..HEADER_SIZE]);
    }

    #[inline]
    pub fn append(&mut self, data: &[u8]) -> usize {
        let available = self.buf.len() - self.len;
        let to_copy = data.len().min(available);
        self.buf[self.len..self.len + to_copy].copy_from_slice(&data[..to_copy]);
        self.len += to_copy;
        to_copy
    }

    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.buf[HEADER_SIZE..self.len]
    }

    #[inline]
    pub fn finish(self) -> usize {
        self.len
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

pub struct PacketReader<'a> {
    buf: &'a [u8],
}

impl<'a> PacketReader<'a> {
    #[inline]
    pub fn new(buf: &'a [u8]) -> io::Result<Self> {
        if buf.len() < HEADER_SIZE {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Packet too small"));
        }
        Ok(Self { buf })
    }

    #[inline]
    pub fn header(&self) -> io::Result<PacketHeader> {
        PacketHeader::read_from(self.buf)
    }

    #[inline]
    pub fn payload(&self) -> &[u8] {
        &self.buf[HEADER_SIZE..]
    }

    #[inline]
    pub fn raw(&self) -> &[u8] {
        self.buf
    }
}

pub struct Fragmenter {
    fragment_sequence: u8,
}

impl Fragmenter {
    pub fn new() -> Self {
        Self { fragment_sequence: 0 }
    }

    pub fn fragment<'a>(&mut self, data: &'a [u8]) -> FragmentIterator<'a> {
        let total = ((data.len() + MAX_FRAGMENT_SIZE - 1) / MAX_FRAGMENT_SIZE) as u8;
        let id = self.fragment_sequence;
        self.fragment_sequence = self.fragment_sequence.wrapping_add(1);

        FragmentIterator {
            data,
            fragment_id: id,
            fragment_count: total.max(1),
            current: 0,
        }
    }

    #[inline]
    pub fn needs_fragmentation(data: &[u8]) -> bool {
        data.len() > MAX_PAYLOAD_SIZE
    }
}

impl Default for Fragmenter {
    fn default() -> Self {
        Self::new()
    }
}

pub struct FragmentIterator<'a> {
    data: &'a [u8],
    fragment_id: u8,
    fragment_count: u8,
    current: u8,
}

impl<'a> Iterator for FragmentIterator<'a> {
    type Item = (u8, u8, u8, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        if self.current >= self.fragment_count {
            return None;
        }

        let start = self.current as usize * MAX_FRAGMENT_SIZE;
        let end = (start + MAX_FRAGMENT_SIZE).min(self.data.len());
        let chunk = &self.data[start..end];

        let result = (self.fragment_id, self.current, self.fragment_count, chunk);
        self.current += 1;
        Some(result)
    }
}

pub struct FragmentAssembler {
    fragments: Vec<Option<Vec<u8>>>,
    fragment_id: u8,
    expected_count: u8,
    received_count: u8,
}

impl FragmentAssembler {
    pub fn new(fragment_id: u8, fragment_count: u8) -> Self {
        Self {
            fragments: vec![None; fragment_count as usize],
            fragment_id,
            expected_count: fragment_count,
            received_count: 0,
        }
    }

    pub fn add(&mut self, index: u8, data: &[u8]) -> bool {
        if index >= self.expected_count {
            return false;
        }

        let idx = index as usize;
        if self.fragments[idx].is_none() {
            self.fragments[idx] = Some(data.to_vec());
            self.received_count += 1;
        }

        self.received_count >= self.expected_count
    }

    pub fn reassemble(&self) -> Option<Vec<u8>> {
        if self.received_count < self.expected_count {
            return None;
        }

        let total_size: usize = self.fragments.iter()
            .filter_map(|f| f.as_ref())
            .map(|f| f.len())
            .sum();

        let mut result = Vec::with_capacity(total_size);
        for fragment in &self.fragments {
            if let Some(data) = fragment {
                result.extend_from_slice(data);
            }
        }

        Some(result)
    }

    #[inline]
    pub fn id(&self) -> u8 {
        self.fragment_id
    }

    #[inline]
    pub fn is_complete(&self) -> bool {
        self.received_count >= self.expected_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_roundtrip() {
        let mut buf = [0u8; HEADER_SIZE];
        let header = PacketHeader::new(1234, 2, PacketFlag::Reliable as u8);
        header.write_to(&mut buf);

        let parsed = PacketHeader::read_from(&buf).unwrap();
        assert_eq!(parsed.sequence, 1234);
        assert_eq!(parsed.channel, 2);
        assert!(parsed.is_reliable());
    }

    #[test]
    fn test_fragmentation() {
        let mut fragmenter = Fragmenter::new();
        let data = vec![0u8; MAX_FRAGMENT_SIZE * 3 + 100];

        let fragments: Vec<_> = fragmenter.fragment(&data).collect();
        assert_eq!(fragments.len(), 4);

        let mut assembler = FragmentAssembler::new(fragments[0].0, fragments[0].2);
        for (id, idx, _, chunk) in &fragments {
            let complete = assembler.add(*idx, chunk);
            if *idx == 3 {
                assert!(complete);
            }
        }

        let reassembled = assembler.reassemble().unwrap();
        assert_eq!(reassembled.len(), data.len());
    }
}
