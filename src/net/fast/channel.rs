//! Channel types and message reliability handling.
//!
//! FastNet supports multiple channel types for different use cases:
//!
//! | Channel Type | Reliable | Ordered | Use Case |
//! |--------------|----------|---------|----------|
//! | Unreliable | ❌ | ❌ | Position updates, particles |
//! | UnreliableSequenced | ❌ | Latest | Input, voice chat |
//! | Reliable | ✅ | ❌ | Item pickups, damage events |
//! | ReliableOrdered | ✅ | ✅ | Chat, commands, state sync |

#![allow(dead_code)] // Internal API - some fields/methods reserved for future use

use std::collections::{VecDeque, HashMap};

use super::packet::{PacketFlag, Fragmenter, FragmentAssembler};

/// Channel reliability and ordering modes.
///
/// Choose the appropriate channel type based on your data requirements:
///
/// - **Unreliable**: Fire-and-forget. Fastest but may lose packets.
/// - **UnreliableSequenced**: Only processes the most recent packet, drops old ones.
/// - **Reliable**: Guaranteed delivery, but order may vary.
/// - **ReliableOrdered**: Guaranteed delivery in exact send order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ChannelType {
    /// No guarantees. Fast but may lose packets.
    Unreliable = 0,
    /// Only the latest packet is processed (older packets dropped).
    UnreliableSequenced = 1,
    /// Guaranteed delivery, but order may vary.
    Reliable = 2,
    /// Guaranteed delivery in exact order.
    ReliableOrdered = 3,
}

impl From<u8> for ChannelType {
    fn from(v: u8) -> Self {
        match v {
            0 => Self::Unreliable,
            1 => Self::UnreliableSequenced,
            2 => Self::Reliable,
            3 => Self::ReliableOrdered,
            _ => Self::Unreliable,
        }
    }
}

#[derive(Clone)]
pub struct PendingMessage {
    pub sequence: u16,
    pub data: Vec<u8>,
    pub send_time: std::time::Instant,
    pub send_count: u8,
    pub needs_ack: bool,
}

pub struct Channel {
    pub id: u8,
    pub channel_type: ChannelType,

    send_sequence: u16,
    pending_send: HashMap<u16, PendingMessage>,  // O(1) ACK lookup
    fragmenter: Fragmenter,

    recv_sequence: u16,
    last_recv_sequence: Option<u16>,
    recv_buffer: VecDeque<Vec<u8>>,
    reorder_buffer: Vec<Option<Vec<u8>>>,
    fragment_assemblers: Vec<FragmentAssembler>,

    max_pending: usize,
}

impl Channel {
    pub fn new(id: u8, channel_type: ChannelType) -> Self {
        Self {
            id,
            channel_type,
            send_sequence: 0,
            pending_send: HashMap::with_capacity(256),
            fragmenter: Fragmenter::new(),
            recv_sequence: 0,
            last_recv_sequence: None,
            recv_buffer: VecDeque::with_capacity(256),
            reorder_buffer: vec![None; 256],
            fragment_assemblers: Vec::new(),
            max_pending: 256,
        }
    }

    pub fn send(&mut self, data: Vec<u8>) -> Option<Vec<OutgoingPacket>> {
        if self.pending_send.len() >= self.max_pending {
            return None;
        }

        let needs_ack = matches!(self.channel_type, ChannelType::Reliable | ChannelType::ReliableOrdered);
        let mut packets = Vec::new();

        if Fragmenter::needs_fragmentation(&data) {
            for (frag_id, frag_idx, frag_count, chunk) in self.fragmenter.fragment(&data) {
                let seq = self.send_sequence;
                self.send_sequence = self.send_sequence.wrapping_add(1);

                let mut flags = PacketFlag::Fragment as u8;
                if needs_ack {
                    flags |= PacketFlag::Reliable as u8;
                }

                packets.push(OutgoingPacket {
                    sequence: seq,
                    channel: self.id,
                    flags,
                    fragment_id: frag_id,
                    fragment_count: frag_count,
                    fragment_index: frag_idx,
                    data: chunk.to_vec(),
                });

                if needs_ack {
                    self.pending_send.insert(seq, PendingMessage {
                        sequence: seq,
                        data: chunk.to_vec(),
                        send_time: std::time::Instant::now(),
                        send_count: 1,
                        needs_ack: true,
                    });
                }
            }
        } else {
            let seq = self.send_sequence;
            self.send_sequence = self.send_sequence.wrapping_add(1);

            let mut flags = 0u8;
            if needs_ack {
                flags |= PacketFlag::Reliable as u8;
            }

            packets.push(OutgoingPacket {
                sequence: seq,
                channel: self.id,
                flags,
                fragment_id: 0,
                fragment_count: 0,
                fragment_index: 0,
                data: data.clone(),
            });

            if needs_ack {
                self.pending_send.insert(seq, PendingMessage {
                    sequence: seq,
                    data,
                    send_time: std::time::Instant::now(),
                    send_count: 1,
                    needs_ack: true,
                });
            }
        }

        Some(packets)
    }

    pub fn receive(&mut self, sequence: u16, is_fragment: bool,
                   fragment_id: u8, fragment_index: u8, fragment_count: u8,
                   data: &[u8]) -> Option<Vec<u8>> {

        if is_fragment {
            return self.handle_fragment(fragment_id, fragment_index, fragment_count, data);
        }

        match self.channel_type {
            ChannelType::Unreliable => {

                Some(data.to_vec())
            }

            ChannelType::UnreliableSequenced => {

                let dominated = self.last_recv_sequence
                    .map(|last| !sequence_greater_than(sequence, last))
                    .unwrap_or(false);

                if dominated {
                    None
                } else {
                    self.last_recv_sequence = Some(sequence);
                    Some(data.to_vec())
                }
            }

            ChannelType::Reliable => {

                Some(data.to_vec())
            }

            ChannelType::ReliableOrdered => {

                self.handle_ordered(sequence, data)
            }
        }
    }

    fn handle_fragment(&mut self, fragment_id: u8, fragment_index: u8,
                       fragment_count: u8, data: &[u8]) -> Option<Vec<u8>> {

        let assembler_idx = self.fragment_assemblers.iter()
            .position(|a| a.id() == fragment_id);

        let idx = match assembler_idx {
            Some(i) => i,
            None => {
                self.fragment_assemblers.push(
                    FragmentAssembler::new(fragment_id, fragment_count)
                );
                self.fragment_assemblers.len() - 1
            }
        };

        let complete = self.fragment_assemblers[idx].add(fragment_index, data);

        if complete {
            let result = self.fragment_assemblers[idx].reassemble();
            self.fragment_assemblers.remove(idx);

            if let Some(full_data) = result {
                match self.channel_type {
                    ChannelType::UnreliableSequenced => {

                        Some(full_data)
                    }
                    _ => Some(full_data),
                }
            } else {
                None
            }
        } else {
            None
        }
    }

    fn handle_ordered(&mut self, sequence: u16, data: &[u8]) -> Option<Vec<u8>> {
        let expected = self.recv_sequence;

        if sequence == expected {

            self.recv_sequence = self.recv_sequence.wrapping_add(1);

            while let Some(buffered) = self.reorder_buffer[self.recv_sequence as usize % 256].take() {
                self.recv_buffer.push_back(buffered);
                self.recv_sequence = self.recv_sequence.wrapping_add(1);
            }

            Some(data.to_vec())
        } else if sequence_greater_than(sequence, expected) {

            let idx = sequence as usize % 256;
            self.reorder_buffer[idx] = Some(data.to_vec());
            None
        } else {

            None
        }
    }

    #[inline]
    pub fn recv(&mut self) -> Option<Vec<u8>> {
        self.recv_buffer.pop_front()
    }

    /// O(1) ACK - removes pending message by sequence number.
    #[inline]
    pub fn ack(&mut self, sequence: u16) {
        self.pending_send.remove(&sequence);
    }

    pub fn process_ack_bitfield(&mut self, ack: u16, bitfield: u32) {
        self.ack(ack);

        for i in 0..32 {
            if bitfield & (1 << i) != 0 {
                let seq = ack.wrapping_sub(i + 1);
                self.ack(seq);
            }
        }
    }

    /// Get messages that need retransmission.
    pub fn get_retransmissions(&self, rto: std::time::Duration) -> impl Iterator<Item = &PendingMessage> {
        let now = std::time::Instant::now();
        self.pending_send.values()
            .filter(move |msg| msg.needs_ack && now.duration_since(msg.send_time) > rto)
    }

    /// O(1) mark retransmitted by sequence.
    #[inline]
    pub fn mark_retransmitted(&mut self, sequence: u16) {
        if let Some(msg) = self.pending_send.get_mut(&sequence) {
            msg.send_time = std::time::Instant::now();
            msg.send_count += 1;
        }
    }

    #[inline]
    pub fn pending_count(&self) -> usize {
        self.pending_send.len()
    }

    #[inline]
    pub fn next_sequence(&self) -> u16 {
        self.send_sequence
    }
}

pub struct OutgoingPacket {
    pub sequence: u16,
    pub channel: u8,
    pub flags: u8,
    pub fragment_id: u8,
    pub fragment_count: u8,
    pub fragment_index: u8,
    pub data: Vec<u8>,
}

#[inline]
pub fn sequence_greater_than(s1: u16, s2: u16) -> bool {
    let diff = s1.wrapping_sub(s2);
    diff > 0 && diff < 32768
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unreliable_channel() {
        let mut ch = Channel::new(0, ChannelType::Unreliable);

        let packets = ch.send(vec![1, 2, 3]).unwrap();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].data, vec![1, 2, 3]);

        let msg = ch.receive(0, false, 0, 0, 0, &[4, 5, 6]);
        assert_eq!(msg, Some(vec![4, 5, 6]));
    }

    #[test]
    fn test_reliable_ordered() {
        let mut ch = Channel::new(0, ChannelType::ReliableOrdered);

        let r1 = ch.receive(1, false, 0, 0, 0, &[2]);
        let r0 = ch.receive(0, false, 0, 0, 0, &[1]);

        assert!(r1.is_none());
        assert_eq!(r0, Some(vec![1]));

        let buffered = ch.recv();
        assert_eq!(buffered, Some(vec![2]));
    }

    #[test]
    fn test_sequence_comparison() {
        assert!(sequence_greater_than(1, 0));
        assert!(sequence_greater_than(100, 50));
        assert!(!sequence_greater_than(50, 100));

        assert!(sequence_greater_than(0, 65535));
        assert!(!sequence_greater_than(65535, 0));
    }
}
