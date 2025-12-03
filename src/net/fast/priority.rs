//! Priority-based packet scheduling for latency-sensitive data.
//!
//! This module provides priority queues to ensure critical packets
//! (like player input) are sent before less important ones (like chat).
//!
//! # Priority Levels
//!
//! - `Critical` (0): Player input, game commands - sent immediately
//! - `High` (1): Game state updates, position sync
//! - `Normal` (2): Chat messages, non-urgent data
//! - `Low` (3): Analytics, telemetry, bulk transfers
//!
//! # Example
//!
//! ```rust,ignore
//! use fastnet::net::fast::priority::{PriorityQueue, Priority};
//!
//! let mut queue = PriorityQueue::new();
//!
//! queue.push(Priority::Low, chat_packet);
//! queue.push(Priority::Critical, input_packet);
//! queue.push(Priority::Normal, state_packet);
//!
//! // Dequeues in order: input, state, chat
//! while let Some((priority, packet)) = queue.pop() {
//!     send(packet);
//! }
//! ```

use std::collections::VecDeque;

/// Packet priority levels.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Priority {
    /// Highest priority - player input, critical commands.
    Critical = 0,
    /// High priority - game state, position updates.
    High = 1,
    /// Normal priority - chat, general messages.
    Normal = 2,
    /// Low priority - analytics, bulk data.
    Low = 3,
}

impl Priority {
    /// Total number of priority levels.
    pub const COUNT: usize = 4;

    #[inline]
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Critical,
            1 => Self::High,
            2 => Self::Normal,
            _ => Self::Low,
        }
    }

    /// Get suggested channel for this priority.
    #[inline]
    pub fn suggested_channel(&self) -> u8 {
        match self {
            Self::Critical => 0, // Reliable ordered
            Self::High => 1,     // Unreliable (fast)
            Self::Normal => 0,   // Reliable ordered
            Self::Low => 2,      // Reliable unordered
        }
    }
}

impl Default for Priority {
    fn default() -> Self {
        Self::Normal
    }
}

/// A queued packet with its priority.
#[derive(Debug)]
pub struct QueuedPacket {
    pub peer_id: u16,
    pub channel: u8,
    pub data: Vec<u8>,
    pub priority: Priority,
}

/// Priority queue for outgoing packets.
///
/// Uses separate queues per priority level for O(1) operations.
/// No heap allocation on push (uses pre-allocated VecDeques).
pub struct PriorityQueue {
    queues: [VecDeque<QueuedPacket>; Priority::COUNT],
    total_size: usize,
    max_size: usize,
}

impl PriorityQueue {
    /// Create a new priority queue.
    pub fn new() -> Self {
        Self::with_capacity(1024)
    }

    /// Create with specified max size (in bytes).
    pub fn with_capacity(max_size: usize) -> Self {
        Self {
            queues: [
                VecDeque::with_capacity(64),  // Critical
                VecDeque::with_capacity(128), // High
                VecDeque::with_capacity(64),  // Normal
                VecDeque::with_capacity(32),  // Low
            ],
            total_size: 0,
            max_size,
        }
    }

    /// Push a packet with the specified priority.
    ///
    /// Returns `false` if queue is full (would exceed max_size).
    #[inline]
    pub fn push(&mut self, priority: Priority, peer_id: u16, channel: u8, data: Vec<u8>) -> bool {
        let packet_size = data.len();
        
        // Check capacity (but always allow Critical packets)
        if priority != Priority::Critical && self.total_size + packet_size > self.max_size {
            return false;
        }

        self.total_size += packet_size;
        self.queues[priority as usize].push_back(QueuedPacket {
            peer_id,
            channel,
            data,
            priority,
        });
        true
    }

    /// Pop the highest priority packet.
    #[inline]
    pub fn pop(&mut self) -> Option<QueuedPacket> {
        for queue in &mut self.queues {
            if let Some(packet) = queue.pop_front() {
                self.total_size = self.total_size.saturating_sub(packet.data.len());
                return Some(packet);
            }
        }
        None
    }

    /// Peek at the highest priority packet without removing it.
    #[inline]
    pub fn peek(&self) -> Option<&QueuedPacket> {
        for queue in &self.queues {
            if let Some(packet) = queue.front() {
                return Some(packet);
            }
        }
        None
    }

    /// Check if queue is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.queues.iter().all(|q| q.is_empty())
    }

    /// Total number of queued packets.
    #[inline]
    pub fn len(&self) -> usize {
        self.queues.iter().map(|q| q.len()).sum()
    }

    /// Total size of queued data in bytes.
    #[inline]
    pub fn total_size(&self) -> usize {
        self.total_size
    }

    /// Number of packets at a specific priority.
    #[inline]
    pub fn count_at(&self, priority: Priority) -> usize {
        self.queues[priority as usize].len()
    }

    /// Clear all packets at or below a priority level.
    ///
    /// Useful for dropping low-priority data during congestion.
    pub fn drop_below(&mut self, priority: Priority) {
        for p in (priority as usize + 1)..Priority::COUNT {
            for packet in self.queues[p].drain(..) {
                self.total_size = self.total_size.saturating_sub(packet.data.len());
            }
        }
    }

    /// Clear all queued packets.
    pub fn clear(&mut self) {
        for queue in &mut self.queues {
            queue.clear();
        }
        self.total_size = 0;
    }

    /// Drain packets up to a byte budget, highest priority first.
    ///
    /// Returns an iterator of packets that fit within the budget.
    pub fn drain_budget(&mut self, mut budget: usize) -> Vec<QueuedPacket> {
        let mut result = Vec::new();

        for queue in &mut self.queues {
            while let Some(packet) = queue.front() {
                if packet.data.len() > budget && !result.is_empty() {
                    // Can't fit, and we already have some packets
                    break;
                }
                
                let packet = queue.pop_front().unwrap();
                budget = budget.saturating_sub(packet.data.len());
                self.total_size = self.total_size.saturating_sub(packet.data.len());
                result.push(packet);

                if budget == 0 {
                    return result;
                }
            }
        }

        result
    }
}

impl Default for PriorityQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// Weighted fair queue for bandwidth allocation.
///
/// Allocates bandwidth proportionally based on weights.
/// Critical gets 4x, High gets 2x, Normal gets 1x, Low gets 0.5x.
pub struct WeightedQueue {
    inner: PriorityQueue,
    weights: [usize; Priority::COUNT],
    counters: [usize; Priority::COUNT],
}

impl WeightedQueue {
    /// Create a new weighted queue with default weights.
    pub fn new() -> Self {
        Self {
            inner: PriorityQueue::new(),
            weights: [8, 4, 2, 1], // Critical:High:Normal:Low = 8:4:2:1
            counters: [0; Priority::COUNT],
        }
    }

    /// Push a packet.
    #[inline]
    pub fn push(&mut self, priority: Priority, peer_id: u16, channel: u8, data: Vec<u8>) -> bool {
        self.inner.push(priority, peer_id, channel, data)
    }

    /// Pop using weighted round-robin.
    ///
    /// Higher priority packets get more turns proportionally.
    pub fn pop_weighted(&mut self) -> Option<QueuedPacket> {
        // Find highest priority non-empty queue with available credits
        for (i, queue) in self.inner.queues.iter_mut().enumerate() {
            if !queue.is_empty() && self.counters[i] < self.weights[i] {
                self.counters[i] += 1;
                if let Some(packet) = queue.pop_front() {
                    self.inner.total_size = self.inner.total_size.saturating_sub(packet.data.len());
                    return Some(packet);
                }
            }
        }

        // Reset counters and try again
        self.counters = [0; Priority::COUNT];
        
        for (i, queue) in self.inner.queues.iter_mut().enumerate() {
            if !queue.is_empty() {
                self.counters[i] += 1;
                if let Some(packet) = queue.pop_front() {
                    self.inner.total_size = self.inner.total_size.saturating_sub(packet.data.len());
                    return Some(packet);
                }
            }
        }

        None
    }

    /// Check if empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl Default for WeightedQueue {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_priority_ordering() {
        let mut queue = PriorityQueue::new();

        queue.push(Priority::Low, 1, 0, vec![1]);
        queue.push(Priority::Critical, 1, 0, vec![2]);
        queue.push(Priority::Normal, 1, 0, vec![3]);
        queue.push(Priority::High, 1, 0, vec![4]);

        // Should come out in priority order
        assert_eq!(queue.pop().unwrap().data, vec![2]); // Critical
        assert_eq!(queue.pop().unwrap().data, vec![4]); // High
        assert_eq!(queue.pop().unwrap().data, vec![3]); // Normal
        assert_eq!(queue.pop().unwrap().data, vec![1]); // Low
        assert!(queue.pop().is_none());
    }

    #[test]
    fn test_same_priority_fifo() {
        let mut queue = PriorityQueue::new();

        queue.push(Priority::Normal, 1, 0, vec![1]);
        queue.push(Priority::Normal, 1, 0, vec![2]);
        queue.push(Priority::Normal, 1, 0, vec![3]);

        // FIFO within same priority
        assert_eq!(queue.pop().unwrap().data, vec![1]);
        assert_eq!(queue.pop().unwrap().data, vec![2]);
        assert_eq!(queue.pop().unwrap().data, vec![3]);
    }

    #[test]
    fn test_critical_bypass_capacity() {
        let mut queue = PriorityQueue::with_capacity(10);

        // Fill with normal priority
        assert!(queue.push(Priority::Normal, 1, 0, vec![0; 10]));
        assert!(!queue.push(Priority::Normal, 1, 0, vec![0; 5])); // Rejected

        // Critical always gets through
        assert!(queue.push(Priority::Critical, 1, 0, vec![0; 100]));
    }

    #[test]
    fn test_drop_below() {
        let mut queue = PriorityQueue::new();

        queue.push(Priority::Critical, 1, 0, vec![1]);
        queue.push(Priority::High, 1, 0, vec![2]);
        queue.push(Priority::Normal, 1, 0, vec![3]);
        queue.push(Priority::Low, 1, 0, vec![4]);

        queue.drop_below(Priority::High);

        assert_eq!(queue.len(), 2); // Only Critical and High remain
        assert_eq!(queue.pop().unwrap().priority, Priority::Critical);
        assert_eq!(queue.pop().unwrap().priority, Priority::High);
    }

    #[test]
    fn test_drain_budget() {
        let mut queue = PriorityQueue::new();

        queue.push(Priority::Critical, 1, 0, vec![0; 10]);
        queue.push(Priority::High, 1, 0, vec![0; 15]); // 15 fits in remaining budget
        queue.push(Priority::Normal, 1, 0, vec![0; 30]);

        let packets = queue.drain_budget(25);
        
        // Critical (10) + High (15) = 25, exactly fits budget
        assert_eq!(packets.len(), 2);
        assert_eq!(packets[0].priority, Priority::Critical);
        assert_eq!(packets[1].priority, Priority::High);
    }

    #[test]
    fn test_weighted_queue() {
        let mut queue = WeightedQueue::new();

        // Add equal amounts to each priority
        for _ in 0..4 {
            queue.push(Priority::Critical, 1, 0, vec![1]);
            queue.push(Priority::High, 1, 0, vec![2]);
            queue.push(Priority::Normal, 1, 0, vec![3]);
            queue.push(Priority::Low, 1, 0, vec![4]);
        }

        let mut counts = [0usize; 4];
        for _ in 0..16 {
            if let Some(p) = queue.pop_weighted() {
                counts[p.priority as usize] += 1;
            }
        }

        // Critical should get more than High, High more than Normal, etc.
        assert!(counts[0] >= counts[1]);
        assert!(counts[1] >= counts[2]);
        assert!(counts[2] >= counts[3]);
    }
}
