//! Jitter buffer for smooth streaming playback.
//!
//! This module provides a jitter buffer that smooths out network timing
//! variations, essential for live streaming and voice/video in games.
//!
//! # How It Works
//!
//! Packets arrive with varying delays (jitter). The buffer:
//! 1. Holds packets for a target delay
//! 2. Reorders out-of-order packets
//! 3. Conceals lost packets (optional)
//! 4. Delivers at consistent intervals
//!
//! # Example
//!
//! ```rust,ignore
//! use fastnet::net::fast::jitter::JitterBuffer;
//! use std::time::Duration;
//!
//! // 50ms buffer for voice
//! let mut buffer = JitterBuffer::new(Duration::from_millis(50));
//!
//! // Receive packets
//! buffer.push(seq, timestamp, data);
//!
//! // Playback at regular intervals
//! loop {
//!     if let Some(packet) = buffer.pop() {
//!         play(packet);
//!     }
//!     sleep(Duration::from_millis(20)); // 50 fps
//! }
//! ```

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Maximum packets to buffer (prevents unbounded memory).
const MAX_BUFFER_SIZE: usize = 256;

/// A buffered packet awaiting playback.
#[derive(Debug)]
pub struct BufferedPacket {
    /// Sequence number for ordering.
    pub sequence: u32,
    /// Original timestamp from sender.
    pub timestamp: u32,
    /// Packet data.
    pub data: Vec<u8>,
    /// When this packet was received.
    pub received_at: Instant,
}

/// Jitter buffer statistics.
#[derive(Debug, Clone, Default)]
pub struct JitterStats {
    /// Packets received.
    pub received: u64,
    /// Packets played out.
    pub played: u64,
    /// Packets dropped (too late).
    pub dropped_late: u64,
    /// Packets dropped (duplicate).
    pub dropped_duplicate: u64,
    /// Packets concealed (interpolated).
    pub concealed: u64,
    /// Current jitter estimate in microseconds.
    pub jitter_us: u32,
    /// Current buffer depth in packets.
    pub buffer_depth: usize,
}

/// Adaptive jitter buffer for streaming media.
pub struct JitterBuffer {
    /// Buffered packets, sorted by sequence.
    buffer: VecDeque<BufferedPacket>,
    /// Target buffer delay.
    target_delay: Duration,
    /// Minimum buffer delay.
    min_delay: Duration,
    /// Maximum buffer delay.
    max_delay: Duration,
    /// Current adaptive delay.
    current_delay: Duration,
    /// Next expected sequence number.
    next_seq: u32,
    /// Has the buffer started playback?
    playing: bool,
    /// When playback started.
    play_start: Option<Instant>,
    /// Last played timestamp.
    last_played_ts: u32,
    /// Statistics.
    stats: JitterStats,
    /// Jitter estimation (exponential moving average).
    jitter_ema: f64,
    /// Last packet arrival time for jitter calc.
    last_arrival: Option<Instant>,
    /// Last packet timestamp for jitter calc.
    last_timestamp: Option<u32>,
}

impl JitterBuffer {
    /// Create a new jitter buffer with the specified target delay.
    pub fn new(target_delay: Duration) -> Self {
        Self {
            buffer: VecDeque::with_capacity(64),
            target_delay,
            min_delay: target_delay / 2,
            max_delay: target_delay * 3,
            current_delay: target_delay,
            next_seq: 0,
            playing: false,
            play_start: None,
            last_played_ts: 0,
            stats: JitterStats::default(),
            jitter_ema: 0.0,
            last_arrival: None,
            last_timestamp: None,
        }
    }

    /// Create with min/max delay bounds.
    pub fn with_bounds(target: Duration, min: Duration, max: Duration) -> Self {
        let mut jb = Self::new(target);
        jb.min_delay = min;
        jb.max_delay = max;
        jb
    }

    /// Push a packet into the buffer.
    ///
    /// Returns `true` if packet was accepted, `false` if dropped.
    pub fn push(&mut self, sequence: u32, timestamp: u32, data: Vec<u8>) -> bool {
        let now = Instant::now();
        self.stats.received += 1;

        // Update jitter estimate
        self.update_jitter(now, timestamp);

        // Check for duplicates
        if self.playing && self.seq_before(sequence, self.next_seq) {
            self.stats.dropped_duplicate += 1;
            return false;
        }

        // Check if too late (already past playback point)
        if self.playing {
            if let Some(start) = self.play_start {
                let elapsed = now.duration_since(start);
                let packet_time = self.ts_to_duration(timestamp, self.last_played_ts);
                if packet_time + self.current_delay < elapsed {
                    self.stats.dropped_late += 1;
                    return false;
                }
            }
        }

        // Check buffer capacity
        if self.buffer.len() >= MAX_BUFFER_SIZE {
            // Drop oldest
            self.buffer.pop_front();
        }

        let packet = BufferedPacket {
            sequence,
            timestamp,
            data,
            received_at: now,
        };

        // Insert in sequence order
        let pos = self.buffer.iter().position(|p| self.seq_before(sequence, p.sequence));
        match pos {
            Some(i) => self.buffer.insert(i, packet),
            None => self.buffer.push_back(packet),
        }

        self.stats.buffer_depth = self.buffer.len();
        true
    }

    /// Pop the next packet for playback.
    ///
    /// Returns `None` if no packet is ready yet.
    pub fn pop(&mut self) -> Option<BufferedPacket> {
        let now = Instant::now();

        // Start playback when buffer reaches target depth
        if !self.playing {
            if self.buffer.len() >= 3 {
                self.playing = true;
                self.play_start = Some(now);
                if let Some(first) = self.buffer.front() {
                    self.next_seq = first.sequence;
                    self.last_played_ts = first.timestamp;
                }
            } else {
                return None;
            }
        }

        // Check if we have the next expected packet
        if let Some(front) = self.buffer.front() {
            if front.sequence == self.next_seq {
                // Check if it's time to play
                let wait_time = front.received_at + self.current_delay;
                if now >= wait_time {
                    let packet = self.buffer.pop_front().unwrap();
                    self.next_seq = self.next_seq.wrapping_add(1);
                    self.last_played_ts = packet.timestamp;
                    self.stats.played += 1;
                    self.stats.buffer_depth = self.buffer.len();
                    self.adapt_delay();
                    return Some(packet);
                }
            } else if self.seq_before(self.next_seq, front.sequence) {
                // Missing packet(s) - skip and conceal
                self.stats.concealed += 1;
                self.next_seq = front.sequence;
            }
        }

        None
    }

    /// Get current statistics.
    #[inline]
    pub fn stats(&self) -> &JitterStats {
        &self.stats
    }

    /// Get current buffer delay.
    #[inline]
    pub fn current_delay(&self) -> Duration {
        self.current_delay
    }

    /// Get current buffer depth.
    #[inline]
    pub fn depth(&self) -> usize {
        self.buffer.len()
    }

    /// Reset the buffer.
    pub fn reset(&mut self) {
        self.buffer.clear();
        self.playing = false;
        self.play_start = None;
        self.next_seq = 0;
        self.current_delay = self.target_delay;
    }

    /// Update jitter estimation (RFC 3550 algorithm).
    fn update_jitter(&mut self, arrival: Instant, timestamp: u32) {
        if let (Some(last_arr), Some(last_ts)) = (self.last_arrival, self.last_timestamp) {
            let arrival_diff = arrival.duration_since(last_arr).as_micros() as i64;
            let ts_diff = timestamp.wrapping_sub(last_ts) as i64;
            
            // D = interarrival time difference
            let d = (arrival_diff - ts_diff).abs() as f64;
            
            // Exponential moving average: J = J + (|D| - J) / 16
            self.jitter_ema += (d - self.jitter_ema) / 16.0;
            self.stats.jitter_us = self.jitter_ema as u32;
        }

        self.last_arrival = Some(arrival);
        self.last_timestamp = Some(timestamp);
    }

    /// Adapt delay based on jitter.
    fn adapt_delay(&mut self) {
        // Increase delay if jitter is high, decrease if low
        let jitter_ms = self.jitter_ema / 1000.0;
        let target_ms = self.target_delay.as_millis() as f64;

        if jitter_ms > target_ms * 0.8 {
            // High jitter, increase delay
            let new_delay = self.current_delay + Duration::from_millis(5);
            self.current_delay = new_delay.min(self.max_delay);
        } else if jitter_ms < target_ms * 0.3 && self.buffer.len() > 5 {
            // Low jitter and buffer building up, decrease delay
            let new_delay = self.current_delay.saturating_sub(Duration::from_millis(2));
            self.current_delay = new_delay.max(self.min_delay);
        }
    }

    /// Check if seq a is before seq b (with wraparound).
    #[inline]
    fn seq_before(&self, a: u32, b: u32) -> bool {
        let diff = a.wrapping_sub(b) as i32;
        diff < 0
    }

    /// Convert timestamp difference to duration (assumes 1000 units/sec).
    #[inline]
    fn ts_to_duration(&self, ts: u32, base_ts: u32) -> Duration {
        let diff = ts.wrapping_sub(base_ts);
        Duration::from_millis(diff as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jitter_buffer_basic() {
        let mut jb = JitterBuffer::new(Duration::from_millis(50));

        // Push some packets
        assert!(jb.push(0, 0, vec![1]));
        assert!(jb.push(1, 20, vec![2]));
        assert!(jb.push(2, 40, vec![3]));

        // Buffer should be building
        assert_eq!(jb.depth(), 3);
    }

    #[test]
    fn test_jitter_buffer_ordering() {
        let mut jb = JitterBuffer::new(Duration::from_millis(10));

        // Push out of order
        jb.push(2, 40, vec![3]);
        jb.push(0, 0, vec![1]);
        jb.push(1, 20, vec![2]);

        // Should be reordered
        std::thread::sleep(Duration::from_millis(15));
        
        let p1 = jb.pop().unwrap();
        assert_eq!(p1.sequence, 0);
    }

    #[test]
    fn test_jitter_buffer_duplicate() {
        let mut jb = JitterBuffer::new(Duration::from_millis(10));

        jb.push(0, 0, vec![1]);
        jb.push(1, 20, vec![2]);
        jb.push(2, 40, vec![3]);

        std::thread::sleep(Duration::from_millis(15));
        jb.pop(); // seq 0

        // Try to push duplicate
        assert!(!jb.push(0, 0, vec![1]));
        assert_eq!(jb.stats().dropped_duplicate, 1);
    }

    #[test]
    fn test_jitter_stats() {
        let mut jb = JitterBuffer::new(Duration::from_millis(5));

        for i in 0..10 {
            jb.push(i, i * 20, vec![i as u8]);
        }

        assert_eq!(jb.stats().received, 10);
        assert!(jb.stats().buffer_depth > 0);
    }
}
