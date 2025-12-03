//! Real-time network metrics and telemetry.
//!
//! This module provides low-overhead metrics collection for monitoring
//! network performance, debugging issues, and adaptive algorithms.
//!
//! # Collected Metrics
//!
//! - **Latency**: RTT, jitter, min/max/avg
//! - **Throughput**: Bytes/packets per second
//! - **Reliability**: Packet loss rate, retransmissions
//! - **Connection**: State, uptime, peers
//!
//! # Example
//!
//! ```rust,ignore
//! use fastnet::net::fast::metrics::ConnectionMetrics;
//!
//! let mut metrics = ConnectionMetrics::new();
//!
//! // Record events
//! metrics.record_sent(100);
//! metrics.record_received(100);
//! metrics.record_rtt(Duration::from_micros(150));
//!
//! // Get snapshot
//! let snapshot = metrics.snapshot();
//! println!("RTT: {:?}, Loss: {:.2}%", snapshot.rtt_avg, snapshot.loss_percent);
//! ```

use std::time::{Duration, Instant};

/// Window size for sliding averages (in samples).
const WINDOW_SIZE: usize = 100;

/// Sliding window for computing statistics.
#[derive(Clone)]
struct SlidingWindow {
    values: [u32; WINDOW_SIZE],
    index: usize,
    count: usize,
    sum: u64,
}

impl SlidingWindow {
    const fn new() -> Self {
        Self {
            values: [0; WINDOW_SIZE],
            index: 0,
            count: 0,
            sum: 0,
        }
    }

    #[inline]
    fn push(&mut self, value: u32) {
        // Remove old value from sum
        if self.count == WINDOW_SIZE {
            self.sum -= self.values[self.index] as u64;
        } else {
            self.count += 1;
        }

        // Add new value
        self.values[self.index] = value;
        self.sum += value as u64;
        self.index = (self.index + 1) % WINDOW_SIZE;
    }

    #[inline]
    fn average(&self) -> u32 {
        if self.count == 0 {
            0
        } else {
            (self.sum / self.count as u64) as u32
        }
    }

    #[inline]
    fn min(&self) -> u32 {
        self.values[..self.count.min(WINDOW_SIZE)]
            .iter()
            .copied()
            .min()
            .unwrap_or(0)
    }

    #[inline]
    fn max(&self) -> u32 {
        self.values[..self.count.min(WINDOW_SIZE)]
            .iter()
            .copied()
            .max()
            .unwrap_or(0)
    }
}

impl Default for SlidingWindow {
    fn default() -> Self {
        Self::new()
    }
}

/// Metrics snapshot at a point in time.
#[derive(Debug, Clone, Default)]
pub struct MetricsSnapshot {
    /// Average RTT in microseconds.
    pub rtt_avg_us: u32,
    /// Minimum RTT in microseconds.
    pub rtt_min_us: u32,
    /// Maximum RTT in microseconds.
    pub rtt_max_us: u32,
    /// Jitter (RTT variance) in microseconds.
    pub jitter_us: u32,
    /// Total bytes sent.
    pub bytes_sent: u64,
    /// Total bytes received.
    pub bytes_received: u64,
    /// Total packets sent.
    pub packets_sent: u64,
    /// Total packets received.
    pub packets_received: u64,
    /// Packets lost (sent but not acked).
    pub packets_lost: u64,
    /// Packet loss percentage.
    pub loss_percent: f32,
    /// Packets retransmitted.
    pub retransmissions: u64,
    /// Current send rate (bytes/sec).
    pub send_rate_bps: u64,
    /// Current receive rate (bytes/sec).
    pub recv_rate_bps: u64,
    /// Connection uptime.
    pub uptime: Duration,
}

/// Per-connection metrics collector.
pub struct ConnectionMetrics {
    /// RTT samples.
    rtt_window: SlidingWindow,
    /// Last RTT for jitter calculation.
    last_rtt_us: u32,
    /// Jitter (smoothed RTT variance).
    jitter_us: u32,
    
    /// Total bytes sent.
    bytes_sent: u64,
    /// Total bytes received.
    bytes_received: u64,
    /// Total packets sent.
    packets_sent: u64,
    /// Total packets received.
    packets_received: u64,
    /// Packets lost.
    packets_lost: u64,
    /// Retransmissions.
    retransmissions: u64,

    /// Bytes sent in current second.
    send_rate_current: u64,
    /// Bytes received in current second.
    recv_rate_current: u64,
    /// Last rate calculation time.
    rate_last_update: Instant,
    /// Computed send rate.
    send_rate_bps: u64,
    /// Computed receive rate.
    recv_rate_bps: u64,

    /// Connection start time.
    connected_at: Instant,
}

impl ConnectionMetrics {
    /// Create new metrics collector.
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            rtt_window: SlidingWindow::new(),
            last_rtt_us: 0,
            jitter_us: 0,
            bytes_sent: 0,
            bytes_received: 0,
            packets_sent: 0,
            packets_received: 0,
            packets_lost: 0,
            retransmissions: 0,
            send_rate_current: 0,
            recv_rate_current: 0,
            rate_last_update: now,
            send_rate_bps: 0,
            recv_rate_bps: 0,
            connected_at: now,
        }
    }

    /// Record a sent packet.
    #[inline]
    pub fn record_sent(&mut self, bytes: usize) {
        self.bytes_sent += bytes as u64;
        self.packets_sent += 1;
        self.send_rate_current += bytes as u64;
        self.maybe_update_rate();
    }

    /// Record a received packet.
    #[inline]
    pub fn record_received(&mut self, bytes: usize) {
        self.bytes_received += bytes as u64;
        self.packets_received += 1;
        self.recv_rate_current += bytes as u64;
        self.maybe_update_rate();
    }

    /// Record an RTT measurement.
    #[inline]
    pub fn record_rtt(&mut self, rtt: Duration) {
        let rtt_us = rtt.as_micros() as u32;
        
        // Update jitter (RFC 3550)
        if self.last_rtt_us > 0 {
            let diff = (rtt_us as i32 - self.last_rtt_us as i32).unsigned_abs();
            self.jitter_us = self.jitter_us + (diff.saturating_sub(self.jitter_us)) / 16;
        }
        self.last_rtt_us = rtt_us;

        self.rtt_window.push(rtt_us);
    }

    /// Record a lost packet.
    #[inline]
    pub fn record_loss(&mut self) {
        self.packets_lost += 1;
    }

    /// Record a retransmission.
    #[inline]
    pub fn record_retransmission(&mut self) {
        self.retransmissions += 1;
    }

    /// Get current RTT average.
    #[inline]
    pub fn rtt_avg(&self) -> Duration {
        Duration::from_micros(self.rtt_window.average() as u64)
    }

    /// Get current jitter.
    #[inline]
    pub fn jitter(&self) -> Duration {
        Duration::from_micros(self.jitter_us as u64)
    }

    /// Get packet loss percentage.
    #[inline]
    pub fn loss_percent(&self) -> f32 {
        if self.packets_sent == 0 {
            0.0
        } else {
            (self.packets_lost as f32 / self.packets_sent as f32) * 100.0
        }
    }

    /// Get current send rate in bytes/sec.
    #[inline]
    pub fn send_rate(&self) -> u64 {
        self.send_rate_bps
    }

    /// Get current receive rate in bytes/sec.
    #[inline]
    pub fn recv_rate(&self) -> u64 {
        self.recv_rate_bps
    }

    /// Get a complete metrics snapshot.
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            rtt_avg_us: self.rtt_window.average(),
            rtt_min_us: self.rtt_window.min(),
            rtt_max_us: self.rtt_window.max(),
            jitter_us: self.jitter_us,
            bytes_sent: self.bytes_sent,
            bytes_received: self.bytes_received,
            packets_sent: self.packets_sent,
            packets_received: self.packets_received,
            packets_lost: self.packets_lost,
            loss_percent: self.loss_percent(),
            retransmissions: self.retransmissions,
            send_rate_bps: self.send_rate_bps,
            recv_rate_bps: self.recv_rate_bps,
            uptime: self.connected_at.elapsed(),
        }
    }

    /// Update rate calculations (called periodically).
    fn maybe_update_rate(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.rate_last_update);

        if elapsed >= Duration::from_secs(1) {
            let secs = elapsed.as_secs_f64();
            self.send_rate_bps = (self.send_rate_current as f64 / secs) as u64;
            self.recv_rate_bps = (self.recv_rate_current as f64 / secs) as u64;
            self.send_rate_current = 0;
            self.recv_rate_current = 0;
            self.rate_last_update = now;
        }
    }

    /// Reset all counters.
    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

impl Default for ConnectionMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Aggregate metrics across all connections.
#[derive(Debug, Clone, Default)]
pub struct AggregateMetrics {
    /// Number of active connections.
    pub connections: usize,
    /// Total bytes sent across all connections.
    pub total_bytes_sent: u64,
    /// Total bytes received across all connections.
    pub total_bytes_received: u64,
    /// Average RTT across all connections.
    pub avg_rtt_us: u32,
    /// Total packet loss rate.
    pub avg_loss_percent: f32,
    /// Total send rate.
    pub total_send_rate_bps: u64,
    /// Total receive rate.
    pub total_recv_rate_bps: u64,
}

/// Collector for aggregate metrics.
pub struct MetricsCollector {
    snapshots: Vec<MetricsSnapshot>,
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self {
            snapshots: Vec::new(),
        }
    }

    /// Update with snapshots from all connections.
    pub fn update(&mut self, snapshots: Vec<MetricsSnapshot>) {
        self.snapshots = snapshots;
    }

    /// Compute aggregate metrics.
    pub fn aggregate(&self) -> AggregateMetrics {
        if self.snapshots.is_empty() {
            return AggregateMetrics::default();
        }

        let n = self.snapshots.len();
        let mut agg = AggregateMetrics {
            connections: n,
            ..Default::default()
        };

        for s in &self.snapshots {
            agg.total_bytes_sent += s.bytes_sent;
            agg.total_bytes_received += s.bytes_received;
            agg.avg_rtt_us += s.rtt_avg_us;
            agg.avg_loss_percent += s.loss_percent;
            agg.total_send_rate_bps += s.send_rate_bps;
            agg.total_recv_rate_bps += s.recv_rate_bps;
        }

        agg.avg_rtt_us /= n as u32;
        agg.avg_loss_percent /= n as f32;

        agg
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sliding_window() {
        let mut w = SlidingWindow::new();

        w.push(10);
        w.push(20);
        w.push(30);

        assert_eq!(w.average(), 20);
        assert_eq!(w.min(), 10);
        assert_eq!(w.max(), 30);
    }

    #[test]
    fn test_connection_metrics() {
        let mut m = ConnectionMetrics::new();

        m.record_sent(100);
        m.record_sent(200);
        m.record_received(150);
        m.record_rtt(Duration::from_micros(100));
        m.record_rtt(Duration::from_micros(150));
        m.record_loss();

        let s = m.snapshot();
        assert_eq!(s.bytes_sent, 300);
        assert_eq!(s.bytes_received, 150);
        assert_eq!(s.packets_sent, 2);
        assert_eq!(s.packets_lost, 1);
        assert!(s.loss_percent > 0.0);
    }

    #[test]
    fn test_jitter_calculation() {
        let mut m = ConnectionMetrics::new();

        // Consistent RTT = low jitter
        for _ in 0..10 {
            m.record_rtt(Duration::from_micros(100));
        }
        assert!(m.jitter().as_micros() < 10);

        // Variable RTT = higher jitter
        let mut m2 = ConnectionMetrics::new();
        m2.record_rtt(Duration::from_micros(50));
        m2.record_rtt(Duration::from_micros(150));
        m2.record_rtt(Duration::from_micros(50));
        m2.record_rtt(Duration::from_micros(150));
        assert!(m2.jitter().as_micros() > 0);
    }

    #[test]
    fn test_aggregate_metrics() {
        let mut collector = MetricsCollector::new();

        let snap1 = MetricsSnapshot {
            rtt_avg_us: 100,
            bytes_sent: 1000,
            ..Default::default()
        };
        let snap2 = MetricsSnapshot {
            rtt_avg_us: 200,
            bytes_sent: 2000,
            ..Default::default()
        };

        collector.update(vec![snap1, snap2]);
        let agg = collector.aggregate();

        assert_eq!(agg.connections, 2);
        assert_eq!(agg.total_bytes_sent, 3000);
        assert_eq!(agg.avg_rtt_us, 150);
    }
}
