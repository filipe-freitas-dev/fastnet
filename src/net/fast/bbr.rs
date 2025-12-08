//! BBR (Bottleneck Bandwidth and Round-trip propagation time) Congestion Control.
//!
//! BBR is a model-based congestion control algorithm developed by Google that:
//! - Estimates bottleneck bandwidth (BtlBw) and minimum RTT (RTprop)
//! - Maintains low queue occupancy for minimal latency
//! - Probes for more bandwidth without causing excessive queuing
//!
//! This implementation is optimized for game networking where low latency is critical.
//!
//! ## Key Benefits over AIMD (TCP Reno style)
//!
//! - **Lower latency**: Keeps queues near-empty instead of filling them
//! - **Better bandwidth utilization**: Model-based instead of loss-based
//! - **Faster convergence**: Reaches optimal rate quickly
//! - **Fairness**: Works well alongside other flows

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Maximum packet size for calculations (MTU - headers).
const MAX_PACKET_SIZE: usize = 1200;

/// BBR probe bandwidth gain cycle (8 phases).
const PROBE_BW_GAIN_CYCLE: [f64; 8] = [1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0];

/// Startup gain - aggressive to quickly find bandwidth.
const STARTUP_GAIN: f64 = 2.885; // 2/ln(2)

/// Drain gain - quickly drain queues after startup.
const DRAIN_GAIN: f64 = 1.0 / STARTUP_GAIN;

/// Probe RTT duration.
const PROBE_RTT_DURATION: Duration = Duration::from_millis(200);

/// RTprop filter window (10 seconds).
const RTPROP_FILTER_LEN: Duration = Duration::from_secs(10);

/// BtlBw filter window (10 RTTs, approximated).
const BTLBW_FILTER_LEN: usize = 10;

/// Minimum congestion window (packets).
const MIN_CWND: u32 = 4;

/// Initial congestion window (packets).
const INITIAL_CWND: u32 = 10;

/// BBR operating state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BbrState {
    /// Exponential growth to find bandwidth.
    Startup,
    /// Drain queues after startup.
    Drain,
    /// Steady state - probe for bandwidth changes.
    ProbeBw,
    /// Periodically probe for lower RTT.
    ProbeRtt,
}

/// Windowed max filter for bandwidth estimation.
#[derive(Debug)]
struct MaxFilter {
    samples: VecDeque<(Instant, u64)>,
    window_len: usize,
}

impl MaxFilter {
    fn new(window_len: usize) -> Self {
        Self {
            samples: VecDeque::with_capacity(window_len),
            window_len,
        }
    }

    /// Add a sample and return the current max.
    fn update(&mut self, value: u64, now: Instant) -> u64 {
        // Remove old samples
        while self.samples.len() >= self.window_len {
            self.samples.pop_front();
        }

        // Remove samples smaller than current (they can never be max)
        while let Some(&(_, v)) = self.samples.back() {
            if v <= value {
                self.samples.pop_back();
            } else {
                break;
            }
        }

        self.samples.push_back((now, value));
        self.samples.front().map(|&(_, v)| v).unwrap_or(value)
    }

    /// Get current max value.
    #[inline]
    fn get(&self) -> u64 {
        self.samples.front().map(|&(_, v)| v).unwrap_or(0)
    }

    fn reset(&mut self) {
        self.samples.clear();
    }
}

/// Windowed min filter for RTT estimation.
#[derive(Debug)]
struct MinFilter {
    value: Duration,
    timestamp: Instant,
    window: Duration,
}

impl MinFilter {
    fn new(window: Duration) -> Self {
        Self {
            value: Duration::from_secs(1), // Start high
            timestamp: Instant::now(),
            window,
        }
    }

    /// Update with new RTT sample.
    fn update(&mut self, rtt: Duration, now: Instant) -> Duration {
        // Reset if window expired
        if now.duration_since(self.timestamp) > self.window {
            self.value = rtt;
            self.timestamp = now;
        } else if rtt <= self.value {
            self.value = rtt;
            self.timestamp = now;
        }
        self.value
    }

    #[inline]
    fn get(&self) -> Duration {
        self.value
    }

    fn expired(&self, now: Instant) -> bool {
        now.duration_since(self.timestamp) > self.window
    }
}

/// BBR congestion control state.
#[derive(Debug)]
pub struct BbrCongestionControl {
    // Core BBR model
    state: BbrState,
    btl_bw: MaxFilter,        // Bottleneck bandwidth (bytes/sec)
    rt_prop: MinFilter,       // Min RTT
    
    // Pacing
    pacing_rate: u64,         // bytes/sec
    pacing_gain: f64,
    cwnd_gain: f64,
    
    // Congestion window
    cwnd: u32,                // packets
    
    // Probe BW state
    cycle_index: usize,
    cycle_start: Instant,
    
    // Probe RTT state
    probe_rtt_done_stamp: Option<Instant>,
    probe_rtt_round_done: bool,
    
    // Tracking
    delivered: u64,           // Total bytes delivered
    delivered_time: Instant,
    last_delivered: u64,
    last_delivered_time: Instant,
    
    // Round counting
    round_count: u64,
    round_start: bool,
    next_round_delivered: u64,
    
    // Loss tracking
    loss_in_round: bool,
    
    // Full pipe detection (startup exit)
    filled_pipe: bool,
    full_bw: u64,
    full_bw_count: u32,
    
    // Inflight tracking
    inflight: u32,            // packets currently in flight
    
    // Startup/drain tracking
    startup_exit_time: Option<Instant>,
}

impl BbrCongestionControl {
    /// Create new BBR congestion control.
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            state: BbrState::Startup,
            btl_bw: MaxFilter::new(BTLBW_FILTER_LEN),
            rt_prop: MinFilter::new(RTPROP_FILTER_LEN),
            
            pacing_rate: 0,
            pacing_gain: STARTUP_GAIN,
            cwnd_gain: STARTUP_GAIN,
            
            cwnd: INITIAL_CWND,
            
            cycle_index: 0,
            cycle_start: now,
            
            probe_rtt_done_stamp: None,
            probe_rtt_round_done: false,
            
            delivered: 0,
            delivered_time: now,
            last_delivered: 0,
            last_delivered_time: now,
            
            round_count: 0,
            round_start: false,
            next_round_delivered: 0,
            
            loss_in_round: false,
            
            filled_pipe: false,
            full_bw: 0,
            full_bw_count: 0,
            
            inflight: 0,
            startup_exit_time: None,
        }
    }

    /// Called when a packet is sent.
    #[inline]
    pub fn on_send(&mut self, _bytes: usize) {
        self.inflight = self.inflight.saturating_add(1);
    }

    /// Called when an ACK is received.
    /// 
    /// # Parameters
    /// - `bytes_acked`: Number of bytes acknowledged
    /// - `rtt`: Measured round-trip time for this ACK
    pub fn on_ack(&mut self, bytes_acked: usize, rtt: Duration) {
        let now = Instant::now();
        
        self.inflight = self.inflight.saturating_sub(1);
        self.delivered += bytes_acked as u64;
        
        // Update RTprop
        self.rt_prop.update(rtt, now);
        
        // Calculate delivery rate
        let delivery_rate = self.calculate_delivery_rate(now);
        if delivery_rate > 0 {
            self.btl_bw.update(delivery_rate, now);
        }
        
        // Update round counting
        self.update_round(now);
        
        // Check for filled pipe (startup exit condition)
        self.check_full_pipe();
        
        // State machine
        match self.state {
            BbrState::Startup => self.update_startup(now),
            BbrState::Drain => self.update_drain(now),
            BbrState::ProbeBw => self.update_probe_bw(now),
            BbrState::ProbeRtt => self.update_probe_rtt(now),
        }
        
        // Update pacing rate and cwnd
        self.update_pacing_rate();
        self.update_cwnd();
        
        // Reset round tracking
        self.last_delivered = self.delivered;
        self.last_delivered_time = now;
        self.loss_in_round = false;
    }

    /// Called when packet loss is detected.
    pub fn on_loss(&mut self, _bytes_lost: usize) {
        self.inflight = self.inflight.saturating_sub(1);
        self.loss_in_round = true;
        
        // BBR doesn't react to loss the same way as AIMD
        // But we do note it for full pipe detection
    }

    /// Called on retransmission timeout.
    pub fn on_timeout(&mut self) {
        // BBR is more resilient to timeouts
        // Just reduce cwnd slightly
        self.cwnd = (self.cwnd / 2).max(MIN_CWND);
        self.inflight = 0;
    }

    /// Get available congestion window (packets that can be sent).
    #[inline]
    pub fn available_window(&self) -> usize {
        self.cwnd.saturating_sub(self.inflight) as usize
    }

    /// Get current congestion window size.
    #[inline]
    pub fn cwnd(&self) -> u32 {
        self.cwnd
    }

    /// Get current pacing rate in bytes/sec.
    #[inline]
    pub fn pacing_rate(&self) -> u64 {
        self.pacing_rate
    }

    /// Get estimated bandwidth in bytes/sec.
    #[inline]
    pub fn bandwidth(&self) -> u64 {
        self.btl_bw.get()
    }

    /// Get minimum RTT observed.
    #[inline]
    pub fn min_rtt(&self) -> Duration {
        self.rt_prop.get()
    }

    /// Get current state.
    #[inline]
    pub fn state(&self) -> BbrState {
        self.state
    }

    /// Get inter-packet pacing interval.
    #[inline]
    pub fn pacing_interval(&self) -> Duration {
        if self.pacing_rate == 0 {
            Duration::from_micros(100) // Default 10kpps
        } else {
            let interval_ns = (MAX_PACKET_SIZE as u64 * 1_000_000_000) / self.pacing_rate;
            Duration::from_nanos(interval_ns.max(1))
        }
    }

    // === Private methods ===

    fn calculate_delivery_rate(&self, now: Instant) -> u64 {
        let bytes = self.delivered.saturating_sub(self.last_delivered);
        let elapsed = now.duration_since(self.last_delivered_time);
        
        if elapsed.is_zero() || bytes == 0 {
            return 0;
        }
        
        // bytes/sec
        (bytes * 1_000_000_000) / elapsed.as_nanos() as u64
    }

    fn update_round(&mut self, _now: Instant) {
        if self.delivered >= self.next_round_delivered {
            self.round_count += 1;
            self.round_start = true;
            self.next_round_delivered = self.delivered;
        } else {
            self.round_start = false;
        }
    }

    fn check_full_pipe(&mut self) {
        if self.filled_pipe || !self.round_start {
            return;
        }

        let bw = self.btl_bw.get();
        
        // Check if bandwidth is still growing (>25% increase)
        if bw >= self.full_bw + self.full_bw / 4 {
            self.full_bw = bw;
            self.full_bw_count = 0;
            return;
        }
        
        self.full_bw_count += 1;
        
        // 3 rounds without significant growth = pipe is full
        if self.full_bw_count >= 3 {
            self.filled_pipe = true;
        }
    }

    fn update_startup(&mut self, now: Instant) {
        if self.filled_pipe {
            self.enter_drain(now);
        }
    }

    fn enter_drain(&mut self, now: Instant) {
        self.state = BbrState::Drain;
        self.pacing_gain = DRAIN_GAIN;
        self.cwnd_gain = STARTUP_GAIN; // Keep cwnd high during drain
        self.startup_exit_time = Some(now);
    }

    fn update_drain(&mut self, now: Instant) {
        // Exit drain when inflight drops to BDP
        let bdp = self.bdp();
        if self.inflight as u64 <= bdp {
            self.enter_probe_bw(now);
        }
    }

    fn enter_probe_bw(&mut self, now: Instant) {
        self.state = BbrState::ProbeBw;
        self.cycle_index = 0;
        self.cycle_start = now;
        self.pacing_gain = PROBE_BW_GAIN_CYCLE[0];
        self.cwnd_gain = 2.0;
    }

    fn update_probe_bw(&mut self, now: Instant) {
        // Advance cycle
        let rt_prop = self.rt_prop.get();
        if now.duration_since(self.cycle_start) >= rt_prop {
            self.cycle_index = (self.cycle_index + 1) % PROBE_BW_GAIN_CYCLE.len();
            self.cycle_start = now;
            self.pacing_gain = PROBE_BW_GAIN_CYCLE[self.cycle_index];
        }

        // Check if we should probe RTT
        if self.rt_prop.expired(now) {
            self.enter_probe_rtt(now);
        }
    }

    fn enter_probe_rtt(&mut self, now: Instant) {
        self.state = BbrState::ProbeRtt;
        self.pacing_gain = 1.0;
        self.cwnd_gain = 1.0;
        self.probe_rtt_done_stamp = None;
        self.probe_rtt_round_done = false;
        // Reduce cwnd to minimum to drain queues
        self.cwnd = MIN_CWND;
        
        // Force RTT filter to reset on next sample
        self.rt_prop = MinFilter::new(RTPROP_FILTER_LEN);
        self.rt_prop.timestamp = now;
    }

    fn update_probe_rtt(&mut self, now: Instant) {
        // Wait for inflight to drain
        if self.probe_rtt_done_stamp.is_none() {
            if self.inflight <= MIN_CWND {
                self.probe_rtt_done_stamp = Some(now + PROBE_RTT_DURATION);
                self.probe_rtt_round_done = false;
                self.next_round_delivered = self.delivered;
            }
        } else if let Some(done_stamp) = self.probe_rtt_done_stamp {
            if self.round_start {
                self.probe_rtt_round_done = true;
            }
            
            if self.probe_rtt_round_done && now >= done_stamp {
                // Exit ProbeRTT
                self.restore_after_probe_rtt(now);
            }
        }
    }

    fn restore_after_probe_rtt(&mut self, now: Instant) {
        if self.filled_pipe {
            self.enter_probe_bw(now);
        } else {
            self.state = BbrState::Startup;
            self.pacing_gain = STARTUP_GAIN;
            self.cwnd_gain = STARTUP_GAIN;
        }
    }

    fn update_pacing_rate(&mut self) {
        let bw = self.btl_bw.get();
        if bw > 0 {
            self.pacing_rate = (bw as f64 * self.pacing_gain) as u64;
        } else {
            // Initial estimate: assume 1Mbps
            self.pacing_rate = (1_000_000.0 * self.pacing_gain) as u64;
        }
    }

    fn update_cwnd(&mut self) {
        let bdp = self.bdp();
        
        // Target cwnd = gain × BDP
        let target = ((bdp as f64 * self.cwnd_gain) as u32).max(MIN_CWND);
        
        // Allow cwnd to grow if we're below target
        if self.cwnd < target {
            self.cwnd = target.min(self.cwnd + 1);
        }
        
        // Clamp to reasonable bounds
        self.cwnd = self.cwnd.clamp(MIN_CWND, 1024);
    }

    /// Calculate Bandwidth-Delay Product (in packets).
    fn bdp(&self) -> u64 {
        let bw = self.btl_bw.get();
        let rtt = self.rt_prop.get();
        
        if bw == 0 || rtt.is_zero() {
            return MIN_CWND as u64;
        }
        
        // BDP = bandwidth × RTT (in bytes)
        let bdp_bytes = (bw as u128 * rtt.as_nanos()) / 1_000_000_000;
        
        // Convert to packets
        (bdp_bytes as u64 / MAX_PACKET_SIZE as u64).max(MIN_CWND as u64)
    }
}

impl Default for BbrCongestionControl {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bbr_creation() {
        let bbr = BbrCongestionControl::new();
        assert_eq!(bbr.state, BbrState::Startup);
        assert_eq!(bbr.cwnd, INITIAL_CWND);
    }

    #[test]
    fn test_bbr_startup_to_drain() {
        let mut bbr = BbrCongestionControl::new();
        
        // Simulate receiving ACKs with consistent RTT
        for i in 0..50 {
            bbr.on_send(1200);
            bbr.on_ack(1200, Duration::from_millis(10));
            
            // After pipe fills, should transition to drain
            if i > 20 && bbr.filled_pipe {
                break;
            }
        }
        
        // Should have detected full pipe
        assert!(bbr.filled_pipe || bbr.state != BbrState::Startup);
    }

    #[test]
    fn test_bbr_pacing_rate() {
        let mut bbr = BbrCongestionControl::new();
        
        // Send some packets
        for _ in 0..10 {
            bbr.on_send(1200);
            std::thread::sleep(Duration::from_micros(100));
            bbr.on_ack(1200, Duration::from_millis(5));
        }
        
        // Should have estimated some bandwidth
        assert!(bbr.pacing_rate > 0);
    }

    #[test]
    fn test_bbr_min_rtt() {
        let mut bbr = BbrCongestionControl::new();
        
        bbr.on_send(1200);
        bbr.on_ack(1200, Duration::from_millis(10));
        
        bbr.on_send(1200);
        bbr.on_ack(1200, Duration::from_millis(5));
        
        bbr.on_send(1200);
        bbr.on_ack(1200, Duration::from_millis(8));
        
        // Min RTT should be 5ms
        assert!(bbr.min_rtt() <= Duration::from_millis(6));
    }

    #[test]
    fn test_bbr_available_window() {
        let mut bbr = BbrCongestionControl::new();
        
        let initial_window = bbr.available_window();
        assert!(initial_window > 0);
        
        // Send some packets
        bbr.on_send(1200);
        bbr.on_send(1200);
        
        // Available should decrease
        assert!(bbr.available_window() < initial_window);
        
        // ACK one
        bbr.on_ack(1200, Duration::from_millis(10));
        
        // Available should increase
        assert!(bbr.available_window() > initial_window - 2);
    }

    #[test]
    fn test_bbr_loss_handling() {
        let mut bbr = BbrCongestionControl::new();
        
        for _ in 0..5 {
            bbr.on_send(1200);
        }
        
        // Lose some packets
        bbr.on_loss(1200);
        bbr.on_loss(1200);
        
        // BBR should be resilient - cwnd shouldn't drop dramatically
        assert!(bbr.cwnd >= MIN_CWND);
    }

    #[test]
    fn test_pacing_interval() {
        let mut bbr = BbrCongestionControl::new();
        
        // With no bandwidth estimate, should have a default interval
        let interval = bbr.pacing_interval();
        assert!(interval > Duration::ZERO);
        
        // After getting bandwidth estimate
        for _ in 0..10 {
            bbr.on_send(1200);
            std::thread::sleep(Duration::from_micros(50));
            bbr.on_ack(1200, Duration::from_millis(1));
        }
        
        // Should have tighter pacing
        let new_interval = bbr.pacing_interval();
        assert!(new_interval > Duration::ZERO);
    }
}
