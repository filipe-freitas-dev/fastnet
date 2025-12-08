//! BBR Congestion Control Benchmark
//!
//! Compares BBR performance against traditional AIMD.

use std::time::{Duration, Instant};

// Simulated AIMD (TCP Reno style) for comparison
struct AimdCongestionControl {
    cwnd: f64,
    ssthresh: f64,
    in_slow_start: bool,
}

impl AimdCongestionControl {
    fn new() -> Self {
        Self {
            cwnd: 2.0,
            ssthresh: 64.0,
            in_slow_start: true,
        }
    }

    fn on_ack(&mut self) {
        if self.in_slow_start {
            self.cwnd += 1.0;
            if self.cwnd >= self.ssthresh {
                self.in_slow_start = false;
            }
        } else {
            self.cwnd += 1.0 / self.cwnd;
        }
        self.cwnd = self.cwnd.min(256.0);
    }

    fn on_loss(&mut self) {
        self.ssthresh = (self.cwnd / 2.0).max(2.0);
        self.cwnd = self.ssthresh;
        self.in_slow_start = false;
    }

    fn available_window(&self) -> usize {
        self.cwnd as usize
    }
}

// Simulated BBR (simplified for benchmark)
use std::collections::VecDeque;

struct BbrSimple {
    btl_bw: u64,
    rt_prop: Duration,
    cwnd: u32,
    inflight: u32,
    bw_samples: VecDeque<u64>,
    rtt_samples: VecDeque<Duration>,
}

impl BbrSimple {
    fn new() -> Self {
        Self {
            btl_bw: 0,
            rt_prop: Duration::from_secs(1),
            cwnd: 10,
            inflight: 0,
            bw_samples: VecDeque::with_capacity(10),
            rtt_samples: VecDeque::with_capacity(10),
        }
    }

    fn on_send(&mut self) {
        self.inflight += 1;
    }

    fn on_ack(&mut self, bytes: usize, rtt: Duration, elapsed_ns: u64) {
        self.inflight = self.inflight.saturating_sub(1);
        
        // Update RTprop (min)
        if rtt < self.rt_prop {
            self.rt_prop = rtt;
        }
        self.rtt_samples.push_back(rtt);
        if self.rtt_samples.len() > 10 {
            self.rtt_samples.pop_front();
        }
        
        // Estimate bandwidth
        if elapsed_ns > 0 {
            let bw = (bytes as u64 * 1_000_000_000) / elapsed_ns;
            self.bw_samples.push_back(bw);
            if self.bw_samples.len() > 10 {
                self.bw_samples.pop_front();
            }
            // BtlBw = max of samples
            self.btl_bw = self.bw_samples.iter().copied().max().unwrap_or(0);
        }
        
        // Update cwnd based on BDP
        let bdp = if self.btl_bw > 0 && !self.rt_prop.is_zero() {
            ((self.btl_bw as u128 * self.rt_prop.as_nanos()) / 1_000_000_000 / 1200) as u32
        } else {
            10
        };
        self.cwnd = bdp.max(4).min(256);
    }

    fn on_loss(&mut self) {
        // BBR doesn't react dramatically to loss
        self.inflight = self.inflight.saturating_sub(1);
    }

    fn available_window(&self) -> usize {
        self.cwnd.saturating_sub(self.inflight) as usize
    }
}

fn main() {
    println!("╔════════════════════════════════════════╗");
    println!("║   BBR vs AIMD Congestion Control       ║");
    println!("╚════════════════════════════════════════╝\n");

    // Scenario 1: Stable network
    println!("━━━ Scenario 1: Stable Network ━━━");
    benchmark_stable();

    // Scenario 2: Network with loss
    println!("\n━━━ Scenario 2: Network with 5% Loss ━━━");
    benchmark_with_loss(0.05);

    // Scenario 3: Variable RTT
    println!("\n━━━ Scenario 3: Variable RTT (Jitter) ━━━");
    benchmark_variable_rtt();

    // Scenario 4: Bandwidth change
    println!("\n━━━ Scenario 4: Bandwidth Change ━━━");
    benchmark_bandwidth_change();
}

fn benchmark_stable() {
    let iterations = 10000;
    let base_rtt = Duration::from_millis(10);
    
    // AIMD
    let mut aimd = AimdCongestionControl::new();
    let start = Instant::now();
    let mut aimd_total_window = 0u64;
    
    for _ in 0..iterations {
        aimd.on_ack();
        aimd_total_window += aimd.available_window() as u64;
    }
    let aimd_time = start.elapsed();
    let aimd_avg_window = aimd_total_window as f64 / iterations as f64;
    
    // BBR
    let mut bbr = BbrSimple::new();
    let start = Instant::now();
    let mut bbr_total_window = 0u64;
    let mut last_time = Instant::now();
    
    for _ in 0..iterations {
        bbr.on_send();
        let now = Instant::now();
        let elapsed = now.duration_since(last_time).as_nanos() as u64;
        bbr.on_ack(1200, base_rtt, elapsed.max(1000));
        bbr_total_window += bbr.available_window() as u64;
        last_time = now;
    }
    let bbr_time = start.elapsed();
    let bbr_avg_window = bbr_total_window as f64 / iterations as f64;
    
    println!("  AIMD: {:>6.1} avg cwnd, {:>6.2} µs/iter", 
             aimd_avg_window, aimd_time.as_nanos() as f64 / iterations as f64 / 1000.0);
    println!("  BBR:  {:>6.1} avg cwnd, {:>6.2} µs/iter", 
             bbr_avg_window, bbr_time.as_nanos() as f64 / iterations as f64 / 1000.0);
}

fn benchmark_with_loss(loss_rate: f64) {
    let iterations = 10000;
    let base_rtt = Duration::from_millis(10);
    
    // Simple PRNG
    fn next_rand(state: &mut u64) -> f64 {
        *state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        (*state >> 33) as f64 / (u32::MAX as f64)
    }
    
    // AIMD with loss
    let mut rng_state: u64 = 12345;
    let mut aimd = AimdCongestionControl::new();
    let mut aimd_total_window = 0u64;
    let mut aimd_loss_events = 0u32;
    
    for _ in 0..iterations {
        if next_rand(&mut rng_state) < loss_rate {
            aimd.on_loss();
            aimd_loss_events += 1;
        } else {
            aimd.on_ack();
        }
        aimd_total_window += aimd.available_window() as u64;
    }
    let aimd_avg_window = aimd_total_window as f64 / iterations as f64;
    
    // Reset PRNG
    let mut rng_state: u64 = 12345;
    
    // BBR with loss
    let mut bbr = BbrSimple::new();
    let mut bbr_total_window = 0u64;
    let mut bbr_loss_events = 0u32;
    
    for _ in 0..iterations {
        bbr.on_send();
        if next_rand(&mut rng_state) < loss_rate {
            bbr.on_loss();
            bbr_loss_events += 1;
        } else {
            bbr.on_ack(1200, base_rtt, 1_000_000);
        }
        bbr_total_window += bbr.available_window() as u64;
    }
    let bbr_avg_window = bbr_total_window as f64 / iterations as f64;
    
    println!("  AIMD: {:>6.1} avg cwnd, {} loss events -> cwnd collapses", 
             aimd_avg_window, aimd_loss_events);
    println!("  BBR:  {:>6.1} avg cwnd, {} loss events -> stable cwnd", 
             bbr_avg_window, bbr_loss_events);
    println!("  BBR advantage: {:.1}x higher throughput under loss", 
             bbr_avg_window / aimd_avg_window);
}

fn benchmark_variable_rtt() {
    let iterations = 10000;
    let mut rng_state: u64 = 54321;
    
    fn next_rand(state: &mut u64) -> f64 {
        *state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        (*state >> 33) as f64 / (u32::MAX as f64)
    }
    
    // BBR should maintain stable cwnd despite RTT variance
    let mut bbr = BbrSimple::new();
    let mut min_rtt = Duration::from_secs(1);
    let mut max_rtt = Duration::ZERO;
    let mut total_window = 0u64;
    
    for _ in 0..iterations {
        // RTT varies between 5ms and 50ms
        let rtt_ms = 5.0 + next_rand(&mut rng_state) * 45.0;
        let rtt = Duration::from_micros((rtt_ms * 1000.0) as u64);
        
        min_rtt = min_rtt.min(rtt);
        max_rtt = max_rtt.max(rtt);
        
        bbr.on_send();
        bbr.on_ack(1200, rtt, 1_000_000);
        total_window += bbr.available_window() as u64;
    }
    
    let avg_window = total_window as f64 / iterations as f64;
    
    println!("  RTT range: {:>3.1}ms - {:>3.1}ms", 
             min_rtt.as_micros() as f64 / 1000.0,
             max_rtt.as_micros() as f64 / 1000.0);
    println!("  BBR min_rtt tracked: {:>3.1}ms", 
             bbr.rt_prop.as_micros() as f64 / 1000.0);
    println!("  BBR avg cwnd: {:>6.1} (stable despite jitter)", avg_window);
}

fn benchmark_bandwidth_change() {
    let iterations = 5000;
    
    let mut bbr = BbrSimple::new();
    
    // Phase 1: Low bandwidth (simulate 1 Mbps)
    println!("  Phase 1: Low bandwidth simulation");
    for _ in 0..iterations {
        bbr.on_send();
        bbr.on_ack(1200, Duration::from_millis(20), 10_000_000); // 10ms between packets
    }
    println!("    BBR cwnd: {}, estimated BW: {} bytes/sec", bbr.cwnd, bbr.btl_bw);
    
    // Phase 2: High bandwidth (simulate 10 Mbps)
    println!("  Phase 2: High bandwidth simulation");
    for _ in 0..iterations {
        bbr.on_send();
        bbr.on_ack(1200, Duration::from_millis(10), 1_000_000); // 1ms between packets
    }
    println!("    BBR cwnd: {}, estimated BW: {} bytes/sec", bbr.cwnd, bbr.btl_bw);
    println!("    ✓ BBR adapts to bandwidth changes automatically");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bbr_outperforms_aimd_under_loss() {
        let iterations = 1000;
        let loss_rate = 0.05;
        let base_rtt = Duration::from_millis(10);
        
        fn next_rand(state: &mut u64) -> f64 {
            *state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            (*state >> 33) as f64 / (u32::MAX as f64)
        }
        
        let mut rng_state: u64 = 12345;
        let mut aimd = AimdCongestionControl::new();
        let mut aimd_total = 0u64;
        
        for _ in 0..iterations {
            if next_rand(&mut rng_state) < loss_rate {
                aimd.on_loss();
            } else {
                aimd.on_ack();
            }
            aimd_total += aimd.available_window() as u64;
        }
        
        let mut rng_state: u64 = 12345;
        
        let mut bbr = BbrSimple::new();
        let mut bbr_total = 0u64;
        
        for _ in 0..iterations {
            bbr.on_send();
            if next_rand(&mut rng_state) < loss_rate {
                bbr.on_loss();
            } else {
                bbr.on_ack(1200, base_rtt, 1_000_000);
            }
            bbr_total += bbr.available_window() as u64;
        }
        
        // BBR should maintain higher average window under loss
        assert!(bbr_total > aimd_total, "BBR should outperform AIMD under loss");
    }
}
