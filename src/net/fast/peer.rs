//! Peer management and connection state tracking.
//!
//! This module handles individual peer connections, including:
//! - Connection state machine
//! - RTT estimation and congestion control
//! - Channel management per peer
//! - Timeout and keepalive handling

#![allow(dead_code)] // Internal API - some methods reserved for future use

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use super::channel::{Channel, ChannelType, OutgoingPacket};
use super::packet::PacketHeader;

/// Connection state for a peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionState {
    /// Not connected
    Disconnected,
    /// Handshake in progress
    Connecting,
    /// Fully connected and operational
    Connected,
    /// Graceful disconnect in progress
    Disconnecting,
}

/// Configuration for peer connections.
#[derive(Clone, Debug)]
pub struct PeerConfig {
    /// Channel types to create for this peer
    pub channels: Vec<ChannelType>,
    /// Minimum retransmission timeout
    pub rto_min: Duration,
    /// Maximum retransmission timeout
    pub rto_max: Duration,
    /// Interval between keepalive pings
    pub ping_interval: Duration,
    /// Connection timeout (no response)
    pub timeout: Duration,
}

impl Default for PeerConfig {
    fn default() -> Self {
        Self {
            channels: vec![
                ChannelType::ReliableOrdered,
                ChannelType::Unreliable,
                ChannelType::Reliable,
                ChannelType::UnreliableSequenced,
            ],
            rto_min: Duration::from_millis(100),
            rto_max: Duration::from_secs(5),
            ping_interval: Duration::from_secs(1),
            timeout: Duration::from_secs(30),
        }
    }
}

#[derive(Debug)]
struct CongestionControl {
    cwnd: f64,
    ssthresh: f64,
    in_slow_start: bool,
}

impl CongestionControl {
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

    fn on_timeout(&mut self) {
        self.ssthresh = (self.cwnd / 2.0).max(2.0);
        self.cwnd = 2.0;
        self.in_slow_start = true;
    }

    fn on_loss(&mut self) {
        self.ssthresh = (self.cwnd / 2.0).max(2.0);
        self.cwnd = self.ssthresh;
        self.in_slow_start = false;
    }

    #[inline]
    fn available_window(&self) -> usize {
        self.cwnd as usize
    }
}

#[derive(Debug)]
struct RttEstimator {
    srtt: Duration,
    rttvar: Duration,
    rto: Duration,
    min_rto: Duration,
    max_rto: Duration,
}

impl RttEstimator {
    fn new(min_rto: Duration, max_rto: Duration) -> Self {
        Self {
            srtt: Duration::from_millis(100),
            rttvar: Duration::from_millis(50),
            rto: Duration::from_millis(200),
            min_rto,
            max_rto,
        }
    }

    fn update(&mut self, rtt: Duration) {

        let alpha = 0.125;
        let beta = 0.25;

        let rtt_secs = rtt.as_secs_f64();
        let srtt_secs = self.srtt.as_secs_f64();
        let rttvar_secs = self.rttvar.as_secs_f64();

        let new_rttvar = (1.0 - beta) * rttvar_secs + beta * (srtt_secs - rtt_secs).abs();
        let new_srtt = (1.0 - alpha) * srtt_secs + alpha * rtt_secs;

        self.rttvar = Duration::from_secs_f64(new_rttvar);
        self.srtt = Duration::from_secs_f64(new_srtt);

        let rto = new_srtt + 4.0 * new_rttvar;
        self.rto = Duration::from_secs_f64(rto).clamp(self.min_rto, self.max_rto);
    }

    #[inline]
    fn rto(&self) -> Duration {
        self.rto
    }

    #[inline]
    fn rtt(&self) -> Duration {
        self.srtt
    }
}

struct AckTracker {

    remote_sequence: u16,

    ack_bitfield: u32,

    send_times: HashMap<u16, Instant>,
}

impl AckTracker {
    fn new() -> Self {
        Self {
            remote_sequence: 0,
            ack_bitfield: 0,
            send_times: HashMap::with_capacity(256),
        }
    }

    fn on_send(&mut self, sequence: u16) {
        self.send_times.insert(sequence, Instant::now());

        if self.send_times.len() > 512 {
            let cutoff = Instant::now() - Duration::from_secs(30);
            self.send_times.retain(|_, t| *t > cutoff);
        }
    }

    fn on_recv(&mut self, sequence: u16) -> (u16, u32) {
        if sequence == 0 && self.remote_sequence == 0 {

            self.remote_sequence = sequence;
        } else if super::channel::sequence_greater_than(sequence, self.remote_sequence) {

            let diff = sequence.wrapping_sub(self.remote_sequence);
            if diff < 32 {
                self.ack_bitfield = (self.ack_bitfield << diff) | 1;
            } else {
                self.ack_bitfield = 1;
            }
            self.remote_sequence = sequence;
        } else {

            let diff = self.remote_sequence.wrapping_sub(sequence);
            if diff > 0 && diff <= 32 {
                self.ack_bitfield |= 1 << (diff - 1);
            }
        }

        (self.remote_sequence, self.ack_bitfield)
    }

    fn process_ack(&mut self, ack: u16) -> Option<Duration> {
        self.send_times.remove(&ack).map(|t| t.elapsed())
    }
}

pub struct Peer {
    pub id: u16,
    pub address: SocketAddr,
    pub state: ConnectionState,

    channels: Vec<Channel>,
    rtt: RttEstimator,
    congestion: CongestionControl,
    ack_tracker: AckTracker,

    local_sequence: u16,
    last_recv: Instant,
    last_send: Instant,
    last_ping: Instant,

    config: PeerConfig,
}

impl Peer {
    pub fn new(id: u16, address: SocketAddr, config: PeerConfig) -> Self {
        let channels = config.channels.iter()
            .enumerate()
            .map(|(i, &ct)| Channel::new(i as u8, ct))
            .collect();

        Self {
            id,
            address,
            state: ConnectionState::Disconnected,
            channels,
            rtt: RttEstimator::new(config.rto_min, config.rto_max),
            congestion: CongestionControl::new(),
            ack_tracker: AckTracker::new(),
            local_sequence: 0,
            last_recv: Instant::now(),
            last_send: Instant::now(),
            last_ping: Instant::now(),
            config,
        }
    }

    pub fn send(&mut self, channel_id: u8, data: Vec<u8>) -> Option<Vec<OutgoingPacket>> {
        self.channels.get_mut(channel_id as usize)?.send(data)
    }

    pub fn recv(&mut self, channel_id: u8) -> Option<Vec<u8>> {
        self.channels.get_mut(channel_id as usize)?.recv()
    }

    pub fn on_packet_received(&mut self, header: &PacketHeader, payload: &[u8])
        -> (u16, u32, Option<Vec<u8>>)
    {
        self.last_recv = Instant::now();

        let (ack, bitfield) = self.ack_tracker.on_recv(header.sequence);

        if let Some(rtt) = self.ack_tracker.process_ack(header.ack) {
            self.rtt.update(rtt);
            self.congestion.on_ack();
        }

        for i in 0..32 {
            if header.ack_bitfield & (1 << i) != 0 {
                let seq = header.ack.wrapping_sub(i + 1);
                if let Some(rtt) = self.ack_tracker.process_ack(seq) {
                    self.rtt.update(rtt);
                    self.congestion.on_ack();
                }
            }
        }

        for channel in &mut self.channels {
            channel.process_ack_bitfield(header.ack, header.ack_bitfield);
        }

        let msg = if !payload.is_empty() {
            if let Some(channel) = self.channels.get_mut(header.channel as usize) {
                channel.receive(
                    header.sequence,
                    header.is_fragment(),
                    header.fragment_id,
                    header.fragment_id,
                    header.fragment_count,
                    payload,
                )
            } else {
                None
            }
        } else {
            None
        };

        (ack, bitfield, msg)
    }

    pub fn prepare_header(&mut self, channel_id: u8, flags: u8) -> PacketHeader {
        let seq = self.local_sequence;
        self.local_sequence = self.local_sequence.wrapping_add(1);
        self.ack_tracker.on_send(seq);

        let (ack, bitfield) = (self.ack_tracker.remote_sequence, self.ack_tracker.ack_bitfield);

        let mut header = PacketHeader::new(seq, channel_id, flags);
        header.ack = ack;
        header.ack_bitfield = bitfield;
        header
    }

    pub fn get_retransmissions(&mut self) -> Vec<(u8, u16, Vec<u8>)> {
        let rto = self.rtt.rto();
        let mut result = Vec::new();

        for channel in &mut self.channels {
            let channel_id = channel.id;
            for msg in channel.get_retransmissions(rto) {
                result.push((channel_id, msg.sequence, msg.data.clone()));
            }
        }
        if !result.is_empty() {
            self.congestion.on_timeout();
        }

        result
    }

    pub fn mark_retransmitted(&mut self, channel_id: u8, sequence: u16) {
        if let Some(channel) = self.channels.get_mut(channel_id as usize) {
            channel.mark_retransmitted(sequence);
        }
    }

    pub fn needs_ping(&self) -> bool {
        self.last_ping.elapsed() >= self.config.ping_interval
    }

    pub fn on_ping_sent(&mut self) {
        self.last_ping = Instant::now();
    }

    pub fn is_timed_out(&self) -> bool {
        self.last_recv.elapsed() > self.config.timeout
    }

    #[inline]
    pub fn congestion_window(&self) -> usize {
        self.congestion.available_window()
    }

    #[inline]
    pub fn rtt(&self) -> Duration {
        self.rtt.rtt()
    }

    #[inline]
    pub fn rto(&self) -> Duration {
        self.rtt.rto()
    }

    pub fn connect(&mut self) {
        self.state = ConnectionState::Connecting;
    }

    pub fn on_connected(&mut self) {
        self.state = ConnectionState::Connected;
        self.last_recv = Instant::now();
    }

    pub fn disconnect(&mut self) {
        self.state = ConnectionState::Disconnecting;
    }

    pub fn touch(&mut self) {
        self.last_recv = Instant::now();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_creation() {
        let peer = Peer::new(1, "127.0.0.1:7777".parse().unwrap(), PeerConfig::default());
        assert_eq!(peer.id, 1);
        assert_eq!(peer.channels.len(), 4);
    }

    #[test]
    fn test_rtt_estimation() {
        let mut rtt = RttEstimator::new(Duration::from_millis(50), Duration::from_secs(5));

        rtt.update(Duration::from_millis(100));
        rtt.update(Duration::from_millis(110));
        rtt.update(Duration::from_millis(95));

        assert!(rtt.rtt() > Duration::from_millis(90));
        assert!(rtt.rtt() < Duration::from_millis(120));
    }

    #[test]
    fn test_congestion_control() {
        let mut cc = CongestionControl::new();
        assert!(cc.in_slow_start);

        for _ in 0..10 {
            cc.on_ack();
        }
        assert!(cc.cwnd > 10.0);

        cc.on_timeout();
        assert_eq!(cc.cwnd, 2.0);
        assert!(cc.in_slow_start);
    }
}
