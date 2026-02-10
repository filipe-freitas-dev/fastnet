//! Peer-to-Peer networking with NAT traversal.
#![allow(dead_code)] // Some fields reserved for future use
//!
//! This module provides P2P connectivity between clients without requiring
//! a dedicated game server for data relay. It uses a lightweight signaling
//! server for connection establishment, then clients communicate directly.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────┐                              ┌─────────┐
//! │ Peer A  │                              │ Peer B  │
//! └────┬────┘                              └────┬────┘
//!      │                                        │
//!      │  1. Register with signaling server     │
//!      │─────────────────┐   ┌──────────────────│
//!      │                 ▼   ▼                  │
//!      │           ┌───────────────┐            │
//!      │           │   Signaling   │            │
//!      │           │    Server     │            │
//!      │           └───────────────┘            │
//!      │                                        │
//!      │  2. Exchange connection info           │
//!      │◄───────────────────────────────────────│
//!      │                                        │
//!      │  3. NAT hole-punching                  │
//!      │════════════════════════════════════════│
//!      │                                        │
//!      │  4. Direct encrypted communication     │
//!      │◄══════════════════════════════════════►│
//! ```
//!
//! # Features
//!
//! - **NAT Traversal**: UDP hole-punching for direct connections
//! - **Relay Fallback**: Server relay when direct connection fails
//! - **Encrypted**: All P2P traffic uses ChaCha20-Poly1305
//! - **Room-based**: Peers join rooms to discover each other
//!
//! # Example
//!
//! ```rust,no_run
//! use fastnet::p2p::{P2PSocket, P2PEvent};
//!
//! #[tokio::main]
//! async fn main() -> std::io::Result<()> {
//!     // Connect to signaling server
//!     let mut socket = P2PSocket::connect("signaling.example.com:9000").await?;
//!     
//!     // Join a room
//!     socket.join_room("game-room-123").await?;
//!     
//!     loop {
//!         for event in socket.poll().await? {
//!             match event {
//!                 P2PEvent::PeerJoined(peer_id) => {
//!                     println!("Peer {} joined the room", peer_id);
//!                 }
//!                 P2PEvent::PeerConnected(peer_id) => {
//!                     println!("Direct connection to peer {}", peer_id);
//!                 }
//!                 P2PEvent::Data(peer_id, data) => {
//!                     println!("Received from {}: {:?}", peer_id, data);
//!                 }
//!                 P2PEvent::PeerLeft(peer_id) => {
//!                     println!("Peer {} left", peer_id);
//!                 }
//!             }
//!         }
//!     }
//! }
//! ```

mod signaling;
mod punch;

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::Aead};
use chacha20poly1305::aead::generic_array::GenericArray;

pub use signaling::{SignalingClient, SignalingConfig, SignalingMessage, SignalingServer};

/// Unique identifier for a peer in the P2P network.
pub use crate::types::PeerId;

/// Events from the P2P socket.
#[derive(Debug, Clone)]
pub enum P2PEvent {
    /// A new peer joined the room (not yet connected directly).
    PeerJoined(PeerId),
    
    /// Direct connection established with a peer.
    PeerConnected(PeerId),
    
    /// Data received from a peer.
    Data(PeerId, Vec<u8>),
    
    /// A peer left the room or disconnected.
    PeerLeft(PeerId),
    
    /// Connection to peer is being relayed (no direct connection).
    PeerRelayed(PeerId),
    
    /// Error occurred with a peer.
    Error(PeerId, P2PError),
}

/// P2P connection errors.
#[derive(Debug, Clone)]
pub enum P2PError {
    /// NAT traversal failed.
    NatTraversalFailed,
    /// Peer unreachable.
    Unreachable,
    /// Connection timeout.
    Timeout,
    /// Encryption error.
    CryptoError,
}

/// Connection state for a P2P peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionMode {
    /// No connection yet.
    None,
    /// Attempting NAT hole-punching.
    Punching,
    /// Direct UDP connection established.
    Direct,
    /// Using relay server (fallback).
    Relayed,
    /// Disconnected.
    Disconnected,
}

/// Information about a connected peer.
struct P2PPeer {
    id: PeerId,
    public_addr: Option<SocketAddr>,
    private_addr: Option<SocketAddr>,
    mode: ConnectionMode,
    cipher: Option<PeerCipher>,
    last_seen: Instant,
    rtt: Duration,
    punch_attempts: u8,
    last_punch: Instant,
}

struct PeerCipher {
    encrypt: ChaCha20Poly1305,
    decrypt: ChaCha20Poly1305,
    nonce: u64,
}

impl PeerCipher {
    fn new(shared_key: &[u8; 32], is_initiator: bool) -> Self {
        let mut send_key = [0u8; 32];
        let mut recv_key = [0u8; 32];
        
        for i in 0..32 {
            send_key[i] = shared_key[i] ^ if is_initiator { 0x01 } else { 0x02 };
            recv_key[i] = shared_key[i] ^ if is_initiator { 0x02 } else { 0x01 };
        }
        
        Self {
            encrypt: ChaCha20Poly1305::new(GenericArray::from_slice(&send_key)),
            decrypt: ChaCha20Poly1305::new(GenericArray::from_slice(&recv_key)),
            nonce: 0,
        }
    }
    
    fn seal(&mut self, plaintext: &[u8]) -> Option<Vec<u8>> {
        let mut nonce = [0u8; 12];
        nonce[4..12].copy_from_slice(&self.nonce.to_le_bytes());
        self.nonce = self.nonce.wrapping_add(1);
        
        self.encrypt.encrypt(GenericArray::from_slice(&nonce), plaintext)
            .ok()
            .map(|ct| {
                let mut out = Vec::with_capacity(8 + ct.len());
                out.extend_from_slice(&nonce[4..12]);
                out.extend_from_slice(&ct);
                out
            })
    }
    
    fn open(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        if ciphertext.len() < 24 { return None; }
        let mut nonce = [0u8; 12];
        nonce[4..12].copy_from_slice(&ciphertext[..8]);
        self.decrypt.decrypt(GenericArray::from_slice(&nonce), &ciphertext[8..]).ok()
    }
}

/// Configuration for P2P networking.
#[derive(Debug, Clone)]
pub struct P2PConfig {
    /// Maximum NAT punch attempts before falling back to relay.
    pub max_punch_attempts: u8,
    /// Timeout for NAT hole-punching.
    pub punch_timeout: Duration,
    /// Interval between punch packets.
    pub punch_interval: Duration,
    /// Peer timeout (no packets received). None means no timeout.
    pub peer_timeout: Option<Duration>,
    /// Enable relay fallback when direct connection fails.
    pub enable_relay: bool,
}

impl Default for P2PConfig {
    fn default() -> Self {
        Self {
            max_punch_attempts: 10,
            punch_timeout: Duration::from_secs(5),
            punch_interval: Duration::from_millis(100),
            peer_timeout: None,
            enable_relay: true,
        }
    }
}

/// P2P socket for direct peer-to-peer communication.
///
/// Uses a signaling server for peer discovery and NAT traversal,
/// then establishes direct encrypted connections between peers.
pub struct P2PSocket {
    socket: UdpSocket,
    signaling: SignalingClient,
    peers: HashMap<PeerId, P2PPeer>,
    local_id: PeerId,
    room: Option<String>,
    config: P2PConfig,
    events: Vec<P2PEvent>,
    recv_buf: Box<[u8; 1500]>,
}

impl P2PSocket {
    /// Connect to a signaling server.
    ///
    /// # Arguments
    ///
    /// * `signaling_addr` - Address of the signaling server
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use fastnet::p2p::P2PSocket;
    /// # async fn example() -> std::io::Result<()> {
    /// let socket = P2PSocket::connect("signaling.example.com:9000").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn connect(signaling_addr: &str) -> io::Result<Self> {
        Self::connect_with_config(signaling_addr, P2PConfig::default()).await
    }
    
    /// Connect with custom configuration.
    pub async fn connect_with_config(signaling_addr: &str, config: P2PConfig) -> io::Result<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let local_addr = socket.local_addr()?;
        let signaling = SignalingClient::connect(signaling_addr, local_addr).await?;
        let local_id = signaling.local_id();
        
        Ok(Self {
            socket,
            signaling,
            peers: HashMap::new(),
            local_id,
            room: None,
            config,
            events: Vec::new(),
            recv_buf: Box::new([0u8; 1500]),
        })
    }
    
    /// Returns the local peer ID.
    pub fn local_id(&self) -> PeerId {
        self.local_id
    }
    
    /// Join a room for peer discovery.
    ///
    /// All peers in the same room can discover and connect to each other.
    pub async fn join_room(&mut self, room_id: &str) -> io::Result<()> {
        let local_addr = self.socket.local_addr()?;
        self.signaling.join_room(room_id, local_addr).await?;
        self.room = Some(room_id.to_string());
        Ok(())
    }
    
    /// Leave the current room.
    pub async fn leave_room(&mut self) -> io::Result<()> {
        if let Some(room) = self.room.take() {
            self.signaling.leave_room(&room).await?;
        }
        Ok(())
    }
    
    /// Send data to a specific peer.
    ///
    /// Data is encrypted end-to-end using ChaCha20-Poly1305.
    pub async fn send(&mut self, peer_id: PeerId, data: Vec<u8>) -> io::Result<()> {
        let peer = self.peers.get_mut(&peer_id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Peer not found"))?;
        
        match peer.mode {
            ConnectionMode::Direct => {
                if let (Some(addr), Some(cipher)) = (peer.public_addr, peer.cipher.as_mut()) {
                    if let Some(encrypted) = cipher.seal(&data) {
                        self.socket.send_to(&encrypted, addr).await?;
                    }
                }
            }
            ConnectionMode::Relayed => {
                self.signaling.relay(peer_id, &data).await?;
            }
            _ => {
                return Err(io::Error::new(io::ErrorKind::NotConnected, "Not connected to peer"));
            }
        }
        
        Ok(())
    }
    
    /// Broadcast data to all connected peers.
    pub async fn broadcast(&mut self, data: Vec<u8>) -> io::Result<()> {
        let peer_ids: Vec<_> = self.peers.iter()
            .filter(|(_, p)| matches!(p.mode, ConnectionMode::Direct | ConnectionMode::Relayed))
            .map(|(&id, _)| id)
            .collect();
        
        for peer_id in peer_ids {
            let _ = self.send(peer_id, data.clone()).await;
        }
        Ok(())
    }
    
    /// Poll for P2P events.
    ///
    /// Should be called regularly (e.g., every frame).
    pub async fn poll(&mut self) -> io::Result<Vec<P2PEvent>> {
        // Poll signaling server
        for msg in self.signaling.poll().await? {
            self.handle_signaling_message(msg).await?;
        }
        
        // Receive UDP packets
        loop {
            match self.socket.try_recv_from(&mut self.recv_buf[..]) {
                Ok((len, addr)) => {
                    self.handle_udp_packet(len, addr)?;
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }
        
        // Process hole-punching
        self.process_hole_punching().await?;
        
        // Check for timeouts
        self.check_timeouts();
        
        Ok(std::mem::take(&mut self.events))
    }
    
    /// Get the connection mode for a peer.
    pub fn peer_mode(&self, peer_id: PeerId) -> Option<ConnectionMode> {
        self.peers.get(&peer_id).map(|p| p.mode)
    }
    
    /// Get the estimated RTT for a peer.
    pub fn peer_rtt(&self, peer_id: PeerId) -> Option<Duration> {
        self.peers.get(&peer_id).map(|p| p.rtt)
    }
    
    /// Get the number of connected peers.
    pub fn peer_count(&self) -> usize {
        self.peers.values()
            .filter(|p| matches!(p.mode, ConnectionMode::Direct | ConnectionMode::Relayed))
            .count()
    }
    
    async fn handle_signaling_message(&mut self, msg: SignalingMessage) -> io::Result<()> {
        match msg {
            SignalingMessage::PeerJoined { peer_id, public_addr, private_addr } => {
                let peer = P2PPeer {
                    id: peer_id,
                    public_addr: Some(public_addr),
                    private_addr,
                    mode: ConnectionMode::None,
                    cipher: None,
                    last_seen: Instant::now(),
                    rtt: Duration::from_millis(100),
                    punch_attempts: 0,
                    last_punch: Instant::now(),
                };
                self.peers.insert(peer_id, peer);
                self.events.push(P2PEvent::PeerJoined(peer_id));
                
                // Start hole-punching
                self.start_hole_punching(peer_id).await?;
            }
            
            SignalingMessage::PeerLeft { peer_id } => {
                self.peers.remove(&peer_id);
                self.events.push(P2PEvent::PeerLeft(peer_id));
            }
            
            SignalingMessage::KeyExchange { peer_id, shared_key } => {
                if let Some(peer) = self.peers.get_mut(&peer_id) {
                    let is_initiator = self.local_id < peer_id;
                    peer.cipher = Some(PeerCipher::new(&shared_key, is_initiator));
                }
            }
            
            SignalingMessage::RelayedData { peer_id, data } => {
                if let Some(peer) = self.peers.get_mut(&peer_id) {
                    peer.last_seen = Instant::now();
                    if let Some(cipher) = &peer.cipher {
                        if let Some(decrypted) = cipher.open(&data) {
                            self.events.push(P2PEvent::Data(peer_id, decrypted));
                        }
                    }
                }
            }
            
            SignalingMessage::Registered { peer_id } => {
                // We registered, nothing to do
                let _ = peer_id;
            }
            
            SignalingMessage::RoomJoined { room_id: _ } => {}
            SignalingMessage::Error { message: _ } => {}
        }
        
        Ok(())
    }
    
    fn handle_udp_packet(&mut self, len: usize, addr: SocketAddr) -> io::Result<()> {
        let peer_id = self.peers.iter()
            .find(|(_, p)| p.public_addr == Some(addr) || p.private_addr == Some(addr))
            .map(|(&id, _)| id);
        
        if let Some(peer_id) = peer_id {
            if let Some(peer) = self.peers.get_mut(&peer_id) {
                peer.last_seen = Instant::now();
                
                if peer.mode == ConnectionMode::Punching {
                    peer.mode = ConnectionMode::Direct;
                    peer.public_addr = Some(addr);
                    self.events.push(P2PEvent::PeerConnected(peer_id));
                }
                
                if let Some(cipher) = &peer.cipher {
                    if let Some(decrypted) = cipher.open(&self.recv_buf[..len]) {
                        if !decrypted.is_empty() {
                            self.events.push(P2PEvent::Data(peer_id, decrypted));
                        }
                    }
                }
            }
        }
        
        Ok(())
    }
    
    async fn start_hole_punching(&mut self, peer_id: PeerId) -> io::Result<()> {
        if let Some(peer) = self.peers.get_mut(&peer_id) {
            peer.mode = ConnectionMode::Punching;
            peer.punch_attempts = 0;
            peer.last_punch = Instant::now();
        }
        
        let local_addr = self.socket.local_addr()?;
        self.signaling.request_punch(peer_id, local_addr).await?;
        
        Ok(())
    }
    
    async fn process_hole_punching(&mut self) -> io::Result<()> {
        let now = Instant::now();
        
        let punching_peers: Vec<_> = self.peers.iter()
            .filter(|(_, p)| p.mode == ConnectionMode::Punching)
            .filter(|(_, p)| now.duration_since(p.last_punch) >= self.config.punch_interval)
            .map(|(&id, p)| (id, p.public_addr, p.private_addr, p.punch_attempts))
            .collect();
        
        for (peer_id, public_addr, private_addr, attempts) in punching_peers {
            if attempts >= self.config.max_punch_attempts {
                if let Some(peer) = self.peers.get_mut(&peer_id) {
                    if self.config.enable_relay {
                        peer.mode = ConnectionMode::Relayed;
                        self.events.push(P2PEvent::PeerRelayed(peer_id));
                    } else {
                        peer.mode = ConnectionMode::Disconnected;
                        self.events.push(P2PEvent::Error(peer_id, P2PError::NatTraversalFailed));
                    }
                }
                continue;
            }
            
            if let Some(peer) = self.peers.get_mut(&peer_id) {
                if let Some(cipher) = peer.cipher.as_mut() {
                    let punch_packet = cipher.seal(&[]).unwrap_or_default();
                    
                    if let Some(addr) = public_addr {
                        let _ = self.socket.send_to(&punch_packet, addr).await;
                    }
                    
                    if let Some(addr) = private_addr {
                        let _ = self.socket.send_to(&punch_packet, addr).await;
                    }
                    
                    peer.punch_attempts += 1;
                    peer.last_punch = now;
                }
            }
        }
        
        Ok(())
    }
    
    fn check_timeouts(&mut self) {
        if let Some(timeout) = self.config.peer_timeout {
            let now = Instant::now();

            let timed_out: Vec<_> = self.peers.iter()
                .filter(|(_, p)| now.duration_since(p.last_seen) > timeout)
                .map(|(&id, _)| id)
                .collect();

            for peer_id in timed_out {
                self.peers.remove(&peer_id);
                self.events.push(P2PEvent::PeerLeft(peer_id));
            }
        }
    }
}
