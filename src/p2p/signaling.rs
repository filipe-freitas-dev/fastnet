//! Signaling server and client for P2P connection establishment.
#![allow(dead_code)] // Some fields reserved for future use
//!
//! The signaling server helps peers discover each other and exchange
//! connection information for NAT traversal.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, RwLock};
use uuid::Uuid;

use super::PeerId;

/// Messages exchanged via the signaling server.
#[derive(Debug, Clone)]
pub enum SignalingMessage {
    /// Server assigned us a peer ID.
    Registered { peer_id: PeerId },
    
    /// Successfully joined a room.
    RoomJoined { room_id: String },
    
    /// A peer joined our room.
    PeerJoined {
        peer_id: PeerId,
        public_addr: SocketAddr,
        private_addr: Option<SocketAddr>,
    },
    
    /// A peer left our room.
    PeerLeft { peer_id: PeerId },
    
    /// Key exchange data from a peer.
    KeyExchange {
        peer_id: PeerId,
        shared_key: [u8; 32],
    },
    
    /// Data relayed from a peer.
    RelayedData {
        peer_id: PeerId,
        data: Vec<u8>,
    },
    
    /// Error message.
    Error { message: String },
}

// Wire protocol message types
const MSG_REGISTER: u8 = 1;
const MSG_JOIN_ROOM: u8 = 2;
const MSG_LEAVE_ROOM: u8 = 3;
const MSG_PEER_JOINED: u8 = 4;
const MSG_PEER_LEFT: u8 = 5;
const MSG_PUNCH_REQUEST: u8 = 6;
const MSG_KEY_EXCHANGE: u8 = 7;
const MSG_RELAY: u8 = 8;
const MSG_ERROR: u8 = 9;

// UUID size in bytes
const UUID_SIZE: usize = 16;

/// Client for connecting to a signaling server.
pub struct SignalingClient {
    stream: TcpStream,
    local_id: PeerId,
    recv_buf: Vec<u8>,
}

impl SignalingClient {
    /// Connect to a signaling server.
    pub async fn connect(addr: &str, local_udp_addr: SocketAddr) -> io::Result<Self> {
        let mut stream = TcpStream::connect(addr).await?;
        
        // Send registration
        let mut buf = vec![MSG_REGISTER];
        buf.extend_from_slice(&local_udp_addr.port().to_le_bytes());
        
        // Include local IP for private address detection
        match local_udp_addr.ip() {
            std::net::IpAddr::V4(ip) => {
                buf.push(4);
                buf.extend_from_slice(&ip.octets());
            }
            std::net::IpAddr::V6(ip) => {
                buf.push(6);
                buf.extend_from_slice(&ip.octets());
            }
        }
        
        Self::write_message(&mut stream, &buf).await?;
        
        // Read peer ID (UUID)
        let msg = Self::read_message_static(&mut stream).await?;
        if msg.len() < 1 + UUID_SIZE || msg[0] != MSG_REGISTER {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid registration response"));
        }
        
        let local_id = read_uuid(&msg[1..1 + UUID_SIZE]);
        
        Ok(Self {
            stream,
            local_id,
            recv_buf: Vec::with_capacity(4096),
        })
    }
    
    /// Returns the local peer ID assigned by the server.
    pub fn local_id(&self) -> PeerId {
        self.local_id
    }
    
    /// Join a room.
    pub async fn join_room(&mut self, room_id: &str, local_addr: SocketAddr) -> io::Result<()> {
        let mut buf = vec![MSG_JOIN_ROOM];
        buf.extend_from_slice(&(room_id.len() as u16).to_le_bytes());
        buf.extend_from_slice(room_id.as_bytes());
        buf.extend_from_slice(&local_addr.port().to_le_bytes());
        
        Self::write_message(&mut self.stream, &buf).await
    }
    
    /// Leave a room.
    pub async fn leave_room(&mut self, room_id: &str) -> io::Result<()> {
        let mut buf = vec![MSG_LEAVE_ROOM];
        buf.extend_from_slice(&(room_id.len() as u16).to_le_bytes());
        buf.extend_from_slice(room_id.as_bytes());
        
        Self::write_message(&mut self.stream, &buf).await
    }
    
    /// Request hole-punching to a peer.
    pub async fn request_punch(&mut self, peer_id: PeerId, local_addr: SocketAddr) -> io::Result<()> {
        let mut buf = vec![MSG_PUNCH_REQUEST];
        buf.extend_from_slice(peer_id.as_bytes());
        buf.extend_from_slice(&local_addr.port().to_le_bytes());
        
        Self::write_message(&mut self.stream, &buf).await
    }
    
    /// Relay data to a peer via the server.
    pub async fn relay(&mut self, peer_id: PeerId, data: &[u8]) -> io::Result<()> {
        let mut buf = vec![MSG_RELAY];
        buf.extend_from_slice(peer_id.as_bytes());
        buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
        buf.extend_from_slice(data);
        
        Self::write_message(&mut self.stream, &buf).await
    }
    
    /// Poll for messages from the signaling server.
    pub async fn poll(&mut self) -> io::Result<Vec<SignalingMessage>> {
        let mut messages = Vec::new();
        
        // Non-blocking read
        self.stream.set_nodelay(true)?;
        
        loop {
            let mut len_buf = [0u8; 4];
            match self.stream.try_read(&mut len_buf) {
                Ok(0) => return Err(io::Error::new(io::ErrorKind::ConnectionReset, "Disconnected")),
                Ok(4) => {
                    let len = u32::from_le_bytes(len_buf) as usize;
                    let mut buf = vec![0u8; len];
                    self.stream.read_exact(&mut buf).await?;
                    
                    if let Some(msg) = self.parse_message(&buf) {
                        messages.push(msg);
                    }
                }
                Ok(_) => break,
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }
        
        Ok(messages)
    }
    
    fn parse_message(&self, buf: &[u8]) -> Option<SignalingMessage> {
        if buf.is_empty() { return None; }
        
        match buf[0] {
            MSG_PEER_JOINED => {
                // 1 + 16 (uuid) + 2 (port) + 1 (ip_type) + 4 (ipv4) = 24 min
                if buf.len() < 1 + UUID_SIZE + 7 { return None; }
                
                let peer_id = read_uuid(&buf[1..1 + UUID_SIZE]);
                let offset = 1 + UUID_SIZE;
                
                let port = u16::from_le_bytes([buf[offset], buf[offset + 1]]);
                let ip_type = buf[offset + 2];
                
                let public_addr = if ip_type == 4 && buf.len() >= offset + 7 {
                    let ip = std::net::Ipv4Addr::new(
                        buf[offset + 3], buf[offset + 4], buf[offset + 5], buf[offset + 6]
                    );
                    SocketAddr::new(std::net::IpAddr::V4(ip), port)
                } else {
                    return None;
                };
                
                // Optional private address
                let priv_offset = offset + 7;
                let private_addr = if buf.len() >= priv_offset + 7 && buf[priv_offset] == 4 {
                    let priv_port = u16::from_le_bytes([buf[priv_offset + 1], buf[priv_offset + 2]]);
                    let ip = std::net::Ipv4Addr::new(
                        buf[priv_offset + 3], buf[priv_offset + 4], 
                        buf[priv_offset + 5], buf[priv_offset + 6]
                    );
                    Some(SocketAddr::new(std::net::IpAddr::V4(ip), priv_port))
                } else {
                    None
                };
                
                Some(SignalingMessage::PeerJoined { peer_id, public_addr, private_addr })
            }
            
            MSG_PEER_LEFT => {
                if buf.len() < 1 + UUID_SIZE { return None; }
                let peer_id = read_uuid(&buf[1..1 + UUID_SIZE]);
                Some(SignalingMessage::PeerLeft { peer_id })
            }
            
            MSG_KEY_EXCHANGE => {
                if buf.len() < 1 + UUID_SIZE + 32 { return None; }
                
                let peer_id = read_uuid(&buf[1..1 + UUID_SIZE]);
                let offset = 1 + UUID_SIZE;
                
                let mut shared_key = [0u8; 32];
                shared_key.copy_from_slice(&buf[offset..offset + 32]);
                
                Some(SignalingMessage::KeyExchange { peer_id, shared_key })
            }
            
            MSG_RELAY => {
                if buf.len() < 1 + UUID_SIZE + 4 { return None; }
                
                let peer_id = read_uuid(&buf[1..1 + UUID_SIZE]);
                let offset = 1 + UUID_SIZE;
                
                let data_len = u32::from_le_bytes([
                    buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3]
                ]) as usize;
                
                if buf.len() < offset + 4 + data_len { return None; }
                
                let data = buf[offset + 4..offset + 4 + data_len].to_vec();
                
                Some(SignalingMessage::RelayedData { peer_id, data })
            }
            
            MSG_ERROR => {
                let msg_len = if buf.len() > 3 {
                    u16::from_le_bytes([buf[1], buf[2]]) as usize
                } else {
                    0
                };
                
                let message = if buf.len() >= 3 + msg_len {
                    String::from_utf8_lossy(&buf[3..3 + msg_len]).to_string()
                } else {
                    "Unknown error".to_string()
                };
                
                Some(SignalingMessage::Error { message })
            }
            
            _ => None,
        }
    }
    
    async fn write_message(stream: &mut TcpStream, data: &[u8]) -> io::Result<()> {
        let len = (data.len() as u32).to_le_bytes();
        stream.write_all(&len).await?;
        stream.write_all(data).await?;
        stream.flush().await
    }
    
    async fn read_message_static(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let len = u32::from_le_bytes(len_buf) as usize;
        
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf).await?;
        Ok(buf)
    }
}

/// Configuration for the signaling server.
#[derive(Debug, Clone)]
pub struct SignalingConfig {
    /// Maximum peers per room (0 = unlimited).
    pub max_peers_per_room: usize,
    /// Message buffer size per client.
    pub message_buffer_size: usize,
}

impl Default for SignalingConfig {
    fn default() -> Self {
        Self {
            max_peers_per_room: 64, // Default 64 peers per room
            message_buffer_size: 256, // Larger buffer for many peers
        }
    }
}

/// Room data on the signaling server.
struct RoomData {
    peers: HashMap<PeerId, PeerInfo>,
}

struct PeerInfo {
    public_addr: SocketAddr,
    private_addr: Option<SocketAddr>,
    tx: mpsc::Sender<Vec<u8>>,
}

/// Simple signaling server for P2P connection establishment.
///
/// This server helps peers discover each other and relay messages
/// when direct connections aren't possible.
pub struct SignalingServer {
    listener: TcpListener,
    rooms: Arc<RwLock<HashMap<String, RoomData>>>,
    peers: Arc<RwLock<HashMap<PeerId, PeerInfo>>>,
    config: Arc<SignalingConfig>,
}

impl SignalingServer {
    /// Bind the signaling server to an address with default config.
    pub async fn bind(addr: &str) -> io::Result<Self> {
        Self::bind_with_config(addr, SignalingConfig::default()).await
    }
    
    /// Bind with custom configuration.
    pub async fn bind_with_config(addr: &str, config: SignalingConfig) -> io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        
        Ok(Self {
            listener,
            rooms: Arc::new(RwLock::new(HashMap::new())),
            peers: Arc::new(RwLock::new(HashMap::new())),
            config: Arc::new(config),
        })
    }
    
    /// Run the signaling server.
    pub async fn run(self) -> io::Result<()> {
        loop {
            let (stream, addr) = self.listener.accept().await?;
            let rooms = Arc::clone(&self.rooms);
            let peers = Arc::clone(&self.peers);
            let config = Arc::clone(&self.config);
            
            tokio::spawn(async move {
                if let Err(e) = Self::handle_client(stream, addr, rooms, peers, config).await {
                    eprintln!("Client error: {}", e);
                }
            });
        }
    }
    
    async fn handle_client(
        mut stream: TcpStream,
        client_addr: SocketAddr,
        rooms: Arc<RwLock<HashMap<String, RoomData>>>,
        peers: Arc<RwLock<HashMap<PeerId, PeerInfo>>>,
        config: Arc<SignalingConfig>,
    ) -> io::Result<()> {
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(config.message_buffer_size);
        
        // Generate UUID for this peer
        let peer_id = Uuid::new_v4();
        
        // Wait for registration
        let msg = SignalingClient::read_message_static(&mut stream).await?;
        if msg.is_empty() || msg[0] != MSG_REGISTER {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Expected registration"));
        }
        
        let client_port = u16::from_le_bytes([msg[1], msg[2]]);
        let public_addr = SocketAddr::new(client_addr.ip(), client_port);
        
        // Parse private address if provided
        let private_addr = if msg.len() >= 8 && msg[3] == 4 {
            let ip = std::net::Ipv4Addr::new(msg[4], msg[5], msg[6], msg[7]);
            Some(SocketAddr::new(std::net::IpAddr::V4(ip), client_port))
        } else {
            None
        };
        
        // Store peer info
        {
            let mut peers_lock = peers.write().await;
            peers_lock.insert(peer_id, PeerInfo {
                public_addr,
                private_addr,
                tx: tx.clone(),
            });
        }
        
        // Send peer ID (UUID) back
        let mut response = vec![MSG_REGISTER];
        response.extend_from_slice(peer_id.as_bytes());
        SignalingClient::write_message(&mut stream, &response).await?;
        
        let mut current_room: Option<String> = None;
        
        // Main loop
        loop {
            tokio::select! {
                // Outgoing messages
                Some(data) = rx.recv() => {
                    if let Err(e) = SignalingClient::write_message(&mut stream, &data).await {
                        eprintln!("Failed to send to peer {}: {}", peer_id, e);
                        break;
                    }
                }
                
                // Incoming messages
                result = SignalingClient::read_message_static(&mut stream) => {
                    match result {
                        Ok(msg) => {
                            Self::handle_message(
                                peer_id,
                                &msg,
                                &mut current_room,
                                public_addr,
                                private_addr,
                                &rooms,
                                &peers,
                                &tx,
                                &config,
                            ).await?;
                        }
                        Err(_) => break,
                    }
                }
            }
        }
        
        // Cleanup
        if let Some(room_id) = &current_room {
            let mut rooms_lock = rooms.write().await;
            if let Some(room) = rooms_lock.get_mut(room_id) {
                room.peers.remove(&peer_id);
                
                // Notify other peers
                let mut leave_msg = vec![MSG_PEER_LEFT];
                leave_msg.extend_from_slice(peer_id.as_bytes());
                
                for (_, peer_info) in &room.peers {
                    let _ = peer_info.tx.send(leave_msg.clone()).await;
                }
            }
        }
        
        peers.write().await.remove(&peer_id);
        
        Ok(())
    }
    
    async fn handle_message(
        peer_id: PeerId,
        msg: &[u8],
        current_room: &mut Option<String>,
        public_addr: SocketAddr,
        private_addr: Option<SocketAddr>,
        rooms: &Arc<RwLock<HashMap<String, RoomData>>>,
        peers: &Arc<RwLock<HashMap<PeerId, PeerInfo>>>,
        tx: &mpsc::Sender<Vec<u8>>,
        config: &SignalingConfig,
    ) -> io::Result<()> {
        if msg.is_empty() { return Ok(()); }
        
        match msg[0] {
            MSG_JOIN_ROOM => {
                if msg.len() < 3 { return Ok(()); }
                
                let room_len = u16::from_le_bytes([msg[1], msg[2]]) as usize;
                if msg.len() < 3 + room_len { return Ok(()); }
                
                let room_id = String::from_utf8_lossy(&msg[3..3 + room_len]).to_string();
                
                // Check room capacity before joining
                {
                    let rooms_lock = rooms.read().await;
                    if let Some(room) = rooms_lock.get(&room_id) {
                        if config.max_peers_per_room > 0 && room.peers.len() >= config.max_peers_per_room {
                            // Room is full, send error
                            let mut err_msg = vec![MSG_ERROR];
                            let error_str = "Room is full";
                            err_msg.extend_from_slice(&(error_str.len() as u16).to_le_bytes());
                            err_msg.extend_from_slice(error_str.as_bytes());
                            let _ = tx.send(err_msg).await;
                            return Ok(());
                        }
                    }
                }
                
                // Leave current room
                if let Some(old_room) = current_room.take() {
                    let mut rooms_lock = rooms.write().await;
                    if let Some(room) = rooms_lock.get_mut(&old_room) {
                        room.peers.remove(&peer_id);
                    }
                }
                
                // Join new room
                let mut rooms_lock = rooms.write().await;
                let room = rooms_lock.entry(room_id.clone()).or_insert_with(|| RoomData {
                    peers: HashMap::new(),
                });
                
                // Notify existing peers about new peer
                let mut join_msg = vec![MSG_PEER_JOINED];
                join_msg.extend_from_slice(peer_id.as_bytes());
                join_msg.extend_from_slice(&public_addr.port().to_le_bytes());
                join_msg.push(4); // IPv4
                if let std::net::IpAddr::V4(ip) = public_addr.ip() {
                    join_msg.extend_from_slice(&ip.octets());
                }
                if let Some(priv_addr) = private_addr {
                    join_msg.push(4);
                    join_msg.extend_from_slice(&priv_addr.port().to_le_bytes());
                    if let std::net::IpAddr::V4(ip) = priv_addr.ip() {
                        join_msg.extend_from_slice(&ip.octets());
                    }
                }
                
                for (_, peer_info) in &room.peers {
                    let _ = peer_info.tx.send(join_msg.clone()).await;
                }
                
                // Notify new peer about existing peers
                for (&existing_id, peer_info) in &room.peers {
                    let mut notify_msg = vec![MSG_PEER_JOINED];
                    notify_msg.extend_from_slice(existing_id.as_bytes());
                    notify_msg.extend_from_slice(&peer_info.public_addr.port().to_le_bytes());
                    notify_msg.push(4);
                    if let std::net::IpAddr::V4(ip) = peer_info.public_addr.ip() {
                        notify_msg.extend_from_slice(&ip.octets());
                    }
                    if let Some(priv_addr) = peer_info.private_addr {
                        notify_msg.push(4);
                        notify_msg.extend_from_slice(&priv_addr.port().to_le_bytes());
                        if let std::net::IpAddr::V4(ip) = priv_addr.ip() {
                            notify_msg.extend_from_slice(&ip.octets());
                        }
                    }
                    let _ = tx.send(notify_msg).await;
                    
                    // Generate shared key for the pair
                    let mut shared_key = [0u8; 32];
                    rand::RngCore::fill_bytes(&mut rand::rng(), &mut shared_key);
                    
                    // Send key to both peers
                    let mut key_msg_a = vec![MSG_KEY_EXCHANGE];
                    key_msg_a.extend_from_slice(existing_id.as_bytes());
                    key_msg_a.extend_from_slice(&shared_key);
                    let _ = tx.send(key_msg_a).await;
                    
                    let mut key_msg_b = vec![MSG_KEY_EXCHANGE];
                    key_msg_b.extend_from_slice(peer_id.as_bytes());
                    key_msg_b.extend_from_slice(&shared_key);
                    let _ = peer_info.tx.send(key_msg_b).await;
                }
                
                // Add peer to room
                room.peers.insert(peer_id, PeerInfo {
                    public_addr,
                    private_addr,
                    tx: tx.clone(),
                });
                
                *current_room = Some(room_id);
            }
            
            MSG_RELAY => {
                if msg.len() < 1 + UUID_SIZE + 4 { return Ok(()); }
                
                let target_id = read_uuid(&msg[1..1 + UUID_SIZE]);
                let offset = 1 + UUID_SIZE;
                
                let data_len = u32::from_le_bytes([
                    msg[offset], msg[offset + 1], msg[offset + 2], msg[offset + 3]
                ]) as usize;
                
                if msg.len() < offset + 4 + data_len { return Ok(()); }
                
                let data = &msg[offset + 4..offset + 4 + data_len];
                
                // Forward to target peer
                let peers_lock = peers.read().await;
                if let Some(target) = peers_lock.get(&target_id) {
                    let mut relay_msg = vec![MSG_RELAY];
                    relay_msg.extend_from_slice(peer_id.as_bytes());
                    relay_msg.extend_from_slice(&(data.len() as u32).to_le_bytes());
                    relay_msg.extend_from_slice(data);
                    let _ = target.tx.send(relay_msg).await;
                }
            }
            
            _ => {}
        }
        
        Ok(())
    }
}

/// Read UUID from bytes.
fn read_uuid(bytes: &[u8]) -> Uuid {
    let mut arr = [0u8; 16];
    arr.copy_from_slice(&bytes[..16]);
    Uuid::from_bytes(arr)
}
