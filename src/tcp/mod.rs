//! TCP fallback transport for restricted networks.
#![allow(dead_code)] // Some fields reserved for future use
//!
//! When UDP is blocked (corporate firewalls, some mobile networks),
//! this module provides TCP-based transport with the same encryption.
//!
//! # Architecture
//!
//! ```text
//! ┌────────────────────────────────────────────────────────────┐
//! │                    HybridSocket                            │
//! │  ┌──────────────┐              ┌──────────────┐            │
//! │  │     UDP      │◄── Try ────►│     TCP      │            │
//! │  │  (Primary)   │   First      │  (Fallback)  │            │
//! │  └──────────────┘              └──────────────┘            │
//! │         │                             │                    │
//! │         └─────────┬───────────────────┘                    │
//! │                   ▼                                        │
//! │          ┌──────────────┐                                  │
//! │          │  ChaCha20    │                                  │
//! │          │  Poly1305    │                                  │
//! │          └──────────────┘                                  │
//! └────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Usage
//!
//! ```rust,no_run
//! use fastnet::tcp::{HybridSocket, TransportMode};
//!
//! #[tokio::main]
//! async fn main() -> std::io::Result<()> {
//!     // Connect with automatic fallback
//!     let mut socket = HybridSocket::connect("game.example.com:7778").await?;
//!     
//!     // Check which transport is being used
//!     match socket.transport_mode() {
//!         TransportMode::Udp => println!("Using UDP (optimal)"),
//!         TransportMode::Tcp => println!("Using TCP (fallback)"),
//!     }
//!     
//!     // Use normally - API is the same
//!     socket.send(0, b"Hello!".to_vec()).await?;
//!     
//!     Ok(())
//! }
//! ```

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio_rustls::server::TlsStream as ServerTlsStream;
use tokio_rustls::client::TlsStream as ClientTlsStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_rustls::rustls::{self, pki_types::{CertificateDer, PrivateKeyDer, ServerName}};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::Aead};
use chacha20poly1305::aead::generic_array::GenericArray;
use uuid::Uuid;

use crate::types::SessionId;

const UUID_SIZE: usize = 16;

/// Current transport mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportMode {
    /// UDP transport (optimal, low latency).
    Udp,
    /// TCP transport (fallback, higher latency but more reliable through firewalls).
    Tcp,
}

/// Events from the hybrid socket.
#[derive(Debug)]
pub enum HybridEvent {
    /// A peer connected.
    Connected(SessionId),
    /// Data received.
    Data(SessionId, u8, Vec<u8>),
    /// A peer disconnected.
    Disconnected(SessionId),
    /// Transport mode changed.
    TransportChanged(TransportMode),
}

/// Configuration for hybrid transport.
#[derive(Debug, Clone)]
pub struct HybridConfig {
    /// Timeout for UDP connectivity test.
    pub udp_test_timeout: Duration,
    /// Number of UDP test packets before falling back.
    pub udp_test_packets: u8,
    /// Enable automatic fallback to TCP.
    pub auto_fallback: bool,
    /// TCP keepalive interval.
    pub tcp_keepalive: Duration,
}

impl Default for HybridConfig {
    fn default() -> Self {
        Self {
            udp_test_timeout: Duration::from_secs(3),
            udp_test_packets: 3,
            auto_fallback: true,
            tcp_keepalive: Duration::from_secs(30),
        }
    }
}

/// Per-peer encryption state.
struct PeerCipher {
    encrypt: ChaCha20Poly1305,
    decrypt: ChaCha20Poly1305,
    nonce: u64,
}

impl PeerCipher {
    fn new(send_key: &[u8; 32], recv_key: &[u8; 32]) -> Self {
        Self {
            encrypt: ChaCha20Poly1305::new(GenericArray::from_slice(send_key)),
            decrypt: ChaCha20Poly1305::new(GenericArray::from_slice(recv_key)),
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

/// Hybrid socket supporting both UDP and TCP transport.
///
/// Automatically detects if UDP is available and falls back to TCP if not.
pub struct HybridSocket {
    // UDP transport
    udp_socket: Option<UdpSocket>,
    
    // TCP transport
    tcp_stream: Option<ClientTlsStream<TcpStream>>,
    
    // Current mode
    mode: TransportMode,
    
    // Peer cipher
    cipher: Option<PeerCipher>,
    session_id: SessionId,
    
    // Server address
    server_addr: SocketAddr,
    
    // Config
    config: HybridConfig,
    
    // Buffers
    recv_buf: Box<[u8; 2048]>,
    events: Vec<HybridEvent>,
}

impl HybridSocket {
    /// Connect to a server with automatic transport selection.
    ///
    /// Tries UDP first, falls back to TCP if UDP is blocked.
    pub async fn connect(addr: &str) -> io::Result<Self> {
        Self::connect_with_config(addr, HybridConfig::default()).await
    }
    
    /// Connect with custom configuration.
    pub async fn connect_with_config(addr: &str, config: HybridConfig) -> io::Result<Self> {
        let server_addr: SocketAddr = addr.parse()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid address"))?;
        
        // Always establish TCP/TLS first for key exchange
        let tcp = TcpStream::connect(server_addr).await?;
        
        let tls_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InsecureVerifier))
            .with_no_client_auth();
        
        let connector = TlsConnector::from(Arc::new(tls_config));
        let domain = ServerName::try_from("localhost")
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid server name"))?;
        
        let mut tls = connector.connect(domain, tcp).await?;
        
        // Receive keys and configuration: session_id(16) + udp_port(2) + send_key(32) + recv_key(32)
        let mut key_buf = [0u8; 82];
        tls.read_exact(&mut key_buf).await?;
        
        let session_id = read_uuid(&key_buf[..UUID_SIZE]);
        let udp_port = u16::from_le_bytes([key_buf[UUID_SIZE], key_buf[UUID_SIZE + 1]]);
        
        let mut send_key = [0u8; 32];
        let mut recv_key = [0u8; 32];
        send_key.copy_from_slice(&key_buf[UUID_SIZE + 2..UUID_SIZE + 34]);
        recv_key.copy_from_slice(&key_buf[UUID_SIZE + 34..UUID_SIZE + 66]);
        
        let cipher = PeerCipher::new(&send_key, &recv_key);
        
        // Try UDP if configured
        let (mode, udp_socket) = if config.auto_fallback {
            let udp_addr = SocketAddr::new(server_addr.ip(), udp_port);
            match Self::test_udp(&config, udp_addr).await {
                Ok(socket) => (TransportMode::Udp, Some(socket)),
                Err(_) => (TransportMode::Tcp, None),
            }
        } else {
            (TransportMode::Tcp, None)
        };
        
        let mut socket = Self {
            udp_socket,
            tcp_stream: Some(tls),
            mode,
            cipher: Some(cipher),
            session_id,
            server_addr,
            config,
            recv_buf: Box::new([0u8; 2048]),
            events: Vec::new(),
        };
        
        socket.events.push(HybridEvent::Connected(session_id));
        
        Ok(socket)
    }
    
    async fn test_udp(config: &HybridConfig, addr: SocketAddr) -> io::Result<UdpSocket> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(addr).await?;
        
        // Send test packets
        let test_data = b"UDP_TEST";
        for _ in 0..config.udp_test_packets {
            socket.send(test_data).await?;
        }
        
        // Wait for response
        let mut buf = [0u8; 64];
        match tokio::time::timeout(config.udp_test_timeout, socket.recv(&mut buf)).await {
            Ok(Ok(_)) => Ok(socket),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "UDP test timeout")),
        }
    }
    
    /// Get the current transport mode.
    pub fn transport_mode(&self) -> TransportMode {
        self.mode
    }
    
    /// Get the session ID.
    pub fn session_id(&self) -> SessionId {
        self.session_id
    }
    
    /// Send data to the server.
    pub async fn send(&mut self, channel: u8, data: Vec<u8>) -> io::Result<()> {
        let cipher = self.cipher.as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "Not connected"))?;
        
        // Build packet: channel(1) + data
        let mut packet = Vec::with_capacity(1 + data.len());
        packet.push(channel);
        packet.extend_from_slice(&data);
        
        let encrypted = cipher.seal(&packet)
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Encryption failed"))?;
        
        match self.mode {
            TransportMode::Udp => {
                if let Some(socket) = &self.udp_socket {
                    socket.send(&encrypted).await?;
                }
            }
            TransportMode::Tcp => {
                if let Some(stream) = &mut self.tcp_stream {
                    // Frame the message: length(4) + data
                    let len = (encrypted.len() as u32).to_le_bytes();
                    stream.write_all(&len).await?;
                    stream.write_all(&encrypted).await?;
                    stream.flush().await?;
                }
            }
        }
        
        Ok(())
    }
    
    /// Poll for events.
    pub async fn poll(&mut self) -> io::Result<Vec<HybridEvent>> {
        match self.mode {
            TransportMode::Udp => self.poll_udp().await?,
            TransportMode::Tcp => self.poll_tcp().await?,
        }
        
        Ok(std::mem::take(&mut self.events))
    }
    
    async fn poll_udp(&mut self) -> io::Result<()> {
        // Collect packets first to avoid borrow issues
        let mut packets = Vec::new();
        
        if let Some(socket) = &self.udp_socket {
            loop {
                let mut buf = [0u8; 2048];
                match socket.try_recv(&mut buf) {
                    Ok(len) => {
                        packets.push(buf[..len].to_vec());
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => return Err(e),
                }
            }
        }
        
        // Process collected packets
        for packet in packets {
            self.handle_packet(&packet)?;
        }
        
        Ok(())
    }
    
    async fn poll_tcp(&mut self) -> io::Result<()> {
        let stream = self.tcp_stream.as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "TCP not available"))?;
        
        // Non-blocking read
        let mut len_buf = [0u8; 4];
        match tokio::time::timeout(Duration::from_millis(1), stream.read_exact(&mut len_buf)).await {
            Ok(Ok(_)) => {
                let len = u32::from_le_bytes(len_buf) as usize;
                let mut buf = vec![0u8; len];
                stream.read_exact(&mut buf).await?;
                self.handle_packet(&buf)?;
            }
            Ok(Err(e)) if e.kind() == io::ErrorKind::UnexpectedEof => {
                self.events.push(HybridEvent::Disconnected(self.session_id));
            }
            _ => {}
        }
        
        Ok(())
    }
    
    fn handle_packet(&mut self, data: &[u8]) -> io::Result<()> {
        if let Some(cipher) = &self.cipher {
            if let Some(decrypted) = cipher.open(data) {
                if !decrypted.is_empty() {
                    let channel = decrypted[0];
                    let payload = decrypted[1..].to_vec();
                    self.events.push(HybridEvent::Data(self.session_id, channel, payload));
                }
            }
        }
        Ok(())
    }
    
    /// Force switch to TCP transport.
    pub async fn switch_to_tcp(&mut self) -> io::Result<()> {
        if self.mode == TransportMode::Tcp {
            return Ok(());
        }
        
        self.udp_socket = None;
        self.mode = TransportMode::Tcp;
        self.events.push(HybridEvent::TransportChanged(TransportMode::Tcp));
        
        Ok(())
    }
}

/// Hybrid server supporting both UDP and TCP clients.
pub struct HybridServer {
    udp_socket: UdpSocket,
    tcp_listener: TcpListener,
    tls_acceptor: TlsAcceptor,
    peers: HashMap<SessionId, ServerPeer>,
    recv_buf: Box<[u8; 2048]>,
    events: Vec<HybridEvent>,
}

struct ServerPeer {
    mode: TransportMode,
    udp_addr: Option<SocketAddr>,
    tcp_stream: Option<ServerTlsStream<TcpStream>>,
    cipher: PeerCipher,
}

impl HybridServer {
    /// Bind the server to the specified addresses.
    pub async fn bind(
        udp_addr: SocketAddr,
        tcp_addr: SocketAddr,
        certs: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> io::Result<Self> {
        let udp_socket = UdpSocket::bind(udp_addr).await?;
        let tcp_listener = TcpListener::bind(tcp_addr).await?;
        
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        
        let tls_acceptor = TlsAcceptor::from(Arc::new(config));
        
        Ok(Self {
            udp_socket,
            tcp_listener,
            tls_acceptor,
            peers: HashMap::new(),
            recv_buf: Box::new([0u8; 2048]),
            events: Vec::new(),
        })
    }
    
    /// Poll for events.
    pub async fn poll(&mut self) -> io::Result<Vec<HybridEvent>> {
        // Accept new TCP connections
        loop {
            match self.tcp_listener.accept().now_or_never() {
                Some(Ok((tcp, addr))) => {
                    if let Ok(tls) = self.tls_acceptor.clone().accept(tcp).await {
                        self.handle_new_connection(tls, addr).await?;
                    }
                }
                _ => break,
            }
        }
        
        // Receive UDP packets
        loop {
            match self.udp_socket.try_recv_from(&mut self.recv_buf[..]) {
                Ok((len, addr)) => {
                    self.handle_udp_packet(len, addr)?;
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }
        
        // Poll TCP streams
        self.poll_tcp_streams().await?;
        
        Ok(std::mem::take(&mut self.events))
    }
    
    async fn handle_new_connection(
        &mut self,
        mut tls: ServerTlsStream<TcpStream>,
        _client_addr: SocketAddr,
    ) -> io::Result<()> {
        let session_id = Uuid::new_v4();
        
        // Generate keys
        let mut send_key = [0u8; 32];
        let mut recv_key = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut send_key);
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut recv_key);
        
        // Send connection info: session_id(16) + udp_port(2) + send_key(32) + recv_key(32)
        let udp_port = self.udp_socket.local_addr()?.port();
        
        let mut buf = [0u8; 82];
        buf[..UUID_SIZE].copy_from_slice(session_id.as_bytes());
        buf[UUID_SIZE..UUID_SIZE + 2].copy_from_slice(&udp_port.to_le_bytes());
        buf[UUID_SIZE + 2..UUID_SIZE + 34].copy_from_slice(&recv_key); // Client's send = our recv
        buf[UUID_SIZE + 34..UUID_SIZE + 66].copy_from_slice(&send_key); // Client's recv = our send
        
        tls.write_all(&buf).await?;
        
        let cipher = PeerCipher::new(&send_key, &recv_key);
        
        self.peers.insert(session_id, ServerPeer {
            mode: TransportMode::Tcp,
            udp_addr: None,
            tcp_stream: Some(tls),
            cipher,
        });
        
        self.events.push(HybridEvent::Connected(session_id));
        
        Ok(())
    }
    
    fn handle_udp_packet(&mut self, len: usize, addr: SocketAddr) -> io::Result<()> {
        // Check if it's a test packet
        if len == 8 && &self.recv_buf[..8] == b"UDP_TEST" {
            let _ = self.udp_socket.try_send_to(b"UDP_OK", addr);
            return Ok(());
        }
        
        // Find peer by address or try to decrypt
        let session_id = self.peers.iter()
            .find(|(_, p)| p.udp_addr == Some(addr))
            .map(|(&id, _)| id);
        
        if let Some(session_id) = session_id {
            if let Some(peer) = self.peers.get(&session_id) {
                if let Some(decrypted) = peer.cipher.open(&self.recv_buf[..len]) {
                    if !decrypted.is_empty() {
                        let channel = decrypted[0];
                        let payload = decrypted[1..].to_vec();
                        self.events.push(HybridEvent::Data(session_id, channel, payload));
                    }
                }
            }
        } else {
            // Try to identify peer by decryption
            for (&session_id, peer) in &mut self.peers {
                if let Some(decrypted) = peer.cipher.open(&self.recv_buf[..len]) {
                    peer.udp_addr = Some(addr);
                    peer.mode = TransportMode::Udp;
                    
                    if !decrypted.is_empty() {
                        let channel = decrypted[0];
                        let payload = decrypted[1..].to_vec();
                        self.events.push(HybridEvent::Data(session_id, channel, payload));
                    }
                    break;
                }
            }
        }
        
        Ok(())
    }
    
    async fn poll_tcp_streams(&mut self) -> io::Result<()> {
        let session_ids: Vec<_> = self.peers.keys().copied().collect();
        
        for session_id in session_ids {
            if let Some(peer) = self.peers.get_mut(&session_id) {
                if let Some(stream) = &mut peer.tcp_stream {
                    let mut len_buf = [0u8; 4];
                    match tokio::time::timeout(Duration::from_millis(1), stream.read_exact(&mut len_buf)).await {
                        Ok(Ok(_)) => {
                            let len = u32::from_le_bytes(len_buf) as usize;
                            let mut buf = vec![0u8; len];
                            if stream.read_exact(&mut buf).await.is_ok() {
                                if let Some(decrypted) = peer.cipher.open(&buf) {
                                    if !decrypted.is_empty() {
                                        let channel = decrypted[0];
                                        let payload = decrypted[1..].to_vec();
                                        self.events.push(HybridEvent::Data(session_id, channel, payload));
                                    }
                                }
                            }
                        }
                        Ok(Err(_)) => {
                            self.events.push(HybridEvent::Disconnected(session_id));
                        }
                        Err(_) => {}
                    }
                }
            }
        }
        
        Ok(())
    }
    
    /// Send data to a peer.
    pub async fn send(&mut self, session_id: SessionId, channel: u8, data: Vec<u8>) -> io::Result<()> {
        let peer = self.peers.get_mut(&session_id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Peer not found"))?;
        
        let mut packet = Vec::with_capacity(1 + data.len());
        packet.push(channel);
        packet.extend_from_slice(&data);
        
        let encrypted = peer.cipher.seal(&packet)
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Encryption failed"))?;
        
        match peer.mode {
            TransportMode::Udp => {
                if let Some(addr) = peer.udp_addr {
                    self.udp_socket.send_to(&encrypted, addr).await?;
                }
            }
            TransportMode::Tcp => {
                if let Some(stream) = &mut peer.tcp_stream {
                    let len = (encrypted.len() as u32).to_le_bytes();
                    stream.write_all(&len).await?;
                    stream.write_all(&encrypted).await?;
                    stream.flush().await?;
                }
            }
        }
        
        Ok(())
    }
    
    /// Get peer count.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }
    
    /// Get transport mode for a peer.
    pub fn peer_mode(&self, session_id: SessionId) -> Option<TransportMode> {
        self.peers.get(&session_id).map(|p| p.mode)
    }
}

// Insecure verifier for development (accepts any certificate)
#[derive(Debug)]
struct InsecureVerifier;

impl rustls::client::danger::ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

// Helper trait for non-blocking accept
trait NowOrNever {
    type Output;
    fn now_or_never(self) -> Option<Self::Output>;
}

impl<F: std::future::Future> NowOrNever for F {
    type Output = F::Output;
    fn now_or_never(self) -> Option<Self::Output> {
        use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
        
        const VTABLE: RawWakerVTable = RawWakerVTable::new(
            |_| RawWaker::new(std::ptr::null(), &VTABLE),
            |_| {},
            |_| {},
            |_| {},
        );
        
        let raw_waker = RawWaker::new(std::ptr::null(), &VTABLE);
        let waker = unsafe { Waker::from_raw(raw_waker) };
        let mut cx = Context::from_waker(&waker);
        
        let mut pinned = std::pin::pin!(self);
        match pinned.as_mut().poll(&mut cx) {
            Poll::Ready(v) => Some(v),
            Poll::Pending => None,
        }
    }
}

/// Read UUID from bytes.
fn read_uuid(bytes: &[u8]) -> Uuid {
    let mut arr = [0u8; 16];
    arr.copy_from_slice(&bytes[..16]);
    Uuid::from_bytes(arr)
}
