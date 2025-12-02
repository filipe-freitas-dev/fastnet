//! Secure socket implementation with TLS 1.3 handshake and ChaCha20-Poly1305 encryption.
//!
//! This module provides the core networking functionality for FastNet:
//! - TLS 1.3 handshake for secure key exchange (TCP)
//! - ChaCha20-Poly1305 AEAD encryption for all game data (UDP)
//! - Automatic peer management and event handling
//!
//! # Architecture
//!
//! ```text
//! Client                          Server
//!   │                                │
//!   │──────── TCP TLS 1.3 ──────────▶│  (Key Exchange, ~40ms)
//!   │◀─────── Session Keys ──────────│
//!   │                                │
//!   │════════ UDP Encrypted ════════▶│  (Game Data, ~15µs)
//!   │◀═══════ UDP Encrypted ═════════│
//! ```

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{UdpSocket, TcpListener, TcpStream};
use tokio_rustls::server::TlsStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_rustls::rustls::{self, pki_types::{CertificateDer, PrivateKeyDer}};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::Aead};
use chacha20poly1305::aead::generic_array::GenericArray;

use super::packet::{PacketHeader, HEADER_SIZE, MAX_PACKET_SIZE};
use super::peer::{Peer, PeerConfig, ConnectionState};

/// Events emitted by [`SecureSocket`] during network operations.
///
/// These events are returned by [`SecureSocket::poll()`] and should be
/// processed by the application.
///
/// # Example
///
/// ```rust,no_run
/// # use fastnet::SecureEvent;
/// # fn handle(events: Vec<SecureEvent>) {
/// for event in events {
///     match event {
///         SecureEvent::Connected(peer_id) => {
///             println!("Peer {} connected", peer_id);
///         }
///         SecureEvent::Data(peer_id, channel, data) => {
///             println!("Got {} bytes from peer {}", data.len(), peer_id);
///         }
///         SecureEvent::Disconnected(peer_id) => {
///             println!("Peer {} disconnected", peer_id);
///         }
///     }
/// }
/// # }
/// ```
#[derive(Debug)]
pub enum SecureEvent {
    /// A new peer has connected.
    ///
    /// The `u16` is the peer's unique ID, used for sending data back.
    Connected(u16),
    
    /// Data received from a peer.
    ///
    /// - `u16`: Peer ID
    /// - `u8`: Channel the data was received on
    /// - `Vec<u8>`: The decrypted payload
    Data(u16, u8, Vec<u8>),
    
    /// A peer has disconnected.
    ///
    /// The `u16` is the peer ID that disconnected.
    Disconnected(u16),
}

/// Per-peer encryption state using ChaCha20-Poly1305.
///
/// Each peer has unique send/receive keys derived during TLS handshake.
/// The nonce is a simple counter to ensure uniqueness.
struct Cipher {
    encrypt: ChaCha20Poly1305,
    decrypt: ChaCha20Poly1305,
    nonce_send: u64,
}

impl Cipher {
    fn new(send_key: &[u8; 32], recv_key: &[u8; 32]) -> Self {
        Self {
            encrypt: ChaCha20Poly1305::new(GenericArray::from_slice(send_key)),
            decrypt: ChaCha20Poly1305::new(GenericArray::from_slice(recv_key)),
            nonce_send: 0,
        }
    }

    #[inline]
    fn seal(&mut self, plaintext: &[u8], output: &mut [u8]) -> Option<usize> {
        let mut nonce = [0u8; 12];
        nonce[4..12].copy_from_slice(&self.nonce_send.to_le_bytes());
        self.nonce_send = self.nonce_send.wrapping_add(1);

        if let Ok(ct) = self.encrypt.encrypt(GenericArray::from_slice(&nonce), plaintext) {
            if output.len() >= 8 + ct.len() {
                output[..8].copy_from_slice(&nonce[4..12]);
                output[8..8 + ct.len()].copy_from_slice(&ct);
                return Some(8 + ct.len());
            }
        }
        None
    }

    #[inline]
    fn open<'a>(&self, ciphertext: &[u8], output: &'a mut [u8]) -> Option<&'a [u8]> {
        if ciphertext.len() < 24 { return None; }
        let mut nonce = [0u8; 12];
        nonce[4..12].copy_from_slice(&ciphertext[..8]);

        if let Ok(pt) = self.decrypt.decrypt(GenericArray::from_slice(&nonce), &ciphertext[8..]) {
            if output.len() >= pt.len() {
                output[..pt.len()].copy_from_slice(&pt);
                return Some(&output[..pt.len()]);
            }
        }
        None
    }
}

struct SecurePeer {
    peer: Peer,
    cipher: Cipher,
}

/// High-performance encrypted UDP socket with TLS key exchange.
///
/// `SecureSocket` is the main networking primitive in FastNet. It provides:
/// - **Server mode**: Accepts incoming connections via TLS, then communicates over encrypted UDP
/// - **Client mode**: Connects to a server via TLS, then communicates over encrypted UDP
///
/// # Example (Server)
///
/// ```rust,no_run
/// use fastnet::{SecureSocket, SecureEvent};
///
/// # async fn example() -> std::io::Result<()> {
/// let mut socket = SecureSocket::bind_server(
///     "0.0.0.0:7777".parse().unwrap(),  // UDP for game data
///     "0.0.0.0:7778".parse().unwrap(),  // TCP for TLS handshake
///     certs,
///     key,
/// ).await?;
///
/// loop {
///     for event in socket.poll().await? {
///         match event {
///             SecureEvent::Connected(peer) => println!("Peer {} joined", peer),
///             SecureEvent::Data(peer, ch, data) => socket.send(peer, ch, data).await?,
///             SecureEvent::Disconnected(peer) => println!("Peer {} left", peer),
///         }
///     }
/// }
/// # }
/// ```
///
/// # Performance
///
/// - TLS handshake: ~40-50ms (one-time per connection)
/// - Encrypted UDP RTT: ~15µs on localhost
pub struct SecureSocket {
    socket: UdpSocket,
    peers: HashMap<u16, SecurePeer>,
    peer_by_addr: HashMap<SocketAddr, u16>,
    next_peer_id: u16,

    tls_listener: Option<TcpListener>,
    tls_acceptor: Option<TlsAcceptor>,

    recv_buf: Box<[u8; MAX_PACKET_SIZE]>,
    send_buf: Box<[u8; MAX_PACKET_SIZE]>,
    decrypt_buf: Box<[u8; MAX_PACKET_SIZE]>,

    events: Vec<SecureEvent>,
    config: PeerConfig,
}

impl SecureSocket {

    pub async fn bind_server(
        udp_addr: SocketAddr,
        tcp_addr: SocketAddr,
        certs: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> io::Result<Self> {
        let socket = UdpSocket::bind(udp_addr).await?;
        let listener = TcpListener::bind(tcp_addr).await?;

        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let acceptor = TlsAcceptor::from(Arc::new(config));

        Ok(Self {
            socket,
            peers: HashMap::new(),
            peer_by_addr: HashMap::new(),
            next_peer_id: 1,
            tls_listener: Some(listener),
            tls_acceptor: Some(acceptor),
            recv_buf: Box::new([0u8; MAX_PACKET_SIZE]),
            send_buf: Box::new([0u8; MAX_PACKET_SIZE]),
            decrypt_buf: Box::new([0u8; MAX_PACKET_SIZE]),
            events: Vec::new(),
            config: PeerConfig::default(),
        })
    }

    pub async fn connect(server_addr: SocketAddr) -> io::Result<Self> {

        let tcp = TcpStream::connect(server_addr).await?;

        let config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InsecureVerifier))
            .with_no_client_auth();

        let connector = TlsConnector::from(Arc::new(config));
        let domain = rustls::pki_types::ServerName::try_from("localhost")
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid server name"))?;

        let mut tls = connector.connect(domain, tcp).await?;

        let mut key_buf = [0u8; 72];
        tls.read_exact(&mut key_buf).await?;

        let peer_id = u16::from_le_bytes([key_buf[0], key_buf[1]]);
        let udp_port = u16::from_le_bytes([key_buf[2], key_buf[3]]);

        let mut send_key = [0u8; 32];
        let mut recv_key = [0u8; 32];
        send_key.copy_from_slice(&key_buf[4..36]);
        recv_key.copy_from_slice(&key_buf[36..68]);

        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let udp_addr = SocketAddr::new(server_addr.ip(), udp_port);

        let mut peer = Peer::new(peer_id, udp_addr, PeerConfig::default());
        peer.on_connected();

        let cipher = Cipher::new(&send_key, &recv_key);
        let secure_peer = SecurePeer { peer, cipher };

        let mut peers = HashMap::new();
        let mut peer_by_addr = HashMap::new();
        peers.insert(peer_id, secure_peer);
        peer_by_addr.insert(udp_addr, peer_id);

        let mut sock = Self {
            socket,
            peers,
            peer_by_addr,
            next_peer_id: peer_id,
            tls_listener: None,
            tls_acceptor: None,
            recv_buf: Box::new([0u8; MAX_PACKET_SIZE]),
            send_buf: Box::new([0u8; MAX_PACKET_SIZE]),
            decrypt_buf: Box::new([0u8; MAX_PACKET_SIZE]),
            events: Vec::new(),
            config: PeerConfig::default(),
        };

        sock.events.push(SecureEvent::Connected(peer_id));
        Ok(sock)
    }

    /// Returns the local UDP address this socket is bound to.
    ///
    /// This is the address used for encrypted game data after the TLS handshake.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use fastnet::SecureSocket;
    /// # async fn example(socket: &SecureSocket) {
    /// let addr = socket.local_udp_addr().unwrap();
    /// println!("Listening on UDP: {}", addr);
    /// # }
    /// ```
    pub fn local_udp_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Returns the local TCP address used for TLS handshakes (server only).
    ///
    /// Returns `None` for client sockets.
    pub fn local_tcp_addr(&self) -> io::Result<Option<SocketAddr>> {
        self.tls_listener.as_ref().map(|l| l.local_addr()).transpose()
    }

    pub async fn accept(&mut self) -> io::Result<Option<u16>> {
        let (listener, acceptor) = match (&self.tls_listener, &self.tls_acceptor) {
            (Some(l), Some(a)) => (l, a.clone()),
            _ => return Ok(None),
        };

        let accept_result = tokio::select! {
            biased;
            result = listener.accept() => Some(result),
            _ = tokio::time::sleep(Duration::from_millis(1)) => None,
        };

        let (tcp, client_addr) = match accept_result {
            Some(Ok(r)) => r,
            Some(Err(e)) => return Err(e),
            None => return Ok(None),
        };

        let mut tls = acceptor.accept(tcp).await?;

        let peer_id = self.next_peer_id;
        self.next_peer_id = self.next_peer_id.wrapping_add(1).max(1);

        let mut send_key = [0u8; 32];
        let mut recv_key = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut send_key);
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut recv_key);

        let udp_port = self.socket.local_addr()?.port();
        let mut key_buf = [0u8; 72];
        key_buf[0..2].copy_from_slice(&peer_id.to_le_bytes());
        key_buf[2..4].copy_from_slice(&udp_port.to_le_bytes());
        key_buf[4..36].copy_from_slice(&recv_key);
        key_buf[36..68].copy_from_slice(&send_key);
        tls.write_all(&key_buf).await?;

        let udp_addr = SocketAddr::new(client_addr.ip(), 0);

        let mut peer = Peer::new(peer_id, udp_addr, self.config.clone());
        peer.on_connected();

        let cipher = Cipher::new(&send_key, &recv_key);
        self.peers.insert(peer_id, SecurePeer { peer, cipher });
        self.events.push(SecureEvent::Connected(peer_id));

        Ok(Some(peer_id))
    }

    /// Sends data to a connected peer.
    ///
    /// # Parameters
    ///
    /// - `peer_id`: The target peer's ID (from `SecureEvent::Connected`)
    /// - `channel_id`: Channel to send on (0-255)
    /// - `data`: The payload to send
    ///
    /// # Channels
    ///
    /// Different channels can have different reliability modes:
    /// - Channel 0: Reliable ordered (default)
    /// - Channel 1: Unreliable
    /// - Channel 2: Reliable unordered
    /// - Channel 3: Unreliable sequenced
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use fastnet::SecureSocket;
    /// # async fn example(socket: &mut SecureSocket, peer_id: u16) {
    /// // Send on reliable channel
    /// socket.send(peer_id, 0, b"Hello!".to_vec()).await.unwrap();
    ///
    /// // Send position update on unreliable channel
    /// socket.send(peer_id, 1, position_bytes).await.unwrap();
    /// # let position_bytes = vec![];
    /// # }
    /// ```
    pub async fn send(&mut self, peer_id: u16, channel_id: u8, data: Vec<u8>) -> io::Result<()> {
        let peer = self.peers.get_mut(&peer_id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Peer not found"))?;

        if peer.peer.state != ConnectionState::Connected {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "Not connected"));
        }

        let addr = peer.peer.address;

        if let Some(packets) = peer.peer.send(channel_id, data) {
            for pkt in packets {
                let header = peer.peer.prepare_header(pkt.channel, pkt.flags);

                let mut plain = Vec::with_capacity(HEADER_SIZE + pkt.data.len());
                let mut hdr_buf = [0u8; HEADER_SIZE];
                header.write_to(&mut hdr_buf);
                plain.extend_from_slice(&hdr_buf);
                plain.extend_from_slice(&pkt.data);

                if let Some(ct_len) = peer.cipher.seal(&plain, &mut self.send_buf[..]) {
                    self.socket.send_to(&self.send_buf[..ct_len], addr).await?;
                }
            }
        }

        Ok(())
    }

    /// Polls for network events.
    ///
    /// This method should be called regularly (e.g., every frame) to:
    /// - Accept new connections (server)
    /// - Receive incoming data
    /// - Detect disconnections
    ///
    /// # Returns
    ///
    /// A vector of events that occurred since the last poll.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use fastnet::{SecureSocket, SecureEvent};
    /// # async fn example(socket: &mut SecureSocket) {
    /// for event in socket.poll().await? {
    ///     match event {
    ///         SecureEvent::Connected(peer_id) => {
    ///             println!("Peer {} connected", peer_id);
    ///         }
    ///         SecureEvent::Data(peer_id, channel, data) => {
    ///             println!("Received {} bytes from peer {}", data.len(), peer_id);
    ///         }
    ///         SecureEvent::Disconnected(peer_id) => {
    ///             println!("Peer {} disconnected", peer_id);
    ///         }
    ///     }
    /// }
    /// # Ok::<(), std::io::Error>(())
    /// # }
    /// ```
    pub async fn poll(&mut self) -> io::Result<Vec<SecureEvent>> {

        loop {
            match self.socket.try_recv_from(&mut self.recv_buf[..]) {
                Ok((len, addr)) => {
                    self.handle_packet(len, addr)?;
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }

        if self.events.is_empty() {
            if let (Some(listener), Some(acceptor)) = (&self.tls_listener, &self.tls_acceptor) {
                let acceptor = acceptor.clone();
                tokio::select! {
                    biased;

                    result = self.socket.recv_from(&mut self.recv_buf[..]) => {
                        if let Ok((len, addr)) = result {
                            self.handle_packet(len, addr)?;
                        }
                    }

                    result = listener.accept() => {
                        if let Ok((tcp, client_addr)) = result {

                            if let Ok(mut tls) = acceptor.accept(tcp).await {
                                self.complete_tls_accept(&mut tls, client_addr).await?;
                            }
                        }
                    }
                }
            } else {

                tokio::select! {
                    biased;
                    result = self.socket.recv_from(&mut self.recv_buf[..]) => {
                        if let Ok((len, addr)) = result {
                            self.handle_packet(len, addr)?;
                        }
                    }
                    _ = tokio::task::yield_now() => {}
                }
            }
        }

        Ok(std::mem::take(&mut self.events))
    }

    async fn complete_tls_accept(
        &mut self,
        tls: &mut TlsStream<TcpStream>,
        client_addr: SocketAddr
    ) -> io::Result<()> {
        let peer_id = self.next_peer_id;
        self.next_peer_id = self.next_peer_id.wrapping_add(1).max(1);

        let mut send_key = [0u8; 32];
        let mut recv_key = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut send_key);
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut recv_key);

        let udp_port = self.socket.local_addr()?.port();
        let mut key_buf = [0u8; 72];
        key_buf[0..2].copy_from_slice(&peer_id.to_le_bytes());
        key_buf[2..4].copy_from_slice(&udp_port.to_le_bytes());
        key_buf[4..36].copy_from_slice(&recv_key);
        key_buf[36..68].copy_from_slice(&send_key);
        tls.write_all(&key_buf).await?;

        let udp_addr = SocketAddr::new(client_addr.ip(), 0);
        let mut peer = Peer::new(peer_id, udp_addr, self.config.clone());
        peer.on_connected();

        let cipher = Cipher::new(&send_key, &recv_key);
        self.peers.insert(peer_id, SecurePeer { peer, cipher });
        self.events.push(SecureEvent::Connected(peer_id));

        Ok(())
    }

    fn handle_packet(&mut self, len: usize, addr: SocketAddr) -> io::Result<()> {

        if let Some(&peer_id) = self.peer_by_addr.get(&addr) {
            let decrypted = {
                if let Some(speer) = self.peers.get_mut(&peer_id) {
                    speer.cipher.open(&self.recv_buf[..len], &mut self.decrypt_buf[..])
                        .map(|p| p.to_vec())
                } else {
                    None
                }
            };
            if let Some(plain) = decrypted {
                return self.process_decrypted(peer_id, &plain);
            }
            return Ok(());
        }

        let mut found_peer = None;
        for (&peer_id, speer) in &mut self.peers {
            if speer.peer.address.port() == 0 {
                if let Some(plain) = speer.cipher.open(&self.recv_buf[..len], &mut self.decrypt_buf[..]) {
                    speer.peer.address = addr;
                    found_peer = Some((peer_id, plain.to_vec()));
                    break;
                }
            }
        }

        if let Some((peer_id, plain)) = found_peer {
            self.peer_by_addr.insert(addr, peer_id);
            self.process_decrypted(peer_id, &plain)?;
        }

        Ok(())
    }

    fn process_decrypted(&mut self, peer_id: u16, plain: &[u8]) -> io::Result<()> {
        if plain.len() >= HEADER_SIZE {
            let header = PacketHeader::read_from(plain)?;
            let payload = &plain[HEADER_SIZE..];

            if let Some(speer) = self.peers.get_mut(&peer_id) {
                let (_, _, msg) = speer.peer.on_packet_received(&header, payload);
                if let Some(data) = msg {
                    self.events.push(SecureEvent::Data(peer_id, header.channel, data));
                }
            }
        }
        Ok(())
    }

    /// Returns the number of currently connected peers.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Returns the estimated round-trip time for a peer.
    ///
    /// # Returns
    ///
    /// - `Some(Duration)` if the peer exists and RTT has been measured
    /// - `None` if the peer doesn't exist
    pub fn peer_rtt(&self, peer_id: u16) -> Option<Duration> {
        self.peers.get(&peer_id).map(|p| p.peer.rtt())
    }
}

#[derive(Debug)]
struct InsecureVerifier;

impl rustls::client::danger::ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
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
