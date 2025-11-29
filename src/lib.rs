//! # FastNet - Ultra-Low Latency Encrypted Networking
//!
//! FastNet is a high-performance networking library designed for real-time multiplayer games.
//! It provides encrypted UDP communication with latencies as low as **15 microseconds**
//! while maintaining strong security through TLS 1.3 and ChaCha20-Poly1305 encryption.
//!
//! ## Features
//!
//! - **Ultra-Low Latency**: ~15µs average RTT on localhost
//! - **Built-in Encryption**: TLS 1.3 handshake + ChaCha20-Poly1305 AEAD
//! - **Zero Configuration Security**: Encryption is always on
//! - **Game Engine Ready**: C/C++ FFI for Unreal Engine, Unity, Godot
//!
//! ## Quick Start
//!
//! ### Server
//!
//! ```rust,no_run
//! use fastnet::net::{SecureSocket, SecureEvent};
//! use std::net::SocketAddr;
//!
//! #[tokio::main]
//! async fn main() -> std::io::Result<()> {
//!     let udp_addr: SocketAddr = "0.0.0.0:7777".parse().unwrap();
//!     let tcp_addr: SocketAddr = "0.0.0.0:7778".parse().unwrap();
//!     
//!     // Load your TLS certificates
//!     let certs = vec![]; // Load from file
//!     let key = todo!();  // Load from file
//!     
//!     let mut socket = SecureSocket::bind_server(udp_addr, tcp_addr, certs, key).await?;
//!     
//!     loop {
//!         for event in socket.poll().await? {
//!             match event {
//!                 SecureEvent::Connected(peer_id) => {
//!                     println!("Peer {} connected", peer_id);
//!                 }
//!                 SecureEvent::Data(peer_id, channel, data) => {
//!                     // Echo back
//!                     socket.send(peer_id, channel, data).await?;
//!                 }
//!                 SecureEvent::Disconnected(peer_id) => {
//!                     println!("Peer {} disconnected", peer_id);
//!                 }
//!             }
//!         }
//!     }
//! }
//! ```
//!
//! ### Client
//!
//! ```rust,no_run
//! use fastnet::net::{SecureSocket, SecureEvent};
//!
//! #[tokio::main]
//! async fn main() -> std::io::Result<()> {
//!     let server_addr = "127.0.0.1:7778".parse().unwrap();
//!     let mut socket = SecureSocket::connect(server_addr).await?;
//!     
//!     // Send data on channel 0
//!     socket.send(1, 0, b"Hello!".to_vec()).await?;
//!     
//!     // Poll for events
//!     for event in socket.poll().await? {
//!         if let SecureEvent::Data(_, _, data) = event {
//!             println!("Received: {:?}", data);
//!         }
//!     }
//!     
//!     Ok(())
//! }
//! ```
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │                     SecureSocket                        │
//! │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐ │
//! │  │ TLS 1.3     │  │ ChaCha20    │  │ Channels        │ │
//! │  │ Handshake   │──│ Poly1305    │──│ (Reliable/etc)  │ │
//! │  └─────────────┘  └─────────────┘  └─────────────────┘ │
//! │                          │                              │
//! │                    ┌─────┴─────┐                       │
//! │                    │    UDP    │                       │
//! │                    └───────────┘                       │
//! └─────────────────────────────────────────────────────────┘
//! ```
//!
//! ## C/C++ Integration
//!
//! Build with the `ffi` feature to generate a C-compatible dynamic library:
//!
//! ```bash
//! cargo build --release --features ffi
//! ```
//!
//! See the `include/fastnet.h` header for the C API documentation.

pub mod net;

#[cfg(feature = "ffi")]
pub mod ffi;

// Re-export main types at crate root for convenience
pub use net::{SecureSocket, SecureEvent};
