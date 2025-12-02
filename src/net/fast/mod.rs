//! Fast networking implementation with built-in encryption.
//!
//! This module contains the core networking components:
//!
//! - [`SecureSocket`] - Main API for encrypted UDP communication
//! - [`SecureEvent`] - Network events (connect, data, disconnect)
//!
//! ## Internal Modules
//!
//! - `packet` - Packet format, headers, and fragmentation
//! - `channel` - Reliability and ordering modes
//! - `peer` - Connection state and RTT estimation
//! - `secure` - TLS handshake and ChaCha20-Poly1305 encryption

mod packet;
mod channel;
mod peer;
mod secure;

pub use secure::{SecureSocket, SecureEvent};
