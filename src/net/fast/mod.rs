//! Fast networking implementation with built-in encryption.
//!
//! This module contains the core networking components:
//!
//! - [`SecureSocket`] - Main API for encrypted UDP communication
//! - [`SecureEvent`] - Network events (connect, data, disconnect)
//!
//! ## Performance Modules
//!
//! - [`fec`] - Forward Error Correction for packet recovery
//! - [`delta`] - Delta compression for bandwidth reduction
//! - [`priority`] - Priority queues for latency-sensitive data
//! - [`jitter`] - Jitter buffer for smooth streaming
//! - [`metrics`] - Real-time network metrics
//! - [`interest`] - Spatial filtering for MMO scalability
//!
//! ## Security Modules
//!
//! - [`reconnect`] - 0-RTT session resumption with replay protection
//!
//! ## Internal Modules
//!
//! - `packet` - Packet format, headers, and fragmentation
//! - `channel` - Reliability and ordering modes
//! - `peer` - Connection state and RTT estimation
//! - `secure` - TLS handshake and ChaCha20-Poly1305 encryption
//! - `tuning` - Socket tuning and OS-level optimizations

mod packet;
mod channel;
mod peer;
mod secure;
pub mod tuning;
pub mod fec;
pub mod delta;
pub mod priority;
pub mod jitter;
pub mod metrics;
pub mod reconnect;
pub mod interest;
pub mod migration;

pub use secure::{SecureSocket, SecureEvent};
pub use tuning::{SocketConfig, batch};
