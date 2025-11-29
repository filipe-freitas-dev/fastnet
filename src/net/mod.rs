//! # FastNet Networking Module
//!
//! This module provides ultra-low latency encrypted networking for real-time games.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    SecureSocket                             │
//! │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
//! │  │ TLS 1.3     │  │ ChaCha20    │  │ Reliable Channels   │ │
//! │  │ Handshake   │──│ Poly1305    │──│ (optional)          │ │
//! │  └─────────────┘  └─────────────┘  └─────────────────────┘ │
//! │                          │                                  │
//! │                    ┌─────┴─────┐                           │
//! │                    │    UDP    │                           │
//! │                    └───────────┘                           │
//! └─────────────────────────────────────────────────────────────┘
//! ```

pub(crate) mod fast;

pub use fast::{SecureSocket, SecureEvent};
