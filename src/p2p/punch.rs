//! NAT hole-punching utilities.
#![allow(dead_code)] // Utilities for future use
//!
//! This module provides utilities for NAT traversal using UDP hole-punching.

use std::net::SocketAddr;

/// NAT type detection result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatType {
    /// No NAT (public IP).
    None,
    /// Full cone NAT (easiest to traverse).
    FullCone,
    /// Restricted cone NAT.
    RestrictedCone,
    /// Port restricted cone NAT.
    PortRestrictedCone,
    /// Symmetric NAT (hardest to traverse).
    Symmetric,
    /// Unknown NAT type.
    Unknown,
}

/// Information about a peer's network configuration.
#[derive(Debug, Clone)]
pub struct PeerEndpoint {
    /// Public address (as seen by the signaling server).
    pub public_addr: SocketAddr,
    /// Private/local address (LAN IP).
    pub private_addr: Option<SocketAddr>,
    /// Detected NAT type.
    pub nat_type: NatType,
}

impl PeerEndpoint {
    /// Create a new peer endpoint.
    pub fn new(public_addr: SocketAddr) -> Self {
        Self {
            public_addr,
            private_addr: None,
            nat_type: NatType::Unknown,
        }
    }
    
    /// Check if peers are on the same LAN.
    pub fn same_lan(&self, other: &PeerEndpoint) -> bool {
        if let (Some(a), Some(b)) = (&self.private_addr, &other.private_addr) {
            // Check if IPs are in the same subnet (simple /24 check)
            match (a.ip(), b.ip()) {
                (std::net::IpAddr::V4(ip_a), std::net::IpAddr::V4(ip_b)) => {
                    let oct_a = ip_a.octets();
                    let oct_b = ip_b.octets();
                    oct_a[0] == oct_b[0] && oct_a[1] == oct_b[1] && oct_a[2] == oct_b[2]
                }
                _ => false,
            }
        } else {
            false
        }
    }
    
    /// Get the best address to try for connection.
    ///
    /// Prefers private address if on same LAN, otherwise public address.
    pub fn best_addr(&self, local: &PeerEndpoint) -> SocketAddr {
        if self.same_lan(local) {
            self.private_addr.unwrap_or(self.public_addr)
        } else {
            self.public_addr
        }
    }
}

/// Determine if direct P2P connection is likely to succeed.
///
/// Returns true if at least one peer has a traversable NAT.
pub fn can_punch(a: NatType, b: NatType) -> bool {
    match (a, b) {
        // At least one with no NAT or full cone
        (NatType::None, _) | (_, NatType::None) => true,
        (NatType::FullCone, _) | (_, NatType::FullCone) => true,
        
        // Both restricted but not symmetric
        (NatType::RestrictedCone, NatType::RestrictedCone) => true,
        (NatType::RestrictedCone, NatType::PortRestrictedCone) => true,
        (NatType::PortRestrictedCone, NatType::RestrictedCone) => true,
        (NatType::PortRestrictedCone, NatType::PortRestrictedCone) => true,
        
        // Symmetric NAT usually fails
        (NatType::Symmetric, NatType::Symmetric) => false,
        
        // Unknown - try anyway
        (NatType::Unknown, _) | (_, NatType::Unknown) => true,
        
        // Other combinations might work
        _ => true,
    }
}
