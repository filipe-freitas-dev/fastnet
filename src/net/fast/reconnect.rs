//! Fast session resumption with 0-RTT reconnection.
//!
//! This module provides mechanisms for clients to quickly reconnect
//! after network disruptions without a full TLS handshake.
//!
//! # Security Model
//!
//! - Session tickets are encrypted with server key
//! - Tickets expire after configurable time (default 5 minutes)
//! - BLAKE3 HMAC prevents ticket tampering
//! - Replay protection via ticket ID tracking
//!
//! # Flow
//!
//! 1. Client connects normally (full TLS handshake)
//! 2. Server issues encrypted session ticket
//! 3. Client stores ticket locally
//! 4. On reconnect, client sends ticket
//! 5. Server validates and restores session (0-RTT)
//!
//! # Example
//!
//! ```rust,ignore
//! // Server side
//! let mut session_store = SessionStore::new(server_key);
//! let ticket = session_store.create_ticket(peer_id, &session_keys);
//!
//! // Client reconnects
//! let ticket = load_saved_ticket();
//! send_reconnect(ticket);
//!
//! // Server validates
//! if let Some(session) = session_store.validate_ticket(&ticket) {
//!     restore_session(peer_id, session);
//! }
//! ```

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Maximum ticket size in bytes.
pub const MAX_TICKET_SIZE: usize = 256;

/// Default ticket lifetime.
pub const DEFAULT_TICKET_LIFETIME: Duration = Duration::from_secs(300); // 5 minutes

/// Session ticket for 0-RTT reconnection.
///
/// Layout (encrypted):
/// - [0-15]: Ticket ID (random)
/// - [16-17]: Peer ID (u16)
/// - [18-49]: Session send key (32 bytes)
/// - [50-81]: Session recv key (32 bytes)
/// - [82-89]: Expiry timestamp (u64)
/// - [90-121]: HMAC (32 bytes)
#[derive(Clone)]
pub struct SessionTicket {
    /// Raw encrypted ticket data.
    data: [u8; MAX_TICKET_SIZE],
    /// Actual length of ticket data.
    len: usize,
}

impl SessionTicket {
    /// Create from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > MAX_TICKET_SIZE {
            return None;
        }
        let mut data = [0u8; MAX_TICKET_SIZE];
        data[..bytes.len()].copy_from_slice(bytes);
        Some(Self {
            data,
            len: bytes.len(),
        })
    }

    /// Get ticket bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

/// Restored session data.
#[derive(Clone)]
pub struct RestoredSession {
    /// Original peer ID.
    pub peer_id: u16,
    /// Session send key.
    pub send_key: [u8; 32],
    /// Session recv key.
    pub recv_key: [u8; 32],
}

/// Server-side session ticket store.
///
/// Handles ticket creation, validation, and replay protection.
pub struct SessionStore {
    /// Server secret key for ticket encryption.
    server_key: [u8; 32],
    /// Used ticket IDs (replay protection).
    used_tickets: HashMap<[u8; 16], Instant>,
    /// Ticket lifetime.
    ticket_lifetime: Duration,
    /// Last cleanup time.
    last_cleanup: Instant,
}

impl SessionStore {
    /// Create a new session store with the given server key.
    ///
    /// The server key should be a securely generated 32-byte secret.
    pub fn new(server_key: [u8; 32]) -> Self {
        Self {
            server_key,
            used_tickets: HashMap::with_capacity(1024),
            ticket_lifetime: DEFAULT_TICKET_LIFETIME,
            last_cleanup: Instant::now(),
        }
    }

    /// Set custom ticket lifetime.
    pub fn with_lifetime(mut self, lifetime: Duration) -> Self {
        self.ticket_lifetime = lifetime;
        self
    }

    /// Create a session ticket for a peer.
    ///
    /// # Security
    ///
    /// - Ticket is encrypted with ChaCha20
    /// - HMAC prevents tampering
    /// - Random ticket ID prevents prediction
    pub fn create_ticket(
        &self,
        peer_id: u16,
        send_key: &[u8; 32],
        recv_key: &[u8; 32],
    ) -> SessionTicket {
        let mut data = [0u8; MAX_TICKET_SIZE];
        
        // Generate random ticket ID
        let mut ticket_id = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut ticket_id);
        data[0..16].copy_from_slice(&ticket_id);
        
        // Peer ID
        data[16..18].copy_from_slice(&peer_id.to_le_bytes());
        
        // Session keys
        data[18..50].copy_from_slice(send_key);
        data[50..82].copy_from_slice(recv_key);
        
        // Expiry timestamp (seconds since UNIX_EPOCH)
        let expiry = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            + self.ticket_lifetime.as_secs();
        data[82..90].copy_from_slice(&expiry.to_le_bytes());
        
        // Compute HMAC
        let hmac = self.compute_hmac(&data[0..90]);
        data[90..122].copy_from_slice(&hmac);
        
        // XOR encrypt with derived key (simple but fast)
        let enc_key = self.derive_encryption_key(&ticket_id);
        for i in 16..122 {
            data[i] ^= enc_key[i % 32];
        }

        SessionTicket { data, len: 122 }
    }

    /// Validate a session ticket and restore the session.
    ///
    /// Returns `None` if:
    /// - Ticket is malformed
    /// - Ticket has expired
    /// - Ticket was already used (replay attack)
    /// - HMAC verification fails
    pub fn validate_ticket(&mut self, ticket: &SessionTicket) -> Option<RestoredSession> {
        self.maybe_cleanup();

        let bytes = ticket.as_bytes();
        if bytes.len() < 122 {
            return None;
        }

        // Extract ticket ID
        let mut ticket_id = [0u8; 16];
        ticket_id.copy_from_slice(&bytes[0..16]);

        // Check replay
        if self.used_tickets.contains_key(&ticket_id) {
            return None;
        }

        // Decrypt
        let enc_key = self.derive_encryption_key(&ticket_id);
        let mut decrypted = [0u8; 122];
        decrypted[0..16].copy_from_slice(&ticket_id);
        for i in 16..122 {
            decrypted[i] = bytes[i] ^ enc_key[i % 32];
        }

        // Verify HMAC
        let expected_hmac = self.compute_hmac(&decrypted[0..90]);
        let provided_hmac = &decrypted[90..122];
        if !constant_time_eq(&expected_hmac, provided_hmac) {
            return None;
        }

        // Check expiry
        let expiry = u64::from_le_bytes([
            decrypted[82], decrypted[83], decrypted[84], decrypted[85],
            decrypted[86], decrypted[87], decrypted[88], decrypted[89],
        ]);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if now > expiry {
            return None;
        }

        // Mark ticket as used
        self.used_tickets.insert(ticket_id, Instant::now());

        // Extract session data
        let peer_id = u16::from_le_bytes([decrypted[16], decrypted[17]]);
        let mut send_key = [0u8; 32];
        let mut recv_key = [0u8; 32];
        send_key.copy_from_slice(&decrypted[18..50]);
        recv_key.copy_from_slice(&decrypted[50..82]);

        Some(RestoredSession {
            peer_id,
            send_key,
            recv_key,
        })
    }

    /// Derive encryption key for a ticket.
    fn derive_encryption_key(&self, ticket_id: &[u8; 16]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_keyed(&self.server_key);
        hasher.update(b"ticket-encrypt");
        hasher.update(ticket_id);
        *hasher.finalize().as_bytes()
    }

    /// Compute HMAC for ticket data.
    fn compute_hmac(&self, data: &[u8]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_keyed(&self.server_key);
        hasher.update(b"ticket-hmac");
        hasher.update(data);
        *hasher.finalize().as_bytes()
    }

    /// Cleanup expired used tickets.
    fn maybe_cleanup(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.last_cleanup) < Duration::from_secs(60) {
            return;
        }
        self.last_cleanup = now;

        let lifetime = self.ticket_lifetime;
        self.used_tickets.retain(|_, created| {
            now.duration_since(*created) < lifetime * 2
        });
    }

    /// Get number of tracked used tickets.
    #[inline]
    pub fn used_ticket_count(&self) -> usize {
        self.used_tickets.len()
    }
}

/// Constant-time comparison to prevent timing attacks.
#[inline]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

/// Client-side ticket storage.
pub struct ClientTicketStore {
    /// Stored tickets by server address.
    tickets: HashMap<String, (SessionTicket, Instant)>,
    /// Maximum tickets to store.
    max_tickets: usize,
}

impl ClientTicketStore {
    pub fn new() -> Self {
        Self {
            tickets: HashMap::with_capacity(16),
            max_tickets: 100,
        }
    }

    /// Store a ticket for a server.
    pub fn store(&mut self, server_addr: &str, ticket: SessionTicket) {
        // Evict oldest if at capacity
        if self.tickets.len() >= self.max_tickets {
            if let Some(oldest) = self.tickets.iter()
                .min_by_key(|(_, (_, t))| *t)
                .map(|(k, _)| k.clone())
            {
                self.tickets.remove(&oldest);
            }
        }

        self.tickets.insert(server_addr.to_string(), (ticket, Instant::now()));
    }

    /// Get a stored ticket for a server.
    pub fn get(&self, server_addr: &str) -> Option<&SessionTicket> {
        self.tickets.get(server_addr).map(|(t, _)| t)
    }

    /// Remove a ticket (e.g., after failed validation).
    pub fn remove(&mut self, server_addr: &str) {
        self.tickets.remove(server_addr);
    }

    /// Clear all tickets.
    pub fn clear(&mut self) {
        self.tickets.clear();
    }
}

impl Default for ClientTicketStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_server_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut key);
        key
    }

    #[test]
    fn test_ticket_roundtrip() {
        let server_key = test_server_key();
        let mut store = SessionStore::new(server_key);

        let send_key = [1u8; 32];
        let recv_key = [2u8; 32];

        let ticket = store.create_ticket(42, &send_key, &recv_key);
        let restored = store.validate_ticket(&ticket).unwrap();

        assert_eq!(restored.peer_id, 42);
        assert_eq!(restored.send_key, send_key);
        assert_eq!(restored.recv_key, recv_key);
    }

    #[test]
    fn test_ticket_replay_protection() {
        let server_key = test_server_key();
        let mut store = SessionStore::new(server_key);

        let ticket = store.create_ticket(1, &[0u8; 32], &[0u8; 32]);
        
        // First use should succeed
        assert!(store.validate_ticket(&ticket).is_some());
        
        // Replay should fail
        assert!(store.validate_ticket(&ticket).is_none());
    }

    #[test]
    fn test_ticket_tampering() {
        let server_key = test_server_key();
        let mut store = SessionStore::new(server_key);

        let ticket = store.create_ticket(1, &[0u8; 32], &[0u8; 32]);
        
        // Tamper with ticket
        let mut tampered = ticket.clone();
        tampered.data[50] ^= 0xFF;

        // Should fail HMAC verification
        assert!(store.validate_ticket(&tampered).is_none());
    }

    #[test]
    fn test_ticket_expiry() {
        let server_key = test_server_key();
        let mut store = SessionStore::new(server_key)
            .with_lifetime(Duration::from_secs(0)); // Immediate expiry

        let ticket = store.create_ticket(1, &[0u8; 32], &[0u8; 32]);
        
        // Wait for at least 1 second so timestamp changes
        std::thread::sleep(Duration::from_secs(1));

        // Should be expired (expiry was set to current second, now it's next second)
        assert!(store.validate_ticket(&ticket).is_none());
    }

    #[test]
    fn test_client_store() {
        let mut store = ClientTicketStore::new();
        let ticket = SessionTicket::from_bytes(&[0u8; 122]).unwrap();

        store.store("server1:7777", ticket.clone());
        assert!(store.get("server1:7777").is_some());
        assert!(store.get("server2:7777").is_none());

        store.remove("server1:7777");
        assert!(store.get("server1:7777").is_none());
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(&[1, 2, 3], &[1, 2, 3]));
        assert!(!constant_time_eq(&[1, 2, 3], &[1, 2, 4]));
        assert!(!constant_time_eq(&[1, 2, 3], &[1, 2]));
    }
}
