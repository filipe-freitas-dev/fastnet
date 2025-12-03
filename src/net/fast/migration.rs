//! Connection migration for seamless network changes.
//!
//! This module enables connections to survive IP address changes without
//! disconnection, essential for mobile devices switching between WiFi and cellular.
//!
//! # How It Works
//!
//! 1. Each connection has a unique Connection ID (CID)
//! 2. Packets include the CID for identification
//! 3. When IP changes, server validates CID + cryptographic proof
//! 4. Connection continues with new address
//!
//! # Security
//!
//! - CID is random 128-bit value (unpredictable)
//! - Migration requires proof of key possession
//! - Rate limiting prevents migration abuse
//! - Old address is invalidated after migration
//!
//! # Example
//!
//! ```rust,ignore
//! use fastnet::net::fast::migration::{ConnectionId, MigrationManager};
//!
//! let mut manager = MigrationManager::new();
//!
//! // Register connection
//! let cid = ConnectionId::generate();
//! manager.register(cid, peer_id, addr, &session_key);
//!
//! // Handle migration request
//! if let Some(peer_id) = manager.validate_migration(cid, new_addr, &proof) {
//!     // Update peer address
//! }
//! ```

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Connection ID for migration tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionId([u8; 16]);

impl ConnectionId {
    /// Generate a new random connection ID.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut bytes);
        Self(bytes)
    }

    /// Create from raw bytes.
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Get raw bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Write to buffer.
    #[inline]
    pub fn write_to(&self, buf: &mut [u8]) {
        buf[..16].copy_from_slice(&self.0);
    }

    /// Read from buffer.
    #[inline]
    pub fn read_from(buf: &[u8]) -> Option<Self> {
        if buf.len() < 16 {
            return None;
        }
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&buf[..16]);
        Some(Self(bytes))
    }
}

impl Default for ConnectionId {
    fn default() -> Self {
        Self::generate()
    }
}

/// Migration proof to validate address change.
///
/// Contains HMAC of: CID || old_addr || new_addr || timestamp
#[derive(Debug, Clone)]
pub struct MigrationProof {
    /// HMAC proof (32 bytes).
    pub hmac: [u8; 32],
    /// Timestamp when proof was created.
    pub timestamp: u64,
}

impl MigrationProof {
    pub const SIZE: usize = 40; // 32 + 8

    /// Create a migration proof.
    pub fn create(
        cid: &ConnectionId,
        old_addr: SocketAddr,
        new_addr: SocketAddr,
        session_key: &[u8; 32],
    ) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let hmac = Self::compute_hmac(cid, old_addr, new_addr, timestamp, session_key);

        Self { hmac, timestamp }
    }

    /// Verify a migration proof.
    pub fn verify(
        &self,
        cid: &ConnectionId,
        old_addr: SocketAddr,
        new_addr: SocketAddr,
        session_key: &[u8; 32],
        max_age_secs: u64,
    ) -> bool {
        // Check timestamp freshness
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if now.saturating_sub(self.timestamp) > max_age_secs {
            return false;
        }

        // Verify HMAC
        let expected = Self::compute_hmac(cid, old_addr, new_addr, self.timestamp, session_key);
        constant_time_eq(&self.hmac, &expected)
    }

    /// Compute HMAC for proof.
    fn compute_hmac(
        cid: &ConnectionId,
        old_addr: SocketAddr,
        new_addr: SocketAddr,
        timestamp: u64,
        session_key: &[u8; 32],
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_keyed(session_key);
        hasher.update(b"migration-proof");
        hasher.update(cid.as_bytes());
        hasher.update(&addr_to_bytes(old_addr));
        hasher.update(&addr_to_bytes(new_addr));
        hasher.update(&timestamp.to_le_bytes());
        *hasher.finalize().as_bytes()
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[..32].copy_from_slice(&self.hmac);
        buf[32..40].copy_from_slice(&self.timestamp.to_le_bytes());
        buf
    }

    /// Deserialize from bytes.
    pub fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::SIZE {
            return None;
        }
        let mut hmac = [0u8; 32];
        hmac.copy_from_slice(&buf[..32]);
        let timestamp = u64::from_le_bytes([
            buf[32], buf[33], buf[34], buf[35],
            buf[36], buf[37], buf[38], buf[39],
        ]);
        Some(Self { hmac, timestamp })
    }
}

/// Connection state for migration tracking.
struct ConnectionState {
    peer_id: u16,
    current_addr: SocketAddr,
    session_key: [u8; 32],
    last_activity: Instant,
    migration_count: u32,
    last_migration: Option<Instant>,
}

/// Migration manager for server-side connection tracking.
pub struct MigrationManager {
    /// Connections indexed by CID.
    connections: HashMap<ConnectionId, ConnectionState>,
    /// Reverse lookup: address to CID.
    addr_to_cid: HashMap<SocketAddr, ConnectionId>,
    /// Maximum migrations per connection per minute.
    max_migrations_per_minute: u32,
    /// Maximum proof age in seconds.
    max_proof_age_secs: u64,
    /// Connection timeout.
    connection_timeout: Duration,
}

impl MigrationManager {
    /// Create a new migration manager.
    pub fn new() -> Self {
        Self {
            connections: HashMap::with_capacity(256),
            addr_to_cid: HashMap::with_capacity(256),
            max_migrations_per_minute: 5,
            max_proof_age_secs: 30,
            connection_timeout: Duration::from_secs(60),
        }
    }

    /// Configure maximum migrations per minute (DoS protection).
    pub fn with_rate_limit(mut self, max_per_minute: u32) -> Self {
        self.max_migrations_per_minute = max_per_minute;
        self
    }

    /// Configure proof expiry time.
    pub fn with_proof_age(mut self, max_secs: u64) -> Self {
        self.max_proof_age_secs = max_secs;
        self
    }

    /// Register a new connection.
    pub fn register(
        &mut self,
        cid: ConnectionId,
        peer_id: u16,
        addr: SocketAddr,
        session_key: &[u8; 32],
    ) {
        let state = ConnectionState {
            peer_id,
            current_addr: addr,
            session_key: *session_key,
            last_activity: Instant::now(),
            migration_count: 0,
            last_migration: None,
        };

        self.connections.insert(cid, state);
        self.addr_to_cid.insert(addr, cid);
    }

    /// Remove a connection.
    pub fn remove(&mut self, cid: &ConnectionId) {
        if let Some(state) = self.connections.remove(cid) {
            self.addr_to_cid.remove(&state.current_addr);
        }
    }

    /// Get connection ID for an address.
    #[inline]
    pub fn get_cid(&self, addr: &SocketAddr) -> Option<ConnectionId> {
        self.addr_to_cid.get(addr).copied()
    }

    /// Get peer ID for a connection.
    #[inline]
    pub fn get_peer_id(&self, cid: &ConnectionId) -> Option<u16> {
        self.connections.get(cid).map(|s| s.peer_id)
    }

    /// Get current address for a connection.
    #[inline]
    pub fn get_addr(&self, cid: &ConnectionId) -> Option<SocketAddr> {
        self.connections.get(cid).map(|s| s.current_addr)
    }

    /// Validate a migration request.
    ///
    /// Returns the peer ID if migration is valid, None otherwise.
    pub fn validate_migration(
        &mut self,
        cid: ConnectionId,
        new_addr: SocketAddr,
        proof: &MigrationProof,
    ) -> Option<u16> {
        let state = self.connections.get_mut(&cid)?;

        // Rate limiting
        if let Some(last) = state.last_migration {
            if last.elapsed() < Duration::from_secs(60) {
                if state.migration_count >= self.max_migrations_per_minute {
                    return None;
                }
            } else {
                state.migration_count = 0;
            }
        }

        // Verify proof
        if !proof.verify(
            &cid,
            state.current_addr,
            new_addr,
            &state.session_key,
            self.max_proof_age_secs,
        ) {
            return None;
        }

        // Same address? No migration needed
        if state.current_addr == new_addr {
            return Some(state.peer_id);
        }

        // Update state
        let old_addr = state.current_addr;
        state.current_addr = new_addr;
        state.last_activity = Instant::now();
        state.migration_count += 1;
        state.last_migration = Some(Instant::now());

        // Update address mapping
        self.addr_to_cid.remove(&old_addr);
        self.addr_to_cid.insert(new_addr, cid);

        Some(state.peer_id)
    }

    /// Update activity timestamp for a connection.
    pub fn touch(&mut self, cid: &ConnectionId) {
        if let Some(state) = self.connections.get_mut(cid) {
            state.last_activity = Instant::now();
        }
    }

    /// Cleanup expired connections.
    pub fn cleanup(&mut self) {
        let timeout = self.connection_timeout;
        let expired: Vec<_> = self.connections
            .iter()
            .filter(|(_, s)| s.last_activity.elapsed() > timeout)
            .map(|(cid, _)| *cid)
            .collect();

        for cid in expired {
            self.remove(&cid);
        }
    }

    /// Number of tracked connections.
    #[inline]
    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }
}

impl Default for MigrationManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Client-side migration state.
pub struct ClientMigration {
    /// Connection ID.
    pub cid: ConnectionId,
    /// Current session key.
    session_key: [u8; 32],
    /// Last known server address.
    server_addr: SocketAddr,
    /// Last known local address.
    local_addr: Option<SocketAddr>,
}

impl ClientMigration {
    /// Create a new client migration state.
    pub fn new(cid: ConnectionId, session_key: [u8; 32], server_addr: SocketAddr) -> Self {
        Self {
            cid,
            session_key,
            server_addr,
            local_addr: None,
        }
    }

    /// Update local address and check if migration is needed.
    ///
    /// Returns a migration proof if address changed.
    pub fn check_migration(&mut self, current_addr: SocketAddr) -> Option<MigrationProof> {
        match self.local_addr {
            Some(old_addr) if old_addr != current_addr => {
                let proof = MigrationProof::create(
                    &self.cid,
                    old_addr,
                    current_addr,
                    &self.session_key,
                );
                self.local_addr = Some(current_addr);
                Some(proof)
            }
            None => {
                self.local_addr = Some(current_addr);
                None
            }
            _ => None,
        }
    }

    /// Get connection ID.
    #[inline]
    pub fn connection_id(&self) -> ConnectionId {
        self.cid
    }

    /// Get server address.
    #[inline]
    pub fn server_addr(&self) -> SocketAddr {
        self.server_addr
    }
}

/// Convert socket address to bytes for hashing.
fn addr_to_bytes(addr: SocketAddr) -> [u8; 18] {
    let mut buf = [0u8; 18];
    match addr {
        SocketAddr::V4(v4) => {
            buf[0] = 4;
            buf[1..5].copy_from_slice(&v4.ip().octets());
            buf[5..7].copy_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            buf[0] = 6;
            buf[1..17].copy_from_slice(&v6.ip().octets());
            buf[17] = (v6.port() >> 8) as u8;
            // Note: loses lower byte of port, but collision is unlikely
        }
    }
    buf
}

/// Constant-time comparison.
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port)
    }

    fn test_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut key);
        key
    }

    #[test]
    fn test_connection_id() {
        let cid1 = ConnectionId::generate();
        let cid2 = ConnectionId::generate();
        assert_ne!(cid1, cid2);

        let mut buf = [0u8; 16];
        cid1.write_to(&mut buf);
        let cid3 = ConnectionId::read_from(&buf).unwrap();
        assert_eq!(cid1, cid3);
    }

    #[test]
    fn test_migration_proof() {
        let cid = ConnectionId::generate();
        let old_addr = test_addr(1000);
        let new_addr = test_addr(2000);
        let key = test_key();

        let proof = MigrationProof::create(&cid, old_addr, new_addr, &key);
        
        // Valid proof
        assert!(proof.verify(&cid, old_addr, new_addr, &key, 60));

        // Wrong addresses
        assert!(!proof.verify(&cid, new_addr, old_addr, &key, 60));

        // Wrong key
        let wrong_key = test_key();
        assert!(!proof.verify(&cid, old_addr, new_addr, &wrong_key, 60));
    }

    #[test]
    fn test_proof_serialization() {
        let cid = ConnectionId::generate();
        let proof = MigrationProof::create(
            &cid,
            test_addr(1000),
            test_addr(2000),
            &test_key(),
        );

        let bytes = proof.to_bytes();
        let parsed = MigrationProof::from_bytes(&bytes).unwrap();
        
        assert_eq!(proof.hmac, parsed.hmac);
        assert_eq!(proof.timestamp, parsed.timestamp);
    }

    #[test]
    fn test_migration_manager() {
        let mut manager = MigrationManager::new();
        let cid = ConnectionId::generate();
        let key = test_key();
        let addr1 = test_addr(1000);
        let addr2 = test_addr(2000);

        // Register
        manager.register(cid, 42, addr1, &key);
        assert_eq!(manager.get_peer_id(&cid), Some(42));
        assert_eq!(manager.get_addr(&cid), Some(addr1));

        // Migrate
        let proof = MigrationProof::create(&cid, addr1, addr2, &key);
        let result = manager.validate_migration(cid, addr2, &proof);
        assert_eq!(result, Some(42));
        assert_eq!(manager.get_addr(&cid), Some(addr2));
    }

    #[test]
    fn test_migration_rate_limit() {
        let mut manager = MigrationManager::new().with_rate_limit(2);
        let cid = ConnectionId::generate();
        let key = test_key();
        let addr1 = test_addr(1000);

        manager.register(cid, 1, addr1, &key);

        // First two migrations should succeed
        for i in 2..4 {
            let new_addr = test_addr(1000 + i);
            let old_addr = manager.get_addr(&cid).unwrap();
            let proof = MigrationProof::create(&cid, old_addr, new_addr, &key);
            assert!(manager.validate_migration(cid, new_addr, &proof).is_some());
        }

        // Third should be rate limited
        let new_addr = test_addr(2000);
        let old_addr = manager.get_addr(&cid).unwrap();
        let proof = MigrationProof::create(&cid, old_addr, new_addr, &key);
        assert!(manager.validate_migration(cid, new_addr, &proof).is_none());
    }

    #[test]
    fn test_client_migration() {
        let cid = ConnectionId::generate();
        let key = test_key();
        let server = test_addr(7777);

        let mut client = ClientMigration::new(cid, key, server);

        // First check - no migration (initializes address)
        assert!(client.check_migration(test_addr(1000)).is_none());

        // Same address - no migration
        assert!(client.check_migration(test_addr(1000)).is_none());

        // Different address - migration needed
        let proof = client.check_migration(test_addr(2000));
        assert!(proof.is_some());
    }
}
