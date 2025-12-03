//! Common types used across FastNet modules.

use uuid::Uuid;

/// Unique identifier for a peer connection.
pub type PeerId = Uuid;

/// Unique identifier for a transfer operation.
pub type TransferId = Uuid;

/// Unique identifier for a session.
pub type SessionId = Uuid;
