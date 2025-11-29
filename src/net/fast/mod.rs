//! Fast networking implementation with encryption.

mod packet;
mod channel;
mod peer;
mod secure;

pub use secure::{SecureSocket, SecureEvent};
