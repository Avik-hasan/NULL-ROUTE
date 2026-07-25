//! Unified, typed error surface.
//!
//! Every fallible operation in the workspace returns [`Result`]. There are no
//! `unwrap()`/`expect()` shortcuts in production paths — callers must handle or
//! explicitly propagate every variant.

use thiserror::Error;

pub type Result<T> = core::result::Result<T, VpnError>;

#[derive(Debug, Error)]
pub enum VpnError {
    #[error("i/o error: {0}")]
    Io(String),

    #[error("serialization error: {0}")]
    Serde(String),

    #[error("cryptographic failure: {0}")]
    Crypto(String),

    #[error("handshake failed: {0}")]
    Handshake(String),

    #[error("replayed or stale packet dropped (counter={counter}, window_floor={floor})")]
    Replay { counter: u64, floor: u64 },

    #[error("packet malformed: {0}")]
    MalformedPacket(String),

    #[error("ipc protocol violation: {0}")]
    Ipc(String),

    #[error("access denied constructing security descriptor: {0}")]
    SecurityDescriptor(String),

    #[error("windows filtering platform error: {0}")]
    Wfp(String),

    #[error("routing table error: {0}")]
    Routing(String),

    #[error("seamless handover failed: {0}")]
    Handover(String),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("operation timed out after {0} ms")]
    Timeout(u64),

    #[error("invalid state: {0}")]
    InvalidState(String),
}

impl From<std::io::Error> for VpnError {
    fn from(e: std::io::Error) -> Self {
        VpnError::Io(e.to_string())
    }
}

impl From<serde_json::Error> for VpnError {
    fn from(e: serde_json::Error) -> Self {
        VpnError::Serde(e.to_string())
    }
}
