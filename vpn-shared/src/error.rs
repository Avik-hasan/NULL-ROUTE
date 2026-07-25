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
}
