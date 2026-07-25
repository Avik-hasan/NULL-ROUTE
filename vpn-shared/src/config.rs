//! Client & server configuration models.

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// A single VPS exit node in the hopping pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Human-readable codename shown in the diagnostics log (e.g. "OBLIVION-4").
    pub codename: String,
    /// UDP endpoint of the server daemon.
    pub endpoint: SocketAddr,
    /// Server static public key (base64, X25519) for the Noise_IK responder.
    pub server_public_key: String,
    /// Geographic hint used purely for UI display.
    pub region: String,
}
