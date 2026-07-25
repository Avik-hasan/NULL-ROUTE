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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// Ordered pool of exit nodes; index 0 is the initial connection target.
    pub nodes: Vec<NodeConfig>,
    /// Client static private key (base64, X25519).
    pub client_private_key: String,
    /// Pre-shared key (base64, 32 bytes) mixed into Noise_IKpsk2.
    pub preshared_key: String,
    /// How often to rotate the exit IP, in seconds. `0` disables hopping.
    #[serde(default = "default_hop_interval")]
    pub hop_interval_secs: u64,
    /// Block WebRTC STUN/TURN discovery via the DNS blacklist.
    #[serde(default = "default_true")]
    pub block_webrtc: bool,
    /// Enable the WFP kill switch.
    #[serde(default = "default_true")]
    pub kill_switch: bool,
}

fn default_hop_interval() -> u64 {
    300
}
fn default_true() -> bool {
    true
}
