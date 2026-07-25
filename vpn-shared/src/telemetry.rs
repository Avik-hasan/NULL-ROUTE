//! Telemetry & diagnostics-log models consumed by the cyberpunk GUI.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnState {
    Disconnected,
    Handshaking,
    Connected,
    Rotating,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Telemetry {
    pub state: ConnState,
    pub active_node: Option<String>,
    pub exit_ip: Option<String>,
    /// Instantaneous throughput in bits/sec.
    pub down_bps: u64,
    pub up_bps: u64,
    /// Round-trip latency to the active node in milliseconds.
    pub latency_ms: f32,
    /// Total bytes since the session began.
    pub bytes_rx: u64,
    pub bytes_tx: u64,
    /// Seconds since connect.
    pub uptime_secs: u64,
}
