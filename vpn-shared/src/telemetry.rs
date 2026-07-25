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

impl Default for Telemetry {
    fn default() -> Self {
        Self {
            state: ConnState::Disconnected,
            active_node: None,
            exit_ip: None,
            down_bps: 0,
            up_bps: 0,
            latency_ms: 0.0,
            bytes_rx: 0,
            bytes_tx: 0,
            uptime_secs: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum LogLevel {
    Ok,
    Info,
    Warn,
    Rotating,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEvent {
    /// Milliseconds since UNIX epoch (formatted client-side).
    pub ts_ms: u64,
    pub level: LogLevel,
    pub message: String,
}

impl LogEvent {
    pub fn now(level: LogLevel, message: impl Into<String>) -> Self {
        let ts_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        Self { ts_ms, level, message: message.into() }
    }
}
