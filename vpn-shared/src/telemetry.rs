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
