//! GUI <-> service IPC message contract.
//!
//! Framing: each message is a single length-delimited JSON object. The service
//! rejects anything that fails to deserialize into these enums (see
//! `vpn-client::ipc`), which — combined with the pipe ACL — prevents malformed
//! or hostile local callers from driving the elevated service.

use serde::{Deserialize, Serialize};

/// Commands sent from the (unprivileged) GUI to the (elevated) service.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum IpcCommand {
    /// Handshake so both sides can reject version mismatches early.
    Hello { protocol_version: u32 },
    /// Connect to node at the given pool index.
    Connect { node_index: usize },
    /// Tear down the tunnel and restore original network state.
    Disconnect,
    /// Force an immediate seamless handover to another node.
    RotateNow { node_index: Option<usize> },
    /// Query live status/telemetry.
    GetStatus,
    /// Toggle the kill switch at runtime.
    SetKillSwitch { enabled: bool },
    /// Terminate the elevated background service.
    Terminate,
}
