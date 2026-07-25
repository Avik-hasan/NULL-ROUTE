//! Connection orchestration: handshake, data-plane pump, telemetry, and the
//! client half of the seamless-handover protocol.
//!
//! This ties together `vpn-core` (crypto/protocol/MSS) with the platform
//! modules (`wfp`, `routing`, `dns`) and exposes an async API the IPC layer
//! drives via `IpcCommand`.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use parking_lot::Mutex;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::interval;
use tracing::{info, warn};

use vpn_core::crypto::{build_handshake, Role, SecretKey, Session};
use vpn_core::mss_clamp;
use vpn_core::protocol::PacketKind;
use vpn_shared::config::{ClientConfig, NodeConfig};
use vpn_shared::telemetry::{ConnState, LogEvent, LogLevel, Telemetry};
use vpn_shared::{Result, VpnError};

/// Handle to the live connection, shared with the IPC layer.
#[derive(Clone)]
pub struct ConnectionHandle {
    /// The active session, atomically swappable for zero-drop handover.
    pub(crate) active: Arc<ArcSwap<Session>>,
    pub(crate) telemetry: Arc<Mutex<Telemetry>>,
    pub(crate) logs: mpsc::UnboundedSender<LogEvent>,
    pub(crate) bytes_tx: Arc<AtomicU64>,
    pub(crate) bytes_rx: Arc<AtomicU64>,
}

impl ConnectionHandle {
    pub fn telemetry(&self) -> Telemetry {
        self.telemetry.lock().clone()
    }

    pub(crate) fn log(&self, level: LogLevel, msg: impl Into<String>) {
        let ev = LogEvent::now(level, msg);
        let _ = self.logs.send(ev);
    }
}

/// Base64 (std alphabet) decode without an extra dependency.
pub(crate) fn b64(s: &str) -> Result<Vec<u8>> {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut lut = [255u8; 256];
    for (i, &c) in T.iter().enumerate() {
        lut[c as usize] = i as u8;
    }
    let s: Vec<u8> = s.bytes().filter(|&b| b != b'=' && !b.is_ascii_whitespace()).collect();
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    for chunk in s.chunks(4) {
        if chunk.len() == 1 {
            return Err(VpnError::Config("invalid base64: dangling character".into()));
        }
        let mut acc = 0u32;
        let mut bits = 0;
        for &c in chunk {
            let v = lut[c as usize];
            if v == 255 {
                return Err(VpnError::Config("invalid base64".into()));
            }
            acc = (acc << 6) | v as u32;
            bits += 6;
        }
        let mut shift = bits - (bits % 8);
        while shift >= 8 {
            shift -= 8;
            out.push((acc >> shift) as u8);
        }
    }
    Ok(out)
}

/// Convenience for tests / callers needing a placeholder endpoint.
pub fn loopback(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
}
