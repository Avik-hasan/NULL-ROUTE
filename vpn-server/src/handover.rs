//! Server-side seamless handover / exit-IP hopping.
//!
//! Two complementary mechanisms give the client a continuously changing exit IP
//! without dropping flows:
//!
//!  1. **Server-side interface rotation** (this module): the daemon rotates the
//!     outbound SNAT source address between the configured `exit_interfaces`.
//!     Existing TCP flows that were already SNAT'd keep their conntrack entry;
//!     new connections egress from the freshly selected interface. This changes
//!     the *apparent* exit IP seen by new destinations without renegotiating the
//!     tunnel at all.
//!
//!  2. **Client-driven session migration** (see client `connection.rs` +
//!     `peer::migrate`): the client pre-establishes a second Noise session to a
//!     different node and atomically swaps. The server keeps the peer's tunnel
//!     IP stable across the swap so inner flows are undisturbed.
//!
//! The atomic swap of the active exit interface uses `ArcSwap` so the forwarding
//! path never blocks and never observes a torn value.

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use tracing::info;

/// Chooses which outbound interface the SNAT rule currently targets.
pub struct HandoverEngine {
    interfaces: Vec<String>,
    active: ArcSwap<String>,
}

impl HandoverEngine {
    pub fn new(interfaces: Vec<String>) -> Self {
        let first = interfaces
            .first()
            .cloned()
            .unwrap_or_else(|| "eth0".to_string());
        Self {
            interfaces,
            active: ArcSwap::from_pointee(first),
        }
    }

    pub fn active(&self) -> Arc<String> {
        self.active.load_full()
    }

    /// Advance to the next exit interface and re-point the SNAT rule.
    pub fn rotate(&self) {
        if self.interfaces.len() < 2 {
            return;
        }
        let current = self.active();
        let idx = self
            .interfaces
            .iter()
            .position(|i| i == current.as_str())
            .unwrap_or(0);
        let next = &self.interfaces[(idx + 1) % self.interfaces.len()];
        if let Err(e) = repoint_snat(current.as_str(), next) {
            tracing::warn!(error = %e, "snat repoint failed; keeping current exit");
            return;
        }
        self.active.store(Arc::new(next.clone()));
        info!(from = %current, to = %next, "exit interface rotated (server-side IP hop)");
    }
}

/// Replace the MASQUERADE/SNAT rule so new flows egress via `next`.
///
/// Implemented with `iptables` for portability; on nftables hosts swap in the
/// equivalent `nft` invocation. Errors are surfaced, never panicked.
fn repoint_snat(current: &str, next: &str) -> vpn_shared::Result<()> {
    use vpn_shared::VpnError;
    // Remove old masquerade (ignore "rule doesn't exist").
    let _ = std::process::Command::new("iptables")
        .args(["-t", "nat", "-D", "POSTROUTING", "-o", current, "-j", "MASQUERADE"])
        .status();
    let ok = std::process::Command::new("iptables")
        .args(["-t", "nat", "-A", "POSTROUTING", "-o", next, "-j", "MASQUERADE"])
        .status()
        .map_err(|e| VpnError::Handover(format!("iptables spawn: {e}")))?;
    if !ok.success() {
        return Err(VpnError::Handover(format!(
            "iptables MASQUERADE on {next} failed with {ok}"
        )));
    }
    Ok(())
}

/// Periodically rotate the exit interface.
pub fn spawn_rotation(engine: Arc<HandoverEngine>, every: Duration) {
    if every.is_zero() {
        return;
    }
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(every);
        tick.tick().await;
        loop {
            tick.tick().await;
            engine.rotate();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handover_engine_rotation() {
        let interfaces = vec!["eth0".to_string(), "eth1".to_string()];
        let engine = HandoverEngine::new(interfaces);
        
        assert_eq!(engine.current_interface(), "eth0");
        
        engine.rotate();
        assert_eq!(engine.current_interface(), "eth1");
        
        engine.rotate();
        assert_eq!(engine.current_interface(), "eth0");
    }
}
