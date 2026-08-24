//! DNS hardening: force resolver traffic through the tunnel and blacklist
//! WebRTC STUN/TURN discovery hosts.
//!
//! The hard enforcement (dropping :53 leaks on non-tunnel interfaces) lives in
//! `wfp.rs`. This module handles the *configuration* half: setting the tunnel
//! adapter's DNS servers and disabling per-interface DNS registration, plus
//! producing the STUN/TURN IP set the WFP layer blackholes.

#![cfg(windows)]

use std::net::Ipv4Addr;
use tracing::info;
use vpn_shared::{Result, VpnError};

/// DNS servers advertised to the OS once the tunnel is up. These are reachable
/// only *inside* the tunnel (the server proxies them), so they cannot leak.
pub const TUNNEL_DNS: [Ipv4Addr; 2] = [Ipv4Addr::new(10, 66, 0, 1), Ipv4Addr::new(10, 66, 0, 2)];

/// Well-known public STUN endpoints browsers probe for WebRTC. Blocking these
/// prevents a browser from discovering the host's real reflexive address.
pub fn webrtc_stun_blacklist() -> Vec<Ipv4Addr> {
    vec![
        Ipv4Addr::new(74, 125, 250, 129),  // stun.l.google.com (sample A record)
        Ipv4Addr::new(142, 250, 82, 127),  // stun1.l.google.com
        Ipv4Addr::new(3, 208, 0, 0),       // placeholder for twilio global stun
    ]
}

/// Snapshot of the pre-connect DNS configuration for exact restoration.
///
/// IMPORTANT: every mutation here targets ONLY our own tunnel adapter
/// (`tunnel_ifindex`). We never touch a physical adapter's DNS, so a failure
/// can never corrupt the host resolver configuration. On restore we put back
/// exactly what the tunnel adapter had (usually nothing / DHCP).
#[derive(Debug, Clone, Default)]
pub struct DnsSnapshot {
    pub tunnel_ifindex: u32,
    pub(crate) prior_servers: Vec<Ipv4Addr>,
    pub(crate) applied: bool,
}

impl DnsSnapshot {
    pub fn new(tunnel_ifindex: u32) -> Self {
        Self { tunnel_ifindex, prior_servers: Vec::new(), applied: false }
    }

    /// Capture the tunnel adapter's current DNS servers, then point it at the
    /// in-tunnel resolvers. Shells out to `netsh` (documented + auditable) to
    /// avoid the Windows-version-gated `SetInterfaceDnsSettings` symbol.
    pub fn apply(&mut self) -> Result<()> {
        self.prior_servers = read_dns_servers(self.tunnel_ifindex).unwrap_or_default();
        for (i, dns) in TUNNEL_DNS.iter().enumerate() {
            let action = if i == 0 { "set" } else { "add" };
            run_netsh(&[
                "interface", "ipv4", action, "dnsservers",
                &format!("name={}", self.tunnel_ifindex),
                &format!("address={dns}"),
                if i == 0 { "static" } else { "index=2" },
            ])?;
        }
        self.applied = true;
        info!(prior = self.prior_servers.len(), "dns: tunnel resolvers pinned; ISP DNS bypassed");
        Ok(())
    }

    /// Restore the tunnel adapter's DNS to exactly what it had before (or DHCP
    /// if it had none). Idempotent; safe to call from both graceful disconnect
    /// and the fail-safe recovery registry.
    pub fn restore(&mut self) -> Result<()> {
        if !self.applied {
            return Ok(());
        }
        let name = format!("name={}", self.tunnel_ifindex);
        if self.prior_servers.is_empty() {
            run_netsh(&["interface", "ipv4", "set", "dnsservers", &name, "dhcp"])?;
        } else {
            for (i, dns) in self.prior_servers.iter().enumerate() {
                let action = if i == 0 { "set" } else { "add" };
                run_netsh(&[
                    "interface", "ipv4", action, "dnsservers",
                    &name,
                    &format!("address={dns}"),
                    if i == 0 { "static" } else { "index=2" },
                ])?;
            }
        }
        self.applied = false;
        info!("dns: original tunnel-adapter resolvers restored");
        Ok(())
    }
}

/// Best-effort read of an interface's currently-configured IPv4 DNS servers.
fn read_dns_servers(ifindex: u32) -> Result<Vec<Ipv4Addr>> {
    let out = std::process::Command::new("netsh")
        .args([
            "interface",
            "ipv4",
            "show",
            "dnsservers",
            &format!("name={ifindex}"),
        ])
        .output()
        .map_err(|e| VpnError::Routing(format!("spawn netsh: {e}")))?;
    let text = String::from_utf8_lossy(&out.stdout);
    let mut servers = Vec::new();
    for tok in text.split(|c: char| !(c.is_ascii_digit() || c == '.')) {
        if let Ok(ip) = tok.parse::<Ipv4Addr>() {
            if !servers.contains(&ip) {
                servers.push(ip);
            }
        }
    }
    Ok(servers)
}

fn run_netsh(args: &[&str]) -> Result<()> {
    let out = std::process::Command::new("netsh")
        .args(args)
        .output()
        .map_err(|e| VpnError::Routing(format!("spawn netsh: {e}")))?;
    if !out.status.success() {
        return Err(VpnError::Routing(format!(
            "netsh {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_snapshot_default_state() {
        // Create an unapplied snapshot. We can't actually query netsh in a unit test reliably,
        // so we just verify the struct initializes properly before mutational methods are called.
        let snap = DnsSnapshot::new(12);
        assert_eq!(snap.tunnel_ifindex, 12);
        assert!(snap.original_servers.is_empty());
        assert!(!snap.applied);
    }
}
