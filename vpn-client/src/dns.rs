//! DNS hardening: force resolver traffic through the tunnel and blacklist
//! WebRTC STUN/TURN discovery hosts.
//!
//! The hard enforcement (dropping :53 leaks on non-tunnel interfaces) lives in
//! `wfp.rs`. This module handles the *configuration* half: setting the tunnel
//! adapter's DNS servers and disabling per-interface DNS registration, plus
//! producing the STUN/TURN IP set the WFP layer blackholes.

#![cfg(windows)]

use std::net::Ipv4Addr;

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
}
