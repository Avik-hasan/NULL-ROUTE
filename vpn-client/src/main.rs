//! `vpn-client` — the elevated Windows VPN service.
//!
//! Boot sequence:
//!   1. Install panic/Ctrl-C guards + cleanup registry (fail-safe first!).
//!   2. Open a dynamic WFP engine, arm IPv6 blackhole + WebRTC block.
//!   3. Serve the ACL-secured named pipe for the GUI.
//!   4. On `Connect`, create the tunnel, register restore steps BEFORE applying
//!      persistent routing/DNS, arm the kill switch + DNS bind, then start the
//!      data pump + hopper.

#![cfg_attr(not(windows), allow(unused))]

#[cfg(windows)]
mod dns;
#[cfg(windows)]
mod ipc;
mod recovery;
#[cfg(windows)]
mod routing;
#[cfg(windows)]
mod wfp;

fn main() {}
