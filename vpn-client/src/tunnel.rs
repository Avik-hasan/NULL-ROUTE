//! Wintun data-plane adapter acquisition.
//!
//! The kill switch, split-tunnel routing, and in-tunnel DNS binding are only
//! safe to apply once a real Wintun adapter exists to actually carry traffic.
//! Arming enforcement without a live tunnel would black-hole the user's network
//! (a self-inflicted lockout).

#![cfg(windows)]

/// A live tunnel adapter: its interface index (for routing/DNS) and LUID (for
/// WFP interface conditions).
pub struct TunnelAdapter {
    pub ifindex: u32,
    pub luid: u64,
}
