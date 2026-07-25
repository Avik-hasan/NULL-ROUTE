//! Wintun data-plane adapter acquisition.
//!
//! The kill switch, split-tunnel routing, and in-tunnel DNS binding are only
//! safe to apply once a real Wintun adapter exists to actually carry traffic.
//! Arming enforcement without a live tunnel would black-hole the user's network
//! (a self-inflicted lockout).
//!
//! Until the `wintun.dll` FFI (`WintunCreateAdapter` / `WintunStartSession`) is
//! wired in, [`create_tunnel`] returns an error. Because `connection::activate`
//! calls this **before** touching any persistent OS state, a partial build can
//! never leave the machine in a broken network state.

#![cfg(windows)]

use vpn_shared::{Result, VpnError};

/// A live tunnel adapter: its interface index (for routing/DNS) and LUID (for
/// WFP interface conditions).
pub struct TunnelAdapter {
    pub ifindex: u32,
    pub luid: u64,
}

/// Create + start the Wintun adapter.
///
/// NOTE: returns `Err` in this build on purpose — see the module docs. When the
/// Wintun FFI is added, this must:
///   1. `WintunCreateAdapter("custom-vpn", "Wintun", &guid)`
///   2. resolve the adapter LUID via `WintunGetAdapterLUID`
///   3. convert LUID -> interface index via `ConvertInterfaceLuidToIndex`
///   4. `WintunStartSession` and return the session handle alongside this struct.
pub fn create_tunnel() -> Result<TunnelAdapter> {
    Err(VpnError::InvalidState(
        "Wintun data-plane adapter is not yet wired in this build; \
         routing/DNS changes and the kill switch are intentionally NOT applied \
         so the system can never be locked out by a partial install"
            .into(),
    ))
}
