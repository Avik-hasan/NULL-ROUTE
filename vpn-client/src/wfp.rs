//! Windows Filtering Platform (WFP) integration.
//!
//! Implements three defensive controls as WFP filters inside a single dynamic
//! session + provider so they are torn down automatically if the process dies
//! (WFP auto-deletes `FWPM_SESSION_FLAG_DYNAMIC` objects on session close — a
//! second safety net beneath `recovery.rs`).
//!
//! Controls:
//!  * [`block_ipv6_outbound`]  — Sec.1.1 IPv6 leak blackholing.
//!  * [`bind_dns_to_tunnel`]   — Sec.1.2 force all :53 out the Wintun LUID; drop leaks.
//!  * [`enable_kill_switch`]   — Sec.2.2 permit only the encrypted UDP path to
//!                               the active endpoint; block everything else.
//!  * [`add_webrtc_blackhole`] — Sec.2.3 drop known STUN/TURN destinations.
//!
//! The Win32 WFP surface is large; this module wraps the exact calls we need
//! with strong error mapping and a guard that guarantees engine handle closure.

#![cfg(windows)]

use std::net::Ipv4Addr;
use tracing::info;
use vpn_shared::{Result, VpnError};
use windows::core::{GUID, PCWSTR};
use windows::Win32::Foundation::{ERROR_SUCCESS, HANDLE};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineClose0, FwpmEngineOpen0, FwpmProviderAdd0, FwpmSubLayerAdd0,
    FwpmTransactionAbort0, FwpmTransactionBegin0, FwpmTransactionCommit0,
    FWPM_DISPLAY_DATA0, FWPM_PROVIDER0, FWPM_SESSION0, FWPM_SUBLAYER0,
    FWPM_SESSION_FLAG_DYNAMIC,
};

/// Stable GUIDs identifying our provider & sublayer across restarts.
const PROVIDER_GUID: GUID = GUID::from_u128(0x7b1e_9a20_1c44_4f0a_9d3e_5f6a7b8c9d01);
const SUBLAYER_GUID: GUID = GUID::from_u128(0x7b1e_9a20_1c44_4f0a_9d3e_5f6a7b8c9d02);

/// Higher weight = evaluated first. Kill-switch permit must outrank the block.
pub(crate) const WEIGHT_PERMIT: u8 = 15;
pub(crate) const WEIGHT_BLOCK: u8 = 10;

/// RAII wrapper over an open WFP engine handle.
pub struct WfpEngine {
    pub(crate) handle: HANDLE,
}

unsafe impl Send for WfpEngine {}
unsafe impl Sync for WfpEngine {}

impl Drop for WfpEngine {
    fn drop(&mut self) {
        if !self.handle.is_invalid() {
            unsafe {
                let _ = FwpmEngineClose0(self.handle);
            }
        }
    }
}

impl WfpEngine {
    /// Open a **dynamic** WFP session. All objects added are auto-removed when
    /// this handle closes (process exit or explicit drop), which is our
    /// last-line kill-switch cleanup guarantee.
    pub fn open() -> Result<Self> {
        let mut session = FWPM_SESSION0::default();
        session.flags = FWPM_SESSION_FLAG_DYNAMIC;
        session.displayData = display("custom-vpn", "dynamic filtering session");

        let mut handle = HANDLE::default();
        let rc = unsafe {
            FwpmEngineOpen0(PCWSTR::null(), 10, None, Some(&session), &mut handle)
        };
        if rc != ERROR_SUCCESS.0 {
            return Err(VpnError::Wfp(format!("FwpmEngineOpen0 failed: {:#x}", rc)));
        }
        let engine = Self { handle };
        engine.register_provider_and_sublayer()?;
        Ok(engine)
    }

    fn register_provider_and_sublayer(&self) -> Result<()> {
        let mut provider = FWPM_PROVIDER0::default();
        provider.providerKey = PROVIDER_GUID;
        provider.displayData = display("custom-vpn", "Custom VPN provider");
        let rc = unsafe { FwpmProviderAdd0(self.handle, &provider, None) };
        if rc != ERROR_SUCCESS.0 && rc != 0x8032_0009 {
            return Err(VpnError::Wfp(format!("FwpmProviderAdd0: {:#x}", rc)));
        }

        let mut sublayer = FWPM_SUBLAYER0::default();
        sublayer.subLayerKey = SUBLAYER_GUID;
        sublayer.providerKey = &PROVIDER_GUID as *const _ as *mut _;
        sublayer.displayData = display("custom-vpn", "Custom VPN sublayer");
        sublayer.weight = 0xffff;
        let rc = unsafe { FwpmSubLayerAdd0(self.handle, &sublayer, None) };
        if rc != ERROR_SUCCESS.0 && rc != 0x8032_0009 {
            return Err(VpnError::Wfp(format!("FwpmSubLayerAdd0: {:#x}", rc)));
        }
        Ok(())
    }

    /// Run a closure inside an explicit WFP transaction (atomic filter set).
    pub(crate) fn in_transaction<F: FnOnce() -> Result<()>>(&self, f: F) -> Result<()> {
        let rc = unsafe { FwpmTransactionBegin0(self.handle, 0) };
        if rc != ERROR_SUCCESS.0 {
            return Err(VpnError::Wfp(format!("TransactionBegin: {:#x}", rc)));
        }
        match f() {
            Ok(()) => {
                let rc = unsafe { FwpmTransactionCommit0(self.handle) };
                if rc != ERROR_SUCCESS.0 {
                    return Err(VpnError::Wfp(format!("TransactionCommit: {:#x}", rc)));
                }
                Ok(())
            }
            Err(e) => {
                unsafe {
                    let _ = FwpmTransactionAbort0(self.handle);
                }
                Err(e)
            }
        }
    }
}

fn display(name: &'static str, desc: &'static str) -> FWPM_DISPLAY_DATA0 {
    use widestring::U16CString;
    let name = U16CString::from_str(name).unwrap_or_default().into_raw();
    let desc = U16CString::from_str(desc).unwrap_or_default().into_raw();
    FWPM_DISPLAY_DATA0 {
        name: windows::core::PWSTR(name),
        description: windows::core::PWSTR(desc),
    }
}
