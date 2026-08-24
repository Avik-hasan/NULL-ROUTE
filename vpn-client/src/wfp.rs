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
    FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterDeleteById0, FwpmProviderAdd0,
    FwpmSubLayerAdd0,
    FwpmTransactionAbort0, FwpmTransactionBegin0, FwpmTransactionCommit0, FWPM_ACTION0,
    FWPM_DISPLAY_DATA0, FWPM_FILTER0, FWPM_FILTER_CONDITION0, FWPM_PROVIDER0, FWPM_SESSION0,
    FWPM_SUBLAYER0, FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_MATCH_EQUAL, FWP_UINT16,
    FWP_VALUE0, FWP_CONDITION_VALUE0, FWPM_SESSION_FLAG_DYNAMIC,
};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWPM_CONDITION_IP_LOCAL_INTERFACE, FWPM_CONDITION_IP_PROTOCOL,
    FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_CONDITION_IP_REMOTE_PORT,
    FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6,
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

    /// Sec.1.1 — Blackhole ALL outbound IPv6 at the ALE connect-v6 layer.
    pub fn block_ipv6_outbound(&self) -> Result<()> {
        self.in_transaction(|| {
            let filter = block_filter(
                FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                "block-all-ipv6-outbound",
                &[],
                WEIGHT_BLOCK,
            );
            let _ = self.add_filter("block-all-ipv6-outbound", &filter)?;
            Ok(())
        })?;
        info!("WFP: outbound IPv6 blackholed");
        Ok(())
    }

    /// Sec.1.2 — Permit UDP/TCP :53 only when leaving via `tunnel_luid`, and
    /// block :53 on every other interface so the resolver cannot fan out.
    pub fn bind_dns_to_tunnel(&self, tunnel_luid: u64) -> Result<Vec<u64>> {
        let mut ids = Vec::new();
        self.in_transaction(|| {
            for proto in [17u16 /*UDP*/, 6u16 /*TCP*/] {
                let permit = permit_filter(
                    FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                    "permit-dns-on-tunnel",
                    &[
                        cond_u8_protocol(proto as u8),
                        cond_u16_remote_port(53),
                        cond_u64_local_iface(tunnel_luid),
                    ],
                    WEIGHT_PERMIT,
                );
                ids.push(self.add_filter("permit-dns-on-tunnel", &permit)?);

                let block = block_filter(
                    FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                    "block-dns-leak",
                    &[cond_u8_protocol(proto as u8), cond_u16_remote_port(53)],
                    WEIGHT_BLOCK,
                );
                ids.push(self.add_filter("block-dns-leak", &block)?);
            }
            Ok(())
        })?;
        info!(luid = tunnel_luid, "WFP: DNS bound exclusively to tunnel adapter");
        Ok(ids)
    }

    /// Sec.2.2 — Kill switch. Permit outbound UDP to exactly the active VPN endpoint.
    pub fn enable_kill_switch(&self, server_ip: Ipv4Addr, server_port: u16) -> Result<Vec<u64>> {
        let mut ids = Vec::new();
        self.in_transaction(|| {
            let permit = permit_filter(
                FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                "permit-vpn-endpoint",
                &[
                    cond_u8_protocol(17),
                    cond_u32_remote_addr(server_ip),
                    cond_u16_remote_port(server_port),
                ],
                WEIGHT_PERMIT,
            );
            ids.push(self.add_filter("permit-vpn-endpoint", &permit)?);

            let block = block_filter(
                FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                "killswitch-block-all-v4",
                &[],
                WEIGHT_BLOCK,
            );
            ids.push(self.add_filter("killswitch-block-all-v4", &block)?);
            Ok(())
        })?;
        info!(%server_ip, server_port, "WFP: kill switch armed");
        Ok(ids)
    }

    /// Sec.2.3 — Drop connections to well-known WebRTC STUN/TURN endpoints.
    pub fn add_webrtc_blackhole(&self, stun_ips: &[Ipv4Addr]) -> Result<()> {
        self.in_transaction(|| {
            for ip in stun_ips {
                let block = block_filter(
                    FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                    "block-webrtc-stun",
                    &[cond_u32_remote_addr(*ip)],
                    WEIGHT_BLOCK,
                );
                let _ = self.add_filter("block-webrtc-stun", &block)?;
            }
            Ok(())
        })?;
        info!(count = stun_ips.len(), "WFP: WebRTC STUN/TURN blackholed");
        Ok(())
    }

    pub fn remove_filters(&self, ids: &[u64]) -> Result<()> {
        let mut first_err: Option<VpnError> = None;
        for &id in ids {
            let rc = unsafe { FwpmFilterDeleteById0(self.handle, id) };
            if rc != ERROR_SUCCESS.0 && rc != 0x8032_0003 {
                first_err.get_or_insert(VpnError::Wfp(format!(
                    "FwpmFilterDeleteById0({id}): {:#x}",
                    rc
                )));
            }
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    pub(crate) fn add_filter(&self, name: &str, filter: &FWPM_FILTER0) -> Result<u64> {
        let mut id: u64 = 0;
        let rc = unsafe { FwpmFilterAdd0(self.handle, filter, None, Some(&mut id)) };
        if rc != ERROR_SUCCESS.0 {
            return Err(VpnError::Wfp(format!("FwpmFilterAdd0 ({name}): {:#x}", rc)));
        }
        Ok(id)
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

fn base_filter(layer: GUID, name: &'static str, weight: u8) -> FWPM_FILTER0 {
    let mut f = FWPM_FILTER0::default();
    f.layerKey = layer;
    f.subLayerKey = SUBLAYER_GUID;
    f.displayData = display(name, name);
    f.weight = FWP_VALUE0 {
        r#type: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_UINT8,
        Anonymous: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_VALUE0_0 {
            uint8: weight,
        },
    };
    f
}

fn attach_conditions(f: &mut FWPM_FILTER0, conds: &[FWPM_FILTER_CONDITION0]) {
    if conds.is_empty() {
        return;
    }
    let boxed = conds.to_vec().into_boxed_slice();
    f.numFilterConditions = boxed.len() as u32;
    f.filterCondition = Box::leak(boxed).as_mut_ptr();
}

fn block_filter(
    layer: GUID,
    name: &'static str,
    conds: &[FWPM_FILTER_CONDITION0],
    weight: u8,
) -> FWPM_FILTER0 {
    let mut f = base_filter(layer, name, weight);
    f.action = FWPM_ACTION0 {
        r#type: FWP_ACTION_BLOCK,
        ..Default::default()
    };
    attach_conditions(&mut f, conds);
    f
}

fn permit_filter(
    layer: GUID,
    name: &'static str,
    conds: &[FWPM_FILTER_CONDITION0],
    weight: u8,
) -> FWPM_FILTER0 {
    let mut f = base_filter(layer, name, weight);
    f.action = FWPM_ACTION0 {
        r#type: FWP_ACTION_PERMIT,
        ..Default::default()
    };
    attach_conditions(&mut f, conds);
    f
}

fn cond_u8_protocol(proto: u8) -> FWPM_FILTER_CONDITION0 {
    let mut c = FWPM_FILTER_CONDITION0::default();
    c.fieldKey = FWPM_CONDITION_IP_PROTOCOL;
    c.matchType = FWP_MATCH_EQUAL;
    c.conditionValue = FWP_CONDITION_VALUE0 {
        r#type: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_UINT8,
        Anonymous: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_VALUE0_0 {
            uint8: proto,
        },
    };
    c
}

fn cond_u16_remote_port(port: u16) -> FWPM_FILTER_CONDITION0 {
    let mut c = FWPM_FILTER_CONDITION0::default();
    c.fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
    c.matchType = FWP_MATCH_EQUAL;
    c.conditionValue = FWP_CONDITION_VALUE0 {
        r#type: FWP_UINT16,
        Anonymous: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_VALUE0_0 {
            uint16: port,
        },
    };
    c
}

fn cond_u32_remote_addr(ip: Ipv4Addr) -> FWPM_FILTER_CONDITION0 {
    let mut c = FWPM_FILTER_CONDITION0::default();
    c.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
    c.matchType = FWP_MATCH_EQUAL;
    let mask = Box::new(windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_V4_ADDR_AND_MASK {
        addr: u32::from(ip).to_be(),
        mask: 0xFFFFFFFF,
    });
    c.conditionValue = FWP_CONDITION_VALUE0 {
        r#type: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_V4_ADDR_MASK,
        Anonymous: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_VALUE0_0 {
            v4AddrMask: Box::leak(mask) as *mut _,
        },
    };
    c
}

fn cond_u64_local_iface(luid: u64) -> FWPM_FILTER_CONDITION0 {
    let boxed = Box::leak(Box::new(luid));
    let mut c = FWPM_FILTER_CONDITION0::default();
    c.fieldKey = FWPM_CONDITION_IP_LOCAL_INTERFACE;
    c.matchType = FWP_MATCH_EQUAL;
    c.conditionValue = FWP_CONDITION_VALUE0 {
        r#type: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_UINT64,
        Anonymous: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_VALUE0_0 {
            uint64: boxed as *mut u64,
        },
    };
    c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wfp_cond_u8_protocol() {
        let cond = cond_u8_protocol(17); // UDP
        assert_eq!(cond.matchType, windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_MATCH_EQUAL);
        assert_eq!(cond.conditionValue.r#type, windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_UINT8);
        unsafe {
            assert_eq!(cond.conditionValue.Anonymous.uint8, 17);
        }
    }

    #[test]
    fn test_wfp_cond_u16_remote_port() {
        let cond = cond_u16_remote_port(3478);
        assert_eq!(cond.matchType, windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_MATCH_EQUAL);
        unsafe {
            assert_eq!(cond.conditionValue.Anonymous.uint16, 3478);
        }
    }
}
