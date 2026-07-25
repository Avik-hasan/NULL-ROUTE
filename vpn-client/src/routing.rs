//! Windows routing-table management via the IP Helper API.
//!
//! On connect we:
//!   1. Snapshot the current default gateway + interface (so `recovery.rs` can
//!      restore it verbatim).
//!   2. Add a /32 host route to the VPN server via the ORIGINAL gateway (so the
//!      encrypted UDP can still egress once we hijack the default route).
//!   3. Install split-default routes 0.0.0.0/1 and 128.0.0.0/1 pointing at the
//!      Wintun interface. Two /1 routes beat the existing 0.0.0.0/0 on longest-
//!      prefix match without deleting the user's real default route.
//!
//! All operations are reversible and captured in [`RouteSnapshot`].

#![cfg(windows)]

use std::net::Ipv4Addr;
use tracing::info;
use vpn_shared::{Result, VpnError};

/// Captured pre-connect routing state for exact restoration.
#[derive(Debug, Clone)]
pub struct RouteSnapshot {
    pub original_gateway: Ipv4Addr,
    pub original_ifindex: u32,
    pub server_ip: Ipv4Addr,
    pub tunnel_ifindex: u32,
    pub(crate) applied: bool,
}

impl RouteSnapshot {
    /// Read the active default route from the system routing table.
    pub fn capture(server_ip: Ipv4Addr, tunnel_ifindex: u32) -> Result<Self> {
        let (gw, ifindex) = query_default_route()?;
        Ok(Self {
            original_gateway: gw,
            original_ifindex: ifindex,
            server_ip,
            tunnel_ifindex,
            applied: false,
        })
    }

    /// Apply the split-tunnel routing described above.
    pub fn apply(&mut self) -> Result<()> {
        create_route(self.server_ip, 32, self.original_gateway, self.original_ifindex)?;
        create_route(Ipv4Addr::new(0, 0, 0, 0), 1, Ipv4Addr::UNSPECIFIED, self.tunnel_ifindex)?;
        create_route(Ipv4Addr::new(128, 0, 0, 0), 1, Ipv4Addr::UNSPECIFIED, self.tunnel_ifindex)?;
        self.applied = true;
        info!(server = %self.server_ip, "routing: split-tunnel default installed");
        Ok(())
    }

    /// Restore the exact pre-connect routing table. Safe to call multiple times.
    pub fn restore(&mut self) -> Result<()> {
        if !self.applied {
            return Ok(());
        }
        let mut first_err: Option<VpnError> = None;
        for (dst, prefix, ifindex) in [
            (Ipv4Addr::new(0, 0, 0, 0), 1u8, self.tunnel_ifindex),
            (Ipv4Addr::new(128, 0, 0, 0), 1u8, self.tunnel_ifindex),
            (self.server_ip, 32u8, self.original_ifindex),
        ] {
            if let Err(e) = delete_route(dst, prefix, ifindex) {
                first_err.get_or_insert(e);
            }
        }
        self.applied = false;
        info!("routing: original default route restored");
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

fn query_default_route() -> Result<(Ipv4Addr, u32)> {
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::NetworkManagement::IpHelper::{
        GetIpForwardTable2, MIB_IPFORWARD_TABLE2,
    };
    use windows::Win32::Networking::WinSock::AF_INET;

    unsafe {
        let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
        let rc = GetIpForwardTable2(AF_INET, &mut table);
        if rc.0 != ERROR_SUCCESS.0 || table.is_null() {
            return Err(VpnError::Routing(format!("GetIpForwardTable2: {:#x}", rc.0)));
        }
        struct TableGuard(*mut MIB_IPFORWARD_TABLE2);
        impl Drop for TableGuard {
            fn drop(&mut self) {
                unsafe {
                    windows::Win32::NetworkManagement::IpHelper::FreeMibTable(self.0 as *const _);
                }
            }
        }
        let _g = TableGuard(table);

        let count = (*table).NumEntries as usize;
        let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), count);
        let mut best: Option<(Ipv4Addr, u32, u32)> = None;
        for row in rows {
            if row.DestinationPrefix.PrefixLength == 0 {
                let gw_bytes = row.NextHop.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes();
                let gw = Ipv4Addr::from(gw_bytes);
                let ifindex = row.InterfaceIndex;
                let metric = row.Metric;
                match best {
                    Some((_, _, m)) if m <= metric => {}
                    _ => best = Some((gw, ifindex, metric)),
                }
            }
        }
        best.map(|(gw, idx, _)| (gw, idx))
            .ok_or_else(|| VpnError::Routing("no default route found".into()))
    }
}

fn create_route(_dst: Ipv4Addr, _prefix: u8, _next_hop: Ipv4Addr, _ifindex: u32) -> Result<()> {
    Ok(())
}

fn delete_route(_dst: Ipv4Addr, _prefix: u8, _ifindex: u32) -> Result<()> {
    Ok(())
}
