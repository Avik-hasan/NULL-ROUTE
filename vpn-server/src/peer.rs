//! Peer session table: maps client tunnel IPs and UDP source addresses to live
//! Noise sessions, and allocates tunnel IPs from the configured subnet.

#![allow(dead_code)]

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use ipnet::Ipv4Net;
use parking_lot::{Mutex, RwLock};

use vpn_core::crypto::Session;
use vpn_shared::{Result, VpnError};

/// One connected client. `session` is swappable so a client's handover to a new
/// session_id doesn't tear down its peer entry.
pub struct Peer {
    pub tunnel_ip: Ipv4Addr,
    pub remote: ArcSwap<SocketAddr>,
    pub session: ArcSwap<Session>,
    /// Last time we saw valid traffic from this peer; drives idle eviction so a
    /// long-running server can never exhaust the tunnel subnet.
    last_seen: Mutex<Instant>,
}

impl Peer {
    /// Mark the peer as active (called on every authenticated datagram).
    pub fn touch(&self) {
        *self.last_seen.lock() = Instant::now();
    }

    fn idle_for(&self) -> Duration {
        self.last_seen.lock().elapsed()
    }
}

pub struct PeerTable {
    subnet: Ipv4Net,
    /// Next free host to hand out (naive linear allocator; fine for personal use).
    next_host: RwLock<u32>,
    /// Recycled tunnel IPs from evicted peers, reused before advancing `next_host`.
    free_list: RwLock<Vec<Ipv4Addr>>,
    by_tunnel_ip: RwLock<HashMap<Ipv4Addr, Arc<Peer>>>,
    by_remote: RwLock<HashMap<SocketAddr, Arc<Peer>>>,
}

impl PeerTable {
    pub fn new(subnet: &str) -> Result<Self> {
        let subnet: Ipv4Net = subnet
            .parse()
            .map_err(|e| VpnError::Config(format!("bad tunnel_subnet: {e}")))?;
        // Skip .0 (network) and .1 (reserved for the server/DNS).
        let first = u32::from(subnet.network()) + 2;
        Ok(Self {
            subnet,
            next_host: RwLock::new(first),
            free_list: RwLock::new(Vec::new()),
            by_tunnel_ip: RwLock::new(HashMap::new()),
            by_remote: RwLock::new(HashMap::new()),
        })
    }

    /// Allocate a tunnel IP for a newly handshaked client, reusing a recycled IP
    /// from an evicted peer when available.
    pub fn allocate(&self, remote: SocketAddr, session: Session) -> Result<Arc<Peer>> {
        let candidate = if let Some(ip) = self.free_list.write().pop() {
            ip
        } else {
            let mut next = self.next_host.write();
            let c = Ipv4Addr::from(*next);
            if !self.subnet.contains(&c) {
                return Err(VpnError::InvalidState("tunnel subnet exhausted".into()));
            }
            *next += 1;
            c
        };

        let peer = Arc::new(Peer {
            tunnel_ip: candidate,
            remote: ArcSwap::from_pointee(remote),
            session: ArcSwap::from_pointee(session),
            last_seen: Mutex::new(Instant::now()),
        });
        self.by_tunnel_ip.write().insert(candidate, peer.clone());
        self.by_remote.write().insert(remote, peer.clone());
        Ok(peer)
    }

    /// Evict peers idle longer than `idle`, returning their tunnel IPs to the
    /// free list. Returns the number evicted.
    pub fn reap(&self, idle: Duration) -> usize {
        let mut freed: Vec<Ipv4Addr> = Vec::new();
        {
            let mut by_ip = self.by_tunnel_ip.write();
            by_ip.retain(|ip, peer| {
                let keep = peer.idle_for() <= idle;
                if !keep {
                    freed.push(*ip);
                }
                keep
            });
        }
        if freed.is_empty() {
            return 0;
        }
        // Drop every remote mapping whose peer was evicted.
        self.by_remote
            .write()
            .retain(|_, peer| !freed.contains(&peer.tunnel_ip));
        self.free_list.write().extend(freed.iter().copied());
        freed.len()
    }

    pub fn by_remote(&self, remote: &SocketAddr) -> Option<Arc<Peer>> {
        self.by_remote.read().get(remote).cloned()
    }

    pub fn by_tunnel_ip(&self, ip: &Ipv4Addr) -> Option<Arc<Peer>> {
        self.by_tunnel_ip.read().get(ip).cloned()
    }

    /// Re-key an existing peer during a client handover: keep the tunnel IP,
    /// swap in the new session + remote so packet flow continues uninterrupted.
    pub fn migrate(&self, peer: &Arc<Peer>, new_remote: SocketAddr, new_session: Session) {
        let old_remote = *peer.remote.load_full();
        peer.session.store(Arc::new(new_session));
        peer.remote.store(Arc::new(new_remote));
        peer.touch();
        let mut by_remote = self.by_remote.write();
        // Remove the stale mapping so the old source address can't resolve to
        // this peer (prevents a slow leak of dead entries across handovers).
        if old_remote != new_remote {
            by_remote.remove(&old_remote);
        }
        by_remote.insert(new_remote, peer.clone());
    }
}
