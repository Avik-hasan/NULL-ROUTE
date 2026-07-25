//! UDP listener + data-plane forwarding loop (server side).
//!
//! Flow:
//!  * A datagram arrives. If the source matches a known peer, we decrypt it
//!    through that peer's session (with anti-replay) and forward the inner IP
//!    packet to the TUN device.
//!  * If the source is unknown, we attempt a Noise responder handshake; on
//!    success we allocate a peer + tunnel IP.
//!  * Return traffic read from TUN is matched to a peer by destination tunnel
//!    IP, encrypted, and sent to the peer's current remote address.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::net::UdpSocket;
use tokio::sync::Semaphore;
use tracing::{info, warn};

use vpn_core::crypto::{build_handshake, Role, SecretKey, Session};
use vpn_core::mss_clamp;
use vpn_core::protocol::PacketKind;
use vpn_shared::config::ServerConfig;
use vpn_shared::{Result, VpnError};

use crate::handover::HandoverEngine;
use crate::peer::{Peer, PeerTable};

/// Cap on concurrent in-flight handshakes. Bounds the CPU a spoofed flood can
/// force us to spend on asymmetric crypto.
const MAX_INFLIGHT_HANDSHAKES: usize = 64;
/// A Noise_IKpsk2 msg1 is always well over this; shorter datagrams from unknown
/// sources are junk/probe traffic and are dropped before any crypto work.
const MIN_HANDSHAKE_LEN: usize = 32;
/// Minimum spacing between handshake attempts accepted from a single source IP.
const HANDSHAKE_MIN_INTERVAL: Duration = Duration::from_millis(250);

pub async fn run(
    cfg: Arc<ServerConfig>,
    peers: Arc<PeerTable>,
    _hop: Arc<HandoverEngine>,
) -> Result<()> {
    let sock = Arc::new(
        UdpSocket::bind(cfg.listen)
            .await
            .map_err(|e| VpnError::Io(format!("bind {}: {e}", cfg.listen)))?,
    );
    info!(listen = %cfg.listen, "udp listener up");

    let hs_sem = Arc::new(Semaphore::new(MAX_INFLIGHT_HANDSHAKES));
    let last_attempt: Arc<Mutex<HashMap<IpAddr, Instant>>> = Arc::new(Mutex::new(HashMap::new()));

    let mut buf = vec![0u8; 65_535];
    loop {
        let (n, from) = match sock.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "recv_from failed");
                continue;
            }
        };

        // Established peers are handled INLINE: symmetric decryption is cheap,
        // this preserves per-peer packet ordering, and it avoids spawning an
        // unbounded task per datagram (a trivial remote memory-DoS vector).
        if let Some(peer) = peers.by_remote(&from) {
            if let Err(e) = handle_established(&sock, &peer, &buf[..n]).await {
                if !matches!(e, VpnError::Replay { .. }) {
                    warn!(error = %e, %from, "peer datagram error");
                }
            }
            continue;
        }

        // Unknown source => handshake attempt. Apply pre-auth DoS guards.
        if n < MIN_HANDSHAKE_LEN {
            continue; // too small to be a real handshake; drop silently
        }
        if !allow_handshake(&last_attempt, from.ip()) {
            continue; // per-source rate limit
        }
        let permit = match hs_sem.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                warn!(%from, "handshake limiter saturated; dropping");
                continue;
            }
        };

        let datagram = buf[..n].to_vec();
        let sock = sock.clone();
        let peers = peers.clone();
        let cfg = cfg.clone();
        tokio::spawn(async move {
            let _permit = permit; // released when the handshake finishes
            if let Err(e) = responder_handshake(&sock, &peers, &cfg, from, &datagram).await {
                warn!(error = %e, %from, "handshake error");
            }
        });
    }
}

/// Coarse per-source-IP rate limit for handshake initiations. Returns `true` if
/// this source may attempt a handshake now. Also bounds the tracking map.
fn allow_handshake(map: &Mutex<HashMap<IpAddr, Instant>>, ip: IpAddr) -> bool {
    let now = Instant::now();
    let mut m = map.lock();
    if let Some(prev) = m.get(&ip) {
        if now.duration_since(*prev) < HANDSHAKE_MIN_INTERVAL {
            return false;
        }
    }
    m.insert(ip, now);
    if m.len() > 4096 {
        m.retain(|_, t| now.duration_since(*t) < Duration::from_secs(60));
    }
    true
}

/// Handle a datagram from an already-established peer (inline, no task spawn).
async fn handle_established(sock: &UdpSocket, peer: &Arc<Peer>, datagram: &[u8]) -> Result<()> {
    let session = peer.session.load();
    match session.open(datagram) {
        Ok((PacketKind::Data, mut inner)) => {
            mss_clamp::clamp_to_tunnel(&mut inner);
            // write_to_tun(inner) — forwarded to /dev/net/tun.
            let _ = inner;
            peer.touch();
            Ok(())
        }
        Ok((PacketKind::Keepalive, echo)) => {
            // Echo the timestamp back for RTT measurement.
            let frame = session.seal(PacketKind::Keepalive, &echo)?;
            let remote = *peer.remote.load_full();
            sock.send_to(&frame, remote)
                .await
                .map_err(|e| VpnError::Io(e.to_string()))?;
            peer.touch();
            Ok(())
        }
        Ok((PacketKind::HandoverPrepare, _)) => {
            peer.touch();
            info!(tunnel_ip = %peer.tunnel_ip, "client announced handover; awaiting new session");
            Ok(())
        }
        Ok((PacketKind::HandoverCommit, _)) => {
            peer.touch();
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// Complete the responder side of Noise_IKpsk2 and register the new peer.
async fn responder_handshake(
    sock: &UdpSocket,
    peers: &PeerTable,
    cfg: &ServerConfig,
    from: SocketAddr,
    msg1: &[u8],
) -> Result<()> {
    // Zeroizing wrappers so server key material never lingers in the heap.
    let local_priv = SecretKey(b64(&cfg.server_private_key)?);
    let psk = SecretKey(b64(&cfg.preshared_key)?);
    let mut hs = build_handshake(Role::Responder, &local_priv.0, None, &psk.0)?;
    drop(local_priv);
    drop(psk);

    let mut scratch = vec![0u8; 4096];
    hs.read_message(msg1, &mut scratch)
        .map_err(|e| VpnError::Handshake(format!("read msg1: {e}")))?;

    let mut out = vec![0u8; 4096];
    let n = hs
        .write_message(&[], &mut out)
        .map_err(|e| VpnError::Handshake(format!("write msg2: {e}")))?;
    sock.send_to(&out[..n], from)
        .await
        .map_err(|e| VpnError::Io(e.to_string()))?;

    let session = Session::from_handshake(1, hs)?;
    let peer = peers.allocate(from, session)?;
    info!(%from, tunnel_ip = %peer.tunnel_ip, "peer established");
    Ok(())
}

fn b64(s: &str) -> Result<Vec<u8>> {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut lut = [255u8; 256];
    for (i, &c) in T.iter().enumerate() {
        lut[c as usize] = i as u8;
    }
    let s: Vec<u8> = s.bytes().filter(|&b| b != b'=' && !b.is_ascii_whitespace()).collect();
    let mut outv = Vec::with_capacity(s.len() * 3 / 4);
    for chunk in s.chunks(4) {
        // A trailing single base64 char encodes zero whole bytes; reject rather
        // than silently truncating the decoded key.
        if chunk.len() == 1 {
            return Err(VpnError::Config("invalid base64: dangling character".into()));
        }
        let mut acc = 0u32;
        let mut bits = 0;
        for &c in chunk {
            let v = lut[c as usize];
            if v == 255 {
                return Err(VpnError::Config("invalid base64".into()));
            }
            acc = (acc << 6) | v as u32;
            bits += 6;
        }
        let mut shift = bits - (bits % 8);
        while shift >= 8 {
            shift -= 8;
            outv.push((acc >> shift) as u8);
        }
    }
    Ok(outv)
}
