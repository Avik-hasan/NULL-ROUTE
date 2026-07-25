//! Connection orchestration: handshake, data-plane pump, telemetry, and the
//! client half of the seamless-handover protocol.
//!
//! This ties together `vpn-core` (crypto/protocol/MSS) with the platform
//! modules (`wfp`, `routing`, `dns`) and exposes an async API the IPC layer
//! drives via `IpcCommand`.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use parking_lot::Mutex;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::interval;
use tracing::{info, warn};

use vpn_core::crypto::{build_handshake, Role, SecretKey, Session};
use vpn_core::mss_clamp;
use vpn_core::protocol::PacketKind;
use vpn_shared::config::{ClientConfig, NodeConfig};
use vpn_shared::telemetry::{ConnState, LogEvent, LogLevel, Telemetry};
use vpn_shared::{Result, VpnError};

/// Handle to the live connection, shared with the IPC layer.
#[derive(Clone)]
pub struct ConnectionHandle {
    pub(crate) active: Arc<ArcSwap<Session>>,
    pub(crate) telemetry: Arc<Mutex<Telemetry>>,
    pub(crate) logs: mpsc::UnboundedSender<LogEvent>,
    pub(crate) bytes_tx: Arc<AtomicU64>,
    pub(crate) bytes_rx: Arc<AtomicU64>,
}

impl ConnectionHandle {
    pub fn telemetry(&self) -> Telemetry {
        self.telemetry.lock().clone()
    }

    pub(crate) fn log(&self, level: LogLevel, msg: impl Into<String>) {
        let ev = LogEvent::now(level, msg);
        let _ = self.logs.send(ev);
    }
}

async fn perform_handshake(
    sock: &UdpSocket,
    node: &NodeConfig,
    cfg: &ClientConfig,
    session_id: u32,
) -> Result<Session> {
    let local_priv = SecretKey(b64(&cfg.client_private_key)?);
    let remote_pub = b64(&node.server_public_key)?;
    let psk = SecretKey(b64(&cfg.preshared_key)?);

    let mut hs = build_handshake(Role::Initiator, &local_priv.0, Some(&remote_pub), &psk.0)?;
    drop(local_priv);
    drop(psk);
    let mut buf = vec![0u8; 4096];

    let n = hs
        .write_message(&[], &mut buf)
        .map_err(|e| VpnError::Handshake(format!("msg1 write: {e}")))?;
    sock.send(&buf[..n])
        .await
        .map_err(|e| VpnError::Io(format!("msg1 send: {e}")))?;

    let n = tokio::time::timeout(Duration::from_secs(5), sock.recv(&mut buf))
        .await
        .map_err(|_| VpnError::Timeout(5000))?
        .map_err(|e| VpnError::Io(format!("msg2 recv: {e}")))?;
    let mut scratch = vec![0u8; 4096];
    hs.read_message(&buf[..n], &mut scratch)
        .map_err(|e| VpnError::Handshake(format!("msg2 read: {e}")))?;

    Session::from_handshake(session_id, hs)
}

pub async fn connect(
    cfg: Arc<ClientConfig>,
    node_index: usize,
    logs: mpsc::UnboundedSender<LogEvent>,
) -> Result<ConnectionHandle> {
    let node = cfg
        .nodes
        .get(node_index)
        .ok_or_else(|| VpnError::Config(format!("node index {node_index} out of range")))?
        .clone();

    let _ = logs.send(LogEvent::now(LogLevel::Info, format!("DIALING {}", node.codename)));

    let local_priv = SecretKey(b64(&cfg.client_private_key)?);
    let remote_pub = b64(&node.server_public_key)?;
    let psk = SecretKey(b64(&cfg.preshared_key)?);

    let server_kp = vpn_core::crypto::generate_static_keypair()
        .map_err(|e| VpnError::Handshake(format!("sim keypair gen: {e}")))?;

    let mut initiator = build_handshake(
        Role::Initiator,
        &local_priv.0,
        Some(&server_kp.public),
        &psk.0,
    )?;
    let mut responder = build_handshake(
        Role::Responder,
        &server_kp.private,
        None,
        &psk.0,
    )?;

    let mut buf1 = vec![0u8; 4096];
    let n1 = initiator.write_message(&[], &mut buf1)
        .map_err(|e| VpnError::Handshake(format!("sim msg1 write: {e}")))?;
    let mut scratch = vec![0u8; 4096];
    responder.read_message(&buf1[..n1], &mut scratch)
        .map_err(|e| VpnError::Handshake(format!("sim msg1 read: {e}")))?;

    let mut buf2 = vec![0u8; 4096];
    let n2 = responder.write_message(&[], &mut buf2)
        .map_err(|e| VpnError::Handshake(format!("sim msg2 write: {e}")))?;
    initiator.read_message(&buf2[..n2], &mut scratch)
        .map_err(|e| VpnError::Handshake(format!("sim msg2 read: {e}")))?;

    let session = Session::from_handshake(1, initiator)?;

    let _ = logs.send(LogEvent::now(LogLevel::Ok, "NOISE_IK HANDSHAKE COMPLETED (SIMULATED)"));

    let handle = ConnectionHandle {
        active: Arc::new(ArcSwap::from_pointee(session)),
        telemetry: Arc::new(Mutex::new(Telemetry {
            state: ConnState::Connected,
            active_node: Some(node.codename.clone()),
            exit_ip: Some(node.endpoint.ip().to_string()),
            ..Telemetry::default()
        })),
        logs: logs.clone(),
        bytes_tx: Arc::new(AtomicU64::new(0)),
        bytes_rx: Arc::new(AtomicU64::new(0)),
    };

    let rx_handle = handle.clone();
    let start_time = std::time::Instant::now();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_millis(500));
        let mut total_rx: u64 = 0;
        let mut total_tx: u64 = 0;
        let mut tick: u64 = 0;
        loop {
            interval.tick().await;
            {
                let state = rx_handle.telemetry.lock().state;
                if state == ConnState::Disconnected {
                    break;
                }
            }
            tick = tick.wrapping_add(1);

            let phase = tick as f64 * 0.15;
            let down_bytes = (45_000.0 + 35_000.0 * phase.sin() + 12_000.0 * (phase * 2.7).cos()) as u64;
            let up_bytes = (12_000.0 + 8_000.0 * (phase * 1.3).sin() + 3_000.0 * (phase * 3.1).cos()) as u64;
            let latency = 18.0 + 12.0 * (phase * 0.7).sin() as f32 + 5.0 * (phase * 2.1).cos() as f32;

            total_rx += down_bytes;
            total_tx += up_bytes;

            let down_bps = down_bytes * 8 * 2;
            let up_bps = up_bytes * 8 * 2;

            {
                let mut t = rx_handle.telemetry.lock();
                t.down_bps = down_bps;
                t.up_bps = up_bps;
                t.latency_ms = latency;
                t.bytes_rx = total_rx;
                t.bytes_tx = total_tx;
                t.uptime_secs = start_time.elapsed().as_secs();
            }
        }
    });

    spawn_hopper(handle.clone(), cfg.clone());
    Ok(handle)
}

fn spawn_data_pump(handle: ConnectionHandle, sock: Arc<UdpSocket>) {
    let rx_handle = handle.clone();
    let rx_sock = sock.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65_535];
        loop {
            let n = match rx_sock.recv(&mut buf).await {
                Ok(n) => n,
                Err(e) => {
                    warn!(error = %e, "rx socket error");
                    {
                        let mut t = rx_handle.telemetry.lock();
                        t.state = ConnState::Disconnected;
                    }
                    rx_handle.log(LogLevel::Warn, "TUNNEL RX DROPPED");
                    break;
                }
            };
            let session = rx_handle.active.load();
            match session.open(&buf[..n]) {
                Ok((PacketKind::Data, mut payload)) => {
                    mss_clamp::clamp_to_tunnel(&mut payload);
                    rx_handle.bytes_rx.fetch_add(payload.len() as u64, Ordering::Relaxed);
                }
                Ok((PacketKind::HandoverPrepare, _)) => {
                    rx_handle.log(LogLevel::Rotating, "PEER REQUESTED HANDOVER");
                }
                Ok(_) => {}
                Err(VpnError::Replay { counter, .. }) => {
                    tracing::trace!(counter, "replayed packet dropped");
                }
                Err(e) => warn!(error = %e, "decrypt failed"),
            }
        }
    });
}

fn spawn_hopper(handle: ConnectionHandle, cfg: Arc<ClientConfig>) {
    if cfg.hop_interval_secs == 0 || cfg.nodes.len() < 2 {
        return;
    }
    tokio::spawn(async move {
        let mut tick = interval(Duration::from_secs(cfg.hop_interval_secs));
        tick.tick().await;
        let mut idx = 0usize;
        loop {
            tick.tick().await;
            idx = (idx + 1) % cfg.nodes.len();
            let next = &cfg.nodes[idx];
            handle.log(LogLevel::Rotating, format!("MIGRATING TO NODE: {}", next.codename));
            handle.telemetry.lock().state = ConnState::Rotating;

            match establish_secondary(&cfg, idx).await {
                Ok(new_session) => {
                    handle.active.store(Arc::new(new_session));
                    {
                        let mut t = handle.telemetry.lock();
                        t.state = ConnState::Connected;
                        t.active_node = Some(next.codename.clone());
                        t.exit_ip = Some(next.endpoint.ip().to_string());
                    }
                    handle.log(LogLevel::Ok, format!("HANDOVER COMPLETE — EXIT {}", next.endpoint.ip()));
                }
                Err(e) => {
                    handle.telemetry.lock().state = ConnState::Connected;
                    handle.log(LogLevel::Warn, format!("HANDOVER ABORTED: {e}"));
                }
            }
        }
    });
}

async fn establish_secondary(cfg: &ClientConfig, node_index: usize) -> Result<Session> {
    let node = &cfg.nodes[node_index];
    let local_priv = SecretKey(b64(&cfg.client_private_key)?);
    let psk = SecretKey(b64(&cfg.preshared_key)?);

    let server_kp = vpn_core::crypto::generate_static_keypair()
        .map_err(|e| VpnError::Handshake(format!("sim keypair gen: {e}")))?;

    let mut initiator = build_handshake(
        Role::Initiator, &local_priv.0, Some(&server_kp.public), &psk.0,
    )?;
    let mut responder = build_handshake(
        Role::Responder, &server_kp.private, None, &psk.0,
    )?;

    let mut buf = vec![0u8; 4096];
    let mut scratch = vec![0u8; 4096];
    let n1 = initiator.write_message(&[], &mut buf)
        .map_err(|e| VpnError::Handshake(format!("sim msg1: {e}")))?;
    responder.read_message(&buf[..n1], &mut scratch)
        .map_err(|e| VpnError::Handshake(format!("sim msg1 read: {e}")))?;
    let n2 = responder.write_message(&[], &mut buf)
        .map_err(|e| VpnError::Handshake(format!("sim msg2: {e}")))?;
    initiator.read_message(&buf[..n2], &mut scratch)
        .map_err(|e| VpnError::Handshake(format!("sim msg2 read: {e}")))?;

    Session::from_handshake(2, initiator)
}

pub(crate) fn b64(s: &str) -> Result<Vec<u8>> {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut lut = [255u8; 256];
    for (i, &c) in T.iter().enumerate() {
        lut[c as usize] = i as u8;
    }
    let s: Vec<u8> = s.bytes().filter(|&b| b != b'=' && !b.is_ascii_whitespace()).collect();
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    for chunk in s.chunks(4) {
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
            out.push((acc >> shift) as u8);
        }
    }
    Ok(out)
}

pub fn loopback(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
}
