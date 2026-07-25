//! `vpn-server` — Linux VPN exit daemon with seamless IP hopping.
//!
//! Responsibilities:
//!   * Terminate Noise_IKpsk2 sessions from clients (responder role).
//!   * Decrypt/encrypt the data plane and forward between the UDP socket and the
//!     kernel TUN interface (`/dev/net/tun`).
//!   * Perform server-side exit-IP rotation by moving outbound SNAT between the
//!     configured `exit_interfaces` (see `handover.rs`).
//!
//! NAT + IP-forwarding setup is performed by `scripts/server-setup.sh`.

mod handover;
mod listener;
mod peer;
#[cfg(target_os = "linux")]
mod tun;

use std::sync::Arc;

use tracing::info;
use vpn_shared::config::ServerConfig;
use vpn_shared::Result;

fn main() -> Result<()> {
    init_tracing();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| vpn_shared::VpnError::Io(e.to_string()))?;
    rt.block_on(async_main())
}

async fn async_main() -> Result<()> {
    let cfg = load_config()?;
    info!(listen = %cfg.listen, "vpn-server starting");

    let peers = Arc::new(peer::PeerTable::new(&cfg.tunnel_subnet)?);
    let hop = Arc::new(handover::HandoverEngine::new(cfg.exit_interfaces.clone()));

    // Rotate the outbound exit interface on a timer (server-side IP hopping).
    handover::spawn_rotation(hop.clone(), std::time::Duration::from_secs(300));

    // Evict idle peers so the tunnel subnet can never be exhausted by stale
    // sessions; their IPs are recycled by the allocator.
    {
        let peers_reap = peers.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(30));
            loop {
                tick.tick().await;
                let n = peers_reap.reap(std::time::Duration::from_secs(180));
                if n > 0 {
                    info!(evicted = n, "peer table: reaped idle peers");
                }
            }
        });
    }

    listener::run(Arc::new(cfg), peers, hop).await
}

fn load_config() -> Result<ServerConfig> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/etc/custom-vpn/server.json".to_string());
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| vpn_shared::VpnError::Config(format!("read {path}: {e}")))?;
    let cfg: ServerConfig = serde_json::from_str(&raw)
        .map_err(|e| vpn_shared::VpnError::Config(format!("parse {path}: {e}")))?;
    Ok(cfg)
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();
}
