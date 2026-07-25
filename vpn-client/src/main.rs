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

mod connection;
#[cfg(windows)]
mod dns;
#[cfg(windows)]
mod ipc;
mod recovery;
#[cfg(windows)]
mod routing;
#[cfg(windows)]
mod tunnel;
#[cfg(windows)]
mod wfp;

use std::sync::Arc;
use parking_lot::Mutex;
use tokio::sync::mpsc;
use tracing::{info, warn};

use connection::ConnectionHandle;
use recovery::CleanupRegistry;
use vpn_shared::config::ClientConfig;
use vpn_shared::ipc::{IpcCommand, IpcResponse};
use vpn_shared::telemetry::{ConnState, LogEvent, Telemetry};
use vpn_shared::{Result, PROTOCOL_VERSION};

/// Global service state shared across IPC client connections.
#[derive(Clone)]
pub struct ServiceState {
    pub config: Arc<ClientConfig>,
    pub handle: Arc<Mutex<Option<ConnectionHandle>>>,
    pub registry: CleanupRegistry,
}

impl ServiceState {
    pub fn new(config: ClientConfig, registry: CleanupRegistry) -> Self {
        Self {
            config: Arc::new(config),
            handle: Arc::new(Mutex::new(None)),
            registry,
        }
    }

    pub async fn dispatch(
        &self,
        cmd: IpcCommand,
        log_tx: mpsc::UnboundedSender<LogEvent>,
    ) -> Result<IpcResponse> {
        match cmd {
            IpcCommand::Hello { protocol_version } => {
                if protocol_version != PROTOCOL_VERSION {
                    return Ok(IpcResponse::Error {
                        message: format!("protocol mismatch: GUI {protocol_version}, service {PROTOCOL_VERSION}"),
                    });
                }
                Ok(IpcResponse::Hello {
                    protocol_version: PROTOCOL_VERSION,
                    service_version: env!("CARGO_PKG_VERSION").to_string(),
                })
            }
            IpcCommand::GetStatus => {
                let guard = self.handle.lock();
                if let Some(h) = guard.as_ref() {
                    Ok(IpcResponse::Status(h.telemetry()))
                } else {
                    Ok(IpcResponse::Status(Telemetry {
                        state: ConnState::Disconnected,
                        ..Telemetry::default()
                    }))
                }
            }
            IpcCommand::Connect { node_index } => {
                if self.handle.lock().is_some() {
                    return Ok(IpcResponse::Error {
                        message: "already connected; disconnect first".into(),
                    });
                }
                match connection::connect(self.config.clone(), node_index, log_tx).await {
                    Ok(h) => {
                        *self.handle.lock() = Some(h);
                        Ok(IpcResponse::Ack)
                    }
                    Err(e) => Ok(IpcResponse::Error {
                        message: format!("connect failed: {e}"),
                    }),
                }
            }
            IpcCommand::Disconnect => {
                if self.handle.lock().take().is_some() {
                    self.registry.run_cleanup();
                }
                Ok(IpcResponse::Ack)
            }
            IpcCommand::RotateNow { node_index: _ } => {
                Ok(IpcResponse::Ack)
            }
            IpcCommand::SetKillSwitch { enabled: _ } => {
                Ok(IpcResponse::Ack)
            }
            IpcCommand::Terminate => {
                self.registry.run_cleanup();
                std::process::exit(0);
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    info!("vpn-client starting up...");

    let registry = CleanupRegistry::new();
    recovery::install_guards(registry.clone());

    #[cfg(windows)]
    {
        if let Ok(wfp_engine) = wfp::WfpEngine::open() {
            let _ = wfp_engine.block_ipv6_outbound();
            let _ = wfp_engine.add_webrtc_blackhole(&dns::webrtc_stun_blacklist());
            std::mem::forget(wfp_engine);
        }
    }

    let config = ClientConfig {
        nodes: vec![
            vpn_shared::config::NodeConfig {
                codename: "OBLIVION-1".into(),
                endpoint: connection::loopback(51820),
                server_public_key: "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=".into(),
                region: "US-East".into(),
            },
            vpn_shared::config::NodeConfig {
                codename: "OBLIVION-2".into(),
                endpoint: connection::loopback(51821),
                server_public_key: "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=".into(),
                region: "EU-West".into(),
            },
        ],
        client_private_key: "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=".into(),
        preshared_key: "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=".into(),
        hop_interval_secs: 30,
        block_webrtc: true,
        kill_switch: true,
    };
    let state = ServiceState::new(config, registry);

    #[cfg(windows)]
    {
        info!("serving IPC named pipe...");
        let st = state.clone();
        ipc::serve(move |mut pipe| {
            let st = st.clone();
            async move {
                let (log_tx, mut log_rx) = mpsc::unbounded_channel::<LogEvent>();
                loop {
                    tokio::select! {
                        Some(ev) = log_rx.recv() => {
                            if let Ok(json) = serde_json::to_vec(&IpcResponse::LogLine(ev)) {
                                if let Err(e) = ipc::write_frame(&mut pipe, &json).await {
                                    warn!(error = %e, "ipc log write error");
                                    break;
                                }
                            }
                        }
                        res = ipc::read_frame(&mut pipe) => {
                            match res {
                                Ok(frame) => {
                                    if let Ok(cmd) = serde_json::from_slice::<IpcCommand>(&frame) {
                                        let resp = st.dispatch(cmd, log_tx.clone()).await.unwrap_or_else(|e| {
                                            IpcResponse::Error { message: e.to_string() }
                                        });
                                        if let Ok(json) = serde_json::to_vec(&resp) {
                                            if let Err(e) = ipc::write_frame(&mut pipe, &json).await {
                                                warn!(error = %e, "ipc response write error");
                                                break;
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    warn!(error = %e, "client disconnected");
                                    break;
                                }
                            }
                        }
                    }
                }
                Ok(())
            }
        })
        .await?;
    }

    #[cfg(not(windows))]
    {
        warn!("named pipe IPC is only supported on Windows; running idle");
        tokio::signal::ctrl_c().await.ok();
    }

    Ok(())
}
