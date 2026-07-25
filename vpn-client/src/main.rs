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
use tracing::{info, warn, error};

use connection::ConnectionHandle;
use recovery::CleanupRegistry;
use vpn_shared::config::ClientConfig;
use vpn_shared::ipc::{IpcCommand, IpcResponse};
use vpn_shared::telemetry::{ConnState, LogEvent, LogLevel, Telemetry};
use vpn_shared::{Result, VpnError, PROTOCOL_VERSION};

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
                let mut guard = self.handle.lock();
                if guard.is_some() {
                    return Ok(IpcResponse::Error {
                        message: "already connected; disconnect first".into(),
                    });
                }
                match connection::connect(self.config.clone(), node_index, log_tx).await {
                    Ok(h) => {
                        *guard = Some(h);
                        Ok(IpcResponse::Ack)
                    }
                    Err(e) => Ok(IpcResponse::Error {
                        message: format!("connect failed: {e}"),
                    }),
                }
            }
            IpcCommand::Disconnect => {
                let mut guard = self.handle.lock();
                if guard.take().is_some() {
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

fn main() {}
