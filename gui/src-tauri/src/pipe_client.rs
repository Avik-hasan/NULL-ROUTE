//! Client side of the named-pipe IPC (GUI -> service).
//!
//! On Windows we open `\\.\pipe\custom-vpn` and speak the length-delimited JSON
//! protocol from `vpn_shared::ipc`. Off-Windows we synthesize telemetry so the
//! UI can be previewed on any OS.

use vpn_shared::telemetry::{ConnState, Telemetry};
use vpn_shared::{Result, VpnError};

#[cfg(windows)]
mod imp {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::windows::named_pipe::ClientOptions;
    use vpn_shared::ipc::{IpcCommand, IpcResponse};
    use vpn_shared::{PIPE_NAME, PROTOCOL_VERSION};

    async fn round_trip(cmd: IpcCommand) -> Result<IpcResponse> {
        let mut pipe = ClientOptions::new()
            .open(PIPE_NAME)
            .map_err(|e| VpnError::Ipc(format!("open pipe: {e}")))?;

        // Handshake first.
        write(&mut pipe, &IpcCommand::Hello { protocol_version: PROTOCOL_VERSION }).await?;
        let _hello = read(&mut pipe).await?;

        write(&mut pipe, &cmd).await?;
        read(&mut pipe).await
    }

    async fn write(
        pipe: &mut tokio::net::windows::named_pipe::NamedPipeClient,
        cmd: &IpcCommand,
    ) -> Result<()> {
        let body = serde_json::to_vec(cmd)?;
        let len = u32::try_from(body.len()).map_err(|_| VpnError::Ipc("too large".into()))?;
        pipe.write_all(&len.to_be_bytes()).await.map_err(io)?;
        pipe.write_all(&body).await.map_err(io)?;
        pipe.flush().await.map_err(io)?;
        Ok(())
    }

    async fn read(
        pipe: &mut tokio::net::windows::named_pipe::NamedPipeClient,
    ) -> Result<IpcResponse> {
        // Hard cap on a single response frame so a malfunctioning/hostile peer
        // on the pipe cannot make the GUI allocate an arbitrary amount of RAM.
        const MAX_FRAME: usize = 1 << 20; // 1 MiB
        let mut len = [0u8; 4];
        pipe.read_exact(&mut len).await.map_err(io)?;
        let n = u32::from_be_bytes(len) as usize;
        if n > MAX_FRAME {
            return Err(VpnError::Ipc(format!("ipc frame too large: {n} bytes")));
        }
        let mut buf = vec![0u8; n];
        pipe.read_exact(&mut buf).await.map_err(io)?;
        Ok(serde_json::from_slice(&buf)?)
    }

    fn io(e: std::io::Error) -> VpnError {
        VpnError::Ipc(e.to_string())
    }

    pub async fn connect(node_index: usize) -> Result<()> {
        match round_trip(IpcCommand::Connect { node_index }).await? {
            IpcResponse::Ack => Ok(()),
            IpcResponse::Error { message } => Err(VpnError::Ipc(message)),
            other => Err(VpnError::Ipc(format!("unexpected: {other:?}"))),
        }
    }
    pub async fn disconnect() -> Result<()> {
        round_trip(IpcCommand::Disconnect).await.map(|_| ())
    }
    pub async fn terminate() -> Result<()> {
        round_trip(IpcCommand::Terminate).await.map(|_| ())
    }
    pub async fn rotate() -> Result<()> {
        round_trip(IpcCommand::RotateNow { node_index: None }).await.map(|_| ())
    }
    pub async fn status() -> Result<Telemetry> {
        match round_trip(IpcCommand::GetStatus).await? {
            IpcResponse::Status(t) => Ok(t),
            other => Err(VpnError::Ipc(format!("unexpected: {other:?}"))),
        }
    }
}

#[cfg(not(windows))]
mod imp {
    use super::*;
    pub async fn connect(_: usize) -> Result<()> {
        Ok(())
    }
    pub async fn disconnect() -> Result<()> {
        Ok(())
    }
    pub async fn terminate() -> Result<()> {
        Ok(())
    }
    pub async fn rotate() -> Result<()> {
        Ok(())
    }
    pub async fn status() -> Result<Telemetry> {
        Ok(Telemetry {
            state: ConnState::Connected,
            active_node: Some("OBLIVION-4".into()),
            exit_ip: Some("185.213.44.9".into()),
            down_bps: 88_000_000,
            up_bps: 12_000_000,
            latency_ms: 27.0,
            bytes_rx: 1_200_000_000,
            bytes_tx: 240_000_000,
            uptime_secs: 4230,
        })
    }
}

pub use imp::{connect, disconnect, rotate, status, terminate};
