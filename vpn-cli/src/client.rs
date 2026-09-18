use std::io::{Read, Write};
use std::time::Duration;
use vpn_shared::ipc::{IpcCommand, IpcResponse};
use vpn_shared::{PROTOCOL_VERSION, VpnError, Result};

#[cfg(windows)]
const PIPE_NAME: &str = r"\\.\pipe\custom-vpn";
#[cfg(not(windows))]
const PIPE_NAME: &str = "/tmp/custom-vpn.sock";

/// A simple synchronous IPC client for the CLI to communicate with the daemon.
pub struct IpcClient {
    #[cfg(windows)]
    pipe: std::fs::File,
}

impl IpcClient {
    pub fn connect() -> Result<Self> {
        #[cfg(windows)]
        {
            // Try connecting to the pipe with a small backoff.
            let mut retries = 5;
            loop {
                match std::fs::OpenOptions::new().read(true).write(true).open(PIPE_NAME) {
                    Ok(mut pipe) => {
                        // Send the hello handshake immediately.
                        let hello = IpcCommand::Hello { protocol_version: PROTOCOL_VERSION };
                        let frame = serde_json::to_vec(&hello).unwrap();
                        let len_prefix = (frame.len() as u32).to_le_bytes();
                        pipe.write_all(&len_prefix).map_err(|e| VpnError::Io(e.to_string()))?;
                        pipe.write_all(&frame).map_err(|e| VpnError::Io(e.to_string()))?;
                        
                        return Ok(Self { pipe });
                    }
                    Err(e) if retries > 0 => {
                        retries -= 1;
                        std::thread::sleep(Duration::from_millis(100));
                    }
                    Err(e) => {
                        return Err(VpnError::Io(format!("Could not connect to daemon pipe: {e}")));
                    }
                }
            }
        }
        #[cfg(not(windows))]
        Err(VpnError::Io("CLI IPC only supported on Windows daemon for now".into()))
    }

    pub fn send_command(&mut self, cmd: IpcCommand) -> Result<()> {
        #[cfg(windows)]
        {
            let frame = serde_json::to_vec(&cmd).unwrap();
            let len_prefix = (frame.len() as u32).to_le_bytes();
            self.pipe.write_all(&len_prefix).map_err(|e| VpnError::Io(e.to_string()))?;
            self.pipe.write_all(&frame).map_err(|e| VpnError::Io(e.to_string()))?;
            Ok(())
        }
        #[cfg(not(windows))]
        Err(VpnError::Io("Unsupported OS".into()))
    }

    pub fn read_response(&mut self) -> Result<IpcResponse> {
        #[cfg(windows)]
        {
            let mut len_buf = [0u8; 4];
            self.pipe.read_exact(&mut len_buf).map_err(|e| VpnError::Io(e.to_string()))?;
            let len = u32::from_le_bytes(len_buf) as usize;
            
            if len > 65_536 {
                return Err(VpnError::Io("Response frame too large".into()));
            }

            let mut frame = vec![0u8; len];
            self.pipe.read_exact(&mut frame).map_err(|e| VpnError::Io(e.to_string()))?;
            
            let resp: IpcResponse = serde_json::from_slice(&frame)
                .map_err(|e| VpnError::Io(format!("Invalid IPC JSON response: {e}")))?;
            Ok(resp)
        }
        #[cfg(not(windows))]
        Err(VpnError::Io("Unsupported OS".into()))
    }
}
