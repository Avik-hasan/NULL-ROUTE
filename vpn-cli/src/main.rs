mod args;
mod client;
mod display;

use clap::Parser;
use args::{Cli, Commands};
use client::IpcClient;
use vpn_shared::ipc::IpcCommand;

fn main() {
    let cli = Cli::parse();

    let mut ipc = match IpcClient::connect() {
        Ok(client) => client,
        Err(e) => {
            display::print_error(&format!("Daemon is not running or accessible: {e}"));
            std::process::exit(1);
        }
    };

    match cli.command {
        Commands::Connect { node } => {
            if let Err(e) = ipc.send_command(IpcCommand::Connect { node_index: node as usize }) {
                display::print_error(&format!("Failed to send connect command: {e}"));
                std::process::exit(1);
            }
            display::print_success(&format!("Connection request sent for node index {}", node));
        }
        Commands::Disconnect => {
            if let Err(e) = ipc.send_command(IpcCommand::Disconnect) {
                display::print_error(&format!("Failed to send disconnect command: {e}"));
                std::process::exit(1);
            }
            display::print_success("Disconnect request sent.");
        }
        Commands::Status => {
            // Depending on daemon implementation, we might send a specific status request
            // For now, we'll assume the daemon responds with telemetry periodically or on query.
            display::print_success("Querying status...");
            // Stubbed: in a real loop we'd wait for IpcResponse::Telemetry
        }
    }
}
