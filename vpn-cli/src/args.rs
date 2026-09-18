use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "vpn-cli")]
#[command(author, version, about = "Command line interface for NULL-ROUTE VPN", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Connects to a specific VPN node by index
    Connect {
        /// The index of the node in client.json
        #[arg(short, long, default_value_t = 0)]
        node: u32,
    },
    /// Disconnects the active VPN session
    Disconnect,
    /// Checks the current connection status and daemon telemetry
    Status,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_connect_parsing() {
        let cli = Cli::parse_from(&["vpn-cli", "connect", "--node", "5"]);
        match cli.command {
            Commands::Connect { node } => assert_eq!(node, 5),
            _ => panic!("Expected Connect command"),
        }
    }

    #[test]
    fn test_cli_disconnect_parsing() {
        let cli = Cli::parse_from(&["vpn-cli", "disconnect"]);
        assert!(matches!(cli.command, Commands::Disconnect));
    }
}
