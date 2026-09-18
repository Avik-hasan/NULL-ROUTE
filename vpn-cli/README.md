# vpn-cli

The official command-line interface for NULL-ROUTE VPN.

## Usage

The CLI communicates with the privileged Windows daemon (`vpn-client`) using the same Named Pipe architecture as the GUI. This allows headless servers and scripts to orchestrate the VPN connection safely.

```bash
# Connect to node index 0
vpn-cli connect --node 0

# Check connection status
vpn-cli status

# Disconnect the active session
vpn-cli disconnect
```

## Security
Like the GUI, the CLI does not require administrator privileges to run. It simply passes validated JSON messages to the secure `vpn-client` daemon, which handles the actual WFP and Routing mutations.
