# GUI Architecture (Tauri + React)

The graphical user interface is entirely unprivileged and built using web technologies.

## Frameworks
- **Core**: Tauri v2
- **Frontend**: React 18, TypeScript, Tailwind CSS
- **State Management**: React Context / Hooks

## IPC Communication
Because the GUI does not have administrator privileges, it cannot directly modify routing or firewall rules.
Instead, the Tauri Rust backend (`pipe_client.rs`) acts as a bridge. It connects to the `vpn-client` Windows Named Pipe (`\\.\pipe\custom-vpn`).

When the user clicks "Connect":
1. React calls Tauri `invoke("connect", { nodeIndex: 0 })`.
2. Tauri serializes this into the JSON `IpcCommand::Connect`.
3. The command is written to the Named Pipe.
4. The background `vpn-client` daemon receives the command, validates it, and performs the privileged network setup.
5. The daemon streams status back over the pipe.
6. Tauri relays these status updates to React via window events (`listen('vpn-state', ...)`).

## Security
The Tauri webview has extremely strict Content Security Policies (CSP). It cannot execute arbitrary JavaScript, connect to the internet directly, or read arbitrary local files. The attack surface is practically zero.
