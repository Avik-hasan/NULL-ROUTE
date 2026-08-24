# custom-vpn-gui

The unprivileged desktop application for NULL-ROUTE.

## Tech Stack
- **Tauri**: Rust-based secure webview backend.
- **React**: Component-based UI framework.
- **Tailwind CSS**: Utility-first styling.
- **Vite**: Ultra-fast frontend build tooling.

## Security Posture
The GUI has absolutely no system privileges. It cannot bypass the Windows firewall or manipulate routing.
It communicates exclusively with the `vpn-client` Windows Service via a Named Pipe (`\\.\pipe\custom-vpn`). 

Because the GUI is inherently untrusted by the backend, all `IpcCommand` frames sent by the GUI are strictly validated by the daemon before execution.
