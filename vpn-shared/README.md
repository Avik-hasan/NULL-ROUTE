# vpn-shared

This crate defines the common schemas and constants shared across the Windows daemon, Linux daemon, and Tauri GUI.

## Contents
- **IPC Definitions (`ipc.rs`)**: JSON payloads used over the Named Pipe between the GUI and daemon (`IpcCommand`, `IpcResponse`).
- **Telemetry (`telemetry.rs`)**: Status and log structures emitted by the background daemons.
- **Configuration (`config.rs`)**: JSON schemas for `client.json` and `server.json` (handling PSKs, Node Arrays, Listen addresses).
- **Errors (`error.rs`)**: Centralized `VpnError` enum utilizing `thiserror`.

By keeping these types in a separate crate, both the unprivileged GUI and privileged daemon can strongly type their boundaries without duplicating schema logic.
