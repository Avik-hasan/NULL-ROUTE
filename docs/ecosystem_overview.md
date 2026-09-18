# NULL-ROUTE Ecosystem Overview

The NULL-ROUTE project is a sprawling ecosystem consisting of several highly specialized Rust crates working in tandem.

## 1. Daemons (Privileged)
- **`vpn-client` (Windows)**: The `NT AUTHORITY\SYSTEM` service that mutates routing and firewall state.
- **`vpn-server` (Linux)**: The `root` async daemon multiplexing UDP tunnels into `/dev/net/tun`.

## 2. Interfaces (Unprivileged)
- **`custom-vpn-gui`**: A Tauri + React application providing a graphical user experience.
- **`vpn-cli`**: A `clap`-powered command line interface for headless orchestration.
Both of these interfaces communicate with the Windows daemon exclusively over a strictly validated JSON Named Pipe (`\\.\pipe\custom-vpn`).

## 3. Libraries (Pure Rust)
- **`vpn-core`**: The purely functional, `no_std` cryptographic engine implementing `Noise_IKpsk2`.
- **`vpn-shared`**: The schema definitions for IPC and telemetry data to prevent mismatch between components.

## 4. Cloud Infrastructure
- **`vpn-api`**: A mock `axum` REST API simulating a subscription backend and dynamic node directory.
