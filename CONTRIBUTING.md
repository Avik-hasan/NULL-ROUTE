# Contributing to NULL-ROUTE

Thank you for your interest in contributing to **NULL-ROUTE**, the advanced custom-protocol VPN featuring anti-replay protection, dynamic WFP kill-switches, and seamless exit-IP handover.

## Architecture Overview

The repository is structured as a cargo workspace with clear security boundaries:

* **`vpn-shared`**: Common IPC schemas (`IpcCommand`, `IpcResponse`), telemetry structs, and error definitions.
* **`vpn-core`**: Pure, platform-agnostic cryptography and protocol engine (X25519, ChaCha20-Poly1305, Noise_IKpsk2, MSS clamping).
* **`vpn-client`**: Elevated Windows system service (LocalSystem) managing WFP filtering rules, Win32 named pipes with DACL enforcement, IP Helper routing, and netsh DNS pinning.
* **`vpn-server`**: High-performance Linux exit daemon with `/dev/net/tun` ioctls and server-side SNAT interface rotation.
* **`gui` / `src-tauri`**: Unprivileged interactive desktop client built with Tauri and React/Tailwind.
* **`tools/keygen`**: Command-line X25519 utility for generating static and pre-shared keys.

## Development Setup

### Prerequisites
* **Rust**: Toolchain 1.80+ (`rustup update stable`).
* **Windows (Client Development)**: Windows 10/11 SDK for WFP and Win32 APIs, Wintun driver (`wintun.dll`).
* **Linux (Server Development)**: Root privileges or `CAP_NET_ADMIN` capability for `/dev/net/tun` and nftables/iptables integration.
* **Node.js**: v18+ for frontend UI compilation in `gui/`.

### Building and Testing

To verify all core crates and services across the workspace:

```bash
# Check syntax and type compatibility across all crates
cargo check --workspace

# Run automated unit and integration tests
cargo test --workspace

# Build release binaries
cargo build --release --workspace
```

## Pull Request Guidelines

1. **Commit History**: Please keep commits focused and incremental. Write clear, imperative commit messages (e.g., `feat(vpn-client): add WFP WebRTC stun blocking filter`).
2. **Fail-Safe Hygiene**: When modifying OS state (firewalls, DNS, routing), ensure RAII guards or `recovery::CleanupRegistry` hooks are in place so system network access is restored on panic or unexpected shutdown.
3. **Security**: Never log sensitive key material (private keys or pre-shared keys). Use `zeroize::Zeroize` wrappers for in-memory secret handling.
4. **Formatting**: Run `cargo fmt` and `cargo clippy` before submitting your PR.
