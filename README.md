# Custom VPN v2 — Oblivion Protocol

A hyper-secure, commercial-grade **personal** VPN written in Rust, with a
cyberpunk **Tauri v2** desktop UI, a hardened **Windows** client service, and a
**Linux** exit-server daemon featuring seamless IP hopping.

> Personal-privacy tooling. Run servers you own/control and comply with the laws
> and terms of service that apply to you.

## Workspace layout

```
custom-vpn/
├─ Cargo.toml                # virtual workspace + pinned deps
├─ vpn-shared/               # error, config, ipc, telemetry types (no_unsafe)
├─ vpn-core/                 # crypto (Noise_IKpsk2), anti-replay window, MSS clamp
│   └─ src/{crypto,protocol,mss_clamp}.rs
├─ vpn-client/               # Windows service (elevated)
│   └─ src/{ipc,wfp,routing,dns,recovery,connection,main}.rs
├─ vpn-server/               # Linux daemon
│   └─ src/{listener,peer,handover,tun,main}.rs
├─ gui/                      # Tauri v2 cyberpunk frontend
│   ├─ src/{index.html,styles.css,app.js}
│   └─ src-tauri/            # Tauri shell + pipe client
├─ tools/keygen/             # X25519 keypair + PSK generator
├─ scripts/                  # server-setup.sh, systemd unit
└─ config/                   # example client/server JSON
```

## Security remediations implemented (Section 1)

| # | Threat | Where |
|---|--------|-------|
| 1 | IPv6 leak → full outbound v6 blackhole | `vpn-client/src/wfp.rs::block_ipv6_outbound` |
| 2 | DNS leak → :53 bound to Wintun LUID, else dropped | `wfp.rs::bind_dns_to_tunnel`, `dns.rs` |
| 3 | IPC LPE → Named Pipe DACL: SYSTEM + interactive user only | `wfp`/`ipc.rs::build_pipe_security` |
| 4 | Replay → thread-safe 64-packet sliding-window bitmap | `vpn-core/src/protocol.rs::AntiReplayWindow` |
| 5 | Panic lockout → catch_unwind + LIFO cleanup registry | `vpn-client/src/recovery.rs` |
| 6 | MTU frag → dynamic TCP MSS clamping | `vpn-core/src/mss_clamp.rs` |

## Next-gen privacy (Section 2)

- **Continuous IP hopping / seamless handover** — client pre-establishes a second
  Noise session and atomically swaps via `ArcSwap` (`connection.rs`); the server
  keeps the peer's tunnel IP stable (`peer.rs::migrate`) and rotates its exit
  interface (`handover.rs`). Zero dropped TCP flows.
- **WFP kill switch** — only the encrypted UDP path to the active endpoint is
  permitted; everything else is blocked (`wfp.rs::enable_kill_switch`). The
  dynamic WFP session auto-purges on process death.
- **WebRTC leak mitigation** — STUN/TURN destinations blackholed (`dns.rs` +
  `wfp.rs::add_webrtc_blackhole`).

## Build

### Prerequisites
- Rust stable (see `rust-toolchain.toml`).
- Windows client: MSVC toolchain + the Wintun DLL alongside `vpn-client.exe`.
- GUI: Node + the Tauri v2 CLI (`cargo tauri`).

### Core + server (Linux)
```bash
cargo build --release -p vpn-core -p vpn-server
cargo test  -p vpn-core        # anti-replay + MSS unit tests
```

### Windows client
```powershell
cargo build --release -p vpn-client --target x86_64-pc-windows-msvc
```

### GUI (Windows)
```powershell
cd gui
cargo tauri build
```

### Generate keys
```bash
cargo run --manifest-path tools/keygen/Cargo.toml
```

## Deploy the server
```bash
sudo ./scripts/server-setup.sh eth0 eth1     # TUN + forwarding + NAT
sudo cp config/server.example.json /etc/custom-vpn/server.json  # then edit
sudo ./target/release/vpn-server /etc/custom-vpn/server.json
```

## Preview the UI without a backend
Open `gui/src/index.html` in a browser — it runs in simulated-telemetry mode
(animated chart + diagnostics log) when `window.__TAURI__` is absent.

## Notes on `unsafe`
`vpn-shared` and `vpn-core` are `#![forbid(unsafe_code)]`. All `unsafe` is
confined to the Windows FFI in `vpn-client` (WFP, SID/ACL, IP Helper) and the
Linux TUN ioctl, each wrapped with RAII guards and explicit error mapping. There
are no `unwrap()`/`expect()` calls on production paths.
