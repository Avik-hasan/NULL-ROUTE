# Changelog

All notable changes to the NULL-ROUTE project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Complete Rust-based `vpn-client` daemon for Windows LocalSystem execution.
- Windows Filtering Platform (WFP) Kill-Switch and WebRTC block rules.
- IP Helper Longest-Prefix-Match routing engine for 0.0.0.0/1 overrides.
- Netsh-based physical adapter DNS pinning (DNS Leak Protection).
- `tokio::select!` based JSON IPC over dynamic DACL Named Pipes.
- `vpn-server` Linux exit daemon with `/dev/net/tun` async ioctls.
- Zero-drop Handover protocol for seamless interface and IP rotation.
- `vpn-core` cryptographic engine implementing `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`.
- Tauri React/Tailwind frontend GUI.
- GitHub Actions CI/CD workflows and community health files.
- Extensive `docs/` architectural documentation covering LPE mitigation, packet flow, and routing.
