//! `vpn-shared` — types shared across the GUI, client service, and server.
//!
//! This crate is intentionally dependency-light and platform-agnostic so it can
//! be compiled for the Windows client, the Linux server, and the Tauri GUI
//! without pulling in OS-specific code.

#![forbid(unsafe_code)]

pub mod config;
pub mod error;
pub mod ipc;
pub mod telemetry;

pub use error::{Result, VpnError};

/// The canonical Windows named-pipe path used for GUI <-> service IPC.
///
/// The ACL that locks this pipe down to SYSTEM + the interactive user is built
/// in `vpn-client::ipc`.
pub const PIPE_NAME: &str = r"\\.\pipe\custom-vpn";

/// Wire protocol version. Bump on any breaking change to `ipc` or `telemetry`.
pub const PROTOCOL_VERSION: u32 = 2;

/// Default transport MTU for the virtual adapter (Wintun / TUN).
pub const TUNNEL_MTU: u16 = 1420;
