//! `vpn-shared` — types shared across the GUI, client service, and server.
//!
//! This crate is intentionally dependency-light and platform-agnostic so it can
//! be compiled for the Windows client, the Linux server, and the Tauri GUI
//! without pulling in OS-specific code.

#![forbid(unsafe_code)]

pub mod config;
pub mod error;

pub use error::{Result, VpnError};
