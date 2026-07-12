//! Tauri v2 shell. Bridges the cyberpunk web UI to the elevated `vpn-client`
//! service over the ACL-secured named pipe.
//!
//! Commands exposed to JS:
//!   * `engage(node_index)`  -> connect
//!   * `disengage()`         -> disconnect
//!   * `rotate_now()`        -> force seamless handover
//!   * `get_status()`        -> telemetry snapshot
//!
//! The IPC client is Windows-only; on other platforms the commands return a
//! simulated telemetry stream so the UI can be developed/previewed anywhere.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod pipe_client;

use serde::Serialize;
use vpn_shared::telemetry::Telemetry;

#[derive(Serialize)]
struct CmdResult {
    ok: bool,
    message: String,
}

#[tauri::command]
async fn engage(node_index: usize) -> Result<CmdResult, String> {
    pipe_client::connect(node_index)
        .await
        .map(|_| CmdResult { ok: true, message: "ENGAGED".into() })
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn disengage() -> Result<CmdResult, String> {
    pipe_client::disconnect()
        .await
        .map(|_| CmdResult { ok: true, message: "DISENGAGED".into() })
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn terminate_service() -> Result<CmdResult, String> {
    pipe_client::terminate()
        .await
        .map(|_| CmdResult { ok: true, message: "TERMINATED".into() })
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn rotate_now() -> Result<CmdResult, String> {
    pipe_client::rotate()
        .await
        .map(|_| CmdResult { ok: true, message: "ROTATING".into() })
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_status() -> Result<Telemetry, String> {
    pipe_client::status().await.map_err(|e| e.to_string())
}

#[tauri::command]
fn minimize_window(window: tauri::Window) {
    let _ = window.minimize();
}

#[tauri::command]
fn maximize_window(window: tauri::Window) {
    if let Ok(maximized) = window.is_maximized() {
        if maximized {
            let _ = window.unmaximize();
        } else {
            let _ = window.maximize();
        }
    }
}

#[tauri::command]
fn close_window(window: tauri::Window) {
    let _ = window.close();
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .invoke_handler(tauri::generate_handler![
            engage,
            disengage,
            terminate_service,
            rotate_now,
            get_status,
            minimize_window,
            maximize_window,
            close_window
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
