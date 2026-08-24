<#
.SYNOPSIS
Builds the entire Windows VPN Client ecosystem including the Rust system service and Tauri GUI.

.DESCRIPTION
This script checks for dependencies (Rust, Node.js), compiles the `vpn-client` daemon in release mode,
compiles the `custom-vpn-gui` frontend, and places the resulting binaries in the `release/` staging folder.
#>

$ErrorActionPreference = "Stop"

Write-Host "Starting NULL-ROUTE Windows Build..." -ForegroundColor Cyan

# 1. Check prerequisites
if (-not (Get-Command "cargo" -ErrorAction SilentlyContinue)) {
    throw "Cargo (Rust) is not installed or not in PATH."
}
if (-not (Get-Command "npm" -ErrorAction SilentlyContinue)) {
    throw "npm (Node.js) is not installed or not in PATH."
}

# 2. Build the System Daemon (vpn-client)
Write-Host "Building vpn-client (Release)..." -ForegroundColor Yellow
cargo build -p vpn-client --release

# 3. Build the GUI (Tauri)
Write-Host "Building custom-vpn-gui (Release)..." -ForegroundColor Yellow
Set-Location -Path "gui"
npm install
npm run tauri build
Set-Location -Path ".."

# 4. Stage Binaries
$StagingDir = "target/staging"
if (-not (Test-Path $StagingDir)) {
    New-Item -ItemType Directory -Path $StagingDir | Out-Null
}

Copy-Item -Path "target/release/vpn-client.exe" -Destination $StagingDir -Force
Copy-Item -Path "gui/src-tauri/target/release/custom-vpn-gui.exe" -Destination $StagingDir -Force

Write-Host "Build complete! Artifacts are in target/staging/" -ForegroundColor Green
