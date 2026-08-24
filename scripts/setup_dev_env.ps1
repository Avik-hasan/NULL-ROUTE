<#
.SYNOPSIS
Sets up the development environment for NULL-ROUTE on Windows.

.DESCRIPTION
Installs Rust components, checks for Node.js, and downloads the Wintun driver
required for local testing and debugging of the vpn-client.
#>

$ErrorActionPreference = "Stop"

Write-Host "Setting up NULL-ROUTE Dev Environment..." -ForegroundColor Cyan

# 1. Update Rust Toolchain
Write-Host "Updating Rust toolchain..." -ForegroundColor Yellow
rustup update stable
rustup component add clippy rustfmt

# 2. Check Node
if (-not (Get-Command "npm" -ErrorAction SilentlyContinue)) {
    Write-Host "WARNING: Node.js (npm) is not installed. You will not be able to build the Tauri GUI." -ForegroundColor Red
} else {
    Write-Host "Node.js found." -ForegroundColor Green
}

# 3. Download Wintun
$WintunUrl = "https://www.wintun.net/builds/wintun-0.14.1.zip"
$ZipPath = "$env:TEMP\wintun.zip"
$ExtractPath = "$env:TEMP\wintun_extract"
$TargetDll = "vpn-client\wintun.dll"

if (-not (Test-Path $TargetDll)) {
    Write-Host "Downloading Wintun driver..." -ForegroundColor Yellow
    Invoke-WebRequest -Uri $WintunUrl -OutFile $ZipPath
    Expand-Archive -Path $ZipPath -DestinationPath $ExtractPath -Force
    
    # Copy amd64 dll to client root
    Copy-Item -Path "$ExtractPath\wintun\bin\amd64\wintun.dll" -Destination $TargetDll -Force
    
    Remove-Item -Path $ZipPath -Force
    Remove-Item -Path $ExtractPath -Recurse -Force
    Write-Host "Wintun driver installed for local debugging." -ForegroundColor Green
} else {
    Write-Host "Wintun driver already exists." -ForegroundColor Green
}

Write-Host "Dev environment setup complete!" -ForegroundColor Cyan
