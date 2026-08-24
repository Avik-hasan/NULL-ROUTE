#!/usr/bin/env bash
set -euo pipefail

echo "Deploying NULL-ROUTE vpn-server daemon..."

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (or use sudo)."
  exit 1
fi

# Build the release binary
cargo build -p vpn-server --release

# Stop existing service if any
systemctl stop custom-vpn || true

# Copy binary
cp target/release/vpn-server /usr/local/bin/vpn-server
chmod +x /usr/local/bin/vpn-server

# Copy service file
cp scripts/custom-vpn.service /etc/systemd/system/
systemctl daemon-reload

# Apply NAT setup
bash scripts/server-setup.sh

# Restart and enable
systemctl enable custom-vpn
systemctl start custom-vpn

echo "Deployment successful! Check status with: systemctl status custom-vpn"
