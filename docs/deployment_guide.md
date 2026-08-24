# Deployment Guide

This guide covers deploying the NULL-ROUTE ecosystem to production.

## Server Deployment (Linux)

The `vpn-server` daemon is designed for Ubuntu 22.04 LTS or 24.04 LTS.

1. **Clone and Build**:
   ```bash
   git clone https://github.com/Avik-hasan/NULL-ROUTE.git
   cd NULL-ROUTE
   sudo bash scripts/deploy_server.sh
   ```

2. **Configuration**:
   Edit `/etc/custom-vpn/server.json`:
   ```json
   {
       "listen": "0.0.0.0:51820",
       "server_private_key": "<base64_private_key>",
       "preshared_key": "<base64_psk>",
       "tunnel_subnet": "10.66.0.0/24",
       "exit_interfaces": ["eth0", "eth1"]
   }
   ```

3. **Restart**: `sudo systemctl restart custom-vpn`

## Client Deployment (Windows)

The client requires Windows 10/11.

1. **Build**:
   Run `scripts/build_windows.ps1` from a developer prompt.
2. **Install Service**:
   Run a privileged command prompt:
   ```cmd
   sc create "NULL-ROUTE" binPath= "C:\Program Files\NULL-ROUTE\vpn-client.exe" start= auto
   sc start "NULL-ROUTE"
   ```
3. **Run GUI**:
   Launch `custom-vpn-gui.exe` as a standard user.
