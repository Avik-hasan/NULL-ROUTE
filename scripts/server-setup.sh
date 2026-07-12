#!/usr/bin/env bash
# Custom VPN server bootstrap: TUN, IP forwarding, and NAT.
# Run as root on the Linux VPS. Idempotent.
set -euo pipefail

TUN_DEV="${TUN_DEV:-cvpn0}"
TUN_ADDR="${TUN_ADDR:-10.66.0.1/24}"
EXIT_IFACES=("${@:-eth0}")   # pass one or more exit interfaces as args

echo "[*] Enabling IPv4 forwarding"
sysctl -w net.ipv4.ip_forward=1
grep -q '^net.ipv4.ip_forward=1' /etc/sysctl.conf || echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf

# Reverse-path filtering off so multi-exit (IP hopping) return paths work.
sysctl -w net.ipv4.conf.all.rp_filter=2

echo "[*] Creating TUN device ${TUN_DEV}"
if ! ip link show "${TUN_DEV}" >/dev/null 2>&1; then
  ip tuntap add dev "${TUN_DEV}" mode tun
fi
ip addr replace "${TUN_ADDR}" dev "${TUN_DEV}"
ip link set "${TUN_DEV}" up

echo "[*] Installing NAT (MASQUERADE) on: ${EXIT_IFACES[*]}"
for IFACE in "${EXIT_IFACES[@]}"; do
  iptables -t nat -C POSTROUTING -o "${IFACE}" -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -o "${IFACE}" -j MASQUERADE
done

# Allow forwarding to/from the tunnel.
iptables -C FORWARD -i "${TUN_DEV}" -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "${TUN_DEV}" -j ACCEPT
iptables -C FORWARD -o "${TUN_DEV}" -j ACCEPT 2>/dev/null || iptables -A FORWARD -o "${TUN_DEV}" -j ACCEPT

echo "[+] Server network prepared. Start the daemon:"
echo "    ./vpn-server /etc/custom-vpn/server.json"
