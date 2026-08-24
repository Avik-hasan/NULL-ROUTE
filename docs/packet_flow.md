# Packet Flow Architecture

This document tracks the journey of an outbound IPv4 packet from a Windows user application to the internet, and the return path back.

## Outbound Flow

1. **Application Generation**: A browser creates a TCP packet destined for `8.8.8.8:443`.
2. **WFP & Routing**: 
   - Windows checks the routing table. Due to our `0.0.0.0/1` LPM override, the packet is routed to the `wintun` interface (e.g. `10.66.0.100`).
   - The WFP Kill-Switch evaluates the packet. Since the packet is on the VPN interface, the rule passes.
3. **Data Pump (vpn-client)**:
   - The `vpn-client` daemon reads the raw IP packet from the Wintun adapter.
   - The packet is passed to the active cryptographic `Session`.
   - `vpn-core` checks the TCP headers. If it's a TCP SYN packet, the MSS clamping logic rewrites the MSS option to prevent fragmentation over the UDP tunnel.
   - The IP packet is authenticated and encrypted using ChaCha20-Poly1305.
4. **Transport**: The encrypted payload is wrapped in a UDP datagram and sent over the physical internet via the bound local UDP socket to the `vpn-server` port.

## Inbound Flow (Server Processing)

1. **Listener (vpn-server)**: The Linux server receives the UDP datagram.
2. **Authentication**: The server looks up the client's `Session` via the `PeerTable` using the UDP source address.
3. **Decryption**: The packet is decrypted. The anti-replay counter is checked and updated.
4. **Kernel Injection**: The decrypted plain IP packet is written to `/dev/net/tun`.
5. **SNAT Routing**: The Linux kernel receives the packet. `iptables` / `nftables` performs Source NAT (SNAT/MASQUERADE), rewriting the source IP from `10.66.0.100` to the server's public IP (`eth0`). The packet is routed to the public internet.
