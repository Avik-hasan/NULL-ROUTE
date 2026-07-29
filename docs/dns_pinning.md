# DNS Pinning and Leak Protection

To ensure absolute privacy, the `vpn-client` must prevent the Windows DNS Client (Dnscache) from resolving queries through the ISP's physical adapter, which would result in DNS leaks.

## Mechanism

NULL-ROUTE forces all DNS queries into the VPN tunnel by aggressively pinning the physical adapter's DNS servers.

1. **Snapshot**: Upon connection, `DnsSnapshot::capture` reads the physical interface's current primary and secondary DNS server IPs from the Windows Registry or via WMI.
2. **Override**: The engine executes `netsh interface ipv4 set dnsservers` on the physical interface, forcibly overriding the ISP's DNS with the VPN's internal synthetic DNS IPs (e.g. `10.66.0.1` and `10.66.0.2`).
3. **Redirection**: Because the default gateway has already been overridden via the `routing_engine`, all outbound UDP port 53 packets destined for these internal IPs are seamlessly swallowed by the `wintun` interface and transported securely to the `vpn-server`.
4. **Restoration**: During a graceful disconnect or a process panic (via `CleanupRegistry`), `DnsSnapshot::restore` executes `netsh` once more to place the original ISP DNS servers back onto the adapter.
