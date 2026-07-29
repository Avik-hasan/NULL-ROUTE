# Windows IP Helper Routing

NULL-ROUTE manages system routing tables through the modern Windows IP Helper API (Iphlpapi) rather than shelling out to `route.exe`. This guarantees deterministic execution and allows us to read exact LUIDs and metric variables dynamically.

## Default Gateway Override
When a tunnel is established, the engine does *not* delete the physical network interface's default route (`0.0.0.0/0`).
Instead, it inserts two split routes:
- `0.0.0.0/1`
- `128.0.0.0/1`

Because these routes have a `\1` CIDR mask, they are technically more specific than the physical `0.0.0.0/0` route. The Windows TCP/IP stack will prefer the VPN tunnel adapter for all general internet traffic automatically via standard Longest Prefix Match (LPM) logic.

## Tunnel Exemption
To prevent the encrypted payload datagrams from looping back into the tunnel interface, a highly-specific `/32` route is injected targeting the remote VPN server IP, pointing out via the physical interface's default gateway.

## Lifecycle Management
All routing structures are managed within the `RouteSnapshot` struct. The struct implements a Capture and Restore pattern. Upon process panic, the `CleanupRegistry` instantly drops the injected `/1` routes and the `/32` bypass, returning the routing table to its exact pre-connection state.
