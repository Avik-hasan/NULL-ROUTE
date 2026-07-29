# WFP Firewall Engine

The Windows Filtering Platform (WFP) is used by `vpn-client` to enforce absolute network containment and implement the VPN Kill-Switch.

## Dynamic Sessions
Unlike traditional VPNs that permanently write firewall rules to the system (which can conflict with other AV software or persist after a crash), NULL-ROUTE uses **Dynamic WFP Sessions**.
When the WFP Engine handle is closed (gracefully or via process death), the Windows kernel automatically drops all associated filters. This guarantees that a crashed VPN client will never leave the user permanently disconnected from the internet.

## WebRTC Leak Protection
A major vector for real-IP leakage is WebRTC STUN/TURN UDP requests. The WFP engine actively blackholes all outbound UDP traffic destined for ports `3478` and `5349` across all network interfaces, completely immunizing the user against WebRTC leaks.

## Kill-Switch Logic
When the kill-switch is engaged, the engine deploys a `FWPM_LAYER_ALE_AUTH_CONNECT_V4` block filter with a high weight. A single permit filter is then dynamically inserted to allow traffic *only* to the current VPN exit node IP address on the designated UDP port. All other non-tunnel outbound IPv4 traffic is silently dropped.
