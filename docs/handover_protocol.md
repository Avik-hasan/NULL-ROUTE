# Seamless Handover Protocol

The NULL-ROUTE Seamless Handover Protocol allows a client to migrate from one VPN exit node to another with absolutely **zero packet loss** and **no connection drops** for established TCP streams.

## Motivation

Traditional VPNs tear down the `tun` interface or flush the routing table during a server switch, resulting in dropped packets, broken TCP sessions, and visible interruptions to the end user (e.g. video buffer stalls, SSH disconnects).

NULL-ROUTE avoids this by treating the VPN tunnel as a persistent local subnet, while migrating the *underlying* encrypted transport and exit-IP behind the scenes.

## Flow Diagram

1. **Client Trigger**: The `vpn-client` hopper timer expires (`hop_interval_secs`).
2. **Pre-authentication**: The client initiates a `Noise_IKpsk2` handshake with the *next* exit node in the configuration array, *while still sending all data-plane traffic to the current node*.
3. **Session Swap**: Once the handshake completes, the client possesses a new encryption session (`ArcSwap` pointer).
4. **Data Plane Cutover**: The client atomically swaps the session pointer. The very next packet read from the local `tun` interface is encrypted with the *new* session and sent to the *new* server's IP address.
5. **Server Side Handling**: The new server recognizes the handshake and dynamically allocates the client's internal Tunnel IP. NAT state for the new TCP flow begins immediately on the new exit node.
6. **Graceful Degradation**: If the handshake to the new node fails, the client simply aborts the handover and continues communicating with the original node. No downtime is experienced.

## Security Constraints

Because each hop negotiates a fresh ephemeral keypair (via Noise IK), the cryptographic Nonce space is entirely refreshed. Anti-replay counters are reset to `1` safely without risk of nonce reuse, because the underlying AEAD key has completely changed.
