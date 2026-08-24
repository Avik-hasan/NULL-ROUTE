# vpn-server (Linux)

This is the multi-threaded, asynchronous Linux exit daemon for NULL-ROUTE.

## Architecture
- **Async TUN**: Leverages tokio's `AsyncFd` for non-blocking I/O against `/dev/net/tun`.
- **Peer Management**: Uses `ArcSwap` and `parking_lot::RwLock` to manage active client sessions without locking up the UDP reader loop.
- **Pre-Auth DoS Mitigation**: Applies a strict per-IP handshake rate limit and global semaphore to protect against CPU exhaustion attacks.
- **Seamless Handover**: The server dynamically reallocates sessions to new incoming connections and performs NAT interface rotation (`HandoverEngine`) every 5 minutes to continuously shift the exit IP.
