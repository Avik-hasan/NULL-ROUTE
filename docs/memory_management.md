# Memory Management and Safety

NULL-ROUTE is written in Rust to eliminate the vast majority of memory safety vulnerabilities (buffer overflows, use-after-free, double-free) that plague legacy C-based VPN clients.

## Zeroization
We utilize the `zeroize` crate to strictly enforce cryptographic hygiene.
- Private keys (`SecretKey`) implement `ZeroizeOnDrop`. 
- When an object goes out of scope (due to an error, return, or panic), the memory is synchronously zeroed out before being returned to the allocator.

## ArcSwap and Lock-Free Data Planes
Traditional VPNs use `Mutex` or `RwLock` to protect the active encryption session. This causes extreme lock contention on multi-gigabit connections, dropping packets while waiting for a lock.
NULL-ROUTE uses `ArcSwap` for the active `Session` and `RemoteAddress`. The UDP receiver can load the session entirely lock-free, decrypt the packet, and forward it. When a handover occurs, the pointer is swapped atomically.

## Async Worker Pools
The Linux server leverages tokio's `AsyncFd` for the `/dev/net/tun` interface. This allows us to use a multi-threaded work-stealing runtime without dedicating an entire OS thread to blocking I/O calls, keeping memory overhead to just a few megabytes per 10,000 active clients.
