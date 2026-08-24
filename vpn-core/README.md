# vpn-core

This crate is the heart of the NULL-ROUTE project. 

It is completely `no_std` compatible (with an allocator) and contains absolutely no OS-specific code (no Windows APIs, no Linux ioctls, no sockets, no routing). It is a pure data-transformation engine.

## Features
- **Cryptography**: `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`. Powered by `x25519-dalek` and `chacha20poly1305`.
- **Packet Formatting**: Handles binary serialization of Handshake, Keepalive, Data, and Handover packets.
- **Anti-Replay**: 64-bit sliding window implementation.
- **MSS Clamping**: Inspects raw IPv4 packets to adjust the TCP Maximum Segment Size, preventing IP fragmentation inside the tunnel.

## Security
Every type in this crate that handles a secret (Private Keys, Symmetric Keys, Handshake States) correctly utilizes the `zeroize` crate to scrub heap memory on drop.
