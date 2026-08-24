# Cryptography Deep Dive

The NULL-ROUTE protocol provides state-of-the-art encryption with perfect forward secrecy (PFS) and identity hiding.

## Protocol Core: Noise_IKpsk2

We implement the `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s` protocol pattern.

### Why IK?
The `IK` pattern allows the client to send encrypted payloads immediately in the very first handshake packet (Zero-RTT data), while providing identity hiding for the server. Both parties authenticate each other via pre-exchanged static keys.

### Why psk2?
We append a Pre-Shared Key (PSK) to the end of the handshake (`psk2`). This provides Post-Quantum Resistance (PQR). Even if a future quantum computer breaks Curve25519, the traffic cannot be decrypted without the symmetric PSK, which is quantum-safe.

## Zeroization and Memory Security

Key material is the most sensitive data in a VPN. 
All types representing private keys in `vpn-core` wrap their inner arrays in `zeroize::ZeroizeOnDrop`. 

When a session expires, a handover finishes, or the application crashes, the memory containing the keys is proactively overwritten with zeros before the OS reclaims the page, preventing cold-boot attacks and mitigating memory-dump vulnerabilities.

## Anti-Replay Mechanism

A sliding window bitmap (64-bits wide) is maintained by the receiver. 
When a packet arrives:
1. The AEAD tag is verified.
2. The packet's nonce is checked against the sliding window.
3. If the nonce is older than the window or the bit is already set, the packet is instantly dropped.
4. Otherwise, the window slides forward and the bit is recorded.
