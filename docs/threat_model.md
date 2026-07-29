# Security and Threat Model

This document outlines the threat model for the NULL-ROUTE VPN ecosystem, specifically addressing Local Privilege Escalation (LPE) vectors, cryptographic boundaries, and denial-of-service (DoS) mitigations.

## 1. Local Privilege Escalation (LPE)

### 1.1 The IPC Boundary
The `vpn-client` runs as a high-privileged Windows Service (`NT AUTHORITY\SYSTEM`). The GUI runs as an unprivileged standard user in the interactive session.
* **Risk**: A malicious local process running as a standard user or lower integrity level could connect to the IPC channel and command the service to execute arbitrary actions or reconfigure network state destructively.
* **Mitigation**: The IPC channel is a Windows Named Pipe protected by a strict, dynamically generated Discretionary Access Control List (DACL). The DACL explicitly grants `GENERIC_READ | GENERIC_WRITE` *only* to `SYSTEM` and the SID of the interactive console session user (`WTSQueryUserToken`). There is no `Everyone` or `Authenticated Users` ACE.

### 1.2 State Rollback (Fail-Safety)
* **Risk**: If the `vpn-client` service panics or is forcefully terminated, the system may be left with a blackholed default gateway or a poisoned DNS cache, causing a complete denial of internet service for the user.
* **Mitigation**: All persistent OS state mutations (IP Helper routing modifications, Netsh DNS pinning) are tracked in a `CleanupRegistry` struct. A custom Panic Hook and Ctrl-C signal handler guarantee that a LIFO-ordered cleanup routine is executed before the process exits, instantly restoring the system's previous network configuration.

## 2. Cryptographic Security

### 2.1 Key Management
* **Risk**: Secret keys left in heap memory could be extracted via crash dumps or page-file analysis.
* **Mitigation**: All cryptographic private keys and pre-shared keys are encapsulated in a `SecretKey` wrapper that strictly implements `zeroize::ZeroizeOnDrop`. Memory is scrubbed the instant the key goes out of scope.

### 2.2 Replay Attacks
* **Risk**: An attacker captures a valid VPN data packet and replays it to the server to trigger unauthorized actions or exhaust bandwidth.
* **Mitigation**: `vpn-core` implements a strict sliding-window anti-replay filter using a 64-bit bitmap and counter. Duplicate nonces within the same cryptographic session are mathematically rejected.

## 3. Pre-Authentication DoS
* **Risk**: An attacker floods the `vpn-server` with spoofed UDP datagrams, forcing it to perform expensive Curve25519 asymmetric cryptography (Noise Handshakes) and exhausting CPU resources.
* **Mitigation**: The `listener.rs` module applies an aggressive rate-limit (`allow_handshake`) bound to the source IP. Additionally, in-flight handshakes are strictly bounded by a tokio `Semaphore`. Excess requests during saturation are silently dropped.
