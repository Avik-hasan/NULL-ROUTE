# IPC Threat Model and DACL Architecture

The NULL-ROUTE Windows Client (`vpn-client`) orchestrates privileged system state changes (Routing, DNS, WFP Filters). To allow the unprivileged GUI to control it, a local IPC channel is established over Windows Named Pipes.

## Named Pipe Vulnerabilities
Standard named pipes in Windows are extremely vulnerable to malicious local processes. If an unprivileged process can write to the pipe, it could command the `vpn-client` to execute arbitrary tasks, escalating privileges or tearing down security boundaries.

## The Discretionary Access Control List (DACL)
To guarantee security, `vpn-client` applies a strict Security Descriptor (SD) when instantiating the Named Pipe Server (`\\.\pipe\custom-vpn`).

The DACL is dynamically constructed to allow EXACTLY two entities to access the pipe:
1. `NT AUTHORITY\SYSTEM` (The local system administrator and the service itself)
2. `The Interactive Console User` (Discovered dynamically via `WTSQueryUserToken`)

By explicitly mapping these SIDs and rejecting all others (there is no `Everyone` ACE), the named pipe becomes mathematically invisible and inaccessible to background services, other unprivileged users, or untrusted sandboxed applications.

## Message Framing
Once access is granted, the IPC pipe communicates via length-delimited JSON frames. The daemon uses `tokio::select!` to safely multiplex `IpcCommand` frames alongside asynchronous log streaming without introducing lock contention on the pipe.
