# vpn-client (Windows)

This is the highly privileged local system daemon for NULL-ROUTE on Windows.

## Architecture
The client is architected to run as a Windows Service (`NT AUTHORITY\SYSTEM`).
It coordinates the following OS APIs:
- **Wintun**: Virtual network adapter injection.
- **Windows Filtering Platform (WFP)**: High-weight block and permit rules for the Kill-Switch.
- **IP Helper (Iphlpapi)**: Dynamically injects `0.0.0.0/1` and `/32` bypass routes.
- **Netsh**: Modifies physical adapter DNS to block leaks.
- **Win32 Named Pipes**: Multiplexes JSON IPC frames over a pipe secured by an explicit DACL.

## Fail Safety
The `recovery::CleanupRegistry` guarantees that the system's routing, firewall, and DNS state is fully restored on shutdown or panic.
