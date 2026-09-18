# vpn-api

A mock REST API backend for NULL-ROUTE built with `axum`.

## Purpose
This crate simulates a central authentication and node-distribution server. In a production environment, the client needs to know:
1. Whether the user's subscription is active.
2. The dynamic IPs and public keys of the available VPN exit nodes.

This server provides the following endpoints:
- `POST /api/v1/auth`: Validates a token and returns user subscription status.
- `GET /api/v1/nodes`: Returns a list of active `vpn-server` instances globally.

## Architecture
- **Web Framework**: `axum` (async-first, built on `hyper`).
- **State**: `tokio::sync::RwLock` backed thread-safe memory state.
- **Serialization**: `serde_json` mapping models.
