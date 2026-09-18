#!/usr/bin/env bash
set -euo pipefail

echo "Starting NULL-ROUTE Mock Backend API Server..."

# Build the release binary
cargo build -p vpn-api --release

echo "Server starting on http://127.0.0.1:8080"
echo "Press Ctrl+C to stop."

RUST_LOG=info target/release/vpn-api
