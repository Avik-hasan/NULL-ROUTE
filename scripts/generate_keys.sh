#!/usr/bin/env bash
set -euo pipefail

echo "Generating cryptographic keys for NULL-ROUTE..."

# Ensure we are in the workspace root
cargo build -p keygen --release

echo ""
echo "=== Server Static Keypair ==="
target/release/keygen

echo ""
echo "=== Client Static Keypair ==="
target/release/keygen

echo ""
echo "=== Pre-Shared Key (PSK) ==="
target/release/keygen
echo ""

echo "Copy the corresponding public/private keys into server.json and client_config.json."
