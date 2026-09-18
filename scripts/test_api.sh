#!/usr/bin/env bash
set -euo pipefail

echo "Testing Auth Endpoint (Valid Token)..."
curl -s -X POST http://127.0.0.1:8080/api/v1/auth \
  -H "Content-Type: application/json" \
  -d '{"token": "mock-token-123"}' | jq .

echo ""
echo "Testing Nodes Endpoint..."
curl -s http://127.0.0.1:8080/api/v1/nodes | jq .
