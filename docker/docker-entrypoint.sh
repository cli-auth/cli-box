#!/bin/bash
set -euo pipefail

# Auto-initialize PKI on first start
if [ ! -f "./state/client_ca.crt" ]; then
    echo "==> First start detected, initializing PKI..."
    box init
    echo ""
fi

# Build server args
args=(
    --listen :443
)

# Use config file if provided
if [ -f "./config.toml" ]; then
    args+=(-config "./config.toml")
fi

exec box serve "${args[@]}" "$@"
