#!/bin/bash
set -euo pipefail

# Auto-initialize PKI on first start
if [ ! -f "./state/ca.crt" ]; then
    echo "==> First start detected, initializing PKI..."
    cli-box-server init
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
