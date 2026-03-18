#!/bin/bash
set -euo pipefail

STATE_DIR="/data/state"
SECURE_DIR="/data/secure"
CONFIG_DIR="/data/config"

# Auto-initialize PKI on first start
if [ ! -f "$STATE_DIR/ca.crt" ]; then
    echo "==> First start detected, initializing PKI..."
    cli-box-server init --state-dir "$STATE_DIR"
    echo ""
fi

# Build server args
args=(
    -listen :443
    -state-dir "$STATE_DIR"
    -secure-dir "$SECURE_DIR"
)

# Use config file if provided
if [ -f "$CONFIG_DIR/config.toml" ]; then
    args+=(-config "$CONFIG_DIR/config.toml")
fi

exec cli-box-server "${args[@]}" "$@"
