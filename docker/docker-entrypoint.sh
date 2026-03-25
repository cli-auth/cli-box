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
    --policy-dir ./policies
)

exec box serve "${args[@]}" "$@"
