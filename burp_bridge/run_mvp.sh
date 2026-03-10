#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p burp_bridge/out
export BURP_BRIDGE_HOST=${BURP_BRIDGE_HOST:-127.0.0.1}
export BURP_BRIDGE_PORT=${BURP_BRIDGE_PORT:-8765}
echo "🌸 Starting Burp Bridge on http://${BURP_BRIDGE_HOST}:${BURP_BRIDGE_PORT}"
python3 burp_bridge/collector.py
