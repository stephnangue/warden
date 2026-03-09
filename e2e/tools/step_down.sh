#!/usr/bin/env bash
# Force the leader to step down.
# Usage: step_down.sh [port]

PORT="${1:-8500}"
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TOKEN=$(cat "$SCRIPT_DIR/.root_token" 2>/dev/null || echo "")

if [ -z "$TOKEN" ]; then
  echo "ERROR: No root token found at $SCRIPT_DIR/.root_token"
  exit 1
fi

HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
  -X PUT "https://127.0.0.1:${PORT}/v1/sys/step-down" \
  -H "X-Warden-Token: $TOKEN")
echo "Step-down on port $PORT: HTTP $HTTP_CODE"
