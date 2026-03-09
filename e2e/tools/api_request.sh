#!/usr/bin/env bash
# Make an authenticated API request to a Warden node.
# Usage: api_request.sh <method> <path> [port] [body]
#
# Examples:
#   api_request.sh GET sys/health 8500
#   api_request.sh GET sys/leader 8510
#   api_request.sh PUT sys/step-down 8500
#   api_request.sh POST sys/providers/test-vault 8500 '{"type":"vault"}'

METHOD="${1:?Usage: api_request.sh <method> <path> [port] [body]}"
PATH_="${2:?Usage: api_request.sh <method> <path> [port] [body]}"
PORT="${3:-8500}"
BODY="${4:-}"
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TOKEN=$(cat "$SCRIPT_DIR/.root_token" 2>/dev/null || echo "")

ARGS=(-sk -X "$METHOD" "https://127.0.0.1:${PORT}/v1/${PATH_}" -w "\nHTTP_STATUS:%{http_code}\n")
if [ -n "$TOKEN" ]; then
  ARGS+=(-H "X-Warden-Token: $TOKEN")
fi
if [ -n "$BODY" ]; then
  ARGS+=(-H "Content-Type: application/json" -d "$BODY")
fi

curl "${ARGS[@]}" 2>/dev/null
