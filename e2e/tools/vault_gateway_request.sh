#!/usr/bin/env bash
# Make a request through the Warden Vault gateway using transparent mode.
# Authenticates with a JWT via Authorization: Bearer header.
#
# Usage: vault_gateway_request.sh <method> <vault_path> [port] [body]
#
# Examples:
#   vault_gateway_request.sh GET secret/data/e2e/app-config
#   vault_gateway_request.sh GET secret/data/e2e/app-config 8510
#   vault_gateway_request.sh POST secret/data/e2e/new-secret 8500 '{"data":{"key":"value"}}'
#   vault_gateway_request.sh GET sys/health

METHOD="${1:?Usage: vault_gateway_request.sh <method> <vault_path> [port] [body]}"
VAULT_PATH="${2:?Usage: vault_gateway_request.sh <method> <vault_path> [port] [body]}"
PORT="${3:-8500}"
BODY="${4:-}"
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# Obtain a JWT for transparent mode authentication.
JWT=$(bash "$SCRIPT_DIR/tools/get_jwt.sh" 2>/dev/null || echo "")
if [ -z "$JWT" ]; then
  echo "ERROR: Could not obtain JWT from Hydra" >&2
  exit 1
fi

# Build gateway URL: /v1/vault/role/e2e-reader/gateway/v1/<vault_path>
URL="https://127.0.0.1:${PORT}/v1/vault/role/e2e-reader/gateway/v1/${VAULT_PATH}"

ARGS=(-sk -X "$METHOD" "$URL" -w "\nHTTP_STATUS:%{http_code}\n")
ARGS+=(-H "Authorization: Bearer $JWT")
if [ -n "$BODY" ]; then
  ARGS+=(-H "Content-Type: application/json" -d "$BODY")
fi

curl "${ARGS[@]}" 2>/dev/null
