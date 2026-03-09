#!/usr/bin/env bash
# Make a non-transparent mode request through the Warden Vault gateway.
# Authenticates with X-Warden-Token (obtained via JWT login with e2e-nt-reader role),
# Warden mints a Vault token, proxies to Vault.
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

# Obtain a Warden token via JWT login with the e2e-nt-reader role.
# The root token does NOT have a credential spec and cannot be used for gateway requests.
JWT=$(bash "$SCRIPT_DIR/tools/get_jwt.sh" 2>/dev/null || echo "")
if [ -n "$JWT" ]; then
  LOGIN=$(curl -sk -X POST "https://127.0.0.1:${PORT}/v1/auth/jwt/login" \
    -H "Content-Type: application/json" \
    -d "{\"jwt\":\"$JWT\",\"role\":\"e2e-nt-reader\"}" 2>/dev/null)
  TOKEN=$(echo "$LOGIN" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['data']['token'])" 2>/dev/null || echo "")
fi
if [ -z "$TOKEN" ]; then
  echo "ERROR: Could not obtain Warden token for non-transparent gateway" >&2
  exit 1
fi

# Build gateway URL: /v1/vault-nt/gateway/v1/<vault_path> (non-transparent mount)
URL="https://127.0.0.1:${PORT}/v1/vault-nt/gateway/v1/${VAULT_PATH}"

ARGS=(-sk -X "$METHOD" "$URL" -w "\nHTTP_STATUS:%{http_code}\n")
ARGS+=(-H "X-Warden-Token: $TOKEN")
if [ -n "$BODY" ]; then
  ARGS+=(-H "Content-Type: application/json" -d "$BODY")
fi

curl "${ARGS[@]}" 2>/dev/null
