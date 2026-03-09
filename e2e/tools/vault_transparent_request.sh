#!/usr/bin/env bash
# Make a transparent mode request through the Warden Vault gateway.
# Authenticates with a JWT (Authorization: Bearer), Warden performs implicit
# auth, mints a Vault token, and proxies to Vault.
#
# Usage: vault_transparent_request.sh <method> <vault_path> [role] [port] [body]
#
# The JWT is fetched from Hydra automatically (or pass JWT= env var).
#
# Examples:
#   vault_transparent_request.sh GET secret/data/e2e/app-config
#   vault_transparent_request.sh GET secret/data/e2e/app-config e2e-reader 8510
#   vault_transparent_request.sh POST secret/data/e2e/new 8500 '{"data":{"key":"val"}}'
#   JWT=$(bash e2e/tools/get_jwt.sh) vault_transparent_request.sh GET secret/data/e2e/app-config

METHOD="${1:?Usage: vault_transparent_request.sh <method> <vault_path> [role] [port] [body]}"
VAULT_PATH="${2:?Usage: vault_transparent_request.sh <method> <vault_path> [role] [port] [body]}"
ROLE="${3:-e2e-reader}"
PORT="${4:-8500}"
BODY="${5:-}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Get JWT from Hydra if not provided via environment
if [ -z "$JWT" ]; then
  JWT=$(bash "$SCRIPT_DIR/get_jwt.sh" 2>/dev/null)
  if [ -z "$JWT" ]; then
    echo "ERROR: Failed to get JWT from Hydra" >&2
    exit 1
  fi
fi

# Build transparent gateway URL: /v1/vault/role/<role>/gateway/v1/<vault_path>
URL="https://127.0.0.1:${PORT}/v1/vault/role/${ROLE}/gateway/v1/${VAULT_PATH}"

ARGS=(-sk -X "$METHOD" "$URL" -w "\nHTTP_STATUS:%{http_code}\n")
ARGS+=(-H "Authorization: Bearer $JWT")
if [ -n "$BODY" ]; then
  ARGS+=(-H "Content-Type: application/json" -d "$BODY")
fi

curl "${ARGS[@]}" 2>/dev/null
