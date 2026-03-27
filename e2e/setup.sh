#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PIDS_DIR="$SCRIPT_DIR/.pids"
LOGS_DIR="$SCRIPT_DIR/.logs"
BIN_DIR="$SCRIPT_DIR/.bin"

# Auto-detect docker compose CLI (v2 plugin vs v1 standalone)
if docker compose version &>/dev/null; then
  DOCKER_COMPOSE="docker compose"
elif command -v docker-compose &>/dev/null; then
  DOCKER_COMPOSE="docker-compose"
else
  echo "ERROR: Neither 'docker compose' nor 'docker-compose' found"
  exit 1
fi

# Vault dev server constants
VAULT_ADDR="http://127.0.0.1:8200"
VAULT_TOKEN="e2e-vault-root-token"
VAULT_APPROLE_ROLE_ID="e2e-approle-role-id-1234"
VAULT_APPROLE_SECRET_ID="e2e-approle-secret-id-5678"

# Hydra constants
HYDRA_PUBLIC="http://localhost:4444"
HYDRA_ADMIN="http://localhost:4445"

echo "=== Warden E2E Cluster Setup ==="
echo ""

# Step 0a: Generate TLS certificates for Warden API listeners (mTLS support)
WARDEN_CERT_DIR="$SCRIPT_DIR/.certs"
mkdir -p "$WARDEN_CERT_DIR"

if [ ! -f "$WARDEN_CERT_DIR/server.crt" ]; then
  echo "Generating Warden API server certificate..."
  openssl ecparam -genkey -name prime256v1 -noout -out "$WARDEN_CERT_DIR/server.key" 2>/dev/null
  openssl req -new -key "$WARDEN_CERT_DIR/server.key" -out "$WARDEN_CERT_DIR/server.csr" \
    -subj "/CN=warden-e2e/O=Warden E2E" 2>/dev/null
  openssl x509 -req -in "$WARDEN_CERT_DIR/server.csr" -signkey "$WARDEN_CERT_DIR/server.key" \
    -out "$WARDEN_CERT_DIR/server.crt" -days 365 \
    -extfile <(printf "subjectAltName=IP:127.0.0.1,DNS:localhost") 2>/dev/null
  rm -f "$WARDEN_CERT_DIR/server.csr"
fi

if [ ! -f "$WARDEN_CERT_DIR/client-ca.crt" ]; then
  echo "Generating mTLS client CA certificate..."
  openssl ecparam -genkey -name prime256v1 -noout -out "$WARDEN_CERT_DIR/client-ca.key" 2>/dev/null
  openssl req -x509 -new -key "$WARDEN_CERT_DIR/client-ca.key" -out "$WARDEN_CERT_DIR/client-ca.crt" \
    -days 365 -subj "/CN=E2E mTLS Client CA/O=Warden E2E" 2>/dev/null
fi

# Step 0b: Generate TLS certificates for nginx load balancer
NGINX_CERT_DIR="$SCRIPT_DIR/loadbalancer/certs"
mkdir -p "$NGINX_CERT_DIR"

if [ ! -f "$NGINX_CERT_DIR/ca.crt" ]; then
  echo "Generating LB CA certificate..."
  openssl ecparam -genkey -name prime256v1 -noout -out "$NGINX_CERT_DIR/ca.key" 2>/dev/null
  openssl req -x509 -new -key "$NGINX_CERT_DIR/ca.key" -out "$NGINX_CERT_DIR/ca.crt" \
    -days 365 -subj "/CN=E2E LB CA/O=Warden E2E" 2>/dev/null
fi

if [ ! -f "$NGINX_CERT_DIR/server.crt" ]; then
  echo "Generating nginx server certificate..."
  openssl ecparam -genkey -name prime256v1 -noout -out "$NGINX_CERT_DIR/server.key" 2>/dev/null
  openssl req -x509 -new -key "$NGINX_CERT_DIR/server.key" -out "$NGINX_CERT_DIR/server.crt" \
    -days 365 -subj "/CN=e2e-nginx-lb" 2>/dev/null
fi

# Step 1: Start infrastructure (PostgreSQL + Vault + Hydra + Nginx)
echo "[1/10] Starting infrastructure (PostgreSQL + Vault + Hydra + Nginx)..."
for pull_attempt in 1 2 3; do
  if $DOCKER_COMPOSE -f "$SCRIPT_DIR/docker-compose.yml" up -d 2>&1; then
    break
  fi
  if [ "$pull_attempt" -eq 3 ]; then
    echo "ERROR: docker compose up failed after 3 attempts"
    exit 1
  fi
  echo "  Retrying docker compose up (attempt $((pull_attempt + 1))/3)..."
  sleep 5
done

echo "Waiting for PostgreSQL to be ready..."
until docker exec e2e-postgres-warden pg_isready -U warden -q 2>/dev/null; do
  sleep 1
done
echo "PostgreSQL is ready."

echo "Waiting for Vault to be ready..."
for attempt in $(seq 1 30); do
  if curl -s "$VAULT_ADDR/v1/sys/health" >/dev/null 2>&1; then
    break
  fi
  if [ "$attempt" -eq 30 ]; then
    echo "  ERROR: Vault not ready after 30 attempts"
    exit 1
  fi
  sleep 1
done
echo "Vault is ready."

echo "Waiting for Hydra to be ready..."
for attempt in $(seq 1 60); do
  if curl -s "$HYDRA_ADMIN/health/ready" >/dev/null 2>&1; then
    break
  fi
  if [ "$attempt" -eq 60 ]; then
    echo "  ERROR: Hydra not ready after 60 attempts"
    exit 1
  fi
  sleep 2
done
echo "Hydra is ready."

echo "Waiting for Nginx LB to be ready..."
for attempt in $(seq 1 30); do
  if curl -sk "https://127.0.0.1:8000/nginx-health" >/dev/null 2>&1; then
    break
  fi
  if [ "$attempt" -eq 30 ]; then
    echo "  WARNING: Nginx LB not ready after 30 attempts (LB tests will skip)"
  fi
  sleep 1
done
if curl -sk "https://127.0.0.1:8000/nginx-health" >/dev/null 2>&1; then
  echo "Nginx LB is ready."
fi

# Step 2: Reset E2E tables (clean state)
echo ""
echo "[2/10] Resetting E2E tables..."
docker exec e2e-postgres-warden psql -U warden -d warden -c \
  "DROP TABLE IF EXISTS e2e_ha_locks; DROP TABLE IF EXISTS e2e_kv_store;" \
  2>/dev/null || true

# Step 3: Build Warden binary
echo ""
echo "[3/10] Building Warden..."
cd "$PROJECT_ROOT"
mkdir -p "$BIN_DIR"
go build -o "$BIN_DIR/warden" .
echo "Warden built at $BIN_DIR/warden"

# Generate seal key (32 bytes for AES-256-GCM-96) if it doesn't exist
if [ ! -f "$SCRIPT_DIR/configs/seal.key" ]; then
  echo "  Generating seal key..."
  openssl rand 32 > "$SCRIPT_DIR/configs/seal.key"
fi

# Step 4: Start 3 Warden nodes
echo ""
echo "[4/10] Starting 3 Warden nodes..."
mkdir -p "$PIDS_DIR" "$LOGS_DIR"

# Clean up any leftover PIDs
rm -f "$PIDS_DIR"/*.pid

cd "$SCRIPT_DIR/configs"
for i in 1 2 3; do
  echo "  Starting node $i..."
  "$BIN_DIR/warden" server --config="$SCRIPT_DIR/configs/node${i}.hcl" \
    > "$LOGS_DIR/node${i}.log" 2>&1 &
  echo $! > "$PIDS_DIR/node${i}.pid"
  echo "  Node $i started (PID: $(cat "$PIDS_DIR/node${i}.pid"))"
done

# Step 5: Initialize the cluster (only if not already initialized)
echo ""
echo "[5/10] Checking initialization status..."

export WARDEN_ADDR="https://127.0.0.1:8500"
export WARDEN_SKIP_VERIFY="true"

# Wait for at least one node to respond (not 000/unreachable)
echo "  Waiting for a node to become reachable..."
for attempt in $(seq 1 30); do
  HEALTH_CODE=$(curl -sk -o /dev/null -w "%{http_code}" "https://127.0.0.1:8500/v1/sys/health" 2>/dev/null || true)
  if [ -n "$HEALTH_CODE" ] && [ "$HEALTH_CODE" != "000" ]; then
    break
  fi
  if [ "$attempt" -eq 30 ]; then
    echo "  ERROR: No node reachable after 30 attempts. Check logs:"
    tail -20 "$LOGS_DIR/node1.log" 2>/dev/null || true
    exit 1
  fi
  sleep 1
done
echo "  Node reachable (health: $HEALTH_CODE)"

if [ "$HEALTH_CODE" = "501" ]; then
  echo "  Cluster not initialized. Running operator init..."
  INIT_OUTPUT=$("$BIN_DIR/warden" operator init --secret-shares=1 --secret-threshold=1 2>&1)
  echo "$INIT_OUTPUT"

  # Extract root token from init output
  ROOT_TOKEN=$(echo "$INIT_OUTPUT" | grep -A1 "Root Token:" | tail -1 | tr -d '[:space:]')
  if [ -z "$ROOT_TOKEN" ]; then
    echo "ERROR: Could not extract root token from init output"
    echo "Full output:"
    echo "$INIT_OUTPUT"
    exit 1
  fi

  echo "$ROOT_TOKEN" > "$SCRIPT_DIR/.root_token"
  echo "  Root token saved to $SCRIPT_DIR/.root_token"

  # Wait for auto-unseal and leader election after init
  echo "  Waiting for auto-unseal and leader election..."
  sleep 5
else
  echo "  Cluster already initialized (health: $HEALTH_CODE)."
  if [ ! -f "$SCRIPT_DIR/.root_token" ]; then
    echo "  WARNING: .root_token file not found. You may need to provide it manually."
  else
    echo "  Using existing root token from $SCRIPT_DIR/.root_token"
  fi
fi

# Step 6: Verify cluster health
echo ""
echo "[6/10] Verifying cluster health..."

HEALTHY=0
for attempt in $(seq 1 10); do
  LEADER_COUNT=0
  STANDBY_COUNT=0
  for port in 8500 8510 8520; do
    HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" "https://127.0.0.1:${port}/v1/sys/health" 2>/dev/null || echo "000")
    case "$HTTP_CODE" in
      200) LEADER_COUNT=$((LEADER_COUNT + 1)) ;;
      429) STANDBY_COUNT=$((STANDBY_COUNT + 1)) ;;
    esac
  done

  if [ "$LEADER_COUNT" -eq 1 ] && [ "$STANDBY_COUNT" -eq 2 ]; then
    HEALTHY=1
    break
  fi

  echo "  Waiting... (attempt $attempt/10, leaders=$LEADER_COUNT, standbys=$STANDBY_COUNT)"
  sleep 3
done

if [ "$HEALTHY" -ne 1 ]; then
  echo "=== CLUSTER FAILED TO START ==="
  echo ""
  echo "Node logs:"
  for i in 1 2 3; do
    echo "--- node $i (last 15 lines) ---"
    tail -15 "$LOGS_DIR/node${i}.log" 2>/dev/null || echo "  (no log)"
  done
  exit 1
fi

echo "  Cluster healthy (1 leader + 2 standbys)"

# Read root token for remaining setup steps
WARDEN_TOKEN=$(cat "$SCRIPT_DIR/.root_token" 2>/dev/null || echo "")
if [ -z "$WARDEN_TOKEN" ]; then
  echo "ERROR: No root token available for Vault/provider setup"
  exit 1
fi

# Helper: make authenticated Warden API request
warden_api() {
  local method="$1" path="$2" body="${3:-}"
  local args=(-sk -X "$method" "https://127.0.0.1:8500/v1/${path}" -H "X-Warden-Token: $WARDEN_TOKEN")
  if [ -n "$body" ]; then
    args+=(-H "Content-Type: application/json" -d "$body")
  fi
  curl "${args[@]}" 2>/dev/null
}

# Helper: make Vault API request with root token
vault_api() {
  local method="$1" path="$2" body="${3:-}"
  local args=(-s -X "$method" "${VAULT_ADDR}/v1/${path}" -H "X-Vault-Token: $VAULT_TOKEN")
  if [ -n "$body" ]; then
    args+=(-H "Content-Type: application/json" -d "$body")
  fi
  curl "${args[@]}" 2>/dev/null
}

# Step 7: Configure Vault dev server
echo ""
echo "[7/10] Configuring Vault dev server..."

# Write test secrets to KV v2 (enabled at secret/ by default in dev mode)
echo "  Writing test secrets..."
vault_api POST "secret/data/e2e/app-config" \
  '{"data":{"api_key":"e2e-test-key-12345","database_url":"postgres://localhost/testdb","environment":"e2e"}}'
vault_api POST "secret/data/e2e/database" \
  '{"data":{"username":"e2e-user","password":"e2e-password-secure","host":"db.example.com","port":"5432"}}'

# Create policy for Warden-minted service tokens (read-only secrets access)
echo "  Creating Vault policies..."
vault_api PUT "sys/policies/acl/e2e-secrets-reader" \
  '{"policy":"path \"secret/data/*\" {\n  capabilities = [\"read\", \"list\"]\n}\npath \"secret/metadata/*\" {\n  capabilities = [\"list\", \"read\"]\n}"}'

# Create policy for Warden AppRole (token creation + secrets access)
vault_api PUT "sys/policies/acl/e2e-warden-service" \
  '{"policy":"path \"secret/data/*\" {\n  capabilities = [\"create\", \"read\", \"update\", \"delete\", \"list\"]\n}\npath \"secret/metadata/*\" {\n  capabilities = [\"list\", \"read\"]\n}\npath \"auth/token/create/*\" {\n  capabilities = [\"create\", \"update\"]\n}\npath \"auth/token/revoke-accessor\" {\n  capabilities = [\"update\"]\n}\npath \"auth/e2e_approle/role/*\" {\n  capabilities = [\"read\", \"create\", \"update\"]\n}"}'

# Enable AppRole auth at custom path
echo "  Enabling AppRole auth..."
vault_api POST "sys/auth/e2e_approle" '{"type":"approle"}' || true

sleep 1

# Create AppRole role
echo "  Creating AppRole role..."
vault_api POST "auth/e2e_approle/role/warden-e2e-role" \
  '{"token_policies":["default","e2e-warden-service"],"token_ttl":"3600","token_period":"3600","token_type":"service","bind_secret_id":true}'

sleep 1

# Set custom role_id
vault_api POST "auth/e2e_approle/role/warden-e2e-role/role-id" \
  "{\"role_id\":\"$VAULT_APPROLE_ROLE_ID\"}"

# Create custom secret_id
vault_api POST "auth/e2e_approle/role/warden-e2e-role/custom-secret-id" \
  "{\"secret_id\":\"$VAULT_APPROLE_SECRET_ID\"}"

# Create token role for Warden to mint tokens via credential spec
echo "  Creating token role 'e2e-secrets-reader'..."
vault_api POST "auth/token/roles/e2e-secrets-reader" \
  '{"allowed_policies":["e2e-secrets-reader"],"disallowed_policies":["root"],"orphan":true,"token_period":"1h","renewable":true,"token_explicit_max_ttl":"24h","token_type":"service"}'

# Verify AppRole login works
echo "  Verifying AppRole login..."
LOGIN_RESULT=$(vault_api POST "auth/e2e_approle/login" \
  "{\"role_id\":\"$VAULT_APPROLE_ROLE_ID\",\"secret_id\":\"$VAULT_APPROLE_SECRET_ID\"}")
if echo "$LOGIN_RESULT" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d.get('auth',{}).get('client_token')" 2>/dev/null; then
  echo "  AppRole login verified."
else
  echo "  WARNING: AppRole login verification failed"
  echo "  $LOGIN_RESULT"
fi

# Step 8: Create Hydra OAuth2 clients
echo ""
echo "[8/10] Creating Hydra OAuth2 clients..."

# Client for AI agent (transparent mode testing)
curl -s -X POST "$HYDRA_ADMIN/admin/clients" \
  -H "Content-Type: application/json" \
  -d '{"client_id":"e2e-agent","client_name":"E2E Agent","client_secret":"agent-secret","grant_types":["client_credentials"],"response_types":[],"scope":"api:read api:write","token_endpoint_auth_method":"client_secret_post"}' \
  >/dev/null 2>&1 && echo "  [OK] e2e-agent" || echo "  [SKIP] e2e-agent (already exists?)"

# Client for CI/CD pipeline
curl -s -X POST "$HYDRA_ADMIN/admin/clients" \
  -H "Content-Type: application/json" \
  -d '{"client_id":"e2e-pipeline","client_name":"E2E Pipeline","client_secret":"pipeline-secret","grant_types":["client_credentials"],"response_types":[],"scope":"api:read api:write","token_endpoint_auth_method":"client_secret_post"}' \
  >/dev/null 2>&1 && echo "  [OK] e2e-pipeline" || echo "  [SKIP] e2e-pipeline (already exists?)"

# Client with 2s token TTL for expired JWT testing
curl -s -X POST "$HYDRA_ADMIN/admin/clients" \
  -H "Content-Type: application/json" \
  -d '{"client_id":"e2e-ephemeral","client_name":"E2E Ephemeral","client_secret":"ephemeral-secret","grant_types":["client_credentials"],"response_types":[],"scope":"api:read api:write","token_endpoint_auth_method":"client_secret_post","client_credentials_grant_access_token_lifespan":"2s"}' \
  >/dev/null 2>&1 && echo "  [OK] e2e-ephemeral (2s TTL)" || echo "  [SKIP] e2e-ephemeral (already exists?)"

# Verify JWT issuance works
echo "  Verifying JWT issuance..."
JWT_RESPONSE=$(curl -s -X POST "$HYDRA_PUBLIC/oauth2/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=e2e-agent&client_secret=agent-secret&scope=api:read api:write" 2>/dev/null)
if echo "$JWT_RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d.get('access_token','').startswith('eyJ')" 2>/dev/null; then
  echo "  JWT issuance verified."
else
  echo "  WARNING: JWT issuance verification failed"
  echo "  $JWT_RESPONSE"
fi

# Step 9: Configure Warden with Vault provider
echo ""
echo "[9/10] Configuring Warden with Vault provider..."

# 9a. Mount Vault provider
echo "  Mounting Vault provider at vault/..."
warden_api POST "sys/providers/vault" '{"type":"vault"}'

sleep 1

# 9b. Configure Vault provider address
echo "  Configuring Vault provider..."
warden_api PUT "vault/config" \
  "{\"vault_address\":\"$VAULT_ADDR\",\"tls_skip_verify\":true,\"timeout\":\"30s\"}"

# 9c. Create credential source (AppRole auth to Vault dev server)
echo "  Creating credential source 'vault-e2e'..."
warden_api POST "sys/cred/sources/vault-e2e" \
  "{\"type\":\"hvault\",\"rotation_period\":300,\"config\":{\"vault_address\":\"$VAULT_ADDR\",\"auth_method\":\"approle\",\"role_id\":\"$VAULT_APPROLE_ROLE_ID\",\"secret_id\":\"$VAULT_APPROLE_SECRET_ID\",\"approle_mount\":\"e2e_approle\",\"role_name\":\"warden-e2e-role\"}}"

# 9d. Create credential spec (mint Vault tokens via token role)
echo "  Creating credential spec 'vault-token-reader'..."
warden_api POST "sys/cred/specs/vault-token-reader" \
  '{"type":"vault_token","source":"vault-e2e","config":{"mint_method":"vault_token","token_role":"e2e-secrets-reader"}}'

# 9e. Create Warden policy for Vault gateway access
echo "  Creating Warden policy 'vault-gateway-access'..."
warden_api POST "sys/policies/cbp/vault-gateway-access" \
  '{"policy":"path \"vault/gateway*\" {\n  capabilities = [\"read\", \"create\", \"update\", \"delete\", \"list\"]\n}\npath \"vault/role/+/gateway*\" {\n  capabilities = [\"read\", \"create\", \"update\", \"delete\", \"list\"]\n}"}'

# 9f. Enable JWT auth method in Warden
echo "  Enabling JWT auth method..."
warden_api POST "sys/auth/jwt" '{"type":"jwt"}'

sleep 1

# 9g. Configure JWT auth with Hydra OIDC discovery
echo "  Configuring JWT auth with Hydra OIDC..."
warden_api PUT "auth/jwt/config" \
  "{\"mode\":\"oidc\",\"oidc_discovery_url\":\"$HYDRA_PUBLIC\",\"bound_issuer\":\"$HYDRA_PUBLIC\"}"

# 9h. Create JWT role linking to credential spec
echo "  Creating JWT role 'e2e-reader'..."
warden_api POST "auth/jwt/role/e2e-reader" \
  '{"token_policies":["vault-gateway-access"],"cred_spec_name":"vault-token-reader","user_claim":"sub","token_ttl":3600}'

# 9i. Enable transparent mode on Vault provider
echo "  Enabling transparent mode..."
warden_api POST "vault/config" \
  '{"auto_auth_path":"auth/jwt/"}'

# Step 10: Verify Vault integration
echo ""
echo "[10/10] Verifying Vault integration..."

# 10a. Transparent mode: read secret through vault gateway with JWT
echo "  Testing transparent mode (JWT -> vault/gateway -> Vault)..."
TEST_JWT=$(bash "$SCRIPT_DIR/tools/get_jwt.sh" 2>/dev/null || echo "")
if [ -n "$TEST_JWT" ]; then
  T_RESULT=$(curl -sk -o /dev/null -w "%{http_code}" \
    "https://127.0.0.1:8500/v1/vault/role/e2e-reader/gateway/v1/secret/data/e2e/app-config" \
    -H "Authorization: Bearer $TEST_JWT" 2>/dev/null)
  if [ "$T_RESULT" = "200" ]; then
    echo "  Transparent mode: OK (HTTP $T_RESULT)"
  else
    echo "  Transparent mode: FAILED (HTTP $T_RESULT)"
  fi
else
  echo "  Transparent mode: SKIPPED (could not get JWT from Hydra)"
fi

# Final summary
echo ""
echo "=== CLUSTER READY ==="
echo ""
for port in 8500 8510 8520; do
  HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" "https://127.0.0.1:${port}/v1/sys/health" 2>/dev/null)
  case "$HTTP_CODE" in
    200) echo "  Node :${port} — ACTIVE (200)" ;;
    429) echo "  Node :${port} — STANDBY (429)" ;;
    *)   echo "  Node :${port} — $HTTP_CODE" ;;
  esac
done
echo ""
echo "Infrastructure:"
echo "  Vault:  $VAULT_ADDR (token: $VAULT_TOKEN)"
echo "  Hydra:  $HYDRA_PUBLIC (OIDC) / $HYDRA_ADMIN (admin)"
echo ""
echo "Vault integration:"
echo "  curl -k -H 'Authorization: Bearer <jwt>' https://127.0.0.1:8500/v1/vault/role/e2e-reader/gateway/v1/secret/data/e2e/app-config"
echo "  Get JWT:         bash e2e/tools/get_jwt.sh"
echo ""
echo "To start chaos testing:"
echo "  cd $SCRIPT_DIR && claude --dangerously-skip-permissions \"Begin the chaos testing loop\""
