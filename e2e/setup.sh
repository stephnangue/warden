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
  # SANs matter: a client that verifies rejects a certificate carrying only a CN,
  # so without them this certificate is usable only with -k. The issuer documents
  # are served through this listener, and a verifier fetching them (a Kubernetes
  # API server, say) does verify. e2e-nginx/nginx are the container name and
  # service alias, for a verifier inside the compose network.
  openssl ecparam -genkey -name prime256v1 -noout -out "$NGINX_CERT_DIR/server.key" 2>/dev/null
  openssl req -new -key "$NGINX_CERT_DIR/server.key" -out "$NGINX_CERT_DIR/server.csr" \
    -subj "/CN=e2e-nginx-lb" 2>/dev/null
  openssl x509 -req -sha256 -in "$NGINX_CERT_DIR/server.csr" -signkey "$NGINX_CERT_DIR/server.key" \
    -out "$NGINX_CERT_DIR/server.crt" -days 365 \
    -extfile <(printf "subjectAltName=IP:127.0.0.1,DNS:localhost,DNS:e2e-nginx,DNS:nginx") 2>/dev/null
  rm -f "$NGINX_CERT_DIR/server.csr"
  if [ ! -s "$NGINX_CERT_DIR/server.crt" ]; then
    echo "ERROR: failed to generate nginx server certificate"
    exit 1
  fi
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

# Enable the transit secrets engine for the OIDC issuer's external signer (remote
# signing). The issuer's private signing key is created here and never leaves it.
# The nodes' signer stanza authenticates with the dev root token (this is a
# throwaway e2e vault); production uses a least-privilege token (see the signer
# block in deploy/config/warden.hcl).
echo "Enabling Vault transit for the OIDC issuer signer..."
curl -s -X POST "$VAULT_ADDR/v1/sys/mounts/transit" \
  -H "X-Vault-Token: $VAULT_TOKEN" -d '{"type":"transit"}' >/dev/null 2>&1 || true
echo "  transit enabled."

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
  INIT_OUTPUT=$("$BIN_DIR/warden" operator init -o table --secret-shares=1 --secret-threshold=1 2>&1)
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

# A whole multi-field credential in one secret, for credential chaining: an
# api_key spec references this and its source declares which of the other keys
# travel. "owner" is the sort of bookkeeping operators keep beside a key, here so
# the payload is a realistic blob rather than exactly what one consumer wants.
# What proves undeclared fields stay behind is the control row in
# e2e/fullchain/credential_chaining_test.go, which drives this same secret through
# a source declaring nothing and asserts the application key never ships.
vault_api POST "secret/data/e2e/datadog-keys" \
  '{"data":{"api_key":"e2e-dd-chained-not-a-real-key","application_key":"e2e-dd-chained-not-a-real-app-key","owner":"e2e-undeclared-field"}}'

# The personal access token a keyless gitlab source mints with. Chained the same
# way as the datadog keys above, but consumed by a driver that calls an API with
# it rather than one that passes it through — so what the gitlab row in
# e2e/fullchain/gitlab_test.go proves is that this value authenticated a real
# mint, having reached the driver from here and nowhere else.
vault_api POST "secret/data/e2e/gitlab-pat" \
  '{"data":{"pat":"e2e-gl-chained-not-a-real-pat"}}'

# The same arrangement for a gitlab source authenticating as an OAuth application
# instead. What is chained here is the whole client credential, which the driver
# spends on a token grant rather than on the mint itself — so the oauth2 rows prove
# the chain reached one call earlier than the pat rows do.
#
# Both halves, because they authenticate as a pair: a chained oauth2 source is
# refused an inline application_id precisely so an id cannot name one application
# while the secret beside it belongs to another.
vault_api POST "secret/data/e2e/gitlab-app-secret" \
  '{"data":{"application_id":"e2e-gl-app-id","application_secret":"e2e-gl-app-secret-not-a-real-secret"}}'

# The management secret key a keyless scaleway source creates dynamic API keys
# with. Chained like the gitlab pat above and spent the same way — on a header of
# the driver's own mint call, X-Auth-Token on POST /iam/v1alpha1/api-keys — so
# the dynamic row in e2e/fullchain/scaleway_test.go proves this value
# authenticated a real key-create, having reached the driver from here and
# nowhere else.
vault_api POST "secret/data/e2e/scaleway-mgmt-key" \
  '{"data":{"management_secret_key":"e2e-scw-mgmt-not-a-real-secret-key"}}'

# A whole scaleway key pair, for the chain that hangs off a SPEC rather than a
# source. Scaleway is the one provider whose two mint methods chain different
# secrets: dynamic_keys chains the management key above, which authenticates the
# source's own calls, while static_keys chains this pair, which IS the
# credential and authenticates nothing of the source's.
#
# Both halves travel for that reason, and the access key carries the SCW prefix
# because the credential type refuses anything else at parse — chained or not.
vault_api POST "secret/data/e2e/scaleway-static-pair" \
  '{"data":{"access_key":"SCWE2ECHAINEDPAIR000","secret_key":"e2e-scw-chained-pair-not-a-real-secret"}}'

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

# Vault JWT auth trusting Hydra, for workload-identity federation.
#
# Configured here rather than with the rest of the Vault setup because Vault
# fetches the JWKS when this is written, and Hydra is only known-responsive once
# the token above has been issued.
#
# A credential spec referenced through secret_spec must be minted as the
# session-pinned caller, which forces the exchange path — and on an hvault source
# that path requires auth_method=oidc_federation. So the AppRole source above
# cannot back a chained secret; this is the second, keyless source that can.
echo "  Enabling Vault JWT auth (workload identity federation)..."
vault_api POST "sys/auth/jwt" '{"type":"jwt"}' || true

# The issuer is what Hydra stamps into its tokens; the JWKS is fetched over the
# compose network, where that hostname does not resolve. They differ on purpose.
vault_api POST "auth/jwt/config" \
  '{"jwks_url":"http://hydra:4444/.well-known/jwks.json","bound_issuer":"http://localhost:4444"}'

# Hydra client-credentials tokens carry an empty aud, so the role binds the
# subject instead — which for those tokens is the client id.
#
# A list rather than one subject, because a chained secret fetched with
# agent_identity federates as the calling agent: a row proving two agents resolve
# different secrets needs both of them able to log in here. Still a closed list —
# an unknown client is refused exactly as before. bound_subject is cleared in the
# same write on purpose: a role write merges, so leaving it set would silently keep
# the single-subject restriction in force.
vault_api POST "auth/jwt/role/warden-e2e-fed" \
  '{"role_type":"jwt","bound_subject":"","bound_claims":{"sub":["e2e-agent","e2e-pipeline"]},"user_claim":"sub","bound_issuer":"http://localhost:4444","token_policies":["e2e-secrets-reader"],"token_ttl":"1h"}'

# Verify the federation login works, so a later gateway 401 is not mistaken for
# a chaining bug.
echo "  Verifying Vault JWT federation login..."
# `|| true` is not decoration: under `set -euo pipefail` a failed decode would
# abort the whole script here, so a transient Hydra hiccup — which the issuance
# check above deliberately treats as a warning — would silently skip every
# remaining step and leave a half-configured cluster.
FED_TOKEN=$(echo "$JWT_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])" 2>/dev/null || true)
if [ -z "$FED_TOKEN" ]; then
  echo "  WARNING: no JWT to verify federation login with (see the issuance warning above)"
else
  FED_LOGIN=$(vault_api POST "auth/jwt/login" "{\"role\":\"warden-e2e-fed\",\"jwt\":\"$FED_TOKEN\"}")
  if echo "$FED_LOGIN" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d.get('auth',{}).get('client_token')" 2>/dev/null; then
    echo "  Vault JWT federation login verified."
  else
    echo "  WARNING: Vault JWT federation login failed"
    echo "  $FED_LOGIN"
  fi
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

# 9c-bis. Keyless federation source, for credential chaining.
#
# No rotation_period and no role_id/secret_id: a keyless source has no shared
# session to rotate, and the driver rejects the AppRole fields outright.
echo "  Creating credential source 'vault-fed-e2e' (OIDC federation)..."
warden_api POST "sys/cred/sources/vault-fed-e2e" \
  "{\"type\":\"hvault\",\"config\":{\"vault_address\":\"$VAULT_ADDR\",\"auth_method\":\"oidc_federation\",\"jwt_role\":\"warden-e2e-fed\",\"jwt_mount\":\"jwt\"}}"

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

# 9j. Enable Warden's own OIDC issuer (workload identity federation).
#
# Suites minting Warden-signed identity assertions (subject_token_source=
# warden_identity) need the issuer enabled and ready. With the signer "transit"
# stanza in every node's config, this write provisions the signing keys IN
# transit — the private key is created there and never enters Warden. The write
# is a partial update and idempotent: re-applying it regenerates no keys, so the
# JWKS kids stay stable across setup re-runs.
#
# issuer_url is the `iss` claim and the origin verifiers fetch discovery/JWKS
# from, so it must outlive any single node: the load balancer fronts all three
# and proxies every path, whereas a node origin goes dark whenever that node is
# killed — which the HA suites do deliberately.
#
# Unlike the checks above this one aborts rather than warns. The issuer is part
# of the harness contract now, and a silent failure here surfaces far from its
# cause: suites that re-apply the config without an issuer_url would fail with
# "issuer_url is required", saying nothing about setup having skipped this step.
echo "  Enabling Warden OIDC issuer..."
ISSUER_RESULT=$(warden_api POST "sys/oidc-issuer/config" \
  '{"enabled":true,"issuer_url":"https://127.0.0.1:8000"}')
if echo "$ISSUER_RESULT" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d['data']['ready'] is True" 2>/dev/null; then
  echo "  OIDC issuer enabled and ready."
else
  echo "ERROR: OIDC issuer enable failed or not ready"
  echo "  $ISSUER_RESULT"
  exit 1
fi

# 9k. A second Vault JWT auth mount, trusting WARDEN'S OWN issuer.
#
# Until now every chained suite has had to use subject_token_source=
# agent_identity, because the only Vault JWT mount trusts Hydra: a Warden-minted
# assertion fails its signature, its iss, its sub and its aud. warden_identity —
# the mode for a spec with no inbound agent JWT to forward — went untested.
#
# Static keys rather than a jwks_url, on purpose. Vault would otherwise have to
# fetch the JWKS from a Warden node, and no compose-network path to one exists:
# only nginx carries a host-gateway mapping. But the issuer's signing keys live
# in THIS Vault's transit engine already (the signer stanza in every node's
# config), so the public halves are readable right here with no network hop and
# no certificate to pin.
#
# Every transit version is pinned, not just the newest: enabling the issuer
# pre-publishes the next key alongside the active one, so pinning one would
# start rejecting assertions the moment a cutover happened.
#
# This must follow 9j — the transit keys exist only once that write has run.
echo "  Enabling Vault JWT auth for Warden-issued assertions..."
vault_api POST "sys/auth/jwt-warden" '{"type":"jwt"}' >/dev/null

WARDEN_JWT_CONFIG=$(vault_api GET "transit/keys/warden-oidc-rs256" | python3 -c "
import sys, json
keys = json.load(sys.stdin)['data']['keys']
pems = [v['public_key'] for _, v in sorted(keys.items(), key=lambda kv: int(kv[0]))]
if not pems:
    raise SystemExit(1)
print(json.dumps({
    'jwt_validation_pubkeys': pems,
    'bound_issuer': 'https://127.0.0.1:8000',
    'jwt_supported_algs': ['RS256'],
}))
" 2>/dev/null || true)
if [ -z "$WARDEN_JWT_CONFIG" ]; then
  echo "ERROR: could not read the OIDC issuer's public keys from Vault transit"
  exit 1
fi
vault_api POST "auth/jwt-warden/config" "$WARDEN_JWT_CONFIG" >/dev/null

# bound_audiences is mandatory here where the Hydra role binds sub instead: a
# Warden assertion always carries an aud, and Vault refuses a JWT whose aud the
# role does not bind. The subject is bound on warden_sub — the raw principal —
# rather than sub, whose composite form embeds a mount accessor regenerated on
# every setup run. Same closed client list as the Hydra role.
vault_api POST "auth/jwt-warden/role/warden-e2e-warden-fed" \
  '{"role_type":"jwt","bound_audiences":["https://vault.e2e.warden"],"bound_claims":{"warden_sub":["e2e-agent","e2e-pipeline"]},"user_claim":"warden_sub","token_policies":["e2e-secrets-reader"],"token_ttl":"1h"}' >/dev/null

# The federation source that logs in there. audience sits on the SOURCE so a
# spec need not repeat assertion_audience: the driver derives it from here.
echo "  Creating credential source 'vault-warden-fed-e2e' (Warden-identity federation)..."
warden_api POST "sys/cred/sources/vault-warden-fed-e2e" \
  "{\"type\":\"hvault\",\"config\":{\"vault_address\":\"$VAULT_ADDR\",\"auth_method\":\"oidc_federation\",\"jwt_role\":\"warden-e2e-warden-fed\",\"jwt_mount\":\"jwt-warden\",\"audience\":\"https://vault.e2e.warden\"}}"

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
