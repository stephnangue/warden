#!/usr/bin/env bash
# Idempotent Warden bootstrap for the policy-hygiene tutorial.
# Runs section 5 of the README in one shot: JWT auth, Vault + Anthropic
# providers, credential sources/specs, JWT roles, and the two scoped policies.
#
# Requires:
#   - WARDEN_ADDR + WARDEN_TOKEN exported (admin shell setup from section 4)
#   - bao-out/creds.env populated by bao-init.sh (ROLE_ID + SECRET_ID)
#   - Anthropic API key passed via --anthropic-key=sk-... or $ANTHROPIC_API_KEY
#
# Usage:
#   ./warden-init.sh --anthropic-key=sk-ant-... [--slack-token=xoxb-...]
#   ANTHROPIC_API_KEY=sk-ant-... SLACK_TOKEN=xoxb-... ./warden-init.sh
#
# --slack-token is optional; without it, the Slack provider/role/policy
# are skipped (the agent will fail the Slack upload, but Goose's hygiene
# work and Forgejo's actions/upload-artifact still produce the report).
set -euo pipefail

ANTHROPIC_KEY="${ANTHROPIC_API_KEY:-}"
SLACK_TOKEN="${SLACK_TOKEN:-}"
for arg in "$@"; do
  case $arg in
    --anthropic-key=*) ANTHROPIC_KEY="${arg#--anthropic-key=}" ;;
    --slack-token=*)   SLACK_TOKEN="${arg#--slack-token=}" ;;
    *) echo "unknown arg: $arg" >&2; exit 1 ;;
  esac
done

if [ -z "$ANTHROPIC_KEY" ]; then
  echo "ERROR: pass --anthropic-key=sk-... or set ANTHROPIC_API_KEY" >&2
  exit 1
fi

if [ ! -f bao-out/creds.env ]; then
  echo "ERROR: bao-out/creds.env missing — run 'docker compose up bao-init' first" >&2
  exit 1
fi
. ./bao-out/creds.env

WARDEN="${WARDEN:-warden}"
command -v "$WARDEN" >/dev/null 2>&1 || { [ -x ./warden ] && WARDEN=./warden; } \
  || { echo "ERROR: warden binary not found. Set WARDEN=/path/to/warden" >&2; exit 1; }

# 5a. JWT auth pointed at Forgejo's Actions OIDC
$WARDEN auth enable --type=jwt 2>/dev/null || true
$WARDEN write auth/jwt/config \
    mode=jwt \
    jwks_url=http://forgejo.local:3000/api/actions/.well-known/keys \
    bound_issuer=http://forgejo.local:3000/api/actions \
    default_audience=http://warden.local

# 5b. Vault provider → OpenBao (AppRole login via the bao-init creds)
$WARDEN provider enable --type=vault vault 2>/dev/null || true
$WARDEN write vault/config \
    vault_address=http://127.0.0.1:8200 \
    auto_auth_path=auth/jwt/

# Order matters: delete spec before source (spec depends on source).
$WARDEN cred spec delete -f policy-scanner 2>/dev/null || true
$WARDEN cred source delete -f openbao-root 2>/dev/null || true
$WARDEN cred source create openbao-root --type=hvault \
    --rotation-period=24h \
    --config=vault_address=http://127.0.0.1:8200 \
    --config=auth_method=approle \
    --config=approle_mount=approle/ \
    --config=role_name=warden-policy-scanner \
    --config=role_id="$ROLE_ID" \
    --config=secret_id="$SECRET_ID"
$WARDEN cred spec create policy-scanner --source openbao-root \
    --config mint_method=vault_token \
    --config token_role=policy-reader \
    --config ttl=1h

$WARDEN write auth/jwt/role/policy-scanner \
    bound_claims='{"repository":"siteowner/policy-hygiene","ref":"refs/heads/main","ref_type":"branch"}' \
    cred_spec_name=policy-scanner \
    token_policies=vault-readonly

# 5c. Anthropic provider → api.anthropic.com
$WARDEN provider enable --type=anthropic anthropic 2>/dev/null || true
$WARDEN write anthropic/config \
    anthropic_url=https://api.deepseek.com/anthropic \
    auto_auth_path=auth/jwt/ \
    timeout=120s

$WARDEN cred spec delete -f anthropic-ops 2>/dev/null || true
$WARDEN cred source delete -f anthropic-src 2>/dev/null || true
$WARDEN cred source create anthropic-src --type=apikey \
    --rotation-period=0 \
    --config=api_url=https://api.deepseek.com \
    --config=verify_endpoint=/v1/models \
    --config=auth_header_type=custom_header \
    --config=auth_header_name=x-api-key \
    --config=extra_headers=anthropic-version:2023-06-01
$WARDEN cred spec create anthropic-ops --source anthropic-src \
    --config api_key="$ANTHROPIC_KEY"

$WARDEN write auth/jwt/role/anthropic-ops \
    bound_claims='{"repository":"siteowner/policy-hygiene","ref":"refs/heads/main","ref_type":"branch"}' \
    cred_spec_name=anthropic-ops \
    token_policies=anthropic-ops

# 5d. Two access policies — one per JWT role
cat > /tmp/vault-readonly.hcl <<'EOF'
path "vault/role/policy-scanner/gateway/v1/sys/policies/acl"   { capabilities = ["read"] }
path "vault/role/policy-scanner/gateway/v1/sys/policies/acl/*" { capabilities = ["read"] }
path "vault/role/policy-scanner/gateway/v1/sys/mounts"         { capabilities = ["read"] }
path "vault/role/policy-scanner/gateway/v1/sys/auth"           { capabilities = ["read"] }
path "vault/role/policy-scanner/gateway/v1/identity/entity/id"   { capabilities = ["read"] }
path "vault/role/policy-scanner/gateway/v1/identity/entity/id/*" { capabilities = ["read"] }
EOF
$WARDEN policy write vault-readonly /tmp/vault-readonly.hcl

cat > /tmp/anthropic-ops.hcl <<'EOF'
path "anthropic/role/anthropic-ops/gateway/v1/messages" { capabilities = ["create"] }
path "anthropic/role/anthropic-ops/gateway/v1/models"   { capabilities = ["read"] }
EOF
$WARDEN policy write anthropic-ops /tmp/anthropic-ops.hcl

# 5e. Slack provider → slack.com/api (optional — skip if no --slack-token)
if [ -n "$SLACK_TOKEN" ]; then
  $WARDEN provider enable --type=slack slack 2>/dev/null || true
  $WARDEN write slack/config slack_url=https://slack.com/api auto_auth_path=auth/jwt/

  $WARDEN cred spec delete -f slack-ops 2>/dev/null || true
  $WARDEN cred source delete -f slack-src 2>/dev/null || true
  $WARDEN cred source create slack-src --type=apikey \
      --rotation-period=0 \
      --config=api_url=https://slack.com/api \
      --config=verify_endpoint=/auth.test \
      --config=verify_method=POST
  $WARDEN cred spec create slack-ops --source slack-src \
      --config api_key="$SLACK_TOKEN"

  $WARDEN write auth/jwt/role/slack-ops \
      bound_claims='{"repository":"siteowner/policy-hygiene","ref":"refs/heads/main","ref_type":"branch"}' \
      cred_spec_name=slack-ops \
      token_policies=slack-ops

  cat > /tmp/slack-ops.hcl <<'EOF'
path "slack/role/slack-ops/gateway/conversations.info"           { capabilities = ["read"] }
path "slack/role/slack-ops/gateway/conversations.canvases.create" { capabilities = ["create"] }
path "slack/role/slack-ops/gateway/canvases.delete"              { capabilities = ["create"] }
path "slack/role/slack-ops/gateway/chat.postMessage"             { capabilities = ["create"] }
path "slack/role/slack-ops/gateway/auth.test"                    { capabilities = ["create"] }
EOF
  $WARDEN policy write slack-ops /tmp/slack-ops.hcl
  echo "warden-init: section 5 complete (Slack delivery enabled)"
else
  echo "warden-init: section 5 complete (Slack delivery skipped — no --slack-token given)"
fi
