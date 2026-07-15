#!/usr/bin/env bash
# Idempotent Warden bootstrap for the policy-hygiene tutorial.
#
# What this provisions, all under the shared `tutorial/` namespace:
#   1. Namespace `tutorial/` with custom_metadata.auto_auth_path=jwt/ —
#      lets bare-JWT calls to /v1/sys/* (introspect, provider list,
#      skill read) get implicit authentication.
#   2. JWT auth method pointed at Forgejo's Actions OIDC, with
#      default_role=discovery-baseline as the fallback when the URL
#      carries no role segment.
#   3. discovery-baseline role + policy — read-only access to the four
#      sys/* paths the agent's discovery loop hits.
#   4. Three task roles with dense, operator-set descriptions
#      (policy-scanner, anthropic-ops, slack-ops) — the descriptions
#      embed mount_url and (for Slack) the destination channel so the
#      agent has no need to read env vars to find them.
#   5. Two decoy roles (kv-secrets-reader, slack-alert-poster) that
#      share the same JWT identity but describe wrong-for-this-task
#      bindings — used to prove the agent matches by description, not
#      by provider type.
#   6. Vault + Anthropic + (optional) Slack providers, each carrying a
#      description.
#
# Requires:
#   - WARDEN_ADDR + WARDEN_TOKEN exported (admin shell setup from section 4)
#   - bao-out/creds.env populated by bao-init.sh (ROLE_ID + SECRET_ID)
#   - Anthropic API key passed via -anthropic-key=sk-... or $ANTHROPIC_API_KEY
#
# Usage:
#   ./warden-init.sh -anthropic-key=sk-ant-... \
#                    [-slack-token=xoxb-...] \
#                    [-slack-channel-id=C0123456789] \
#                    [-slack-channel-name='#sec-hygiene']
#
# -slack-token is optional; without it, the Slack provider/role/policy
# are skipped (the agent will fail the Slack upload, but Goose's hygiene
# work and Forgejo's actions/upload-artifact still produce the report).
# -slack-channel-id and -slack-channel-name are required when
# -slack-token is given; they end up in the slack-ops role's description
# so the agent extracts the channel from discovery, not from env vars.
set -euo pipefail

ANTHROPIC_KEY="${ANTHROPIC_API_KEY:-}"
SLACK_TOKEN="${SLACK_TOKEN:-}"
SLACK_CHANNEL_ID="${SLACK_CHANNEL_ID:-}"
SLACK_CHANNEL_NAME="${SLACK_CHANNEL_NAME:-}"
for arg in "$@"; do
  case $arg in
    --anthropic-key=*|-anthropic-key=*)           ANTHROPIC_KEY="${arg#*=}" ;;
    --slack-token=*|-slack-token=*)               SLACK_TOKEN="${arg#*=}" ;;
    --slack-channel-id=*|-slack-channel-id=*)     SLACK_CHANNEL_ID="${arg#*=}" ;;
    --slack-channel-name=*|-slack-channel-name=*) SLACK_CHANNEL_NAME="${arg#*=}" ;;
    *) echo "unknown arg: $arg" >&2; exit 1 ;;
  esac
done

if [ -z "$ANTHROPIC_KEY" ]; then
  echo "ERROR: pass -anthropic-key=sk-... or set ANTHROPIC_API_KEY" >&2
  exit 1
fi

if [ -n "$SLACK_TOKEN" ] && { [ -z "$SLACK_CHANNEL_ID" ] || [ -z "$SLACK_CHANNEL_NAME" ]; }; then
  echo "ERROR: -slack-token requires -slack-channel-id=C... and -slack-channel-name=#..." >&2
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

# 5pre. Bootstrap a file audit device.
#
# The dev server ships zero audit by default — the broker fail-opens at
# zero, so the cluster runs unaudited until we enable one. §9 of the
# README tails this file to verify identity-attribution; without this
# step the file never exists.
if ! "$WARDEN" audit list 2>/dev/null | grep -q "^audit-default/"; then
  "$WARDEN" audit enable -file-path=./warden-audit.log -path=audit-default file
fi

# 5a. Create the shared tutorial namespace.
#
# Root namespace cannot carry custom_metadata. The agent's discovery
# calls (warden role list, warden provider list, warden skill read X)
# arrive as bare JWTs on /v1/sys/* — no Warden session token and no
# role segment in the URL. The auto_auth_path metadata tells Warden
# which auth mount to use for implicit authentication on those calls;
# without it, every sys/* call returns 401. Idempotent — future
# tutorials reuse this namespace rather than each creating their own.
$WARDEN namespace create tutorial -metadata=auto_auth_path=auth/jwt/ 2>/dev/null || true
export WARDEN_NAMESPACE=tutorial

# 5b. JWT auth pointed at Forgejo's Actions OIDC.
#
# default_role=discovery-baseline is the fallback when the URL has no
# role segment (i.e. /v1/sys/* calls). It carries just enough policy
# for the agent to run the discovery loop.
$WARDEN auth enable jwt 2>/dev/null || true
$WARDEN write auth/jwt/config \
    jwks_url=http://forgejo.local:3000/api/actions/.well-known/keys \
    bound_issuer=http://forgejo.local:3000/api/actions \
    default_audience=http://warden.local \
    default_role=discovery-baseline

# 5c. discovery-baseline role + policy.
#
# Any JWT from the trusted Forgejo repo that hits /v1/sys/* without a
# role gets resolved to this role and inherits the discovery-baseline
# policy. The role has no cred_spec_name — it does not mint upstream
# credentials. It exists only to authorize the agent's introspection
# calls so it can pick a real (task-specific) role afterwards.
$WARDEN write auth/jwt/role/discovery-baseline \
    description="Baseline namespace identity for any authenticated agent. Grants read on sys/introspect/roles, sys/providers, and sys/skills/*. No upstream credentials are minted by this role." \
    bound_audiences=http://warden.local \
    bound_claims='{"repository":"siteowner/policy-hygiene"}' \
    user_claim=sub

cat > /tmp/discovery-baseline.hcl <<'EOF'
# `warden provider list` and `warden skill list` send GET ?warden-list=true,
# which Warden classifies as LIST (not READ) at the policy layer — so both
# capabilities are needed: `list` for the listing calls, `read` for the
# per-record reads (sys/providers/<path>, sys/skills/<name>).
path "sys/introspect/roles" { capabilities = ["read"] }
path "sys/providers"        { capabilities = ["read", "list"] }
path "sys/providers/*"      { capabilities = ["read"] }
path "sys/skills"           { capabilities = ["read", "list"] }
path "sys/skills/*"         { capabilities = ["read"] }
EOF
$WARDEN policy write discovery-baseline /tmp/discovery-baseline.hcl

# Attach the discovery-baseline policy to the discovery-baseline role.
$WARDEN write auth/jwt/role/discovery-baseline \
    token_policies=discovery-baseline

# 5d. Vault provider → OpenBao (AppRole login via the bao-init creds).
$WARDEN provider enable \
    -description="Internal OpenBao cluster — ACL policies, mounts, identity (read-mostly)" \
    -path=vault vault 2>/dev/null || true
$WARDEN write vault/config \
    vault_address=http://127.0.0.1:8200 \
    auto_auth_path=auth/jwt/

# Order matters: delete spec before source (spec depends on source).
$WARDEN cred spec delete -f policy-scanner 2>/dev/null || true
$WARDEN cred source delete -f openbao-root 2>/dev/null || true
$WARDEN cred source create openbao-root -type=hvault \
    -rotation-period=24h \
    -config=vault_address=http://127.0.0.1:8200 \
    -config=auth_method=approle \
    -config=approle_mount=approle/ \
    -config=role_name=warden-policy-scanner \
    -config=role_id="$ROLE_ID" \
    -config=secret_id="$SECRET_ID"
$WARDEN cred spec create policy-scanner -source openbao-root \
    -config mint_method=vault_token \
    -config token_role=policy-reader \
    -config ttl=1h

# policy-scanner role — dense description embedding the upstream mount.
# The agent reads this verbatim from `warden role list` and pairs it
# with the vault provider's mount_url for the audit work.
$WARDEN write auth/jwt/role/policy-scanner \
    description="Read-only ACL policy hygiene auditing against OpenBao at /v1/tutorial/vault/. Reads policies, mounts, and entity bindings; no writes." \
    bound_claims='{"repository":"siteowner/policy-hygiene","ref":"refs/heads/main","ref_type":"branch"}' \
    cred_spec_name=policy-scanner \
    token_policies=vault-readonly

# 5e. Anthropic provider → DeepSeek's Anthropic-compatible endpoint.
#
# Note: this is the LLM leg consumed by Goose's own Anthropic SDK
# (configured via ANTHROPIC_HOST + ANTHROPIC_API_KEY in the workflow).
# The agent does not "discover" this leg — the runtime wires it
# in before the agent starts. See docs/agent-flow.md §1.
$WARDEN provider enable \
    -description="Anthropic-compatible LLM endpoint (default: DeepSeek). Internal — used by Goose runtime, not chosen by agents." \
    -path=anthropic anthropic 2>/dev/null || true
$WARDEN write anthropic/config \
    anthropic_url=https://api.deepseek.com/anthropic \
    auto_auth_path=auth/jwt/ \
    timeout=120s

$WARDEN cred spec delete -f anthropic-ops 2>/dev/null || true
$WARDEN cred source delete -f anthropic-src 2>/dev/null || true
$WARDEN cred source create anthropic-src -type=apikey \
    -rotation-period=0 \
    -config=api_url=https://api.deepseek.com \
    -config=verify_endpoint=/v1/models \
    -config=auth_header_type=custom_header \
    -config=auth_header_name=x-api-key \
    -config=extra_headers=anthropic-version:2023-06-01
$WARDEN cred spec create anthropic-ops -source anthropic-src \
    -config api_key="$ANTHROPIC_KEY"

$WARDEN write auth/jwt/role/anthropic-ops \
    description="LLM inference for the hygiene auditor agent. Used internally by Goose — agents do not call this role directly." \
    bound_claims='{"repository":"siteowner/policy-hygiene","ref":"refs/heads/main","ref_type":"branch"}' \
    cred_spec_name=anthropic-ops \
    token_policies=anthropic-ops

# 5f. Decoy: kv-secrets-reader.
#
# Same JWT identity, same vault provider, but described for a
# different task (KV-v2 secrets) and bound to a cred spec that has
# no permission to read ACL policies. The agent must skip this
# role when picking one for the hygiene audit — proof that role
# selection is description-driven, not provider-typed.
$WARDEN write auth/jwt/role/kv-secrets-reader \
    description="Read application secrets from KV-v2 at /v1/tutorial/vault/ (e.g. secret/data/app/*). Not for policy or identity reads." \
    bound_claims='{"repository":"siteowner/policy-hygiene"}' \
    cred_spec_name=policy-scanner \
    token_policies=discovery-baseline \
    user_claim=sub

# 5g. Access policies — one per JWT task role.
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

# 5h. Slack provider → slack.com/api (optional — skip if no -slack-token).
if [ -n "$SLACK_TOKEN" ]; then
  $WARDEN provider enable \
      -description="Slack workspace for security-team notifications and canvas reports" \
      -path=slack slack 2>/dev/null || true
  $WARDEN write slack/config slack_url=https://slack.com/api auto_auth_path=auth/jwt/

  $WARDEN cred spec delete -f slack-ops 2>/dev/null || true
  $WARDEN cred source delete -f slack-src 2>/dev/null || true
  $WARDEN cred source create slack-src -type=apikey \
      -rotation-period=0 \
      -config=api_url=https://slack.com/api \
      -config=verify_endpoint=/auth.test \
      -config=verify_method=POST
  $WARDEN cred spec create slack-ops -source slack-src \
      -config api_key="$SLACK_TOKEN"

  # slack-ops role description embeds the destination channel (name + id)
  # so the agent extracts them from discovery rather than from env vars.
  $WARDEN write auth/jwt/role/slack-ops \
      description="Post hygiene reports as Slack canvas in channel ${SLACK_CHANNEL_NAME} (${SLACK_CHANNEL_ID}) via the Slack provider at /v1/tutorial/slack/." \
      bound_claims='{"repository":"siteowner/policy-hygiene","ref":"refs/heads/main","ref_type":"branch"}' \
      cred_spec_name=slack-ops \
      token_policies=slack-ops

  # Slack Web API is all POST (no REST verbs), so every method maps to
  # the `create` capability at Warden's policy layer — including
  # read-style ones like conversations.info and auth.test.
  cat > /tmp/slack-ops.hcl <<'EOF'
path "slack/role/slack-ops/gateway/conversations.info"            { capabilities = ["create"] }
path "slack/role/slack-ops/gateway/conversations.canvases.create" { capabilities = ["create"] }
path "slack/role/slack-ops/gateway/canvases.delete"               { capabilities = ["create"] }
path "slack/role/slack-ops/gateway/chat.postMessage"              { capabilities = ["create"] }
path "slack/role/slack-ops/gateway/auth.test"                     { capabilities = ["create"] }
EOF
  $WARDEN policy write slack-ops /tmp/slack-ops.hcl

  # 5i. Decoy: slack-alert-poster.
  #
  # Same JWT identity, same slack provider, but described for short
  # alert messages to a different channel — and bound only to the
  # discovery-baseline policy, so the canvas calls would 403 even if
  # the agent did pick it. The agent must read the description and
  # reject this role for canvas publishing.
  $WARDEN write auth/jwt/role/slack-alert-poster \
      description="Post short alert notifications to #oncall-pings (C9876543210) via the Slack provider at /v1/tutorial/slack/. One-line messages only — not for hygiene reports." \
      bound_claims='{"repository":"siteowner/policy-hygiene"}' \
      cred_spec_name=slack-ops \
      token_policies=discovery-baseline \
      user_claim=sub

  echo "warden-init: section 5 complete (namespace=tutorial, Slack delivery enabled)"
else
  echo "warden-init: section 5 complete (namespace=tutorial, Slack delivery skipped — no -slack-token given)"
fi
