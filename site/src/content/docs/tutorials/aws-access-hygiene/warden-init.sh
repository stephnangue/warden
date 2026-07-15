#!/usr/bin/env bash
# Idempotent Warden bootstrap for the aws-access-hygiene tutorial.
#
# What this provisions, all under the `tutorial-aws/` namespace:
#   1. Namespace `tutorial-aws/` with custom_metadata.auto_auth_path=jwt/
#      so bare-JWT calls to /v1/sys/* (introspect, provider list,
#      skill read) get implicit authentication.
#   2. JWT auth method pointed at Forgejo's Actions OIDC, with
#      default_role=discovery-baseline as the fallback for /v1/sys/*.
#   3. discovery-baseline role + policy — read-only on the four sys/*
#      paths the agent's discovery loop needs.
#   4. AWS provider + 1 source (the broker IAM user's keys produced by
#      aws-init.sh) + 5 sts_assume_role credential specs (one per active
#      Warden role, each targeting a distinct narrowly-scoped IAM role).
#      The 3 AWS decoy roles deliberately have no credential spec, so
#      invoking one fails at credential minting.
#   5. Slack provider (optional, -slack-token=...) + 1 source + 1 spec
#      for the canvas-posting role; 1 decoy without a spec.
#   6. Per-role access policies. The AWS policy is uniform across all
#      five active AWS roles: read/create/list on path "aws/gateway" and
#      "aws/gateway/*" — Warden's AWS gateway cannot inspect SigV4
#      service/action at the policy layer, so per-lens least-privilege is
#      enforced AWS-side via the AssumeRole + IAM-role-policy chain.
#
# Requires:
#   - WARDEN_ADDR + WARDEN_TOKEN exported (admin shell from section 4).
#   - aws-out/creds.env populated by aws-init.sh.
#
# Usage:
#   ./warden-init.sh -anthropic-key=sk-...
#   ./warden-init.sh -anthropic-key=sk-... \
#                    -slack-token=xoxb-... \
#                    -slack-channel-id=C0XXXXXXX \
#                    -slack-channel-name='#access-audits' \
#                    -repo=siteowner/aws-access-hygiene
#
# -anthropic-key is required (the LLM key Warden hands to Goose at
# runtime; it never enters the agent's environment). It can also be
# passed via the ANTHROPIC_API_KEY env var.
#
# -slack-token is optional; without it the Slack provider/role/spec
# are skipped (the agent will fail the canvas post but Goose's audit
# still produces Security Hub findings).
set -euo pipefail

ANTHROPIC_KEY="${ANTHROPIC_API_KEY:-}"
SLACK_TOKEN="${SLACK_TOKEN:-}"
SLACK_CHANNEL_ID="${SLACK_CHANNEL_ID:-}"
SLACK_CHANNEL_NAME="${SLACK_CHANNEL_NAME:-}"
REPO="siteowner/aws-access-hygiene"

for arg in "$@"; do
  case $arg in
    --anthropic-key=*|-anthropic-key=*)           ANTHROPIC_KEY="${arg#*=}" ;;
    --slack-token=*|-slack-token=*)               SLACK_TOKEN="${arg#*=}" ;;
    --slack-channel-id=*|-slack-channel-id=*)     SLACK_CHANNEL_ID="${arg#*=}" ;;
    --slack-channel-name=*|-slack-channel-name=*) SLACK_CHANNEL_NAME="${arg#*=}" ;;
    --repo=*|-repo=*)                             REPO="${arg#*=}" ;;
    *) echo "unknown arg: $arg" >&2; exit 1 ;;
  esac
done

if [ -z "$ANTHROPIC_KEY" ]; then
  echo "ERROR: pass -anthropic-key=sk-... or set ANTHROPIC_API_KEY" >&2
  echo "       (this is the LLM key Warden hands to Goose at runtime; never enters the agent env)" >&2
  exit 1
fi

if [ -n "$SLACK_TOKEN" ] && { [ -z "$SLACK_CHANNEL_ID" ] || [ -z "$SLACK_CHANNEL_NAME" ]; }; then
  echo "ERROR: -slack-token requires -slack-channel-id=C... and -slack-channel-name=#..." >&2
  exit 1
fi

if [ ! -f aws-out/creds.env ]; then
  echo "ERROR: aws-out/creds.env missing — run ./aws-init.sh first" >&2
  exit 1
fi
. ./aws-out/creds.env

WARDEN="${WARDEN:-warden}"
command -v "$WARDEN" >/dev/null 2>&1 || { [ -x ./warden ] && WARDEN=./warden; } \
  || { echo "ERROR: warden binary not found. Set WARDEN=/path/to/warden" >&2; exit 1; }

# Bootstrap a file audit device. The dev server ships zero audit by
# default — the broker fail-opens at zero, so the cluster runs unaudited
# until we enable one. §10 of the README tails this file to verify
# per-call role attribution; without this step the file never exists.
if ! "$WARDEN" audit list 2>/dev/null | grep -q "^audit-default/"; then
  "$WARDEN" audit enable -file-path=./warden-audit.log -path=audit-default file
fi

BOUND_CLAIMS_FULL=$(printf '{"repository":"%s","ref":"refs/heads/main","ref_type":"branch"}' "$REPO")
BOUND_CLAIMS_REPO=$(printf '{"repository":"%s"}' "$REPO")

# 5a. Create the tutorial-aws namespace.
#
# The discovery loop hits /v1/sys/* as a bare JWT (no Warden session,
# no role segment in the URL). auto_auth_path tells Warden which auth
# mount to resolve those calls against.
$WARDEN namespace create tutorial-aws -metadata=auto_auth_path=auth/jwt/ 2>/dev/null || true
export WARDEN_NAMESPACE=tutorial-aws

# 5b. JWT auth pointed at Forgejo's Actions OIDC.
$WARDEN auth enable jwt 2>/dev/null || true
$WARDEN write auth/jwt/config \
    jwks_url=http://forgejo.local:3000/api/actions/.well-known/keys \
    bound_issuer=http://forgejo.local:3000/api/actions \
    default_audience=http://warden.local \
    default_role=discovery-baseline

# 5c. discovery-baseline role + policy.
$WARDEN write auth/jwt/role/discovery-baseline \
    description="Baseline namespace identity for any authenticated agent. Grants read on sys/introspect/roles, sys/providers, and sys/skills/*. No upstream credentials are minted by this role." \
    bound_audiences=http://warden.local \
    bound_claims="$BOUND_CLAIMS_REPO" \
    user_claim=sub

cat > /tmp/aws-tut-discovery-baseline.hcl <<'EOF'
# `warden provider list` and `warden skill list` send GET ?warden-list=true,
# which Warden classifies as LIST (not READ). The discovery loop needs
# both: `list` for the listings, `read` for per-record reads.
path "sys/introspect/roles" { capabilities = ["read"] }
path "sys/providers"        { capabilities = ["read", "list"] }
path "sys/providers/*"      { capabilities = ["read"] }
path "sys/skills"           { capabilities = ["read", "list"] }
path "sys/skills/*"         { capabilities = ["read"] }
EOF
$WARDEN policy write discovery-baseline /tmp/aws-tut-discovery-baseline.hcl

$WARDEN write auth/jwt/role/discovery-baseline \
    token_policies=discovery-baseline

# 5d. AWS provider, one source, five AssumeRole specs.
#
# auto_auth_path is REQUIRED on the AWS provider's config — unlike the
# vault provider where it's optional metadata. proxy_domains is not set
# here: it is only consulted by the S3 processors for virtual-hosted
# bucket URL rewriting, and this tutorial uses no S3 calls.
$WARDEN provider enable \
    -description="AWS gateway proxied via the warden-aws-tutorial-broker IAM user — five lenses across IAM, CloudTrail, Access Analyzer, IAM Policy Simulator, and Security Hub. Each role's description names the AWS account its assumed IAM role lives in." \
    -path=aws aws 2>/dev/null || true
$WARDEN write aws/config \
    auto_auth_path=auth/jwt/

# Order matters: drop specs before source (specs reference source).
for spec in iam-reader-spec cloudtrail-reader-spec access-analyzer-reader-spec policy-simulator-spec securityhub-writer-spec; do
  $WARDEN cred spec delete -f "$spec" 2>/dev/null || true
done
$WARDEN cred source delete -f demo-aws-source 2>/dev/null || true

$WARDEN cred source create demo-aws-source -type=aws \
    -rotation-period=0 \
    -config=access_key_id="$WARDEN_AWS_BROKER_ACCESS_KEY_ID" \
    -config=secret_access_key="$WARDEN_AWS_BROKER_SECRET_ACCESS_KEY" \
    -config=region="$WARDEN_AWS_REGION"

# Five specs, one per active Warden role. The source is shared; the
# differentiator is the target IAM role ARN each spec assumes.
$WARDEN cred spec create iam-reader-spec -source demo-aws-source \
    -config mint_method=sts_assume_role \
    -config role_arn="$WARDEN_AWS_ROLE_IAM_READER_ARN" \
    -config session_name=warden-iam-reader \
    -config ttl=1h

$WARDEN cred spec create cloudtrail-reader-spec -source demo-aws-source \
    -config mint_method=sts_assume_role \
    -config role_arn="$WARDEN_AWS_ROLE_CLOUDTRAIL_READER_ARN" \
    -config session_name=warden-cloudtrail-reader \
    -config ttl=1h

$WARDEN cred spec create access-analyzer-reader-spec -source demo-aws-source \
    -config mint_method=sts_assume_role \
    -config role_arn="$WARDEN_AWS_ROLE_ACCESS_ANALYZER_ARN" \
    -config session_name=warden-access-analyzer \
    -config ttl=1h

$WARDEN cred spec create policy-simulator-spec -source demo-aws-source \
    -config mint_method=sts_assume_role \
    -config role_arn="$WARDEN_AWS_ROLE_POLICY_SIMULATOR_ARN" \
    -config session_name=warden-policy-simulator \
    -config ttl=1h

$WARDEN cred spec create securityhub-writer-spec -source demo-aws-source \
    -config mint_method=sts_assume_role \
    -config role_arn="$WARDEN_AWS_ROLE_SECURITYHUB_WRITER_ARN" \
    -config session_name=warden-securityhub-writer \
    -config ttl=1h

# Five active Warden roles — each pointing at one spec. Descriptions
# carry what the agent needs to pick the right role per lens: what data
# it can access, what region's resources it covers, and what it is NOT
# for. The call-shape contract (env vars, URL pattern) lives in the AWS
# provider skill (warden skill read aws), not here.
$WARDEN write auth/jwt/role/iam-reader \
    description="Read-only IAM inventory in AWS account ${WARDEN_AWS_ACCOUNT_ID}: list roles, users, groups; read attached/inline policy documents, trust policies, and last-accessed data. IAM is a global service — applies account-wide. Not for STS AssumeRole into other accounts, not for IAM writes, not for CloudTrail or Access Analyzer." \
    bound_claims="$BOUND_CLAIMS_FULL" \
    cred_spec_name=iam-reader-spec \
    token_policies=aws-gateway-access

$WARDEN write auth/jwt/role/cloudtrail-reader \
    description="Read CloudTrail management-event history via LookupEvents in AWS account ${WARDEN_AWS_ACCOUNT_ID}, region ${WARDEN_AWS_REGION}. Not for trail configuration, not for data events, not for IAM data or Access Analyzer. Use when correlating IAM principals with actual API usage windows." \
    bound_claims="$BOUND_CLAIMS_FULL" \
    cred_spec_name=cloudtrail-reader-spec \
    token_policies=aws-gateway-access

$WARDEN write auth/jwt/role/access-analyzer-reader \
    description="Read IAM Access Analyzer external-trust findings (ListAnalyzers, ListFindings) in AWS account ${WARDEN_AWS_ACCOUNT_ID}, region ${WARDEN_AWS_REGION}. Not for archiving or resolving findings, not for analyzer configuration. Use when surfacing trust policies that allow external accounts or anonymous principals." \
    bound_claims="$BOUND_CLAIMS_FULL" \
    cred_spec_name=access-analyzer-reader-spec \
    token_policies=aws-gateway-access

$WARDEN write auth/jwt/role/policy-simulator-runner \
    description="Run IAM policy simulator (SimulatePrincipalPolicy) in AWS account ${WARDEN_AWS_ACCOUNT_ID} — read-only dry-run of effective access. IAM simulator is a global service — applies account-wide. Not for IAM data inventory or for live calls; use only to verify what a principal could do, not what it has done." \
    bound_claims="$BOUND_CLAIMS_FULL" \
    cred_spec_name=policy-simulator-spec \
    token_policies=aws-gateway-access

$WARDEN write auth/jwt/role/securityhub-writer \
    description="Write structured findings into AWS Security Hub via BatchImportFindings in AWS account ${WARDEN_AWS_ACCOUNT_ID}, region ${WARDEN_AWS_REGION}. Cannot read findings, cannot disable controls, cannot delete; ingest only. Use only after audit analysis is complete and findings are formatted to ASFF. Not for read-side audit work." \
    bound_claims="$BOUND_CLAIMS_FULL" \
    cred_spec_name=securityhub-writer-spec \
    token_policies=aws-gateway-access

# Three AWS decoy roles — same JWT identity, descriptions that warn off,
# and NO cred_spec_name so invocation fails at credential minting before
# any AWS call leaves Warden. They exist for the agent to read and
# reject by description: proof that the picker is description-driven,
# not provider-typed.
$WARDEN write auth/jwt/role/iam-admin \
    description="Administer IAM: create/delete principals, attach/detach policies, rotate access keys. Destructive scope; do not pick for any audit, simulator, or finding-publication task." \
    bound_claims="$BOUND_CLAIMS_REPO" \
    token_policies=discovery-baseline \
    user_claim=sub

$WARDEN write auth/jwt/role/securityhub-admin \
    description="Administer Security Hub: enable/disable controls, manage insights, delete findings, configure subscriptions. Destructive; do not pick for finding-import-only tasks." \
    bound_claims="$BOUND_CLAIMS_REPO" \
    token_policies=discovery-baseline \
    user_claim=sub

$WARDEN write auth/jwt/role/account-root-bridge \
    description="Bridge to root-account-level operations via STS AssumeRole into the management account. Break-glass only; do not pick for routine audits or read-only inventory." \
    bound_claims="$BOUND_CLAIMS_REPO" \
    token_policies=discovery-baseline \
    user_claim=sub

# Access policy for the AWS gateway. One policy, attached to all five
# active AWS roles. It is identical across roles because Warden's AWS
# gateway cannot distinguish service/action at the policy layer (no
# ParseStreamBody on the aws provider). Per-lens least-privilege lives
# at the AssumeRole + IAM-role-policy layer, set up by aws-init.sh.
cat > /tmp/aws-tut-aws-gateway-access.hcl <<'EOF'
# AWS uses both GET (read) and POST (create) extensively, and warden
# classifies paginated GET ?list=true as LIST. Grant all three on the
# gateway path; service/action scoping is AWS-side via the assumed role.
path "aws/gateway"   { capabilities = ["read", "create", "list"] }
path "aws/gateway/*" { capabilities = ["read", "create", "list"] }
EOF
$WARDEN policy write aws-gateway-access /tmp/aws-tut-aws-gateway-access.hcl

# 5e. Anthropic provider — Goose's LLM leg.
#
# Goose's Anthropic SDK is configured by the runtime (ANTHROPIC_HOST +
# ANTHROPIC_API_KEY=<JWT>) before the agent process starts. This is
# not part of the agent's discovery loop — it's wired in for the
# Goose runtime itself. The role is marked "Internal" so an agent
# does not pick it for a task.
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
    description="LLM inference for the access-hygiene auditor agent. Used internally by Goose — agents do not call this role directly." \
    bound_claims="$BOUND_CLAIMS_FULL" \
    cred_spec_name=anthropic-ops \
    token_policies=anthropic-ops

cat > /tmp/aws-tut-anthropic-ops.hcl <<'EOF'
path "anthropic/role/anthropic-ops/gateway/v1/messages" { capabilities = ["create"] }
path "anthropic/role/anthropic-ops/gateway/v1/models"   { capabilities = ["read"] }
EOF
$WARDEN policy write anthropic-ops /tmp/aws-tut-anthropic-ops.hcl

# 5f. Slack provider (optional).
if [ -n "$SLACK_TOKEN" ]; then
  $WARDEN provider enable \
      -description="Slack workspace for access-audit canvas reports — channel embedded in the hygiene-poster role description" \
      -path=slack slack 2>/dev/null || true
  $WARDEN write slack/config slack_url=https://slack.com/api auto_auth_path=auth/jwt/

  $WARDEN cred spec delete -f hygiene-poster-spec 2>/dev/null || true
  $WARDEN cred source delete -f demo-slack-source 2>/dev/null || true
  $WARDEN cred source create demo-slack-source -type=apikey \
      -rotation-period=0 \
      -config=api_url=https://slack.com/api \
      -config=verify_endpoint=/auth.test \
      -config=verify_method=POST
  $WARDEN cred spec create hygiene-poster-spec -source demo-slack-source \
      -config api_key="$SLACK_TOKEN"

  $WARDEN write auth/jwt/role/hygiene-poster \
      description="Post hygiene canvases to ${SLACK_CHANNEL_NAME} (${SLACK_CHANNEL_ID}) via the Slack provider at /v1/tutorial-aws/slack/. Canvas create/update + one-line notify. Not for alerts or incident dispatch." \
      bound_claims="$BOUND_CLAIMS_FULL" \
      cred_spec_name=hygiene-poster-spec \
      token_policies=slack-hygiene-poster

  cat > /tmp/aws-tut-slack-hygiene-poster.hcl <<'EOF'
# Slack Web API is all POST, so every method maps to the create capability.
path "slack/role/hygiene-poster/gateway/conversations.info"            { capabilities = ["create"] }
path "slack/role/hygiene-poster/gateway/conversations.canvases.create" { capabilities = ["create"] }
path "slack/role/hygiene-poster/gateway/canvases.create"               { capabilities = ["create"] }
path "slack/role/hygiene-poster/gateway/canvases.edit"                 { capabilities = ["create"] }
path "slack/role/hygiene-poster/gateway/canvases.delete"               { capabilities = ["create"] }
path "slack/role/hygiene-poster/gateway/chat.postMessage"              { capabilities = ["create"] }
path "slack/role/hygiene-poster/gateway/auth.test"                     { capabilities = ["create"] }
EOF
  $WARDEN policy write slack-hygiene-poster /tmp/aws-tut-slack-hygiene-poster.hcl

  $WARDEN write auth/jwt/role/alert-poster \
      description="Dispatch short alert pings to #ops-alerts via the Slack provider. One-line text messages only; not for canvases or hygiene reports." \
      bound_claims="$BOUND_CLAIMS_REPO" \
      token_policies=discovery-baseline \
      user_claim=sub

  echo "warden-init: section 5 complete (namespace=tutorial-aws, Slack delivery enabled)"
else
  echo "warden-init: section 5 complete (namespace=tutorial-aws, Slack delivery skipped — no -slack-token given)"
fi
