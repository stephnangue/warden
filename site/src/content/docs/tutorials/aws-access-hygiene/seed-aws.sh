#!/usr/bin/env bash
# Idempotent AWS-side seed of audit-target IAM roles for the
# aws-access-hygiene tutorial.
#
# These targets are distinct from the broker user and the five
# AssumeRole-backed roles provisioned by aws-init.sh, which power
# Warden's specs. The targets exist purely to give the audit something
# interesting to find.
#
# What gets seeded:
#   1. tutorial-target-clean-role
#      Clean baseline — narrow scope, no smells. Anchor for contrast.
#   2. tutorial-target-wildcard-role
#      Triggers the inventory lens: attached inline policy with
#      Action "iam:*" + Resource "*".
#   3. tutorial-target-stale-role
#      Triggers the usage lens: created here, never invoked elsewhere,
#      so LastUsed is null. The audit treats "no recorded activity in
#      the last 90 days" as stale — null/never-used fits.
#   4. tutorial-target-external-trust-role
#      Triggers the exposure lens: trust policy admits a non-self
#      account ID (default: 999999999999). Access Analyzer flags this
#      as external trust.
#   5. tutorial-target-under-described-role
#      Triggers the effective-access lens: description claims "read-only
#      S3 bucket inventory" but the attached policy grants s3:* on *.
#      The simulator dry-run surfaces the mismatch.
#
# Idempotent — re-runnable; existing targets are left alone. Use
# --teardown to remove them.
#
# Requires:
#   - aws CLI v2, logged in as a principal that can create IAM roles
#     and attach inline policies in the chosen sandbox account.
#   - jq.
#
# Usage:
#   ./seed-aws.sh
#   ./seed-aws.sh --account-id=123456789012
#   ./seed-aws.sh --external-account-id=222222222222
#   ./seed-aws.sh --teardown
set -euo pipefail

ACCOUNT_ID=""
EXTERNAL_ACCOUNT_ID="999999999999"
TEARDOWN="false"

for arg in "$@"; do
  case $arg in
    --account-id=*)          ACCOUNT_ID="${arg#--account-id=}" ;;
    --external-account-id=*) EXTERNAL_ACCOUNT_ID="${arg#--external-account-id=}" ;;
    --teardown)              TEARDOWN="true" ;;
    *) echo "unknown arg: $arg" >&2; exit 1 ;;
  esac
done

command -v aws >/dev/null 2>&1 || { echo "ERROR: aws CLI not found" >&2; exit 1; }
command -v jq  >/dev/null 2>&1 || { echo "ERROR: jq not found" >&2; exit 1; }

if [ -z "$ACCOUNT_ID" ]; then
  ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
fi

# All five targets get a self-trust policy so they're assumable in
# principle by anything inside the account — keeps them realistic
# without trusting anything outside. The external-trust target
# overrides this with a cross-account trust.
SELF_TRUST=$(jq -n --arg arn "arn:aws:iam::${ACCOUNT_ID}:root" '{
  Version: "2012-10-17",
  Statement: [{
    Effect: "Allow",
    Principal: { AWS: $arn },
    Action: "sts:AssumeRole"
  }]
}')

EXTERNAL_TRUST=$(jq -n --arg arn "arn:aws:iam::${EXTERNAL_ACCOUNT_ID}:root" '{
  Version: "2012-10-17",
  Statement: [{
    Effect: "Allow",
    Principal: { AWS: $arn },
    Action: "sts:AssumeRole"
  }]
}')

# Inline permission policies — each one is shaped to trip exactly the
# lens the role's name advertises. Names are agent-facing in the
# audit; descriptions matter too.
PERMS_NARROW='{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:GetObject"],
    "Resource": "arn:aws:s3:::tutorial-target-clean-bucket/*"
  }]
}'

PERMS_WILDCARD='{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "iam:*",
    "Resource": "*"
  }]
}'

PERMS_STALE='{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["cloudwatch:GetMetricData"],
    "Resource": "*"
  }]
}'

PERMS_UNDER_DESCRIBED='{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "s3:*",
    "Resource": "*"
  }]
}'

ROLE_CLEAN="tutorial-target-clean-role"
ROLE_WILDCARD="tutorial-target-wildcard-role"
ROLE_STALE="tutorial-target-stale-role"
ROLE_EXTERNAL_TRUST="tutorial-target-external-trust-role"
ROLE_UNDER_DESCRIBED="tutorial-target-under-described-role"

ALL_TARGETS=(
  "$ROLE_CLEAN"
  "$ROLE_WILDCARD"
  "$ROLE_STALE"
  "$ROLE_EXTERNAL_TRUST"
  "$ROLE_UNDER_DESCRIBED"
)

teardown_role () {
  local role_name="$1"
  if ! aws iam get-role --role-name "$role_name" >/dev/null 2>&1; then
    echo "seed-aws: target '$role_name' not present"
    return 0
  fi
  for policy in $(aws iam list-role-policies --role-name "$role_name" \
        --query 'PolicyNames[]' --output text); do
    aws iam delete-role-policy --role-name "$role_name" --policy-name "$policy" >/dev/null
  done
  aws iam delete-role --role-name "$role_name" >/dev/null
  echo "seed-aws: removed target '$role_name'"
}

if [ "$TEARDOWN" = "true" ]; then
  for role in "${ALL_TARGETS[@]}"; do
    teardown_role "$role"
  done
  echo "seed-aws: teardown complete"
  exit 0
fi

# Seed (idempotent).
seed_role () {
  local role_name="$1"
  local trust_policy="$2"
  local description="$3"
  local inline_policy_name="$4"
  local inline_policy_doc="$5"

  if aws iam get-role --role-name "$role_name" >/dev/null 2>&1; then
    aws iam update-assume-role-policy \
      --role-name "$role_name" \
      --policy-document "$trust_policy" >/dev/null
    aws iam update-role \
      --role-name "$role_name" \
      --description "$description" >/dev/null
    echo "seed-aws: refreshed target '$role_name'"
  else
    aws iam create-role \
      --role-name "$role_name" \
      --assume-role-policy-document "$trust_policy" \
      --description "$description" \
      >/dev/null
    echo "seed-aws: created target '$role_name'"
  fi

  aws iam put-role-policy \
    --role-name "$role_name" \
    --policy-name "$inline_policy_name" \
    --policy-document "$inline_policy_doc" >/dev/null
}

# Role descriptions read like ops-written role notes — they do NOT
# state what the audit should find. The audit must reach its
# conclusions from underlying data (attached policies, RoleLastUsed,
# trust policies, simulator output). The one exception is the
# under-described target, whose description is deliberately narrower
# than its actual policy — that mismatch is what the effective_access
# lens is built to catch.

seed_role "$ROLE_CLEAN" "$SELF_TRUST" \
  "S3 GetObject for the internal ETL job that reads tutorial-target-clean-bucket." \
  "clean-narrow" "$PERMS_NARROW"

seed_role "$ROLE_WILDCARD" "$SELF_TRUST" \
  "Legacy platform-team IAM admin role — used during account bootstrap and still attached for break-glass." \
  "wildcard-iam" "$PERMS_WILDCARD"

seed_role "$ROLE_STALE" "$SELF_TRUST" \
  "Metrics reader for the deprecated Q2 dashboards prototype." \
  "stale-metrics-reader" "$PERMS_STALE"

seed_role "$ROLE_EXTERNAL_TRUST" "$EXTERNAL_TRUST" \
  "Cross-account audit role granting read access from partner-org account ${EXTERNAL_ACCOUNT_ID}." \
  "external-trust-empty" "$PERMS_NARROW"

seed_role "$ROLE_UNDER_DESCRIBED" "$SELF_TRUST" \
  "Read-only S3 bucket inventory for the data-discovery team." \
  "under-described-s3" "$PERMS_UNDER_DESCRIBED"

echo "seed-aws: seeded 5 audit-target roles"
echo "seed-aws: Access Analyzer findings for '${ROLE_EXTERNAL_TRUST}' may take a few minutes to appear."
