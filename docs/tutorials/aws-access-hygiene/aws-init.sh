#!/usr/bin/env bash
# Idempotent AWS-side bootstrap for the aws-access-hygiene tutorial.
#
# Provisions, in the reader's sandbox AWS account:
#   1. One broker IAM user (default: warden-aws-tutorial-broker) whose
#      only permission is sts:AssumeRole on the five role ARNs below.
#      Its long-lived access keys are what Warden holds. The keys cannot
#      be used to do anything operational on their own.
#   2. Five IAM roles, each with a trust policy admitting only the broker
#      user as a principal and a narrow inline permissions policy
#      matching its purpose:
#        tutorial-iam-reader-role          → iam:Get*, iam:List*
#        tutorial-cloudtrail-reader-role   → cloudtrail:LookupEvents,
#                                            cloudtrail:Describe*
#        tutorial-access-analyzer-role     → access-analyzer:Get*,
#                                            access-analyzer:List*
#        tutorial-policy-simulator-role    → iam:SimulatePrincipalPolicy
#        tutorial-securityhub-writer-role  → securityhub:BatchImportFindings
#   3. Writes the broker access keys and the five role ARNs to
#      aws-out/creds.env, which warden-init.sh sources.
#
# Idempotent: re-running with the same name prefix is safe. Existing
# users/roles/policies are left alone; missing pieces are created. The
# broker access key is rotated only when --rotate-key is passed
# (otherwise existing keys are preserved).
#
# Requires:
#   - aws CLI v2, logged in as a principal that can create IAM users/roles
#     and access keys in the chosen sandbox account.
#   - jq (used for trust-policy JSON construction).
#
# Usage:
#   ./aws-init.sh
#   ./aws-init.sh --account-id=123456789012 --name-prefix=tutorial
#   ./aws-init.sh --rotate-key      # forces a new access key
set -euo pipefail

ACCOUNT_ID=""
NAME_PREFIX="tutorial"
BROKER_NAME="warden-aws-tutorial-broker"
REGION="us-east-1"
ROTATE_KEY="false"

for arg in "$@"; do
  case $arg in
    --account-id=*)   ACCOUNT_ID="${arg#--account-id=}" ;;
    --name-prefix=*)  NAME_PREFIX="${arg#--name-prefix=}" ;;
    --broker-name=*)  BROKER_NAME="${arg#--broker-name=}" ;;
    --region=*)       REGION="${arg#--region=}" ;;
    --rotate-key)     ROTATE_KEY="true" ;;
    *) echo "unknown arg: $arg" >&2; exit 1 ;;
  esac
done

command -v aws >/dev/null 2>&1 || { echo "ERROR: aws CLI not found" >&2; exit 1; }
command -v jq  >/dev/null 2>&1 || { echo "ERROR: jq not found" >&2; exit 1; }

if [ -z "$ACCOUNT_ID" ]; then
  ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
fi

BROKER_ARN="arn:aws:iam::${ACCOUNT_ID}:user/${BROKER_NAME}"
ROLE_IAM_READER="${NAME_PREFIX}-iam-reader-role"
ROLE_CLOUDTRAIL_READER="${NAME_PREFIX}-cloudtrail-reader-role"
ROLE_ACCESS_ANALYZER="${NAME_PREFIX}-access-analyzer-role"
ROLE_POLICY_SIMULATOR="${NAME_PREFIX}-policy-simulator-role"
ROLE_SECURITYHUB_WRITER="${NAME_PREFIX}-securityhub-writer-role"

ROLE_NAMES=(
  "$ROLE_IAM_READER"
  "$ROLE_CLOUDTRAIL_READER"
  "$ROLE_ACCESS_ANALYZER"
  "$ROLE_POLICY_SIMULATOR"
  "$ROLE_SECURITYHUB_WRITER"
)

# 1. Broker IAM user.
if aws iam get-user --user-name "$BROKER_NAME" >/dev/null 2>&1; then
  echo "aws-init: broker user '$BROKER_NAME' already exists"
else
  aws iam create-user --user-name "$BROKER_NAME" >/dev/null
  echo "aws-init: created broker user '$BROKER_NAME'"
fi

# 2. Five IAM roles, each trusting only the broker user.
#
# Why a fresh trust policy per role rather than a shared assume-role
# principal: each role's trust statement names the broker by ARN, so if
# the broker is ever recreated under a different account or path,
# updating the trust policies is the single point of change.
TRUST_POLICY=$(jq -n --arg arn "$BROKER_ARN" '{
  Version: "2012-10-17",
  Statement: [{
    Effect: "Allow",
    Principal: { AWS: $arn },
    Action: "sts:AssumeRole"
  }]
}')

create_or_update_role () {
  local role_name="$1"
  if aws iam get-role --role-name "$role_name" >/dev/null 2>&1; then
    aws iam update-assume-role-policy \
      --role-name "$role_name" \
      --policy-document "$TRUST_POLICY" >/dev/null
    echo "aws-init: refreshed trust policy on role '$role_name'"
  else
    aws iam create-role \
      --role-name "$role_name" \
      --assume-role-policy-document "$TRUST_POLICY" \
      --description "Warden tutorial — narrowly-scoped role assumed via the broker user" \
      >/dev/null
    echo "aws-init: created role '$role_name'"
  fi
}

# Inline permission policies — each one names exactly the AWS actions
# that role's lens needs and nothing else. These are the AWS-layer
# enforcement of the read/write split: SecurityHub:BatchImportFindings is
# reachable only from the writer role; everything else is read-only.
PERMS_IAM_READER='{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["iam:Get*", "iam:List*"],
    "Resource": "*"
  }]
}'

PERMS_CLOUDTRAIL_READER='{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["cloudtrail:LookupEvents", "cloudtrail:Describe*", "cloudtrail:Get*"],
    "Resource": "*"
  }]
}'

PERMS_ACCESS_ANALYZER='{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["access-analyzer:Get*", "access-analyzer:List*"],
    "Resource": "*"
  }]
}'

PERMS_POLICY_SIMULATOR='{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["iam:SimulatePrincipalPolicy"],
    "Resource": "*"
  }]
}'

PERMS_SECURITYHUB_WRITER='{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["securityhub:BatchImportFindings"],
    "Resource": "*"
  }]
}'

attach_inline_policy () {
  local role_name="$1"
  local policy_name="$2"
  local policy_doc="$3"
  aws iam put-role-policy \
    --role-name "$role_name" \
    --policy-name "$policy_name" \
    --policy-document "$policy_doc" >/dev/null
  echo "aws-init: attached inline policy '$policy_name' to role '$role_name'"
}

for role in "${ROLE_NAMES[@]}"; do
  create_or_update_role "$role"
done

attach_inline_policy "$ROLE_IAM_READER"          "iam-read-only"           "$PERMS_IAM_READER"
attach_inline_policy "$ROLE_CLOUDTRAIL_READER"   "cloudtrail-read-only"    "$PERMS_CLOUDTRAIL_READER"
attach_inline_policy "$ROLE_ACCESS_ANALYZER"     "access-analyzer-read"    "$PERMS_ACCESS_ANALYZER"
attach_inline_policy "$ROLE_POLICY_SIMULATOR"    "policy-simulator-read"   "$PERMS_POLICY_SIMULATOR"
attach_inline_policy "$ROLE_SECURITYHUB_WRITER"  "securityhub-batch-write" "$PERMS_SECURITYHUB_WRITER"

# 3. Broker user policy — sts:AssumeRole on exactly those five role ARNs.
#
# No wildcards, no other actions. The broker cannot escalate.
BROKER_POLICY=$(jq -n \
  --arg r1 "arn:aws:iam::${ACCOUNT_ID}:role/${ROLE_IAM_READER}" \
  --arg r2 "arn:aws:iam::${ACCOUNT_ID}:role/${ROLE_CLOUDTRAIL_READER}" \
  --arg r3 "arn:aws:iam::${ACCOUNT_ID}:role/${ROLE_ACCESS_ANALYZER}" \
  --arg r4 "arn:aws:iam::${ACCOUNT_ID}:role/${ROLE_POLICY_SIMULATOR}" \
  --arg r5 "arn:aws:iam::${ACCOUNT_ID}:role/${ROLE_SECURITYHUB_WRITER}" \
  '{
    Version: "2012-10-17",
    Statement: [{
      Effect: "Allow",
      Action: "sts:AssumeRole",
      Resource: [$r1, $r2, $r3, $r4, $r5]
    }]
  }')

aws iam put-user-policy \
  --user-name "$BROKER_NAME" \
  --policy-name "assume-tutorial-roles" \
  --policy-document "$BROKER_POLICY" >/dev/null
echo "aws-init: attached AssumeRole policy to broker user"

# 4. Broker access key.
#
# IAM users can hold at most two active access keys. If --rotate-key was
# given we delete the existing key(s) before creating a new one.
# Otherwise: if exactly one key already exists we keep it (and emit
# creds.env with a placeholder note), and if zero exist we create one.
ACCESS_KEY_FILE="aws-out/access-key.json"
mkdir -p aws-out

current_key_count=$(aws iam list-access-keys --user-name "$BROKER_NAME" \
  --query 'length(AccessKeyMetadata)' --output text)

if [ "$ROTATE_KEY" = "true" ] && [ "$current_key_count" -gt 0 ]; then
  for k in $(aws iam list-access-keys --user-name "$BROKER_NAME" \
        --query 'AccessKeyMetadata[].AccessKeyId' --output text); do
    aws iam delete-access-key --user-name "$BROKER_NAME" --access-key-id "$k" >/dev/null
    echo "aws-init: rotated out access key '$k'"
  done
  current_key_count=0
fi

if [ "$current_key_count" -eq 0 ]; then
  aws iam create-access-key --user-name "$BROKER_NAME" > "$ACCESS_KEY_FILE"
  ACCESS_KEY_ID=$(jq -r '.AccessKey.AccessKeyId'     "$ACCESS_KEY_FILE")
  SECRET_ACCESS_KEY=$(jq -r '.AccessKey.SecretAccessKey' "$ACCESS_KEY_FILE")
  echo "aws-init: created new access key (saved to $ACCESS_KEY_FILE)"
elif [ -f "$ACCESS_KEY_FILE" ]; then
  ACCESS_KEY_ID=$(jq -r '.AccessKey.AccessKeyId'     "$ACCESS_KEY_FILE")
  SECRET_ACCESS_KEY=$(jq -r '.AccessKey.SecretAccessKey' "$ACCESS_KEY_FILE")
  echo "aws-init: reusing access key from $ACCESS_KEY_FILE"
else
  cat >&2 <<MSG
aws-init: broker user has an existing access key but $ACCESS_KEY_FILE
is missing. AWS does not let you re-read a secret access key after
creation. Re-run with --rotate-key to drop the orphan key and mint a
fresh one, or restore $ACCESS_KEY_FILE from a backup if you have one.
MSG
  exit 1
fi

# 5. Emit creds.env for warden-init.sh.
cat > aws-out/creds.env <<EOF
# Generated by aws-init.sh — sourced by warden-init.sh.
# Treat as a secret: it contains the broker IAM user's static credentials.
WARDEN_AWS_ACCOUNT_ID=${ACCOUNT_ID}
WARDEN_AWS_REGION=${REGION}
WARDEN_AWS_BROKER_NAME=${BROKER_NAME}
WARDEN_AWS_BROKER_ACCESS_KEY_ID=${ACCESS_KEY_ID}
WARDEN_AWS_BROKER_SECRET_ACCESS_KEY=${SECRET_ACCESS_KEY}

WARDEN_AWS_ROLE_IAM_READER_ARN=arn:aws:iam::${ACCOUNT_ID}:role/${ROLE_IAM_READER}
WARDEN_AWS_ROLE_CLOUDTRAIL_READER_ARN=arn:aws:iam::${ACCOUNT_ID}:role/${ROLE_CLOUDTRAIL_READER}
WARDEN_AWS_ROLE_ACCESS_ANALYZER_ARN=arn:aws:iam::${ACCOUNT_ID}:role/${ROLE_ACCESS_ANALYZER}
WARDEN_AWS_ROLE_POLICY_SIMULATOR_ARN=arn:aws:iam::${ACCOUNT_ID}:role/${ROLE_POLICY_SIMULATOR}
WARDEN_AWS_ROLE_SECURITYHUB_WRITER_ARN=arn:aws:iam::${ACCOUNT_ID}:role/${ROLE_SECURITYHUB_WRITER}
EOF

chmod 600 aws-out/creds.env
echo "aws-init: wrote aws-out/creds.env"
echo "aws-init: done. Run warden-init.sh next."
