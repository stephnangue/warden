---
name: aws
description: "Call AWS services (S3, EC2, Lambda, DynamoDB, STS, …) through Warden's SigV4 gateway."
category: provider-guide
provider: aws
requires: []
upstream: AWS
---

# AWS through Warden

## What it does

Point your existing AWS SDK at Warden. The SDK signs requests with
SigV4 as usual; Warden verifies the signature, swaps in real AWS
credentials minted from a credential spec, and proxies to the target
AWS service. **No SDK code changes** — only env vars.

## Configure the CLI/SDK

Two values are per-task:
- `<role>` is the role you chose for this task. AWS is unusual: the
  role travels in `AWS_ACCESS_KEY_ID` (Warden reads it out of the SigV4
  Authorization header to pick the credential spec), **not** in the URL.
- `<gateway-url>` is the gateway URL for that role, embedded in the
  role's `description` returned by the `list_roles` MCP tool. It is a
  **relative** path — for AWS, mount-level: `/v1/<namespace>/<mount>/gateway`
  (e.g. `/v1/aws/gateway`, `/v1/team-data/aws-prod/gateway`). Prepend
  `$WARDEN_ADDR`.

Present your identity as the JWT placed in the SigV4 secret slots
(below); Warden verifies the signature against it. A stale JWT surfaces
as `SignatureDoesNotMatch` (typical JWT TTL 5–60 min) — refresh the JWT
and retry.

```bash
export AWS_ACCESS_KEY_ID="<role>"               # Warden role name, not an AWS key
export AWS_SECRET_ACCESS_KEY="<jwt>"
export AWS_SESSION_TOKEN="<jwt>"                # Warden detects "eyJ" prefix
export AWS_ENDPOINT_URL="$WARDEN_ADDR<gateway-url>"
```

The role-selection idiom is non-obvious: **`AWS_ACCESS_KEY_ID` carries
the Warden role name** (not an AWS access key). Warden reads it from
the SigV4 Authorization header to decide which credential spec to
use. To act as a different role, set `AWS_ACCESS_KEY_ID` to that role's
name. If Warden can't resolve a role from the key, it falls back to the
mount's `default_role`, when the operator has configured one.

## Examples

```bash
# Smoke test — confirms identity vehicle + role binding work
aws sts get-caller-identity

# S3
aws s3 ls
aws s3 cp local.txt s3://my-bucket/

# EC2
aws ec2 describe-instances --region us-east-1

# Lambda
aws lambda list-functions
```

For any AWS service: just run the normal SDK or CLI command. Warden
extracts the service and region from the SigV4 Authorization header.

## Quirks

- **JWT expiry → `SignatureDoesNotMatch`.** The SDK signed with a
  token Warden later rejects. Refresh the JWT and retry — the
  symptom is signature, the cause is auth.
- **Wildcard DNS for S3 control-plane and S3 Access Points.** The
  SDK constructs URLs like `<account-id>.s3-control.<region>.<warden-host>`
  for S3 Control APIs; the host needs to resolve to Warden. See
  `provider/aws/README.md` § DNS Configuration for `dnsmasq`,
  `nip.io`, and production wildcard setup.
- **MRAP S3 data-plane (GetObject/PutObject through a Multi-Region
  Access Point) is unsupported.** The SDK uses SigV4A and bypasses
  `AWS_ENDPOINT_URL`. Use the underlying regional bucket directly.
  MRAP control-plane (create, policy, tagging) works fine.
- **S3 Directory Buckets, S3 Table Buckets, S3 Vector Buckets are not
  supported** (different signing or endpoint conventions Warden
  doesn't yet implement).
- Standard Single-Region Access Points work; the ARN goes in the
  request path and Warden routes correctly.

