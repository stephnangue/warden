---
name: aws
description: "Call AWS services (S3, EC2, Lambda, DynamoDB, STS, …) through Warden's SigV4 gateway."
category: provider-guide
provider: aws
upstream: AWS
---

# AWS through Warden

## What it does

Point your existing AWS SDK at Warden. The SDK signs requests with
SigV4 as usual; Warden verifies the signature, swaps in real AWS
credentials minted from a credential spec, and proxies to the target
AWS service. **No SDK code changes** — only env vars.

## Configure the CLI/SDK

`<mount>` and `<role-name>` below come from the discovery flow:
- `<mount>` is the chosen provider's path from `warden provider list`
  (e.g. `aws/`, `aws-prod/` — whichever your task matches).
- `<role-name>` is the role you picked from `warden role list` to perform
  this task.

The JWT (`$JWT`) is provided to the agent's environment by its
runtime — see `warden-shared`. Just use it:

```bash
export AWS_ACCESS_KEY_ID="<role-name>"          # role from `warden role list`
export AWS_SECRET_ACCESS_KEY="$JWT"
export AWS_SESSION_TOKEN="$JWT"                 # Warden detects "eyJ" prefix
export AWS_ENDPOINT_URL="$WARDEN_ADDR/v1/<mount>/gateway"
```

The role-selection idiom is non-obvious: **`AWS_ACCESS_KEY_ID` carries
the Warden role name** (not an AWS access key). Warden reads it from
the SigV4 Authorization header to decide which credential spec to
use.

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

