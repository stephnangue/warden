# AWS Provider

The AWS provider enables proxied access to AWS services through Warden. It intercepts AWS SDK requests, verifies the client's signature using Warden-issued credentials, re-signs the request with real AWS credentials, and forwards it to the target AWS endpoint. This allows Warden to broker access to any AWS service without exposing real credentials to clients.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Step 1: Create the IAM User](#step-1-create-the-iam-user)
- [Step 2: Attach IAM Policies](#step-2-attach-iam-policies)
- [Step 3: Create Target IAM Roles](#step-3-create-target-iam-roles)
- [Step 4: Mount the AWS Provider](#step-4-mount-the-aws-provider)
- [Step 5: Create a Credential Source](#step-5-create-a-credential-source)
- [Step 6: Configure the Provider](#step-6-configure-the-provider)
- [Step 7: Create Credential Specs](#step-7-create-credential-specs)
- [Step 8: Create a Policy](#step-8-create-a-policy)
- [Step 9: Configure JWT Auth and Create a Role](#step-9-configure-jwt-auth-and-create-a-role)
- [Step 10: Make Requests Through the Gateway](#step-10-make-requests-through-the-gateway)
- [Architecture Overview](#architecture-overview)
- [DNS Configuration](#dns-configuration)
- [Configuration Reference](#configuration-reference)
- [Supported AWS Services](#supported-aws-services)
- [Known Limitations](#known-limitations)
- [Troubleshooting](#troubleshooting)

## Prerequisites

- A running Warden server
- The Warden CLI installed and configured
- AWS account with IAM access
- AWS CLI (for initial IAM setup)

```bash
export WARDEN_ADDR="http://127.0.0.1:8400"
export WARDEN_TOKEN="<your-token>"
```

## Step 1: Create the IAM User

Create a dedicated IAM user for Warden. This user holds long-lived access keys that Warden rotates automatically.

```bash
aws iam create-user --user-name warden-cred-source-root
aws iam create-access-key --user-name warden-cred-source-root
```

Save the `AccessKeyId` and `SecretAccessKey` from the output.

## Step 2: Attach IAM Policies

The user needs two policies:

### SelfManageAccessKeys

Allows the user to rotate its own access keys. Warden uses this during credential rotation to create new keys and delete old ones.

```bash
aws iam put-user-policy \
  --user-name warden-cred-source-root \
  --policy-name SelfManageAccessKeys \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": [
          "iam:CreateAccessKey",
          "iam:DeleteAccessKey",
          "iam:ListAccessKeys"
        ],
        "Resource": "arn:aws:iam::<ACCOUNT_ID>:user/warden-cred-source-root"
      }
    ]
  }'
```

### AssumeRoles

Allows the user to assume roles that grant actual permissions. Scope the `Resource` to match your role naming conventions.

```bash
aws iam put-user-policy \
  --user-name warden-cred-source-root \
  --policy-name AssumeRoles \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": "sts:AssumeRole",
        "Resource": [
          "arn:aws:iam::<ACCOUNT_ID>:role/devops-*",
          "arn:aws:iam::<ACCOUNT_ID>:role/internal-secrets-manager-access"
        ]
      }
    ]
  }'
```

## Step 3: Create Target IAM Roles

Create the roles that consumers will assume through Warden. The trust policy must allow the IAM user to assume the role.

```bash
aws iam create-role \
  --role-name devops-warden-role \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Principal": {
          "AWS": "arn:aws:iam::<ACCOUNT_ID>:user/warden-cred-source-root"
        },
        "Action": "sts:AssumeRole"
      }
    ]
  }'
```

Attach the permissions policies your consumers need to this role (e.g., S3 access, EC2 management).

## Step 4: Mount the AWS Provider

Enable the AWS provider at a path of your choice:

```bash
warden provider enable --type=aws
```

To mount at a custom path:

```bash
warden provider enable --type=aws aws-prod
```

Verify the provider is enabled:

```bash
warden provider list
```

## Step 5: Create a Credential Source

The credential source tells Warden how to authenticate to AWS and where the base credentials live.

```bash
warden cred source create my-aws-source \
  --type aws \
  --rotation-period 24h \
  --config access_key_id=AKIA... \
  --config secret_access_key=... \
  --config region=us-east-1
```

The `--rotation-period` controls how often Warden rotates the base IAM access keys. Since the IAM user can only manage its own keys and assume roles (no direct resource access), longer periods are acceptable (e.g., `720h` / 30 days). For stricter environments, use shorter periods (e.g., `12h`-`24h`).

Verify:

```bash
warden cred source read my-aws-source
```

## Step 6: Configure the Provider

Configure the provider with proxy domains and timeouts:

```bash
warden write aws/config <<EOF
{
  "proxy_domains": ["localhost"],
  "max_body_size": 10485760,
  "timeout": "30s"
}
EOF
```

For production, set `proxy_domains` to your Warden server's domain (see [DNS Configuration](#dns-configuration)).

Verify:

```bash
warden read aws/config
```

## Step 7: Create Credential Specs

A credential spec defines what temporary credentials Warden mints for consumers. Multiple specs can share the same source, each assuming a different role with different permissions and TTLs.

### STS AssumeRole (Recommended)

```bash
# Spec for developers — read-only access, short TTL
warden cred spec create developer \
  --type aws_access_keys \
  --source my-aws-source \
  --config mint_method=sts_assume_role \
  --config role_arn=arn:aws:iam::<ACCOUNT_ID>:role/devops-readonly-role \
  --config ttl=1h \
  --min-ttl 600s \
  --max-ttl 2h

# Spec for CI/CD pipelines — deploy permissions
warden cred spec create deployer \
  --type aws_access_keys \
  --source my-aws-source \
  --config mint_method=sts_assume_role \
  --config role_arn=arn:aws:iam::<ACCOUNT_ID>:role/devops-deploy-role \
  --config ttl=30m \
  --min-ttl 600s \
  --max-ttl 1h

# Spec for operators — full access, longer TTL
warden cred spec create operator \
  --type aws_access_keys \
  --source my-aws-source \
  --config mint_method=sts_assume_role \
  --config role_arn=arn:aws:iam::<ACCOUNT_ID>:role/devops-operator-role \
  --config ttl=2h \
  --min-ttl 600s \
  --max-ttl 4h
```

Each spec points to a different `role_arn`, so the IAM user's `AssumeRoles` policy must allow assuming all of them (the `devops-*` wildcard in Step 2 covers this).

### Secrets Manager

The `secrets_manager` mint method fetches credentials from AWS Secrets Manager. The base IAM user doesn't have Secrets Manager permissions, so the **source** needs `assume_role_arn` to assume a role that does:

```bash
# Source with elevated permissions for Secrets Manager
warden cred source create my-aws-source-sm \
  --type aws \
  --rotation-period 720h \
  --config access_key_id=AKIA... \
  --config secret_access_key=... \
  --config region=us-east-1 \
  --config assume_role_arn=arn:aws:iam::<ACCOUNT_ID>:role/internal-secrets-manager-access

# Spec that fetches a secret
warden cred spec create db-creds \
  --type aws_access_keys \
  --source my-aws-source-sm \
  --config mint_method=secrets_manager \
  --config secret_id=prod/database/credentials
```

## Step 8: Create a Policy

Create a policy that grants access to the AWS provider gateway:

```bash
warden policy write aws-access - <<EOF
path "aws/gateway*" {
  capabilities = ["read", "create", "update", "delete", "patch"]
}
EOF
```

Verify:

```bash
warden policy read aws-access
```

## Step 9: Configure JWT Auth and Create a Role

Set up a JWT auth method and create a role that binds the credential spec and policy:

```bash
# Enable JWT auth if not already enabled
warden auth enable --type=jwt

# Configure JWT (e.g., with JWKS URL)
warden write auth/jwt/config mode=jwt jwks_url=https://your-idp/.well-known/jwks.json

# Create a role that binds the credential spec and policy
warden write auth/jwt/role/aws-user \
    token_type=aws_access_keys \
    token_policies="aws-access" \
    user_claim=sub \
    cred_spec_name=developer \
    token_ttl=1h
```

## Step 10: Make Requests Through the Gateway

### Login and Extract Credentials

```bash
LOGIN_OUTPUT=$(warden login --method=jwt --token=$JWT --role=aws-user)

export AWS_ACCESS_KEY_ID=$(echo "$LOGIN_OUTPUT" | grep "| data" | sed 's/.*access_key_id=\([^,]*\).*/\1/')
export AWS_SECRET_ACCESS_KEY=$(echo "$LOGIN_OUTPUT" | grep "| data" | sed 's/.*secret_access_key=\([^ |]*\).*/\1/')
```

### Use the Gateway Proxy

Point the AWS SDK at the Warden gateway endpoint:

```bash
export AWS_ENDPOINT_URL=http://localhost:8400/v1/aws/gateway
```

Then use the AWS CLI or SDK as normal — all requests are proxied through Warden:

```bash
# S3
aws s3 ls
aws s3 cp file.txt s3://my-bucket/

# EC2
aws ec2 describe-instances

# DynamoDB
aws dynamodb list-tables

# Any other AWS service
aws lambda list-functions
```

Warden verifies the client's signature, re-signs the request with real AWS credentials, and proxies it to the target service. The response is returned directly to the client.

## Architecture Overview

```
                          +-----------------------------+
                          |  AWS IAM User               |
                          |  warden-cred-source-root    |
                          |                             |
                          |  Policies:                  |
                          |  - SelfManageAccessKeys     |
                          |  - AssumeRoles (devops-*,   |
                          |    internal-*)              |
                          +--------+--------------------+
                                   |
              +--------------------+--------------------+
              |                    |                     |
       IAM key rotation    sts:AssumeRole         sts:AssumeRole
       (self-management)         |                      |
              |          +-------v--------+   +---------v-----------+
              |          | devops-*       |   | internal-*          |
              |          | roles          |   | roles               |
              |          | (consumer      |   | (source driver      |
              |          |  permissions)  |   |  permissions, e.g.  |
              |          +-------+--------+   |  Secrets Manager)   |
              |                  |             +---------+-----------+
              v                  v                       v
       Warden rotates     Warden mints           Source driver
       base keys          STS creds for           uses elevated
       periodically       consumers               permissions
```

### Request Flow

1. Client signs request with Warden-issued credentials (Access Key ID / Secret Access Key)
2. Request is sent to Warden gateway endpoint
3. Warden verifies the incoming SigV4 signature using the stored secret key
4. Warden retrieves real AWS credentials from the credential spec
5. Warden re-signs the request with valid AWS credentials
6. Request is forwarded to the actual AWS endpoint
7. Response is returned to the client

### Security Model

- **Least privilege on the IAM user**: The user can only rotate its own keys and assume specific roles. If the base keys leak, the attacker still needs to know which roles to assume.
- **Short-lived consumer credentials**: STS credentials expire automatically (controlled by TTL). No long-lived secrets are exposed to consumers.
- **Automatic key rotation**: Warden rotates the base IAM keys on the configured schedule, limiting the window of exposure for any single key pair.
- **Audit trail**: Each STS AssumeRole call is logged in CloudTrail with a distinct session name.

## DNS Configuration

The AWS provider requires **wildcard DNS configuration** for services that use virtual-hosted style URLs, particularly:

- **S3 Control API** (ListTagsForResource, GetAccessPointPolicy, etc.)
- **S3 Access Points**
- Any service where the account ID or resource name is prepended to the hostname

### How It Works

When AWS SDKs make S3 Control API requests, they construct URLs like:

```
https://<account-id>.s3-control.<region>.amazonaws.com/...
```

When proxied through Warden, the SDK rewrites the URL to:

```
https://<account-id>.<proxy-domain>:<port>/v1/aws/gateway/...
```

For example, with `proxy_domains=["localhost"]` and account `123456789012`:

```
https://123456789012.localhost:8400/v1/aws/gateway/v20180820/tags/...
```

### Local Development

**Option 1: dnsmasq (recommended for macOS)**

```bash
brew install dnsmasq
echo "address=/localhost/127.0.0.1" >> /opt/homebrew/etc/dnsmasq.conf
sudo brew services start dnsmasq
sudo mkdir -p /etc/resolver
echo "nameserver 127.0.0.1" | sudo tee /etc/resolver/localhost
```

**Option 2: Manual /etc/hosts (one account at a time)**

```
127.0.0.1 123456789012.localhost
```

**Option 3: Wildcard DNS service**

Services like [nip.io](https://nip.io) or [sslip.io](https://sslip.io) provide wildcard DNS:

```bash
warden write aws/config proxy_domains="127.0.0.1.nip.io"
```

### Production Setup

Configure wildcard DNS records pointing to your Warden server:

```
*.warden.yourdomain.com  →  A record or CNAME to Warden server
warden.yourdomain.com    →  A record to Warden server
```

Then configure Warden:

```bash
warden write aws/config proxy_domains="warden.yourdomain.com"
```

For HTTPS, you'll need a **wildcard SSL certificate** (`*.warden.yourdomain.com`), obtainable from Let's Encrypt (free, via DNS-01 challenge), commercial CAs, or internal PKI.

## Configuration Reference

### Provider Config

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `proxy_domains` | list(string) | `["localhost"]` | Domains that Warden listens on for proxied requests |
| `max_body_size` | int | `10485760` (10 MB) | Maximum request body size in bytes (max 100 MB) |
| `timeout` | duration | `30s` | Request timeout (e.g., `30s`, `5m`) |

### Credential Source Config

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `access_key_id` | string | Yes | IAM user access key ID |
| `secret_access_key` | string | Yes | IAM user secret access key |
| `region` | string | Yes | AWS region for API calls |
| `assume_role_arn` | string | No | Role ARN for source driver to assume (needed for Secrets Manager mint method) |

### Credential Spec Config — sts_assume_role

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mint_method` | string | Yes | Must be `sts_assume_role` |
| `role_arn` | string | Yes | ARN of the role to assume for consumers |
| `ttl` | duration | No | Default credential TTL (default: `1h`) |
| `session_name` | string | No | STS session name (default: `warden-<spec_name>`) |
| `external_id` | string | No | External ID for the AssumeRole call |
| `policy` | string | No | Inline session policy to further restrict permissions |

### Credential Spec Config — secrets_manager

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mint_method` | string | Yes | Must be `secrets_manager` |
| `secret_id` | string | Yes | Secret ID or ARN in Secrets Manager |
| `version_stage` | string | No | Version stage to retrieve (default: `AWSCURRENT`) |

### TTL Bounds

- `--min-ttl`: Minimum credential TTL. Requests for shorter TTLs are clamped up.
- `--max-ttl`: Maximum credential TTL. Requests for longer TTLs are clamped down.

## Supported AWS Services

The provider includes specialized processors for:

| Processor | Services | Notes |
|-----------|----------|-------|
| **S3** | Standard S3 operations | Virtual-hosted and path-style bucket addressing |
| **S3 Control** | Account-level S3 operations | Tagging, access points, storage lens (requires wildcard DNS) |
| **S3 Access Points** | Single-region access points | ARN-based routing |
| **Generic AWS** | All other services | EC2, Lambda, DynamoDB, SQS, SNS, IAM, CloudWatch, etc. |

## Known Limitations

### Multi-Region Access Points (MRAP) Data Plane

**MRAP data plane operations (PutObject, GetObject, etc.) cannot be proxied through Warden.** This is a fundamental limitation:

1. **SigV4A Signing**: MRAP data operations use Signature Version 4A (`AWS4-ECDSA-P256-SHA256`), which Warden does not support.
2. **SDK Endpoint Resolution**: The AWS SDK resolves MRAP ARNs to virtual-hosted style URLs and sends requests directly to AWS, bypassing `AWS_ENDPOINT_URL`.
3. **Global Routing**: MRAPs route requests to the nearest region internally.

| Operation | Supported | Notes |
|-----------|-----------|-------|
| MRAP creation/deletion (S3 Control) | Yes | Uses standard SigV4 |
| MRAP policy/tagging (S3 Control) | Yes | Uses standard SigV4 |
| MRAP data operations (PutObject, GetObject) | No | Uses SigV4A, bypasses proxy |

**Workaround**: Use the underlying regional buckets directly instead of the MRAP ARN.

### Standard (Single-Region) Access Points

Standard S3 Access Points **are fully supported**. The AWS SDK places the Access Point ARN in the request path, and Warden correctly routes these requests.

## Troubleshooting

### "Signature does not match" errors

1. Verify DNS resolves correctly:
   ```bash
   nslookup <account-id>.<proxy-domain>
   ```
2. Check that the Host header matches what the SDK signed.
3. Ensure Warden is listening on the resolved address.

### Requests fail to reach Warden

1. Wildcard DNS is not configured (see [DNS Configuration](#dns-configuration)).
2. `proxy_domains` doesn't match the endpoint URL configured in your AWS SDK.
3. Firewall rules are blocking the connection.

### S3 Control API returns 403

This typically means DNS is not resolving `<account-id>.<proxy-domain>` to Warden, or signature verification fails due to a host mismatch.

### Debug Logging

Enable trace-level logging to see detailed request processing:

```hcl
log_level = "trace"
```

This shows incoming request details, signature verification steps, processor selection, target URL construction, and re-signing operations.
