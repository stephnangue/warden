# AWS Provider

The AWS provider enables proxied access to AWS services through Warden. It intercepts AWS SDK requests, verifies the client's signature using Warden-issued credentials, re-signs the request with real AWS credentials, and forwards it to the target AWS endpoint. This allows Warden to broker access to any AWS service without exposing real credentials to clients.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Step 1: Configure JWT Auth and Create a Role](#step-1-configure-jwt-auth-and-create-a-role)
- [Step 2: Mount and Configure the Provider](#step-2-mount-and-configure-the-provider)
- [Step 3: Create a Credential Source and Specs](#step-3-create-a-credential-source-and-specs)
- [Step 4: Create a Policy](#step-4-create-a-policy)
- [Step 5: Get a JWT and Make Requests](#step-5-get-a-jwt-and-make-requests)
- [Architecture Overview](#architecture-overview)
- [DNS Configuration](#dns-configuration)
- [Configuration Reference](#configuration-reference)
- [Supported AWS Services](#supported-aws-services)
- [Known Limitations](#known-limitations)
- [Troubleshooting](#troubleshooting)

## Prerequisites

- Docker and Docker Compose installed and running
- AWS account with IAM access
- AWS CLI (for initial IAM setup)

> **New to Warden?** Follow these steps to get a local dev environment running:
>
> **1. Deploy the quickstart stack** — this starts an identity provider ([Ory Hydra](https://www.ory.sh/hydra/)) needed to issue JWTs for authentication in Steps 1 and 5:
> ```bash
> curl -fsSL -o docker-compose.quickstart.yml \
>   https://raw.githubusercontent.com/stephnangue/warden/main/docker-compose.quickstart.yml
> docker compose -f docker-compose.quickstart.yml up -d
> ```
>
> **2. Download the latest Warden binary:**
> ```bash
> # macOS (Apple Silicon)
> curl -L https://github.com/stephnangue/warden/releases/latest/download/warden_$(curl -s https://api.github.com/repos/stephnangue/warden/releases/latest | grep tag_name | cut -d '"' -f4 | tr -d v)_darwin_arm64.tar.gz | tar xz
>
> # macOS (Intel)
> curl -L https://github.com/stephnangue/warden/releases/latest/download/warden_$(curl -s https://api.github.com/repos/stephnangue/warden/releases/latest | grep tag_name | cut -d '"' -f4 | tr -d v)_darwin_amd64.tar.gz | tar xz
>
> # Linux (x86_64)
> curl -L https://github.com/stephnangue/warden/releases/latest/download/warden_$(curl -s https://api.github.com/repos/stephnangue/warden/releases/latest | grep tag_name | cut -d '"' -f4 | tr -d v)_linux_amd64.tar.gz | tar xz
>
> # Linux (ARM64)
> curl -L https://github.com/stephnangue/warden/releases/latest/download/warden_$(curl -s https://api.github.com/repos/stephnangue/warden/releases/latest | grep tag_name | cut -d '"' -f4 | tr -d v)_linux_arm64.tar.gz | tar xz
> ```
>
> **3. Add the binary to your PATH:**
> ```bash
> export PATH="$PWD:$PATH"
> ```
>
> **4. Start the Warden server** in dev mode:
> ```bash
> warden server --dev --dev-root-token=root
> ```
>
> **5. In another terminal window**, export the environment variables for the CLI:
> ```bash
> export PATH="$PWD:$PATH"
> export WARDEN_ADDR="http://127.0.0.1:8400"
> export WARDEN_TOKEN="root"
> ```

### Create the IAM User

Create a dedicated IAM user for Warden, called Warden root user. This user holds long-lived access keys that Warden rotates automatically.

```bash
aws iam create-user --user-name warden-cred-source-root
aws iam create-access-key --user-name warden-cred-source-root
```

Save the `AccessKeyId` and `SecretAccessKey` from the output.

### Attach IAM Policies

The Warden root user needs two policies:

#### SelfManageAccessKeys

Allows the root user to rotate its own access keys. Warden uses this during credential rotation to create new keys and delete old ones.

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

#### AssumeRoles

Allows the root user to assume roles that grant actual permissions. Scope the `Resource` to match your role naming conventions.

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

### Create Target IAM Roles

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

## Step 1: Configure JWT Auth and Create a Role

Set up a JWT auth method and create a role that binds the credential spec and policy:

```bash
# Enable JWT auth if not already enabled
warden auth enable --type=jwt

# Configure JWT with Hydra's JWKS endpoint (from docker-compose.quickstart.yml)
warden write auth/jwt/config mode=jwt jwks_url=http://localhost:4444/.well-known/jwks.json

# Create a role with token type `aws`
warden write auth/jwt/role/aws-user \
    token_type=aws \
    token_policies="aws-access" \
    user_claim=sub \
    cred_spec_name=developer \
    token_ttl=1h
```

## Step 2: Mount and Configure the Provider

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

## Step 3: Create a Credential Source and Specs

The credential source tells Warden how to authenticate to AWS and where the base credentials live. Use `AccessKeyId` and `SecretAccessKey` you saved in the [Prerequisites](#prerequisites) to create the cred source.

```bash
warden cred source create my-aws-source \
  --type aws \
  --rotation-period 24h \
  --config access_key_id=<AccessKeyId> \
  --config secret_access_key=<SecretAccessKey> \
  --config region=us-east-1
```

The `--rotation-period` controls how often Warden rotates the base IAM access keys. Since the IAM user can only manage its own keys and assume roles (no direct resource access), longer periods are acceptable (e.g., `720h` / 30 days). For stricter environments, use shorter periods (e.g., `12h`-`24h`).

Verify:

```bash
warden cred source read my-aws-source
```

A credential spec defines what temporary credentials Warden mints for consumers. Multiple specs can share the same source, each assuming a different role with different permissions and TTLs.

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

Each spec points to a different `role_arn`, so the IAM user's `AssumeRoles` policy must allow assuming all of them (the `devops-*` wildcard in the [AssumeRoles policy](#attach-iam-policies) covers this).

## Step 4: Create a Policy

Create a policy that grants access to the AWS provider gateway. Note that this policy is intentionally coarse-grained for simplicity, but it can be made much more fine-grained to restrict access to specific paths or capabilities as needed:

```bash
warden policy write aws-access - <<EOF
path "aws/gateway*" {
  capabilities = ["read", "create", "update", "delete", "patch"]
}
EOF
```

For tighter control, add runtime conditions to protect destructive operations on specific paths. For example, restrict S3 object deletion to trusted networks during business hours while leaving read access unconditional:

```bash
warden policy write aws-prod-restricted - <<EOF
path "aws/gateway*" {
  capabilities = ["delete"]
  conditions {
    source_ip   = ["10.0.0.0/8"]
    time_window = ["08:00-18:00 UTC"]
    day_of_week = ["Mon", "Tue", "Wed", "Thu", "Fri"]
  }
}

path "aws/gateway*" {
  capabilities = ["read", "create", "update", "patch"]
}
EOF
```

Condition types are AND-ed (all must be satisfied), values within each type are OR-ed (at least one must match). Supported types: `source_ip` (CIDR or bare IP), `time_window` (`HH:MM-HH:MM TZ`, supports midnight-spanning), `day_of_week` (3-letter abbreviations).

Verify:

```bash
warden policy read aws-access
```

## Step 5: Get a JWT and Make Requests

Get a JWT from Hydra using one of the quickstart clients:

```bash
export JWT=$(curl -s -X POST http://localhost:4444/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=my-agent&client_secret=agent-secret&scope=api:read api:write" \
  | jq -r '.access_token')
```

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

## Cleanup

To stop Warden and the identity provider:

```bash
# Stop Warden (Ctrl+C in the terminal where it's running)

# Stop and remove the identity provider containers
docker compose -f docker-compose.quickstart.yml down -v
```

Since Warden dev mode uses in-memory storage, all configuration is lost when the server stops.

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

## TLS Certificate Authentication

Steps 1 and 5 above use JWT authentication. Alternatively, you can authenticate with a TLS client certificate. This is useful for workloads that already have X.509 certificates — Kubernetes pods with cert-manager, VMs with machine certificates, or SPIFFE X.509-SVIDs from a service mesh.

> **Prerequisite:** Certificate authentication requires TLS to be enabled on the Warden listener so that client certificates can be presented during the TLS handshake (mTLS). In dev mode, use `--dev-tls` to enable TLS with auto-generated certificates, or provide your own with `--dev-tls-cert-file`, `--dev-tls-key-file`, and `--dev-tls-ca-cert-file`. Alternatively, place Warden behind a load balancer that terminates TLS and forwards the client certificate via the `X-Forwarded-Client-Cert` or `X-SSL-Client-Cert` header.

Steps 2–4 (provider setup) are identical. Replace Steps 1 and 5 with the following.

### Enable Cert Auth

```bash
warden auth enable --type=cert
```

### Configure Trusted CA

Configure the trusted CA for this backend:

```bash
warden write auth/cert/config \
    trusted_ca_pem=@/path/to/ca.pem \
    default_role=aws-user
```

### Create a role with token type `aws`

```bash
warden write auth/cert/role/aws-user \
    allowed_common_names="agent-*" \
    token_type=aws \
    token_policies="aws-access" \
    cred_spec_name=developer \
    token_ttl=1h
```

The `allowed_common_names` field supports glob patterns. You can also match on other certificate fields: `allowed_dns_sans`, `allowed_email_sans`, `allowed_uri_sans`, or `allowed_organizational_units`.

### Login and Use

```bash
warden login --method=cert --role=aws-user \
    --cert=./client.pem --key=./client-key.pem
```

Then use AWS tools with the session credentials, exactly as shown in [Step 5](#step-5-get-a-jwt-and-make-requests).

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

### S3 Directory Buckets (Express One Zone)

**S3 Directory Buckets are not currently supported.** Directory buckets (names ending in `--<zone-id>--x-s3`) use a session-based authentication mechanism: the SDK calls `CreateSession` to obtain 5-minute scoped credentials, then signs data plane requests with those credentials using the `x-amz-s3session-token` header. Warden does not yet implement this session flow.

### S3 Table Buckets

**S3 Table Buckets are not currently supported.** S3 Tables is a separate service (`s3tables.<region>.amazonaws.com`) with its own signing name (`s3tables`). Warden does not yet have a processor for this service.

### S3 Vector Buckets

**S3 Vector Buckets are not currently supported.** S3 Vectors is a separate service (`s3vectors.<region>.api.aws`) with its own signing name (`s3vectors`). Warden does not yet have a processor for this service.

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
