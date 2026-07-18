---
title: "AWS"
---

The AWS provider enables proxied access to AWS services through Warden. Clients embed their identity (JWT or TLS client certificate) directly in standard AWS SDK requests. Warden implicitly authenticates the caller, verifies the request signature for integrity, re-signs the request with real AWS credentials, and forwards it to the target AWS endpoint. No explicit Warden login step is required — the AWS SDK works as normal.

## Prerequisites

- Docker and Docker Compose installed and running
- AWS account with IAM access
- AWS CLI (for initial IAM setup)

:::note[New to Warden?]
Follow [Local dev setup](/provider-backends/local-dev-setup/) to start a local dev environment (Ory Hydra + a Warden dev server) before Step 1.
:::

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

Enable the JWT auth method and point it at your identity provider's JWKS endpoint, then create a role that binds the credential spec and policy. Enabling the mount and configuring the key source is covered once in [JWT auth](/auth-methods/jwt/#step-1-configure-the-key-source) — for the local dev setup:

```bash
warden auth enable jwt
warden write auth/jwt/config jwks_url=http://localhost:4444/.well-known/jwks.json

# Create a role
warden write auth/jwt/role/aws-user \
    token_policies="aws-access" \
    user_claim=sub \
    cred_spec_name=developer
```

## Step 2: Mount and Configure the Provider

Enable the AWS provider at a path of your choice:

```bash
warden provider enable aws
```

To mount at a custom path:

```bash
warden provider enable -path=aws-prod aws
```

Verify the provider is enabled:

```bash
warden provider list
```

Configure the provider:

```bash
warden write aws/config <<EOF
{
  "proxy_domains": ["localhost"],
  "max_body_size": 10485760,
  "timeout": "30s",
  "auto_auth_path": "auth/jwt/",
  "default_role": "aws-user"
}
EOF
```

- `auto_auth_path`: the auth backend Warden uses to validate the embedded credential (JWT or certificate).
- `default_role`: the auth role to use for all requests. When set, this takes precedence over the `access_key_id` value in the SigV4 header.

For production, set `proxy_domains` to your Warden server's domain (see [DNS Configuration](#dns-configuration)).

See [Provider configuration](/provider-backends/configuration/) for the full list of common config fields (`proxy_domains`, `timeout`, `tls_skip_verify`, `ca_data`, and more).

Verify:

```bash
warden read aws/config
```

## Step 3: Create a Credential Source and Specs

The credential source tells Warden how to authenticate to AWS and where the base credentials live. Use `AccessKeyId` and `SecretAccessKey` you saved in the [Prerequisites](#prerequisites) to create the cred source.

```bash
warden cred source create my-aws-source \
  -type aws \
  -rotation-period 24h \
  -config access_key_id=<AccessKeyId> \
  -config secret_access_key=<SecretAccessKey> \
  -config region=us-east-1
```

The `-rotation-period` controls how often Warden rotates the base IAM access keys. Since the IAM user can only manage its own keys and assume roles (no direct resource access), longer periods are acceptable (e.g., `720h` / 30 days). For stricter environments, use shorter periods (e.g., `12h`-`24h`).

Verify:

```bash
warden cred source read my-aws-source
```

A credential spec defines what temporary credentials Warden mints for consumers. Multiple specs can share the same source, each assuming a different role with different permissions and TTLs.

```bash
# Spec for developers — read-only access, short TTL
warden cred spec create developer \
  -source my-aws-source \
  -config mint_method=sts_assume_role \
  -config role_arn=arn:aws:iam::<ACCOUNT_ID>:role/devops-readonly-role \
  -config ttl=1h \
  -min-ttl 600s \
  -max-ttl 2h

# Spec for CI/CD pipelines — deploy permissions
warden cred spec create deployer \
  -source my-aws-source \
  -config mint_method=sts_assume_role \
  -config role_arn=arn:aws:iam::<ACCOUNT_ID>:role/devops-deploy-role \
  -config ttl=30m \
  -min-ttl 600s \
  -max-ttl 1h

# Spec for operators — full access, longer TTL
warden cred spec create operator \
  -source my-aws-source \
  -config mint_method=sts_assume_role \
  -config role_arn=arn:aws:iam::<ACCOUNT_ID>:role/devops-operator-role \
  -config ttl=2h \
  -min-ttl 600s \
  -max-ttl 4h
```

Each spec points to a different `role_arn`, so the IAM user's `AssumeRoles` policy must allow assuming all of them (the `devops-*` wildcard in the [AssumeRoles policy](#attach-iam-policies) covers this).

### Alternative: Vault/OpenBao as Credential Source

Instead of storing AWS credentials directly in Warden, you can store them in a Vault/OpenBao instance and have Warden fetch them at runtime. This supports two mint methods: `static_aws` (static credentials from KV v2) and `dynamic_aws` (temporary credentials from the Vault AWS secrets engine).

**Prerequisites:** A Vault/OpenBao instance with:
- An AppRole configured for Warden access
- Either a KV v2 mount containing AWS credentials, or an AWS secrets engine with configured roles

```bash
# Create a Vault credential source
warden cred source create aws-vault-src \
  -type=hvault \
  -config=vault_address=https://vault.example.com \
  -config=auth_method=approle \
  -config=role_id=<role-id> \
  -config=secret_id=<secret-id> \
  -config=approle_mount=approle \
  -config=role_name=warden-role \
  -rotation-period=24h
```

#### static_aws — fetch static credentials from KV v2

The KV v2 secret must contain `access_key_id` and `secret_access_key` fields.

```bash
warden cred spec create developer \
  -source aws-vault-src \
  -config mint_method=static_aws \
  -config kv2_mount=secret \
  -config secret_path=aws/creds \
  -min-ttl 600s \
  -max-ttl 2h
```

#### dynamic_aws — generate credentials via Vault AWS secrets engine

Vault generates temporary AWS credentials using its [AWS secrets engine](https://developer.hashicorp.com/vault/docs/secrets/aws). The role must already be configured in Vault.

```bash
warden cred spec create developer \
  -source aws-vault-src \
  -config mint_method=dynamic_aws \
  -config aws_mount=aws \
  -config role_name=my-vault-aws-role \
  -config ttl=1h \
  -min-ttl 600s \
  -max-ttl 2h
```

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
  condition = <<-CEL
    cidrContains("10.0.0.0/8", request.client_ip) &&
    now.getHours("UTC") >= 8 && now.getHours("UTC") < 18 &&
    now.getDayOfWeek("UTC") in [1, 2, 3, 4, 5]
  CEL
}

path "aws/gateway*" {
  capabilities = ["read", "create", "update", "patch"]
}
EOF
```

The `condition` is a [CEL](https://cel.dev) expression (see [CEL conditions](/concepts/cel-conditions/)): `cidrContains` restricts by network and `now.getHours`/`now.getDayOfWeek` by time of day and weekday. It must evaluate to `true` for the rule to apply, and fails closed.

Verify:

```bash
warden policy read aws-access
```

## Step 5: Configure AWS SDK and Make Requests

With Warden there is no explicit login step. The client embeds its identity directly in the AWS SDK credentials, and Warden authenticates implicitly on every request.

### JWT Auth method

Get a JWT from your identity provider — see [Obtaining a JWT](/auth-methods/jwt/#obtaining-a-jwt) (the local dev setup issues one from Hydra). Export it as `$JWT`.

Configure the AWS SDK to use the JWT as credentials. The auth role name goes in `AWS_ACCESS_KEY_ID`, and the JWT goes in both `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN`:

```bash
export AWS_ACCESS_KEY_ID="aws-user"
export AWS_SECRET_ACCESS_KEY="$JWT"
export AWS_SESSION_TOKEN="$JWT"
export AWS_ENDPOINT_URL="http://localhost:8400/v1/aws/gateway"
```

When `default_role` is configured on the provider (as done in [Step 2](#step-2-mount-and-configure-the-provider)), all requests use that role regardless of the `AWS_ACCESS_KEY_ID` value. When `default_role` is not set, Warden uses the `AWS_ACCESS_KEY_ID` value as the auth role name.

Then use the AWS CLI or SDK as normal — all requests are transparently proxied through Warden:

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

Warden detects the JWT in the `X-Amz-Security-Token` header, authenticates it against the configured auth backend, verifies the SigV4 signature for request integrity, re-signs the request with real AWS credentials, and proxies it to the target service.

### Certificate Auth method

For workloads that already have X.509 certificates (Kubernetes pods with cert-manager, VMs with machine certificates, SPIFFE X.509-SVIDs), Warden can authenticate using TLS client certificates instead of JWTs.

:::note[Prerequisite]
Certificate auth requires mTLS on the Warden listener so the client certificate can be presented during the handshake. See [Enabling mTLS on the listener](/auth-methods/cert/#enabling-mtls-on-the-listener).
:::

#### Set up cert auth and configure the provider

Replace Step 1 with cert auth setup, and update the provider's `auto_auth_path`:

```bash
# Enable cert auth
warden auth enable cert

# Configure trusted CA
warden write auth/cert/config \
    trusted_ca_pem=@/path/to/ca.pem \
    default_role=aws-user

# Create a role
warden write auth/cert/role/aws-user \
    allowed_common_names="agent-*" \
    token_policies="aws-access" \
    cred_spec_name=developer

# Update the provider to use cert auth
warden write aws/config <<EOF
{
  "proxy_domains": ["localhost"],
  "auto_auth_path": "auth/cert/",
  "default_role": "aws-user"
}
EOF
```

The `allowed_common_names` field supports glob patterns; you can also match on other certificate fields. See [Create a role](/auth-methods/cert/#step-3-create-a-role) for the full set of constraint fields.

#### Configure the AWS SDK

The client uses the auth role name as both `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`. No session token is needed:

```bash
export AWS_ACCESS_KEY_ID="aws-user"
export AWS_SECRET_ACCESS_KEY="aws-user"
export AWS_ENDPOINT_URL="https://localhost:8400/v1/aws/gateway"
```

The client certificate is presented during the TLS handshake (or forwarded by a load balancer). Warden extracts it, authenticates against the cert auth backend, and proxies the request.

The AWS CLI does not support presenting client certificates for mTLS. Cert auth requires an HTTP client that supports mTLS, or a load balancer in front of Warden that forwards the client certificate via the `X-SSL-Client-Cert` or `X-Forwarded-Client-Cert` header. When Warden is behind such a load balancer, the AWS CLI works as normal:

## Cleanup

To stop Warden and the identity provider:

```bash
# Stop Warden (Ctrl+C in the terminal where it's running)

# Stop and remove the identity provider containers
docker compose -f docker-compose.quickstart.yml down -v
```

Since Warden dev mode uses in-memory storage, all configuration is lost when the server stops.

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
4. In JWT mode, ensure the JWT has not expired — an expired JWT will cause a signature mismatch because the SDK signs with the old token value.

### Requests fail to reach Warden

1. Wildcard DNS is not configured (see [DNS Configuration](#dns-configuration)).
2. `proxy_domains` doesn't match the endpoint URL configured in your AWS SDK.
3. Firewall rules are blocking the connection.

### Request returns 401/403

1. Check that `auto_auth_path` points to a valid, enabled auth backend (e.g., `auth/jwt/`).
2. Ensure the auth role exists and has a valid `cred_spec_name`.
3. For JWT mode: verify the JWT is valid and not expired.
4. For cert mode: verify the client certificate is signed by the trusted CA configured in the cert auth backend.

### S3 Control API returns 403

This typically means DNS is not resolving `<account-id>.<proxy-domain>` to Warden, or signature verification fails due to a host mismatch.

### Debug Logging

Enable trace-level logging to see detailed request processing:

```hcl
log_level = "trace"
```

This shows incoming request details, signature verification steps, processor selection, target URL construction, and re-signing operations.
