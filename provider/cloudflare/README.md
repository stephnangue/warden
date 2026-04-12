# Cloudflare Provider

The Cloudflare provider enables proxied access to Cloudflare APIs through Warden. It supports two authentication modes, auto-detected per request:

- **Standard API** — Injects `Authorization: Bearer` header with the API token. Covers zones, DNS records, Workers, accounts, firewall rules, and all other Cloudflare products.
- **R2 Object Storage** — Verifies the client's SigV4 signature, re-signs with real Cloudflare R2 credentials, and forwards to `<account_id>.r2.cloudflarestorage.com`. Compatible with any S3 client (AWS CLI, boto3, s3cmd, MinIO).

## Table of Contents

- [Prerequisites](#prerequisites)
- [Step 1: Configure JWT Auth and Create a Role](#step-1-configure-jwt-auth-and-create-a-role)
- [Step 2: Mount and Configure the Provider](#step-2-mount-and-configure-the-provider)
- [Step 3: Create a Credential Source and Spec](#step-3-create-a-credential-source-and-spec)
- [Step 4: Create a Policy](#step-4-create-a-policy)
- [Step 5: Get a JWT and Make Requests](#step-5-get-a-jwt-and-make-requests)
- [R2 Object Storage](#r2-object-storage)
- [TLS Certificate Authentication](#tls-certificate-authentication)
- [Configuration Reference](#configuration-reference)
- [Token Management](#token-management)

## Prerequisites

- Docker and Docker Compose installed and running
- A **Cloudflare account** with:
  - An API token (from Cloudflare Dashboard > My Profile > API Tokens) for the REST API
  - R2 API credentials (access key ID + secret access key) for Object Storage — generate via Cloudflare Dashboard > R2 > Manage R2 API Tokens

> **New to Warden?** Follow these steps to get a local dev environment running:
>
> **1. Deploy the quickstart stack** — this starts an identity provider ([Ory Hydra](https://www.ory.sh/hydra/)) needed to issue JWTs for authentication in Steps 1 and 5:
> ```bash
> curl -fsSL -o docker-compose.quickstart.yml \
>   https://raw.githubusercontent.com/stephnangue/warden/main/deploy/docker-compose.quickstart.yml
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

## Step 1: Configure JWT Auth and Create a Role

Set up a JWT auth method and create a role that binds the credential spec and policy. Clients authenticate directly with their JWT — no separate login step is needed.

> **This step must come before configuring the provider.** Warden validates at configuration time that the auth backend referenced by `auto_auth_path` is already mounted.

```bash
# Enable JWT auth if not already enabled
warden auth enable --type=jwt

# Configure JWT with Hydra's JWKS endpoint (from docker-compose.quickstart.yml)
warden write auth/jwt/config mode=jwt jwks_url=http://localhost:4444/.well-known/jwks.json

# Create a role that binds the credential spec and policy
warden write auth/jwt/role/cloudflare-user \
    token_policies="cloudflare-access" \
    user_claim=sub \
    cred_spec_name=cloudflare-ops
```

## Step 2: Mount and Configure the Provider

Enable the Cloudflare provider at a path of your choice:

```bash
warden provider enable --type=cloudflare
```

To mount at a custom path:

```bash
warden provider enable --type=cloudflare cloudflare-prod
```

Verify the provider is enabled:

```bash
warden provider list
```

Configure the provider with `auto_auth_path` and `account_id`. The `account_id` is required for R2 Object Storage and can be found in the Cloudflare Dashboard URL (`https://dash.cloudflare.com/<account_id>`):

```bash
warden write cloudflare/config <<EOF
{
  "cloudflare_url": "https://api.cloudflare.com/client/v4",
  "account_id": "your-cloudflare-account-id",
  "auto_auth_path": "auth/jwt/",
  "timeout": "30s",
  "max_body_size": 10485760
}
EOF
```

For EU or FedRAMP jurisdictions, add the `r2_jurisdiction` field:

```bash
warden write cloudflare/config <<EOF
{
  "cloudflare_url": "https://api.cloudflare.com/client/v4",
  "account_id": "your-cloudflare-account-id",
  "r2_jurisdiction": "eu",
  "auto_auth_path": "auth/jwt/",
  "timeout": "30s"
}
EOF
```

Verify the configuration:

```bash
warden read cloudflare/config
```

## Step 3: Create a Credential Source and Spec

### Option A: Static Keys

Create a Cloudflare credential source and spec. You can configure both modes or just the one you need:

**Dual-mode (API + R2):**

```bash
warden cred source create cloudflare-src \
  --type=local

warden cred spec create cloudflare-ops \
  --source cloudflare-src \
  --type=cloudflare_keys \
  --config mint_method=static_keys \
  --config access_key_id=your-r2-access-key-id \
  --config secret_access_key=your-r2-secret-access-key \
  --config api_token=your-cloudflare-api-token
```

**API-only (no R2):**

```bash
warden cred spec create cloudflare-api-only \
  --source cloudflare-src \
  --type=cloudflare_keys \
  --config mint_method=static_keys \
  --config api_token=your-cloudflare-api-token
```

**R2-only (no API):**

```bash
warden cred spec create cloudflare-r2-only \
  --source cloudflare-src \
  --type=cloudflare_keys \
  --config mint_method=static_keys \
  --config access_key_id=your-r2-access-key-id \
  --config secret_access_key=your-r2-secret-access-key
```

### Option B: Vault/OpenBao as Credential Source

Store your Cloudflare credentials in a Vault/OpenBao KV v2 secret engine and have Warden fetch them at runtime.

**Prerequisites:** A Vault/OpenBao instance with:
- A KV v2 mount containing your Cloudflare credentials (e.g., at `secret/cloudflare/prod` with at least `api_token` and/or `access_key_id` + `secret_access_key` fields)
- An AppRole configured for Warden access

```bash
warden cred source create cloudflare-vault-src \
  --type=hvault \
  --config=vault_address=https://vault.example.com \
  --config=auth_method=approle \
  --config=role_id=your-role-id \
  --config=secret_id=your-secret-id \
  --config=approle_mount=approle \
  --config=role_name=warden-role \
  --rotation-period=24h

warden cred spec create cloudflare-ops \
  --source cloudflare-vault-src \
  --type=cloudflare_keys \
  --config mint_method=static_cloudflare \
  --config kv2_mount=secret \
  --config secret_path=cloudflare/prod
```

The KV v2 secret at `secret/cloudflare/prod` should contain at least `api_token` (for API mode) and/or `access_key_id` + `secret_access_key` (for R2 mode).

Verify:

```bash
warden cred spec read cloudflare-ops
```

## Step 4: Create a Policy

Create a policy that grants access to the Cloudflare provider gateway:

```bash
warden policy write cloudflare-access - <<EOF
path "cloudflare/role/+/gateway*" {
  capabilities = ["create", "read", "update", "delete", "patch"]
}
EOF
```

For fine-grained access control, restrict which Cloudflare resources and actions a role can use:

```bash
warden policy write cloudflare-readonly - <<EOF
path "cloudflare/role/+/gateway/zones" {
  capabilities = ["read"]
}

path "cloudflare/role/+/gateway/zones/+/*" {
  capabilities = ["read"]
}

path "cloudflare/role/+/gateway/user/tokens/verify" {
  capabilities = ["read"]
}

path "cloudflare/role/+/gateway/accounts/+/workers/*" {
  capabilities = ["read"]
}
EOF
```

Verify:

```bash
warden policy read cloudflare-access
```

## Step 5: Get a JWT and Make Requests

Get a JWT from Hydra using one of the quickstart clients:

```bash
export JWT_TOKEN=$(curl -s -X POST http://localhost:4444/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=my-agent&client_secret=agent-secret&scope=api:read api:write" \
  | jq -r '.access_token')
```

Requests use role-based paths. Warden performs implicit JWT authentication and injects the Cloudflare token automatically.

The URL pattern is: `/v1/cloudflare/role/{role}/gateway/{api-path}`

Export CF_ENDPOINT as environment variable:
```bash
export CF_ENDPOINT="${WARDEN_ADDR}/v1/cloudflare/role/cloudflare-user/gateway"
```

### Verify Token

```bash
curl -s "${CF_ENDPOINT}/user/tokens/verify" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### List Zones

```bash
curl -s "${CF_ENDPOINT}/zones" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### List DNS Records for a Zone

```bash
curl -s "${CF_ENDPOINT}/zones/${ZONE_ID}/dns_records" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### Create a DNS Record

```bash
curl -s -X POST "${CF_ENDPOINT}/zones/${ZONE_ID}/dns_records" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "A",
    "name": "app.example.com",
    "content": "192.0.2.1",
    "ttl": 3600,
    "proxied": true
  }'
```

### List Workers Scripts

```bash
curl -s "${CF_ENDPOINT}/accounts/${ACCOUNT_ID}/workers/scripts" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### List Firewall Rules

```bash
curl -s "${CF_ENDPOINT}/zones/${ZONE_ID}/firewall/rules" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### Get Account Details

```bash
curl -s "${CF_ENDPOINT}/accounts/${ACCOUNT_ID}" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

## R2 Object Storage

The Cloudflare provider auto-detects R2 requests by the presence of a SigV4 `Authorization` header. Any S3-compatible client works — AWS CLI, boto3, s3cmd, MinIO Client.

### R2 Transparent Auth with JWT

Configure your S3 client to point at Warden's gateway endpoint. Use your JWT as both the access key and secret key:

```bash
aws configure set aws_access_key_id "${JWT_TOKEN}"
aws configure set aws_secret_access_key "${JWT_TOKEN}"
aws configure set region auto
```

### R2 Transparent Auth with Certificates

For certificate-based authentication, use the role name as both the access key and secret key:

```bash
aws configure set aws_access_key_id "cloudflare-user"
aws configure set aws_secret_access_key "cloudflare-user"
aws configure set region auto
```

### R2 Operations

```bash
# List buckets
aws s3 ls \
  --endpoint-url "${WARDEN_ADDR}/v1/cloudflare/role/cloudflare-user/gateway"

# List objects in a bucket
aws s3 ls s3://my-bucket/ \
  --endpoint-url "${WARDEN_ADDR}/v1/cloudflare/role/cloudflare-user/gateway"

# Upload a file
aws s3 cp myfile.txt s3://my-bucket/myfile.txt \
  --endpoint-url "${WARDEN_ADDR}/v1/cloudflare/role/cloudflare-user/gateway"

# Download a file
aws s3 cp s3://my-bucket/myfile.txt ./downloaded.txt \
  --endpoint-url "${WARDEN_ADDR}/v1/cloudflare/role/cloudflare-user/gateway"
```

### R2 Jurisdictions

| Jurisdiction | R2 Endpoint | Config |
|-------------|-------------|--------|
| Default | `<account_id>.r2.cloudflarestorage.com` | `r2_jurisdiction` omitted or empty |
| EU | `<account_id>.eu.r2.cloudflarestorage.com` | `r2_jurisdiction=eu` |
| FedRAMP | `<account_id>.fedramp.r2.cloudflarestorage.com` | `r2_jurisdiction=fedramp` |

R2 always uses `auto` as the region for SigV4 signing. The `account_id` is configured in the provider config (Step 2).

## Cleanup

To stop Warden and the identity provider:

```bash
# Stop Warden (Ctrl+C in the terminal where it's running)

# Stop and remove the identity provider containers
docker compose -f docker-compose.quickstart.yml down -v
```

Since Warden dev mode uses in-memory storage, all configuration is lost when the server stops.

## TLS Certificate Authentication

Steps 4-5 above use JWT authentication. Alternatively, you can authenticate with a TLS client certificate. This is useful for workloads that already have X.509 certificates — Kubernetes pods with cert-manager, VMs with machine certificates, or SPIFFE X.509-SVIDs from a service mesh.

> **Prerequisite:** Certificate authentication requires TLS to be enabled on the Warden listener so that client certificates can be presented during the TLS handshake (mTLS). In dev mode, use `--dev-tls` to enable TLS with auto-generated certificates, or provide your own with `--dev-tls-cert-file`, `--dev-tls-key-file`, and `--dev-tls-ca-cert-file`. Alternatively, place Warden behind a load balancer that terminates TLS and forwards the client certificate via the `X-Forwarded-Client-Cert` or `X-SSL-Client-Cert` header.

Steps 1-3 (provider setup) are identical. Replace Steps 4-5 with the following.

### Enable Cert Auth

```bash
warden auth enable --type=cert
```

### Configure Trusted CA

Provide the PEM-encoded CA certificate that signs your client certificates:

```bash
warden write auth/cert/config \
    trusted_ca_pem=@/path/to/ca.pem \
    default_role=cloudflare-user
```

### Create a Cert Role

Create a role that binds allowed certificate identities to a credential spec and policy:

```bash
warden write auth/cert/role/cloudflare-user \
    allowed_common_names="agent-*" \
    token_policies="cloudflare-access" \
    cred_spec_name=cloudflare-ops
```

The `allowed_common_names` field supports glob patterns. You can also match on other certificate fields: `allowed_dns_sans`, `allowed_email_sans`, `allowed_uri_sans`, or `allowed_organizational_units`.

### Configure Provider for Cert Auth

Update the provider config to use cert auth:

```bash
warden write cloudflare/config <<EOF
{
  "cloudflare_url": "https://api.cloudflare.com/client/v4",
  "account_id": "your-cloudflare-account-id",
  "auto_auth_path": "auth/cert/",
  "timeout": "30s",
  "max_body_size": 10485760
}
EOF
```

### Make Requests with Certificates

Standard API:

```bash
curl --cert client.pem --key client-key.pem \
    --cacert warden-ca.pem \
    -s "https://warden.internal/v1/cloudflare/role/cloudflare-user/gateway/zones" \
    -H "Content-Type: application/json"
```

R2 Object Storage:

```bash
aws s3 ls s3://my-bucket/ \
  --endpoint-url "https://warden.internal/v1/cloudflare/role/cloudflare-user/gateway"
```

## Configuration Reference

### Provider Config

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `cloudflare_url` | string | `https://api.cloudflare.com/client/v4` | Cloudflare API base URL |
| `account_id` | string | — | Cloudflare account ID (required for R2 Object Storage) |
| `r2_jurisdiction` | string | — | R2 jurisdiction: empty (default), `eu`, or `fedramp` |
| `max_body_size` | int | 10485760 (10 MB) | Maximum request body size in bytes (max 100 MB) |
| `timeout` | duration | `30s` | Request timeout |
| `auto_auth_path` | string | — | **Required.** Auth mount path for implicit authentication (e.g., `auth/jwt/`, `auth/cert/`) |
| `default_role` | string | — | Fallback role when not specified in URL |

### Credential Spec Config (static_keys)

At least one mode must be configured: `api_token` for the REST API, or `access_key_id` + `secret_access_key` for R2. Both can be set for dual-mode access.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mint_method` | string | Yes | Must be `static_keys` |
| `access_key_id` | string | R2 mode | Cloudflare R2 access key ID (required with `secret_access_key`) |
| `secret_access_key` | string | R2 mode | Cloudflare R2 secret access key (sensitive — required with `access_key_id`) |
| `api_token` | string | API mode | API bearer token for the REST API (sensitive) |

### Credential Spec Config (Vault — static_cloudflare)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mint_method` | string | Yes | Must be `static_cloudflare` |
| `kv2_mount` | string | Yes | KV v2 mount path in Vault |
| `secret_path` | string | Yes | Path to the secret within the mount |

### Credential Source Config (Vault/OpenBao)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `vault_address` | string | Yes | Vault server address (e.g., `https://vault.example.com`) |
| `vault_namespace` | string | No | Vault namespace (Enterprise/HCP only) |
| `auth_method` | string | No | Authentication method (`approle`) |
| `role_id` | string | Yes* | AppRole role ID (*required when `auth_method=approle`) |
| `secret_id` | string | Yes* | AppRole secret ID (*required when `auth_method=approle`) |
| `approle_mount` | string | Yes* | AppRole auth mount path (*required when `auth_method=approle`) |
| `role_name` | string | Yes* | AppRole role name for rotation (*required when `auth_method=approle`) |

## Token Management

### Static Keys

| Aspect | Details |
|--------|---------|
| **Storage** | Credentials (api_token and/or access_key_id + secret_access_key) are stored on the credential spec |
| **Rotation** | Manual — regenerate in Cloudflare Dashboard and update the spec |
| **Lifetime** | Static — no expiration or auto-refresh |

**To rotate static credentials:**

1. Generate new credentials in Cloudflare Dashboard (R2 > Manage R2 API Tokens for R2 keys, My Profile > API Tokens for API tokens)
2. Update the credential spec with the fields you use:
   ```bash
   # Dual-mode
   warden cred spec update cloudflare-ops \
     --config access_key_id=new-access-key-id \
     --config secret_access_key=new-secret-access-key \
     --config api_token=new-api-token

   # API-only
   warden cred spec update cloudflare-api-only \
     --config api_token=new-api-token

   # R2-only
   warden cred spec update cloudflare-r2-only \
     --config access_key_id=new-access-key-id \
     --config secret_access_key=new-secret-access-key
   ```
3. Revoke the old credentials in the Cloudflare Dashboard
