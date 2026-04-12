# OVH Provider

The OVH provider enables proxied access to OVHcloud APIs through Warden. It supports two authentication modes, auto-detected per request:

- **Standard API** — Injects `Authorization: Bearer` header with the API token. Covers account info, cloud projects, domains, IPs, and all other OVHcloud products.
- **S3 Object Storage** — Verifies the client's SigV4 signature, re-signs with real OVH S3 credentials, and forwards to `s3.{region}.io.cloud.ovh.net`. Compatible with any S3 client (AWS CLI, boto3, s3cmd, MinIO).

## Table of Contents

- [Prerequisites](#prerequisites)
- [Step 1: Configure JWT Auth and Create a Role](#step-1-configure-jwt-auth-and-create-a-role)
- [Step 2: Mount and Configure the Provider](#step-2-mount-and-configure-the-provider)
- [Step 3: Create a Credential Source and Spec](#step-3-create-a-credential-source-and-spec)
- [Step 4: Create a Policy](#step-4-create-a-policy)
- [Step 5: Get a JWT and Make Requests](#step-5-get-a-jwt-and-make-requests)
- [S3 Object Storage](#s3-object-storage)
- [Regional Endpoints](#regional-endpoints)
- [TLS Certificate Authentication](#tls-certificate-authentication)
- [Configuration Reference](#configuration-reference)
- [Token Management](#token-management)

## Prerequisites

- Docker and Docker Compose installed and running
- An **OVHcloud account** with an OAuth2 service account (`client_id` + `client_secret`) — create one via [OVHcloud IAM](https://www.ovh.com/auth/) with `flow: "CLIENT_CREDENTIALS"`
- For S3 Object Storage: a Public Cloud project ID and user ID

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
warden write auth/jwt/role/ovh-user \
    token_policies="ovh-access" \
    user_claim=sub \
    cred_spec_name=ovh-ops
```

## Step 2: Mount and Configure the Provider

Enable the OVH provider at a path of your choice:

```bash
warden provider enable --type=ovh
```

To mount at a custom path:

```bash
warden provider enable --type=ovh ovh-prod
```

Verify the provider is enabled:

```bash
warden provider list
```

Configure the provider with `auto_auth_path`. This allows clients to authenticate with their JWT directly — no explicit Warden login required:

```bash
warden write ovh/config <<EOF
{
  "ovh_url": "https://eu.api.ovh.com/1.0",
  "auto_auth_path": "auth/jwt/",
  "timeout": "30s",
  "max_body_size": 10485760
}
EOF
```

Verify the configuration:

```bash
warden read ovh/config
```

## Step 3: Create a Credential Source and Spec

Create an OVH credential source using an OAuth2 service account. Warden automatically mints bearer tokens (~1h TTL, auto-refreshed) and/or creates S3 credentials on demand.

**Prerequisites:** An OVH OAuth2 service account — create one via `POST /me/api/oauth2/client` with `flow: "CLIENT_CREDENTIALS"`. See the [e2e test README](e2e_test/README.md#creating-an-oauth2-api-token) for step-by-step instructions.

```bash
warden cred source create ovh-src \
  --type=ovh \
  --config client_id=your-client-id \
  --config client_secret=your-client-secret \
  --config ovh_endpoint=ovh-eu \
  --config project_id=your-cloud-project-id \
  --config user_id=your-cloud-user-id
```

The `project_id` and `user_id` are only needed for S3 credential management (`dynamic_s3` and `oauth2_token_and_s3` mint methods). They can be omitted if you only need API tokens, or overridden per-spec for multi-tenant S3 access.

**API-only mode** (auto-refreshed OAuth2 bearer tokens):

```bash
warden cred spec create ovh-api \
  --source ovh-src \
  --type=ovh_keys \
  --config mint_method=oauth2_token
```

**S3-only mode** (dynamic S3 credentials, revocable):

```bash
warden cred spec create ovh-s3 \
  --source ovh-src \
  --type=ovh_keys \
  --config mint_method=dynamic_s3
```

**Dual mode** (OAuth2 token + S3 credentials):

```bash
warden cred spec create ovh-dual \
  --source ovh-src \
  --type=ovh_keys \
  --config mint_method=oauth2_token_and_s3
```

**Multi-tenant S3 access** — override `project_id` and `user_id` per-spec to target different S3 users:

```bash
# Read-only S3 user
warden cred spec create ovh-s3-reader \
  --source ovh-src \
  --type=ovh_keys \
  --config mint_method=dynamic_s3 \
  --config project_id=my-project \
  --config user_id=reader-user-id

# Read-write S3 user
warden cred spec create ovh-s3-writer \
  --source ovh-src \
  --type=ovh_keys \
  --config mint_method=dynamic_s3 \
  --config project_id=my-project \
  --config user_id=writer-user-id
```

Verify:

```bash
warden cred spec read ovh-api
```

## Step 4: Create a Policy

Create a policy that grants access to the OVH provider gateway:

```bash
warden policy write ovh-access - <<EOF
path "ovh/role/+/gateway*" {
  capabilities = ["create", "read", "update", "delete", "patch"]
}
EOF
```

For fine-grained access control, restrict which OVH resources and actions a role can use:

```bash
warden policy write ovh-readonly - <<EOF
path "ovh/role/+/gateway/me" {
  capabilities = ["read"]
}

path "ovh/role/+/gateway/cloud/project" {
  capabilities = ["read"]
}

path "ovh/role/+/gateway/domain" {
  capabilities = ["read"]
}

path "ovh/role/+/gateway/ip" {
  capabilities = ["read"]
}
EOF
```

Verify:

```bash
warden policy read ovh-access
```

## Step 5: Get a JWT and Make Requests

Get a JWT from Hydra using one of the quickstart clients:

```bash
export JWT_TOKEN=$(curl -s -X POST http://localhost:4444/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=my-agent&client_secret=agent-secret&scope=api:read api:write" \
  | jq -r '.access_token')
```

Requests use role-based paths. Warden performs implicit JWT authentication and injects the OVH credentials automatically.

The URL pattern is: `/v1/ovh/role/{role}/gateway/{api-path}`

Export OVH_ENDPOINT as environment variable:
```bash
export OVH_ENDPOINT="${WARDEN_ADDR}/v1/ovh/role/ovh-user/gateway"
```

### Get Account Info

```bash
curl -s "${OVH_ENDPOINT}/me" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### List Cloud Projects

```bash
curl -s "${OVH_ENDPOINT}/cloud/project" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### List Domains

```bash
curl -s "${OVH_ENDPOINT}/domain" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### List IP Addresses

```bash
curl -s "${OVH_ENDPOINT}/ip" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### Get Cloud Project Details

```bash
curl -s "${OVH_ENDPOINT}/cloud/project/{projectId}" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### List Cloud Project Instances

```bash
curl -s "${OVH_ENDPOINT}/cloud/project/{projectId}/instance" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

## S3 Object Storage

The OVH provider auto-detects S3 requests by the presence of a SigV4 `Authorization` header. Any S3-compatible client works — AWS CLI, boto3, s3cmd, MinIO Client.

### S3 Transparent Auth with JWT

Configure your S3 client to point at Warden's gateway endpoint. Use your JWT as both the access key and secret key:

```bash
aws configure set aws_access_key_id "${JWT_TOKEN}"
aws configure set aws_secret_access_key "${JWT_TOKEN}"
aws configure set region gra
```

### S3 Transparent Auth with Certificates

For certificate-based authentication, use the role name as both the access key and secret key:

```bash
aws configure set aws_access_key_id "ovh-user"
aws configure set aws_secret_access_key "ovh-user"
aws configure set region gra
```

### S3 Operations

```bash
# List buckets
aws s3 ls \
  --endpoint-url "${WARDEN_ADDR}/v1/ovh/role/ovh-user/gateway"

# List objects in a bucket
aws s3 ls s3://my-bucket/ \
  --endpoint-url "${WARDEN_ADDR}/v1/ovh/role/ovh-user/gateway"

# Upload a file
aws s3 cp myfile.txt s3://my-bucket/myfile.txt \
  --endpoint-url "${WARDEN_ADDR}/v1/ovh/role/ovh-user/gateway"

# Download a file
aws s3 cp s3://my-bucket/myfile.txt ./downloaded.txt \
  --endpoint-url "${WARDEN_ADDR}/v1/ovh/role/ovh-user/gateway"
```

### Supported S3 Regions

| Region | Location | S3 Endpoint |
|--------|----------|-------------|
| `gra` | Gravelines, France | `s3.gra.io.cloud.ovh.net` |
| `bhs` | Beauharnois, Canada | `s3.bhs.io.cloud.ovh.net` |
| `sbg` | Strasbourg, France | `s3.sbg.io.cloud.ovh.net` |
| `de` | Frankfurt, Germany | `s3.de.io.cloud.ovh.net` |
| `uk` | London, United Kingdom | `s3.uk.io.cloud.ovh.net` |
| `waw` | Warsaw, Poland | `s3.waw.io.cloud.ovh.net` |

The region is extracted from the SigV4 Authorization header and used to route to the correct OVH S3 endpoint.

## Cleanup

To stop Warden and the identity provider:

```bash
# Stop Warden (Ctrl+C in the terminal where it's running)

# Stop and remove the identity provider containers
docker compose -f docker-compose.quickstart.yml down -v
```

Since Warden dev mode uses in-memory storage, all configuration is lost when the server stops.

## Regional Endpoints

OVHcloud operates three regional API endpoints. Each region has its own API base URL and OAuth2 token URL.

| Region | API Base URL | OAuth2 Token URL |
|--------|-------------|-----------------|
| Europe (default) | `https://eu.api.ovh.com/1.0` | `https://www.ovh.com/auth/oauth2/token` |
| Canada | `https://ca.api.ovh.com/1.0` | `https://ca.ovh.com/auth/oauth2/token` |
| United States | `https://api.us.ovhcloud.com/1.0` | `https://us.ovhcloud.com/auth/oauth2/token` |

To use a non-EU region, update the provider config:

```bash
# Example: configure for the US region
warden write ovh/config <<EOF
{
  "ovh_url": "https://api.us.ovhcloud.com/1.0",
  "auto_auth_path": "auth/jwt/",
  "timeout": "30s"
}
EOF
```

S3 Object Storage regions are independent of the API region and are auto-detected from the SigV4 header.

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
    default_role=ovh-user
```

### Create a Cert Role

Create a role that binds allowed certificate identities to a credential spec and policy:

```bash
warden write auth/cert/role/ovh-user \
    allowed_common_names="agent-*" \
    token_policies="ovh-access" \
    cred_spec_name=ovh-ops
```

The `allowed_common_names` field supports glob patterns. You can also match on other certificate fields: `allowed_dns_sans`, `allowed_email_sans`, `allowed_uri_sans`, or `allowed_organizational_units`.

### Configure Provider for Cert Auth

Update the provider config to use cert auth:

```bash
warden write ovh/config <<EOF
{
  "ovh_url": "https://eu.api.ovh.com/1.0",
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
    -s "https://warden.internal/v1/ovh/role/ovh-user/gateway/me" \
    -H "Content-Type: application/json"
```

S3 Object Storage:

```bash
aws s3 ls s3://my-bucket/ \
  --endpoint-url "https://warden.internal/v1/ovh/role/ovh-user/gateway"
```

## Configuration Reference

### Provider Config

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `ovh_url` | string | `https://eu.api.ovh.com/1.0` | OVH API base URL |
| `max_body_size` | int | 10485760 (10 MB) | Maximum request body size in bytes (max 100 MB) |
| `timeout` | duration | `30s` | Request timeout |
| `auto_auth_path` | string | — | **Required.** Auth mount path for implicit authentication (e.g., `auth/jwt/`, `auth/cert/`) |
| `default_role` | string | — | Fallback role when not specified in URL |

### Credential Source Config (OVH OAuth2)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `client_id` | string | Yes | OAuth2 service account client ID |
| `client_secret` | string | Yes | OAuth2 service account client secret (sensitive) |
| `ovh_endpoint` | string | No | Regional endpoint: `ovh-eu` (default), `ovh-ca`, or `ovh-us` |
| `project_id` | string | For S3 | Default Public Cloud project ID (can be overridden per-spec) |
| `user_id` | string | For S3 | Default Public Cloud user ID (can be overridden per-spec) |

### Credential Spec Config (OVH source — oauth2_token)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mint_method` | string | Yes | Must be `oauth2_token` |

### Credential Spec Config (OVH source — dynamic_s3)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mint_method` | string | Yes | Must be `dynamic_s3` |
| `project_id` | string | No | Override source default project ID |
| `user_id` | string | No | Override source default user ID |

### Credential Spec Config (OVH source — oauth2_token_and_s3)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mint_method` | string | Yes | Must be `oauth2_token_and_s3` |
| `project_id` | string | No | Override source default project ID |
| `user_id` | string | No | Override source default user ID |

## Token Management

| Aspect | Details |
|--------|---------|
| **Storage** | OAuth2 `client_id` + `client_secret` stored on the credential source (long-lived) |
| **API tokens** | Auto-minted via `client_credentials` grant, ~1h TTL, refreshed automatically |
| **S3 credentials** | Created on demand via OVH API, revoked when credential lease expires |
| **Rotation** | Rotate the OAuth2 service account secret in OVHcloud IAM, then update the source |

**To rotate the OAuth2 service account:**

1. Create a new service account or regenerate the secret in OVHcloud IAM
2. Update the credential source:
   ```bash
   warden cred source update ovh-src \
     --config client_id=new-client-id \
     --config client_secret=new-client-secret
   ```
3. Revoke the old service account in OVHcloud IAM
