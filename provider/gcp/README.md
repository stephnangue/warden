# GCP Provider

The GCP provider enables proxied access to Google Cloud Platform APIs through Warden. It authenticates using service account keys, supports OAuth2 token minting and service account impersonation, and handles automated key rotation.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Step 1: Mount the GCP Provider](#step-1-mount-the-gcp-provider)
- [Step 2: Configure the Provider](#step-2-configure-the-provider)
- [Step 3: Create a Credential Source](#step-3-create-a-credential-source)
- [Step 4: Create a Credential Spec](#step-4-create-a-credential-spec)
- [Step 5: Create a Policy](#step-5-create-a-policy)
- [Step 6: Configure JWT Auth and Create a Role](#step-6-configure-jwt-auth-and-create-a-role)
- [Step 7: Get a JWT](#step-7-get-a-jwt)
- [Step 8: Make Requests Through the Gateway](#step-8-make-requests-through-the-gateway)
- [Mint Methods](#mint-methods)
- [Credential Rotation](#credential-rotation)
- [Configuration Reference](#configuration-reference)

## Prerequisites

- A running Warden server
- The Warden CLI installed and configured
- A GCP **service account key** (JSON format) with appropriate IAM permissions

> **New to Warden?** Download the binary from the [latest release](https://github.com/stephnangue/warden/releases/latest), then start the identity provider and Warden in dev mode:
> ```bash
> curl -fsSL -o docker-compose.quickstart.yml \
>   https://raw.githubusercontent.com/stephnangue/warden/main/docker-compose.quickstart.yml
> docker compose -f docker-compose.quickstart.yml up -d
> ./warden server --dev
> ```

```bash
export WARDEN_ADDR="http://127.0.0.1:8400"
export WARDEN_TOKEN="<your-token>"
```

### Creating a Service Account Key

1. Go to the [GCP Console](https://console.cloud.google.com/) > **IAM & Admin > Service Accounts**.
2. Select or create a service account.
3. Go to the **Keys** tab and click **Add Key > Create new key > JSON**.
4. Download the JSON key file.

For key rotation support, the service account also needs:
- `iam.serviceAccountKeys.create`
- `iam.serviceAccountKeys.delete`

For impersonation, the source service account needs `iam.serviceAccounts.getAccessToken` on the target service account.

## Step 1: Mount the GCP Provider

Enable the GCP provider at a path of your choice:

```bash
warden provider enable --type=gcp
```

To mount at a custom path:

```bash
warden provider enable --type=gcp gcp-prod
```

Verify the provider is enabled:

```bash
warden provider list
```

## Step 2: Configure the Provider

Configure the provider with transparent mode enabled. This allows clients to authenticate with their JWT directly — no explicit Warden login required:

```bash
warden write gcp/config <<EOF
{
  "transparent_mode": true,
  "auto_auth_path": "auth/jwt/",
  "timeout": "30s",
  "max_body_size": 10485760
}
EOF
```

Verify the configuration:

```bash
warden read gcp/config
```

## Step 3: Create a Credential Source

The credential source holds the service account key used to authenticate with GCP.

```bash
warden cred source create gcp-sa \
  --type=gcp_access_token \
  --rotation-period=720h \
  --config=source=gcp \
  --config=service_account_key=@/path/to/service-account-key.json
```

The `@` prefix reads the file contents into the config value.

Verify the source was created:

```bash
warden cred source read gcp-sa
```

## Step 4: Create a Credential Spec

Create a credential spec that references the credential source. The spec defines how Warden mints OAuth2 tokens and gets associated with tokens at login time.

### Option A: Direct Access Token (Recommended)

Mint OAuth2 access tokens using the source service account directly:

```bash
warden cred spec create gcp-cloud-platform \
  --type=gcp_access_token \
  --source=gcp-sa \
  --min-ttl=5m \
  --max-ttl=1h \
  --config=mint_method=access_token \
  --config=scopes=https://www.googleapis.com/auth/cloud-platform
```

### Option B: Impersonated Access Token

Mint tokens on behalf of another service account:

```bash
warden cred spec create gcp-impersonated \
  --type=gcp_access_token \
  --source=gcp-sa \
  --min-ttl=5m \
  --max-ttl=1h \
  --config=mint_method=impersonated_access_token \
  --config=target_service_account=target@my-project.iam.gserviceaccount.com \
  --config=scopes=https://www.googleapis.com/auth/cloud-platform \
  --config=lifetime=3600s
```

Verify:

```bash
warden cred spec read gcp-cloud-platform
```

## Step 5: Create a Policy

Create a policy that grants access to the GCP provider gateway. Note that this policy is intentionally coarse-grained for simplicity, but it can be made much more fine-grained to restrict access to specific paths or capabilities as needed:

```bash
warden policy write gcp-access - <<EOF
path "gcp/role/+/gateway*" {
  capabilities = ["create", "read", "update", "delete", "patch"]
}
EOF
```

Verify:

```bash
warden policy read gcp-access
```

## Step 6: Configure JWT Auth and Create a Role

Set up a JWT auth method and create a role that binds the credential spec and policy. With transparent mode, clients authenticate directly with their JWT — no separate login step is needed.

```bash
# Enable JWT auth if not already enabled
warden auth enable --type=jwt

# Configure JWT with Hydra's JWKS endpoint (from docker-compose.quickstart.yml)
warden write auth/jwt/config mode=jwt jwks_url=http://localhost:4444/.well-known/jwks.json

# Create a role that binds the credential spec and policy
warden write auth/jwt/role/gcp-user \
    token_type=jwt_role \
    token_policies="gcp-access" \
    user_claim=sub \
    cred_spec_name=gcp-cloud-platform \
    token_ttl=1h
```

## Step 7: Get a JWT

Get a JWT from Hydra using one of the quickstart clients:

```bash
export JWT_TOKEN=$(curl -s -X POST http://localhost:4444/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=my-agent&client_secret=agent-secret&scope=api:read api:write" \
  | jq -r '.access_token')
```

## Step 8: Make Requests Through the Gateway

With transparent mode, requests use role-based paths. Warden performs implicit JWT authentication and injects the OAuth2 Bearer token automatically.

The URL pattern is: `/v1/gcp/role/{role}/gateway/{googleapis-host}/{path}`

The first path segment after `gateway/` is the GCP API host, and the rest is the API path.

Export GCP_ENDPOINT as environment variable:
```bash
export GCP_ENDPOINT="${WARDEN_ADDR}/v1/gcp/role/gcp-user/gateway"
```

### Cloud Storage — List Buckets

```bash
curl "${GCP_ENDPOINT}/storage.googleapis.com/storage/v1/b?project=my-project" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### Cloud Storage — Get Object

```bash
curl "${GCP_ENDPOINT}/storage.googleapis.com/storage/v1/b/my-bucket/o/my-object" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### Compute Engine — List Instances

```bash
curl "${GCP_ENDPOINT}/compute.googleapis.com/compute/v1/projects/my-project/zones/us-central1-a/instances" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### Secret Manager — List Secrets

```bash
curl "${GCP_ENDPOINT}/secretmanager.googleapis.com/v1/projects/my-project/secrets" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### BigQuery — List Datasets

```bash
curl "${GCP_ENDPOINT}/bigquery.googleapis.com/bigquery/v2/projects/my-project/datasets" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### IAM — List Service Accounts

```bash
curl "${GCP_ENDPOINT}/iam.googleapis.com/v1/projects/my-project/serviceAccounts" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

## Cleanup

To stop Warden and the identity provider:

```bash
# Stop Warden (Ctrl+C in the terminal where it's running)

# Stop and remove the identity provider containers
docker compose -f docker-compose.quickstart.yml down -v
```

Since Warden dev mode uses in-memory storage, all configuration is lost when the server stops.

## Mint Methods

| Method | Description | Token Lifetime | Use Case |
|--------|-------------|----------------|----------|
| `access_token` | OAuth2 token from source SA key | ~1 hour (auto-refreshed) | Direct access with source SA permissions |
| `impersonated_access_token` | Token minted on behalf of another SA | Configurable via `lifetime` (default: 1h) | Least-privilege delegation without sharing target SA keys |

Both methods return tokens that expire naturally and cannot be revoked.

### Returned Credential Data

```json
{
  "access_token": "ya29.xxx...",
  "project_id": "my-project",
  "scopes": "https://www.googleapis.com/auth/cloud-platform",
  "token_type": "Bearer",
  "target_service_account": "target@my-project.iam.gserviceaccount.com"
}
```

The `target_service_account` field is only present for impersonated tokens.

## Credential Rotation

The GCP provider supports the two-stage async rotation pattern for service account keys:

1. **Prepare**: Creates a new service account key via the IAM API.
2. **Activate**: After the activation delay, switches to the new key and invalidates all cached tokens.
3. **Cleanup**: Deletes the old service account key via the IAM API.

The default activation delay is **2 minutes** (configurable via `activation_delay` in the credential source config). This accounts for IAM propagation time across GCP.

When the source key rotates, all credential specs sharing that source automatically use the new key — no per-spec rotation is needed.

## Configuration Reference

### Provider Config

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_body_size` | int | 10485760 (10 MB) | Maximum request body size in bytes (max 100 MB) |
| `timeout` | duration | `30s` | Request timeout (e.g., `30s`, `5m`) |
| `transparent_mode` | bool | `false` | Enable implicit JWT authentication |
| `auto_auth_path` | string | — | JWT auth mount path (required when `transparent_mode` is true) |
| `default_role` | string | — | Fallback role when not specified in URL |

### Credential Source Config

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `service_account_key` | string | Yes | Full JSON service account key |
| `activation_delay` | duration | No | Delay before activating rotated keys (default: `2m`) |

### Credential Spec Config (Direct Access Token)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mint_method` | string | Yes | Must be `access_token` |
| `scopes` | string | No | Comma-separated OAuth2 scopes (default: `https://www.googleapis.com/auth/cloud-platform`) |

### Credential Spec Config (Impersonated Access Token)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mint_method` | string | Yes | Must be `impersonated_access_token` |
| `target_service_account` | string | Yes | Email of the service account to impersonate |
| `scopes` | string | No | Comma-separated OAuth2 scopes (default: `https://www.googleapis.com/auth/cloud-platform`) |
| `lifetime` | string | No | Token lifetime (default: `3600s`, max: `43200s` / 12 hours) |
