# Dynatrace Provider

The Dynatrace provider enables proxied access to the Dynatrace REST API through Warden. It forwards requests to Dynatrace endpoints (Entities, Metrics, Logs, Problems, Settings, Tokens, etc.) with automatic credential injection and policy evaluation. Two authentication modes are supported: static API tokens (`apikey` source type) using the `Api-Token` authorization scheme, and OAuth2 client credentials (`oauth2` source type) using the `Bearer` authorization scheme. Vault/OpenBao can also be used as a credential source (`hvault` source type).

## Table of Contents

- [Prerequisites](#prerequisites)
- [Step 1: Configure JWT Auth and Create a Role](#step-1-configure-jwt-auth-and-create-a-role)
- [Step 2: Mount and Configure the Provider](#step-2-mount-and-configure-the-provider)
- [Step 3: Create a Credential Source and Spec](#step-3-create-a-credential-source-and-spec)
- [Step 4: Create a Policy](#step-4-create-a-policy)
- [Step 5: Get a JWT and Make Requests](#step-5-get-a-jwt-and-make-requests)
- [TLS Certificate Authentication](#tls-certificate-authentication)
- [Configuration Reference](#configuration-reference)
- [Token Management](#token-management)

## Prerequisites

- Docker and Docker Compose installed and running
- A **Dynatrace environment** with either:
  - A **Dynatrace API Token** (from Dynatrace > Access tokens) with appropriate scopes, or
  - **OAuth2 client credentials** (from Dynatrace > Account Management > OAuth clients) for Platform API access

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
warden write auth/jwt/role/dynatrace-user \
    token_policies="dynatrace-access" \
    user_claim=sub \
    cred_spec_name=dynatrace-env
```

## Step 2: Mount and Configure the Provider

Enable the Dynatrace provider at a path of your choice:

```bash
warden provider enable --type=dynatrace
```

To mount at a custom path:

```bash
warden provider enable --type=dynatrace dynatrace-prod
```

Verify the provider is enabled:

```bash
warden provider list
```

Configure the provider with `auto_auth_path`. This allows clients to authenticate with their JWT directly — no explicit Warden login required:

```bash
warden write dynatrace/config <<EOF
{
  "dynatrace_url": "https://abc12345.live.dynatrace.com",
  "auto_auth_path": "auth/jwt/",
  "timeout": "30s",
  "max_body_size": 10485760
}
EOF
```

> **Important:** Replace `abc12345` with your actual Dynatrace environment ID. You can find it in your Dynatrace URL (e.g., `https://abc12345.live.dynatrace.com`).

Verify the configuration:

```bash
warden read dynatrace/config
```

## Step 3: Create a Credential Source and Spec

### Option A: Static API Token

The credential source holds only connection info. The API token is stored on the credential spec below, allowing multiple specs with different tokens and scopes to share one source.

```bash
warden cred source create dynatrace-src \
  --type=apikey \
  --rotation-period=0 \
  --config=api_url=https://abc12345.live.dynatrace.com \
  --config=verify_endpoint=/api/v2/tokens/lookup \
  --config=verify_method=POST \
  --config=auth_header_type=custom_header \
  --config=auth_header_name=Authorization \
  --config=extra_headers=Authorization:Api-Token \
  --config=display_name=Dynatrace
```

Create a credential spec that references the credential source. The spec carries the API token and gets associated with tokens at login time.

```bash
warden cred spec create dynatrace-env \
  --source dynatrace-src \
  --config api_key=dt0c01.XXXXXXXX.YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY
```

> **Note:** Dynatrace API tokens follow the format `dt0c01.{token-id}.{secret}`. You can create tokens in Dynatrace under Access tokens with specific scopes.

### Option B: OAuth2 Client Credentials

For Dynatrace Platform API access, use OAuth2 client credentials. This is recommended for applications and automation.

```bash
warden cred source create dynatrace-oauth-src \
  --type=oauth2 \
  --rotation-period=0 \
  --config=client_id=dt0s02.XXXXXXXX \
  --config=client_secret=dt0s02.XXXXXXXX.YYYYYYYYYYYYYYYYYYYY \
  --config=token_url=https://sso.dynatrace.com/sso/oauth2/token \
  --config=default_scopes="storage:buckets:read app-engine:apps:run" \
  --config=token_param.resource=urn:dtaccount:your-account-uuid \
  --config=display_name=Dynatrace
```

Create a credential spec (scope can be overridden per spec):

```bash
warden cred spec create dynatrace-platform \
  --source dynatrace-oauth-src \
  --config scope="storage:buckets:read storage:logs:read"
```

> **Note:** The `token_param.resource` on the source config injects the `resource` form parameter into the OAuth2 token exchange, as required by Dynatrace SSO. OAuth2 tokens are valid for 5 minutes; when a token expires, Warden transparently re-mints a fresh one on the next request.

When using OAuth2, configure the provider URL to point to the Platform API:

```bash
warden write dynatrace/config <<EOF
{
  "dynatrace_url": "https://abc12345.apps.dynatrace.com",
  "auto_auth_path": "auth/jwt/",
  "timeout": "30s"
}
EOF
```

### Option C: Vault/OpenBao as Credential Source

Instead of storing API tokens directly in Warden, you can store them in a Vault/OpenBao KV v2 secret engine and have Warden fetch them at runtime. This centralizes secret management in Vault.

**Prerequisites:** A Vault/OpenBao instance with:
- A KV v2 mount containing your Dynatrace API token (e.g., at `secret/dynatrace/env` with an `api_key` field)
- An AppRole configured for Warden access

```bash
# Create a Vault credential source
warden cred source create dynatrace-vault-src \
  --type=hvault \
  --config=vault_address=https://vault.example.com \
  --config=auth_method=approle \
  --config=role_id=your-role-id \
  --config=secret_id=your-secret-id \
  --config=approle_mount=approle \
  --config=role_name=warden-role \
  --rotation-period=24h
```

Create a credential spec using the `static_apikey` mint method:

```bash
warden cred spec create dynatrace-env \
  --source dynatrace-vault-src \
  --config mint_method=static_apikey \
  --config kv2_mount=secret \
  --config secret_path=dynatrace/env
```

The KV v2 secret at `secret/dynatrace/env` should contain an `api_key` field with the Dynatrace API token.

Verify:

```bash
warden cred spec read dynatrace-env
```

## Step 4: Create a Policy

Create a policy that grants access to the Dynatrace provider gateway:

```bash
warden policy write dynatrace-access - <<EOF
path "dynatrace/role/+/gateway*" {
  capabilities = ["create", "read", "update", "delete", "patch"]
}
EOF
```

For fine-grained access control, restrict which Dynatrace resources and actions a role can use:

```bash
warden policy write dynatrace-readonly - <<EOF
path "dynatrace/role/+/gateway/api/v2/entities*" {
  capabilities = ["read"]
}

path "dynatrace/role/+/gateway/api/v2/metrics*" {
  capabilities = ["read"]
}

path "dynatrace/role/+/gateway/api/v2/problems*" {
  capabilities = ["read"]
}

path "dynatrace/role/+/gateway/api/v2/logs/search" {
  capabilities = ["read"]
}

path "dynatrace/role/+/gateway/api/v2/settings/objects" {
  capabilities = ["read"]
}
EOF
```

Verify:

```bash
warden policy read dynatrace-access
```

## Step 5: Get a JWT and Make Requests

Get a JWT from Hydra using one of the quickstart clients:

```bash
export JWT_TOKEN=$(curl -s -X POST http://localhost:4444/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=my-agent&client_secret=agent-secret&scope=api:read api:write" \
  | jq -r '.access_token')
```

Requests use role-based paths. Warden performs implicit JWT authentication and injects the Dynatrace credentials automatically.

The URL pattern is: `/v1/dynatrace/role/{role}/gateway/{api-path}`

Export DT_ENDPOINT as environment variable:
```bash
export DT_ENDPOINT="${WARDEN_ADDR}/v1/dynatrace/role/dynatrace-user/gateway"
```

### List Entities

```bash
curl -s "${DT_ENDPOINT}/api/v2/entities?pageSize=10" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### Query Metrics

```bash
curl -s "${DT_ENDPOINT}/api/v2/metrics/query?metricSelector=builtin:host.cpu.usage&from=now-1h" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### List Problems

```bash
curl -s "${DT_ENDPOINT}/api/v2/problems?from=now-24h" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### Search Logs

```bash
curl -s -X POST "${DT_ENDPOINT}/api/v2/logs/search" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "status=ERROR",
    "from": "now-1h",
    "to": "now",
    "limit": 25
  }'
```

### List Settings Objects

```bash
curl -s "${DT_ENDPOINT}/api/v2/settings/objects?schemaIds=builtin:alerting.profile&pageSize=10" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### List API Tokens

```bash
curl -s "${DT_ENDPOINT}/api/v2/apiTokens?pageSize=10" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### Create a Custom Event for Alerting

```bash
curl -s -X POST "${DT_ENDPOINT}/api/v2/events/ingest" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "eventType": "CUSTOM_ALERT",
    "title": "Deployment completed",
    "properties": {
      "service": "web-app",
      "version": "2.1.0",
      "environment": "production"
    }
  }'
```

## Cleanup

To stop Warden and the identity provider:

```bash
# Stop Warden (Ctrl+C in the terminal where it's running)

# Stop and remove the identity provider containers
docker compose -f docker-compose.quickstart.yml down -v
```

Since Warden dev mode uses in-memory storage, all configuration is lost when the server stops.

## TLS Certificate Authentication

Steps 1-3 above use JWT authentication. Alternatively, you can authenticate with a TLS client certificate. This is useful for workloads that already have X.509 certificates — Kubernetes pods with cert-manager, VMs with machine certificates, or SPIFFE X.509-SVIDs from a service mesh.

> **Prerequisite:** Certificate authentication requires TLS to be enabled on the Warden listener so that client certificates can be presented during the TLS handshake (mTLS). In dev mode, use `--dev-tls` to enable TLS with auto-generated certificates, or provide your own with `--dev-tls-cert-file`, `--dev-tls-key-file`, and `--dev-tls-ca-cert-file`. Alternatively, place Warden behind a load balancer that terminates TLS and forwards the client certificate via the `X-Forwarded-Client-Cert` or `X-SSL-Client-Cert` header.

Steps 1-3 (provider setup) are identical. Replace Steps 1 and 5 with the following.

### Enable Cert Auth

```bash
warden auth enable --type=cert
```

### Configure Trusted CA

Provide the PEM-encoded CA certificate that signs your client certificates:

```bash
warden write auth/cert/config \
    trusted_ca_pem=@/path/to/ca.pem \
    default_role=dynatrace-user
```

### Create a Cert Role

Create a role that binds allowed certificate identities to a credential spec and policy:

```bash
warden write auth/cert/role/dynatrace-user \
    allowed_common_names="agent-*" \
    token_policies="dynatrace-access" \
    cred_spec_name=dynatrace-env
```

The `allowed_common_names` field supports glob patterns. You can also match on other certificate fields: `allowed_dns_sans`, `allowed_email_sans`, `allowed_uri_sans`, or `allowed_organizational_units`.

### Configure Provider for Cert Auth

Update the provider config to use cert auth:

```bash
warden write dynatrace/config <<EOF
{
  "dynatrace_url": "https://abc12345.live.dynatrace.com",
  "auto_auth_path": "auth/cert/",
  "timeout": "30s",
  "max_body_size": 10485760
}
EOF
```

### Make Requests with Certificates

```bash
curl --cert client.pem --key client-key.pem \
    --cacert warden-ca.pem \
    -s "https://warden.internal/v1/dynatrace/role/dynatrace-user/gateway/api/v2/entities?pageSize=10" \
    -H "Content-Type: application/json"
```

## Configuration Reference

### Provider Config

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `dynatrace_url` | string | — | Dynatrace API base URL (required — must include your environment ID) |
| `max_body_size` | int | 10485760 (10 MB) | Maximum request body size in bytes (max 100 MB) |
| `timeout` | duration | `30s` | Request timeout |
| `auto_auth_path` | string | — | Auth mount path for implicit authentication (e.g., `auth/jwt/`, `auth/cert/`) |
| `default_role` | string | — | Fallback role when not specified in URL |

### Credential Source Config (Static API Token)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `api_url` | string | No | API base URL for verification |
| `verify_endpoint` | string | No | Verification path (e.g., `/api/v2/tokens/lookup`) |
| `verify_method` | string | No | HTTP method for verification (e.g., `POST`) |
| `auth_header_type` | string | No | How to attach key for verification: `custom_header` |
| `auth_header_name` | string | No | Header name for verification (e.g., `Authorization`) |
| `display_name` | string | No | Label for logs/errors (default: `API Key`) |

### Credential Spec Config (Static API Token)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `api_key` | string | Yes | Dynatrace API token (sensitive — masked in output) |

### Credential Source Config (OAuth2)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `client_id` | string | Yes | OAuth2 client ID (e.g., `dt0s02.XXXXXXXX`) |
| `client_secret` | string | Yes | OAuth2 client secret (sensitive) |
| `token_url` | string | Yes | OAuth2 token endpoint (`https://sso.dynatrace.com/sso/oauth2/token`) |
| `default_scopes` | string | No | Default OAuth2 scopes (space-separated) |
| `token_param.resource` | string | No | Account URN for Platform API (e.g., `urn:dtaccount:{account-uuid}`) |
| `display_name` | string | No | Label for logs/errors (default: `OAuth2`) |

### Credential Spec Config (OAuth2)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `scope` | string | No | OAuth2 scope override (space-separated; defaults to source's `default_scopes`) |

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

### Credential Spec Config (Vault — static_apikey)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mint_method` | string | Yes | Must be `static_apikey` |
| `kv2_mount` | string | Yes | KV v2 mount path in Vault |
| `secret_path` | string | Yes | Path to the secret within the mount (must contain `api_key`) |

## Token Management

### Static API Tokens

| Aspect | Details |
|--------|---------|
| **Storage** | API token is stored on the credential spec (not the source) |
| **Validation** | Token is verified at spec creation via `POST /api/v2/tokens/lookup` |
| **Rotation** | Manual — regenerate in Dynatrace and update the spec |
| **Lifetime** | Configurable in Dynatrace (can be set to never expire or with a specific expiry) |
| **Rate Limits** | 50 requests/minute per environment |

**To rotate Dynatrace API tokens:**

1. Create a new API token in Dynatrace (Access tokens > Generate new token) with the same scopes
2. Update the credential spec:
   ```bash
   warden cred spec update dynatrace-env \
     --config api_key=dt0c01.NEW_TOKEN_ID.NEW_TOKEN_SECRET
   ```
3. Revoke the old token in Dynatrace

### OAuth2 Tokens

| Aspect | Details |
|--------|---------|
| **Storage** | Client credentials are stored on the credential source (not the spec) |
| **Minting** | Warden exchanges credentials for a bearer token on each request (cached by TTL) |
| **Lifetime** | 5 minutes (Warden transparently re-mints on the next request after expiry) |
| **Rate Limits** | 50 requests/minute per environment |
