# Grafana Provider

The Grafana provider enables proxied access to the entire Grafana ecosystem through Warden: the dashboard/admin HTTP API, Loki (logs), Mimir (metrics), Tempo (traces), and Pyroscope (profiling). It forwards requests with automatic credential injection and policy evaluation.

A single provider type supports all Grafana services. Mount multiple instances with different `grafana_url` values and use the optional `tenant_id` config to inject the `X-Scope-OrgID` header required by Loki, Mimir, Tempo, and Pyroscope.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Step 1: Configure JWT Auth and Create a Role](#step-1-configure-jwt-auth-and-create-a-role)
- [Step 2: Mount and Configure the Provider](#step-2-mount-and-configure-the-provider)
- [Step 3: Create a Credential Source and Spec](#step-3-create-a-credential-source-and-spec)
- [Step 4: Create a Policy](#step-4-create-a-policy)
- [Step 5: Get a JWT and Make Requests](#step-5-get-a-jwt-and-make-requests)
- [Multi-Service Setup](#multi-service-setup)
- [TLS Certificate Authentication](#tls-certificate-authentication)
- [Configuration Reference](#configuration-reference)
- [Token Management](#token-management)

## Prerequisites

- Docker and Docker Compose installed and running
- A **Grafana service account token** (from Grafana > Administration > Service Accounts) or a **Grafana Cloud access policy token** (from Grafana Cloud > Access Policies)

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
warden write auth/jwt/role/grafana-user \
    token_policies="grafana-access" \
    user_claim=sub \
    cred_spec_name=grafana-ops
```

## Step 2: Mount and Configure the Provider

Enable the Grafana provider at a path of your choice:

```bash
warden provider enable --type=grafana
```

To mount at a custom path (useful for multi-service setups):

```bash
warden provider enable --type=grafana grafana-loki
```

Verify the provider is enabled:

```bash
warden provider list
```

Configure the provider with `auto_auth_path`. This allows clients to authenticate with their JWT directly — no explicit Warden login required:

```bash
warden write grafana/config <<EOF
{
  "grafana_url": "https://mystack.grafana.net/api",
  "auto_auth_path": "auth/jwt/",
  "timeout": "30s",
  "max_body_size": 10485760
}
EOF
```

Verify the configuration:

```bash
warden read grafana/config
```

## Step 3: Create a Credential Source and Spec

### Option A: Static Service Account Token

Create a service account in Grafana:
1. Go to **Administration > Users and Access > Service Accounts**
2. Click **Add service account**
3. Assign a role (Viewer, Editor, or Admin) and create a token
4. Copy the generated token (it is only displayed once)

```bash
warden cred source create grafana-src \
  --type=apikey \
  --rotation-period=0 \
  --config=api_url=https://mystack.grafana.net/api \
  --config=verify_endpoint=/org \
  --config=display_name=Grafana
```

Create a credential spec that references the credential source:

```bash
warden cred spec create grafana-ops \
  --source grafana-src \
  --config api_key=glsa_your-service-account-token
```

### Option B: Dynamic Tokens via Grafana Source Driver

The Grafana source driver uses an admin service account token to programmatically create short-lived service accounts and tokens via the Grafana HTTP API.

```bash
# Create a Grafana credential source with admin token
warden cred source create grafana-dynamic-src \
  --type=grafana \
  --config=grafana_url=https://mystack.grafana.net \
  --config=admin_token=glsa_your-admin-token
```

Create a credential spec for dynamic token minting:

```bash
warden cred spec create grafana-ops \
  --source grafana-dynamic-src \
  --config role=Viewer \
  --config token_expiry=1h \
  --config name_prefix=warden-
```

### Option C: Vault/OpenBao as Credential Source

Store the Grafana token in Vault/OpenBao KV v2 and have Warden fetch it at runtime:

```bash
warden cred source create grafana-vault-src \
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
warden cred spec create grafana-ops \
  --source grafana-vault-src \
  --config mint_method=static_apikey \
  --config kv2_mount=secret \
  --config secret_path=grafana/ops
```

## Step 4: Create a Policy

Create a policy that grants access to the Grafana provider gateway:

```bash
warden policy write grafana-access - <<EOF
path "grafana/role/+/gateway*" {
  capabilities = ["create", "read", "update", "delete", "patch"]
}
EOF
```

For multi-service setups, include all mount paths:

```bash
warden policy write grafana-access - <<EOF
path "grafana/role/+/gateway*" {
  capabilities = ["create", "read", "update", "delete", "patch"]
}

path "grafana-loki/role/+/gateway*" {
  capabilities = ["create", "read", "update", "delete", "patch"]
}

path "grafana-mimir/role/+/gateway*" {
  capabilities = ["read"]
}
EOF
```

## Step 5: Get a JWT and Make Requests

Get a JWT from Hydra using one of the quickstart clients:

```bash
export JWT_TOKEN=$(curl -s -X POST http://localhost:4444/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=my-agent&client_secret=agent-secret&scope=api:read api:write" \
  | jq -r '.access_token')
```

The URL pattern is: `/v1/grafana/role/{role}/gateway/{api-path}`

```bash
export GRAFANA_ENDPOINT="${WARDEN_ADDR}/v1/grafana/role/grafana-user/gateway"
```

### Get Organization Info

```bash
curl -s "${GRAFANA_ENDPOINT}/org" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### List Dashboards

```bash
curl -s "${GRAFANA_ENDPOINT}/search?type=dash-db" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### Get a Dashboard by UID

```bash
curl -s "${GRAFANA_ENDPOINT}/dashboards/uid/{uid}" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### List Data Sources

```bash
curl -s "${GRAFANA_ENDPOINT}/datasources" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### Search Service Accounts

```bash
curl -s "${GRAFANA_ENDPOINT}/serviceaccounts/search" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### List Alerts

```bash
curl -s "${GRAFANA_ENDPOINT}/alertmanager/grafana/api/v2/alerts" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

## Multi-Service Setup

Mount multiple instances of the Grafana provider for different ecosystem services. All share the same credential (a Grafana Cloud access policy token with the appropriate scopes).

### Loki (Logs)

```bash
warden provider enable --type=grafana grafana-loki

warden write grafana-loki/config <<EOF
{
  "grafana_url": "https://logs-prod-us-central1.grafana.net",
  "tenant_id": "12345",
  "auto_auth_path": "auth/jwt/",
  "timeout": "30s"
}
EOF
```

```bash
export LOKI_ENDPOINT="${WARDEN_ADDR}/v1/grafana-loki/role/grafana-user/gateway"

# Query logs
curl -s "${LOKI_ENDPOINT}/loki/api/v1/query?query={job=\"myapp\"}" \
  -H "Authorization: Bearer ${JWT_TOKEN}"

# Query log range
curl -s "${LOKI_ENDPOINT}/loki/api/v1/query_range?query={job=\"myapp\"}&start=1609459200&end=1609545600" \
  -H "Authorization: Bearer ${JWT_TOKEN}"

# List labels
curl -s "${LOKI_ENDPOINT}/loki/api/v1/labels" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### Mimir (Metrics)

```bash
warden provider enable --type=grafana grafana-mimir

warden write grafana-mimir/config <<EOF
{
  "grafana_url": "https://prometheus-prod-us-central1.grafana.net",
  "tenant_id": "12345",
  "auto_auth_path": "auth/jwt/",
  "timeout": "30s"
}
EOF
```

```bash
export MIMIR_ENDPOINT="${WARDEN_ADDR}/v1/grafana-mimir/role/grafana-user/gateway"

# Instant query
curl -s "${MIMIR_ENDPOINT}/prometheus/api/v1/query?query=up" \
  -H "Authorization: Bearer ${JWT_TOKEN}"

# Range query
curl -s "${MIMIR_ENDPOINT}/prometheus/api/v1/query_range?query=up&start=1609459200&end=1609545600&step=60" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### Tempo (Traces)

```bash
warden provider enable --type=grafana grafana-tempo

warden write grafana-tempo/config <<EOF
{
  "grafana_url": "https://tempo-us-central1.grafana.net",
  "tenant_id": "12345",
  "auto_auth_path": "auth/jwt/",
  "timeout": "30s"
}
EOF
```

```bash
export TEMPO_ENDPOINT="${WARDEN_ADDR}/v1/grafana-tempo/role/grafana-user/gateway"

# Search traces
curl -s "${TEMPO_ENDPOINT}/api/search?q={resource.service.name=\"myapp\"}" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

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
    default_role=grafana-user
```

### Create a Cert Role

```bash
warden write auth/cert/role/grafana-user \
    allowed_common_names="agent-*" \
    token_policies="grafana-access" \
    cred_spec_name=grafana-ops
```

### Configure Provider for Cert Auth

```bash
warden write grafana/config <<EOF
{
  "grafana_url": "https://mystack.grafana.net/api",
  "auto_auth_path": "auth/cert/",
  "timeout": "30s"
}
EOF
```

### Make Requests with Certificates

```bash
curl --cert client.pem --key client-key.pem \
    --cacert warden-ca.pem \
    -s "https://warden.internal/v1/grafana/role/grafana-user/gateway/org" \
    -H "Content-Type: application/json"
```

## Configuration Reference

### Provider Config

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `grafana_url` | string | `https://grafana.com/api` | Grafana API base URL (must be HTTPS) |
| `tenant_id` | string | — | Tenant/org ID injected as `X-Scope-OrgID` header (required for Loki, Mimir, Tempo, Pyroscope) |
| `max_body_size` | int | 10485760 (10 MB) | Maximum request body size in bytes (max 100 MB) |
| `timeout` | duration | `30s` | Request timeout |
| `auto_auth_path` | string | — | **Required.** Auth mount path for implicit authentication (e.g., `auth/jwt/`, `auth/cert/`) |
| `default_role` | string | — | Fallback role when not specified in URL |

### Credential Source Config (Grafana Driver)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `grafana_url` | string | Yes | Grafana API base URL (e.g., `https://mystack.grafana.net`) |
| `admin_token` | string | Yes | Admin service account token with ServiceAccount admin permissions |
| `tls_skip_verify` | bool | No | Skip TLS certificate verification (development only) |
| `ca_data` | string | No | Base64-encoded PEM CA certificate for custom/self-signed CAs |

### Credential Spec Config (Grafana Driver)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `role` | string | No | Service account role: `Viewer`, `Editor`, or `Admin` (default: `Viewer`) |
| `token_expiry` | duration | No | Token expiration duration (default: `1h`) |
| `name_prefix` | string | No | Service account name prefix (default: `warden-`) |
| `org_id` | string | No | Organization ID for multi-org setups |

### Credential Source Config (Static API Token)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `api_url` | string | No | API base URL for token verification |
| `verify_endpoint` | string | No | Verification path (e.g., `/org`) |
| `display_name` | string | No | Label for logs/errors (default: `API Key`) |

### Credential Spec Config (Static API Token)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `api_key` | string | Yes | Grafana service account token or Cloud access policy token (sensitive — masked in output) |

## Token Management

### Static Service Account Token

| Aspect | Details |
|--------|---------|
| **Storage** | Token is stored on the credential spec (not the source) |
| **Validation** | Token is verified at spec creation via `GET /org` on the Grafana API |
| **Rotation** | Manual — regenerate in Grafana and update the spec |
| **Lifetime** | Configurable — service account tokens can be set to expire or never expire |

### Dynamic Tokens (Grafana Source Driver)

| Aspect | Details |
|--------|---------|
| **Storage** | Admin token on the source; minted tokens are ephemeral |
| **Minting** | Creates a temporary service account + token via the Grafana HTTP API |
| **TTL** | Configurable via `token_expiry` (default: 1h) |
| **Cleanup** | Service account is deleted on revoke, which revokes all its tokens |

**To rotate a static token:**

1. Generate a new token in Grafana (Administration > Service Accounts > your service account > Add token)
2. Update the credential spec:
   ```bash
   warden cred spec update grafana-ops \
     --config api_key=glsa_your-new-token
   ```
3. Delete the old token in Grafana

### Grafana Cloud Access Policy Tokens

For Grafana Cloud, access policy tokens can authenticate to multiple services (Grafana, Loki, Mimir, Tempo, Pyroscope) with a single token. Configure the token's scopes to control access:

- `metrics:read`, `metrics:write` — Mimir/Prometheus
- `logs:read`, `logs:write` — Loki
- `traces:read`, `traces:write` — Tempo
- `profiles:read`, `profiles:write` — Pyroscope
- `alerts:read`, `alerts:write` — Alertmanager

Create the token at **Grafana Cloud > Security > Access Policies** and use it as a static `api_key` credential spec shared across all Grafana provider mounts.
