# Prometheus Provider

The Prometheus provider enables proxied access to the Prometheus HTTP API through Warden. It forwards requests to Prometheus endpoints (`/api/v1/query`, `/api/v1/targets`, etc.) with automatic credential injection and policy evaluation. It supports both bearer token authentication (for managed services like Grafana Mimir, Amazon Managed Prometheus, and Thanos) and HTTP basic auth (for self-hosted Prometheus instances configured with `--web.config.file`). Credentials are static tokens stored in an `apikey` credential source.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Step 1: Configure JWT Auth and Create a Role](#step-1-configure-jwt-auth-and-create-a-role)
- [Step 2: Mount and Configure the Provider](#step-2-mount-and-configure-the-provider)
- [Step 3: Create a Credential Source and Spec](#step-3-create-a-credential-source-and-spec)
- [Step 4: Create a Policy](#step-4-create-a-policy)
- [Step 5: Get a JWT and Make Requests](#step-5-get-a-jwt-and-make-requests)
- [Cleanup](#cleanup)
- [TLS Certificate Authentication](#tls-certificate-authentication)
- [Configuration Reference](#configuration-reference)
- [Token Management](#token-management)

## Prerequisites

- Docker and Docker Compose installed and running
- A running Prometheus instance (or a compatible service: Grafana Mimir, Amazon Managed Prometheus, Thanos, VictoriaMetrics)
- A bearer token **or** a username/password pair for your Prometheus instance

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
warden write auth/jwt/role/prometheus-user \
    token_policies="prometheus-access" \
    user_claim=sub \
    cred_spec_name=prometheus-ops
```

## Step 2: Mount and Configure the Provider

Enable the Prometheus provider at a path of your choice:

```bash
warden provider enable --type=prometheus
```

To mount at a custom path (e.g., for a specific cluster or environment):

```bash
warden provider enable --type=prometheus prometheus-prod
```

Verify the provider is enabled:

```bash
warden provider list
```

Configure the provider. `prometheus_url` is required — there is no universal Prometheus endpoint:

```bash
warden write prometheus/config <<EOF
{
  "prometheus_url": "https://prometheus.example.com",
  "auto_auth_path": "auth/jwt/",
  "timeout": "30s",
  "max_body_size": 10485760
}
EOF
```

Verify the configuration:

```bash
warden read prometheus/config
```

## Step 3: Create a Credential Source and Spec

### Option A: Bearer Token (Managed Prometheus)

Use this for Grafana Mimir, Amazon Managed Prometheus, Thanos, Cortex, or VictoriaMetrics instances that accept bearer tokens.

```bash
warden cred source create prometheus-src \
  --type=apikey \
  --rotation-period=0 \
  --config=api_url=https://prometheus.example.com \
  --config=display_name=Prometheus
```

Create a credential spec with your bearer token:

```bash
warden cred spec create prometheus-ops \
  --source prometheus-src \
  --config api_key=your-bearer-token
```

### Option B: Basic Auth (Self-hosted Prometheus)

Use this for Prometheus instances configured with `--web.config.file` and bcrypt-hashed passwords.

The `api_key` field must be the base64-encoded `username:password` string:

```bash
# Encode your credentials
ENCODED=$(echo -n "admin:your-password" | base64)
```

Create a credential source with `optional_metadata=auth_type` to allow the auth mode to be set per-spec:

```bash
warden cred source create prometheus-src \
  --type=apikey \
  --rotation-period=0 \
  --config=api_url=https://prometheus.example.com \
  --config=optional_metadata=auth_type \
  --config=display_name=Prometheus
```

Create a credential spec with the base64-encoded credentials and `auth_type=basic`:

```bash
warden cred spec create prometheus-ops \
  --source prometheus-src \
  --config api_key=${ENCODED} \
  --config auth_type=basic
```

### Option C: Vault/OpenBao as Credential Source

Instead of storing the token directly in Warden, you can store it in a Vault/OpenBao KV v2 secret engine and have Warden fetch it at runtime.

**Prerequisites:** A Vault/OpenBao instance with:
- A KV v2 mount containing your Prometheus token (e.g., at `secret/prometheus/ops` with an `api_key` field)
- An AppRole configured for Warden access

```bash
# Create a Vault credential source
warden cred source create prometheus-vault-src \
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
warden cred spec create prometheus-ops \
  --source prometheus-vault-src \
  --config mint_method=static_apikey \
  --config kv2_mount=secret \
  --config secret_path=prometheus/ops
```

The KV v2 secret at `secret/prometheus/ops` must contain at minimum an `api_key` field. For basic auth, also include `auth_type=basic`.

Verify:

```bash
warden cred spec read prometheus-ops
```

## Step 4: Create a Policy

Create a policy that grants access to the Prometheus provider gateway:

```bash
warden policy write prometheus-access - <<EOF
path "prometheus/role/+/gateway*" {
  capabilities = ["create", "read", "update", "delete", "patch"]
}
EOF
```

For read-only access (querying only, no admin endpoints):

```bash
warden policy write prometheus-readonly - <<EOF
path "prometheus/role/+/gateway/api/v1/query*" {
  capabilities = ["create", "read"]
}

path "prometheus/role/+/gateway/api/v1/series*" {
  capabilities = ["read"]
}

path "prometheus/role/+/gateway/api/v1/label*" {
  capabilities = ["read"]
}

path "prometheus/role/+/gateway/api/v1/targets*" {
  capabilities = ["read"]
}

path "prometheus/role/+/gateway/-/healthy" {
  capabilities = ["read"]
}
EOF
```

Verify:

```bash
warden policy read prometheus-access
```

## Step 5: Get a JWT and Make Requests

Get a JWT from Hydra using one of the quickstart clients:

```bash
export JWT_TOKEN=$(curl -s -X POST http://localhost:4444/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=my-agent&client_secret=agent-secret&scope=api:read api:write" \
  | jq -r '.access_token')
```

Requests use role-based paths. Warden performs implicit JWT authentication and injects the Prometheus credential automatically.

The URL pattern is: `/v1/prometheus/role/{role}/gateway/{api-path}`

Export the base endpoint:

```bash
export PROM_ENDPOINT="${WARDEN_ADDR}/v1/prometheus/role/prometheus-user/gateway"
```

### Instant Query

```bash
curl -s "${PROM_ENDPOINT}/api/v1/query" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  --data-urlencode 'query=up' \
  --data-urlencode 'time=2024-01-01T00:00:00Z'
```

### Range Query

```bash
curl -s "${PROM_ENDPOINT}/api/v1/query_range" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  --data-urlencode 'query=rate(http_requests_total[5m])' \
  --data-urlencode 'start=2024-01-01T00:00:00Z' \
  --data-urlencode 'end=2024-01-01T01:00:00Z' \
  --data-urlencode 'step=60'
```

### List Label Names

```bash
curl -s "${PROM_ENDPOINT}/api/v1/labels" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### List Label Values

```bash
curl -s "${PROM_ENDPOINT}/api/v1/label/job/values" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### Find Series

```bash
curl -s "${PROM_ENDPOINT}/api/v1/series" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  --data-urlencode 'match[]=up'
```

### Active Targets

```bash
curl -s "${PROM_ENDPOINT}/api/v1/targets" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### Alerting Rules

```bash
curl -s "${PROM_ENDPOINT}/api/v1/rules" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### Active Alerts

```bash
curl -s "${PROM_ENDPOINT}/api/v1/alerts" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### Health Check

```bash
curl -s "${PROM_ENDPOINT}/-/healthy" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### Readiness Check

```bash
curl -s "${PROM_ENDPOINT}/-/ready" \
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

## TLS Certificate Authentication

Steps 1–4 above use JWT authentication. Alternatively, you can authenticate with a TLS client certificate. This is useful for workloads that already have X.509 certificates — Kubernetes pods with cert-manager, VMs with machine certificates, or SPIFFE X.509-SVIDs from a service mesh.

> **Prerequisite:** Certificate authentication requires TLS to be enabled on the Warden listener so that client certificates can be presented during the TLS handshake (mTLS). In dev mode, use `--dev-tls` to enable TLS with auto-generated certificates, or provide your own with `--dev-tls-cert-file`, `--dev-tls-key-file`, and `--dev-tls-ca-cert-file`. Alternatively, place Warden behind a load balancer that terminates TLS and forwards the client certificate via the `X-Forwarded-Client-Cert` or `X-SSL-Client-Cert` header.

Steps 1–3 (provider setup) are identical. Replace Steps 4–5 with the following.

### Enable Cert Auth

```bash
warden auth enable --type=cert
```

### Configure Trusted CA

Provide the PEM-encoded CA certificate that signs your client certificates:

```bash
warden write auth/cert/config \
    trusted_ca_pem=@/path/to/ca.pem \
    default_role=prometheus-user
```

### Create a Cert Role

```bash
warden write auth/cert/role/prometheus-user \
    allowed_common_names="agent-*" \
    token_policies="prometheus-access" \
    cred_spec_name=prometheus-ops
```

The `allowed_common_names` field supports glob patterns. You can also match on `allowed_dns_sans`, `allowed_email_sans`, `allowed_uri_sans`, or `allowed_organizational_units`.

### Configure Provider for Cert Auth

```bash
warden write prometheus/config <<EOF
{
  "prometheus_url": "https://prometheus.example.com",
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
    -s "https://warden.internal/v1/prometheus/role/prometheus-user/gateway/api/v1/query" \
    --data-urlencode 'query=up'
```

## Configuration Reference

### Provider Config

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `prometheus_url` | string | — | **Required.** Prometheus API base URL (must be HTTPS) |
| `max_body_size` | int | 10485760 (10 MB) | Maximum request body size in bytes (max 100 MB) |
| `timeout` | duration | `30s` | Request timeout |
| `auto_auth_path` | string | — | **Required.** Auth mount path for implicit authentication (e.g., `auth/jwt/`, `auth/cert/`) |
| `default_role` | string | — | Fallback role when not specified in URL |

### Credential Source Config

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `api_url` | string | No | Prometheus API base URL (informational only) |
| `display_name` | string | No | Label for logs/errors (default: `API Key`) |
| `optional_metadata` | string | No | Comma-separated spec fields forwarded into credential data (e.g., `auth_type`) |

### Credential Spec Config

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `api_key` | string | Yes | Bearer token, **or** base64-encoded `username:password` for basic auth (sensitive — masked in output) |
| `auth_type` | string | No | `bearer` (default) or `basic`. Requires `optional_metadata=auth_type` on the credential source. |

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
| `secret_path` | string | Yes | Path to the secret within the mount |

## Token Management

### Bearer Token

| Aspect | Details |
|--------|---------|
| **Storage** | Token is stored on the credential spec |
| **Rotation** | Manual — generate a new token and update the spec |
| **Lifetime** | Depends on the service — managed services typically issue long-lived tokens |

### Basic Auth Credentials

| Aspect | Details |
|--------|---------|
| **Storage** | Base64-encoded `username:password` stored on the credential spec |
| **Rotation** | Manual — update the Prometheus `web.yml` and update the spec with re-encoded credentials |
| **Lifetime** | Static — does not expire unless the password is changed |

**To rotate credentials:**

1. Update your Prometheus `web.yml` (or generate a new token in the managed service)
2. Re-encode the new credentials if using basic auth:
   ```bash
   ENCODED=$(echo -n "admin:new-password" | base64)
   ```
3. Update the credential spec:
   ```bash
   warden cred spec update prometheus-ops \
     --config api_key=${ENCODED}
   ```
