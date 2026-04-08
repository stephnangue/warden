# Datadog Provider

The Datadog provider enables proxied access to the Datadog REST API through Warden. It forwards requests to Datadog endpoints (Metrics, Monitors, Dashboards, Logs, Events, etc.) with automatic credential injection and policy evaluation. Credentials are injected via the `DD-API-KEY` and `DD-APPLICATION-KEY` headers. One credential mode is supported: static API keys (`apikey` source type). Vault/OpenBao can also be used as a credential source (`hvault` source type).

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
- A **Datadog API Key** (from Datadog > Organization Settings > API Keys) and optionally a **Datadog Application Key** (from Datadog > Organization Settings > Application Keys)

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
warden write auth/jwt/role/datadog-user \
    token_policies="datadog-access" \
    user_claim=sub \
    cred_spec_name=datadog-ops
```

## Step 2: Mount and Configure the Provider

Enable the Datadog provider at a path of your choice:

```bash
warden provider enable --type=datadog
```

To mount at a custom path:

```bash
warden provider enable --type=datadog datadog-prod
```

Verify the provider is enabled:

```bash
warden provider list
```

Configure the provider with `auto_auth_path`. This allows clients to authenticate with their JWT directly — no explicit Warden login required:

```bash
warden write datadog/config <<EOF
{
  "datadog_url": "https://api.datadoghq.com",
  "auto_auth_path": "auth/jwt/",
  "timeout": "30s",
  "max_body_size": 10485760
}
EOF
```

Set `datadog_url` to match your Datadog site:

| Site | URL |
|------|-----|
| US1 (default) | `https://api.datadoghq.com` |
| US3 | `https://api.us3.datadoghq.com` |
| US5 | `https://api.us5.datadoghq.com` |
| EU1 | `https://api.datadoghq.eu` |
| AP1 | `https://api.ap1.datadoghq.com` |
| AP2 | `https://api.ap2.datadoghq.com` |
| US1-FED | `https://api.ddog-gov.com` |

Verify the configuration:

```bash
warden read datadog/config
```

## Step 3: Create a Credential Source and Spec

### Option A: Static API Keys

The credential source holds only connection info (`api_url`). The API key and application key are stored on the credential spec below, allowing multiple specs with different keys to share one source.

```bash
warden cred source create datadog-src \
  --type=apikey \
  --rotation-period=0 \
  --config=api_url=https://api.datadoghq.com \
  --config=verify_endpoint=/api/v1/validate \
  --config=auth_header_type=custom_header \
  --config=auth_header_name=DD-API-KEY \
  --config=display_name=Datadog
```

Create a credential spec that references the credential source. The spec carries the API key (and optionally an application key) and gets associated with tokens at login time.

```bash
warden cred spec create datadog-ops \
  --source datadog-src \
  --config api_key=your-datadog-api-key \
  --config application_key=your-datadog-application-key
```

The API key is validated at creation time via a `GET /api/v1/validate` call to the Datadog API (SpecVerifier). If the key is invalid, spec creation will fail.

> **Note:** The `application_key` is optional. If you only need to submit metrics and events (which require only an API key), you can omit it. Most management and read endpoints require both keys.

### Option B: Vault/OpenBao as Credential Source

Instead of storing API keys directly in Warden, you can store them in a Vault/OpenBao KV v2 secret engine and have Warden fetch them at runtime. This centralizes secret management in Vault.

**Prerequisites:** A Vault/OpenBao instance with:
- A KV v2 mount containing your Datadog keys (e.g., at `secret/datadog/ops` with `api_key` and optionally `application_key` fields)
- An AppRole configured for Warden access

```bash
# Create a Vault credential source
warden cred source create datadog-vault-src \
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
warden cred spec create datadog-ops \
  --source datadog-vault-src \
  --config mint_method=static_apikey \
  --config kv2_mount=secret \
  --config secret_path=datadog/ops
```

The KV v2 secret at `secret/datadog/ops` should contain an `api_key` field and optionally an `application_key` field. Warden fetches the secret from Vault on each credential request.

Verify:

```bash
warden cred spec read datadog-ops
```

## Step 4: Create a Policy

Create a policy that grants access to the Datadog provider gateway:

```bash
warden policy write datadog-access - <<EOF
path "datadog/role/+/gateway*" {
  capabilities = ["create", "read", "update", "delete", "patch"]
}
EOF
```

For fine-grained access control, restrict which Datadog resources and actions a role can use:

```bash
warden policy write datadog-readonly - <<EOF
path "datadog/role/+/gateway/api/v1/query" {
  capabilities = ["read"]
}

path "datadog/role/+/gateway/api/v1/monitor" {
  capabilities = ["read"]
}

path "datadog/role/+/gateway/api/v1/dashboard" {
  capabilities = ["read"]
}

path "datadog/role/+/gateway/api/v2/metrics*" {
  capabilities = ["read"]
}

path "datadog/role/+/gateway/api/v2/logs/events/search" {
  capabilities = ["read"]
}
EOF
```

Verify:

```bash
warden policy read datadog-access
```

## Step 5: Get a JWT and Make Requests

Get a JWT from Hydra using one of the quickstart clients:

```bash
export JWT_TOKEN=$(curl -s -X POST http://localhost:4444/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=my-agent&client_secret=agent-secret&scope=api:read api:write" \
  | jq -r '.access_token')
```

Requests use role-based paths. Warden performs implicit JWT authentication and injects the Datadog API key (and application key) automatically.

The URL pattern is: `/v1/datadog/role/{role}/gateway/{api-path}`

Export DD_ENDPOINT as environment variable:
```bash
export DD_ENDPOINT="${WARDEN_ADDR}/v1/datadog/role/datadog-user/gateway"
```

### Validate API Key

```bash
curl -s "${DD_ENDPOINT}/api/v1/validate" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### Query Metrics

```bash
curl -s "${DD_ENDPOINT}/api/v1/query?from=$(date -v-1H +%s)&to=$(date +%s)&query=avg:system.cpu.user{*}" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### Submit Metrics

```bash
curl -s -X POST "${DD_ENDPOINT}/api/v2/series" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "series": [{
      "metric": "custom.test.metric",
      "type": 3,
      "points": [{
        "timestamp": '"$(date +%s)"',
        "value": 42.0
      }],
      "tags": ["env:test"]
    }]
  }'
```

### List Monitors

```bash
curl -s "${DD_ENDPOINT}/api/v1/monitor" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### List Dashboards

```bash
curl -s "${DD_ENDPOINT}/api/v1/dashboard" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### Search Logs

```bash
curl -s -X POST "${DD_ENDPOINT}/api/v2/logs/events/search" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "filter": {
      "query": "service:web-app",
      "from": "now-1h",
      "to": "now"
    },
    "page": {
      "limit": 25
    }
  }'
```

### List Events

```bash
curl -s "${DD_ENDPOINT}/api/v2/events?filter[from]=$(date -v-1d +%Y-%m-%dT%H:%M:%SZ)&filter[to]=$(date +%Y-%m-%dT%H:%M:%SZ)&page[limit]=10" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### Create a Monitor

```bash
curl -s -X POST "${DD_ENDPOINT}/api/v1/monitor" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "High CPU on web servers",
    "type": "metric alert",
    "query": "avg(last_5m):avg:system.cpu.user{role:web} > 90",
    "message": "CPU usage is above 90% on {{host.name}}. @ops-team",
    "tags": ["env:production", "team:platform"],
    "options": {
      "thresholds": {
        "critical": 90,
        "warning": 75
      }
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
    default_role=datadog-user
```

### Create a Cert Role

Create a role that binds allowed certificate identities to a credential spec and policy:

```bash
warden write auth/cert/role/datadog-user \
    allowed_common_names="agent-*" \
    token_policies="datadog-access" \
    cred_spec_name=datadog-ops
```

The `allowed_common_names` field supports glob patterns. You can also match on other certificate fields: `allowed_dns_sans`, `allowed_email_sans`, `allowed_uri_sans`, or `allowed_organizational_units`.

### Configure Provider for Cert Auth

Update the provider config to use cert auth:

```bash
warden write datadog/config <<EOF
{
  "datadog_url": "https://api.datadoghq.com",
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
    -s "https://warden.internal/v1/datadog/role/datadog-user/gateway/api/v1/monitor" \
    -H "Content-Type: application/json"
```

## Configuration Reference

### Provider Config

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `datadog_url` | string | `https://api.datadoghq.com` | Datadog API base URL (must match your Datadog site) |
| `max_body_size` | int | 10485760 (10 MB) | Maximum request body size in bytes (max 100 MB) |
| `timeout` | duration | `30s` | Request timeout |
| `tls_skip_verify` | bool | `false` | Skip TLS certificate verification; also allows `http://` URLs (development only) |
| `ca_data` | string | — | Base64-encoded PEM CA certificate for custom/self-signed CAs |
| `auto_auth_path` | string | — | **Required.** Auth mount path for implicit authentication (e.g., `auth/jwt/`, `auth/cert/`) |
| `default_role` | string | — | Fallback role when not specified in URL |

### Credential Source Config (Static API Keys)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `api_url` | string | No | API base URL (default: `https://api.datadoghq.com`) |
| `verify_endpoint` | string | No | Verification path (e.g., `/api/v1/validate`) |
| `auth_header_type` | string | No | How to attach key for verification: `custom_header` (recommended for Datadog) |
| `auth_header_name` | string | No | Header name for verification (e.g., `DD-API-KEY`) |
| `display_name` | string | No | Label for logs/errors (default: `API Key`) |

### Credential Spec Config (Static API Keys)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `api_key` | string | Yes | Datadog API key (sensitive — masked in output) |
| `application_key` | string | No | Datadog Application key (sensitive — masked in output; required for most management/read endpoints) |

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
| `secret_path` | string | Yes | Path to the secret within the mount (must contain `api_key`, optionally `application_key`) |

## Token Management

### Static API Keys

| Aspect | Details |
|--------|---------|
| **Storage** | API key and application key are stored on the credential spec (not the source) |
| **Validation** | API key is verified at spec creation via `GET /api/v1/validate` |
| **Rotation** | Manual — regenerate in Datadog and update the spec |
| **Lifetime** | Static — no expiration or auto-refresh |

**To rotate Datadog API keys:**

1. Generate a new API key in Datadog (Organization Settings > API Keys)
2. Update the credential spec:
   ```bash
   warden cred spec update datadog-ops \
     --config api_key=your-new-api-key \
     --config application_key=your-new-application-key
   ```
3. Revoke the old keys in Datadog
