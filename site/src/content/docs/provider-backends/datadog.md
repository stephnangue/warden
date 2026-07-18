---
title: "Datadog"
---

The Datadog provider enables proxied access to the Datadog REST API through Warden. It forwards requests to Datadog endpoints (Metrics, Monitors, Dashboards, Logs, Events, etc.) with automatic credential injection and policy evaluation. Credentials are injected via the `DD-API-KEY` and `DD-APPLICATION-KEY` headers. One credential mode is supported: static API keys (`apikey` source type). Vault/OpenBao can also be used as a credential source (`hvault` source type).

## Prerequisites

- Docker and Docker Compose installed and running
- A **Datadog API Key** (from Datadog > Organization Settings > API Keys) and optionally a **Datadog Application Key** (from Datadog > Organization Settings > Application Keys)

:::note[New to Warden?]
Follow [Local dev setup](/provider-backends/local-dev-setup/) to start a local dev environment (Ory Hydra + a Warden dev server) before Step 1.
:::

## Step 1: Configure JWT Auth and Create a Role

Enable the JWT auth method and point it at your identity provider's JWKS endpoint, then create a role that binds the credential spec and policy. Enabling the mount and configuring the key source is covered once in [JWT auth](/auth-methods/jwt/#step-1-configure-the-key-source) — for the local dev setup.

> **This step must come before configuring the provider.** Warden validates at configuration time that the auth backend referenced by `auto_auth_path` is already mounted.

```bash
warden auth enable jwt
warden write auth/jwt/config jwks_url=http://localhost:4444/.well-known/jwks.json

# Create a role that binds the credential spec and policy
warden write auth/jwt/role/datadog-user \
    token_policies="datadog-access" \
    user_claim=sub \
    cred_spec_name=datadog-ops
```

## Step 2: Mount and Configure the Provider

Enable the Datadog provider at a path of your choice:

```bash
warden provider enable datadog
```

To mount at a custom path:

```bash
warden provider enable -path=datadog-prod datadog
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

See [Provider configuration](/provider-backends/configuration/) for the full list of common config fields (`proxy_domains`, `timeout`, `tls_skip_verify`, `ca_data`, and more).

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
  -type=apikey \
  -rotation-period=0 \
  -config=api_url=https://api.datadoghq.com \
  -config=verify_endpoint=/api/v1/validate \
  -config=auth_header_type=custom_header \
  -config=auth_header_name=DD-API-KEY \
  -config=display_name=Datadog
```

Create a credential spec that references the credential source. The spec carries the API key (and optionally an application key) and gets associated with tokens at login time.

```bash
warden cred spec create datadog-ops \
  -source datadog-src \
  -config api_key=your-datadog-api-key \
  -config application_key=your-datadog-application-key
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
  -type=hvault \
  -config=vault_address=https://vault.example.com \
  -config=auth_method=approle \
  -config=role_id=your-role-id \
  -config=secret_id=your-secret-id \
  -config=approle_mount=approle \
  -config=role_name=warden-role \
  -rotation-period=24h
```

Create a credential spec using the `static_apikey` mint method:

```bash
warden cred spec create datadog-ops \
  -source datadog-vault-src \
  -config mint_method=static_apikey \
  -config kv2_mount=secret \
  -config secret_path=datadog/ops
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

Get a JWT from your identity provider — see [Obtaining a JWT](/auth-methods/jwt/#obtaining-a-jwt) (the local dev setup issues one from Hydra). Export it as `$JWT_TOKEN`.

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

:::note[Prerequisite]
Certificate auth requires mTLS on the Warden listener so the client certificate can be presented during the handshake. See [Enabling mTLS on the listener](/auth-methods/cert/#enabling-mtls-on-the-listener).
:::

Steps 1-3 (provider setup) are identical. Replace Steps 4-5 with the following.

### Enable Cert Auth

```bash
warden auth enable cert
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

The `allowed_common_names` field supports glob patterns; you can also match on other certificate fields. See [Create a role](/auth-methods/cert/#step-3-create-a-role) for the full set of constraint fields.

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
     -config api_key=your-new-api-key \
     -config application_key=your-new-application-key
   ```
3. Revoke the old keys in Datadog
