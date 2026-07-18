---
title: "Prometheus"
---

The Prometheus provider enables proxied access to the Prometheus HTTP API through Warden. It forwards requests to Prometheus endpoints (`/api/v1/query`, `/api/v1/targets`, etc.) with automatic credential injection and policy evaluation. It supports both bearer token authentication (for managed services like Grafana Mimir, Amazon Managed Prometheus, and Thanos) and HTTP basic auth (for self-hosted Prometheus instances configured with `--web.config.file`). Credentials are static tokens stored in an `apikey` credential source.

## Prerequisites

- Docker and Docker Compose installed and running
- A running Prometheus instance (or a compatible service: Grafana Mimir, Amazon Managed Prometheus, Thanos, VictoriaMetrics)
- A bearer token **or** a username/password pair for your Prometheus instance

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
warden write auth/jwt/role/prometheus-user \
    token_policies="prometheus-access" \
    user_claim=sub \
    cred_spec_name=prometheus-ops
```

## Step 2: Mount and Configure the Provider

Enable the Prometheus provider at a path of your choice:

```bash
warden provider enable prometheus
```

To mount at a custom path (e.g., for a specific cluster or environment):

```bash
warden provider enable -path=prometheus-prod prometheus
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

See [Provider configuration](/provider-backends/configuration/) for the full list of common config fields (`proxy_domains`, `timeout`, `tls_skip_verify`, `ca_data`, and more).

Verify the configuration:

```bash
warden read prometheus/config
```

## Step 3: Create a Credential Source and Spec

### Option A: Bearer Token (Managed Prometheus)

Use this for Grafana Mimir, Amazon Managed Prometheus, Thanos, Cortex, or VictoriaMetrics instances that accept bearer tokens.

```bash
warden cred source create prometheus-src \
  -type=apikey \
  -rotation-period=0 \
  -config=api_url=https://prometheus.example.com \
  -config=display_name=Prometheus
```

Create a credential spec with your bearer token:

```bash
warden cred spec create prometheus-ops \
  -source prometheus-src \
  -config api_key=your-bearer-token
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
  -type=apikey \
  -rotation-period=0 \
  -config=api_url=https://prometheus.example.com \
  -config=optional_metadata=auth_type \
  -config=display_name=Prometheus
```

Create a credential spec with the base64-encoded credentials and `auth_type=basic`:

```bash
warden cred spec create prometheus-ops \
  -source prometheus-src \
  -config api_key=${ENCODED} \
  -config auth_type=basic
```

### Option C: Vault/OpenBao as Credential Source

Instead of storing the token directly in Warden, you can store it in a Vault/OpenBao KV v2 secret engine and have Warden fetch it at runtime.

**Prerequisites:** A Vault/OpenBao instance with:
- A KV v2 mount containing your Prometheus token (e.g., at `secret/prometheus/ops` with an `api_key` field)
- An AppRole configured for Warden access

```bash
# Create a Vault credential source
warden cred source create prometheus-vault-src \
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
warden cred spec create prometheus-ops \
  -source prometheus-vault-src \
  -config mint_method=static_apikey \
  -config kv2_mount=secret \
  -config secret_path=prometheus/ops
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

Get a JWT from your identity provider — see [Obtaining a JWT](/auth-methods/jwt/#obtaining-a-jwt) (the local dev setup issues one from Hydra). Export it as `$JWT_TOKEN`.

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

:::note[Prerequisite]
Certificate auth requires mTLS on the Warden listener so the client certificate can be presented during the handshake. See [Enabling mTLS on the listener](/auth-methods/cert/#enabling-mtls-on-the-listener).
:::

Steps 1–3 (provider setup) are identical. Replace Steps 4–5 with the following.

### Enable Cert Auth

```bash
warden auth enable cert
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

The `allowed_common_names` field supports glob patterns; you can also match on other certificate fields. See [Create a role](/auth-methods/cert/#step-3-create-a-role) for the full set of constraint fields.

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
     -config api_key=${ENCODED}
   ```
