---
title: "Prometheus"
---

The Prometheus provider enables proxied access to the Prometheus HTTP API through Warden. It forwards requests to Prometheus endpoints (`/api/v1/query`, `/api/v1/targets`, etc.) with automatic credential injection and policy evaluation. It supports both bearer token authentication (for managed services like Grafana Mimir, Amazon Managed Prometheus, and Thanos) and HTTP basic auth (for self-hosted Prometheus instances configured with `--web.config.file`). Credentials are static tokens stored in an `apikey` credential source.

## How a request flows

This mount injects an **`api_key`** credential as `Authorization: Bearer <token>`, or as
Basic auth when the mount sets `auth_type=basic`. The question is where that
auth token lives.

The recommended setup keeps it in the vault that manages it, read per request.

<p align="center"><img alt="An agent presents the user's ID token and its own identity to Warden, which builds an assertion carrying user and agent claims, has an external KMS sign it, reads the Prometheus auth token from an external vault at a path templated by the agent's team and environment, and injects it to the Prometheus API" src="/images/warden-prov-prometheus-vault-apikey.png" width="860"></p>

1. The user authenticates and the agent holds their ID token.
2. The agent calls Warden presenting both credentials and asserting a role.
3. Warden builds the assertion the referenced spec calls for and sends it to a KMS-backed
   issuer unsigned, where one is configured.
4. The issuer returns it signed.
5. Warden authenticates to the **external vault** and reads
   `secret/prometheus/{{agent.team}}/{{agent.env}}`.
6. The vault returns the auth token for that team and environment.
7. Warden injects it and forwards.

The credential is served **verbatim** — nothing is minted. What chaining buys is custody:
it stays in the store that manages it, and the read path decides who reaches which one.

:::note[Steps 3–6 run only on a cache miss]
Warden caches the credential, so most requests skip from step 2 to step 7. The entry is
keyed by namespace, the agent's token id and the spec name — plus the user's token id when
the mount carries a user.
:::

### The simpler variant

<p align="center"><img alt="Warden reads a static Prometheus auth token from its encrypted storage and injects it to the Prometheus API for every caller" src="/images/warden-prov-prometheus-inline-apikey.png" width="860"></p>

**Inline.** The credential sits in Warden's storage. Shortest to set up, weakest custody:
one long-lived credential for every caller.

## Credential modes

| Mode | What Prometheus sees | Where the credential lives |
|---|---|---|
| **Chained** ✅ *recommended* | One long-lived credential, scoped by path | The vault; nothing in Warden |
| **Inline** ⚠️ | One long-lived credential, shared | Warden's storage |

Prometheus exposes no workload-identity federation and mints nothing per request, so the
credential is long-lived in both rows; what changes is whether Warden holds it.

See the [apikey credential driver](/credential-drivers/apikey/) for every source and spec
key.

## Prerequisites

- Docker and Docker Compose installed and running
- A running Prometheus instance (or a compatible service: Grafana Mimir, Amazon Managed Prometheus, Thanos, VictoriaMetrics)
- A bearer token **or** a username/password pair for your Prometheus instance

:::note[New to Warden?]
Follow [Local dev setup](/provider-backends/local-dev-setup/) to start a local dev environment (Ory Hydra + a Warden dev server) before Step 1.
:::

## Step 1: Configure JWT Auth and Create a Role

Enable the JWT auth method and point it at your identity provider's JWKS endpoint, then create a role that binds the credential spec and policy. Enabling the mount and configuring the key source is covered once in [JWT auth](/auth-methods/jwt/#step-1-configure-the-key-source) — for the local dev setup.

> **Set this up before configuring the provider.** The provider resolves
> `auto_auth_path` per request — writing the config only checks that it is
> non-empty, not that the mount exists — so a gateway call fails with `no auth
> mount registered ... for implicit auth` if the referenced auth mount isn't
> there yet.

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

### Option A: Chained (recommended)

The flow in the first diagram. The vault holds the credential; Warden reads it per request
and injects it.

```bash
# The store Warden reads from, reached keylessly — no vault token in Warden
warden cred source create vault-keyless -json '{
  "type": "hvault",
  "config": {
    "vault_address": "https://vault.example.com",
    "auth_method": "oidc_federation",
    "jwt_role": "warden-agents",
    "jwt_mount": "jwt",
    "audience": "https://vault.example.com"
  }
}'

warden cred spec create prometheus-ops -json '{
  "source": "vault-keyless",
  "min_ttl": 600,
  "max_ttl": 3600,
  "config": {
    "mint_method": "static_apikey",
    "subject_token_source": "warden_identity",
    "assertion_metadata_claims": "team,env",
    "kv2_mount": "secret",
    "secret_path": "prometheus/{{agent.team}}/{{agent.env}}"
  }
}'
```

The KV secret must carry the credential under **`api_key`**.

Both principals are available to the path template: `{{agent.sub}}` is free,
`{{agent.<claim>}}` needs `assertion_metadata_claims`, and `{{user.<claim>}}` needs
`assertion_user_claims` plus a user on the request. Swap `{{agent.team}}` for
`{{user.sub}}` to give each person their own credential. Templates resolve at **mint,
not at write**, so a path naming an unprojected claim is accepted by `spec create` and
fails on the first request.

### Enabling Basic auth

The mount decides the scheme. With `auth_type=basic` the credential's `api_key` must be the
**base64 of `username:password`** rather than a bearer token:

```bash
warden write prometheus/config <<EOF
{
  "auth_type": "basic"
}
EOF
```

`auth_type` accepts `bearer` (the default) or `basic`. It is **mount config, not spec
config** — it moved to the mount in v0.20.0.

### Option B: Inline

⚠️ 
```bash
warden cred source create prometheus-src -json '{
  "type": "apikey",
  "config": {
    "api_url": "https://prometheus.example.com",
    "display_name": "Prometheus"
  }
}'

printf '{"source":"prometheus-src","min_ttl":3600,"max_ttl":86400,"config":{"api_key":"%s"}}' \
  "$(cat /path/to/prometheus-token)" | warden cred spec create prometheus-ops -json -
```

One long-lived credential for every caller. Prefer Option A.

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
