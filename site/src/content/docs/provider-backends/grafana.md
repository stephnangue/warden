---
title: "Grafana"
description: "Proxy Grafana, Loki, Mimir, Tempo and Pyroscope through Warden: mint a short-lived service-account token per request from an admin token held in a vault."
---

The Grafana provider enables proxied access to the entire Grafana ecosystem through Warden: the dashboard/admin HTTP API, Loki (logs), Mimir (metrics), Tempo (traces), and Pyroscope (profiling). It forwards requests with automatic credential injection and policy evaluation.

A single provider type supports all Grafana services. Mount multiple instances with different `grafana_url` values and use the optional `tenant_id` config to inject the `X-Scope-OrgID` header required by Loki, Mimir, Tempo, and Pyroscope.

## How a request flows

Two things vary independently: whether the token Grafana sees is **minted per request** or a
fixed one, and whether the credential behind it lives **in Warden** or in a vault.

The best combination does both — a vaulted admin token, used to mint a short-lived service
account token for each request.

<p align="center"><img alt="An agent presents the user's ID token and its own identity to Warden, which builds an assertion carrying user and agent claims, has an external KMS sign it, reads the Grafana admin token from an external vault at a path templated by the agent's team and environment, mints a token on a provisioned service account through the Grafana service-accounts API, and injects it to the Grafana API" src="/images/warden-prov-grafana-cred-chain.png" width="860"></p>

1. The user authenticates and the agent holds their ID token.
2. The agent calls Warden presenting both credentials and asserting a role.
3. Warden builds the assertion the referenced spec calls for and sends it to an **external
   KMS** unsigned.
4. The KMS returns it signed. No signing key lives in Warden.
5. Warden authenticates to the **external vault** and reads
   `secret/grafana/{{agent.team}}/{{agent.env}}`.
6. The vault returns the admin token for that team and environment.
7. Warden calls `POST /api/serviceaccounts/{id}/tokens` with it, on the service account
   the spec names…
8. …and receives a short-lived token for that account.
9. Warden injects that token and forwards.

The admin token is the privileged one — it can mint tokens on any service account — so
keeping it in the vault and never in Warden is the point. What Grafana sees on the request
is a short-lived token on one account instead. Warden does **not** create service accounts;
you provision them in Grafana and name one per spec.

:::note[Steps 3–8 run only on a cache miss]
Warden caches the minted credential, so most requests skip from step 2 to step 9. The entry
is keyed by namespace, the agent's token id and the spec name — plus the user's token id
when the mount carries a user.
:::

### Simpler variants

<p align="center"><img alt="Warden authenticates to an external vault with a KMS-signed assertion carrying user and agent claims, reads a static Grafana API key from a templated path, and injects it to the Grafana API" src="/images/warden-prov-grafana-vault-apikey.png" width="860"></p>

**Vaulted static token.** The vault holds a service-account token directly, served verbatim
— no minting, no token endpoint. The token stays out of Warden and the path scopes who
reaches which token, but it is long-lived and shared by everyone the path resolves for.

<p align="center"><img alt="Warden reads a static Grafana API key from its encrypted storage and injects it to the Grafana API for every caller" src="/images/warden-prov-grafana-inline-apikey.png" width="860"></p>

**Inline static token.** The token sits in Warden's storage. Shortest to set up, weakest
custody: one long-lived token for every caller.

## Credential modes

| Mode | What Grafana sees | Where the credential lives |
|---|---|---|
| **Chained admin token → minted token** ✅ *recommended* | A short-lived token on a provisioned service account | The vault; nothing in Warden |
| **Stored admin token → minted token** | The same short-lived token | The admin token is in Warden |
| **Chained static token** | One long-lived token, per path | The vault |
| **Inline static token** ⚠️ | One long-lived token, shared | Warden's storage |

Grafana exposes no workload-identity federation, so a privileged credential exists
somewhere in every row; what changes is whether it is Warden holding it, and whether the
upstream sees it directly.

See the [Grafana credential driver](/credential-drivers/grafana/) for every source and spec
key.


## Prerequisites

- Docker and Docker Compose installed and running
- A **Grafana service account token** (from Grafana > Administration > Service Accounts) or a **Grafana Cloud access policy token** (from Grafana Cloud > Access Policies)

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
warden write auth/jwt/role/grafana-user \
    token_policies="grafana-access" \
    user_claim=sub \
    cred_spec_name=grafana-ops
```

## Step 2: Mount and Configure the Provider

Enable the Grafana provider at a path of your choice:

```bash
warden provider enable grafana
```

To mount at a custom path (useful for multi-service setups):

```bash
warden provider enable -path=grafana-loki grafana
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

See [Provider configuration](/provider-backends/configuration/) for the full list of common config fields (`proxy_domains`, `timeout`, `tls_skip_verify`, `ca_data`, and more).

Verify the configuration:

```bash
warden read grafana/config
```

## Step 3: Create a Credential Source and Spec

### Option A: Chained admin token (recommended)

The flow in the first diagram. The `grafana` source names a `secret_spec` and holds no
token of its own; Warden reads the admin token per mint and uses it to create a short-lived
service account.

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

# Producer: the admin token, read from KV v2 through that source
warden cred spec create grafana-admin-token -json '{
  "source": "vault-keyless",
  "min_ttl": 600,
  "max_ttl": 3600,
  "config": {
    "mint_method": "kv2_read",
    "subject_token_source": "warden_identity",
    "assertion_metadata_claims": "team,env",
    "kv2_mount": "secret",
    "secret_path": "grafana/{{agent.team}}/{{agent.env}}"
  }
}'

# Consumer: a grafana source holding no token of its own
warden cred source create grafana-src -json '{
  "type": "grafana",
  "config": {
    "grafana_url": "https://mystack.grafana.net",
    "secret_spec": "grafana-admin-token"
  }
}'

warden cred spec create grafana-ops -json '{
  "source": "grafana-src",
  "min_ttl": 600,
  "max_ttl": 3600,
  "config": {
    "service_account_id": "42",
    "token_expiry": "1h",
    "name_prefix": "warden-"
  }
}'
```

`service_account_id` names a service account **you provision in Grafana** — Warden mints
tokens on it, it does not create one. Set it on the spec, or on the source as a default;
a spec with neither is rejected. There is no `role` key: a minted token carries the role of
the account it is issued on, so choose the account whose role you want rather than asking
for one.

`admin_token` must be **omitted** when `secret_spec` is set — leaving it is rejected with
*"admin_token must be omitted when secret_spec is set; the referenced spec supplies the
privileged token"*.

Both principals are available to the path template: `{{agent.sub}}` is free,
`{{agent.<claim>}}` needs `assertion_metadata_claims`, and `{{user.<claim>}}` needs
`assertion_user_claims` plus a user on the request. Templates resolve at **mint, not at
write**, so a path naming an unprojected claim is accepted by `spec create` and fails on the
first request.

### Option B: Admin token stored in Warden

Same minting, but the admin token lives in Warden's storage.

```bash
warden cred source create grafana-src -json '{
  "type": "grafana",
  "config": {
    "grafana_url": "https://mystack.grafana.net",
    "admin_token": "<glsa_your-admin-token>"
  }
}'

warden cred spec create grafana-ops -json '{
  "source": "grafana-src",
  "min_ttl": 600,
  "max_ttl": 3600,
  "config": {
    "service_account_id": "42",
    "token_expiry": "1h",
    "name_prefix": "warden-"
  }
}'
```

### Option C: Chained static token

No minting — the vault holds a service-account token and Warden serves it verbatim. Use
this where the admin token cannot be shared with Warden at all, or where Grafana's
service-account API is unavailable.

Reusing the `vault-keyless` source from Option A:

```bash
warden cred spec create grafana-ops -json '{
  "source": "vault-keyless",
  "min_ttl": 600,
  "max_ttl": 3600,
  "config": {
    "mint_method": "static_apikey",
    "subject_token_source": "warden_identity",
    "assertion_metadata_claims": "team,env",
    "kv2_mount": "secret",
    "secret_path": "grafana/{{agent.team}}/{{agent.env}}"
  }
}'
```

### Option D: Inline static token ⚠️

Create a service account in Grafana (**Administration > Users and Access > Service
Accounts**), assign a role, and create a token — it is shown only once.

```bash
warden cred source create grafana-src -json '{
  "type": "apikey",
  "config": {
    "api_url": "https://mystack.grafana.net/api",
    "verify_endpoint": "/org",
    "display_name": "Grafana"
  }
}'

printf '{"source":"grafana-src","min_ttl":3600,"max_ttl":86400,"config":{"api_key":"%s"}}' \
  "$(cat /path/to/grafana-token)" | warden cred spec create grafana-ops -json -
```

One long-lived token for every caller. Prefer any option above.

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

Get a JWT from your identity provider — see [Obtaining a JWT](/auth-methods/jwt/#obtaining-a-jwt) (the local dev setup issues one from Hydra). Export it as `$JWT_TOKEN`.

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
warden provider enable -path=grafana-loki grafana

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
warden provider enable -path=grafana-mimir grafana

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
warden provider enable -path=grafana-tempo grafana

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
| **Storage** | Admin token on the source, or chained from a vault; minted tokens are ephemeral |
| **Minting** | One token on the service account the spec names, via `POST /api/serviceaccounts/{id}/tokens`. Warden does **not** create service accounts — you provision them in Grafana |
| **TTL** | Configurable via `token_expiry` (default: 1h) |
| **Cleanup** | Revoke deletes that one token, leaving the service account and its other tokens intact. Expired leftovers are swept on later mints |

**To rotate a static token:**

1. Generate a new token in Grafana (Administration > Service Accounts > your service account > Add token)
2. Update the credential spec:
   ```bash
   warden cred spec update grafana-ops \
     -config api_key=glsa_your-new-token
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
