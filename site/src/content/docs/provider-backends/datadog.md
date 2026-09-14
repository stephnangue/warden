---
title: "Datadog"
---

The Datadog provider enables proxied access to the Datadog REST API through Warden. It forwards requests to Datadog endpoints (Metrics, Monitors, Dashboards, Logs, Events, etc.) with automatic credential injection and policy evaluation. Credentials are injected via the `DD-API-KEY` and `DD-APPLICATION-KEY` headers. One credential mode is supported: static API keys (`apikey` source type). Vault/OpenBao can also be used as a credential source (`hvault` source type).

## How a request flows

This mount injects an **`api_key`** credential into the `DD-API-KEY` header, plus
`DD-APPLICATION-KEY` when that credential carries an application key. The question is where that
API key lives.

The recommended setup keeps it in the vault that manages it, read per request.

<p align="center"><img alt="An agent presents the user's ID token and its own identity to Warden, which builds an assertion carrying user and agent claims, has an external KMS sign it, reads the Datadog API key from an external vault at a path templated by the agent's team and environment, and injects it to the Datadog API" src="/images/warden-prov-datadog-vault-apikey.png" width="860"></p>

1. The user authenticates and the agent holds their ID token.
2. The agent calls Warden presenting both credentials and asserting a role.
3. Warden builds the assertion the referenced spec calls for and sends it to a KMS-backed
   issuer unsigned, where one is configured.
4. The issuer returns it signed.
5. Warden authenticates to the **external vault** and reads
   `secret/datadog/{{agent.team}}/{{agent.env}}`.
6. The vault returns the API key for that team and environment.
7. Warden injects it and forwards.

The credential is served **verbatim** — nothing is minted. What chaining buys is custody:
it stays in the store that manages it, and the read path decides who reaches which one.

:::note[Steps 3–6 run only on a cache miss]
Warden caches the credential, so most requests skip from step 2 to step 7. The entry is
keyed by namespace, the agent's token id and the spec name — plus the user's token id when
the mount carries a user.
:::

### The simpler variant

<p align="center"><img alt="Warden reads a static Datadog API key from its encrypted storage and injects it to the Datadog API for every caller" src="/images/warden-prov-datadog-inline-apikey.png" width="860"></p>

**Inline.** The credential sits in Warden's storage. Shortest to set up, weakest custody:
one long-lived credential for every caller.

## Credential modes

| Mode | What Datadog sees | Where the credential lives |
|---|---|---|
| **Chained** ✅ *recommended* | One long-lived credential, scoped by path | The vault; nothing in Warden |
| **Inline** ⚠️ | One long-lived credential, shared | Warden's storage |

Datadog exposes no workload-identity federation and mints nothing per request, so the
credential is long-lived in both rows; what changes is whether Warden holds it.

:::note[Most Datadog endpoints need an application key too]
`DD-API-KEY` alone covers submission endpoints; the read APIs also want
`DD-APPLICATION-KEY`. Warden injects it **only when the credential carries an
`application_key` field**, so declare it on the source with
`credential_fields=application_key`. Warden also strips any inbound
`DD-APPLICATION-KEY` when the credential has none, so a caller's own value cannot be
paired with the mount's API key.
:::

See the [apikey credential driver](/credential-drivers/apikey/) for every source and spec
key.

## Prerequisites

- Docker and Docker Compose installed and running
- A **Datadog API Key** (from Datadog > Organization Settings > API Keys) and optionally a **Datadog Application Key** (from Datadog > Organization Settings > Application Keys)

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

### Option A: Chained (recommended)

The flow in the first diagram. The vault holds the credential; Warden reads it per request
and injects it.

This provider needs a second field — **`application_key`** — beside the key, and that changes the
shape. An adjunct field survives **only** through an `apikey` source that declares it, so
the vault read goes through a *producer* spec and the `apikey` source chains it:

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

# Producer: the whole secret, read from KV v2 — api_key and application_key together
warden cred spec create datadog-secret -json '{
  "source": "vault-keyless",
  "min_ttl": 600,
  "max_ttl": 3600,
  "config": {
    "mint_method": "kv2_read",
    "subject_token_source": "warden_identity",
    "assertion_metadata_claims": "team,env",
    "kv2_mount": "secret",
    "secret_path": "datadog/{{agent.team}}/{{agent.env}}"
  }
}'

# Consumer: an apikey source that declares the adjunct field, chaining the secret
warden cred source create datadog-src -json '{
  "type": "apikey",
  "config": {
    "api_url": "https://api.datadoghq.com",
    "credential_fields": "application_key",
    "display_name": "Datadog"
  }
}'

warden cred spec create datadog-ops -json '{
  "source": "datadog-src",
  "min_ttl": 600,
  "max_ttl": 3600,
  "config": {
    "secret_spec": "datadog-secret"
  }
}'
```

The KV secret must hold **both** `api_key` and `application_key`.

:::caution[Do not point a `static_apikey` spec straight at the vault]
`mint_method=static_apikey` on the `hvault` source yields an `api_key` credential carrying
**the key alone** — adjunct fields are dropped for any non-`apikey` driver. The mount then
takes its fallback branch, which looks identical to a working one from the outside.
Without an `application_key` Warden injects only `DD-API-KEY`, which the read APIs reject. Route the read through the producer above instead.
:::

Both principals are available to the path template: `{{agent.sub}}` is free,
`{{agent.<claim>}}` needs `assertion_metadata_claims`, and `{{user.<claim>}}` needs
`assertion_user_claims` plus a user on the request. Swap `{{agent.team}}` for
`{{user.sub}}` to give each person their own credential. Templates resolve at **mint,
not at write**, so a path naming an unprojected claim is accepted by `spec create` and
fails on the first request.

### Option B: Inline

⚠️ 
```bash
warden cred source create datadog-src -json '{
  "type": "apikey",
  "config": {
    "api_url": "https://api.datadoghq.com",
    "verify_endpoint": "/api/v1/validate",
    "auth_header_type": "custom_header",
    "auth_header_name": "DD-API-KEY",
    "credential_fields": "application_key",
    "display_name": "Datadog"
  }
}'

printf '{"source":"datadog-src","min_ttl":3600,"max_ttl":86400,"config":{"application_key":"<app-key>","api_key":"%s"}}' \
  "$(cat /path/to/datadog-token)" | warden cred spec create datadog-ops -json -
```

One long-lived credential for every caller. Prefer Option A.

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
