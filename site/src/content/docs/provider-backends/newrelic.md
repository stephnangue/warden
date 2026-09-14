---
title: "New Relic"
---

The New Relic provider enables proxied access to the New Relic REST API v2 and NerdGraph (GraphQL) API through Warden. It forwards requests to New Relic endpoints (Applications, Alerts, Dashboards, NRQL queries, Synthetics, etc.) with automatic credential injection and policy evaluation. Credentials are injected via the `Api-Key` header using a New Relic User API key (`NRAK-...`). One credential mode is supported: static API keys (`apikey` source type). Vault/OpenBao can also be used as a credential source (`hvault` source type).

## How a request flows

This mount injects the `Api-Key` header from an **`api_key`** credential. The question is where that
User API key lives.

The recommended setup keeps it in the vault that manages it, read per request.

<p align="center"><img alt="An agent presents the user's ID token and its own identity to Warden, which builds an assertion carrying user and agent claims, has an external KMS sign it, reads the New Relic User API key from an external vault at a path templated by the agent's team and environment, and injects it to the New Relic API" src="/images/warden-prov-newrelic-vault-apikey.png" width="860"></p>

1. The user authenticates and the agent holds their ID token.
2. The agent calls Warden presenting both credentials and asserting a role.
3. Warden builds the assertion the referenced spec calls for and sends it to a KMS-backed
   issuer unsigned, where one is configured.
4. The issuer returns it signed.
5. Warden authenticates to the **external vault** and reads
   `secret/newrelic/{{agent.team}}/{{agent.env}}`.
6. The vault returns the User API key for that team and environment.
7. Warden injects it and forwards.

The credential is served **verbatim** — nothing is minted. What chaining buys is custody:
it stays in the store that manages it, and the read path decides who reaches which one.

:::note[Steps 3–6 run only on a cache miss]
Warden caches the credential, so most requests skip from step 2 to step 7. The entry is
keyed by namespace, the agent's token id and the spec name — plus the user's token id when
the mount carries a user.
:::

### The simpler variant

<p align="center"><img alt="Warden reads a static New Relic User API key from its encrypted storage and injects it to the New Relic API for every caller" src="/images/warden-prov-newrelic-inline-apikey.png" width="860"></p>

**Inline.** The credential sits in Warden's storage. Shortest to set up, weakest custody:
one long-lived credential for every caller.

## Credential modes

| Mode | What New Relic sees | Where the credential lives |
|---|---|---|
| **Chained** ✅ *recommended* | One long-lived credential, scoped by path | The vault; nothing in Warden |
| **Inline** ⚠️ | One long-lived credential, shared | Warden's storage |

New Relic exposes no workload-identity federation and mints nothing per request, so the
credential is long-lived in both rows; what changes is whether Warden holds it.

See the [apikey credential driver](/credential-drivers/apikey/) for every source and spec
key.

## Prerequisites

- Docker and Docker Compose installed and running
- A **New Relic User API Key** (from New Relic > API Keys, prefixed with `NRAK-`)

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
warden write auth/jwt/role/newrelic-user \
    token_policies="newrelic-access" \
    user_claim=sub \
    cred_spec_name=newrelic-ops
```

## Step 2: Mount and Configure the Provider

Enable the New Relic provider at a path of your choice:

```bash
warden provider enable newrelic
```

To mount at a custom path:

```bash
warden provider enable -path=newrelic-prod newrelic
```

Verify the provider is enabled:

```bash
warden provider list
```

Configure the provider with `auto_auth_path`. This allows clients to authenticate with their JWT directly — no explicit Warden login required:

```bash
warden write newrelic/config <<EOF
{
  "newrelic_url": "https://api.newrelic.com",
  "auto_auth_path": "auth/jwt/",
  "timeout": "30s",
  "max_body_size": 10485760
}
EOF
```

See [Provider configuration](/provider-backends/configuration/) for the full list of common config fields (`proxy_domains`, `timeout`, `tls_skip_verify`, `ca_data`, and more).

Set `newrelic_url` to match your New Relic datacenter region:

| Region | URL |
|--------|-----|
| US (default) | `https://api.newrelic.com` |
| EU | `https://api.eu.newrelic.com` |

Verify the configuration:

```bash
warden read newrelic/config
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

warden cred spec create newrelic-ops -json '{
  "source": "vault-keyless",
  "min_ttl": 600,
  "max_ttl": 3600,
  "config": {
    "mint_method": "static_apikey",
    "subject_token_source": "warden_identity",
    "assertion_metadata_claims": "team,env",
    "kv2_mount": "secret",
    "secret_path": "newrelic/{{agent.team}}/{{agent.env}}"
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

### Option B: Inline

⚠️ 
```bash
warden cred source create newrelic-src -json '{
  "type": "apikey",
  "config": {
    "api_url": "https://api.newrelic.com",
    "display_name": "New Relic"
  }
}'

printf '{"source":"newrelic-src","min_ttl":3600,"max_ttl":86400,"config":{"api_key":"%s"}}' \
  "$(cat /path/to/newrelic-token)" | warden cred spec create newrelic-ops -json -
```

One long-lived credential for every caller. Prefer Option A.

## Step 4: Create a Policy

Create a policy that grants access to the New Relic provider gateway:

```bash
warden policy write newrelic-access - <<EOF
path "newrelic/role/+/gateway*" {
  capabilities = ["create", "read", "update", "delete", "patch"]
}
EOF
```

For fine-grained access control, restrict which New Relic resources and actions a role can use:

```bash
warden policy write newrelic-readonly - <<EOF
# NerdGraph (GraphQL) — read-only queries
path "newrelic/role/+/gateway/graphql" {
  capabilities = ["create"]
}

# REST API v2 — read-only endpoints
path "newrelic/role/+/gateway/v2/applications.json" {
  capabilities = ["read"]
}

path "newrelic/role/+/gateway/v2/alerts_policies.json" {
  capabilities = ["read"]
}

path "newrelic/role/+/gateway/v2/key_transactions.json" {
  capabilities = ["read"]
}
EOF
```

> **Note:** NerdGraph requests use POST to `/graphql`, so the `create` capability is needed even for read-only queries. You can further restrict access using body-based policies that inspect the GraphQL query string.

Verify:

```bash
warden policy read newrelic-access
```

## Step 5: Get a JWT and Make Requests

Get a JWT from your identity provider — see [Obtaining a JWT](/auth-methods/jwt/#obtaining-a-jwt) (the local dev setup issues one from Hydra). Export it as `$JWT_TOKEN`.

Requests use role-based paths. Warden performs implicit JWT authentication and injects the New Relic User API key automatically.

The URL pattern is: `/v1/newrelic/role/{role}/gateway/{api-path}`

Export NR_ENDPOINT as environment variable:
```bash
export NR_ENDPOINT="${WARDEN_ADDR}/v1/newrelic/role/newrelic-user/gateway"
```

> **Authentication headers:** The provider accepts the JWT via `Api-Key` (recommended — natural for New Relic clients), `Authorization: Bearer`, or `X-Warden-Token`. All three are equivalent; the examples below use `Api-Key`.

### NerdGraph Query — Get Current User

```bash
curl -s -X POST "${NR_ENDPOINT}/graphql" \
  -H "Api-Key: ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"query": "{ actor { user { email name } } }"}'
```

### NerdGraph Query — Run NRQL

```bash
curl -s -X POST "${NR_ENDPOINT}/graphql" \
  -H "Api-Key: ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ actor { account(id: YOUR_ACCOUNT_ID) { nrql(query: \"SELECT count(*) FROM Transaction SINCE 1 hour ago\") { results } } } }"
  }'
```

### NerdGraph Query — List Entities

```bash
curl -s -X POST "${NR_ENDPOINT}/graphql" \
  -H "Api-Key: ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ actor { entitySearch(query: \"domain = '\''APM'\'' AND type = '\''APPLICATION'\''\") { results { entities { guid name alertSeverity } } } } }"
  }'
```

### NerdGraph Query — List Dashboards

```bash
curl -s -X POST "${NR_ENDPOINT}/graphql" \
  -H "Api-Key: ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ actor { entitySearch(query: \"type = '\''DASHBOARD'\''\") { results { entities { guid name tags { key values } } } } } }"
  }'
```

### NerdGraph Mutation — Create Alert Condition (NRQL)

```bash
curl -s -X POST "${NR_ENDPOINT}/graphql" \
  -H "Api-Key: ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation($accountId: Int!, $policyId: ID!, $condition: AlertsNrqlConditionStaticInput!) { alertsNrqlConditionStaticCreate(accountId: $accountId, policyId: $policyId, condition: $condition) { id name } }",
    "variables": {
      "accountId": YOUR_ACCOUNT_ID,
      "policyId": "YOUR_POLICY_ID",
      "condition": {
        "name": "High Error Rate",
        "enabled": true,
        "nrql": {
          "query": "SELECT count(*) FROM TransactionError WHERE appName = '\''my-app'\''"
        },
        "terms": [{
          "threshold": 10,
          "thresholdOccurrences": "AT_LEAST_ONCE",
          "thresholdDuration": 300,
          "operator": "ABOVE",
          "priority": "CRITICAL"
        }]
      }
    }
  }'
```

### REST API v2 — List Applications

```bash
curl -s "${NR_ENDPOINT}/v2/applications.json" \
  -H "Api-Key: ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### REST API v2 — List Alert Policies

```bash
curl -s "${NR_ENDPOINT}/v2/alerts_policies.json" \
  -H "Api-Key: ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### REST API v2 — List Key Transactions

```bash
curl -s "${NR_ENDPOINT}/v2/key_transactions.json" \
  -H "Api-Key: ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
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
    default_role=newrelic-user
```

### Create a Cert Role

Create a role that binds allowed certificate identities to a credential spec and policy:

```bash
warden write auth/cert/role/newrelic-user \
    allowed_common_names="agent-*" \
    token_policies="newrelic-access" \
    cred_spec_name=newrelic-ops
```

The `allowed_common_names` field supports glob patterns; you can also match on other certificate fields. See [Create a role](/auth-methods/cert/#step-3-create-a-role) for the full set of constraint fields.

### Configure Provider for Cert Auth

Update the provider config to use cert auth:

```bash
warden write newrelic/config <<EOF
{
  "newrelic_url": "https://api.newrelic.com",
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
    -s -X POST "https://warden.internal/v1/newrelic/role/newrelic-user/gateway/graphql" \
    -H "Content-Type: application/json" \
    -d '{"query": "{ actor { user { email } } }"}'
```

## Token Management

### Static API Keys

| Aspect | Details |
|--------|---------|
| **Storage** | User API key is stored on the credential spec (not the source) |
| **Validation** | Not verified at spec creation (NerdGraph requires POST with body); validated on first proxied request |
| **Rotation** | Manual — create a new key in New Relic and update the spec (see below) |
| **Lifetime** | Static — no expiration or auto-refresh |

### About New Relic API Key Types

New Relic has several key types. This provider uses **User API keys** (`NRAK-...`):

| Key Type | Purpose | Manageable via API? |
|----------|---------|---------------------|
| **User Key** (`NRAK-`) | NerdGraph + REST API v2 authentication | Yes (NerdGraph mutations) |
| **License Key** (Ingest) | Report telemetry data (APM, infra) | Yes (create/delete only) |
| **Browser Key** (Ingest) | Report browser monitoring data | Yes (create/delete only) |

> **Note:** License and Browser keys are used for **data ingest**, not API access. If you need to proxy ingest endpoints, you would use a separate provider configuration with the appropriate key type.

### Rotating User API Keys

New Relic does not have an atomic key rotation API. Rotation follows a create-then-delete pattern:

1. **Create** a new User API key in New Relic (UI: API Keys page, or via NerdGraph `apiAccessCreateKeys` mutation)
2. **Update** the credential spec in Warden:
   ```bash
   warden cred spec update newrelic-ops \
     -config api_key=NRAK-YYYYYYYYYYYYYYYYYYYY
   ```
3. **Verify** requests are working with the new key
4. **Delete** the old key in New Relic (UI or via NerdGraph `apiAccessDeleteKeys` mutation)

### Programmatic Key Rotation via NerdGraph

To create a new User API key programmatically:

```graphql
mutation {
  apiAccessCreateKeys(keys: {
    user: {
      accountId: YOUR_ACCOUNT_ID
      userId: YOUR_USER_ID
      name: "Warden Service Key"
      notes: "Rotated on 2026-04-07"
    }
  }) {
    createdKeys { id key name type }
    errors { message type }
  }
}
```

To delete the old key:

```graphql
mutation {
  apiAccessDeleteKeys(keys: {
    userKeyIds: ["OLD_KEY_ID"]
  }) {
    deletedKeys { id }
    errors { message }
  }
}
```

> **Important:** The actual key value is only returned in the `apiAccessCreateKeys` response. Store it securely — subsequent queries will not return the full key.
