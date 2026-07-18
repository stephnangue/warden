---
title: "New Relic"
---

The New Relic provider enables proxied access to the New Relic REST API v2 and NerdGraph (GraphQL) API through Warden. It forwards requests to New Relic endpoints (Applications, Alerts, Dashboards, NRQL queries, Synthetics, etc.) with automatic credential injection and policy evaluation. Credentials are injected via the `Api-Key` header using a New Relic User API key (`NRAK-...`). One credential mode is supported: static API keys (`apikey` source type). Vault/OpenBao can also be used as a credential source (`hvault` source type).

## Prerequisites

- Docker and Docker Compose installed and running
- A **New Relic User API Key** (from New Relic > API Keys, prefixed with `NRAK-`)

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

### Option A: Static API Keys

The credential source holds only connection info (`api_url`). The User API key is stored on the credential spec below, allowing multiple specs with different keys to share one source.

```bash
warden cred source create newrelic-src \
  -type=apikey \
  -rotation-period=0 \
  -config=api_url=https://api.newrelic.com \
  -config=auth_header_type=custom_header \
  -config=auth_header_name=Api-Key \
  -config=display_name=New\ Relic
```

> **Note on verification:** New Relic's NerdGraph endpoint (`/graphql`) requires a POST with a GraphQL body, which the static API key driver's simple GET-based verifier does not support. Therefore `verify_endpoint` is omitted and key validation is skipped at spec creation time. The key will be validated on the first proxied request to New Relic.

Create a credential spec that references the credential source. The spec carries the User API key and gets associated with tokens at login time.

```bash
warden cred spec create newrelic-ops \
  -source newrelic-src \
  -config api_key=NRAK-XXXXXXXXXXXXXXXXXXXX
```

### Option B: Vault/OpenBao as Credential Source

Instead of storing API keys directly in Warden, you can store them in a Vault/OpenBao KV v2 secret engine and have Warden fetch them at runtime. This centralizes secret management in Vault.

**Prerequisites:** A Vault/OpenBao instance with:
- A KV v2 mount containing your New Relic User API key (e.g., at `secret/newrelic/ops` with an `api_key` field)
- An AppRole configured for Warden access

```bash
# Create a Vault credential source
warden cred source create newrelic-vault-src \
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
warden cred spec create newrelic-ops \
  -source newrelic-vault-src \
  -config mint_method=static_apikey \
  -config kv2_mount=secret \
  -config secret_path=newrelic/ops
```

The KV v2 secret at `secret/newrelic/ops` should contain an `api_key` field with the New Relic User API key. Warden fetches the secret from Vault on each credential request.

Verify:

```bash
warden cred spec read newrelic-ops
```

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
