# New Relic Provider

The New Relic provider enables proxied access to the New Relic REST API v2 and NerdGraph (GraphQL) API through Warden. It forwards requests to New Relic endpoints (Applications, Alerts, Dashboards, NRQL queries, Synthetics, etc.) with automatic credential injection and policy evaluation. Credentials are injected via the `Api-Key` header using a New Relic User API key (`NRAK-...`). One credential mode is supported: static API keys (`apikey` source type). Vault/OpenBao can also be used as a credential source (`hvault` source type).

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
- A **New Relic User API Key** (from New Relic > API Keys, prefixed with `NRAK-`)

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
warden write auth/jwt/role/newrelic-user \
    token_policies="newrelic-access" \
    user_claim=sub \
    cred_spec_name=newrelic-ops
```

## Step 2: Mount and Configure the Provider

Enable the New Relic provider at a path of your choice:

```bash
warden provider enable --type=newrelic
```

To mount at a custom path:

```bash
warden provider enable --type=newrelic newrelic-prod
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
  --type=apikey \
  --rotation-period=0 \
  --config=api_url=https://api.newrelic.com \
  --config=auth_header_type=custom_header \
  --config=auth_header_name=Api-Key \
  --config=display_name=New\ Relic
```

> **Note on verification:** New Relic's NerdGraph endpoint (`/graphql`) requires a POST with a GraphQL body, which the static API key driver's simple GET-based verifier does not support. Therefore `verify_endpoint` is omitted and key validation is skipped at spec creation time. The key will be validated on the first proxied request to New Relic.

Create a credential spec that references the credential source. The spec carries the User API key and gets associated with tokens at login time.

```bash
warden cred spec create newrelic-ops \
  --source newrelic-src \
  --config api_key=NRAK-XXXXXXXXXXXXXXXXXXXX
```

### Option B: Vault/OpenBao as Credential Source

Instead of storing API keys directly in Warden, you can store them in a Vault/OpenBao KV v2 secret engine and have Warden fetch them at runtime. This centralizes secret management in Vault.

**Prerequisites:** A Vault/OpenBao instance with:
- A KV v2 mount containing your New Relic User API key (e.g., at `secret/newrelic/ops` with an `api_key` field)
- An AppRole configured for Warden access

```bash
# Create a Vault credential source
warden cred source create newrelic-vault-src \
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
warden cred spec create newrelic-ops \
  --source newrelic-vault-src \
  --config mint_method=static_apikey \
  --config kv2_mount=secret \
  --config secret_path=newrelic/ops
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

Get a JWT from Hydra using one of the quickstart clients:

```bash
export JWT_TOKEN=$(curl -s -X POST http://localhost:4444/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=my-agent&client_secret=agent-secret&scope=api:read api:write" \
  | jq -r '.access_token')
```

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

The `allowed_common_names` field supports glob patterns. You can also match on other certificate fields: `allowed_dns_sans`, `allowed_email_sans`, `allowed_uri_sans`, or `allowed_organizational_units`.

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

## Configuration Reference

### Provider Config

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `newrelic_url` | string | `https://api.newrelic.com` | New Relic API base URL (must match your datacenter region) |
| `max_body_size` | int | 10485760 (10 MB) | Maximum request body size in bytes (max 100 MB) |
| `timeout` | duration | `30s` | Request timeout |
| `tls_skip_verify` | bool | `false` | Skip TLS certificate verification; also allows `http://` URLs (development only) |
| `ca_data` | string | — | Base64-encoded PEM CA certificate for custom/self-signed CAs |
| `auto_auth_path` | string | — | **Required.** Auth mount path for implicit authentication (e.g., `auth/jwt/`, `auth/cert/`) |
| `default_role` | string | — | Fallback role when not specified in URL |

### Credential Source Config (Static API Keys)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `api_url` | string | No | API base URL (default: `https://api.newrelic.com`) |
| `verify_endpoint` | string | No | Verification path (omitted — NerdGraph requires POST with body, which the verifier does not support) |
| `auth_header_type` | string | No | How to attach key for verification: `custom_header` (recommended for New Relic) |
| `auth_header_name` | string | No | Header name for verification (e.g., `Api-Key`) |
| `display_name` | string | No | Label for logs/errors (default: `API Key`) |

### Credential Spec Config (Static API Keys)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `api_key` | string | Yes | New Relic User API key (sensitive — masked in output; prefixed with `NRAK-`) |

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
| `secret_path` | string | Yes | Path to the secret within the mount (must contain `api_key`) |

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
     --config api_key=NRAK-YYYYYYYYYYYYYYYYYYYY
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
