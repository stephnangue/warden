---
title: "Splunk"
---

The Splunk provider enables proxied access to the Splunk REST API through Warden. It forwards requests to Splunk management endpoints (Search Jobs, Saved Searches, Dashboards, Indexes, Token Management, etc.) with automatic credential injection and policy evaluation. Credentials are injected via the `Authorization: Bearer <token>` header using Splunk's JWT token authentication (v7.3+). One credential mode is supported: static bearer tokens (`apikey` source type). Vault/OpenBao can also be used as a credential source (`hvault` source type).

## How a request flows

This mount injects `Authorization: Bearer <token>` from an **`api_key`** credential. The question is where that
auth token lives.

The recommended setup keeps it in the vault that manages it, read per request.

<p align="center"><img alt="An agent presents the user's ID token and its own identity to Warden, which builds an assertion carrying user and agent claims, has an external KMS sign it, reads the Splunk auth token from an external vault at a path templated by the agent's team and environment, and injects it to the Splunk API" src="/images/warden-prov-splunk-vault-apikey.png" width="860"></p>

1. The user authenticates and the agent holds their ID token.
2. The agent calls Warden presenting both credentials and asserting a role.
3. Warden builds the assertion the referenced spec calls for and sends it to a KMS-backed
   issuer unsigned, where one is configured.
4. The issuer returns it signed.
5. Warden authenticates to the **external vault** and reads
   `secret/splunk/{{agent.team}}/{{agent.env}}`.
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

<p align="center"><img alt="Warden reads a static Splunk auth token from its encrypted storage and injects it to the Splunk API for every caller" src="/images/warden-prov-splunk-inline-apikey.png" width="860"></p>

**Inline.** The credential sits in Warden's storage. Shortest to set up, weakest custody:
one long-lived credential for every caller.

## Credential modes

| Mode | What Splunk sees | Where the credential lives |
|---|---|---|
| **Chained** ✅ *recommended* | One long-lived credential, scoped by path | The vault; nothing in Warden |
| **Inline** ⚠️ | One long-lived credential, shared | Warden's storage |

Splunk exposes no workload-identity federation and mints nothing per request, so the
credential is long-lived in both rows; what changes is whether Warden holds it.

See the [apikey credential driver](/credential-drivers/apikey/) for every source and spec
key.

## Prerequisites

- Docker and Docker Compose installed and running
- A **Splunk instance** (Enterprise 7.3+ or Cloud 8.0.2007+) with token authentication enabled
- A **Splunk Bearer Token** with appropriate capabilities (see [Token Management](#token-management))

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
warden write auth/jwt/role/splunk-user \
    token_policies="splunk-access" \
    user_claim=sub \
    cred_spec_name=splunk-ops
```

## Step 2: Mount and Configure the Provider

Enable the Splunk provider at a path of your choice:

```bash
warden provider enable splunk
```

To mount at a custom path:

```bash
warden provider enable -path=splunk-prod splunk
```

Verify the provider is enabled:

```bash
warden provider list
```

Configure the provider with `auto_auth_path`. This allows clients to authenticate with their JWT directly — no explicit Warden login required:

```bash
warden write splunk/config <<EOF
{
  "splunk_url": "https://splunk.example.com:8089",
  "auto_auth_path": "auth/jwt/",
  "timeout": "30s",
  "max_body_size": 10485760
}
EOF
```

See [Provider configuration](/provider-backends/configuration/) for the full list of common config fields (`proxy_domains`, `timeout`, `tls_skip_verify`, `ca_data`, and more).

Set `splunk_url` to your Splunk management endpoint (port 8089). HTTPS is required:

| Deployment | URL |
|------------|-----|
| Enterprise (remote) | `https://splunk.example.com:8089` |
| Splunk Cloud | `https://<stack-name>.splunkcloud.com:8089` |

Verify the configuration:

```bash
warden read splunk/config
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

warden cred spec create splunk-ops -json '{
  "source": "vault-keyless",
  "min_ttl": 600,
  "max_ttl": 3600,
  "config": {
    "mint_method": "static_apikey",
    "subject_token_source": "warden_identity",
    "assertion_metadata_claims": "team,env",
    "kv2_mount": "secret",
    "secret_path": "splunk/{{agent.team}}/{{agent.env}}"
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
warden cred source create splunk-src -json '{
  "type": "apikey",
  "config": {
    "api_url": "https://splunk.example.com:8089",
    "verify_endpoint": "/services/server/info",
    "display_name": "Splunk"
  }
}'

printf '{"source":"splunk-src","min_ttl":3600,"max_ttl":86400,"config":{"api_key":"%s"}}' \
  "$(cat /path/to/splunk-token)" | warden cred spec create splunk-ops -json -
```

One long-lived credential for every caller. Prefer Option A.

## Step 4: Create a Policy

Create a policy that grants access to the Splunk provider gateway:

```bash
warden policy write splunk-access - <<EOF
path "splunk/role/+/gateway*" {
  capabilities = ["create", "read", "update", "delete", "patch"]
}
EOF
```

For fine-grained access control, restrict which Splunk endpoints a role can access:

```bash
warden policy write splunk-readonly - <<EOF
# Search jobs (read-only: list and get results)
path "splunk/role/+/gateway/services/search/jobs" {
  capabilities = ["read"]
}

path "splunk/role/+/gateway/services/search/jobs/*" {
  capabilities = ["read"]
}

# Saved searches (read-only)
path "splunk/role/+/gateway/services/saved/searches" {
  capabilities = ["read"]
}

# Server info
path "splunk/role/+/gateway/services/server/info" {
  capabilities = ["read"]
}

# Apps (read-only)
path "splunk/role/+/gateway/services/apps/local" {
  capabilities = ["read"]
}

# Dashboards (read-only via namespace)
path "splunk/role/+/gateway/servicesNS/+/search/data/ui/views" {
  capabilities = ["read"]
}
EOF
```

Verify:

```bash
warden policy read splunk-access
```

## Step 5: Get a JWT and Make Requests

Get a JWT from your identity provider — see [Obtaining a JWT](/auth-methods/jwt/#obtaining-a-jwt) (the local dev setup issues one from Hydra). Export it as `$JWT_TOKEN`.

Requests use role-based paths. Warden performs implicit JWT authentication and injects the Splunk bearer token automatically.

The URL pattern is: `/v1/splunk/role/{role}/gateway/{api-path}`

Export SPLUNK_ENDPOINT as environment variable:
```bash
export SPLUNK_ENDPOINT="${WARDEN_ADDR}/v1/splunk/role/splunk-user/gateway"
```

### Server Info

```bash
curl -s "${SPLUNK_ENDPOINT}/services/server/info?output_mode=json" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### Create a Search Job

```bash
curl -s -X POST "${SPLUNK_ENDPOINT}/services/search/jobs" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "search=search index=main earliest=-1h | head 10" \
  --data-urlencode "output_mode=json"
```

### Get Search Results

```bash
# Replace <SID> with the search ID from the previous response
curl -s "${SPLUNK_ENDPOINT}/services/search/jobs/<SID>/results?output_mode=json" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### List Saved Searches

```bash
curl -s "${SPLUNK_ENDPOINT}/services/saved/searches?output_mode=json&count=10" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### List Indexes

```bash
curl -s "${SPLUNK_ENDPOINT}/services/data/indexes?output_mode=json" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### List Installed Apps

```bash
curl -s "${SPLUNK_ENDPOINT}/services/apps/local?output_mode=json" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### Submit an Event via REST

```bash
curl -s -X POST "${SPLUNK_ENDPOINT}/services/receivers/simple?source=warden&sourcetype=json&index=main" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"event": "test event from warden", "severity": "info"}'
```

### List Authentication Tokens

```bash
curl -s "${SPLUNK_ENDPOINT}/services/authorization/tokens?output_mode=json" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### Namespace-Scoped Requests

Splunk supports namespace-scoped endpoints via `/servicesNS/{owner}/{app}/`:

```bash
# List dashboards in the "search" app for all users
curl -s "${SPLUNK_ENDPOINT}/servicesNS/-/search/data/ui/views?output_mode=json&count=10" \
  -H "Authorization: Bearer ${JWT_TOKEN}"

# List saved searches for a specific user
curl -s "${SPLUNK_ENDPOINT}/servicesNS/admin/search/saved/searches?output_mode=json" \
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
    default_role=splunk-user
```

### Create a Cert Role

Create a role that binds allowed certificate identities to a credential spec and policy:

```bash
warden write auth/cert/role/splunk-user \
    allowed_common_names="agent-*" \
    token_policies="splunk-access" \
    cred_spec_name=splunk-ops
```

The `allowed_common_names` field supports glob patterns; you can also match on other certificate fields. See [Create a role](/auth-methods/cert/#step-3-create-a-role) for the full set of constraint fields.

### Configure Provider for Cert Auth

Update the provider config to use cert auth:

```bash
warden write splunk/config <<EOF
{
  "splunk_url": "https://splunk.example.com:8089",
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
    -s "https://warden.internal/v1/splunk/role/splunk-user/gateway/services/server/info?output_mode=json"
```

## Token Management

### Splunk Token Types

Splunk supports three JWT token types (v7.3+):

| Type | Lifetime | Modifiable | Best For |
|------|----------|------------|----------|
| **Static** | Indefinite (or custom expiry) | Yes | Service accounts, long-lived integrations |
| **Ephemeral** | Max 6 hours | No | Short-lived automation tasks |
| **Interactive** | Most restricted | No | User sessions |

For Warden, **static tokens** are recommended as they provide stable, long-lived credentials for service-to-service access.

### Required Splunk Capabilities

The Splunk user associated with the bearer token needs appropriate capabilities:

| Capability | Description |
|------------|-------------|
| `search` | Run searches |
| `list_inputs` | List data inputs |
| `list_settings` | View server settings |
| `rest_apps_view` | View apps |
| `edit_tokens_own` | Manage own tokens (for rotation) |

### Creating Tokens in Splunk

**Via Splunk Web:**
Settings > Tokens > New Token

**Via REST API:**

```bash
curl -k -u admin:password -X POST \
  "https://splunk.example.com:8089/services/authorization/tokens?output_mode=json" \
  --data name=warden-service \
  --data audience=warden-proxy \
  --data type=static \
  --data-urlencode "expires_on=+365d"
```

### Token Rotation

| Aspect | Details |
|--------|---------|
| **Storage** | Bearer token is stored on the credential spec (not the source) |
| **Validation** | Token is verified at spec creation via `GET /services/server/info` |
| **Rotation** | Manual — create a new token in Splunk and update the spec |
| **Lifetime** | Configurable — static tokens can be set to never expire |

**To rotate Splunk bearer tokens:**

1. Create a new token in Splunk (with `not_before` set to allow overlap):
   ```bash
   curl -k -u admin:password -X POST \
     "https://splunk.example.com:8089/services/authorization/tokens?output_mode=json" \
     --data name=warden-service \
     --data audience=warden-proxy \
     --data type=static \
     --data-urlencode "expires_on=+365d"
   ```
2. Update the credential spec:
   ```bash
   warden cred spec update splunk-ops \
     -config api_key=your-new-bearer-token
   ```
3. Delete the old token in Splunk:
   ```bash
   curl -k -u admin:password -X DELETE \
     "https://splunk.example.com:8089/services/authorization/tokens/warden-service?output_mode=json" \
     -d id=old-token-id
   ```

### Splunk Cloud Considerations

| Aspect | Splunk Enterprise | Splunk Cloud |
|--------|------------------|--------------|
| Token auth available | v7.3+ | v8.0.2007+ |
| REST API access | Full (all endpoints) | Search tier only |
| Management port | 8089 (configurable) | 8089 (fixed) |
| Endpoint restrictions | None | Many endpoints restricted |
| Token creation | REST API or Web UI | Web UI or support ticket |

When using Splunk Cloud, ensure that the REST API endpoints you need are in the allowed list for your Splunk Cloud version.

## Self-Hosted Splunk

### Custom CA Certificate

If your Splunk instance uses a certificate signed by a private CA:

```bash
CA_DATA=$(base64 < /path/to/corporate-ca.pem)

warden write splunk/config <<EOF
{
  "splunk_url": "https://splunk.internal.corp:8089",
  "ca_data": "${CA_DATA}",
  "auto_auth_path": "auth/jwt/"
}
EOF
```

### Development / Testing (no TLS)

For local development against a Splunk instance without TLS:

```bash
warden write splunk/config <<EOF
{
  "splunk_url": "http://localhost:8089",
  "tls_skip_verify": true,
  "auto_auth_path": "auth/jwt/"
}
EOF
```
