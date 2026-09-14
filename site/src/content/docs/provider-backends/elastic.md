---
title: "Elastic"
description: "Proxy Elasticsearch through Warden: mint a scoped API key per request from a cluster key held in a vault, so no long-lived key sits in Warden."
---

The Elastic provider enables proxied access to Elasticsearch REST APIs through Warden. It forwards requests to Elasticsearch cluster endpoints (Search, Index, Cluster, Security, etc.) with automatic credential injection and policy evaluation. Credentials are injected via the `Authorization: ApiKey` header.

## How a request flows

Two things vary independently: whether the key Elasticsearch sees is **minted per request**
or a fixed one, and whether the credential behind it lives **in Warden** or in a vault.

The best combination does both — a vaulted cluster key, used to mint a scoped API key for
each request.

<p align="center"><img alt="An agent presents the user's ID token and its own identity to Warden, which builds an assertion carrying user and agent claims, has an external KMS sign it, reads the Elasticsearch cluster key from an external vault at a path templated by the agent's team and environment, mints a scoped API key at the Elasticsearch security endpoint, and injects it to the Elasticsearch API" src="/images/warden-prov-elasticsearch-cred-chain.png" width="860"></p>

1. The user authenticates and the agent holds their ID token.
2. The agent calls Warden presenting both credentials and asserting a role.
3. Warden builds the assertion the referenced spec calls for and sends it to an **external
   KMS** unsigned.
4. The KMS returns it signed. No signing key lives in Warden.
5. Warden authenticates to the **external vault** and reads
   `secret/elastic/{{agent.team}}/{{agent.env}}`.
6. The vault returns the cluster key for that team and environment.
7. Warden calls `POST /_security/api_key` with it…
8. …and receives a freshly minted, optionally scoped key.
9. Warden injects it as `Authorization: ApiKey` and forwards.

The cluster key is the privileged one — it holds `manage_api_key` — so keeping it in the
vault and out of Warden is the point. What Elasticsearch sees is a narrower key that can
carry its own `role_descriptors` and expiry.

:::note[Steps 3–8 run only on a cache miss]
Warden caches the minted credential, so most requests skip from step 2 to step 9. The entry
is keyed by namespace, the agent's token id and the spec name — plus the user's token id
when the mount carries a user.
:::

### Simpler variants

<p align="center"><img alt="Warden authenticates to an external vault with a KMS-signed assertion carrying user and agent claims, reads a static Elasticsearch API key from a templated path, and injects it to the Elasticsearch API" src="/images/warden-prov-elasticsearch-vault-apikey.png" width="860"></p>

**Vaulted static key.** The vault holds a pre-encoded API key, served verbatim — no minting.
It stays out of Warden and the path scopes who reaches which key, but it is long-lived and
shared by everyone the path resolves for.

<p align="center"><img alt="Warden reads a static Elasticsearch API key from its encrypted storage and injects it to the Elasticsearch API for every caller" src="/images/warden-prov-elasticsearch-inline-apikey.png" width="860"></p>

**Inline static key.** The key sits in Warden's storage. Shortest to set up, weakest
custody.

## Credential modes

| Mode | What Elasticsearch sees | Where the credential lives |
|---|---|---|
| **Chained cluster key → minted key** ✅ *recommended* | A freshly minted, scopable key | The vault; nothing in Warden |
| **Stored cluster key → minted key** | The same minted key | The cluster key is in Warden, and is rotated |
| **Chained static key** | One long-lived key, per path | The vault |
| **Inline static key** ⚠️ | One long-lived key, shared | Warden's storage |

Elasticsearch exposes no workload-identity federation, so a privileged key exists somewhere
in every row; what changes is whether Warden holds it, and whether the cluster sees it
directly.

See the [Elastic credential driver](/credential-drivers/elastic/) for every source and spec
key.

## Prerequisites

- Docker and Docker Compose installed and running
- An **Elasticsearch cluster** with a reachable HTTPS endpoint and a valid **API key** (from Elasticsearch Security API or Kibana > Stack Management > API Keys)

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
warden write auth/jwt/role/elastic-user \
    token_policies="elastic-access" \
    user_claim=sub \
    cred_spec_name=elastic-ops
```

## Step 2: Mount and Configure the Provider

Enable the Elastic provider at a path of your choice:

```bash
warden provider enable elastic
```

To mount at a custom path:

```bash
warden provider enable -path=elastic-prod elastic
```

Verify the provider is enabled:

```bash
warden provider list
```

Configure the provider with `auto_auth_path` and your Elasticsearch cluster URL. This allows clients to authenticate with their JWT directly — no explicit Warden login required:

```bash
warden write elastic/config <<EOF
{
  "elastic_url": "https://my-cluster.es.us-east-1.aws.cloud.es.io",
  "auto_auth_path": "auth/jwt/",
  "timeout": "30s",
  "max_body_size": 10485760
}
EOF
```

See [Provider configuration](/provider-backends/configuration/) for the full list of common config fields (`proxy_domains`, `timeout`, `tls_skip_verify`, `ca_data`, and more).

> **Note:** `elastic_url` is required and must use HTTPS. There is no default URL since Elasticsearch endpoints are deployment-specific.

Verify the configuration:

```bash
warden read elastic/config
```

## Step 3: Create a Credential Source and Spec

### Option A: Chained cluster key (recommended)

The flow in the first diagram. The `elastic` source names a `secret_spec` and holds no key
of its own; Warden reads the cluster key per mint and uses it to create a scoped API key.

The cluster key needs the `manage_api_key` (or `manage_own_api_key`) cluster privilege:

```bash
curl -s -X POST "https://your-cluster/_security/api_key" \
  -H "Content-Type: application/json" \
  -u "elastic:your-password" \
  -d '{
    "name": "warden-source",
    "role_descriptors": {"warden-manager": {"cluster": ["manage_api_key"]}}
  }' | jq -r '.encoded'
```

Put that `encoded` value in your vault, then:

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

# Producer: the cluster key, read from KV v2 through that source
warden cred spec create elastic-cluster-key -json '{
  "source": "vault-keyless",
  "min_ttl": 600,
  "max_ttl": 3600,
  "config": {
    "mint_method": "kv2_read",
    "subject_token_source": "warden_identity",
    "assertion_metadata_claims": "team,env",
    "kv2_mount": "secret",
    "secret_path": "elastic/{{agent.team}}/{{agent.env}}"
  }
}'

# Consumer: an elastic source holding no key of its own
warden cred source create elastic-src -json '{
  "type": "elastic",
  "config": {
    "elastic_url": "https://my-cluster.es.us-east-1.aws.cloud.es.io",
    "secret_spec": "elastic-cluster-key"
  }
}'

warden cred spec create elastic-ops -json '{
  "source": "elastic-src",
  "min_ttl": 600,
  "max_ttl": 3600
}'
```

`api_key` must be **omitted** when `secret_spec` is set — leaving it is rejected with
*"api_key must be omitted when secret_spec is set; the referenced spec supplies the cluster
key"*.

Both principals are available to the path template: `{{agent.sub}}` is free,
`{{agent.<claim>}}` needs `assertion_metadata_claims`, and `{{user.<claim>}}` needs
`assertion_user_claims` plus a user on the request. Templates resolve at **mint, not at
write**.

**Scope the minted key.** A bare spec mints a key with the source key's permissions;
`role_descriptors` narrows it, and `expiration` bounds it:

```bash
warden cred spec create elastic-readonly -json '{
  "source": "elastic-src",
  "min_ttl": 600,
  "max_ttl": 3600,
  "config": {
    "role_descriptors": "{\"reader\":{\"indices\":[{\"names\":[\"my-index-*\"],\"privileges\":[\"read\"]}]}}",
    "expiration": "1h"
  }
}'
```

### Option B: Cluster key stored in Warden

Same minting, but the cluster key lives in Warden's storage, where it is rotated on the
source's `rotation_period` (integer seconds in JSON — `259200` is 72h).

```bash
warden cred source create elastic-src -json '{
  "type": "elastic",
  "rotation_period": 259200,
  "config": {
    "elastic_url": "https://my-cluster.es.us-east-1.aws.cloud.es.io",
    "api_key": "<your-base64-encoded-source-api-key>"
  }
}'

warden cred spec create elastic-ops -json '{
  "source": "elastic-src",
  "min_ttl": 600,
  "max_ttl": 3600
}'
```

### Option C: Chained static key

No minting — the vault holds a pre-encoded API key and Warden serves it verbatim. Reusing
the `vault-keyless` source from Option A:

```bash
warden cred spec create elastic-ops -json '{
  "source": "vault-keyless",
  "min_ttl": 600,
  "max_ttl": 3600,
  "config": {
    "mint_method": "static_apikey",
    "subject_token_source": "warden_identity",
    "assertion_metadata_claims": "team,env",
    "kv2_mount": "secret",
    "secret_path": "elastic/{{agent.team}}/{{agent.env}}"
  }
}'
```

The KV secret must carry the key under `api_key`, holding the **pre-encoded** value.

### Option D: Inline static key ⚠️

Elasticsearch API keys are `base64(id:api_key)` — use the `encoded` value from the
creation response:

```bash
curl -s -X POST "https://your-cluster/_security/api_key" \
  -H "Content-Type: application/json" \
  -u "elastic:your-password" \
  -d '{"name": "warden-key"}' | jq -r '.encoded'
```

```bash
warden cred source create elastic-src -json '{
  "type": "apikey",
  "config": {
    "api_url": "https://my-cluster.es.us-east-1.aws.cloud.es.io",
    "display_name": "Elastic"
  }
}'

printf '{"source":"elastic-src","min_ttl":3600,"max_ttl":86400,"config":{"api_key":"%s"}}' \
  "$(cat /path/to/encoded-key)" | warden cred spec create elastic-ops -json -
```

**No `verify_endpoint` here, deliberately.** The apikey driver can send `Bearer `, `Token `
or a bare custom header — never Elasticsearch's required `ApiKey ` scheme — so a
verification call would be rejected even with a valid key and block spec creation. Leaving
`verify_endpoint` unset skips verification; the gateway still injects `Authorization:
ApiKey <key>` correctly, because that is the *provider's* extractor rather than the
driver's.

One long-lived key for every caller. Prefer any option above.

## Step 4: Create a Policy

Create a policy that grants access to the Elastic provider gateway:

```bash
warden policy write elastic-access - <<EOF
path "elastic/role/+/gateway*" {
  capabilities = ["create", "read", "update", "delete", "patch"]
}
EOF
```

For fine-grained access control, restrict which Elasticsearch resources a role can access:

```bash
warden policy write elastic-readonly - <<EOF
path "elastic/role/+/gateway/_cluster/health" {
  capabilities = ["read"]
}

path "elastic/role/+/gateway/_cat/indices" {
  capabilities = ["read"]
}

path "elastic/role/+/gateway/my-index-*" {
  capabilities = ["read"]
}
EOF
```

Verify:

```bash
warden policy read elastic-access
```

## Step 5: Get a JWT and Make Requests

Get a JWT from your identity provider — see [Obtaining a JWT](/auth-methods/jwt/#obtaining-a-jwt) (the local dev setup issues one from Hydra). Export it as `$JWT_TOKEN`.

Requests use role-based paths. Warden performs implicit JWT authentication and injects the Elasticsearch API key automatically.

The URL pattern is: `/v1/elastic/role/{role}/gateway/{api-path}`

Export ES_ENDPOINT as environment variable:
```bash
export ES_ENDPOINT="${WARDEN_ADDR}/v1/elastic/role/elastic-user/gateway"
```

### Cluster Health

```bash
curl -s "${ES_ENDPOINT}/_cluster/health" \
  -H "Authorization: ApiKey ${JWT_TOKEN}"
```

### List Indices

```bash
curl -s "${ES_ENDPOINT}/_cat/indices?v" \
  -H "Authorization: ApiKey ${JWT_TOKEN}"
```

### Search Documents

```bash
curl -s -X POST "${ES_ENDPOINT}/my-index/_search" \
  -H "Authorization: ApiKey ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "query": {
      "match": {
        "message": "error"
      }
    },
    "size": 10
  }'
```

### Index a Document

```bash
curl -s -X POST "${ES_ENDPOINT}/my-index/_doc" \
  -H "Authorization: ApiKey ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "message": "Hello from Warden",
    "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"
  }'
```

### Bulk Operations

```bash
curl -s -X POST "${ES_ENDPOINT}/_bulk" \
  -H "Authorization: ApiKey ${JWT_TOKEN}" \
  -H "Content-Type: application/x-ndjson" \
  -d '
{"index":{"_index":"my-index"}}
{"message":"bulk doc 1","timestamp":"2026-01-01T00:00:00Z"}
{"index":{"_index":"my-index"}}
{"message":"bulk doc 2","timestamp":"2026-01-01T00:00:01Z"}
'
```

### Get Cluster Settings

```bash
curl -s "${ES_ENDPOINT}/_cluster/settings?include_defaults=false" \
  -H "Authorization: ApiKey ${JWT_TOKEN}"
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
    default_role=elastic-user
```

### Create a Cert Role

Create a role that binds allowed certificate identities to a credential spec and policy:

```bash
warden write auth/cert/role/elastic-user \
    allowed_common_names="agent-*" \
    token_policies="elastic-access" \
    cred_spec_name=elastic-ops
```

The `allowed_common_names` field supports glob patterns; you can also match on other certificate fields. See [Create a role](/auth-methods/cert/#step-3-create-a-role) for the full set of constraint fields.

### Configure Provider for Cert Auth

Update the provider config to use cert auth:

```bash
warden write elastic/config <<EOF
{
  "elastic_url": "https://my-cluster.es.us-east-1.aws.cloud.es.io",
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
    -s "https://warden.internal/v1/elastic/role/elastic-user/gateway/_cluster/health"
```

## Token Management

### Static API Keys

| Aspect | Details |
|--------|---------|
| **Storage** | API key is stored on the credential spec (not the source) |
| **Rotation** | Manual — create a new key in Elasticsearch and update the spec |
| **Lifetime** | Static — no expiration or auto-refresh |

**To rotate static Elasticsearch API keys:**

1. Create a new API key in Elasticsearch (via API or Kibana)
2. Update the credential spec:
   ```bash
   warden cred spec update elastic-ops \
     -config api_key=your-new-base64-encoded-api-key
   ```
3. Invalidate the old key in Elasticsearch:
   ```bash
   curl -X DELETE "https://your-cluster/_security/api_key" \
     -H "Content-Type: application/json" \
     -d '{"ids": ["old-key-id"]}'
   ```

### Elasticsearch Driver (Automatic Rotation)

| Aspect | Details |
|--------|---------|
| **Storage** | Source API key stored on the credential source; minted keys are ephemeral |
| **Rotation** | Automatic — source key is rotated per `rotation-period` via the Security API |
| **Propagation** | 10-second default activation delay (configurable via `activation_delay`) |
| **Lifecycle** | PrepareRotation (create new key) → wait → CommitRotation (switch) → CleanupRotation (invalidate old) |

## Self-Hosted Elasticsearch

### Custom CA Certificate

If your Elasticsearch cluster uses a certificate signed by a private CA:

```bash
CA_DATA=$(base64 < /path/to/corporate-ca.pem)

warden write elastic/config <<EOF
{
  "elastic_url": "https://elastic.internal.corp:9200",
  "ca_data": "${CA_DATA}",
  "auto_auth_path": "auth/jwt/"
}
EOF
```

### Development / Testing (no TLS)

For local development against an Elasticsearch instance without TLS:

```bash
warden write elastic/config <<EOF
{
  "elastic_url": "http://localhost:9200",
  "tls_skip_verify": true,
  "auto_auth_path": "auth/jwt/"
}
EOF
```
