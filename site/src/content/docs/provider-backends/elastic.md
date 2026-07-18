---
title: "Elastic"
---

The Elastic provider enables proxied access to Elasticsearch REST APIs through Warden. It forwards requests to Elasticsearch cluster endpoints (Search, Index, Cluster, Security, etc.) with automatic credential injection and policy evaluation. Credentials are injected via the `Authorization: ApiKey` header. Three credential modes are supported: static API keys (`apikey` source type), Elasticsearch driver with programmatic key rotation (`elastic` source type), and Vault/OpenBao as a credential source (`hvault` source type).

## Prerequisites

- Docker and Docker Compose installed and running
- An **Elasticsearch cluster** with a reachable HTTPS endpoint and a valid **API key** (from Elasticsearch Security API or Kibana > Stack Management > API Keys)

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

### Option A: Static API Keys

The simplest setup. The credential source holds only connection info. The API key is stored on the credential spec.

Elasticsearch API keys use the format `base64(id:api_key)`. When you create an API key via the Elasticsearch API or Kibana, use the `encoded` value from the response.

```bash
warden cred source create elastic-src \
  -type=apikey \
  -rotation-period=0 \
  -config=api_url=https://my-cluster.es.us-east-1.aws.cloud.es.io \
  -config=verify_endpoint=/ \
  -config=auth_header_type=custom_header \
  -config=auth_header_name=Authorization \
  -config=display_name=Elastic
```

Create a credential spec that references the credential source. The spec carries the pre-encoded API key.

```bash
warden cred spec create elastic-ops \
  -source elastic-src \
  -config api_key=your-base64-encoded-api-key
```

> **Tip:** To get the encoded API key from Elasticsearch:
> ```bash
> curl -s -X POST "https://your-cluster/_security/api_key" \
>   -H "Content-Type: application/json" \
>   -u "elastic:your-password" \
>   -d '{"name": "warden-key"}' | jq -r '.encoded'
> ```

### Option B: Elasticsearch Driver (with API Key Rotation)

The Elasticsearch driver creates API keys programmatically via `POST /_security/api_key` and supports automatic rotation of the source API key. This requires the source API key to have the `manage_api_key` or `manage_own_api_key` cluster privilege.

```bash
warden cred source create elastic-src \
  -type=elastic \
  -config=elastic_url=https://my-cluster.es.us-east-1.aws.cloud.es.io \
  -config=api_key=your-base64-encoded-source-api-key \
  -rotation-period=72h
```

The source API key must have sufficient privileges to create and invalidate API keys. To create such a key:

```bash
curl -s -X POST "https://your-cluster/_security/api_key" \
  -H "Content-Type: application/json" \
  -u "elastic:your-password" \
  -d '{
    "name": "warden-source",
    "role_descriptors": {
      "warden-manager": {
        "cluster": ["manage_api_key"]
      }
    }
  }'
```

Create a credential spec. The driver mints a new API key for each spec:

```bash
warden cred spec create elastic-ops \
  -source elastic-src
```

Optionally restrict the minted key's permissions via `role_descriptors`:

```bash
warden cred spec create elastic-readonly \
  -source elastic-src \
  -config 'role_descriptors={"reader":{"indices":[{"names":["my-index-*"],"privileges":["read"]}]}}'
```

Set an expiration on minted keys:

```bash
warden cred spec create elastic-temp \
  -source elastic-src \
  -config expiration=1h
```

### Option C: Vault/OpenBao as Credential Source

Store the Elasticsearch API key in a Vault/OpenBao KV v2 secret and have Warden fetch it at runtime.

**Prerequisites:** A Vault/OpenBao instance with:
- A KV v2 mount containing your Elasticsearch key (e.g., at `secret/elastic/ops` with an `api_key` field containing the pre-encoded value)
- An AppRole configured for Warden access

```bash
# Create a Vault credential source
warden cred source create elastic-vault-src \
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
warden cred spec create elastic-ops \
  -source elastic-vault-src \
  -config mint_method=static_apikey \
  -config kv2_mount=secret \
  -config secret_path=elastic/ops
```

Verify:

```bash
warden cred spec read elastic-ops
```

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
