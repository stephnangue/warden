# Elastic Provider

The Elastic provider enables proxied access to Elasticsearch REST APIs through Warden. It forwards requests to Elasticsearch cluster endpoints (Search, Index, Cluster, Security, etc.) with automatic credential injection and policy evaluation. Credentials are injected via the `Authorization: ApiKey` header. Three credential modes are supported: static API keys (`apikey` source type), Elasticsearch driver with programmatic key rotation (`elastic` source type), and Vault/OpenBao as a credential source (`hvault` source type).

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
- An **Elasticsearch cluster** with a reachable HTTPS endpoint and a valid **API key** (from Elasticsearch Security API or Kibana > Stack Management > API Keys)

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
warden write auth/jwt/role/elastic-user \
    token_policies="elastic-access" \
    user_claim=sub \
    cred_spec_name=elastic-ops
```

## Step 2: Mount and Configure the Provider

Enable the Elastic provider at a path of your choice:

```bash
warden provider enable --type=elastic
```

To mount at a custom path:

```bash
warden provider enable --type=elastic elastic-prod
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
  --type=apikey \
  --rotation-period=0 \
  --config=api_url=https://my-cluster.es.us-east-1.aws.cloud.es.io \
  --config=verify_endpoint=/ \
  --config=auth_header_type=custom_header \
  --config=auth_header_name=Authorization \
  --config=display_name=Elastic
```

Create a credential spec that references the credential source. The spec carries the pre-encoded API key.

```bash
warden cred spec create elastic-ops \
  --source elastic-src \
  --config api_key=your-base64-encoded-api-key
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
  --type=elastic \
  --config=elastic_url=https://my-cluster.es.us-east-1.aws.cloud.es.io \
  --config=api_key=your-base64-encoded-source-api-key \
  --rotation-period=72h
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
  --source elastic-src
```

Optionally restrict the minted key's permissions via `role_descriptors`:

```bash
warden cred spec create elastic-readonly \
  --source elastic-src \
  --config 'role_descriptors={"reader":{"indices":[{"names":["my-index-*"],"privileges":["read"]}]}}'
```

Set an expiration on minted keys:

```bash
warden cred spec create elastic-temp \
  --source elastic-src \
  --config expiration=1h
```

### Option C: Vault/OpenBao as Credential Source

Store the Elasticsearch API key in a Vault/OpenBao KV v2 secret and have Warden fetch it at runtime.

**Prerequisites:** A Vault/OpenBao instance with:
- A KV v2 mount containing your Elasticsearch key (e.g., at `secret/elastic/ops` with an `api_key` field containing the pre-encoded value)
- An AppRole configured for Warden access

```bash
# Create a Vault credential source
warden cred source create elastic-vault-src \
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
warden cred spec create elastic-ops \
  --source elastic-vault-src \
  --config mint_method=static_apikey \
  --config kv2_mount=secret \
  --config secret_path=elastic/ops
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

Get a JWT from Hydra using one of the quickstart clients:

```bash
export JWT_TOKEN=$(curl -s -X POST http://localhost:4444/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=my-agent&client_secret=agent-secret&scope=api:read api:write" \
  | jq -r '.access_token')
```

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

The `allowed_common_names` field supports glob patterns. You can also match on other certificate fields: `allowed_dns_sans`, `allowed_email_sans`, `allowed_uri_sans`, or `allowed_organizational_units`.

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

## Configuration Reference

### Provider Config

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `elastic_url` | string | — (required) | Elasticsearch cluster URL (must use HTTPS) |
| `max_body_size` | int | 10485760 (10 MB) | Maximum request body size in bytes (max 100 MB) |
| `timeout` | duration | `30s` | Request timeout |
| `auto_auth_path` | string | — | **Required.** Auth mount path for implicit authentication (e.g., `auth/jwt/`, `auth/cert/`) |
| `default_role` | string | — | Fallback role when not specified in URL |

### Credential Source Config (Static API Keys — `apikey` type)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `api_url` | string | No | Elasticsearch cluster URL for verification |
| `verify_endpoint` | string | No | Verification path (e.g., `/`) |
| `auth_header_type` | string | No | How to attach key for verification: `custom_header` |
| `auth_header_name` | string | No | Header name for verification (e.g., `Authorization`) |
| `display_name` | string | No | Label for logs/errors (default: `API Key`) |

### Credential Spec Config (Static API Keys)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `api_key` | string | Yes | Pre-encoded Elasticsearch API key — base64 of `id:api_key` (sensitive — masked in output) |

### Credential Source Config (Elasticsearch Driver — `elastic` type)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `elastic_url` | string | Yes | Elasticsearch cluster URL (HTTPS) |
| `api_key` | string | Yes | Pre-encoded source API key with `manage_api_key` privilege (sensitive — masked in output) |
| `api_key_id` | string | No | API key ID (extracted from `api_key` if omitted) |
| `activation_delay` | duration | No | Wait period for key propagation during rotation (default: `10s`) |
| `key_name_prefix` | string | No | Prefix for generated API key names (default: `warden`) |
| `tls_skip_verify` | bool | No | Skip TLS certificate verification; also allows `http://` URLs (default: `false`) |
| `ca_data` | string | No | Base64-encoded PEM CA certificate for custom/self-signed CAs |

### Credential Spec Config (Elasticsearch Driver)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `key_name` | string | No | Override for the generated API key name |
| `role_descriptors` | string | No | JSON string of Elasticsearch role descriptors to scope the minted key |
| `expiration` | string | No | Key expiration (e.g., `1h`, `30d`). Default: `1h` |

### Credential Source Config (Vault/OpenBao — `hvault` type)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `vault_address` | string | Yes | Vault server address (e.g., `https://vault.example.com`) |
| `vault_namespace` | string | No | Vault namespace (Enterprise/HCP only) |
| `auth_method` | string | No | Authentication method (`approle`) |
| `role_id` | string | Yes* | AppRole role ID (*required when `auth_method=approle`) |
| `secret_id` | string | Yes* | AppRole secret ID (*required when `auth_method=approle`) |
| `approle_mount` | string | Yes* | AppRole auth mount path (*required when `auth_method=approle`) |
| `role_name` | string | Yes* | AppRole role name for rotation (*required when `auth_method=approle`) |

### Credential Spec Config (Vault — `static_apikey`)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mint_method` | string | Yes | Must be `static_apikey` |
| `kv2_mount` | string | Yes | KV v2 mount path in Vault |
| `secret_path` | string | Yes | Path to the secret within the mount (must contain `api_key` field with the pre-encoded value) |

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
     --config api_key=your-new-base64-encoded-api-key
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
