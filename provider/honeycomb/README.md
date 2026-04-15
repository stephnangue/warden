# Honeycomb Provider

The Honeycomb provider enables proxied access to the Honeycomb API through Warden. It forwards requests to Honeycomb endpoints (`/1/events/{dataset}`, `/1/queries/{dataset}`, `/2/teams/{team}/api-keys`, etc.) with automatic credential injection and policy evaluation. Honeycomb uses two authentication modes: the `X-Honeycomb-Team` header for ingest and configuration keys, and `Authorization: Bearer <key_id>:<key_secret>` for management keys. Credentials can be static tokens from an `apikey` source or dynamically minted API keys from the `honeycomb` source driver.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Step 1: Configure JWT Auth and Create a Role](#step-1-configure-jwt-auth-and-create-a-role)
- [Step 2: Mount and Configure the Provider](#step-2-mount-and-configure-the-provider)
- [Step 3: Create a Credential Source and Spec](#step-3-create-a-credential-source-and-spec)
- [Step 4: Create a Policy](#step-4-create-a-policy)
- [Step 5: Get a JWT and Make Requests](#step-5-get-a-jwt-and-make-requests)
- [Cleanup](#cleanup)
- [TLS Certificate Authentication](#tls-certificate-authentication)
- [Configuration Reference](#configuration-reference)
- [Token Management](#token-management)

## Prerequisites

- Docker and Docker Compose installed and running
- A Honeycomb account with a management key (key ID + key secret) for dynamic key minting, **or** a static ingest/configuration key
- Team slug from your Honeycomb organization (visible in your Honeycomb URL)

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
warden write auth/jwt/role/honeycomb-user \
    token_policies="honeycomb-access" \
    user_claim=sub \
    cred_spec_name=honeycomb-ops
```

## Step 2: Mount and Configure the Provider

Enable the Honeycomb provider at a path of your choice:

```bash
warden provider enable --type=honeycomb
```

To mount at a custom path (e.g., for the EU region):

```bash
warden provider enable --type=honeycomb honeycomb-eu
```

Verify the provider is enabled:

```bash
warden provider list
```

Configure the provider:

```bash
warden write honeycomb/config <<EOF
{
  "honeycomb_url": "https://api.honeycomb.io",
  "auto_auth_path": "auth/jwt/",
  "timeout": "30s",
  "max_body_size": 10485760
}
EOF
```

For EU region:

```bash
warden write honeycomb-eu/config <<EOF
{
  "honeycomb_url": "https://api.eu1.honeycomb.io",
  "auto_auth_path": "auth/jwt/",
  "timeout": "30s"
}
EOF
```

Verify the configuration:

```bash
warden read honeycomb/config
```

## Step 3: Create a Credential Source and Spec

### Option A: Static API Key

Use this when you already have a Honeycomb ingest or configuration key and want Warden to proxy requests with it.

```bash
warden cred source create honeycomb-src \
  --type=apikey \
  --rotation-period=0 \
  --config=api_url=https://api.honeycomb.io \
  --config=display_name=Honeycomb
```

Create a credential spec with your API key:

```bash
warden cred spec create honeycomb-ops \
  --source honeycomb-src \
  --config api_key=your-honeycomb-api-key
```

### Option B: Dynamic API Keys (Honeycomb Source Driver)

Use this to have Warden dynamically create and revoke Honeycomb API keys using a management key. This is the recommended approach for production as it provides automatic key rotation and revocation.

**Prerequisites:**
- A Honeycomb management key (Settings > Team Settings > API Keys > Manage Management Keys)
- The team slug from your Honeycomb account
- An environment ID (visible in the URL when you select an environment)

Create a credential source backed by the Honeycomb API:

```bash
warden cred source create honeycomb-src \
  --type=honeycomb \
  --rotation-period=24h \
  --config=management_key_id=hcxmk_01abc123 \
  --config=management_key_secret=your-management-key-secret \
  --config=team_slug=my-team \
  --config=honeycomb_url=https://api.honeycomb.io
```

Create a credential spec that mints ingest keys:

```bash
warden cred spec create honeycomb-ops \
  --source honeycomb-src \
  --config environment_id=your-environment-id \
  --config key_type=ingest \
  --config key_name_prefix=warden- \
  --config key_ttl=24h
```

For configuration keys with specific permissions:

```bash
warden cred spec create honeycomb-config \
  --source honeycomb-src \
  --config environment_id=your-environment-id \
  --config key_type=configuration \
  --config key_name_prefix=warden- \
  --config key_ttl=24h \
  --config 'permissions={"send_events":true,"create_datasets":true,"run_queries":true}'
```

### Option C: Vault/OpenBao as Credential Source

Instead of storing the API key directly in Warden, you can store it in a Vault/OpenBao KV v2 secret engine and have Warden fetch it at runtime.

**Prerequisites:** A Vault/OpenBao instance with:
- A KV v2 mount containing your Honeycomb API key (e.g., at `secret/honeycomb/ops` with an `api_key` field)
- An AppRole configured for Warden access

```bash
# Create a Vault credential source
warden cred source create honeycomb-vault-src \
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
warden cred spec create honeycomb-ops \
  --source honeycomb-vault-src \
  --config mint_method=static_apikey \
  --config kv2_mount=secret \
  --config secret_path=honeycomb/ops
```

The KV v2 secret at `secret/honeycomb/ops` must contain an `api_key` field with your Honeycomb ingest or configuration key.

Verify:

```bash
warden cred spec read honeycomb-ops
```

## Step 4: Create a Policy

Create a policy that grants access to the Honeycomb provider gateway:

```bash
warden policy write honeycomb-access - <<EOF
path "honeycomb/role/+/gateway*" {
  capabilities = ["create", "read", "update", "delete", "patch"]
}
EOF
```

For read-only access (querying only):

```bash
warden policy write honeycomb-readonly - <<EOF
path "honeycomb/role/+/gateway/1/queries*" {
  capabilities = ["create", "read"]
}

path "honeycomb/role/+/gateway/1/boards*" {
  capabilities = ["read"]
}

path "honeycomb/role/+/gateway/1/slos*" {
  capabilities = ["read"]
}

path "honeycomb/role/+/gateway/1/auth" {
  capabilities = ["read"]
}
EOF
```

Verify:

```bash
warden policy read honeycomb-access
```

## Step 5: Get a JWT and Make Requests

Get a JWT from Hydra using one of the quickstart clients:

```bash
export JWT_TOKEN=$(curl -s -X POST http://localhost:4444/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=my-agent&client_secret=agent-secret&scope=api:read api:write" \
  | jq -r '.access_token')
```

Requests use role-based paths. Warden performs implicit JWT authentication and injects the Honeycomb credential automatically.

The URL pattern is: `/v1/honeycomb/role/{role}/gateway/{api-path}`

Export the base endpoint:

```bash
export HC_ENDPOINT="${WARDEN_ADDR}/v1/honeycomb/role/honeycomb-user/gateway"
```

### Verify Authentication

```bash
curl -s "${HC_ENDPOINT}/1/auth" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### Send an Event

```bash
curl -s -X POST "${HC_ENDPOINT}/1/events/my-dataset" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"message": "hello from warden", "duration_ms": 42}'
```

### Send a Batch of Events

```bash
curl -s -X POST "${HC_ENDPOINT}/1/batch/my-dataset" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '[{"data": {"message": "event 1"}}, {"data": {"message": "event 2"}}]'
```

### Query Data

```bash
curl -s -X POST "${HC_ENDPOINT}/1/queries/my-dataset" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "calculations": [{"op": "COUNT"}],
    "time_range": 3600
  }'
```

### List Boards

```bash
curl -s "${HC_ENDPOINT}/1/boards" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### List SLOs

```bash
curl -s "${HC_ENDPOINT}/1/slos" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### List Markers

```bash
curl -s "${HC_ENDPOINT}/1/markers/my-dataset" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### List Triggers

```bash
curl -s "${HC_ENDPOINT}/1/triggers" \
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

Steps 1-4 above use JWT authentication. Alternatively, you can authenticate with a TLS client certificate. This is useful for workloads that already have X.509 certificates — Kubernetes pods with cert-manager, VMs with machine certificates, or SPIFFE X.509-SVIDs from a service mesh.

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
    default_role=honeycomb-user
```

### Create a Cert Role

```bash
warden write auth/cert/role/honeycomb-user \
    allowed_common_names="agent-*" \
    token_policies="honeycomb-access" \
    cred_spec_name=honeycomb-ops
```

The `allowed_common_names` field supports glob patterns. You can also match on `allowed_dns_sans`, `allowed_email_sans`, `allowed_uri_sans`, or `allowed_organizational_units`.

### Configure Provider for Cert Auth

```bash
warden write honeycomb/config <<EOF
{
  "honeycomb_url": "https://api.honeycomb.io",
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
    -s "https://warden.internal/v1/honeycomb/role/honeycomb-user/gateway/1/auth"
```

## Configuration Reference

### Provider Config

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `honeycomb_url` | string | `https://api.honeycomb.io` | Honeycomb API base URL |
| `max_body_size` | int | 10485760 (10 MB) | Maximum request body size in bytes (max 100 MB) |
| `timeout` | duration | `30s` | Request timeout |
| `auto_auth_path` | string | -- | **Required.** Auth mount path for implicit authentication (e.g., `auth/jwt/`, `auth/cert/`) |
| `default_role` | string | -- | Fallback role when not specified in URL |

### Credential Source Config (Honeycomb Driver)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `management_key_id` | string | Yes | Management key ID (`hcxmk_` prefix) for API key operations |
| `management_key_secret` | string | Yes | Management key secret paired with the key ID |
| `team_slug` | string | Yes | Honeycomb team slug used in API paths |
| `honeycomb_url` | string | No | Honeycomb API base URL (default: `https://api.honeycomb.io`) |
| `ca_data` | string | No | Base64-encoded PEM CA certificate for custom/self-signed CAs |
| `tls_skip_verify` | bool | No | Skip TLS certificate verification (development only) |

### Credential Spec Config (Honeycomb Driver)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `environment_id` | string | -- | **Required.** Target Honeycomb environment ID |
| `key_type` | string | `ingest` | Type of key to mint: `ingest` or `configuration` |
| `key_name_prefix` | string | `warden-` | Prefix for generated key names |
| `key_ttl` | duration | `24h` | Warden lease TTL for the minted key |
| `permissions` | string (JSON) | -- | JSON permissions object (configuration keys only) |

### Credential Source Config (Static API Key)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `api_url` | string | No | Honeycomb API base URL (informational only) |
| `display_name` | string | No | Label for logs/errors (default: `API Key`) |

### Credential Spec Config (Static API Key)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `api_key` | string | Yes | Honeycomb ingest or configuration key (sensitive -- masked in output) |

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

### Credential Spec Config (Vault -- static_apikey)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mint_method` | string | Yes | Must be `static_apikey` |
| `kv2_mount` | string | Yes | KV v2 mount path in Vault |
| `secret_path` | string | Yes | Path to the secret within the mount |

## Token Management

### Static API Key

| Aspect | Details |
|--------|---------|
| **Storage** | Key is stored on the credential spec |
| **Rotation** | Manual -- generate a new key in Honeycomb and update the spec |
| **Lifetime** | Does not expire unless deleted in Honeycomb |

### Dynamic API Keys (Honeycomb Source Driver)

| Aspect | Details |
|--------|---------|
| **Storage** | Key secret is captured at creation and managed by Warden |
| **Rotation** | Automatic -- Warden creates a new key and deletes the old one on the configured rotation period |
| **Lifetime** | Controlled by `key_ttl` in the spec config; keys are revoked (deleted) when the lease expires |
| **Revocation** | On lease expiry or manual revocation, Warden calls `DELETE /2/teams/{team}/api-keys/{id}` |

**To rotate static credentials:**

1. Generate a new API key in Honeycomb (Settings > Team Settings > API Keys)
2. Update the credential spec:
   ```bash
   warden cred spec update honeycomb-ops \
     --config api_key=your-new-api-key
   ```
3. Delete the old key in Honeycomb

**To rotate the management key (source driver):**

1. Create a new management key in Honeycomb
2. Update the credential source:
   ```bash
   warden cred source update honeycomb-src \
     --config management_key_id=new-key-id \
     --config management_key_secret=new-key-secret
   ```
3. Delete the old management key in Honeycomb
