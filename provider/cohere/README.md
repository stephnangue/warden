# Cohere Provider

The Cohere provider enables proxied access to the Cohere API through Warden. It forwards requests to Cohere endpoints (Chat, Embed, Rerank, Generate, Models, etc.) with automatic credential injection and policy evaluation. Credentials are injected via the `Authorization: Bearer` header. One credential mode is supported: static API keys (`apikey` source type). Vault/OpenBao can also be used as a credential source (`hvault` source type).

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
- A **Cohere API Key** (from [dashboard.cohere.com/api-keys](https://dashboard.cohere.com/api-keys))

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
warden write auth/jwt/role/cohere-user \
    token_policies="cohere-access" \
    user_claim=sub \
    cred_spec_name=cohere-prod
```

## Step 2: Mount and Configure the Provider

Enable the Cohere provider at a path of your choice:

```bash
warden provider enable --type=cohere
```

To mount at a custom path:

```bash
warden provider enable --type=cohere cohere-prod
```

Verify the provider is enabled:

```bash
warden provider list
```

Configure the provider with `auto_auth_path`. This allows clients to authenticate with their JWT directly — no explicit Warden login required:

```bash
warden write cohere/config <<EOF
{
  "cohere_url": "https://api.cohere.com",
  "auto_auth_path": "auth/jwt/",
  "timeout": "120s",
  "max_body_size": 10485760
}
EOF
```

Verify the configuration:

```bash
warden read cohere/config
```

## Step 3: Create a Credential Source and Spec

### Option A: Static API Keys

The credential source holds only connection info (`api_url`). The API key is stored on the credential spec below, allowing multiple specs with different keys to share one source.

```bash
warden cred source create cohere-src \
  --type=apikey \
  --rotation-period=0 \
  --config=api_url=https://api.cohere.com \
  --config=verify_endpoint=/v1/check-api-key \
  --config=verify_method=POST \
  --config=auth_header_type=bearer \
  --config=display_name=Cohere
```

Create a credential spec that references the credential source. The spec carries the API key and gets associated with tokens at login time.

```bash
warden cred spec create cohere-prod \
  --source cohere-src \
  --config api_key=your-cohere-api-key
```

The API key is validated at creation time via a `POST /v1/check-api-key` call to the Cohere API (SpecVerifier). If the key is invalid, spec creation will fail.

### Option B: Vault/OpenBao as Credential Source

Instead of storing API keys directly in Warden, you can store them in a Vault/OpenBao KV v2 secret engine and have Warden fetch them at runtime. This centralizes secret management in Vault.

**Prerequisites:** A Vault/OpenBao instance with:
- A KV v2 mount containing your Cohere key (e.g., at `secret/cohere/prod` with an `api_key` field)
- An AppRole configured for Warden access

```bash
# Create a Vault credential source
warden cred source create cohere-vault-src \
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
warden cred spec create cohere-prod \
  --source cohere-vault-src \
  --config mint_method=static_apikey \
  --config kv2_mount=secret \
  --config secret_path=cohere/prod
```

The KV v2 secret at `secret/cohere/prod` should contain an `api_key` field. Warden fetches the secret from Vault on each credential request.

Verify:

```bash
warden cred spec read cohere-prod
```

## Step 4: Create a Policy

Create a policy that grants access to the Cohere provider gateway:

```bash
warden policy write cohere-access - <<EOF
path "cohere/role/+/gateway*" {
  capabilities = ["create", "read", "update", "delete", "patch"]
}
EOF
```

For fine-grained access control, restrict which Cohere endpoints a role can use:

```bash
warden policy write cohere-readonly - <<EOF
path "cohere/role/+/gateway/v1/models" {
  capabilities = ["read"]
}

path "cohere/role/+/gateway/v2/chat" {
  capabilities = ["create"]
}

path "cohere/role/+/gateway/v2/embed" {
  capabilities = ["create"]
}

path "cohere/role/+/gateway/v2/rerank" {
  capabilities = ["create"]
}
EOF
```

For request-body policies (e.g., restrict to specific models or limit token usage):

```bash
warden policy write cohere-restricted - <<EOF
path "cohere/role/+/gateway/v2/chat" {
  capabilities = ["create"]
  required_parameters = {
    "model" = ["command-a-03-2025", "command-r-plus-08-2024", "command-r-08-2024"]
  }
  max_parameters = {
    "max_tokens" = 4096
  }
}

path "cohere/role/+/gateway/v2/embed" {
  capabilities = ["create"]
  required_parameters = {
    "model" = ["embed-v4.0", "embed-english-v3.0", "embed-multilingual-v3.0"]
  }
}
EOF
```

Verify:

```bash
warden policy read cohere-access
```

## Step 5: Get a JWT and Make Requests

Get a JWT from Hydra using one of the quickstart clients:

```bash
export JWT_TOKEN=$(curl -s -X POST http://localhost:4444/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=my-agent&client_secret=agent-secret&scope=api:read api:write" \
  | jq -r '.access_token')
```

Requests use role-based paths. Warden performs implicit JWT authentication and injects the Cohere API key automatically.

The URL pattern is: `/v1/cohere/role/{role}/gateway/{api-path}`

Export COHERE_ENDPOINT as environment variable:
```bash
export COHERE_ENDPOINT="${WARDEN_ADDR}/v1/cohere/role/cohere-user/gateway"
```

### Check API Key

```bash
curl -s -X POST "${COHERE_ENDPOINT}/v1/check-api-key" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### List Models

```bash
curl -s "${COHERE_ENDPOINT}/v1/models" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### Chat (v2)

```bash
curl -s -X POST "${COHERE_ENDPOINT}/v2/chat" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "command-a-03-2025",
    "messages": [
      {
        "role": "user",
        "content": "Explain quantum computing in one paragraph."
      }
    ]
  }'
```

### Streaming Chat

```bash
curl -s -N -X POST "${COHERE_ENDPOINT}/v2/chat" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "command-a-03-2025",
    "messages": [
      {
        "role": "user",
        "content": "Write a short poem about the ocean."
      }
    ],
    "stream": true
  }'
```

### Embed

```bash
curl -s -X POST "${COHERE_ENDPOINT}/v2/embed" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "embed-v4.0",
    "texts": [
      "Hello world",
      "How are you?"
    ],
    "input_type": "search_document",
    "embedding_types": ["float"]
  }'
```

### Rerank

```bash
curl -s -X POST "${COHERE_ENDPOINT}/v2/rerank" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "rerank-v3.5",
    "query": "What is the capital of France?",
    "documents": [
      "Paris is the capital of France.",
      "Berlin is the capital of Germany.",
      "Madrid is the capital of Spain."
    ],
    "top_n": 2
  }'
```

### Tokenize

```bash
curl -s -X POST "${COHERE_ENDPOINT}/v1/tokenize" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "text": "Hello, how are you?",
    "model": "command-a-03-2025"
  }'
```

### Detokenize

```bash
curl -s -X POST "${COHERE_ENDPOINT}/v1/detokenize" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "tokens": [33555, 1114, 34],
    "model": "command-a-03-2025"
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
    default_role=cohere-user
```

### Create a Cert Role

Create a role that binds allowed certificate identities to a credential spec and policy:

```bash
warden write auth/cert/role/cohere-user \
    allowed_common_names="agent-*" \
    token_policies="cohere-access" \
    cred_spec_name=cohere-prod
```

The `allowed_common_names` field supports glob patterns. You can also match on other certificate fields: `allowed_dns_sans`, `allowed_email_sans`, `allowed_uri_sans`, or `allowed_organizational_units`.

### Configure Provider for Cert Auth

Update the provider config to use cert auth:

```bash
warden write cohere/config <<EOF
{
  "cohere_url": "https://api.cohere.com",
  "auto_auth_path": "auth/cert/",
  "timeout": "120s",
  "max_body_size": 10485760
}
EOF
```

### Make Requests with Certificates

```bash
curl --cert client.pem --key client-key.pem \
    --cacert warden-ca.pem \
    -s "https://warden.internal/v1/cohere/role/cohere-user/gateway/v1/models" \
    -H "Content-Type: application/json"
```

## Configuration Reference

### Provider Config

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `cohere_url` | string | `https://api.cohere.com` | Cohere API base URL |
| `max_body_size` | int | 10485760 (10 MB) | Maximum request body size in bytes (max 100 MB) |
| `timeout` | duration | `120s` | Request timeout |
| `tls_skip_verify` | bool | `false` | Skip TLS certificate verification; also allows `http://` URLs (development only) |
| `ca_data` | string | — | Base64-encoded PEM CA certificate for custom/self-signed CAs |
| `auto_auth_path` | string | — | **Required.** Auth mount path for implicit authentication (e.g., `auth/jwt/`, `auth/cert/`) |
| `default_role` | string | — | Fallback role when not specified in URL |

### Credential Source Config (Static API Keys)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `api_url` | string | No | API base URL (default: `https://api.cohere.com`) |
| `verify_endpoint` | string | No | Verification path (e.g., `/v1/check-api-key`) |
| `verify_method` | string | No | HTTP method for verification: `POST` (recommended for Cohere) |
| `auth_header_type` | string | No | How to attach key for verification: `bearer` |
| `display_name` | string | No | Label for logs/errors (default: `API Key`) |

### Credential Spec Config (Static API Keys)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `api_key` | string | Yes | Cohere API key (sensitive — masked in output) |

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
| **Storage** | API key is stored on the credential spec (not the source) |
| **Validation** | API key is verified at spec creation via `POST /v1/check-api-key` |
| **Rotation** | Manual — regenerate in Cohere dashboard and update the spec |
| **Lifetime** | Static — no expiration or auto-refresh |

**To rotate Cohere API keys:**

1. Generate a new API key in the Cohere dashboard ([dashboard.cohere.com/api-keys](https://dashboard.cohere.com/api-keys))
2. Update the credential spec:
   ```bash
   warden cred spec update cohere-prod \
     --config api_key=your-new-api-key
   ```
3. Delete the old key in the Cohere dashboard
