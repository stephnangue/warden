# Anthropic Provider

The Anthropic provider enables proxied access to the Anthropic API through Warden. It streams requests to Anthropic endpoints (messages, models) with automatic API key injection and policy evaluation on AI request fields.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Step 1: Configure JWT Auth and Create a Role](#step-1-configure-jwt-auth-and-create-a-role)
- [Step 2: Mount and Configure the Provider](#step-2-mount-and-configure-the-provider)
- [Step 3: Create a Credential Source and Spec](#step-3-create-a-credential-source-and-spec)
- [Step 4: Create a Policy](#step-4-create-a-policy)
- [Step 5: Get a JWT and Make Requests](#step-5-get-a-jwt-and-make-requests)
- [Policy Evaluation on AI Requests](#policy-evaluation-on-ai-requests)
- [Configuration Reference](#configuration-reference)
- [Key Management](#key-management)

## Prerequisites

- Docker and Docker Compose installed and running
- An **Anthropic API key** from [console.anthropic.com](https://console.anthropic.com)

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
warden write auth/jwt/role/anthropic-user \
    token_policies="anthropic-access" \
    cred_spec_name=anthropic-ops
```

## Step 2: Mount and Configure the Provider

Enable the Anthropic provider at a path of your choice:

```bash
warden provider enable --type=anthropic
```

To mount at a custom path:

```bash
warden provider enable --type=anthropic anthropic-prod
```

Verify the provider is enabled:

```bash
warden provider list
```

Configure the provider with `auto_auth_path`. This allows clients to authenticate with their JWT directly — no explicit Warden login required:

```bash
warden write anthropic/config <<EOF
{
  "anthropic_url": "https://api.anthropic.com",
  "auto_auth_path": "auth/jwt/",
  "timeout": "120s",
  "max_body_size": 10485760
}
EOF
```

Verify the configuration:

```bash
warden read anthropic/config
```

## Step 3: Create a Credential Source and Spec

The credential source holds only connection info (`api_url`). The API key is stored on the credential spec below, allowing multiple specs with different keys to share one source.

```bash
warden cred source create anthropic-src \
  --type=apikey \
  --rotation-period=0 \
  --config=api_url=https://api.anthropic.com \
  --config=verify_endpoint=/v1/models \
  --config=auth_header_type=custom_header \
  --config=auth_header_name=x-api-key \
  --config=extra_headers=anthropic-version:2023-06-01 \
  --config=optional_metadata=organization_id \
  --config=display_name=Anthropic
```

Verify the source was created:

```bash
warden cred source read anthropic-src
```

Create a credential spec that references the credential source. The spec carries the API key and gets associated with tokens at login time.

```bash
warden cred spec create anthropic-ops \
  --source anthropic-src \
  --config api_key=<your-anthropic-api-key>
```

The API key is validated at creation time via a `GET /v1/models` call to the Anthropic API (SpecVerifier). If the key is invalid, spec creation will fail.

Verify:

```bash
warden cred spec read anthropic-ops
```

### Alternative: Vault/OpenBao as Credential Source

Instead of storing the API key directly in Warden, you can store it in a Vault/OpenBao KV v2 secret engine and have Warden fetch it at runtime. This centralizes secret management in Vault.

**Prerequisites:** A Vault/OpenBao instance with:
- A KV v2 mount containing your Anthropic API key (e.g., at `secret/anthropic/ops` with an `api_key` field)
- An AppRole configured for Warden access

```bash
# Create a Vault credential source
warden cred source create anthropic-vault-src \
  --type=hvault \
  --config=vault_address=https://vault.example.com \
  --config=auth_method=approle \
  --config=role_id=your-role-id \
  --config=secret_id=your-secret-id \
  --config=approle_mount=approle \
  --config=role_name=warden-role \
  --rotation-period=24h

# Create a credential spec using the static_apikey mint method
warden cred spec create anthropic-ops \
  --source anthropic-vault-src \
  --config mint_method=static_apikey \
  --config kv2_mount=secret \
  --config secret_path=anthropic/ops
```

The KV v2 secret at `secret/anthropic/ops` should contain at minimum an `api_key` field. Warden fetches the secret from Vault on each credential request.

## Step 4: Create a Policy

Create a policy that grants access to the Anthropic provider gateway:

```bash
warden policy write anthropic-access - <<EOF
path "anthropic/role/+/gateway*" {
  capabilities = ["create", "read", "update", "delete", "patch"]
}
EOF
```

For fine-grained cost control, restrict access based on AI request fields:

```bash
warden policy write anthropic-restricted - <<EOF
path "anthropic/role/+/gateway/v1/messages" {
  capabilities = ["create"]
  allowed_parameters = {
    "model" = ["claude-sonnet-4-20250514", "claude-haiku-4-20250414"]
    "stream" = ["true"]
    "*"      = []
  }
}
EOF
```

You can also combine parameter restrictions with runtime conditions to protect costly inference endpoints. For example, restrict messages to specific models and trusted networks during business hours:

```bash
warden policy write anthropic-prod-restricted - <<EOF
path "anthropic/role/+/gateway/v1/messages" {
  capabilities = ["create"]
  allowed_parameters = {
    "model" = ["claude-sonnet-4-20250514", "claude-haiku-4-20250414"]
    "stream" = ["true"]
    "*"      = []
  }
  conditions {
    source_ip   = ["10.0.0.0/8"]
    time_window = ["08:00-18:00 UTC"]
    day_of_week = ["Mon", "Tue", "Wed", "Thu", "Fri"]
  }
}

path "anthropic/role/+/gateway/v1/models" {
  capabilities = ["read"]
}
EOF
```

Condition types are AND-ed (all must be satisfied), values within each type are OR-ed (at least one must match). Supported types: `source_ip` (CIDR or bare IP), `time_window` (`HH:MM-HH:MM TZ`, supports midnight-spanning), `day_of_week` (3-letter abbreviations).

Verify:

```bash
warden policy read anthropic-access
```

## Step 5: Get a JWT and Make Requests

Get a JWT from Hydra using one of the quickstart clients:

```bash
export JWT_TOKEN=$(curl -s -X POST http://localhost:4444/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=my-agent&client_secret=agent-secret&scope=api:read api:write" \
  | jq -r '.access_token')
```

Requests use role-based paths. Warden performs implicit JWT authentication and injects the Anthropic API key (via `x-api-key` header) and `anthropic-version` header automatically.

The URL pattern is: `/v1/anthropic/role/{role}/gateway/{anthropic-api-path}`

Export ANTHROPIC_ENDPOINT as environment variable:
```bash
export ANTHROPIC_ENDPOINT="${WARDEN_ADDR}/v1/anthropic/role/anthropic-user/gateway"
```

### Messages

```bash
curl -X POST "${ANTHROPIC_ENDPOINT}/v1/messages" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "claude-sonnet-4-20250514",
    "max_tokens": 1024,
    "messages": [
      {"role": "user", "content": "Hello, how are you?"}
    ]
  }'
```

### Streaming Messages

```bash
curl -X POST "${ANTHROPIC_ENDPOINT}/v1/messages" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -N \
  -d '{
    "model": "claude-sonnet-4-20250514",
    "max_tokens": 1024,
    "messages": [
      {"role": "user", "content": "Write a short poem about the ocean."}
    ],
    "stream": true
  }'
```

### Using the Anthropic SDK

The Anthropic SDK uses the `x-api-key` header by default. Warden's Anthropic provider accepts this header as a Warden token, so the SDK works with minimal configuration:

```python
import anthropic

client = anthropic.Anthropic(
    api_key="<your-warden-jwt-or-token>",
    base_url="http://127.0.0.1:8400/v1/anthropic/role/anthropic-user/gateway",
)

message = client.messages.create(
    model="claude-sonnet-4-20250514",
    max_tokens=1024,
    messages=[
        {"role": "user", "content": "Hello, Claude!"}
    ],
)
print(message.content[0].text)
```

### Using Claude Code

[Claude Code](https://docs.anthropic.com/en/docs/claude-code) uses the `x-api-key` header natively. Set `ANTHROPIC_BASE_URL` to route all Claude Code traffic through Warden:

```bash
export ANTHROPIC_BASE_URL="http://127.0.0.1:8400/v1/anthropic/role/anthropic-user/gateway"
export ANTHROPIC_API_KEY="<your-warden-jwt-or-token>"

claude
```

Or persist it in your Claude Code settings (`~/.claude/settings.json`):

```json
{
  "env": {
    "ANTHROPIC_BASE_URL": "http://127.0.0.1:8400/v1/anthropic/role/anthropic-user/gateway"
  }
}
```

For TLS-enabled Warden deployments with certificate authentication:

```bash
export ANTHROPIC_BASE_URL="https://warden.internal/v1/anthropic/role/anthropic-user/gateway"
export NODE_EXTRA_CA_CERTS="/path/to/warden-ca.pem"
export CLAUDE_CODE_CLIENT_CERT="/path/to/client.pem"
export CLAUDE_CODE_CLIENT_KEY="/path/to/client-key.pem"

claude
```

For dynamic token refresh (e.g., short-lived JWTs), use an API key helper script:

```json
{
  "env": {
    "ANTHROPIC_BASE_URL": "http://127.0.0.1:8400/v1/anthropic/role/anthropic-user/gateway"
  },
  "apiKeyHelper": "~/bin/get-warden-jwt.sh"
}
```

Where `get-warden-jwt.sh` fetches a fresh JWT from your identity provider.

### Using Claude Desktop

Set environment variables before launching Claude Desktop to route traffic through Warden:

```bash
export ANTHROPIC_BASE_URL="http://127.0.0.1:8400/v1/anthropic/role/anthropic-user/gateway"
export ANTHROPIC_API_KEY="<your-warden-jwt-or-token>"

open -a "Claude"
```

### List Models

```bash
curl "${ANTHROPIC_ENDPOINT}/v1/models" \
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

## Policy Evaluation on AI Requests

The Anthropic provider has request body parsing enabled (`ParseStreamBody: true`), which means Warden can evaluate policies against fields in the AI request body. This enables fine-grained cost control and usage policies.

Evaluable fields include:

| Field | Type | Description |
|-------|------|-------------|
| `model` | string | Model to use (e.g., `claude-sonnet-4-20250514`, `claude-haiku-4-20250414`, `claude-opus-4-20250514`) |
| `max_tokens` | integer | Maximum tokens to generate (required by Anthropic API) |
| `temperature` | float | Sampling temperature |
| `stream` | boolean | Whether to stream the response |
| `top_p` | float | Nucleus sampling parameter |
| `top_k` | integer | Top-k sampling parameter |

This allows operators to enforce policies such as:
- Restrict which models users can access
- Enforce maximum token limits
- Require streaming mode for cost visibility

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
    default_role=anthropic-user
```

### Create a Cert Role

Create a role that binds allowed certificate identities to a credential spec and policy:

```bash
warden write auth/cert/role/anthropic-user \
    allowed_common_names="agent-*" \
    token_policies="anthropic-access" \
    cred_spec_name=anthropic-ops
```

The `allowed_common_names` field supports glob patterns. You can also match on other certificate fields: `allowed_dns_sans`, `allowed_email_sans`, `allowed_uri_sans`, or `allowed_organizational_units`.

### Configure Provider for Cert Auth

Update the provider config to use cert auth:

```bash
warden write anthropic/config <<EOF
{
  "anthropic_url": "https://api.anthropic.com",
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
    -X POST "https://warden.internal/v1/anthropic/role/anthropic-user/gateway/v1/messages" \
    -H "Content-Type: application/json" \
    -d '{
      "model": "claude-sonnet-4-20250514",
      "max_tokens": 1024,
      "messages": [{"role": "user", "content": "Hello"}]
    }'
```

## Configuration Reference

### Provider Config

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `anthropic_url` | string | `https://api.anthropic.com` | Anthropic API base URL (must be HTTPS) |
| `max_body_size` | int | 10485760 (10 MB) | Maximum request body size in bytes (max 100 MB) |
| `timeout` | duration | `120s` | Request timeout — set high for AI inference |
| `tls_skip_verify` | bool | `false` | Skip TLS certificate verification; also allows `http://` URLs (development only) |
| `ca_data` | string | — | Base64-encoded PEM CA certificate for custom/self-signed CAs |
| `auto_auth_path` | string | — | **Required.** Auth mount path for implicit authentication (e.g., `auth/jwt/`, `auth/cert/`) |
| `default_role` | string | — | Fallback role when not specified in URL |

### Credential Source Config

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `api_url` | string | No | API base URL (default: `https://api.anthropic.com`) |
| `verify_endpoint` | string | No | Verification path (e.g., `/v1/models`) |
| `auth_header_type` | string | No | Auth method: `bearer`, `token`, `custom_header` (default: `bearer`) |
| `auth_header_name` | string | No | Header name when `auth_header_type=custom_header` (e.g., `x-api-key`) |
| `extra_headers` | string | No | Additional static headers as `key:value` pairs (e.g., `anthropic-version:2023-06-01`) |
| `optional_metadata` | string | No | Comma-separated spec fields to copy into credential data |
| `display_name` | string | No | Label for logs/errors (default: `API Key`) |

### Credential Spec Config

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `api_key` | string | Yes | Anthropic API key (sensitive — masked in output) |
| `organization_id` | string | No | Organization identifier |

### Credential Spec Config (Vault — static_apikey)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mint_method` | string | Yes | Must be `static_apikey` |
| `kv2_mount` | string | Yes | KV v2 mount path in Vault |
| `secret_path` | string | Yes | Path to the secret within the mount |

## Key Management

| Aspect | Details |
|--------|---------|
| **Storage** | API key is stored on the credential spec (not the source) |
| **Validation** | Key is verified at spec creation via `GET /v1/models` |
| **Rotation** | Manual — Anthropic does not expose key management APIs |
| **Lifetime** | Static — no expiration or auto-refresh |

**To rotate an API key:**

1. Create a new API key in the [Anthropic console](https://console.anthropic.com)
2. Update the credential spec:
   ```bash
   warden cred spec update anthropic-ops \
     --config api_key=<new-api-key>
   ```
3. Delete the old key from the Anthropic console
