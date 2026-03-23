# OpenAI Provider

The OpenAI provider enables proxied access to the OpenAI API through Warden. It streams requests to OpenAI endpoints (chat completions, responses, embeddings, images, models) with automatic API key injection and policy evaluation on AI request fields.

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
- An **OpenAI API key** from [platform.openai.com](https://platform.openai.com)

> **New to Warden?** Follow these steps to get a local dev environment running:
>
> **1. Deploy the quickstart stack** — this starts an identity provider ([Ory Hydra](https://www.ory.sh/hydra/)) needed to issue JWTs for authentication in Steps 1 and 5:
> ```bash
> curl -fsSL -o docker-compose.quickstart.yml \
>   https://raw.githubusercontent.com/stephnangue/warden/main/docker-compose.quickstart.yml
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

Set up a JWT auth method and create a role that binds the credential spec and policy. With transparent mode, clients authenticate directly with their JWT — no separate login step is needed.

> **This step must come before configuring the provider.** Warden validates at configuration time that the auth backend referenced by `auto_auth_path` is already mounted.

```bash
# Enable JWT auth if not already enabled
warden auth enable --type=jwt

# Configure JWT with Hydra's JWKS endpoint (from docker-compose.quickstart.yml)
warden write auth/jwt/config mode=jwt jwks_url=http://localhost:4444/.well-known/jwks.json

# Create a role that binds the credential spec and policy
warden write auth/jwt/role/openai-user \
    token_policies="openai-access" \
    user_claim=sub \
    cred_spec_name=openai-ops \
    token_ttl=1h
```

## Step 2: Mount and Configure the Provider

Enable the OpenAI provider at a path of your choice:

```bash
warden provider enable --type=openai
```

To mount at a custom path:

```bash
warden provider enable --type=openai openai-prod
```

Verify the provider is enabled:

```bash
warden provider list
```

Configure the provider with transparent mode enabled. This allows clients to authenticate with their JWT directly — no explicit Warden login required:

```bash
warden write openai/config <<EOF
{
  "openai_url": "https://api.openai.com",
  "transparent_mode": true,
  "auto_auth_path": "auth/jwt/",
  "timeout": "120s",
  "max_body_size": 10485760
}
EOF
```

Verify the configuration:

```bash
warden read openai/config
```

## Step 3: Create a Credential Source and Spec

The credential source holds only connection info (`api_url`). The API key is stored on the credential spec below, allowing multiple specs with different keys to share one source.

```bash
warden cred source create openai-src \
  --type=openai \
  --rotation-period=0 \
  --config=api_url=https://api.openai.com
```

Verify the source was created:

```bash
warden cred source read openai-src
```

Create a credential spec that references the credential source. The spec carries the API key and gets associated with tokens at login time.

```bash
warden cred spec create openai-ops \
  --type ai_api_key \
  --source openai-src \
  --config api_key=<your-openai-api-key>
```

Optionally include an organization ID and/or project ID:

```bash
warden cred spec create openai-ops \
  --type ai_api_key \
  --source openai-src \
  --config api_key=<your-openai-api-key> \
  --config organization_id=<your-org-id> \
  --config project_id=<your-project-id>
```

The API key is validated at creation time via a `GET /v1/models` call to the OpenAI API (SpecVerifier). If the key is invalid, spec creation will fail.

Verify:

```bash
warden cred spec read openai-ops
```

## Step 4: Create a Policy

Create a policy that grants access to the OpenAI provider gateway:

```bash
warden policy write openai-access - <<EOF
path "openai/role/+/gateway*" {
  capabilities = ["create", "read", "update", "delete", "patch"]
}
EOF
```

For fine-grained cost control, restrict access based on AI request fields:

```bash
warden policy write openai-restricted - <<EOF
path "openai/role/+/gateway/v1/chat/completions" {
  capabilities = ["create"]
  allowed_parameters = {
    "model" = ["gpt-4o", "gpt-4o-mini"]
    "stream" = ["true"]
    "*"      = []
  }
}
EOF
```

You can also combine parameter restrictions with runtime conditions to protect costly inference endpoints. For example, restrict chat completions to specific models and trusted networks during business hours:

```bash
warden policy write openai-prod-restricted - <<EOF
path "openai/role/+/gateway/v1/chat/completions" {
  capabilities = ["create"]
  allowed_parameters = {
    "model" = ["gpt-4o", "gpt-4o-mini"]
    "stream" = ["true"]
    "*"      = []
  }
  conditions {
    source_ip   = ["10.0.0.0/8"]
    time_window = ["08:00-18:00 UTC"]
    day_of_week = ["Mon", "Tue", "Wed", "Thu", "Fri"]
  }
}

path "openai/role/+/gateway/v1/models" {
  capabilities = ["read"]
}
EOF
```

Condition types are AND-ed (all must be satisfied), values within each type are OR-ed (at least one must match). Supported types: `source_ip` (CIDR or bare IP), `time_window` (`HH:MM-HH:MM TZ`, supports midnight-spanning), `day_of_week` (3-letter abbreviations).

Verify:

```bash
warden policy read openai-access
```

## Step 5: Get a JWT and Make Requests

Get a JWT from Hydra using one of the quickstart clients:

```bash
export JWT_TOKEN=$(curl -s -X POST http://localhost:4444/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=my-agent&client_secret=agent-secret&scope=api:read api:write" \
  | jq -r '.access_token')
```

With transparent mode, requests use role-based paths. Warden performs implicit JWT authentication and injects the OpenAI API key automatically.

The URL pattern is: `/v1/openai/role/{role}/gateway/{openai-api-path}`

Export OPENAI_ENDPOINT as environment variable:
```bash
export OPENAI_ENDPOINT="${WARDEN_ADDR}/v1/openai/role/openai-user/gateway"
```

### Chat Completions

```bash
curl -X POST "${OPENAI_ENDPOINT}/v1/chat/completions" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4o",
    "messages": [
      {"role": "user", "content": "Hello, how are you?"}
    ]
  }'
```

### Streaming Chat Completions

```bash
curl -X POST "${OPENAI_ENDPOINT}/v1/chat/completions" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -N \
  -d '{
    "model": "gpt-4o",
    "messages": [
      {"role": "user", "content": "Write a short poem about the ocean."}
    ],
    "stream": true
  }'
```

### Responses API

```bash
curl -X POST "${OPENAI_ENDPOINT}/v1/responses" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4o",
    "input": "Tell me a joke."
  }'
```

### Embeddings

```bash
curl -X POST "${OPENAI_ENDPOINT}/v1/embeddings" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "text-embedding-3-small",
    "input": ["Hello world"]
  }'
```

### List Models

```bash
curl "${OPENAI_ENDPOINT}/v1/models" \
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

The OpenAI provider has request body parsing enabled (`ParseStreamBody: true`), which means Warden can evaluate policies against fields in the AI request body. This enables fine-grained cost control and usage policies.

Evaluable fields include:

| Field | Type | Description |
|-------|------|-------------|
| `model` | string | Model to use (e.g., `gpt-4o`, `gpt-4o-mini`, `o3-mini`) |
| `max_tokens` | integer | Maximum tokens to generate |
| `max_completion_tokens` | integer | Maximum completion tokens (newer API parameter) |
| `temperature` | float | Sampling temperature |
| `stream` | boolean | Whether to stream the response |
| `top_p` | float | Nucleus sampling parameter |

This allows operators to enforce policies such as:
- Restrict which models users can access
- Enforce maximum token limits
- Require streaming mode for cost visibility

## TLS Certificate Authentication

Steps 4–5 above use JWT authentication. Alternatively, you can authenticate with a TLS client certificate. This is useful for workloads that already have X.509 certificates — Kubernetes pods with cert-manager, VMs with machine certificates, or SPIFFE X.509-SVIDs from a service mesh.

> **Prerequisite:** Certificate authentication requires TLS to be enabled on the Warden listener so that client certificates can be presented during the TLS handshake (mTLS). In dev mode, use `--dev-tls` to enable TLS with auto-generated certificates, or provide your own with `--dev-tls-cert-file`, `--dev-tls-key-file`, and `--dev-tls-ca-cert-file`. Alternatively, place Warden behind a load balancer that terminates TLS and forwards the client certificate via the `X-Forwarded-Client-Cert` or `X-SSL-Client-Cert` header.

Steps 1–3 (provider setup) are identical. Replace Steps 4–5 with the following.

### Enable Cert Auth

```bash
warden auth enable --type=cert
```

### Configure Trusted CA

Provide the PEM-encoded CA certificate that signs your client certificates:

```bash
warden write auth/cert/config \
    trusted_ca_pem=@/path/to/ca.pem \
    default_role=openai-user
```

### Create a Cert Role

Create a role that binds allowed certificate identities to a credential spec and policy:

```bash
warden write auth/cert/role/openai-user \
    allowed_common_names="agent-*" \
    token_policies="openai-access" \
    cred_spec_name=openai-ops \
    token_ttl=1h
```

The `allowed_common_names` field supports glob patterns. You can also match on other certificate fields: `allowed_dns_sans`, `allowed_email_sans`, `allowed_uri_sans`, or `allowed_organizational_units`.

### Configure Provider for Cert Auth

Update the provider config to use cert auth for transparent mode:

```bash
warden write openai/config <<EOF
{
  "openai_url": "https://api.openai.com",
  "transparent_mode": true,
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
    -X POST "https://warden.internal/v1/openai/role/openai-user/gateway/v1/chat/completions" \
    -H "Content-Type: application/json" \
    -d '{
      "model": "gpt-4o",
      "messages": [{"role": "user", "content": "Hello"}]
    }'
```

### Explicit Login with Certificates

To use cert auth for explicit login (without transparent mode):

```bash
warden write auth/cert/config \
    trusted_ca_pem=@/path/to/ca.pem \
    token_type=warden \
    default_role=openai-user

warden write auth/cert/role/openai-user \
    allowed_common_names="agent-*" \
    token_type=warden \
    token_policies="openai-access" \
    cred_spec_name=openai-ops \
    token_ttl=1h
```

Then authenticate with the CLI:

```bash
warden login --method=cert --role=openai-user \
    --cert=./client.pem --key=./client-key.pem
```

## Configuration Reference

### Provider Config

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `openai_url` | string | `https://api.openai.com` | OpenAI API base URL (must be HTTPS) |
| `max_body_size` | int | 10485760 (10 MB) | Maximum request body size in bytes (max 100 MB) |
| `timeout` | duration | `120s` | Request timeout — set high for AI inference |
| `transparent_mode` | bool | `false` | Enable implicit authentication (JWT or TLS certificate) |
| `auto_auth_path` | string | — | JWT auth mount path (required when `transparent_mode` is true) |
| `default_role` | string | — | Fallback role when not specified in URL |

### Credential Source Config

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `api_url` | string | `https://api.openai.com` | OpenAI API base URL (must be HTTPS) |

### Credential Spec Config

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `api_key` | string | Yes | OpenAI API key (sensitive — masked in output) |
| `organization_id` | string | No | Organization identifier (injected as `OpenAI-Organization` header) |
| `project_id` | string | No | Project identifier (injected as `OpenAI-Project` header) |

## Key Management

| Aspect | Details |
|--------|---------|
| **Storage** | API key is stored on the credential spec (not the source) |
| **Validation** | Key is verified at spec creation via `GET /v1/models` |
| **Rotation** | Manual — OpenAI does not expose key management APIs |
| **Lifetime** | Static — no expiration or auto-refresh |

**To rotate an API key:**

1. Create a new API key in the [OpenAI dashboard](https://platform.openai.com/api-keys)
2. Update the credential spec:
   ```bash
   warden cred spec update openai-ops \
     --config api_key=<new-api-key>
   ```
3. Delete the old key from the OpenAI dashboard
