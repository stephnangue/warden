# OpenAI Provider

The OpenAI provider enables proxied access to the OpenAI API through Warden. It streams requests to OpenAI endpoints (chat completions, responses, embeddings, images, models) with automatic API key injection and policy evaluation on AI request fields.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Step 1: Mount the OpenAI Provider](#step-1-mount-the-openai-provider)
- [Step 2: Configure the Provider](#step-2-configure-the-provider)
- [Step 3: Create a Credential Source](#step-3-create-a-credential-source)
- [Step 4: Create a Credential Spec](#step-4-create-a-credential-spec)
- [Step 5: Create a Policy](#step-5-create-a-policy)
- [Step 6: Configure JWT Auth and Create a Role](#step-6-configure-jwt-auth-and-create-a-role)
- [Step 7: Get a JWT](#step-7-get-a-jwt)
- [Step 8: Make Requests Through the Gateway](#step-8-make-requests-through-the-gateway)
- [Policy Evaluation on AI Requests](#policy-evaluation-on-ai-requests)
- [Configuration Reference](#configuration-reference)
- [Key Management](#key-management)

## Prerequisites

- Docker and Docker Compose installed and running
- An **OpenAI API key** from [platform.openai.com](https://platform.openai.com)

> **New to Warden?** Follow these steps to get a local dev environment running:
>
> **1. Deploy the quickstart stack** — this starts an identity provider ([Ory Hydra](https://www.ory.sh/hydra/)) needed to issue JWTs for authentication in Steps 6-7:
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
> **3. Start the Warden server** in dev mode:
> ```bash
> ./warden server --dev
> ```
>
> **4. In another terminal window**, export the environment variables for the CLI:
> ```bash
> export WARDEN_ADDR="http://127.0.0.1:8400"
> export WARDEN_TOKEN="<your-token>"
> ```

## Step 1: Mount the OpenAI Provider

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

## Step 2: Configure the Provider

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

## Step 3: Create a Credential Source

The credential source holds only connection info (`api_url`). The API key is stored on the credential spec (Step 4), allowing multiple specs with different keys to share one source.

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

## Step 4: Create a Credential Spec

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

## Step 5: Create a Policy

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

Verify:

```bash
warden policy read openai-access
```

## Step 6: Configure JWT Auth and Create a Role

Set up a JWT auth method and create a role that binds the credential spec and policy. With transparent mode, clients authenticate directly with their JWT — no separate login step is needed.

```bash
# Enable JWT auth if not already enabled
warden auth enable --type=jwt

# Configure JWT with Hydra's JWKS endpoint (from docker-compose.quickstart.yml)
warden write auth/jwt/config mode=jwt jwks_url=http://localhost:4444/.well-known/jwks.json

# Create a role that binds the credential spec and policy
warden write auth/jwt/role/openai-user \
    token_type=jwt_role \
    token_policies="openai-access" \
    user_claim=sub \
    cred_spec_name=openai-ops \
    token_ttl=1h
```

## Step 7: Get a JWT

Get a JWT from Hydra using one of the quickstart clients:

```bash
export JWT_TOKEN=$(curl -s -X POST http://localhost:4444/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=my-agent&client_secret=agent-secret&scope=api:read api:write" \
  | jq -r '.access_token')
```

## Step 8: Make Requests Through the Gateway

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

## Configuration Reference

### Provider Config

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `openai_url` | string | `https://api.openai.com` | OpenAI API base URL (must be HTTPS) |
| `max_body_size` | int | 10485760 (10 MB) | Maximum request body size in bytes (max 100 MB) |
| `timeout` | duration | `120s` | Request timeout — set high for AI inference |
| `transparent_mode` | bool | `false` | Enable implicit JWT authentication |
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
