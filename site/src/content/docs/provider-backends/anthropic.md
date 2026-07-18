---
title: "Anthropic"
---

The Anthropic provider enables proxied access to the Anthropic API through Warden. It streams requests to Anthropic endpoints (messages, models) with automatic API key injection and policy evaluation on AI request fields.

## Prerequisites

- Docker and Docker Compose installed and running
- An **Anthropic API key** from [console.anthropic.com](https://console.anthropic.com)

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
warden write auth/jwt/role/anthropic-user \
    token_policies="anthropic-access" \
    cred_spec_name=anthropic-ops
```

## Step 2: Mount and Configure the Provider

Enable the Anthropic provider at a path of your choice:

```bash
warden provider enable anthropic
```

To mount at a custom path:

```bash
warden provider enable -path=anthropic-prod anthropic
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

See [Provider configuration](/provider-backends/configuration/) for the full list of common config fields (`proxy_domains`, `timeout`, `tls_skip_verify`, `ca_data`, and more).

Verify the configuration:

```bash
warden read anthropic/config
```

## Step 3: Create a Credential Source and Spec

The credential source holds only connection info (`api_url`). The API key is stored on the credential spec below, allowing multiple specs with different keys to share one source.

```bash
warden cred source create anthropic-src \
  -type=apikey \
  -rotation-period=0 \
  -config=api_url=https://api.anthropic.com \
  -config=verify_endpoint=/v1/models \
  -config=auth_header_type=custom_header \
  -config=auth_header_name=x-api-key \
  -config=extra_headers=anthropic-version:2023-06-01 \
  -config=optional_metadata=organization_id \
  -config=display_name=Anthropic
```

Verify the source was created:

```bash
warden cred source read anthropic-src
```

Create a credential spec that references the credential source. The spec carries the API key and gets associated with tokens at login time.

```bash
warden cred spec create anthropic-ops \
  -source anthropic-src \
  -config api_key=<your-anthropic-api-key>
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
  -type=hvault \
  -config=vault_address=https://vault.example.com \
  -config=auth_method=approle \
  -config=role_id=your-role-id \
  -config=secret_id=your-secret-id \
  -config=approle_mount=approle \
  -config=role_name=warden-role \
  -rotation-period=24h

# Create a credential spec using the static_apikey mint method
warden cred spec create anthropic-ops \
  -source anthropic-vault-src \
  -config mint_method=static_apikey \
  -config kv2_mount=secret \
  -config secret_path=anthropic/ops
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
  condition = <<-CEL
    (!has(request.data.model) || request.data.model in ["claude-sonnet-4-20250514", "claude-haiku-4-20250414"]) &&
    (!has(request.data.stream) || request.data.stream == true)
  CEL
}
EOF
```

You can also combine parameter restrictions with runtime conditions to protect costly inference endpoints. For example, restrict messages to specific models and trusted networks during business hours:

```bash
warden policy write anthropic-prod-restricted - <<EOF
path "anthropic/role/+/gateway/v1/messages" {
  capabilities = ["create"]
  condition = <<-CEL
    (!has(request.data.model) || request.data.model in ["claude-sonnet-4-20250514", "claude-haiku-4-20250414"]) &&
    (!has(request.data.stream) || request.data.stream == true) &&
    cidrContains("10.0.0.0/8", request.client_ip) &&
    now.getHours("UTC") >= 8 && now.getHours("UTC") < 18 &&
    now.getDayOfWeek("UTC") in [1, 2, 3, 4, 5]
  CEL
}

path "anthropic/role/+/gateway/v1/models" {
  capabilities = ["read"]
}
EOF
```

The `condition` is a [CEL](https://cel.dev) expression (see [CEL conditions](/concepts/cel-conditions/)): `cidrContains` restricts by network and `now.getHours`/`now.getDayOfWeek` by time of day and weekday. It must evaluate to `true` for the rule to apply, and fails closed.

Verify:

```bash
warden policy read anthropic-access
```

## Step 5: Get a JWT and Make Requests

Get a JWT from your identity provider — see [Obtaining a JWT](/auth-methods/jwt/#obtaining-a-jwt) (the local dev setup issues one from Hydra). Export it as `$JWT_TOKEN`.

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

The `allowed_common_names` field supports glob patterns; you can also match on other certificate fields. See [Create a role](/auth-methods/cert/#step-3-create-a-role) for the full set of constraint fields.

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
     -config api_key=<new-api-key>
   ```
3. Delete the old key from the Anthropic console
