---
title: "Mistral AI"
---

The Mistral provider enables proxied access to the Mistral AI API through Warden. It streams requests to Mistral endpoints (chat completions, embeddings, models) with automatic API key injection and policy evaluation on AI request fields.

## Prerequisites

- Docker and Docker Compose installed and running
- A **Mistral AI API key** from [console.mistral.ai](https://console.mistral.ai)

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
warden write auth/jwt/role/mistral-user \
    token_policies="mistral-access" \
    user_claim=sub \
    cred_spec_name=mistral-ops
```

## Step 2: Mount and Configure the Provider

Enable the Mistral provider at a path of your choice:

```bash
warden provider enable mistral
```

To mount at a custom path:

```bash
warden provider enable -path=mistral-prod mistral
```

Verify the provider is enabled:

```bash
warden provider list
```

Configure the provider with `auto_auth_path`. This allows clients to authenticate with their JWT directly — no explicit Warden login required:

```bash
warden write mistral/config <<EOF
{
  "mistral_url": "https://api.mistral.ai",
  "auto_auth_path": "auth/jwt/",
  "timeout": "120s",
  "max_body_size": 10485760
}
EOF
```

See [Provider configuration](/provider-backends/configuration/) for the full list of common config fields (`proxy_domains`, `timeout`, `tls_skip_verify`, `ca_data`, and more).

Verify the configuration:

```bash
warden read mistral/config
```

## Step 3: Create a Credential Source and Spec

The credential source holds only connection info (`api_url`). The API key is stored on the credential spec below, allowing multiple specs with different keys to share one source.

```bash
warden cred source create mistral-src \
  -type=apikey \
  -rotation-period=0 \
  -config=api_url=https://api.mistral.ai \
  -config=verify_endpoint=/v1/models \
  -config=optional_metadata=organization_id \
  -config=display_name=Mistral
```

Verify the source was created:

```bash
warden cred source read mistral-src
```

Create a credential spec that references the credential source. The spec carries the API key and gets associated with tokens at login time.

```bash
warden cred spec create mistral-ops \
  -source mistral-src \
  -config api_key=<your-mistral-api-key>
```

Optionally include an organization ID:

```bash
warden cred spec create mistral-ops \
  -source mistral-src \
  -config api_key=<your-mistral-api-key> \
  -config organization_id=<your-org-id>
```

The API key is validated at creation time via a `GET /v1/models` call to the Mistral API (SpecVerifier). If the key is invalid, spec creation will fail.

Verify:

```bash
warden cred spec read mistral-ops
```

### Alternative: Vault/OpenBao as Credential Source

Instead of storing the API key directly in Warden, you can store it in a Vault/OpenBao KV v2 secret engine and have Warden fetch it at runtime. This centralizes secret management in Vault.

**Prerequisites:** A Vault/OpenBao instance with:
- A KV v2 mount containing your Mistral API key (e.g., at `secret/mistral/ops` with an `api_key` field)
- An AppRole configured for Warden access

```bash
# Create a Vault credential source
warden cred source create mistral-vault-src \
  -type=hvault \
  -config=vault_address=https://vault.example.com \
  -config=auth_method=approle \
  -config=role_id=your-role-id \
  -config=secret_id=your-secret-id \
  -config=approle_mount=approle \
  -config=role_name=warden-role \
  -rotation-period=24h

# Create a credential spec using the static_apikey mint method
warden cred spec create mistral-ops \
  -source mistral-vault-src \
  -config mint_method=static_apikey \
  -config kv2_mount=secret \
  -config secret_path=mistral/ops
```

The KV v2 secret at `secret/mistral/ops` should contain at minimum an `api_key` field. Warden fetches the secret from Vault on each credential request.

## Step 4: Create a Policy

Create a policy that grants access to the Mistral provider gateway:

```bash
warden policy write mistral-access - <<EOF
path "mistral/role/+/gateway*" {
  capabilities = ["create", "read", "update", "delete", "patch"]
}
EOF
```

For fine-grained cost control, restrict access based on AI request fields:

```bash
warden policy write mistral-restricted - <<EOF
path "mistral/role/+/gateway/v1/chat/completions" {
  capabilities = ["create"]
  condition = <<-CEL
    (!has(request.data.model) || request.data.model in ["mistral-small-latest", "mistral-medium-latest"]) &&
    (!has(request.data.stream) || request.data.stream == true)
  CEL
}
EOF
```

You can also combine parameter restrictions with runtime conditions to protect costly inference endpoints. For example, restrict chat completions to specific models and trusted networks during business hours:

```bash
warden policy write mistral-prod-restricted - <<EOF
path "mistral/role/+/gateway/v1/chat/completions" {
  capabilities = ["create"]
  condition = <<-CEL
    (!has(request.data.model) || request.data.model in ["mistral-small-latest"]) &&
    (!has(request.data.stream) || request.data.stream == true) &&
    cidrContains("10.0.0.0/8", request.client_ip) &&
    now.getHours("UTC") >= 8 && now.getHours("UTC") < 18 &&
    now.getDayOfWeek("UTC") in [1, 2, 3, 4, 5]
  CEL
}

path "mistral/role/+/gateway/v1/models" {
  capabilities = ["read"]
}
EOF
```

The `condition` is a [CEL](https://cel.dev) expression (see [CEL conditions](/concepts/cel-conditions/)): `cidrContains` restricts by network and `now.getHours`/`now.getDayOfWeek` by time of day and weekday. It must evaluate to `true` for the rule to apply, and fails closed.

Verify:

```bash
warden policy read mistral-access
```

## Step 5: Get a JWT and Make Requests

Get a JWT from your identity provider — see [Obtaining a JWT](/auth-methods/jwt/#obtaining-a-jwt) (the local dev setup issues one from Hydra). Export it as `$JWT_TOKEN`.

Requests use role-based paths. Warden performs implicit JWT authentication and injects the Mistral API key automatically.

The URL pattern is: `/v1/mistral/role/{role}/gateway/{mistral-api-path}`

Export MISTRAL_ENDPOINT as environment variable:
```bash
export MISTRAL_ENDPOINT="${WARDEN_ADDR}/v1/mistral/role/mistral-user/gateway"
```

### Chat Completions

```bash
curl -X POST "${MISTRAL_ENDPOINT}/v1/chat/completions" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "mistral-small-latest",
    "messages": [
      {"role": "user", "content": "Hello, how are you?"}
    ]
  }'
```

### Streaming Chat Completions

```bash
curl -X POST "${MISTRAL_ENDPOINT}/v1/chat/completions" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -N \
  -d '{
    "model": "mistral-small-latest",
    "messages": [
      {"role": "user", "content": "Write a short poem about the ocean."}
    ],
    "stream": true
  }'
```

### Embeddings

```bash
curl -X POST "${MISTRAL_ENDPOINT}/v1/embeddings" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "mistral-embed",
    "input": ["Hello world"]
  }'
```

### List Models

```bash
curl "${MISTRAL_ENDPOINT}/v1/models" \
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

The Mistral provider has request body parsing enabled (`ParseStreamBody: true`), which means Warden can evaluate policies against fields in the AI request body. This enables fine-grained cost control and usage policies.

Evaluable fields include:

| Field | Type | Description |
|-------|------|-------------|
| `model` | string | Model to use (e.g., `mistral-small-latest`, `mistral-large-latest`) |
| `max_tokens` | integer | Maximum tokens to generate |
| `temperature` | float | Sampling temperature |
| `stream` | boolean | Whether to stream the response |
| `top_p` | float | Nucleus sampling parameter |

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
    default_role=mistral-user
```

### Create a Cert Role

Create a role that binds allowed certificate identities to a credential spec and policy:

```bash
warden write auth/cert/role/mistral-user \
    allowed_common_names="agent-*" \
    token_policies="mistral-access" \
    cred_spec_name=mistral-ops 
```

The `allowed_common_names` field supports glob patterns; you can also match on other certificate fields. See [Create a role](/auth-methods/cert/#step-3-create-a-role) for the full set of constraint fields.

### Configure Provider for Cert Auth

Update the provider config to use cert auth:

```bash
warden write mistral/config <<EOF
{
  "mistral_url": "https://api.mistral.ai",
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
    -X POST "https://warden.internal/v1/mistral/role/mistral-user/gateway/v1/chat/completions" \
    -H "Content-Type: application/json" \
    -d '{
      "model": "mistral-small-latest",
      "messages": [{"role": "user", "content": "Hello"}]
    }'
```

## Key Management

| Aspect | Details |
|--------|---------|
| **Storage** | API key is stored on the credential spec (not the source) |
| **Validation** | Key is verified at spec creation via `GET /v1/models` |
| **Rotation** | Manual — Mistral does not expose key management APIs |
| **Lifetime** | Static — no expiration or auto-refresh |

**To rotate an API key:**

1. Create a new API key in the [Mistral console](https://console.mistral.ai)
2. Update the credential spec:
   ```bash
   warden cred spec update mistral-ops \
     -config api_key=<new-api-key>
   ```
3. Delete the old key from the Mistral console
