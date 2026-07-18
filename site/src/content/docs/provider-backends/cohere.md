---
title: "Cohere"
---

The Cohere provider enables proxied access to the Cohere API through Warden. It forwards requests to Cohere endpoints (Chat, Embed, Rerank, Generate, Models, etc.) with automatic credential injection and policy evaluation. Credentials are injected via the `Authorization: Bearer` header. One credential mode is supported: static API keys (`apikey` source type). Vault/OpenBao can also be used as a credential source (`hvault` source type).

## Prerequisites

- Docker and Docker Compose installed and running
- A **Cohere API Key** (from [dashboard.cohere.com/api-keys](https://dashboard.cohere.com/api-keys))

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
warden write auth/jwt/role/cohere-user \
    token_policies="cohere-access" \
    user_claim=sub \
    cred_spec_name=cohere-prod
```

## Step 2: Mount and Configure the Provider

Enable the Cohere provider at a path of your choice:

```bash
warden provider enable cohere
```

To mount at a custom path:

```bash
warden provider enable -path=cohere-prod cohere
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

See [Provider configuration](/provider-backends/configuration/) for the full list of common config fields (`proxy_domains`, `timeout`, `tls_skip_verify`, `ca_data`, and more).

Verify the configuration:

```bash
warden read cohere/config
```

## Step 3: Create a Credential Source and Spec

### Option A: Static API Keys

The credential source holds only connection info (`api_url`). The API key is stored on the credential spec below, allowing multiple specs with different keys to share one source.

```bash
warden cred source create cohere-src \
  -type=apikey \
  -rotation-period=0 \
  -config=api_url=https://api.cohere.com \
  -config=verify_endpoint=/v1/check-api-key \
  -config=verify_method=POST \
  -config=auth_header_type=bearer \
  -config=display_name=Cohere
```

Create a credential spec that references the credential source. The spec carries the API key and gets associated with tokens at login time.

```bash
warden cred spec create cohere-prod \
  -source cohere-src \
  -config api_key=your-cohere-api-key
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
warden cred spec create cohere-prod \
  -source cohere-vault-src \
  -config mint_method=static_apikey \
  -config kv2_mount=secret \
  -config secret_path=cohere/prod
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
  condition = <<-CEL
    has(request.data.model) &&
    request.data.model in ["command-a-03-2025", "command-r-plus-08-2024", "command-r-08-2024"] &&
    (!has(request.data.max_tokens) || request.data.max_tokens <= 4096)
  CEL
}

path "cohere/role/+/gateway/v2/embed" {
  capabilities = ["create"]
  condition = <<-CEL
    has(request.data.model) &&
    request.data.model in ["embed-v4.0", "embed-english-v3.0", "embed-multilingual-v3.0"]
  CEL
}
EOF
```

Verify:

```bash
warden policy read cohere-access
```

## Step 5: Get a JWT and Make Requests

Get a JWT from your identity provider — see [Obtaining a JWT](/auth-methods/jwt/#obtaining-a-jwt) (the local dev setup issues one from Hydra). Export it as `$JWT_TOKEN`.

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

The `allowed_common_names` field supports glob patterns; you can also match on other certificate fields. See [Create a role](/auth-methods/cert/#step-3-create-a-role) for the full set of constraint fields.

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
     -config api_key=your-new-api-key
   ```
3. Delete the old key in the Cohere dashboard
