---
title: "Cohere"
---

The Cohere provider enables proxied access to the Cohere API through Warden. It forwards requests to Cohere endpoints (Chat, Embed, Rerank, Generate, Models, etc.) with automatic credential injection and policy evaluation. Credentials are injected via the `Authorization: Bearer` header. One credential mode is supported: static API keys (`apikey` source type). Vault/OpenBao can also be used as a credential source (`hvault` source type).

## How a request flows

This mount injects an **`api_key`** credential into the `Authorization` header as a bearer
token. The question is where that API key lives.

The recommended setup keeps it in the vault that manages it, read per request.

<p align="center"><img alt="An agent presents the user's ID token and its own identity to Warden, which builds an assertion carrying user and agent claims, has an external KMS sign it, reads the Cohere API key from an external vault at a path templated by the user's team and the agent's environment, and injects it to the Cohere API" src="/images/warden-prov-cohere-vault-apikey.png" width="860"></p>

1. The user authenticates and the agent holds their ID token.
2. The agent calls Warden presenting both credentials and asserting a role.
3. Warden builds the assertion the referenced spec calls for and sends it to a KMS-backed
   issuer unsigned, where one is configured.
4. The issuer returns it signed.
5. Warden authenticates to the **external vault** and reads
   `secret/cohere/{{user.team}}/{{agent.env}}`.
6. The vault returns the API key for that team and environment.
7. Warden injects it and forwards.

The credential is served **verbatim** — nothing is minted. What chaining buys is custody:
it stays in the store that manages it, and the read path decides who reaches which one.

:::note[Steps 3–6 run only on a cache miss]
Warden caches the credential, so most requests skip from step 2 to step 7. The entry is
keyed by namespace, the agent's token id and the spec name — plus the user's token id when
the mount carries a user.
:::

### The simpler variant

<p align="center"><img alt="Warden reads a static Cohere API key from its encrypted storage and injects it to the Cohere API for every caller" src="/images/warden-prov-cohere-inline-apikey.png" width="860"></p>

**Inline.** The credential sits in Warden's storage. Shortest to set up, weakest custody:
one long-lived credential for every caller.

## Credential modes

| Mode | What Cohere sees | Where the credential lives |
|---|---|---|
| **Chained** ✅ *recommended* | One long-lived credential, scoped by path | The vault; nothing in Warden |
| **Inline** ⚠️ | One long-lived credential, shared | Warden's storage |

Cohere exposes no workload-identity federation and mints nothing per request, so the
credential is long-lived in both rows; what changes is whether Warden holds it.

:::note[Cohere authenticates with the key alone]
There is no second header to pair with it, so a chained spec can read the vault directly
with `mint_method=static_apikey`. A provider that needs another field beside the key cannot
— adjunct fields are dropped for any non-`apikey` driver, and the read has to go through a
producer spec.
[OpenAI](/provider-backends/openai/#carrying-an-organization-or-project-id) shows that shape.
:::

See the [apikey credential driver](/credential-drivers/apikey/) for every source and spec
key.

## Prerequisites

- Docker and Docker Compose installed and running
- A **Cohere API Key** (from [dashboard.cohere.com/api-keys](https://dashboard.cohere.com/api-keys))

:::note[New to Warden?]
Follow [Local dev setup](/provider-backends/local-dev-setup/) to start a local dev environment (Ory Hydra + a Warden dev server) before Step 1.
:::

## Step 1: Configure JWT Auth and Create a Role

Enable the JWT auth method and point it at your identity provider's JWKS endpoint, then create a role that binds the credential spec and policy. Enabling the mount and configuring the key source is covered once in [JWT auth](/auth-methods/jwt/#step-1-configure-the-key-source) — for the local dev setup.

> **Set this up before configuring the provider.** The provider resolves
> `auto_auth_path` per request — writing the config only checks that it is
> non-empty, not that the mount exists — so a gateway call fails with `no auth
> mount registered ... for implicit auth` if the referenced auth mount isn't
> there yet.

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

### Option A: Chained (recommended)

The flow in the first diagram. The vault holds the API key; Warden reads it per request and
injects it.

The key never enters Warden's storage. Warden reads it from a path built out of the agent's
and user's claims, so a request made for the `platform-eng` team against `prod` reads
`secret/cohere/platform-eng/prod` and can reach nothing else.

**Prerequisites:** a Vault/OpenBao instance with a KV v2 mount holding an `api_key` field,
and a JWT auth role bound to Warden's issuer.

```bash
warden cred source create cohere-vault-src -json '{
  "type": "hvault",
  "config": {
    "vault_address": "https://vault.example.com",
    "auth_method": "oidc_federation",
    "jwt_role": "warden-cohere",
    "jwt_mount": "jwt",
    "audience": "https://vault.example.com"
  }
}'
```

`auth_method=oidc_federation` is keyless — the source stores no `secret_id` and no token, and setting one is rejected on write. It also needs no rotation period, because there is nothing to rotate.

```bash
warden cred spec create cohere-prod -json '{
  "source": "cohere-vault-src",
  "min_ttl": 600,
  "max_ttl": 3600,
  "config": {
    "mint_method": "static_apikey",
    "subject_token_source": "warden_identity",
    "assertion_user_claims": "team",
    "assertion_metadata_claims": "env",
    "kv2_mount": "secret",
    "secret_path": "cohere/{{user.team}}/{{agent.env}}"
  }
}'
```

:::note[Templated paths resolve at mint time, not at write time]
`warden cred spec create` accepts `{{user.team}}` and `{{agent.env}}` without checking that either claim can ever be produced — the substitution happens on each credential request. A claim resolves only if the spec projects it: `{{user.*}}` requires the claim in `assertion_user_claims` **and** `subject_token_source=warden_identity`; `{{agent.*}}` requires it in `assertion_metadata_claims`, except `{{agent.sub}}`, which is always available. An unprojected claim fails the request closed rather than reading some other path.
:::

### Option B: Inline

The second diagram. The key sits in Warden's encrypted storage rather than a vault — no
assertion, no outbound hop to fetch it. Quickest to a working mount, and the reason it
belongs in dev and test rather than production.

The source holds only connection details; the key rides on the spec, so several specs with
different keys can share one source.

```bash
warden cred source create cohere-src -json '{
  "type": "apikey",
  "config": {
    "api_url": "https://api.cohere.com",
    "verify_endpoint": "/v1/check-api-key",
    "verify_method": "POST",
    "auth_header_type": "bearer",
    "display_name": "Cohere"
  }
}'

warden cred spec create cohere-prod -json '{
  "source": "cohere-src",
  "config": {
    "api_key": "<your-cohere-api-key>"
  }
}'
```

`verify_endpoint`, `verify_method` and `auth_header_type` describe how to *verify* a key, not how to inject one: together they build the `POST /v1/check-api-key` call that validates a key when a spec is created, so an invalid key fails here rather than on the first gateway request. Gateway injection is the provider's own job and is not configurable here.

Verify either setup:

```bash
warden cred source read cohere-src
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
