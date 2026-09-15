---
title: "Mistral AI"
---

The Mistral provider enables proxied access to the Mistral AI API through Warden. It streams requests to Mistral endpoints (chat completions, embeddings, models) with automatic API key injection and policy evaluation on AI request fields. Credentials are injected via the `Authorization: Bearer` header. One credential mode is supported: static API keys (`apikey` source type). Vault/OpenBao can also be used as a credential source (`hvault` source type).

## How a request flows

This mount injects an **`api_key`** credential into the `Authorization` header as a bearer
token. The question is where that API key lives.

The recommended setup keeps it in the vault that manages it, read per request.

<p align="center"><img alt="An agent presents the user's ID token and its own identity to Warden, which builds an assertion carrying user and agent claims, has an external KMS sign it, reads the Mistral API key from an external vault at a path templated by the user's team and the agent's environment, and injects it to the Mistral API" src="/images/warden-prov-mistral-vault-apikey.png" width="860"></p>

1. The user authenticates and the agent holds their ID token.
2. The agent calls Warden presenting both credentials and asserting a role.
3. Warden builds the assertion the referenced spec calls for and sends it to a KMS-backed
   issuer unsigned, where one is configured.
4. The issuer returns it signed.
5. Warden authenticates to the **external vault** and reads
   `secret/mistral/{{user.team}}/{{agent.env}}`.
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

<p align="center"><img alt="Warden reads a static Mistral API key from its encrypted storage and injects it to the Mistral API for every caller" src="/images/warden-prov-mistral-inline-apikey.png" width="860"></p>

**Inline.** The credential sits in Warden's storage. Shortest to set up, weakest custody:
one long-lived credential for every caller.

## Credential modes

| Mode | What Mistral sees | Where the credential lives |
|---|---|---|
| **Chained** ✅ *recommended* | One long-lived credential, scoped by path | The vault; nothing in Warden |
| **Inline** ⚠️ | One long-lived credential, shared | Warden's storage |

Mistral exposes no workload-identity federation and mints nothing per request, so the
credential is long-lived in both rows; what changes is whether Warden holds it.

:::note[Mistral authenticates with the key alone]
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
- A **Mistral AI API key** from [console.mistral.ai](https://console.mistral.ai)

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

### Option A: Chained (recommended)

The flow in the first diagram. The vault holds the API key; Warden reads it per request and
injects it.

The key never enters Warden's storage. Warden reads it from a path built out of the agent's
and user's claims, so a request made for the `platform-eng` team against `prod` reads
`secret/mistral/platform-eng/prod` and can reach nothing else.

**Prerequisites:** a Vault/OpenBao instance with a KV v2 mount holding an `api_key` field,
and a JWT auth role bound to Warden's issuer.

```bash
warden cred source create mistral-vault-src -json '{
  "type": "hvault",
  "config": {
    "vault_address": "https://vault.example.com",
    "auth_method": "oidc_federation",
    "jwt_role": "warden-mistral",
    "jwt_mount": "jwt",
    "audience": "https://vault.example.com"
  }
}'
```

`auth_method=oidc_federation` is keyless — the source stores no `secret_id` and no token, and setting one is rejected on write. It also needs no rotation period, because there is nothing to rotate.

```bash
warden cred spec create mistral-ops -json '{
  "source": "mistral-vault-src",
  "min_ttl": 600,
  "max_ttl": 3600,
  "config": {
    "mint_method": "static_apikey",
    "subject_token_source": "warden_identity",
    "assertion_user_claims": "team",
    "assertion_metadata_claims": "env",
    "kv2_mount": "secret",
    "secret_path": "mistral/{{user.team}}/{{agent.env}}"
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
warden cred source create mistral-src -json '{
  "type": "apikey",
  "config": {
    "api_url": "https://api.mistral.ai",
    "verify_endpoint": "/v1/models",
    "display_name": "Mistral"
  }
}'

warden cred spec create mistral-ops -json '{
  "source": "mistral-src",
  "config": {
    "api_key": "<your-mistral-api-key>"
  }
}'
```

`verify_endpoint` describes how to *verify* a key, not how to inject one: it builds the `GET /v1/models` call that validates a key when a spec is created, so an invalid key fails here rather than on the first gateway request. Gateway injection is the provider's own job and is not configurable here.

Verify either setup:

```bash
warden cred source read mistral-src
warden cred spec read mistral-ops
```

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
