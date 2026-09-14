---
title: "Dynatrace"
description: "Proxy the Dynatrace API through Warden: mint an access token per request from OAuth2 client credentials held in a vault."
---

The Dynatrace provider enables proxied access to the Dynatrace REST API through Warden. It forwards requests to Dynatrace endpoints (Entities, Metrics, Logs, Problems, Settings, Tokens, etc.) with automatic credential injection and policy evaluation. Two authentication modes are supported: static API tokens (`apikey` source type) using the `Api-Token` authorization scheme, and OAuth2 client credentials (`oauth2` source type) using the `Bearer` authorization scheme. Vault/OpenBao can also be used as a credential source (`hvault` source type).

## How a request flows

Two things vary independently: whether the token Dynatrace sees is **minted per request** or a
fixed one, and whether the credential behind it lives **in Warden** or in a vault.

The best combination does both — vaulted OAuth2 client credentials, exchanged for a short-lived
access token on each request.

<p align="center"><img alt="An agent presents the user's ID token and its own identity to Warden, which builds an assertion carrying user and agent claims, has an external KMS sign it, reads the Dynatrace OAuth2 client credentials from an external vault at a path templated by the agent's team and environment, exchanges them at the Dynatrace token endpoint for an access token, and injects that token to the Dynatrace API" src="/images/warden-prov-dynatrace-cred-chain.png" width="860"></p>

1. The user authenticates and the agent holds their ID token.
2. The agent calls Warden presenting both credentials and asserting a role.
3. Warden builds the assertion the referenced spec calls for and sends it to an **external
   KMS** unsigned.
4. The KMS returns it signed. No signing key lives in Warden.
5. Warden authenticates to the **external vault** and reads
   `secret/dynatrace/{{agent.team}}/{{agent.env}}`.
6. The vault returns the client credentials for that team and environment.
7. Warden exchanges them at the **Dynatrace token endpoint**…
8. …receiving a short-lived access token.
9. Warden injects that token and forwards.

The client secret is the long-lived credential, so keeping it in the vault and out of
Warden is the point. What Dynatrace sees on each request is a short-lived token instead.

:::note[Steps 3–8 run only on a cache miss]
Warden caches the minted credential, so most requests skip from step 2 to step 9. The entry
is keyed by namespace, the agent's token id and the spec name — plus the user's token id
when the mount carries a user.
:::

### Simpler variants

<p align="center"><img alt="Warden authenticates to an external vault with a KMS-signed assertion carrying user and agent claims, reads a static Dynatrace API token from a templated path, and injects it to the Dynatrace API" src="/images/warden-prov-dynatrace-vault-apikey.png" width="860"></p>

**Vaulted static token.** The vault holds an API token directly, served verbatim — no token
endpoint, nothing minted. It stays out of Warden and the path scopes who reaches which
token, but it is long-lived.

<p align="center"><img alt="Warden reads a static Dynatrace API token from its encrypted storage and injects it to the Dynatrace API for every caller" src="/images/warden-prov-dynatrace-inline-apikey.png" width="860"></p>

**Inline static token.** The token sits in Warden's storage. Shortest to set up, weakest
custody.

## Credential modes

| Mode | What Dynatrace sees | Where the credential lives |
|---|---|---|
| **Chained client credentials → minted token** ✅ *recommended* | A short-lived access token | The vault; nothing in Warden |
| **Stored client credentials → minted token** | The same short-lived token | The client secret is in Warden |
| **Chained static token** | One long-lived token, per path | The vault |
| **Inline static token** ⚠️ | One long-lived token, shared | Warden's storage |

:::caution[OAuth2 and API tokens reach different Dynatrace APIs]
The provider injects `Api-Token` for an `api_key` credential and `Bearer` for an
`oauth_bearer_token` one, because Dynatrace splits its surface:

| Credential | Header | API | `dynatrace_url` |
|---|---|---|---|
| `api_key` (Options C, D) | `Api-Token` | Environment API v2 | `https://{env}.live.dynatrace.com` |
| OAuth2 (Options A, B) | `Bearer` | Platform API | `https://{env}.apps.dynatrace.com` |

The Step 2 config and the Step 5 examples on this page target the **Environment API**, so
they pair with Options C and D. To use OAuth2, point `dynatrace_url` at the platform host
and call platform paths — an OAuth2 token is rejected by the Environment API and vice
versa. Scope your OAuth2 client for the platform capabilities you need; the
`storage:*`/`app-engine:*` scopes shown are platform scopes and do not grant entity or
metric queries.
:::

Dynatrace exposes no workload-identity federation, so a long-lived credential exists somewhere
in every row; what changes is whether Warden holds it, and whether Dynatrace sees it directly.

See the [OAuth2 credential driver](/credential-drivers/oauth2/) and the
[apikey driver](/credential-drivers/apikey/) for every source and spec key.

## Prerequisites

- Docker and Docker Compose installed and running
- A **Dynatrace environment** with either:
  - A **Dynatrace API Token** (from Dynatrace > Access tokens) with appropriate scopes, or
  - **OAuth2 client credentials** (from Dynatrace > Account Management > OAuth clients) for Platform API access

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
warden write auth/jwt/role/dynatrace-user \
    token_policies="dynatrace-access" \
    user_claim=sub \
    cred_spec_name=dynatrace-env
```

## Step 2: Mount and Configure the Provider

Enable the Dynatrace provider at a path of your choice:

```bash
warden provider enable dynatrace
```

To mount at a custom path:

```bash
warden provider enable -path=dynatrace-prod dynatrace
```

Verify the provider is enabled:

```bash
warden provider list
```

Configure the provider with `auto_auth_path`. This allows clients to authenticate with their JWT directly — no explicit Warden login required:

```bash
warden write dynatrace/config <<EOF
{
  "dynatrace_url": "https://abc12345.live.dynatrace.com",
  "auto_auth_path": "auth/jwt/",
  "timeout": "30s",
  "max_body_size": 10485760
}
EOF
```

See [Provider configuration](/provider-backends/configuration/) for the full list of common config fields (`proxy_domains`, `timeout`, `tls_skip_verify`, `ca_data`, and more).

> **Important:** Replace `abc12345` with your actual Dynatrace environment ID. You can find it in your Dynatrace URL (e.g., `https://abc12345.live.dynatrace.com`).

Verify the configuration:

```bash
warden read dynatrace/config
```

## Step 3: Create a Credential Source and Spec

### Option A: Chained client credentials (recommended)

The flow in the first diagram. The `oauth2` source names a `secret_spec` and holds neither
half of the client credential; Warden reads the pair per mint and exchanges it for an
access token.

```bash
# The store Warden reads from, reached keylessly — no vault token in Warden
warden cred source create vault-keyless -json '{
  "type": "hvault",
  "config": {
    "vault_address": "https://vault.example.com",
    "auth_method": "oidc_federation",
    "jwt_role": "warden-agents",
    "jwt_mount": "jwt",
    "audience": "https://vault.example.com"
  }
}'

# Producer: the client credentials, read from KV v2 through that source
warden cred spec create dynatrace-client -json '{
  "source": "vault-keyless",
  "min_ttl": 600,
  "max_ttl": 3600,
  "config": {
    "mint_method": "kv2_read",
    "subject_token_source": "warden_identity",
    "assertion_metadata_claims": "team,env",
    "kv2_mount": "secret",
    "secret_path": "dynatrace/{{agent.team}}/{{agent.env}}"
  }
}'

# Consumer: an oauth2 source holding no client credential of its own
warden cred source create dynatrace-src -json '{
  "type": "oauth2",
  "config": {
    "token_url": "https://sso.dynatrace.com/sso/oauth2/token",
    "default_scopes": "storage:buckets:read app-engine:apps:run",
    "token_param.resource": "urn:dtaccount:your-account-uuid",
    "secret_spec": "dynatrace-client"
  }
}'

warden cred spec create dynatrace-ops -json '{
  "source": "dynatrace-src",
  "min_ttl": 600,
  "max_ttl": 3600
}'
```

`client_id` **and** `client_secret` must both be omitted when `secret_spec` is set — keeping
either is rejected, because the pair authenticates together. The referenced payload supplies
both, under `client_id` and `client_secret`.

`default_scopes` is the **source** key; a spec may narrow it with `scope`:

```bash
warden cred spec create dynatrace-readonly -json '{
  "source": "dynatrace-src",
  "min_ttl": 600,
  "max_ttl": 3600,
  "config": {
    "scope": "storage:buckets:read storage:logs:read"
  }
}'
```

Both principals are available to the path template: `{{agent.sub}}` is free,
`{{agent.<claim>}}` needs `assertion_metadata_claims`, and `{{user.<claim>}}` needs
`assertion_user_claims` plus a user on the request. Templates resolve at **mint, not at
write**.

### Option B: Client credentials stored in Warden

```bash
warden cred source create dynatrace-src -json '{
  "type": "oauth2",
  "config": {
    "token_url": "https://sso.dynatrace.com/sso/oauth2/token",
    "client_id": "<your-client-id>",
    "client_secret": "<your-client-secret>",
    "default_scopes": "storage:buckets:read app-engine:apps:run",
    "token_param.resource": "urn:dtaccount:your-account-uuid",
    "display_name": "Dynatrace"
  }
}'

warden cred spec create dynatrace-ops -json '{
  "source": "dynatrace-src",
  "min_ttl": 600,
  "max_ttl": 3600
}'
```

### Option C: Chained static token

No token endpoint — the vault holds an API token and Warden serves it verbatim. Reusing the
`vault-keyless` source from Option A:

```bash
warden cred spec create dynatrace-ops -json '{
  "source": "vault-keyless",
  "min_ttl": 600,
  "max_ttl": 3600,
  "config": {
    "mint_method": "static_apikey",
    "subject_token_source": "warden_identity",
    "assertion_metadata_claims": "team,env",
    "kv2_mount": "secret",
    "secret_path": "dynatrace/{{agent.team}}/{{agent.env}}"
  }
}'
```

The KV secret must carry the token under `api_key`.

### Option D: Inline static token ⚠️

```bash
warden cred source create dynatrace-src -json '{
  "type": "apikey",
  "config": {
    "api_url": "https://mytenant.live.dynatrace.com",
    "display_name": "Dynatrace"
  }
}'

printf '{"source":"dynatrace-src","min_ttl":3600,"max_ttl":86400,"config":{"api_key":"%s"}}' \
  "$(cat /path/to/dynatrace-token)" | warden cred spec create dynatrace-ops -json -
```

**No `verify_endpoint` here, deliberately.** The apikey driver can send `Bearer `, `Token `
or a bare custom header — never Dynatrace's required `Api-Token ` scheme — so a
verification call would 401 even with a valid token and block spec creation. Leaving
`verify_endpoint` unset skips verification; the gateway still injects the correct
`Api-Token` header, because that is the *provider's* extractor rather than the driver's.

One long-lived token for every caller; prefer any option above.

## Step 4: Create a Policy

Create a policy that grants access to the Dynatrace provider gateway:

```bash
warden policy write dynatrace-access - <<EOF
path "dynatrace/role/+/gateway*" {
  capabilities = ["create", "read", "update", "delete", "patch"]
}
EOF
```

For fine-grained access control, restrict which Dynatrace resources and actions a role can use:

```bash
warden policy write dynatrace-readonly - <<EOF
path "dynatrace/role/+/gateway/api/v2/entities*" {
  capabilities = ["read"]
}

path "dynatrace/role/+/gateway/api/v2/metrics*" {
  capabilities = ["read"]
}

path "dynatrace/role/+/gateway/api/v2/problems*" {
  capabilities = ["read"]
}

path "dynatrace/role/+/gateway/api/v2/logs/search" {
  capabilities = ["read"]
}

path "dynatrace/role/+/gateway/api/v2/settings/objects" {
  capabilities = ["read"]
}
EOF
```

Verify:

```bash
warden policy read dynatrace-access
```

## Step 5: Get a JWT and Make Requests

Get a JWT from your identity provider — see [Obtaining a JWT](/auth-methods/jwt/#obtaining-a-jwt) (the local dev setup issues one from Hydra). Export it as `$JWT_TOKEN`.

Requests use role-based paths. Warden performs implicit JWT authentication and injects the Dynatrace credentials automatically.

The URL pattern is: `/v1/dynatrace/role/{role}/gateway/{api-path}`

Export DT_ENDPOINT as environment variable:
```bash
export DT_ENDPOINT="${WARDEN_ADDR}/v1/dynatrace/role/dynatrace-user/gateway"
```

### List Entities

```bash
curl -s "${DT_ENDPOINT}/api/v2/entities?pageSize=10" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### Query Metrics

```bash
curl -s "${DT_ENDPOINT}/api/v2/metrics/query?metricSelector=builtin:host.cpu.usage&from=now-1h" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### List Problems

```bash
curl -s "${DT_ENDPOINT}/api/v2/problems?from=now-24h" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### Search Logs

```bash
curl -s -X POST "${DT_ENDPOINT}/api/v2/logs/search" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "status=ERROR",
    "from": "now-1h",
    "to": "now",
    "limit": 25
  }'
```

### List Settings Objects

```bash
curl -s "${DT_ENDPOINT}/api/v2/settings/objects?schemaIds=builtin:alerting.profile&pageSize=10" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### List API Tokens

```bash
curl -s "${DT_ENDPOINT}/api/v2/apiTokens?pageSize=10" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### Create a Custom Event for Alerting

```bash
curl -s -X POST "${DT_ENDPOINT}/api/v2/events/ingest" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "eventType": "CUSTOM_ALERT",
    "title": "Deployment completed",
    "properties": {
      "service": "web-app",
      "version": "2.1.0",
      "environment": "production"
    }
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
    default_role=dynatrace-user
```

### Create a Cert Role

Create a role that binds allowed certificate identities to a credential spec and policy:

```bash
warden write auth/cert/role/dynatrace-user \
    allowed_common_names="agent-*" \
    token_policies="dynatrace-access" \
    cred_spec_name=dynatrace-env
```

The `allowed_common_names` field supports glob patterns; you can also match on other certificate fields. See [Create a role](/auth-methods/cert/#step-3-create-a-role) for the full set of constraint fields.

### Configure Provider for Cert Auth

Update the provider config to use cert auth:

```bash
warden write dynatrace/config <<EOF
{
  "dynatrace_url": "https://abc12345.live.dynatrace.com",
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
    -s "https://warden.internal/v1/dynatrace/role/dynatrace-user/gateway/api/v2/entities?pageSize=10" \
    -H "Content-Type: application/json"
```

## Token Management

### Static API Tokens

| Aspect | Details |
|--------|---------|
| **Storage** | API token is stored on the credential spec (not the source) |
| **Validation** | Token is verified at spec creation via `POST /api/v2/tokens/lookup` |
| **Rotation** | Manual — regenerate in Dynatrace and update the spec |
| **Lifetime** | Configurable in Dynatrace (can be set to never expire or with a specific expiry) |
| **Rate Limits** | 50 requests/minute per environment |

**To rotate Dynatrace API tokens:**

1. Create a new API token in Dynatrace (Access tokens > Generate new token) with the same scopes
2. Update the credential spec:
   ```bash
   warden cred spec update dynatrace-env \
     -config api_key=dt0c01.NEW_TOKEN_ID.NEW_TOKEN_SECRET
   ```
3. Revoke the old token in Dynatrace

### OAuth2 Tokens

| Aspect | Details |
|--------|---------|
| **Storage** | Client credentials are stored on the credential source (not the spec) |
| **Minting** | Warden exchanges credentials for a bearer token on each request (cached by TTL) |
| **Lifetime** | 5 minutes (Warden transparently re-mints on the next request after expiry) |
| **Rate Limits** | 50 requests/minute per environment |
