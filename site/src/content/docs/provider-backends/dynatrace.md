---
title: "Dynatrace"
---

The Dynatrace provider enables proxied access to the Dynatrace REST API through Warden. It forwards requests to Dynatrace endpoints (Entities, Metrics, Logs, Problems, Settings, Tokens, etc.) with automatic credential injection and policy evaluation. Two authentication modes are supported: static API tokens (`apikey` source type) using the `Api-Token` authorization scheme, and OAuth2 client credentials (`oauth2` source type) using the `Bearer` authorization scheme. Vault/OpenBao can also be used as a credential source (`hvault` source type).

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

> **This step must come before configuring the provider.** Warden validates at configuration time that the auth backend referenced by `auto_auth_path` is already mounted.

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

### Option A: Static API Token

The credential source holds only connection info. The API token is stored on the credential spec below, allowing multiple specs with different tokens and scopes to share one source.

```bash
warden cred source create dynatrace-src \
  -type=apikey \
  -rotation-period=0 \
  -config=api_url=https://abc12345.live.dynatrace.com \
  -config=verify_endpoint=/api/v2/tokens/lookup \
  -config=verify_method=POST \
  -config=auth_header_type=custom_header \
  -config=auth_header_name=Authorization \
  -config=extra_headers=Authorization:Api-Token \
  -config=display_name=Dynatrace
```

Create a credential spec that references the credential source. The spec carries the API token and gets associated with tokens at login time.

```bash
warden cred spec create dynatrace-env \
  -source dynatrace-src \
  -config api_key=dt0c01.XXXXXXXX.YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY
```

> **Note:** Dynatrace API tokens follow the format `dt0c01.{token-id}.{secret}`. You can create tokens in Dynatrace under Access tokens with specific scopes.

### Option B: OAuth2 Client Credentials

For Dynatrace Platform API access, use OAuth2 client credentials. This is recommended for applications and automation.

```bash
warden cred source create dynatrace-oauth-src \
  -type=oauth2 \
  -rotation-period=0 \
  -config=client_id=dt0s02.XXXXXXXX \
  -config=client_secret=dt0s02.XXXXXXXX.YYYYYYYYYYYYYYYYYYYY \
  -config=token_url=https://sso.dynatrace.com/sso/oauth2/token \
  -config=default_scopes="storage:buckets:read app-engine:apps:run" \
  -config=token_param.resource=urn:dtaccount:your-account-uuid \
  -config=display_name=Dynatrace
```

Create a credential spec (scope can be overridden per spec):

```bash
warden cred spec create dynatrace-platform \
  -source dynatrace-oauth-src \
  -config scope="storage:buckets:read storage:logs:read"
```

> **Note:** The `token_param.resource` on the source config injects the `resource` form parameter into the OAuth2 token exchange, as required by Dynatrace SSO. OAuth2 tokens are valid for 5 minutes; when a token expires, Warden transparently re-mints a fresh one on the next request.

When using OAuth2, configure the provider URL to point to the Platform API:

```bash
warden write dynatrace/config <<EOF
{
  "dynatrace_url": "https://abc12345.apps.dynatrace.com",
  "auto_auth_path": "auth/jwt/",
  "timeout": "30s"
}
EOF
```

### Option C: Vault/OpenBao as Credential Source

Instead of storing API tokens directly in Warden, you can store them in a Vault/OpenBao KV v2 secret engine and have Warden fetch them at runtime. This centralizes secret management in Vault.

**Prerequisites:** A Vault/OpenBao instance with:
- A KV v2 mount containing your Dynatrace API token (e.g., at `secret/dynatrace/env` with an `api_key` field)
- An AppRole configured for Warden access

```bash
# Create a Vault credential source
warden cred source create dynatrace-vault-src \
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
warden cred spec create dynatrace-env \
  -source dynatrace-vault-src \
  -config mint_method=static_apikey \
  -config kv2_mount=secret \
  -config secret_path=dynatrace/env
```

The KV v2 secret at `secret/dynatrace/env` should contain an `api_key` field with the Dynatrace API token.

Verify:

```bash
warden cred spec read dynatrace-env
```

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
