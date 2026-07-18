---
title: "Sentry"
---

The Sentry provider enables proxied access to the Sentry REST API through Warden. It forwards requests to Sentry endpoints (organizations, projects, issues, events, etc.) with automatic credential injection and policy evaluation. Credentials are static Internal Integration tokens created in the Sentry UI (`apikey` source type).

## Prerequisites

- Docker and Docker Compose installed and running
- A **Sentry Internal Integration Token** (from Sentry > Settings > Developer Settings > Internal Integrations)

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
warden write auth/jwt/role/sentry-user \
    token_policies="sentry-access" \
    user_claim=sub \
    cred_spec_name=sentry-ops
```

## Step 2: Mount and Configure the Provider

Enable the Sentry provider at a path of your choice:

```bash
warden provider enable sentry
```

To mount at a custom path:

```bash
warden provider enable -path=sentry-prod sentry
```

Verify the provider is enabled:

```bash
warden provider list
```

Configure the provider with `auto_auth_path`. This allows clients to authenticate with their JWT directly — no explicit Warden login required:

```bash
warden write sentry/config <<EOF
{
  "sentry_url": "https://sentry.io/api/0",
  "auto_auth_path": "auth/jwt/",
  "timeout": "30s",
  "max_body_size": 10485760
}
EOF
```

See [Provider configuration](/provider-backends/configuration/) for the full list of common config fields (`proxy_domains`, `timeout`, `tls_skip_verify`, `ca_data`, and more).

Verify the configuration:

```bash
warden read sentry/config
```

## Step 3: Create a Credential Source and Spec

### Option A: Static Internal Integration Token

The credential source holds only connection info (`api_url`). The auth token is stored on the credential spec below, allowing multiple specs with different tokens to share one source.

First, create an Internal Integration in Sentry:
1. Go to **Settings > Developer Settings > Internal Integrations**
2. Click **Create New Integration**
3. Give it a name and select the required permission scopes
4. Copy the generated token (it is only displayed once)

```bash
warden cred source create sentry-src \
  -type=apikey \
  -rotation-period=0 \
  -config=api_url=https://sentry.io/api/0 \
  -config=verify_endpoint=/ \
  -config=display_name=Sentry
```

Create a credential spec that references the credential source. The spec carries the auth token and gets associated with tokens at login time.

```bash
warden cred spec create sentry-ops \
  -source sentry-src \
  -config api_key=your-sentry-internal-integration-token
```

The token is validated at creation time via a `GET /` call to the Sentry API (SpecVerifier). If the token is invalid, spec creation will fail.

### Option B: Vault/OpenBao as Credential Source

Instead of storing the auth token directly in Warden, you can store it in a Vault/OpenBao KV v2 secret engine and have Warden fetch it at runtime. This centralizes secret management in Vault.

**Prerequisites:** A Vault/OpenBao instance with:
- A KV v2 mount containing your Sentry token (e.g., at `secret/sentry/ops` with an `api_key` field)
- An AppRole configured for Warden access

```bash
# Create a Vault credential source
warden cred source create sentry-vault-src \
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
warden cred spec create sentry-ops \
  -source sentry-vault-src \
  -config mint_method=static_apikey \
  -config kv2_mount=secret \
  -config secret_path=sentry/ops
```

The KV v2 secret at `secret/sentry/ops` should contain at minimum an `api_key` field. Warden fetches the secret from Vault on each credential request.

Verify:

```bash
warden cred spec read sentry-ops
```

## Step 4: Create a Policy

Create a policy that grants access to the Sentry provider gateway:

```bash
warden policy write sentry-access - <<EOF
path "sentry/role/+/gateway*" {
  capabilities = ["create", "read", "update", "delete", "patch"]
}
EOF
```

For fine-grained access control, restrict which Sentry resources and actions a role can use:

```bash
warden policy write sentry-readonly - <<EOF
path "sentry/role/+/gateway/organizations/*" {
  capabilities = ["read"]
}

path "sentry/role/+/gateway/projects/*" {
  capabilities = ["read"]
}
EOF
```

Verify:

```bash
warden policy read sentry-access
```

## Step 5: Get a JWT and Make Requests

Get a JWT from your identity provider — see [Obtaining a JWT](/auth-methods/jwt/#obtaining-a-jwt) (the local dev setup issues one from Hydra). Export it as `$JWT_TOKEN`.

Requests use role-based paths. Warden performs implicit JWT authentication and injects the Sentry token automatically.

The URL pattern is: `/v1/sentry/role/{role}/gateway/{api-path}`

Export SENTRY_ENDPOINT as environment variable:
```bash
export SENTRY_ENDPOINT="${WARDEN_ADDR}/v1/sentry/role/sentry-user/gateway"
```

### List Organizations

```bash
curl -s "${SENTRY_ENDPOINT}/organizations/" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### List Projects

```bash
curl -s "${SENTRY_ENDPOINT}/organizations/{org}/projects/" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### List Issues

```bash
curl -s "${SENTRY_ENDPOINT}/projects/{org}/{project}/issues/" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### Get Issue Details

```bash
curl -s "${SENTRY_ENDPOINT}/issues/{issue_id}/" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### List Project Events

```bash
curl -s "${SENTRY_ENDPOINT}/projects/{org}/{project}/events/" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### List Organization Members

```bash
curl -s "${SENTRY_ENDPOINT}/organizations/{org}/members/" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### Resolve an Issue

```bash
curl -s -X PUT "${SENTRY_ENDPOINT}/issues/{issue_id}/" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "status": "resolved"
  }'
```

### Create a Project

```bash
curl -s -X POST "${SENTRY_ENDPOINT}/teams/{org}/{team}/projects/" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-new-project"
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
    default_role=sentry-user
```

### Create a Cert Role

Create a role that binds allowed certificate identities to a credential spec and policy:

```bash
warden write auth/cert/role/sentry-user \
    allowed_common_names="agent-*" \
    token_policies="sentry-access" \
    cred_spec_name=sentry-ops
```

The `allowed_common_names` field supports glob patterns; you can also match on other certificate fields. See [Create a role](/auth-methods/cert/#step-3-create-a-role) for the full set of constraint fields.

### Configure Provider for Cert Auth

Update the provider config to use cert auth:

```bash
warden write sentry/config <<EOF
{
  "sentry_url": "https://sentry.io/api/0",
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
    -s "https://warden.internal/v1/sentry/role/sentry-user/gateway/organizations/" \
    -H "Content-Type: application/json"
```

## Token Management

### Static Internal Integration Token

| Aspect | Details |
|--------|---------|
| **Storage** | Token is stored on the credential spec (not the source) |
| **Validation** | Token is verified at spec creation via `GET /` on the Sentry API |
| **Rotation** | Manual — regenerate in Sentry and update the spec |
| **Lifetime** | Static — Internal Integration tokens do not expire |

Sentry does not support OAuth2 client credentials flow. For machine-to-machine access, Sentry recommends Internal Integration tokens.

**To rotate a static token:**

1. Generate a new token in Sentry (Settings > Developer Settings > Internal Integrations)
2. Update the credential spec:
   ```bash
   warden cred spec update sentry-ops \
     -config api_key=your-new-token
   ```
3. Revoke the old token in Sentry
