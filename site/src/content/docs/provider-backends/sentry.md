---
title: "Sentry"
---

The Sentry provider enables proxied access to the Sentry REST API through Warden. It forwards requests to Sentry endpoints (organizations, projects, issues, events, etc.) with automatic credential injection and policy evaluation. Credentials are static Internal Integration tokens created in the Sentry UI (`apikey` source type).

## How a request flows

This mount injects `Authorization: Bearer <token>` from an **`api_key`** credential. The question is where that
auth token lives.

The recommended setup keeps it in the vault that manages it, read per request.

<p align="center"><img alt="An agent presents the user's ID token and its own identity to Warden, which builds an assertion carrying user and agent claims, has an external KMS sign it, reads the Sentry auth token from an external vault at a path templated by the agent's team and environment, and injects it to the Sentry API" src="/images/warden-prov-sentry-vault-apikey.png" width="860"></p>

1. The user authenticates and the agent holds their ID token.
2. The agent calls Warden presenting both credentials and asserting a role.
3. Warden builds the assertion the referenced spec calls for and sends it to a KMS-backed
   issuer unsigned, where one is configured.
4. The issuer returns it signed.
5. Warden authenticates to the **external vault** and reads
   `secret/sentry/{{agent.team}}/{{agent.env}}`.
6. The vault returns the auth token for that team and environment.
7. Warden injects it and forwards.

The credential is served **verbatim** — nothing is minted. What chaining buys is custody:
it stays in the store that manages it, and the read path decides who reaches which one.

:::note[Steps 3–6 run only on a cache miss]
Warden caches the credential, so most requests skip from step 2 to step 7. The entry is
keyed by namespace, the agent's token id and the spec name — plus the user's token id when
the mount carries a user.
:::

### The simpler variant

<p align="center"><img alt="Warden reads a static Sentry auth token from its encrypted storage and injects it to the Sentry API for every caller" src="/images/warden-prov-sentry-inline-apikey.png" width="860"></p>

**Inline.** The credential sits in Warden's storage. Shortest to set up, weakest custody:
one long-lived credential for every caller.

## Credential modes

| Mode | What Sentry sees | Where the credential lives |
|---|---|---|
| **Chained** ✅ *recommended* | One long-lived credential, scoped by path | The vault; nothing in Warden |
| **Inline** ⚠️ | One long-lived credential, shared | Warden's storage |

Sentry exposes no workload-identity federation and mints nothing per request, so the
credential is long-lived in both rows; what changes is whether Warden holds it.

See the [apikey credential driver](/credential-drivers/apikey/) for every source and spec
key.

## Prerequisites

- Docker and Docker Compose installed and running
- A **Sentry Internal Integration Token** (from Sentry > Settings > Developer Settings > Internal Integrations)

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

### Option A: Chained (recommended)

The flow in the first diagram. The vault holds the credential; Warden reads it per request
and injects it.

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

warden cred spec create sentry-ops -json '{
  "source": "vault-keyless",
  "min_ttl": 600,
  "max_ttl": 3600,
  "config": {
    "mint_method": "static_apikey",
    "subject_token_source": "warden_identity",
    "assertion_metadata_claims": "team,env",
    "kv2_mount": "secret",
    "secret_path": "sentry/{{agent.team}}/{{agent.env}}"
  }
}'
```

The KV secret must carry the credential under **`api_key`**.

Both principals are available to the path template: `{{agent.sub}}` is free,
`{{agent.<claim>}}` needs `assertion_metadata_claims`, and `{{user.<claim>}}` needs
`assertion_user_claims` plus a user on the request. Swap `{{agent.team}}` for
`{{user.sub}}` to give each person their own credential. Templates resolve at **mint,
not at write**, so a path naming an unprojected claim is accepted by `spec create` and
fails on the first request.

### Option B: Inline

⚠️ 
```bash
warden cred source create sentry-src -json '{
  "type": "apikey",
  "config": {
    "api_url": "https://sentry.io/api/0",
    "verify_endpoint": "/",
    "display_name": "Sentry"
  }
}'

printf '{"source":"sentry-src","min_ttl":3600,"max_ttl":86400,"config":{"api_key":"%s"}}' \
  "$(cat /path/to/sentry-token)" | warden cred spec create sentry-ops -json -
```

One long-lived credential for every caller. Prefer Option A.

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
