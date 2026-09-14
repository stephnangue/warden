---
title: "TFE"
---

The TFE provider enables proxied access to the Terraform Enterprise (TFE) and HCP Terraform API through Warden. It forwards requests to the TFE REST API (Organizations, Workspaces, Runs, State Versions, Variables, Projects, etc.) with automatic credential injection and policy evaluation. Credentials are injected via the `Authorization: Bearer <token>` header. One credential mode is supported: static API tokens (`apikey` source type). Vault/OpenBao can also be used as a credential source (`hvault` source type).

## How a request flows

This mount injects `Authorization: Bearer <token>` from an **`api_key`** credential. The question is where that
API token lives.

The recommended setup keeps it in the vault that manages it, read per request.

<p align="center"><img alt="An agent presents the user's ID token and its own identity to Warden, which builds an assertion carrying user and agent claims, has an external KMS sign it, reads the Terraform Enterprise API token from an external vault at a path templated by the agent's team and environment, and injects it to the Terraform Enterprise API" src="/images/warden-prov-tfe-vault-apikey.png" width="860"></p>

1. The user authenticates and the agent holds their ID token.
2. The agent calls Warden presenting both credentials and asserting a role.
3. Warden builds the assertion the referenced spec calls for and sends it to a KMS-backed
   issuer unsigned, where one is configured.
4. The issuer returns it signed.
5. Warden authenticates to the **external vault** and reads
   `secret/tfe/{{agent.team}}/{{agent.env}}`.
6. The vault returns the API token for that team and environment.
7. Warden injects it and forwards.

The credential is served **verbatim** — nothing is minted. What chaining buys is custody:
it stays in the store that manages it, and the read path decides who reaches which one.

:::note[Steps 3–6 run only on a cache miss]
Warden caches the credential, so most requests skip from step 2 to step 7. The entry is
keyed by namespace, the agent's token id and the spec name — plus the user's token id when
the mount carries a user.
:::

### The simpler variant

<p align="center"><img alt="Warden reads a static Terraform Enterprise API token from its encrypted storage and injects it to the Terraform Enterprise API for every caller" src="/images/warden-prov-tfe-inline-apikey.png" width="860"></p>

**Inline.** The credential sits in Warden's storage. Shortest to set up, weakest custody:
one long-lived credential for every caller.

## Credential modes

| Mode | What Terraform Enterprise sees | Where the credential lives |
|---|---|---|
| **Chained** ✅ *recommended* | One long-lived credential, scoped by path | The vault; nothing in Warden |
| **Inline** ⚠️ | One long-lived credential, shared | Warden's storage |

Terraform Enterprise exposes no workload-identity federation and mints nothing per request, so the
credential is long-lived in both rows; what changes is whether Warden holds it.

See the [apikey credential driver](/credential-drivers/apikey/) for every source and spec
key.

## Prerequisites

- Docker and Docker Compose installed and running
- An **HCP Terraform** account or a **Terraform Enterprise** instance (v202001-1+)
- A **TFE API token** (User, Team, or Organization token — see [Token Types](#token-types))

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
warden write auth/jwt/role/tfe-user \
    token_policies="tfe-access" \
    user_claim=sub \
    cred_spec_name=tfe-ops
```

## Step 2: Mount and Configure the Provider

Enable the TFE provider at a path of your choice:

```bash
warden provider enable tfe
```

To mount at a custom path:

```bash
warden provider enable -path=tfe-prod tfe
```

Verify the provider is enabled:

```bash
warden provider list
```

Configure the provider with `auto_auth_path`. This allows clients to authenticate with their JWT directly — no explicit Warden login required:

```bash
warden write tfe/config <<EOF
{
  "tfe_url": "https://app.terraform.io",
  "auto_auth_path": "auth/jwt/",
  "timeout": "30s",
  "max_body_size": 10485760
}
EOF
```

See [Provider configuration](/provider-backends/configuration/) for the full list of common config fields (`proxy_domains`, `timeout`, `tls_skip_verify`, `ca_data`, and more).

For HCP Terraform, the default URL (`https://app.terraform.io`) works out of the box. For Terraform Enterprise, set `tfe_url` to your instance URL:

| Deployment | URL |
|------------|-----|
| HCP Terraform | `https://app.terraform.io` (default) |
| Terraform Enterprise | `https://tfe.example.com` |

Verify the configuration:

```bash
warden read tfe/config
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

warden cred spec create tfe-ops -json '{
  "source": "vault-keyless",
  "min_ttl": 600,
  "max_ttl": 3600,
  "config": {
    "mint_method": "static_apikey",
    "subject_token_source": "warden_identity",
    "assertion_metadata_claims": "team,env",
    "kv2_mount": "secret",
    "secret_path": "tfe/{{agent.team}}/{{agent.env}}"
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
warden cred source create tfe-src -json '{
  "type": "apikey",
  "config": {
    "api_url": "https://app.terraform.io/api/v2",
    "verify_endpoint": "/account/details",
    "display_name": "Terraform Enterprise"
  }
}'

printf '{"source":"tfe-src","min_ttl":3600,"max_ttl":86400,"config":{"api_key":"%s"}}' \
  "$(cat /path/to/tfe-token)" | warden cred spec create tfe-ops -json -
```

Organization tokens cannot reach `/account/details` — use `"verify_endpoint": "/organizations"` for those.

One long-lived credential for every caller. Prefer Option A.

## Step 4: Create a Policy

Create a policy that grants access to the TFE provider gateway:

```bash
warden policy write tfe-access - <<EOF
path "tfe/role/+/gateway*" {
  capabilities = ["create", "read", "update", "delete", "patch"]
}
EOF
```

For fine-grained access control, restrict which TFE API endpoints a role can access:

```bash
warden policy write tfe-readonly - <<EOF
# Organizations (read-only)
path "tfe/role/+/gateway/api/v2/organizations" {
  capabilities = ["read"]
}

path "tfe/role/+/gateway/api/v2/organizations/*" {
  capabilities = ["read"]
}

# Workspaces (read-only)
path "tfe/role/+/gateway/api/v2/organizations/+/workspaces" {
  capabilities = ["read"]
}

# Runs (read-only)
path "tfe/role/+/gateway/api/v2/runs/*" {
  capabilities = ["read"]
}

# State versions (read-only)
path "tfe/role/+/gateway/api/v2/state-versions/*" {
  capabilities = ["read"]
}

# Projects (read-only)
path "tfe/role/+/gateway/api/v2/projects" {
  capabilities = ["read"]
}
EOF
```

Verify:

```bash
warden policy read tfe-access
```

## Step 5: Get a JWT and Make Requests

Get a JWT from your identity provider — see [Obtaining a JWT](/auth-methods/jwt/#obtaining-a-jwt) (the local dev setup issues one from Hydra). Export it as `$JWT_TOKEN`.

Requests use role-based paths. Warden performs implicit JWT authentication and injects the TFE API token automatically.

The URL pattern is: `/v1/tfe/role/{role}/gateway/{api-path}`

Export TFE_ENDPOINT as environment variable:
```bash
export TFE_ENDPOINT="${WARDEN_ADDR}/v1/tfe/role/tfe-user/gateway"
```

### List Organizations

```bash
curl -s "${TFE_ENDPOINT}/api/v2/organizations" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### List Workspaces

```bash
curl -s "${TFE_ENDPOINT}/api/v2/organizations/my-org/workspaces" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### Get Workspace Details

```bash
curl -s "${TFE_ENDPOINT}/api/v2/organizations/my-org/workspaces/my-workspace" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### Create a Run

```bash
curl -s -X POST "${TFE_ENDPOINT}/api/v2/runs" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/vnd.api+json" \
  -d '{
    "data": {
      "attributes": {
        "message": "Triggered via Warden"
      },
      "type": "runs",
      "relationships": {
        "workspace": {
          "data": {
            "type": "workspaces",
            "id": "ws-WORKSPACE_ID"
          }
        }
      }
    }
  }'
```

### List State Versions

```bash
curl -s "${TFE_ENDPOINT}/api/v2/state-versions?filter%5Bworkspace%5D%5Bname%5D=my-workspace&filter%5Borganization%5D%5Bname%5D=my-org" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### List Variables

```bash
curl -s "${TFE_ENDPOINT}/api/v2/workspaces/ws-WORKSPACE_ID/vars" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### List Projects

```bash
curl -s "${TFE_ENDPOINT}/api/v2/organizations/my-org/projects" \
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

## TLS Certificate Authentication

Steps 1-3 above use JWT authentication. Alternatively, you can authenticate with a TLS client certificate. This is useful for workloads that already have X.509 certificates — Kubernetes pods with cert-manager, VMs with machine certificates, or SPIFFE X.509-SVIDs from a service mesh.

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
    default_role=tfe-user
```

### Create a Cert Role

Create a role that binds allowed certificate identities to a credential spec and policy:

```bash
warden write auth/cert/role/tfe-user \
    allowed_common_names="agent-*" \
    token_policies="tfe-access" \
    cred_spec_name=tfe-ops
```

The `allowed_common_names` field supports glob patterns; you can also match on other certificate fields. See [Create a role](/auth-methods/cert/#step-3-create-a-role) for the full set of constraint fields.

### Configure Provider for Cert Auth

Update the provider config to use cert auth:

```bash
warden write tfe/config <<EOF
{
  "tfe_url": "https://app.terraform.io",
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
    -s "https://warden.internal/v1/tfe/role/tfe-user/gateway/api/v2/organizations"
```

## Token Types

HCP Terraform and Terraform Enterprise support several API token types:

| Type | Scope | Can Execute Runs | Quantity | Best For |
|------|-------|-----------------|----------|----------|
| **User** | User's permissions across all orgs | Yes | Multiple per user | Individual developer access |
| **Team** | Team's assigned workspaces | Yes | Multiple per team | CI/CD pipelines, shared access |
| **Organization** | Organization-level settings | No | One per org | Organization management, workspace provisioning |
| **Audit Trail** | Read-only audit data | No | One per org | SIEM integrations, compliance |
| **Agent** | Agent pool communication | No | Multiple per pool | Self-hosted agent pools |

### Token Considerations

- **User tokens** inherit the user's permissions across all organizations they belong to. Best for individual access patterns.
- **Team tokens** are scoped to a team's workspace assignments. Preferred for CI/CD pipelines as they are not tied to a specific person. Teams can have multiple active tokens.
- **Organization tokens** can manage teams and workspaces but **cannot execute runs**. Use them for infrastructure provisioning, not deployment pipelines. Default expiration is 2 years.
- **Audit Trail tokens** provide read-only access to organization audit data. Useful for SIEM integrations (e.g., Splunk).
- **Agent tokens** are used for agent pool communication with HCP Terraform and cannot be used directly for API access.
- All tokens are shown only once on creation — store them securely.

### Rate Limiting

TFE enforces a rate limit of **30 requests per second** per authenticated user. Exceeding this limit returns HTTP 429. Warden does not add additional rate limiting — clients should implement backoff on 429 responses.

### Token Rotation

| Aspect | Details |
|--------|---------|
| **Storage** | API token is stored on the credential spec (not the source) |
| **Validation** | Token is verified at spec creation when the source configures a `verify_endpoint` |
| **Rotation** | Manual — create a new token in TFE and update the spec |
| **Expiration** | Organization tokens: 2 years (default). User/Team tokens: configurable |

**To rotate TFE API tokens:**

1. Create a new token in HCP Terraform or your TFE instance
2. Update the credential spec:
   ```bash
   warden cred spec update tfe-ops \
     -config api_key=your-new-api-token
   ```
3. Revoke the old token in TFE

## Self-Hosted Terraform Enterprise

### Custom CA Certificate

If your TFE instance uses a certificate signed by a private CA:

```bash
CA_DATA=$(base64 < /path/to/corporate-ca.pem)

warden write tfe/config <<EOF
{
  "tfe_url": "https://tfe.internal.corp",
  "ca_data": "${CA_DATA}",
  "auto_auth_path": "auth/jwt/"
}
EOF
```

### Development / Testing (no TLS)

For local development against a TFE instance without TLS:

```bash
warden write tfe/config <<EOF
{
  "tfe_url": "http://localhost:8080",
  "tls_skip_verify": true,
  "auto_auth_path": "auth/jwt/"
}
EOF
```
