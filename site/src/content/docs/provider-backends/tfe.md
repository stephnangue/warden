---
title: "TFE"
---

The TFE provider enables proxied access to the Terraform Enterprise (TFE) and HCP Terraform API through Warden. It forwards requests to the TFE REST API (Organizations, Workspaces, Runs, State Versions, Variables, Projects, etc.) with automatic credential injection and policy evaluation. Credentials are injected via the `Authorization: Bearer <token>` header. One credential mode is supported: static API tokens (`apikey` source type). Vault/OpenBao can also be used as a credential source (`hvault` source type).

## Prerequisites

- Docker and Docker Compose installed and running
- An **HCP Terraform** account or a **Terraform Enterprise** instance (v202001-1+)
- A **TFE API token** (User, Team, or Organization token — see [Token Types](#token-types))

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

### Option A: Static API Token

The credential source holds only connection info (`api_url`). The API token is stored on the credential spec below, allowing multiple specs with different tokens to share one source.

First, create an API token in HCP Terraform or your TFE instance:

- **User token:** User Settings > Tokens > Create an API token
- **Team token:** Organization > Settings > Teams > Team API Token > Generate
- **Organization token:** Organization > Settings > API Token > Generate

Save the token (it is only displayed once), then create the Warden credential source and spec:

```bash
warden cred source create tfe-src \
  -type=apikey \
  -rotation-period=0 \
  -config=api_url=https://app.terraform.io/api/v2 \
  -config=verify_endpoint=/account/details \
  -config=auth_header_type=bearer \
  -config=display_name=TFE \
  -config=extra_headers=Content-Type:application/vnd.api+json
```

Create a credential spec that references the credential source. The spec carries the API token and gets associated with tokens at login time.

```bash
warden cred spec create tfe-ops \
  -source tfe-src \
  -config api_key=your-tfe-api-token
```

The API token is validated at creation time via a `GET /account/details` call to the TFE API (SpecVerifier). If the token is invalid, spec creation will fail.

> **Note:** Organization tokens cannot access `/account/details`. For organization tokens, use `-config=verify_endpoint=/organizations` instead.

### Option B: Vault/OpenBao as Credential Source

Instead of storing API tokens directly in Warden, you can store them in a Vault/OpenBao KV v2 secret engine and have Warden fetch them at runtime.

**Prerequisites:** A Vault/OpenBao instance with:
- A KV v2 mount containing your TFE token (e.g., at `secret/tfe/ops` with an `api_key` field)
- An AppRole configured for Warden access

```bash
# Create a Vault credential source
warden cred source create tfe-vault-src \
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
warden cred spec create tfe-ops \
  -source tfe-vault-src \
  -config mint_method=static_apikey \
  -config kv2_mount=secret \
  -config secret_path=tfe/ops
```

The KV v2 secret at `secret/tfe/ops` should contain an `api_key` field with the TFE API token. Warden fetches the secret from Vault on each credential request.

Verify:

```bash
warden cred spec read tfe-ops
```

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
| **Validation** | Token is verified at spec creation via the configured verify endpoint |
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
