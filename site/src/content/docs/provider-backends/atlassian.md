---
title: "Atlassian"
---

The Atlassian provider enables proxied access to all Atlassian Cloud and Data Center REST APIs through Warden with automatic credential injection and policy evaluation. A single provider type supports every Atlassian product — mount multiple instances with different `atlassian_url` values for Jira, Confluence, Jira Service Management, Bitbucket, Compass, and the Admin API.

## Prerequisites

- Docker and Docker Compose installed and running
- An **Atlassian API token** (from [id.atlassian.com/manage-profile/security/api-tokens](https://id.atlassian.com/manage-profile/security/api-tokens)) for Atlassian Cloud, or a **Personal Access Token (PAT)** for Data Center instances

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
warden write auth/jwt/role/atlassian-user \
    token_policies="atlassian-access" \
    user_claim=sub \
    cred_spec_name=atlassian-ops
```

## Step 2: Mount and Configure the Provider

Enable the Atlassian provider at a path of your choice:

```bash
warden provider enable -path=jira atlassian
```

Verify the provider is enabled:

```bash
warden provider list
```

Configure the provider with `auto_auth_path` and the Jira Cloud base URL:

```bash
warden write jira/config <<EOF
{
  "atlassian_url": "https://your-domain.atlassian.net/rest/api/3",
  "auto_auth_path": "auth/jwt/",
  "timeout": "30s",
  "max_body_size": 10485760
}
EOF
```

Verify the configuration:

```bash
warden read jira/config
```

## Step 3: Create a Credential Source and Spec

### Option A: Static Atlassian API Token (Cloud)

Atlassian Cloud personal API tokens require both an email address and the token itself — sent as HTTP Basic Auth (`base64(email:token)`). The `optional_metadata=email` source config instructs Warden to forward the `email` field from the spec into the credential, enabling this injection.

Generate an API token at [id.atlassian.com/manage-profile/security/api-tokens](https://id.atlassian.com/manage-profile/security/api-tokens).

```bash
warden cred source create atlassian-src \
  -type=apikey \
  -rotation-period=0 \
  -config=display_name=Atlassian \
  -config=optional_metadata=email
```

Create a credential spec with both `email` and `api_key`:

```bash
warden cred spec create atlassian-ops \
  -source atlassian-src \
  -config email=fred@example.com \
  -config api_key=ATATT3xFfGF0your-api-token
```

### Option B: Personal Access Token (Data Center)

Atlassian Data Center (Jira DC 8.14+, Confluence DC 7.9+, Bitbucket DC 5.5+) supports Personal Access Tokens (PATs) as Bearer tokens — no email needed. Generate a PAT in your profile settings under **Personal Access Tokens**.

```bash
warden cred source create atlassian-dc-src \
  -type=apikey \
  -rotation-period=0 \
  -config=display_name=AtlassianDC
```

Create a credential spec with only `api_key`:

```bash
warden cred spec create atlassian-ops \
  -source atlassian-dc-src \
  -config api_key=your-personal-access-token
```

For older Data Center versions without PAT support, fall back to Basic Auth by adding `optional_metadata=email` to the source and including both `email` and `api_key` (the account password) on the spec.

### Option C: Vault/OpenBao as Credential Source

For both Cloud and Data Center, credentials can be stored in Vault/OpenBao KV v2 and fetched at runtime.

First, write the secret to Vault. The required keys mirror the credential spec fields:

**Cloud** (Basic Auth — needs `email` + `api_key`):
```bash
vault kv put secret/atlassian/ops \
  email=fred@example.com \
  api_key=ATATT3xFfGF0your-api-token
```

**Data Center** (Bearer — needs only `api_key`):
```bash
vault kv put secret/atlassian/ops \
  api_key=your-personal-access-token
```

Then create the Warden credential source and spec:

```bash
warden cred source create atlassian-vault-src \
  -type=hvault \
  -config=vault_address=https://vault.example.com \
  -config=auth_method=approle \
  -config=role_id=your-role-id \
  -config=secret_id=your-secret-id \
  -config=approle_mount=approle \
  -config=role_name=warden-role \
  -rotation-period=24h

warden cred spec create atlassian-ops \
  -source atlassian-vault-src \
  -config mint_method=static_apikey \
  -config kv2_mount=secret \
  -config secret_path=atlassian/ops
```

Warden reads all keys from the KV secret and populates credential data directly. For Cloud, the `email` key triggers Basic Auth injection automatically — no `optional_metadata` config is needed on the Vault source.

## Step 4: Create a Policy

Create a policy that grants access to the Jira provider gateway:

```bash
warden policy write atlassian-access - <<EOF
path "jira/role/+/gateway*" {
  capabilities = ["create", "read", "update", "delete", "patch"]
}
EOF
```

For multi-product setups, include all mount paths:

```bash
warden policy write atlassian-access - <<EOF
path "jira/role/+/gateway*" {
  capabilities = ["create", "read", "update", "delete", "patch"]
}

path "confluence/role/+/gateway*" {
  capabilities = ["create", "read", "update", "delete", "patch"]
}

path "jira-servicedesk/role/+/gateway*" {
  capabilities = ["create", "read", "update", "delete", "patch"]
}
EOF
```

## Step 5: Get a JWT and Make Requests

Get a JWT from your identity provider — see [Obtaining a JWT](/auth-methods/jwt/#obtaining-a-jwt) (the local dev setup issues one from Hydra). Export it as `$JWT_TOKEN`.

The URL pattern is: `/v1/{mount}/role/{role}/gateway/{api-path}`

Warden appends the `{api-path}` directly to `atlassian_url`, so paths in the examples below are relative to the configured base URL.

```bash
export JIRA_ENDPOINT="${WARDEN_ADDR}/v1/jira/role/atlassian-user/gateway"
```

### Get Current User

```bash
curl -s "${JIRA_ENDPOINT}/myself" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### Search Issues

```bash
curl -s "${JIRA_ENDPOINT}/search?jql=project=MYPROJECT" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### Create an Issue

```bash
curl -s -X POST "${JIRA_ENDPOINT}/issue" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "fields": {
      "project": {"key": "MYPROJECT"},
      "summary": "Test issue created via Warden",
      "issuetype": {"name": "Task"}
    }
  }'
```

### List Projects

```bash
curl -s "${JIRA_ENDPOINT}/project" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

## Multi-Product Setup

Mount one instance of the Atlassian provider per product. Each product has its own `atlassian_url` and may require a dedicated credential spec (Bitbucket uses app passwords; the Admin API uses org keys rather than personal tokens).

### Confluence

```bash
warden provider enable -path=confluence atlassian

warden write confluence/config <<EOF
{
  "atlassian_url": "https://your-domain.atlassian.net/wiki/api/v2",
  "auto_auth_path": "auth/jwt/",
  "timeout": "30s"
}
EOF
```

```bash
export CONFLUENCE_ENDPOINT="${WARDEN_ADDR}/v1/confluence/role/atlassian-user/gateway"

# List spaces
curl -s "${CONFLUENCE_ENDPOINT}/spaces" \
  -H "Authorization: Bearer ${JWT_TOKEN}"

# List pages
curl -s "${CONFLUENCE_ENDPOINT}/pages?spaceKey=MYSPACE" \
  -H "Authorization: Bearer ${JWT_TOKEN}"

# Create a page
curl -s -X POST "${CONFLUENCE_ENDPOINT}/pages" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "spaceId": "123456",
    "status": "current",
    "title": "Test Page",
    "body": {"representation": "storage", "value": "<p>Hello from Warden</p>"}
  }'
```

### Jira Service Management

```bash
warden provider enable -path=jira-servicedesk atlassian

warden write jira-servicedesk/config <<EOF
{
  "atlassian_url": "https://your-domain.atlassian.net/rest/servicedeskapi",
  "auto_auth_path": "auth/jwt/",
  "timeout": "30s"
}
EOF
```

```bash
export JSM_ENDPOINT="${WARDEN_ADDR}/v1/jira-servicedesk/role/atlassian-user/gateway"

# List service desks
curl -s "${JSM_ENDPOINT}/servicedesk" \
  -H "Authorization: Bearer ${JWT_TOKEN}"

# Create a request
curl -s -X POST "${JSM_ENDPOINT}/request" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "serviceDeskId": "1",
    "requestTypeId": "10",
    "requestFieldValues": {"summary": "Request via Warden"}
  }'
```

### Bitbucket Cloud

Bitbucket Cloud uses **app passwords** instead of personal API tokens. Create one at [bitbucket.org/account/settings/app-passwords](https://bitbucket.org/account/settings/app-passwords). Use your Bitbucket username as `email` and the app password as `api_key`.

```bash
warden provider enable -path=bitbucket atlassian

warden write bitbucket/config <<EOF
{
  "atlassian_url": "https://api.bitbucket.org/2.0",
  "auto_auth_path": "auth/jwt/",
  "timeout": "30s"
}
EOF

warden cred source create bitbucket-src \
  -type=apikey \
  -rotation-period=0 \
  -config=display_name=Bitbucket \
  -config=optional_metadata=email

warden cred spec create bitbucket-ops \
  -source bitbucket-src \
  -config email=your-bitbucket-username \
  -config api_key=your-app-password
```

```bash
export BITBUCKET_ENDPOINT="${WARDEN_ADDR}/v1/bitbucket/role/atlassian-user/gateway"

# Get current user
curl -s "${BITBUCKET_ENDPOINT}/user" \
  -H "Authorization: Bearer ${JWT_TOKEN}"

# List repositories
curl -s "${BITBUCKET_ENDPOINT}/repositories/your-workspace" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### Atlassian Admin API

The Admin API uses **org API keys** (not personal tokens), which are injected as Bearer tokens. Generate one at [admin.atlassian.com](https://admin.atlassian.com) under **Settings > API keys**. No `email` field is needed.

```bash
warden provider enable -path=atlassian-admin atlassian

warden write atlassian-admin/config <<EOF
{
  "atlassian_url": "https://api.atlassian.com",
  "auto_auth_path": "auth/jwt/",
  "timeout": "30s"
}
EOF

warden cred source create atlassian-admin-src \
  -type=apikey \
  -rotation-period=0 \
  -config=display_name=AtlassianAdmin

warden cred spec create atlassian-admin-ops \
  -source atlassian-admin-src \
  -config api_key=your-org-api-key
```

## Data Center and Self-Hosted

Atlassian Data Center (Jira DC 8.14+, Confluence DC 7.9+, Bitbucket DC 5.5+) supports **Personal Access Tokens (PATs)** as Bearer tokens. The credential source and spec setup follows [Option B in Step 3](#option-b-personal-access-token-data-center). Only the provider mount and URL differ:

```bash
warden provider enable -path=jira-dc atlassian

warden write jira-dc/config <<EOF
{
  "atlassian_url": "https://jira.company.internal/rest/api/2",
  "auto_auth_path": "auth/jwt/",
  "timeout": "30s"
}
EOF
```

For older Data Center versions without PAT support, use Basic Auth the same way as Atlassian Cloud — configure the source with `optional_metadata=email` and include both `email` and `api_key` on the spec.

## TLS Certificate Authentication

Steps 1 and 5 use JWT authentication. Alternatively, you can authenticate with a TLS client certificate. Steps 2-4 (provider, credential, and policy setup) are identical regardless of the auth method.

:::note[Prerequisite]
Certificate auth requires mTLS on the Warden listener so the client certificate can be presented during the handshake. See [Enabling mTLS on the listener](/auth-methods/cert/#enabling-mtls-on-the-listener).
:::

### Enable Cert Auth

```bash
warden auth enable cert
```

### Configure Trusted CA

```bash
warden write auth/cert/config \
    trusted_ca_pem=@/path/to/ca.pem \
    default_role=atlassian-user
```

### Create a Cert Role

```bash
warden write auth/cert/role/atlassian-user \
    allowed_common_names="agent-*" \
    token_policies="atlassian-access" \
    cred_spec_name=atlassian-ops
```

### Configure Provider for Cert Auth

Update the provider config to reference the cert auth mount:

```bash
warden write jira/config <<EOF
{
  "atlassian_url": "https://your-domain.atlassian.net/rest/api/3",
  "auto_auth_path": "auth/cert/",
  "timeout": "30s"
}
EOF
```

### Make Requests with Certificates

```bash
curl --cert client.pem --key client-key.pem \
    --cacert warden-ca.pem \
    -s "https://warden.internal/v1/jira/role/atlassian-user/gateway/myself"
```

## Authentication Modes

Auth mode is detected automatically from the credential data at request time — no provider config needed.

| Credential data | Header injected | Use case |
|---|---|---|
| `email` + `api_key` | `Authorization: Basic base64(email:api_key)` | Atlassian Cloud personal API tokens; Bitbucket app passwords; Data Center basic auth (pre-PAT) |
| `api_key` only | `Authorization: Bearer api_key` | Data Center PATs (DC 8.14+/7.9+/5.5+); Atlassian Admin API org keys |

> **OAuth 2.0 client credentials (machine-to-machine):** Atlassian Cloud supports `grant_type=client_credentials` for Jira and Confluence, returning Bearer tokens that expire after 1 hour. Storing these as static `api_key` values requires manual rotation every hour. Automated minting and refresh will be supported by a future `atlassian` source driver.
