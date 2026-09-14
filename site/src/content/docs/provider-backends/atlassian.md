---
title: "Atlassian"
---

The Atlassian provider enables proxied access to all Atlassian Cloud and Data Center REST APIs through Warden with automatic credential injection and policy evaluation. A single provider type supports every Atlassian product — mount multiple instances with different `atlassian_url` values for Jira, Confluence, Jira Service Management, Bitbucket, Compass, and the Admin API.

## How a request flows

This mount injects an **`api_key`** credential as `Authorization: Basic
<base64(email:token)>` when it carries an `email`, and as `Bearer` otherwise. The question is where that
API token lives.

The recommended setup keeps it in the vault that manages it, read per request.

<p align="center"><img alt="An agent presents the user's ID token and its own identity to Warden, which builds an assertion carrying user and agent claims, has an external KMS sign it, reads the Atlassian API token from an external vault at a path templated by the agent's team and environment, and injects it to the Atlassian API" src="/images/warden-prov-atlassian-vault-apikey.png" width="860"></p>

1. The user authenticates and the agent holds their ID token.
2. The agent calls Warden presenting both credentials and asserting a role.
3. Warden builds the assertion the referenced spec calls for and sends it to a KMS-backed
   issuer unsigned, where one is configured.
4. The issuer returns it signed.
5. Warden authenticates to the **external vault** and reads
   `secret/atlassian/{{agent.team}}/{{agent.env}}`.
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

<p align="center"><img alt="Warden reads a static Atlassian API token from its encrypted storage and injects it to the Atlassian API for every caller" src="/images/warden-prov-atlassian-inline-apikey.png" width="860"></p>

**Inline.** The credential sits in Warden's storage. Shortest to set up, weakest custody:
one long-lived credential for every caller.

## Credential modes

| Mode | What Atlassian sees | Where the credential lives |
|---|---|---|
| **Chained** ✅ *recommended* | One long-lived credential, scoped by path | The vault; nothing in Warden |
| **Inline** ⚠️ | One long-lived credential, shared | Warden's storage |

Atlassian exposes no workload-identity federation and mints nothing per request, so the
credential is long-lived in both rows; what changes is whether Warden holds it.

:::note[Atlassian Cloud needs the email too]
Atlassian Cloud authenticates with `email:api_token` as Basic auth. Warden sends Basic
**only when the credential carries an `email` field**, and falls back to `Bearer` without
one — which Atlassian Cloud rejects. Declare it on the source with
`credential_fields=email` so the value travels with the token; see
[the apikey driver](/credential-drivers/apikey/).
:::

See the [apikey credential driver](/credential-drivers/apikey/) for every source and spec
key.

## Prerequisites

- Docker and Docker Compose installed and running
- An **Atlassian API token** (from [id.atlassian.com/manage-profile/security/api-tokens](https://id.atlassian.com/manage-profile/security/api-tokens)) for Atlassian Cloud, or a **Personal Access Token (PAT)** for Data Center instances

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

### Option A: Chained (recommended)

The flow in the first diagram. The vault holds the credential; Warden reads it per request
and injects it.

This provider needs a second field — **`email`** — beside the key, and that changes the
shape. An adjunct field survives **only** through an `apikey` source that declares it, so
the vault read goes through a *producer* spec and the `apikey` source chains it:

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

# Producer: the whole secret, read from KV v2 — api_key and email together
warden cred spec create atlassian-secret -json '{
  "source": "vault-keyless",
  "min_ttl": 600,
  "max_ttl": 3600,
  "config": {
    "mint_method": "kv2_read",
    "subject_token_source": "warden_identity",
    "assertion_metadata_claims": "team,env",
    "kv2_mount": "secret",
    "secret_path": "atlassian/{{agent.team}}/{{agent.env}}"
  }
}'

# Consumer: an apikey source that declares the adjunct field, chaining the secret
warden cred source create atlassian-src -json '{
  "type": "apikey",
  "config": {
    "api_url": "https://mycompany.atlassian.net",
    "credential_fields": "email",
    "display_name": "Atlassian"
  }
}'

warden cred spec create atlassian-ops -json '{
  "source": "atlassian-src",
  "min_ttl": 600,
  "max_ttl": 3600,
  "config": {
    "secret_spec": "atlassian-secret"
  }
}'
```

The KV secret must hold **both** `api_key` and `email`.

:::caution[Do not point a `static_apikey` spec straight at the vault]
`mint_method=static_apikey` on the `hvault` source yields an `api_key` credential carrying
**the key alone** — adjunct fields are dropped for any non-`apikey` driver. The mount then
takes its fallback branch, which looks identical to a working one from the outside.
Without an `email` Warden falls back to `Bearer`, which Atlassian Cloud rejects. Route the read through the producer above instead.
:::

Both principals are available to the path template: `{{agent.sub}}` is free,
`{{agent.<claim>}}` needs `assertion_metadata_claims`, and `{{user.<claim>}}` needs
`assertion_user_claims` plus a user on the request. Swap `{{agent.team}}` for
`{{user.sub}}` to give each person their own credential. Templates resolve at **mint,
not at write**, so a path naming an unprojected claim is accepted by `spec create` and
fails on the first request.

### Option B: Inline

⚠️ 
```bash
warden cred source create atlassian-src -json '{
  "type": "apikey",
  "config": {
    "api_url": "https://mycompany.atlassian.net",
    "credential_fields": "email",
    "display_name": "Atlassian"
  }
}'

printf '{"source":"atlassian-src","min_ttl":3600,"max_ttl":86400,"config":{"email":"you@example.com","api_key":"%s"}}' \
  "$(cat /path/to/atlassian-token)" | warden cred spec create atlassian-ops -json -
```

One long-lived credential for every caller. Prefer Option A.

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
  -config=credential_fields=email

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

Atlassian Data Center (Jira DC 8.14+, Confluence DC 7.9+, Bitbucket DC 5.5+) supports **Personal Access Tokens (PATs)** as Bearer tokens. The credential source and spec setup follows [Option B in Step 3](#option-b-inline), with one difference: a Data Center PAT authenticates as a plain `Bearer` token, so omit `credential_fields` from the source and the `email` from the spec. Only the provider mount and URL differ:

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

For older Data Center versions without PAT support, use Basic Auth the same way as Atlassian Cloud — configure the source with `credential_fields=email` and include both `email` and `api_key` on the spec.

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
