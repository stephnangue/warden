---
title: "PagerDuty"
description: "Proxy the PagerDuty API through Warden: mint an access token per request from OAuth2 client credentials held in a vault."
---

The PagerDuty provider enables proxied access to the PagerDuty REST API v2 through Warden. It forwards requests to PagerDuty endpoints (incidents, services, users, schedules, etc.) with automatic credential injection and policy evaluation. Two credential modes are supported: static API tokens (`apikey` source type) and OAuth2 client credentials (`oauth2` source type).

## How a request flows

This mount injects `Authorization: Bearer <token>` from an **`api_key`** credential. The
question is where that token lives.

The recommended setup keeps it in the vault that manages it, read per request.

<p align="center"><img alt="An agent presents the user's ID token and its own identity to Warden, which builds an assertion carrying user and agent claims, has an external KMS sign it, reads the PagerDuty API token from an external vault at a path templated by the agent's team and environment, and injects it to the PagerDuty API" src="/images/warden-prov-pagerduty-vault-apikey.png" width="860"></p>

1. The user authenticates and the agent holds their ID token.
2. The agent calls Warden presenting both credentials and asserting a role.
3. Warden builds the assertion the referenced spec calls for and sends it to a KMS-backed
   issuer unsigned, where one is configured.
4. The issuer returns it signed.
5. Warden authenticates to the **external vault** and reads
   `secret/pagerduty/{{agent.team}}/{{agent.env}}`.
6. The vault returns the token for that team and environment.
7. Warden injects it and forwards.

The token is served **verbatim** — nothing is minted. What chaining buys is custody: the
token stays in the store that manages it, and the read path decides who reaches which
token.

:::note[Steps 3–6 run only on a cache miss]
Warden caches the credential, so most requests skip from step 2 to step 7. The entry is
keyed by namespace, the agent's token id and the spec name — plus the user's token id when
the mount carries a user.
:::

### The simpler variant

<p align="center"><img alt="Warden reads a static PagerDuty API token from its encrypted storage and injects it to the PagerDuty API for every caller" src="/images/warden-prov-pagerduty-inline-apikey.png" width="860"></p>

**Inline static token.** The token sits in Warden's storage. Shortest to set up, weakest
custody: one long-lived token for every caller.

## Credential modes

| Mode | What PagerDuty sees | Where the token lives |
|---|---|---|
| **Chained static token** ✅ *recommended* | One long-lived token, scoped by path | The vault; nothing in Warden |
| **Inline static token** ⚠️ | One long-lived token, shared | Warden's storage |

:::caution[This provider accepts only `api_key` credentials]
The gateway injects from a `TypeAPIKey` credential and rejects anything else with
`unsupported credential type`. An `oauth2` credential source yields `oauth_bearer_token`,
so **an OAuth2 client-credentials source cannot be used with this mount today** — the spec
and source create cleanly and every proxied call then fails. Use an `apikey` source, as
below.
:::

PagerDuty exposes no workload-identity federation, so a long-lived token exists in both rows;
what changes is whether Warden holds it.

See the [apikey credential driver](/credential-drivers/apikey/) for every source and spec
key.

## Prerequisites

- Docker and Docker Compose installed and running
- A **PagerDuty API Token** (from PagerDuty > Integrations > API Access Keys) **or** a **PagerDuty OAuth2 App** (client_id and client_secret from PagerDuty > Integrations > App Registration)

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
warden write auth/jwt/role/pagerduty-user \
    token_policies="pagerduty-access" \
    user_claim=sub \
    cred_spec_name=pagerduty-ops
```

## Step 2: Mount and Configure the Provider

Enable the PagerDuty provider at a path of your choice:

```bash
warden provider enable pagerduty
```

To mount at a custom path:

```bash
warden provider enable -path=pagerduty-prod pagerduty
```

Verify the provider is enabled:

```bash
warden provider list
```

Configure the provider with `auto_auth_path`. This allows clients to authenticate with their JWT directly — no explicit Warden login required:

```bash
warden write pagerduty/config <<EOF
{
  "pagerduty_url": "https://api.pagerduty.com",
  "auto_auth_path": "auth/jwt/",
  "timeout": "30s",
  "max_body_size": 10485760
}
EOF
```

See [Provider configuration](/provider-backends/configuration/) for the full list of common config fields (`proxy_domains`, `timeout`, `tls_skip_verify`, `ca_data`, and more).

Verify the configuration:

```bash
warden read pagerduty/config
```

## Step 3: Create a Credential Source and Spec

### Option A: Chained static token (recommended)

The flow in the first diagram. The vault holds the token; Warden reads it per request and
injects it.

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

warden cred spec create pagerduty-ops -json '{
  "source": "vault-keyless",
  "min_ttl": 600,
  "max_ttl": 3600,
  "config": {
    "mint_method": "static_apikey",
    "subject_token_source": "warden_identity",
    "assertion_metadata_claims": "team,env",
    "kv2_mount": "secret",
    "secret_path": "pagerduty/{{agent.team}}/{{agent.env}}"
  }
}'
```

The KV secret must carry the token under **`api_key`**.

Both principals are available to the path template: `{{agent.sub}}` is free,
`{{agent.<claim>}}` needs `assertion_metadata_claims`, and `{{user.<claim>}}` needs
`assertion_user_claims` plus a user on the request. Swap `{{agent.team}}` for
`{{user.sub}}` to give each person their own token. Templates resolve at **mint, not at
write**, so a path naming an unprojected claim is accepted by `spec create` and fails on the
first request.

### Option B: Inline static token ⚠️

```bash
warden cred source create pagerduty-src -json '{
  "type": "apikey",
  "config": {
    "api_url": "https://api.pagerduty.com",
    "display_name": "PagerDuty"
  }
}'

printf '{"source":"pagerduty-src","min_ttl":3600,"max_ttl":86400,"config":{"api_key":"%s"}}' \
  "$(cat /path/to/pagerduty-token)" | warden cred spec create pagerduty-ops -json -
```

One long-lived token for every caller. Prefer Option A.

## Step 4: Create a Policy

Create a policy that grants access to the PagerDuty provider gateway:

```bash
warden policy write pagerduty-access - <<EOF
path "pagerduty/role/+/gateway*" {
  capabilities = ["create", "read", "update", "delete", "patch"]
}
EOF
```

For fine-grained access control, restrict which PagerDuty resources and actions a role can use:

```bash
warden policy write pagerduty-readonly - <<EOF
path "pagerduty/role/+/gateway/incidents" {
  capabilities = ["read"]
}

path "pagerduty/role/+/gateway/services" {
  capabilities = ["read"]
}

path "pagerduty/role/+/gateway/users" {
  capabilities = ["read"]
}

path "pagerduty/role/+/gateway/schedules" {
  capabilities = ["read"]
}

path "pagerduty/role/+/gateway/escalation_policies" {
  capabilities = ["read"]
}
EOF
```

Verify:

```bash
warden policy read pagerduty-access
```

## Step 5: Get a JWT and Make Requests

Get a JWT from your identity provider — see [Obtaining a JWT](/auth-methods/jwt/#obtaining-a-jwt) (the local dev setup issues one from Hydra). Export it as `$JWT_TOKEN`.

Requests use role-based paths. Warden performs implicit JWT authentication and injects the PagerDuty token automatically.

The URL pattern is: `/v1/pagerduty/role/{role}/gateway/{api-path}`

Export PD_ENDPOINT as environment variable:
```bash
export PD_ENDPOINT="${WARDEN_ADDR}/v1/pagerduty/role/pagerduty-user/gateway"
```

### List Incidents

```bash
curl -s "${PD_ENDPOINT}/incidents" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### Get Current User

```bash
curl -s "${PD_ENDPOINT}/users/me" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### List Services

```bash
curl -s "${PD_ENDPOINT}/services" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### List On-Call Schedules

```bash
curl -s "${PD_ENDPOINT}/schedules" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### List Escalation Policies

```bash
curl -s "${PD_ENDPOINT}/escalation_policies" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### Create an Incident

```bash
curl -s -X POST "${PD_ENDPOINT}/incidents" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "incident": {
      "type": "incident",
      "title": "Server unreachable",
      "service": {
        "id": "PSERVICE1",
        "type": "service_reference"
      },
      "urgency": "high"
    }
  }'
```

### Acknowledge an Incident

```bash
curl -s -X PUT "${PD_ENDPOINT}/incidents/PINCIDENT1" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "incident": {
      "type": "incident_reference",
      "status": "acknowledged"
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

## OAuth2 client credentials

PagerDuty supports OAuth2 client-credentials, but **this mount cannot use it today**. The
gateway injects from a `TypeAPIKey` credential and rejects anything else; an `oauth2`
credential source yields `oauth_bearer_token`, so the source and spec create cleanly and
every proxied call then fails with `unsupported credential type: oauth_bearer_token`.

Use an `apikey` source — see [Step 3](#step-3-create-a-credential-source-and-spec). Where
you need OAuth2 against PagerDuty, the generic [`rest` provider](/provider-backends/rest/)
accepts both credential shapes and can front the same API.

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
    default_role=pagerduty-user
```

### Create a Cert Role

Create a role that binds allowed certificate identities to a credential spec and policy:

```bash
warden write auth/cert/role/pagerduty-user \
    allowed_common_names="agent-*" \
    token_policies="pagerduty-access" \
    cred_spec_name=pagerduty-ops
```

The `allowed_common_names` field supports glob patterns; you can also match on other certificate fields. See [Create a role](/auth-methods/cert/#step-3-create-a-role) for the full set of constraint fields.

### Configure Provider for Cert Auth

Update the provider config to use cert auth:

```bash
warden write pagerduty/config <<EOF
{
  "pagerduty_url": "https://api.pagerduty.com",
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
    -s "https://warden.internal/v1/pagerduty/role/pagerduty-user/gateway/incidents" \
    -H "Content-Type: application/json"
```

## Token Management

### Static API Token

| Aspect | Details |
|--------|---------|
| **Storage** | API token is stored on the credential spec (not the source) |
| **Validation** | Token is verified at spec creation via `GET /users/me` |
| **Rotation** | Manual — regenerate in PagerDuty and update the spec |
| **Lifetime** | Static — no expiration or auto-refresh |

**To rotate a static API token:**

1. Generate a new API token in PagerDuty (Integrations > API Access Keys)
2. Update the credential spec:
   ```bash
   warden cred spec update pagerduty-ops \
     -config api_key=your-new-api-token
   ```
3. Revoke the old token in PagerDuty

### OAuth2 Client Credentials

| Aspect | Details |
|--------|---------|
| **Storage** | Client credentials are stored on the credential source |
| **Validation** | Spec is verified at creation by minting a test token and calling `GET /users/me` |
| **Rotation** | Client credentials are managed in PagerDuty; bearer tokens are minted automatically |
| **Lifetime** | Bearer tokens have a TTL set by PagerDuty's `expires_in` response field |

Bearer tokens are minted on demand and cached for their TTL. When a token expires, Warden automatically mints a new one using the stored client credentials.

**To rotate OAuth2 client credentials:**

1. Generate new credentials in PagerDuty (Integrations > App Registration)
2. Update the credential source:
   ```bash
   warden cred source update pagerduty-oauth-src \
     -config=client_id=new-client-id \
     -config=client_secret=new-client-secret
   ```
3. Revoke the old credentials in PagerDuty
