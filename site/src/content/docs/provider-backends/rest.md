---
title: "REST"
---

The REST provider proxies requests to **any single-token REST API** through Warden, with automatic credential injection and policy evaluation. Instead of shipping a dedicated provider per upstream, you point a `rest` mount at the API you want and describe its auth in configuration.

One mount fronts one upstream. Three config fields cover the common conventions:

- **`base_url`** — the upstream API base URL.
- **`token_header`** (+ **`token_prefix`**) — which header the brokered token goes into, and the scheme prefix (`Bearer `, `token `, `SSWS `, …).
- **`headers`** — additional static headers (tenant id, API version, app id) pinned on every request.

The token *value* is always brokered per request from the credential subsystem (per-role minting, rotation, policy, audit) — it is never stored in the mount config.

## Prerequisites

- A REST API reachable from Warden and a token for it (static API key, or a token mintable by one of Warden's credential sources).

> **New to Warden?** Follow these steps to get a local dev environment running:
>
> **1. Deploy the quickstart stack** — this starts an identity provider ([Ory Hydra](https://www.ory.sh/hydra/)) needed to issue JWTs for authentication in Steps 1 and 5:
> ```bash
> curl -fsSL -o docker-compose.quickstart.yml \
>   https://raw.githubusercontent.com/stephnangue/warden/main/deploy/docker-compose.quickstart.yml
> docker compose -f docker-compose.quickstart.yml up -d
> ```
>
> **2. Download the latest Warden binary** from the [releases page](https://github.com/stephnangue/warden/releases/latest) and add it to your `PATH`.
>
> **3. Start the Warden server** in dev mode:
> ```bash
> warden server -dev -dev-root-token=root
> ```
>
> **4. In another terminal window**, export the environment variables for the CLI:
> ```bash
> export WARDEN_ADDR="http://127.0.0.1:8400"
> export WARDEN_TOKEN="root"
> ```

## Step 1: Configure JWT Auth and Create a Role

Set up a JWT auth method and create a role that binds the credential spec and policy. Clients authenticate directly with their JWT — no separate login step is needed.

> **This step must come before configuring the provider.** Warden validates at configuration time that the auth backend referenced by `auto_auth_path` is already mounted.

```bash
# Enable JWT auth if not already enabled
warden auth enable jwt

# Configure JWT with Hydra's JWKS endpoint (from docker-compose.quickstart.yml)
warden write auth/jwt/config jwks_url=http://localhost:4444/.well-known/jwks.json

# Create a role that binds the credential spec and policy
warden write auth/jwt/role/billing-user \
    token_policies="billing-access" \
    user_claim=sub \
    cred_spec_name=billing-ops
```

## Step 2: Mount and Configure the Provider

Enable the provider at a path that names the upstream, and give it a **description** — this is how agents and operators discover what the mount fronts:

```bash
warden provider enable -path=billing-api -description="Internal billing REST API (api.billing.internal)" rest
```

Configure it. `base_url` and `auto_auth_path` are required; the header fields default to `Authorization: Bearer <token>`:

```bash
warden write billing-api/config <<EOF
{
  "base_url": "https://api.billing.internal",
  "auto_auth_path": "auth/jwt/",
  "token_header": "X-Auth-Token",
  "token_prefix": "",
  "headers": "X-Account-Id=acme,X-Api-Version=2024-01",
  "timeout": "30s"
}
EOF
```

Verify the configuration (the token value is never shown — it is brokered per request):

```bash
warden read billing-api/config
```

> **Header values containing commas** (e.g. an `Accept` value like `application/vnd.heroku+json; version=3` is fine, but a comma-bearing value is not) must use the JSON-object form: `"headers": {"Accept": "a,b"}`.

> **Header validation.** `token_header` and `headers` names/values are validated when you write the config — an invalid HTTP header name or value is rejected immediately rather than failing on every proxied request. Header names are treated case-insensitively, so a static header that differs from `token_header` only in case never shadows the injected token.

## Step 3: Create a Credential Source and Spec

The REST provider injects a `TypeAPIKey` or `TypeOAuthBearerToken` credential — any source that mints an `api_key` field works: `apikey` (static), `oauth2` (client-credentials / refresh), `grafana`, `honeycomb`, `elastic`.

### Option A: Static API token

```bash
warden cred source create billing-src \
  -type=apikey \
  -rotation-period=0 \
  -config=display_name=Billing

warden cred spec create billing-ops \
  -source billing-src \
  -config api_key=your-upstream-token
```

### Option B: OAuth2 client-credentials (minted, refreshable)

```bash
warden cred source create billing-oauth-src \
  -type=oauth2 \
  -config=token_url=https://auth.billing.internal/oauth2/token \
  -config=client_id=warden-agent \
  -config=client_secret=your-client-secret \
  -config=scope="invoices:read invoices:write"

warden cred spec create billing-ops \
  -source billing-oauth-src
```

## Step 4: Create a Policy

Grant access to the provider gateway:

```bash
warden policy write billing-access - <<EOF
path "billing-api/role/+/gateway*" {
  capabilities = ["create", "read", "update", "delete", "patch"]
}
EOF
```

## Step 5: Get a JWT and Make Requests

```bash
export JWT_TOKEN=$(curl -s -X POST http://localhost:4444/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=my-agent&client_secret=agent-secret&scope=api:read api:write" \
  | jq -r '.access_token')
```

The URL pattern is `/v1/<mount>/role/{role}/gateway/{api-path}`. Everything after `/gateway/` — path, query, method, body — is forwarded verbatim:

```bash
export BILLING="${WARDEN_ADDR}/v1/billing-api/role/billing-user/gateway"

# GET
curl -s "${BILLING}/v1/invoices?status=open" \
  -H "Authorization: Bearer ${JWT_TOKEN}"

# POST
curl -s -X POST "${BILLING}/v1/invoices" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"customer":"acme","amount":4200}'
```

Warden strips the inbound Warden JWT, injects the upstream token into your configured header (here `X-Auth-Token`), adds the pinned `X-Account-Id`/`X-Api-Version` headers, and forwards to `https://api.billing.internal`. The role may also be supplied via the `X-Warden-Role` header or the mount's `default_role` instead of the URL path.

## Auth Header Recipes

The same provider fronts many APIs by varying three fields. Common upstreams:

| Upstream | `token_header` | `token_prefix` | `headers` |
|---|---|---|---|
| Stripe / HubSpot / Airtable / DigitalOcean / SendGrid | `Authorization` (default) | `Bearer ` (default) | — |
| Notion | `Authorization` | `Bearer ` | `Notion-Version=2022-06-28` |
| Shopify Admin | `X-Shopify-Access-Token` | `""` | — |
| Okta | `Authorization` | `SSWS ` | — |
| Discord (bot) | `Authorization` | `Bot ` | — |
| Snyk | `Authorization` | `token ` | — |
| Linear | `Authorization` | `""` | — |
| Algolia | `X-Algolia-API-Key` | `""` | `X-Algolia-Application-Id=<app>` |
| Postmark | `X-Postmark-Server-Token` | `""` | — |
| Fastly | `Fastly-Key` | `""` | — |
| Twitch (Helix) | `Authorization` | `Bearer ` | `Client-Id=<id>` |

`token_prefix` distinguishes the unset default (`Bearer `) from an explicit empty string (raw token in the header) — set `token_prefix=""` for APIs that want the bare token.

## Configuration Reference

### Provider Config

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `base_url` | string | — | **Required.** Upstream API base URL (HTTPS unless `tls_skip_verify`) |
| `token_header` | string | `Authorization` | Header the brokered token is injected into |
| `token_prefix` | string | `Bearer ` | Prefix prepended to the token; set `""` for a raw token |
| `headers` | key=value | — | Additional static headers injected on every request (override client values) |
| `max_body_size` | int | 10485760 (10 MB) | Maximum request body size in bytes (max 100 MB) |
| `timeout` | duration | `30s` | Request timeout |
| `auto_auth_path` | string | — | **Required.** Auth mount path for implicit authentication (e.g. `auth/jwt/`, `auth/cert/`) |
| `default_role` | string | — | Fallback role when not specified in the URL |
| `tls_skip_verify` | bool | `false` | Skip upstream TLS verification (development only) |
| `ca_data` | string | — | Base64-encoded PEM CA certificate for custom/self-signed CAs |

### Supported Credential Types

| Source `-type` | Credential type | Notes |
|---|---|---|
| `apikey` | `api_key` | Static token on the spec |
| `oauth2` | `oauth_bearer_token` | OAuth2 client-credentials / refresh; token minted and refreshed |
| `grafana`, `honeycomb`, `elastic` | `api_key` | Dynamically minted keys |

All carry the token in the `api_key` field. Git, Kubernetes, and cloud credential types are **not** supported — use their dedicated providers.

## Token Management

| Aspect | Details |
|--------|---------|
| **Storage** | The token lives on the credential spec/source, never in the `rest` mount config |
| **Injection** | Brokered per request and placed in `token_header`; rotated tokens take effect immediately |
| **Rotation** | Static tokens: update the spec (`warden cred spec update`). OAuth2/dynamic: minted and refreshed automatically |
| **Exposure** | `warden read <mount>/config` shows header placement only — never the secret |
