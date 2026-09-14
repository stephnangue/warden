---
title: "REST"
description: "Proxy any single-token REST API through Warden: exchange the caller's identity for an upstream token, chain it per user from a vault, or federate Warden's issuer."
---

The REST provider proxies requests to **any single-token REST API** through Warden, with automatic credential injection and policy evaluation. Instead of shipping a dedicated provider per upstream, you point a `rest` mount at the API you want and describe its auth in configuration.

One mount fronts one upstream. Three config fields cover the common conventions:

- **`base_url`** — the upstream API base URL.
- **`token_header`** (+ **`token_prefix`**) — which header the brokered token goes into, and the scheme prefix (`Bearer `, `token `, `SSWS `, …).
- **`headers`** — additional static headers (tenant id, API version, app id) pinned on every request.

The token *value* is always brokered per request from the credential subsystem (per-role minting, rotation, policy, audit) — it is never stored in the mount config.

## How a request flows

Every request through this mount has the same shape: the agent presents its identity and,
on a mount configured for it, the user's; Warden authorizes the call; then it puts a token
in the header `token_header` names and forwards.

What differs is **where that token comes from**, and the options are not equally good —
they differ in whether the upstream can tell *who* the call was for. This mirrors the
[generic MCP provider](/provider-backends/mcp/#how-a-request-flows), because the question is
the same one.

| Mode | The upstream receives | Represents |
|---|---|---|
| **Delegated exchange** ✅ *best when the upstream supports it* | A token minted for **this user**, with the agent recorded as the actor | The user, and the agent acting for them |
| **Chaining** ✅ *best fallback when the upstream has a plain OAuth token endpoint* | A fresh access token minted per mint from **this user's** consented grant, held in OpenBao/Vault | The user |
| **Keyless federation** ✅ *when the upstream federates Warden's issuer* | A token minted for an assertion describing the agent, and optionally the user | The agent |
| **Chained static key** | A long-lived key held in OpenBao/Vault, scoped by the read path | Whoever the path names — a team, or a person |
| **Static inline** ⚠️ *discouraged* | One long-lived key, the same for everybody | Nobody in particular |

Pick the highest row the upstream will accept. The bottom two are for APIs that only ever
issue a static key — which is most of what a `rest` mount fronts. Even then, **chaining it
from a vault beats storing it in Warden**: the key stays where it is managed, and the read
path decides who reaches which key.

### Delegated exchange

The upstream's authorization server mints a token for the user. Three grants do this,
differing in what the upstream's authorization server implements — all are the
[`token_exchange` driver](/credential-drivers/token-exchange/) with a different `grant`.

**RFC 8693** (`grant=rfc8693`) — the user is the subject, the agent the actor, so the issued
token carries both.

<p align="center"><img alt="Warden sends the user's ID token as the subject and the agent's identity as the actor to the server token endpoint, which returns an access token representing the user with the agent recorded as actor, injected to the REST API" src="/images/warden-prov-rest-token-exchange-rfc8693.png" width="860"></p>

**JWT bearer** (`grant=jwt_bearer`, RFC 7523) — the user's token alone as an assertion
grant. No actor is carried, so the upstream sees the user but not which agent acted.

<p align="center"><img alt="Warden presents the user's ID token alone to the server token endpoint as a JWT bearer assertion grant, receiving an access token that it injects to the REST API" src="/images/warden-prov-rest-token-exchange-rfc7523.png" width="860"></p>

**ID-JAG** (`grant=id_jag`) — for an upstream in a different application domain than your
IdP. Two legs inside one mint: the home IdP issues a single-use assertion bound to the
resource's authorization server, which redeems it for an access token.

<p align="center"><img alt="Warden sends the user's ID token and the agent's identity to the home user identity provider, which returns a single-use ID-JAG assertion bound to the resource authorization server; Warden redeems that for an access token and injects it to the REST API" src="/images/warden-prov-rest-token-exchange-idjag.png" width="860"></p>

### Chaining — from OpenBao/Vault

**Use this when the upstream has an ordinary OAuth token endpoint but no delegated
exchange.** An OpenBao/Vault OAuth secrets engine holds each user's refresh token from
their one-time consent and **mints a fresh access token** on every read — the token is not
sitting in storage waiting to be fetched.

<p align="center"><img alt="Warden authenticates to an external vault with a KMS-signed assertion carrying user and agent claims, reads the path rest/creds templated by the user's subject where the OAuth secrets engine mints a fresh access token from that user's stored refresh token, and injects it to the REST API" src="/images/warden-prov-rest-vault-oauth2.png" width="860"></p>

Warden reaches the store keylessly, and `{{user.sub}}` scopes the read per user — one
person's token can never be served to another, enforced by the path rather than by policy
alone.

### Keyless federation

The upstream trusts **Warden's** issuer. Warden mints a short-lived assertion describing
the agent — and, when the spec sets `assertion_user_claims`, the user too — and trades it at
the upstream's token endpoint.

<p align="center"><img alt="Warden builds an assertion carrying user claims and agent claims, has an external KMS sign it, presents it to the server token endpoint for an access token, and injects that to the REST API" src="/images/warden-prov-rest-fed.png" width="860"></p>

Nothing is stored. The KMS leg is optional and **recommended in production**: with a
[`signer` stanza](/configuration/signer/) configured, the issuer's private key never lives
in Warden.

### Chained static key

When the upstream issues nothing but a static key, chaining still buys you something: the
key stays in the vault that manages it, and the read path scopes which callers reach which
key.

<p align="center"><img alt="Warden authenticates to an external vault with a KMS-signed assertion carrying user and agent claims, reads a static API key from the path secret/rest templated by the user's team and the agent's environment, and injects that key to the REST API" src="/images/warden-prov-rest-vault-apikey.png" width="860"></p>

The key is served **verbatim** — there is no token endpoint and nothing is minted. That is
the difference from the chaining row above, where an OAuth engine mints a fresh token per
read: here the credential is a pre-existing static key, kept out of Warden and scoped by
where it sits.

**What the key represents is the path's choice.** The diagram scopes by team —
`secret/rest/{{user.team}}/{{agent.env}}` — but `{{user.sub}}` gives each person their own
key, and `{{agent.sub}}` each agent. The machinery does not change; only the path and the
claims it needs.

Note the path mixes namespaces: the team comes from the **user's** claims, the environment
from the **agent's**. Each must be projected by the producing spec — `assertion_user_claims`
and `assertion_metadata_claims` respectively — and a claim that is named but missing fails
the mint rather than resolving to something broader.

### Static inline ⚠️

One long-lived token, stored encrypted in Warden and injected for every caller.

<p align="center"><img alt="Warden reads a static API key from its encrypted storage and injects it to the REST API for every caller" src="/images/warden-prov-rest-inline-apikey.png" width="860"></p>

The upstream cannot distinguish callers, the token does not expire, and revoking it affects
everyone. Use it only when there is no vault to chain from — the row above is the same
credential with better custody, at the cost of putting that vault on the mint path.

:::note[Credentials are cached]
Whichever mode you choose, the minted credential is cached, so the exchange, vault read or
signing round-trip does not happen on every call. The entry is keyed by namespace, the
agent's token id and the spec name — plus the **user's** token id when the mount carries a
user, so one user's token is never served to another.
:::

## Prerequisites

- A REST API reachable from Warden and a token for it (static API key, or a token mintable by one of Warden's credential sources).

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
  "headers": {"X-Account-Id": "acme", "X-Api-Version": "2024-01"},
  "timeout": "30s"
}
EOF
```

See [Provider configuration](/provider-backends/configuration/) for the full list of common config fields (`proxy_domains`, `timeout`, `tls_skip_verify`, `ca_data`, and more).

Verify the configuration (the token value is never shown — it is brokered per request):

```bash
warden read billing-api/config
```

:::caution[Use the object form for `headers`]
The string form carries exactly **one** `name=value` pair — it is split on the first `=`
and **never on commas**. Writing `"headers": "A=1,B=2"` therefore produces a single header
`A: 1,B=2`, which passes validation because that is a legal header value, and is silently
wrong. Use the object form (or a JSON array of `"name=value"` strings) whenever you pin
more than one header, or when a value contains a comma:

```json
"headers": {"X-Account-Id": "acme", "X-Api-Version": "2024-01"}
```
:::

> **Header validation.** `token_header` and `headers` names/values are validated when you write the config — an invalid HTTP header name or value is rejected immediately rather than failing on every proxied request. Header names are treated case-insensitively, so a static header that differs from `token_header` only in case never shadows the injected token.

## Step 3: Create a Credential Source and Spec

The REST provider injects an `api_key` or `oauth_bearer_token` credential, and rejects any other type. Any source minting one works: `apikey` (static), `oauth2` (client-credentials / refresh), `grafana`, `elastic`, `token_exchange`.

Configure whichever mode you picked above. They appear here in the same order — best first.

### Option A: Delegated exchange

The upstream's authorization server mints a token for the user. Warden authenticates to it
as an OAuth client, and that client credential need not live in Warden either —
`client_auth=kms_private_key_jwt` signs the client assertion with a key held in a KMS,
reached through `secret_spec`:

```bash
warden cred source create billing-exchange-src -json '{
  "type": "token_exchange",
  "config": {
    "token_url": "https://auth.billing.internal/oauth2/token",
    "grant": "rfc8693",
    "client_auth": "kms_private_key_jwt",
    "secret_spec": "idp-client-signer"
  }
}'

warden cred spec create billing-ops -json '{
  "source": "billing-exchange-src",
  "min_ttl": 600,
  "max_ttl": 3600,
  "config": {
    "subject_token_source": "user_identity",
    "actor_token_source": "agent_identity",
    "audience": "https://api.billing.internal",
    "scope": "invoices:read invoices:write"
  }
}'
```

`actor_token_source` is accepted only alongside `subject_token_source=user_identity`. Use
`warden_identity` as the actor when the agent authenticates by certificate or SPIFFE and
has no bearer to forward. For `jwt_bearer` drop the actor; for `id_jag` set the source's
`grant` and add `resource_token_url`. See
[Token exchange](/credential-drivers/token-exchange/).

### Option B: Chaining — a per-user token from OpenBao/Vault

```bash
warden cred source create billing-vault-src -json '{
  "type": "hvault",
  "config": {
    "vault_address": "https://vault.example.com",
    "auth_method": "oidc_federation",
    "jwt_role": "warden-agents",
    "jwt_mount": "jwt",
    "audience": "https://vault.example.com"
  }
}'

warden cred spec create billing-ops -json '{
  "source": "billing-vault-src",
  "min_ttl": 600,
  "max_ttl": 3600,
  "config": {
    "mint_method": "oauth2",
    "subject_token_source": "warden_identity",
    "assertion_user_claims": "sub",
    "oauth2_mount": "rest",
    "credential_name": "{{user.sub}}"
  }
}'
```

Warden reads `rest/creds/<resolved name>`. The `{{user.sub}}` template works **only on the
federation path** — the claims it resolves from come from the exchange, so a templated
`credential_name` on a non-federated source fails closed.

### Option C: Keyless federation

The subject becomes a Warden-minted assertion, traded at the upstream's token endpoint:

```bash
warden cred spec create billing-ops -json '{
  "source": "billing-exchange-src",
  "min_ttl": 600,
  "max_ttl": 3600,
  "config": {
    "subject_token_source": "warden_identity",
    "assertion_audience": "https://api.billing.internal",
    "assertion_user_claims": "sub,email"
  }
}'
```

A Warden-minted subject **must** declare its audience — an assertion with no `aud` is
replayable at any upstream that does not pin one.

### Option D: Chained static key

For an upstream that issues only a static key. The key lives in the vault, and the **spec**
names a `secret_spec` instead of carrying the key.

```bash
# Producer: the key, read from KV v2 through the keyless Vault source
# created in Option B. The team comes from the user's claims, the
# environment from the agent's.
warden cred spec create billing-key -json '{
  "source": "billing-vault-src",
  "min_ttl": 600,
  "max_ttl": 3600,
  "config": {
    "mint_method": "kv2_read",
    "subject_token_source": "warden_identity",
    "assertion_user_claims": "team",
    "assertion_metadata_claims": "env",
    "kv2_mount": "secret",
    "secret_path": "rest/{{user.team}}/{{agent.env}}"
  }
}'

# Consumer: a plain apikey source, with the key named on the spec
warden cred source create billing-apikey-src -json '{
  "type": "apikey",
  "config": {
    "display_name": "Billing"
  }
}'

warden cred spec create billing-ops -json '{
  "source": "billing-apikey-src",
  "min_ttl": 600,
  "max_ttl": 3600,
  "config": {
    "secret_spec": "billing-key"
  }
}'
```

`secret_spec` goes on the **spec** here, not the source — a spec with neither `api_key` nor
`secret_spec` is rejected with *"'api_key' is required"*. The referenced payload supplies
the key under `api_key`; name a different field with `secret_field`.

**Swap the path to change who the key represents.** `{{user.team}}` gives one key per team;
`{{user.sub}}` gives each person their own; `{{agent.sub}}` gives each agent its own. The
mechanism is identical — only the path and the projected claims change.

### Option E: Static API token ⚠️

One long-lived token for every caller, held in Warden. Use this only when there is no vault
to chain from — Option D is the same credential with better custody, at the cost of a vault
dependency on the mint path.

```bash
warden cred source create billing-src -json '{
  "type": "apikey",
  "config": {
    "display_name": "Billing"
  }
}'

printf '{"source":"billing-src","min_ttl":3600,"max_ttl":86400,"config":{"api_key":"%s"}}' \
  "$(cat /path/to/upstream-token)" | warden cred spec create billing-ops -json -
```

The payload goes through stdin so the token never lands in shell history.

An `oauth2` source with `auth_method=client_credentials` sits between C and D: the token is
minted and refreshable, but it represents the client rather than the caller.

```bash
warden cred source create billing-oauth-src -json '{
  "type": "oauth2",
  "config": {
    "token_url": "https://auth.billing.internal/oauth2/token",
    "client_id": "warden-agent",
    "client_secret": "<your-client-secret>",
    "default_scopes": "invoices:read invoices:write"
  }
}'

warden cred spec create billing-ops -json '{
  "source": "billing-oauth-src",
  "min_ttl": 600,
  "max_ttl": 3600
}'
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

Get a JWT from your identity provider — see [Obtaining a JWT](/auth-methods/jwt/#obtaining-a-jwt) (the local dev setup issues one from Hydra). Export it as `$JWT_TOKEN`.

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

### LLM APIs

Most model APIs are single-token REST APIs, so a `rest` mount fronts them the same way —
which is how you put policy and audit in front of a provider Warden ships no dedicated
backend for.

| Upstream | `base_url` | `token_header` | `token_prefix` | `headers` |
|---|---|---|---|---|
| Google Gemini | `https://generativelanguage.googleapis.com` | `x-goog-api-key` | `""` | — |
| Azure OpenAI | `https://<resource>.openai.azure.com` | `api-key` | `""` | — |
| Groq | `https://api.groq.com/openai/v1` | `Authorization` | `Bearer ` | — |
| Together AI | `https://api.together.xyz/v1` | `Authorization` | `Bearer ` | — |
| Fireworks AI | `https://api.fireworks.ai/inference/v1` | `Authorization` | `Bearer ` | — |
| DeepSeek | `https://api.deepseek.com` | `Authorization` | `Bearer ` | — |
| xAI (Grok) | `https://api.x.ai/v1` | `Authorization` | `Bearer ` | — |
| Perplexity | `https://api.perplexity.ai` | `Authorization` | `Bearer ` | — |
| OpenRouter | `https://openrouter.ai/api/v1` | `Authorization` | `Bearer ` | `HTTP-Referer=<url>`, `X-Title=<app>` |

:::caution[Raise `timeout` for model calls]
This provider defaults to **30 seconds**, which is fine for ordinary REST calls and too
short for generation. The dedicated LLM providers default to **120 seconds** — match that
or higher on a `rest` mount fronting a model API, or long completions are cut off
mid-stream:

```bash
warden write llm/config <<EOF
{
  "base_url": "https://api.groq.com/openai/v1",
  "auto_auth_path": "auth/jwt/",
  "timeout": "120s"
}
EOF
```
:::

**Use the dedicated provider where one exists.** Warden ships
[`anthropic`](/provider-backends/anthropic/), [`openai`](/provider-backends/openai/),
[`mistral`](/provider-backends/mistral/) and [`cohere`](/provider-backends/cohere/), which
already know their upstream's header convention and timeout. Reach for `rest` for the
model APIs above, which have no dedicated backend.

**Two model APIs this provider cannot front:**

- **AWS Bedrock** signs with SigV4 rather than presenting a token, so it needs the
  [`aws` provider](/provider-backends/aws/), which verifies and re-signs.
- **Google Vertex AI** wants an OAuth2 access token minted from a service account — a
  `gcp_access_token` credential. This provider accepts only `api_key` and
  `oauth_bearer_token`, and rejects anything else, so use the
  [`gcp` provider](/provider-backends/gcp/). (Gemini on the *generative-language* endpoint
  above is a different API and works fine here, because it takes a plain key.)

## Token Management

| Aspect | Details |
|--------|---------|
| **Storage** | The token lives on the credential spec/source, never in the `rest` mount config |
| **Injection** | Brokered per request and placed in `token_header`; rotated tokens take effect immediately |
| **Rotation** | Static tokens: update the spec (`warden cred spec update`). OAuth2/dynamic: minted and refreshed automatically |
| **Exposure** | `warden read <mount>/config` shows header placement only — never the secret |
