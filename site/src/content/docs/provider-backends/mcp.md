---
title: "Generic MCP"
description: "Front any bearer-authenticated MCP server with Warden: the agent and the user it acts for are authenticated, and the upstream token is minted, federated, chained or exchanged per request."
---

The `mcp` provider enables proxied access to **any bearer-authenticated MCP
(Model Context Protocol) server** through Warden. MCP clients (Claude Code,
Cursor, Continue, Cline, Goose, ...) point at Warden instead of the MCP server;
Warden authenticates the caller, mints a bearer token bound to the chosen role,
injects it as `Authorization: Bearer <token>`, and streams JSON or SSE responses
back unchanged. Agents never hold the OAuth token or API key.

This is the MCP provider for any server that takes a bearer token in the
`Authorization` header — Cloudflare, Slack, Linear, Sentry, Notion, GitHub,
Google Cloud, and more. (The one MCP upstream it doesn't cover is AWS, which
signs requests with SigV4 rather than a bearer; that keeps its own `mcp_aws`
provider.)

It accepts every bearer-shaped credential type a role may bind —
`oauth_bearer_token`, `api_key`, `github_token` (the same credspec that backs the
`github` REST provider, see [`mcp-github.md`](/provider-backends/mcp-github/)) and
`gcp_access_token`. The type is a consequence of how you obtain the token, which is
the real decision: [How a request flows](#how-a-request-flows) sets out the options and
ranks them.

> **A REST credential is usually not the MCP credential.** Even when an upstream
> has a `<name>` REST provider, its **MCP** server often authenticates
> differently — Slack's REST API takes a static bot token (`xoxb-…`), but its MCP
> server requires an OAuth user token and rejects the bot token. Check the
> upstream's MCP auth before assuming a shared credspec; the per-upstream notes
> in [`mcp-github.md`](/provider-backends/mcp-github/) and [`mcp-slack.md`](/provider-backends/mcp-slack/) record which shape each server uses.

There is **no canonical generic MCP endpoint**, so this provider has **no default
upstream URL** — you must set `mcp_url` before the mount can serve traffic. A
single mount fronts one product; consumers select the right mount by its
operator-set description, not by reading the URL.

> **Per-upstream recipes.** Concrete, copy-pasteable setups for specific MCP
> servers live in the per-upstream pages [`mcp-github.md`](/provider-backends/mcp-github/) and [`mcp-slack.md`](/provider-backends/mcp-slack/).
> This page is the general operator guide; the per-upstream pages layer
> upstream-specific credential, URL, and quirk notes on top.

## How a request flows

Every request through this mount has the same shape. The agent presents its identity and,
on a mount configured for it, the user's; Warden authorizes the JSON-RPC call against
policy; then it puts a bearer token in `Authorization` and forwards.

What differs — and what the rest of this section is about — is **where that bearer token
comes from**. Warden supports several answers, and they are not equally good: they differ
in whether the upstream can tell *who* the call was for.

| Mode | The upstream receives | Represents |
|---|---|---|
| **Delegated exchange** ✅ *best when the upstream supports it* | A token minted for **this user**, with the agent recorded as the actor | The user, and the agent acting for them |
| **Chaining** ✅ *best fallback when the upstream has a plain OAuth token endpoint* | A fresh access token minted per request from **this user's** consented grant, held in OpenBao/Vault | The user |
| **Keyless federation** ✅ *when the upstream federates Warden's issuer* | A token minted for an assertion describing the agent, and optionally the user | The agent |
| **Static inline** ⚠️ *discouraged* | One long-lived key, the same for everybody | Nobody in particular |
| **OAuth2 browser consent** ⛔ *development only* | A token from one human's consent, shared by every caller of the spec | The person who happened to consent |

The first three are all production-grade — pick whichever the upstream supports, in that
order. Fall to **static inline** only when the upstream offers nothing better, such as a
self-hosted server that authenticates one fixed bearer; even then the key at least stays
inside Warden rather than on an agent host.

**OAuth2 browser consent is not a production option at all.** It needs someone at a browser
to provision, and the grant it captures belongs to one person while serving everyone. Use
it to try an upstream out, then move up the table.

Each mode is worked through below, and the
[credential driver pages](/credential-drivers/) hold the full key reference.

### Delegated exchange

The upstream trusts your identity provider, so Warden trades the tokens it already holds
for one the upstream mints. Three grants do this, and which you use depends on what the
upstream's authorization server implements. All three are the
[`token_exchange` driver](/credential-drivers/token-exchange/) with a different `grant`.

**RFC 8693 token exchange** (`grant=rfc8693`) — the user is the *subject*, the agent is the
*actor*. This is the shape that says "this agent, acting for this user", and the issued
token carries both.

<p align="center"><img alt="Warden sends the user's ID token as the subject and the agent's identity as the actor to the OAuth token endpoint, which returns an access token representing the user with the agent recorded as actor, injected as a bearer token to the MCP server" src="/images/warden-prov-mcp-token-exchange-rfc-8693.png" width="860"></p>

**JWT bearer assertion** (`grant=jwt_bearer`, RFC 7523) — the user's token alone is
presented as an assertion grant. Entra's on-behalf-of flow is this shape. No actor is
carried, so the upstream sees the user but not which agent acted.

<p align="center"><img alt="Warden presents the user's ID token alone to the OAuth token endpoint as a JWT bearer assertion grant, receiving an access token that it injects as a bearer token to the MCP server" src="/images/warden-prov-mcp-token-exchange-rfc-7523.png" width="860"></p>

**ID-JAG cross-app access** (`grant=id_jag`) — for an upstream in a *different*
application domain than your IdP. It runs two legs inside one mint: the home IdP issues a
single-use ID-JAG assertion bound to the resource's authorization server, and that server
redeems it for an access token. Only the final token is returned. It needs
`resource_token_url` for leg 2.

<p align="center"><img alt="Warden sends the user's ID token and the agent's identity to the home user identity provider, which returns a single-use ID-JAG assertion bound to the resource authorization server; Warden redeems that at the resource token endpoint for an access token and injects it to the MCP server" src="/images/warden-prov-mcp-token-exchange-idjag.png" width="860"></p>

Carrying an actor requires the delegation shape: `actor_token_source` may be set only when
`subject_token_source=user_identity`, which is enforced at write.

### Chaining — from OpenBao/Vault

**Use this when the upstream has an ordinary OAuth token endpoint but does not yet support
delegated exchange.** It gets you a genuine per-user access token anyway, which is why it
is the strongest fallback available.

An OpenBao/Vault **OAuth secrets engine** holds each user's *refresh token*, captured once
when they consented. On every read it **mints a fresh access token** from that grant — the
access token is not sitting in storage waiting to be fetched, it is minted on demand and
short-lived. Warden reads the calling user's own credential because the spec's
`credential_name` is templated.

<p align="center"><img alt="Warden authenticates to an external OpenBao or Vault with a KMS-signed assertion carrying user and agent claims, reads the path mcp/creds templated by the user's subject where the OAuth secrets engine mints a fresh access token from that user's stored refresh token, and injects it as a bearer token to the MCP server" src="/images/warden-prov-mcp-vault-minted-access-token.png" width="860"></p>

Two things are worth noticing. Warden reaches the store **keylessly** — it logs in with the
same kind of signed assertion, so there is no store token in Warden's storage either. And
the read is scoped by `{{user.sub}}`, so one user's token can never be served to another:
the isolation is enforced by the path, not merely by policy.

### Keyless federation

The upstream trusts **Warden's** issuer rather than your IdP. Warden mints a short-lived
assertion describing the agent — and, when the spec sets `assertion_user_claims`, the user
too — and trades it at the upstream's token endpoint for an access token.

<p align="center"><img alt="Warden builds an assertion carrying user claims and agent claims, has an external KMS sign it, presents it to the OAuth token endpoint for an access token, and injects that as a bearer token to the MCP server" src="/images/warden-prov-mcp-oidc-federation.png" width="860"></p>

Nothing is stored. As with the AWS providers, the KMS leg is optional and **recommended in
production**: with a [`signer` stanza](/configuration/signer/) configured, the issuer's
private key never lives in Warden.

### Static inline ⚠️

One long-lived API key, stored encrypted in Warden and injected for every caller.

<p align="center"><img alt="Warden reads a static API key from its encrypted storage and injects it as a bearer token to the MCP server for every caller" src="/images/warden-prov-mcp-inline-static-key.png" width="860"></p>

The upstream cannot distinguish callers, the key does not expire, and revoking it affects
everyone at once. Use it when the upstream offers nothing better — a self-hosted server
that authenticates a fixed bearer — and prefer any row above it. Even then, the key lives
only in Warden and never on an agent host, which is the one thing this mode still buys you.

:::note[Credentials are cached]
Whichever mode you choose, the minted credential is cached, so the fetch, exchange or
signing round-trip does not happen on every call. The entry is keyed by namespace, the
agent's token id and the spec name — plus the **user's** token id when the mount carries a
user, so one user's token is never served to another. It lives for the shorter of the
credential's lease and the session.
:::

## Prerequisites

- Docker and Docker Compose installed and running
- A reachable bearer-authenticated MCP server and its base URL
- A credential the upstream accepts: either OAuth2 client/consent details (for
  `oauth_bearer_token`) or a static API token (for `api_key`)
- An MCP client that supports remote MCP servers over HTTP (Claude Code, Cursor,
  Continue, Cline, Goose, ...)

:::note[New to Warden?]
Follow [Local dev setup](/provider-backends/local-dev-setup/) to start a local dev environment (Ory Hydra + a Warden dev server) before Step 1.
:::

## Step 1: Configure JWT Auth and Create a Role

Enable the JWT auth method and point it at your identity provider's JWKS endpoint, then create a role that binds the credential spec and policy. Enabling the mount and configuring the key source is covered once in [JWT auth](/auth-methods/jwt/#step-1-configure-the-key-source) — for the local dev setup.

:::caution[Auth paths are not checked against mounted backends]
`auto_auth_path` is required to be non-empty, but Warden does **not** verify that the mount
it names actually exists — nor for `user_auth_path` or `user_auth_role`. A typo is accepted
at write time and surfaces only when a request arrives and fails to authenticate. Enable
the auth mounts first, and re-read the config after writing it.
:::

```bash
warden auth enable jwt
warden write auth/jwt/config jwks_url=http://localhost:4444/.well-known/jwks.json

# Create a role that binds the credential spec and policy
warden write auth/jwt/role/mcp-user \
    token_policies="mcp-access,mcp-access-calls" \
    user_claim=sub \
    cred_spec_name=mcp-creds
```

### Enable audit logging

So every MCP call is recorded, enable a file audit device once per cluster (a
`warden server -dev` instance ships with none):

```bash
warden audit enable -file-path=/tmp/warden-audit.log file
```

Each gateway request then writes a request/response pair to that file — the agent
identity, the bound credential (`type`/`source_name`/`spec_name`), the policy
decision (the `mcp_decision` for MCP policy rules), and the upstream URL.

## Step 2: Mount and Configure the Provider

Enable the `mcp` provider with a description that identifies the product behind
the mount. Because a `mcp` mount can front any MCP server, the description is how
agents and the discovery flow tell mounts apart — set a clear one:

```bash
warden provider enable -path=cloudflare-mcp -description="Cloudflare MCP (docs + observability)" mcp
```

Verify the provider is enabled:

```bash
warden provider list
```

Configure the provider. **`mcp_url` is required — there is no default.** Point it
at your MCP server's base URL. `timeout` bounds a **single call** and defaults to
**60 seconds** — raise it when individual tool calls run long. A long-lived SSE session is
bounded by `listen_timeout` instead, which still defaults to 10 minutes:

```bash
warden write cloudflare-mcp/config <<EOF
{
  "mcp_url": "https://docs.mcp.cloudflare.com/mcp",
  "auto_auth_path": "auth/jwt/",
  "timeout": "10m",
  "max_body_size": 10485760
}
EOF
```

See [Provider configuration](/provider-backends/configuration/) for the full list of common config fields (`proxy_domains`, `timeout`, `tls_skip_verify`, `ca_data`, and more).

Verify the configuration:

```bash
warden read cloudflare-mcp/config
```

## Step 3: Create a Credential Source and Spec

Configure whichever mode you picked in [How a request flows](#how-a-request-flows). They
appear here in the same order — best first.

### Option A: Delegated exchange

The upstream's authorization server mints a token for the user. The source points at its
token endpoint; the spec says which of your tokens fill the subject and actor slots.

Warden authenticates to that endpoint as an OAuth client, and **that client credential
should not live in Warden either**. `client_auth=kms_private_key_jwt` signs the client
assertion with a key held in a KMS, reached through `secret_spec` — so the source stores
no secret at all:

```bash
warden cred source create mcp-exchange-src -json '{
  "type": "token_exchange",
  "config": {
    "token_url": "https://idp.example.com/oauth2/v1/token",
    "grant": "rfc8693",
    "client_auth": "kms_private_key_jwt",
    "secret_spec": "idp-client-signer"
  }
}'
```

`secret_spec` names a spec that mints a **signing capability** rather than key material —
a Vault [`transit_signer`](/credential-drivers/vault/) spec, say. This method has no inline
form: without `secret_spec` there is nothing to sign with, and it is rejected. Everything
identifying the client travels with the key in the referenced payload, so `client_id`,
`private_key`, `client_assertion_kid`, `client_assertion_alg` and `secret_field` must all
be omitted here.

:::note[Create the referenced spec first]
`secret_spec` is resolved when the source is written, so a name that does not exist yet is
rejected with *"create the secret-yielding spec first"*. A `transit_signer` spec also needs
its **own** `jwt_role` — it is deliberately not inherited from the source, because that
role's policy should grant signing with the one key and nothing more.
:::

Then the spec. **RFC 8693** — the user is the subject, the agent the actor:

```bash
warden cred spec create mcp-creds -json '{
  "source": "mcp-exchange-src",
  "min_ttl": 600,
  "max_ttl": 3600,
  "config": {
    "subject_token_source": "user_identity",
    "actor_token_source": "agent_identity",
    "audience": "https://mcp.example.com",
    "scope": "mcp.read mcp.write"
  }
}'
```

#### Which actor source?

`agent_identity` forwards the agent's own inbound JWT, so it exists **only for an agent
that authenticated with one**. An agent authenticated by client certificate or SPIFFE
X509-SVID has no bearer to forward — there set `actor_token_source=warden_identity` and
Warden mints an assertion describing the agent for the actor slot instead:

```bash
warden cred spec create mcp-creds -json '{
  "source": "mcp-exchange-src",
  "min_ttl": 600,
  "max_ttl": 3600,
  "config": {
    "subject_token_source": "user_identity",
    "actor_token_source": "warden_identity",
    "assertion_audience": "https://idp.example.com",
    "audience": "https://mcp.example.com"
  }
}'
```

| `actor_token_source` | Use when | The upstream trusts |
|---|---|---|
| `agent_identity` | The agent authenticates with a JWT | The agent's own IdP |
| `warden_identity` | The agent authenticates any other way — cert, SPIFFE — or you would rather federate one issuer | Warden's issuer |

Either way `actor_token_source` is accepted only alongside
`subject_token_source=user_identity`: an actor is meaningful only in the delegation shape,
and any other pairing is rejected at write. At most one slot is ever `warden_identity`, so
the `assertion_*` keys apply unambiguously to whichever it is.

**JWT bearer (RFC 7523)** — set the source's `grant` to `jwt_bearer` and drop the actor:

```bash
warden cred spec create mcp-creds -json '{
  "source": "mcp-exchange-src",
  "min_ttl": 600,
  "max_ttl": 3600,
  "config": {
    "subject_token_source": "user_identity",
    "audience": "https://mcp.example.com"
  }
}'
```

**ID-JAG** — set `grant=id_jag` and add `resource_token_url`, the resource authorization
server's endpoint for leg 2. Both legs authenticate as the same client, so one keyless
client credential covers both:

```bash
warden cred source create mcp-idjag-src -json '{
  "type": "token_exchange",
  "config": {
    "token_url": "https://idp.example.com/oauth2/v1/token",
    "resource_token_url": "https://auth.resourceapp.example.com/oauth2/token",
    "grant": "id_jag",
    "client_auth": "kms_private_key_jwt",
    "secret_spec": "idp-client-signer"
  }
}'
```

Where a KMS is not available, `client_secret_post` with an inline `client_id` and
`client_secret` works — see [Token exchange](/credential-drivers/token-exchange/) for every
`client_auth` option and the chaining alternative.

### Option B: Chaining — a per-user token from OpenBao/Vault

**The fallback to reach for when the upstream has an ordinary OAuth token endpoint but no
delegated exchange.** An OpenBao/Vault OAuth secrets engine holds the user's refresh token
from their one-time consent and mints a fresh access token on every read, so the upstream
still receives a token that represents the actual user.

The source is keyless: Warden logs in to the store with a signed assertion rather than a
stored token.

```bash
warden cred source create mcp-vault-src -json '{
  "type": "hvault",
  "config": {
    "vault_address": "https://vault.example.com",
    "auth_method": "oidc_federation",
    "jwt_role": "warden-agents",
    "jwt_mount": "jwt",
    "audience": "https://vault.example.com"
  }
}'

warden cred spec create mcp-creds -json '{
  "source": "mcp-vault-src",
  "min_ttl": 600,
  "max_ttl": 3600,
  "config": {
    "mint_method": "oauth2",
    "subject_token_source": "warden_identity",
    "assertion_user_claims": "sub",
    "oauth2_mount": "mcp",
    "credential_name": "{{user.sub}}"
  }
}'
```

Warden reads `mcp/creds/<resolved name>`, and the engine mints against that user's stored
grant. The `{{user.sub}}` template is what makes it per-user, and it **works only on the
federation path** — the claims it resolves from come from the exchange, so a templated
`credential_name` on a non-federated source fails closed. Pair it with a templated policy
on the store side, so the store enforces the same scoping rather than trusting Warden's
path construction.

`jwt_role` is required on a federated source and names the JWT-auth role the assertion logs
in as; `jwt_mount` defaults to `jwt`. The credential's TTL follows the minted token's own
`expire_time`, so Warden re-mints as it approaches expiry rather than serving a stale one.

### Option C: Keyless federation

The upstream trusts Warden's issuer instead of your IdP. The subject becomes a
Warden-minted assertion:

```bash
warden cred spec create mcp-creds -json '{
  "source": "mcp-exchange-src",
  "min_ttl": 600,
  "max_ttl": 3600,
  "config": {
    "subject_token_source": "warden_identity",
    "assertion_audience": "https://mcp.example.com",
    "assertion_user_claims": "sub,email"
  }
}'
```

A Warden-minted subject **must** declare its audience — an assertion with no `aud` is
replayable at any upstream that does not pin one, so omitting it is rejected with *"field
'assertion_audience': is required when the subject or actor is 'warden_identity'"*. The
exception is a source that derives the audience from its own config, like the `hvault`
source in Option B. `assertion_user_claims` is opt-in and fails closed on a claim the
user's login does not carry; omit it and the assertion describes the agent only.

### Option D: Static inline ⚠️

A single long-lived bearer, injected for every caller. Prefer any option above.

```bash
warden cred source create svc-mcp-src -json '{
  "type": "api_key"
}'

warden cred spec create mcp-creds -json '{
  "source": "svc-mcp-src",
  "min_ttl": 3600,
  "max_ttl": 86400,
  "config": {
    "api_key": "<static-token>"
  }
}'
```

The minted credential is an `api_key`. This fits servers documenting a fixed
`Authorization: Bearer <token>`; a server expecting the token in a non-`Authorization`
header (e.g. `x-api-key`) needs a dedicated provider, not this one.

### Option E: OAuth2 authorization-code — development only

:::danger[Not for production]
This flow binds a **single human's browser consent** to a spec that every caller then
shares, and it cannot be provisioned without someone sitting at a browser. Use it to try an
upstream out locally. In production use Option A, or Option B where the upstream has only
a plain OAuth token endpoint — both give the upstream a token that represents the actual
calling user.
:::

Warden stores the refresh token on the spec and mints a fresh access token per request.
Create an `oauth2` source and an `authorization_code` spec, then run the connect flow once
to record consent. For the **Slack MCP server** (`https://mcp.slack.com/mcp`), see
[`mcp-slack.md`](/provider-backends/mcp-slack/) for the exact endpoints and scopes — the
Cloudflare example below shows the general shape.

```bash
warden cred source create cf-oauth-src -json '{
  "type": "oauth2",
  "config": {
    "auth_url": "https://oauth.cloudflare.com/authorize",
    "token_url": "https://oauth.cloudflare.com/token"
  }
}'

warden cred spec create mcp-creds -json '{
  "source": "cf-oauth-src",
  "min_ttl": 600,
  "max_ttl": 3600,
  "config": {
    "auth_method": "authorization_code",
    "client_id": "<client-id>",
    "client_secret": "<client-secret>",
    "redirect_uri": "http://127.0.0.1:8765/callback",
    "scopes": "<space-separated scopes>"
  }
}'

# One-time browser consent; Warden binds the pinned loopback callback, opens the
# browser, captures the code, and stores the refresh token on the spec
warden cred spec connect mcp-creds
```

> Substitute the upstream's real `auth_url` / `token_url` and the OAuth
> `redirect_uri` you registered with it — the values above are illustrative.
> Re-run `connect` to re-authorize after revoking the grant or rotating the
> secret (`-force` replaces a live grant, `-no-browser` prints the URL on a
> headless host).

The minted credential is an `oauth_bearer_token` — Warden injects its token as
`Authorization: Bearer <token>` and refreshes before expiry.

Verify the spec:

```bash
warden cred spec read mcp-creds
```

## Step 4: Create a Policy

MCP traffic passes through two complementary layers of authorization. The minted
bearer token is the security boundary — its scopes bound what the agent can
actually do at the upstream regardless of what Warden lets through. On top of
that, Warden's MCP policies provide governance-style
restrictions enforced at the gateway: allow- and deny-lists for JSON-RPC
methods, tool names, resource URIs, prompt names, and selected tool arguments.

An MCP policy is **body-authoritative** and **deny-by-default** — Warden
strict-parses the JSON-RPC body and a block grants only what it allow-lists
(`initialize`, `ping`, `notifications/*` and `server/discover` stay exempt for the handshake and discovery). See
[Body-Authoritative Authorization](/concepts/mcp/#body-authoritative-authorization)
for the full semantics and [Denial reasons](/concepts/mcp/#denial-reasons) for the
`rule_type` values recorded on each decision.

The examples below use `capabilities = ["create", "read", "delete"]` — the three
MCP Streamable HTTP verbs on the `/gateway/` URL (POST for JSON-RPC, GET for the
SSE stream, DELETE for session terminate). MCP policy enforcement only fires on the
POST half.

The simplest setup grants the gateway and leans on the token's scopes for
everything. It still takes **two** policies: the capability policy granting the
path, and a wildcard MCP policy — without one, every call is denied
(`no_mcp_policy`):

```bash
warden policy write mcp-access - <<EOF
path "cloudflare-mcp/role/+/gateway*" {
  capabilities = ["create", "read", "delete"]
}
EOF

warden policy write -type mcp mcp-access-calls - <<EOF
path "cloudflare-mcp/role/+/gateway*" {
  methods   { allowed = ["*"] }
  tools     { allowed = ["*"] }
  resources { allowed = ["*"] }
  prompts   { allowed = ["*"] }
}
EOF
```

Bind **both** names on the role — an MCP policy comes into scope by being listed
in `token_policies`, exactly like a capability policy.

A policy that restricts the agent to a vetted set of tools:

```bash
warden policy write mcp-readonly - <<EOF
path "cloudflare-mcp/role/+/gateway*" {
  capabilities = ["create", "read", "delete"]
}
EOF

warden policy write -type mcp mcp-readonly-calls - <<EOF
path "cloudflare-mcp/role/+/gateway*" {
  methods { allowed = ["tools/list", "tools/call", "resources/list", "resources/read"] }
  tools { allowed = ["search_docs", "list_*", "get_*"] }
}
EOF
```

An open-then-subtract shape — allow every method and tool, then blocklist the
dangerous ones. Under deny-by-default the `["*"]` allow-lists are required; the
`denied_*` lists carve exceptions out of them:

```bash
warden policy write mcp-safe - <<EOF
path "cloudflare-mcp/role/+/gateway*" {
  capabilities = ["create", "read", "delete"]
}
EOF

warden policy write -type mcp mcp-safe-calls - <<EOF
path "cloudflare-mcp/role/+/gateway*" {
  methods { allowed = ["*"] }
  tools {
    allowed = ["*"]
    denied  = ["delete_*", "purge_*", "update_*"]
  }
}
EOF
```

When a request hits the MCP policy gate and is denied, Warden returns HTTP 403
with a structured JSON body and an RFC 6750 `WWW-Authenticate` header; MCP client
SDKs surface this to the agent as a tool-call failure with an actionable message.
The audit log records the matched rule and the offending tool/parameter.
An MCP mount with **no MCP policy in scope denies every call** (`no_mcp_policy`).
There is no pass-through default: to leave a mount open, write a wildcard MCP
policy and let the token's scopes enforce authorization upstream.

## Step 5: Point an MCP Client at Warden

Get a JWT from your identity provider — see [Obtaining a JWT](/auth-methods/jwt/#obtaining-a-jwt) (the local dev setup issues one from Hydra). Export it as `$JWT_TOKEN`.

Configure your MCP client to point at the Warden mount. The URL pattern is:

```
${WARDEN_ADDR}/v1/<mount-path>/role/{role}/gateway/
```

For Claude Code, Cursor, Continue, Cline, Goose, and other clients that accept
Streamable HTTP MCP servers via a JSON config block:

```json
{
  "mcpServers": {
    "cloudflare": {
      "type": "http",
      "url": "${WARDEN_ADDR}/v1/cloudflare-mcp/role/mcp-user/gateway/",
      "headers": {
        "Authorization": "Bearer ${JWT_TOKEN}"
      }
    }
  }
}
```

> **Heads-up on `${VAR}` in headers.** MCP clients vary in what they substitute
> in `.mcp.json`. HTTP-transport `headers` values are a known gap — the literal
> `${JWT_TOKEN}` string ships on the wire. Paste the actual values instead of
> `${...}` placeholders, or run the JSON through `envsubst` at deploy time.

### Smoke-test with curl

List the tools the server exposes:

```bash
curl -X POST "${WARDEN_ADDR}/v1/cloudflare-mcp/role/mcp-user/gateway/" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

The trailing slash on `gateway/` matters — Warden composes the upstream URL as
the mount's configured upstream URL plus the gateway suffix.

## TLS Certificate Authentication

Steps 1 and 5 above use JWT authentication. Alternatively, you can authenticate
with a TLS client certificate — useful for workloads that already have X.509
certificates (Kubernetes pods with cert-manager, VMs with machine certificates,
or SPIFFE X.509-SVIDs from a service mesh).

:::note[Prerequisite]
Certificate auth requires mTLS on the Warden listener so the client certificate can be presented during the handshake. See [Enabling mTLS on the listener](/auth-methods/cert/#enabling-mtls-on-the-listener).
:::

Steps 2–4 (provider mount, credential, policy) are identical — the `mcp-access`
policy from Step 4 works for either auth method. Replace Steps 1 and 5 with the
following (substitute your own mount path for `cloudflare-mcp`).

### Enable Cert Auth

```bash
warden auth enable cert
```

### Configure Trusted CA

```bash
warden write auth/cert/config \
    trusted_ca_pem=@/path/to/ca.pem \
    default_role=mcp-user
```

### Create a Cert Role

```bash
warden write auth/cert/role/mcp-user \
    allowed_common_names="agent-*" \
    token_policies="mcp-access,mcp-access-calls" \
    cred_spec_name=mcp-creds
```

The `allowed_common_names` field supports glob patterns; you can also match on other certificate fields. See [Create a role](/auth-methods/cert/#step-3-create-a-role) for the full set of constraint fields.

### Configure Provider for Cert Auth

Point the mount's `auto_auth_path` at the cert mount:

```bash
warden write cloudflare-mcp/config <<EOF
{
  "mcp_url": "https://docs.mcp.cloudflare.com/mcp",
  "auto_auth_path": "auth/cert/",
  "timeout": "10m",
  "max_body_size": 10485760
}
EOF
```

### Make Requests with Certificates

`curl` smoke test, role from the URL path:

```bash
curl --cert client.pem --key client-key.pem \
    --cacert warden-ca.pem \
    -X POST "https://warden.internal/v1/cloudflare-mcp/role/mcp-user/gateway/" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json, text/event-stream" \
    -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

#### MCP Client JSON Config (cert auth)

**State of mTLS in MCP clients today.** The MCP specification does not
standardize a client-side TLS configuration block, and the major IDE clients
(Claude Code, Cursor, Continue) do not currently expose first-class fields for
client certificate / key paths. Until that lands, two portable patterns work —
both using header-routed mode so the MCP client only sets headers, never a deep
URL. Look up the mount path by its description first:

```bash
path=$(warden provider list -o json | jq -r '.[] | select(.description=="<your-mount-description>") | .path' | head -1)
namespace=$WARDEN_NAMESPACE
```

The `path` is the mount path from `warden provider list` (e.g. `cloudflare-mcp/`,
`team-tools/cloudflare-mcp/`), **not** the literal provider type `mcp` — Warden
routes on the mount path.

**Pattern A: Local mTLS-terminating sidecar (recommended).** Run a sidecar
(Envoy, nginx, stunnel, `mtls-proxy`) on the agent host that holds the client
cert/key and trusted CA. The MCP client talks plain HTTP over loopback to the
sidecar; the sidecar terminates client TLS, validates Warden's server cert, and
forwards over mTLS with the validated client certificate attached as
`X-SSL-Client-Cert` (URL-encoded PEM) or `X-Forwarded-Client-Cert`. Warden trusts
the forwarded header when the listener is configured to do so.

```json
{
  "mcpServers": {
    "cloudflare": {
      "type": "http",
      "url": "http://127.0.0.1:9443/",
      "headers": {
        "X-Warden-Provider": "cloudflare-mcp/",
        "X-Warden-Namespace": "<namespace>",
        "X-Warden-Role": "mcp-user"
      }
    }
  }
}
```

Substitute your mount's actual `path` and `<namespace>`; `${VAR}` placeholders in
HTTP-transport `headers` are not expanded by the major clients today. Drop
`X-Warden-Role` when cert auth's `default_role` already covers the binding.

**Pattern B: `mcp-remote` as a Node bridge.** Many installations already use
`mcp-remote` (an npx-launched HTTP-to-stdio bridge). It runs in Node, so Node's
TLS env vars flow through: `NODE_EXTRA_CA_CERTS=/path/to/warden-ca.pem` for a
custom CA. Client-certificate handling via `mcp-remote` needs a custom Node TLS
context and is less turnkey — Pattern A is simpler for full mTLS. A CA-only setup
(validates Warden's server cert; mTLS still needs Pattern A):

```json
{
  "mcpServers": {
    "cloudflare": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "https://warden.internal/",
        "--transport", "http-only",
        "--header", "X-Warden-Provider: cloudflare-mcp/",
        "--header", "X-Warden-Namespace: <namespace>",
        "--header", "X-Warden-Role: mcp-user"
      ],
      "env": { "NODE_EXTRA_CA_CERTS": "/path/to/warden-ca.pem" }
    }
  }
}
```

#### Selecting the role with a certificate

With cert auth, the role resolves (in priority order):

1. `X-Warden-Role` header — what the JSON examples set
2. `/role/<role>/` segment in the URL path — for clients that can't send custom headers
3. `default_role` on the cert auth method's config — useful when one cert maps 1:1 to one role
