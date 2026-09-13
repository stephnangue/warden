---
title: "GitHub MCP"
description: "Front GitHub's hosted MCP server with Warden: inject a per-user GitHub token minted at request time, or an App installation token, without the agent ever holding a credential."
---

This guide walks through exposing **GitHub's hosted MCP (Model Context Protocol)
server** to agents via Warden's generic [`mcp`](/provider-backends/mcp/) provider. MCP
clients (Claude Code, Cursor, Continue, Cline, Goose, ...) point at Warden instead
of `api.githubcopilot.com`; Warden authenticates the caller, injects a GitHub
token bound to the chosen role as `Authorization: Bearer <token>`, and streams
JSON or SSE responses back unchanged. Agents never hold a GitHub credential.

## How a request flows

The question this page answers is **whose GitHub identity the tool call runs as**. Two
answers are worth having, and they are not interchangeable:

- **As the calling user** — the agent acts for a person, and GitHub sees that person.
  Branch protection, `CODEOWNERS`, audit attribution and repository permissions all apply
  to them individually.
- **As the app** — the agent acts on its own behalf under a GitHub App installation, with
  permissions granted to the installation rather than to any person.

For the first, an OpenBao/Vault **OAuth secrets engine** holds each user's GitHub refresh
token from their one-time consent and mints a fresh access token per request. Warden reads
the calling user's own credential, because the path is templated by their subject.

<p align="center"><img alt="An agent presents the user's ID token and its own identity to Warden, which authenticates to an external OpenBao or Vault with a KMS-signed assertion carrying user and agent claims, reads the path github/creds templated by the user's subject where the OAuth secrets engine mints a fresh GitHub access token from that user's stored refresh token, and injects it as a bearer token to the GitHub MCP server" src="/images/warden-prov-mcp-github-vault-minted-access-token.png" width="860"></p>

Warden reaches the store keylessly — it logs in with a signed assertion rather than a
stored token — so no GitHub credential and no store token sits in Warden's storage. The
`{{user.sub}}` template is what makes the read per-user: one person's GitHub token can
never be served to another, enforced by the path rather than by policy alone.

This is [the chaining mode](/provider-backends/mcp/#chaining--from-openbaovault) from the
generic MCP page, pointed at a GitHub OAuth engine. It is the production answer whenever
the agent acts for a person.

### Credential shapes

Whichever route you take, the token arrives as a Bearer:

- **`oauth_bearer_token`** — an OAuth2 grant for a GitHub user. Minted per request, either
  from a vault (above) or from a grant stored on the spec (development only).
- **`github_token`** — a GitHub **App** installation token or a **PAT**. The *same*
  credspec that backs the `github` REST provider, so one role binding grants both REST and
  MCP reach on the same identity.

## Prerequisites

- Docker and Docker Compose installed and running
- For [Option A](#option-a-per-user-tokens-from-openbaovault-recommended-for-acting-as-a-user):
  an OpenBao/Vault OAuth secrets engine holding your users' GitHub grants
- For [Option B](#option-b-github-app-installation-token-acting-as-the-app): a **GitHub App**
  — its private key and installation ID
- An MCP client that supports remote MCP servers over HTTP

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
warden write auth/jwt/role/mcp-user \
    token_policies="mcp-github-access,mcp-github-access-calls" \
    user_claim=sub \
    cred_spec_name=github-ops
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

Mount the generic `mcp` provider at a path that identifies GitHub, with a clear
description (agents and the discovery flow tell mounts apart by description, not
type):

```bash
warden provider enable -path=github-mcp -description="GitHub Copilot MCP" mcp
```

Configure it. **`mcp_url` is required** — point it at GitHub's hosted MCP
endpoint. `timeout` bounds a **single call** and defaults to **60 seconds**; a long-lived
SSE session is bounded by `listen_timeout`, which defaults to 10 minutes:

```bash
warden write github-mcp/config <<EOF
{
  "mcp_url": "https://api.githubcopilot.com/mcp",
  "auto_auth_path": "auth/jwt/",
  "max_body_size": 10485760
}
EOF
```

See [Provider configuration](/provider-backends/configuration/) for the full list of common config fields (`proxy_domains`, `timeout`, `tls_skip_verify`, `ca_data`, and more).

## Step 3: Create a Credential Source and Spec

Pick by whose GitHub identity the call should run as. Option A acts as the **calling
user**; Option B acts as the **app**. Options C and D are narrower cases.

If you already configured a `github` source + spec for the `github` REST provider,
**reuse them here unchanged** for Option B or C — bind that spec to the role from Step 1
and skip to Step 4.

### Option A: Per-user tokens from OpenBao/Vault (recommended for acting as a user)

The flow in the diagram above. An OAuth secrets engine holds each user's GitHub grant and
mints an access token per read; Warden resolves the calling user's own path. Nothing
GitHub-related is stored in Warden, and the source is keyless so no store token is either.

```bash
warden cred source create github-vault-src -json '{
  "type": "hvault",
  "config": {
    "vault_address": "https://vault.example.com",
    "auth_method": "oidc_federation",
    "jwt_role": "warden-agents",
    "jwt_mount": "jwt",
    "audience": "https://vault.example.com"
  }
}'

warden cred spec create github-ops -json '{
  "source": "github-vault-src",
  "min_ttl": 600,
  "max_ttl": 3600,
  "config": {
    "mint_method": "oauth2",
    "subject_token_source": "warden_identity",
    "assertion_user_claims": "sub",
    "oauth2_mount": "github",
    "credential_name": "{{user.sub}}"
  }
}'
```

Warden reads `github/creds/<resolved name>`. The mount requires a user leg
(`user_auth_path`) — without a user on the request there is no `{{user.sub}}` to resolve
and the mint fails closed. Pair it with a templated policy on the store side so the store
enforces the same scoping.

Populating the engine — registering the GitHub App and capturing each user's consent — is
OpenBao/Vault-side setup; see its OAuth secrets engine documentation.

### Option B: GitHub App installation token (acting as the app)

The right choice when the agent acts on its own behalf rather than for a person. Create a
GitHub App, note its **App ID**, generate an RSA **private key**, install it and note the
**Installation ID**, and grant it the permissions covering the tools you'll use.

The App's private key is the crown jewel here — anything holding it can mint installation
tokens — so keep it in the store that owns it and let Warden fetch it per mint:

```bash
warden cred source create github-src -json '{
  "type": "github",
  "config": {
    "github_url": "https://api.github.com"
  }
}'

# Producer: the key, read from KV v2 through the keyless Vault source above.
# The path is templated by the agent's team, so one spec serves every team
# and each reaches only its own App key.
warden cred spec create github-app-key -json '{
  "source": "github-vault-src",
  "min_ttl": 600,
  "max_ttl": 3600,
  "config": {
    "mint_method": "kv2_read",
    "subject_token_source": "warden_identity",
    "assertion_metadata_claims": "team",
    "kv2_mount": "secret",
    "secret_path": "github/apps/{{agent.team}}/private-key"
  }
}'

# Consumer: the App spec, with the key sourced rather than stored
warden cred spec create github-ops -json '{
  "source": "github-src",
  "min_ttl": 600,
  "max_ttl": 3600,
  "config": {
    "mint_method": "app",
    "app_id": "<your-app-id>",
    "installation_id": "<your-installation-id>",
    "secret_spec": "github-app-key",
    "secret_field": "private_key"
  }
}'
```

`private_key` is absent from the consumer entirely — Warden fetches the key on each mint
and signs the installation token with it. `secret_field` names which field of the fetched
payload holds the key; store it under `private_key` and you can omit `secret_field`. A
`secret_field` that resolves to an empty or absent field fails loudly rather than quietly
substituting a different key.

**On the templated path.** `{{agent.team}}` resolves from the agent's login-derived
metadata, which reaches the template only when the spec allow-lists it — hence
`assertion_metadata_claims`. The one exception is `{{agent.sub}}`, the raw principal, which
is always projected and needs no listing. A claim that is named but missing from the
agent's login **fails the mint** rather than resolving to something broader, and a resolved
value is checked against a strict allow-list (`A-Za-z0-9._@-`) so it cannot contain a `/`
and span into another team's path. Scope the read on the store side too, with a templated
policy — the path is the coordinate, not the authorization.

Warden mints a short-lived (1 hour) installation token per request and refreshes before
expiry. The agent never sees the private key or the token.

#### Storing the key on the spec instead

Where there is no store to chain from, the key can live on the spec:

Write the payload to a file rather than passing it inline, so the PEM never lands in
shell history — `-json` takes `@file.json`, or `-` to read stdin:

```bash
cat > github-app-spec.json <<EOF
{
  "source": "github-src",
  "min_ttl": 600,
  "max_ttl": 3600,
  "config": {
    "mint_method": "app",
    "app_id": "<your-app-id>",
    "installation_id": "<your-installation-id>",
    "private_key": $(jq -Rs . < /path/to/private-key.pem)
  }
}
EOF

warden cred spec create github-ops -json @github-app-spec.json
rm github-app-spec.json
```

`jq -Rs .` reads the PEM and emits it as a correctly escaped JSON string, so the newlines
survive.

Either way `mint_method=app` requires both `app_id` and `installation_id` — omitting
either is rejected naming it. `mint_method=pat` chains the same way, taking the token from
the fetched payload's `token` field. See
[Credential chaining](/federation/credential-chaining/) and the
[GitHub credential driver](/credential-drivers/github/).

GitHub sees the app, not a person, so per-user branch protection and `CODEOWNERS` rules do
not apply to individuals. Use Option A where that matters.

### Option C: Personal Access Token ⚠️

One person's static token, shared by every caller of the spec, and long-lived.

```bash
printf '{"source":"github-src","min_ttl":3600,"max_ttl":86400,"config":{"mint_method":"pat","token":"%s"}}' \
  "$(cat /path/to/pat)" | warden cred spec create github-ops -json -
```

Warden verifies the PAT against GitHub before storing the spec and rejects an invalid one
with a `401`, so this needs a real token rather than the placeholder above.

Fine for a quick trial; prefer Option A or B otherwise.

### Option D: OAuth2 Authorization Code Flow — development only

:::danger[Not for production]
This binds **one human's browser consent** to a spec every caller then shares, and it
cannot be provisioned without someone at a browser. It reaches the same "act as a GitHub
user" goal as Option A, but for a single fixed user rather than the calling one, with the
grant living in Warden. Use Option A in production.
:::

A human authorizes once in the browser; Warden seals the refresh token and mints a fresh
access token per request.

Refresh tokens come only from a **GitHub App** with user-token expiration enabled
(a classic OAuth App issues a non-expiring user token and no refresh token). Use a
GitHub App, enable **Expire user authorization tokens** in its settings, note the
**Client ID**, generate a **client secret** (distinct from the Option A private
key), and set the app's **Callback URL** to a fixed loopback, e.g.
`http://127.0.0.1:8765/callback`.

This flow uses its own `oauth2` source (not the `github` source above). The user's
effective access is the app's configured **permissions** intersected with the
user's consent — there's no separate scope list to set.

```bash
warden cred source create github-oauth-src -json '{
  "type": "oauth2",
  "config": {
    "auth_url": "https://github.com/login/oauth/authorize",
    "token_url": "https://github.com/login/oauth/access_token"
  }
}'

printf '{"source":"github-oauth-src","min_ttl":600,"max_ttl":3600,"config":{"auth_method":"authorization_code","client_id":"<your-client-id>","client_secret":"%s","redirect_uri":"http://127.0.0.1:8765/callback"}}' \
  "$(cat /path/to/client-secret)" | warden cred spec create github-ops -json -

# One-time browser consent; Warden binds the loopback, captures the code, and
# stores the refresh token on the spec
warden cred spec connect github-ops
```

Re-run `connect` to re-authorize after revoking the grant, changing the app's
permissions, or rotating the secret (`-force` replaces a live grant, `-no-browser`
prints the URL on a headless host).

#### Record the acting user in the audit log

An audit record already captures **who made the request** — the agent identity
(`auth.principal_id` and the verified `auth.actors` chain). With the
authorization-code flow it can also capture **whose GitHub credential was
forwarded** — the consenting user — correlating the two on every proxied call.

That second identity travels in a separate, non-secret **`metadata`** block on the
credential, logged *in the clear* — distinct from the credential's `data` (the raw
token), which the audit layer HMAC-salts by default. Two **source-level** settings
control it:

- `metadata_fields` — comma-separated fields copied into the metadata block
  (default `sub`; empty disables).
- `introspection_url` — GitHub tokens are **opaque** (not JWTs), so Warden GETs
  this userinfo endpoint once per token mint with the access token attached, and
  copies **top-level scalar** fields from the JSON response.

```bash
warden cred source update github-oauth-src -json '{
  "config": {
    "introspection_url": "https://api.github.com/user",
    "metadata_fields": "login"
  }
}'
```

A response audit event then carries both axes — the agent that called and the
GitHub user it acted as — while the token stays salted:

```json
{
  "type": "response",
  "auth": { "principal_id": "agent-alpha", "actors": [{ "subject": "agent-alpha" }] },
  "response": {
    "credential": {
      "type": "oauth_bearer_token",
      "source_name": "github-oauth-src",
      "spec_name": "github-ops",
      "metadata": { "login": "octocat" },
      "data": { "api_key": "hmac-sha256:..." }
    }
  }
}
```

If a captured field is sensitive, add its path to the audit device's `salt_fields`
(e.g. `response.credential.metadata.email`) to HMAC it instead of logging in clear.

## Step 4: Create a Policy

MCP traffic passes through two layers: the minted GitHub token (its scopes are the
security boundary) and Warden's MCP policy (governance at the gateway).

An MCP policy is **body-authoritative** and **deny-by-default** — Warden
strict-parses the JSON-RPC body and a block grants only what it allow-lists
(`initialize`, `ping`, `notifications/*` and `server/discover` stay exempt for the handshake and discovery). See
[Body-Authoritative Authorization](/concepts/mcp/#body-authoritative-authorization)
for the full semantics and [Denial reasons](/concepts/mcp/#denial-reasons) for the
`rule_type` values recorded on each decision.

GitHub-flavored examples:

The simplest setup grants the gateway and leans on token scopes:

```bash
warden policy write mcp-github-access - <<EOF
path "github-mcp/role/+/gateway*" {
  capabilities = ["create", "read", "delete"]
}
EOF

warden policy write -type mcp mcp-github-access-calls - <<EOF
path "github-mcp/role/+/gateway*" {
  methods   { allowed = ["*"] }
  tools     { allowed = ["*"] }
  resources { allowed = ["*"] }
  prompts   { allowed = ["*"] }
}
EOF
```

Bind **both** names on the role — an MCP policy comes into scope by being
listed in `token_policies`, exactly like a capability policy.

Restrict to a vetted set of GitHub tools:

```bash
warden policy write mcp-github-readonly - <<EOF
path "github-mcp/role/+/gateway*" {
  capabilities = ["create", "read", "delete"]
}
EOF

warden policy write -type mcp mcp-github-readonly-calls - <<EOF
path "github-mcp/role/+/gateway*" {
  methods { allowed = ["tools/list","tools/call","resources/list","resources/read"] }
  tools { allowed = ["get_repository","get_pull_request","list_issues","search_code"] }
}
EOF
```

Argument-level gate — permit `create_or_update_file` but never on protected
branches:

```bash
warden policy write mcp-github-no-protected-branches - <<EOF
path "github-mcp/role/+/gateway*" {
  capabilities = ["create", "read", "delete"]
}
EOF

warden policy write -type mcp mcp-github-no-protected-branches-calls - <<EOF
path "github-mcp/role/+/gateway*" {
  methods { allowed = ["tools/call"] }
  tools { allowed = ["create_or_update_file"] }
  condition = <<-CEL
    !has(call.args.branch) || !(
      call.args.branch in ["main", "master", "production"] ||
      call.args.branch.startsWith("release/")
    )
  CEL
}
EOF
```

`capabilities = ["create", "read", "delete"]` covers MCP's three verbs on the
`/gateway/` URL (POST=create, GET=read for the SSE stream, DELETE=delete for
session close). MCP policy enforcement fires only on the POST half.

## Step 5: Point an MCP Client at Warden

Get a JWT from your identity provider — see [Obtaining a JWT](/auth-methods/jwt/#obtaining-a-jwt) (the local dev setup issues one from Hydra). Export it as `$JWT_TOKEN`.

Then point the client at the mount. The URL pattern is:

```
${WARDEN_ADDR}/v1/github-mcp/role/{role}/gateway/
```

> **Keep the trailing slash on `gateway/`** — it is **required**. GitHub's MCP
> server is served at `https://api.githubcopilot.com/mcp/`, and Warden forwards
> the path after `gateway` verbatim, so `gateway/` reaches `…/mcp/`. (This is the
> *opposite* of Slack's MCP server, which rejects the trailing slash.)

### Claude Code (CLI)

```bash
claude mcp add --transport http github \
  "${WARDEN_ADDR}/v1/github-mcp/role/mcp-user/gateway/" \
  --header "Authorization: Bearer ${JWT_TOKEN}"
```

The `role` segment selects which credential spec — and thus which GitHub identity
(App, PAT, or consenting user) — backs the calls.

### Smoke-test with curl

```bash
curl -X POST "${WARDEN_ADDR}/v1/github-mcp/role/mcp-user/gateway/" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'

curl -X POST "${WARDEN_ADDR}/v1/github-mcp/role/mcp-user/gateway/" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_issues","arguments":{"owner":"myorg","repo":"myrepo"}}}'
```

## TLS Certificate Authentication

Steps 1 and 5 use JWT authentication. Alternatively, authenticate with a TLS
client certificate — useful for workloads that already have X.509 certificates
(Kubernetes pods with cert-manager, VMs, SPIFFE X.509-SVIDs). Steps 2–4 are
unchanged; replace Steps 1 and 5 with the following.

:::note[Prerequisite]
Certificate auth requires mTLS on the Warden listener so the client certificate can be presented during the handshake. See [Enabling mTLS on the listener](/auth-methods/cert/#enabling-mtls-on-the-listener).
:::

```bash
# Enable cert auth and trust your CA
warden auth enable cert
warden write auth/cert/config trusted_ca_pem=@/path/to/ca.pem default_role=mcp-user

# Bind allowed cert identities to the credential spec and policy
warden write auth/cert/role/mcp-user \
    allowed_common_names="agent-*" \
    token_policies="mcp-github-access,mcp-github-access-calls" \
    cred_spec_name=github-ops

# Point the mount at the cert auth path
warden write github-mcp/config <<EOF
{
  "mcp_url": "https://api.githubcopilot.com/mcp",
  "auto_auth_path": "auth/cert/",
  "max_body_size": 10485760
}
EOF
```

`curl` smoke test, role from the URL path:

```bash
curl --cert client.pem --key client-key.pem --cacert warden-ca.pem \
    -X POST "https://warden.internal/v1/github-mcp/role/mcp-user/gateway/" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json, text/event-stream" \
    -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

For MCP-client mTLS patterns (local terminating sidecar, or `mcp-remote` as a
Node bridge) and role selection with a certificate, see the [generic provider
README](/provider-backends/mcp/#tls-certificate-authentication) — the patterns are
identical; substitute this mount's `path` (`github-mcp/`).

## Token Scopes and Tool Availability

GitHub's MCP server enforces upstream permissions per tool. Which tools succeed is
determined by the **bound token's permissions**, not Warden policy — a `403` or
`tool not available` usually means a missing scope. Common mappings:

| Tool family | GitHub App permission | PAT scope |
|-------------|------------------------|-----------|
| Repository read | `Contents: Read` | `repo` / `Contents: Read` |
| Issues | `Issues: Read/Write` | `repo` / `Issues: Read/Write` |
| Pull requests | `Pull requests: Read/Write` | `repo` / `Pull requests: Read/Write` |
| Actions | `Actions: Read/Write` | `workflow` |

**Rotate a PAT**: `warden cred spec update github-ops -config token=ghp-new-token`,
then revoke the old one on GitHub. **App tokens** auto-mint and need no rotation;
to rotate the App's private key, update the spec with the new
`private_key=@/path/to/new-key.pem` and delete the old key on GitHub.
