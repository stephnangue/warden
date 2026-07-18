---
title: "GitHub MCP"
---

This guide walks through exposing **GitHub's hosted MCP (Model Context Protocol)
server** to agents via Warden's generic [`mcp`](/provider-backends/mcp/) provider. MCP
clients (Claude Code, Cursor, Continue, Cline, Goose, ...) point at Warden instead
of `api.githubcopilot.com`; Warden authenticates the caller, injects a GitHub
token bound to the chosen role as `Authorization: Bearer <token>`, and streams
JSON or SSE responses back unchanged. Agents never hold a GitHub credential.

It accepts two GitHub credential shapes a role may bind, both injected as a Bearer
token:

- **`github_token`** — a GitHub **App** installation token or a **PAT**. This is
  the *same* credspec that backs the `github` REST provider, so one role binding
  grants both REST and MCP reach on the same identity.
- **`oauth_bearer_token`** — an OAuth2 **authorization-code** grant, so an agent
  acts as a *specific consenting GitHub user* (access limited to the intersection
  of the app's permissions and what that user consented to).

## Prerequisites

- Docker and Docker Compose installed and running
- One of: a **GitHub App** (private key + installation ID — recommended,
  short-lived auto-refreshed tokens), a **Personal Access Token** with the scopes
  covering the tools you'll expose, or a **GitHub App** (Client ID + Secret) to
  act as a consenting user via the authorization-code flow ([Option C](#option-c-oauth2-authorization-code-flow-acting-as-a-github-user))
- An MCP client that supports remote MCP servers over HTTP

:::note[New to Warden?]
Follow [Local dev setup](/provider-backends/local-dev-setup/) to start a local dev environment (Ory Hydra + a Warden dev server) before Step 1.
:::

## Step 1: Configure JWT Auth and Create a Role

Enable the JWT auth method and point it at your identity provider's JWKS endpoint, then create a role that binds the credential spec and policy. Enabling the mount and configuring the key source is covered once in [JWT auth](/auth-methods/jwt/#step-1-configure-the-key-source) — for the local dev setup.

> **Set this up before configuring the provider.** Warden validates at
> configuration time that the auth backend referenced by `auto_auth_path` is
> already mounted.

```bash
warden auth enable jwt
warden write auth/jwt/config jwks_url=http://localhost:4444/.well-known/jwks.json

# Create a role that binds the credential spec and policy
warden write auth/jwt/role/mcp-user \
    token_policies="mcp-github-access" \
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
decision (the `mcp_decision` for `mcp { }` rules), and the upstream URL.

## Step 2: Mount and Configure the Provider

Mount the generic `mcp` provider at a path that identifies GitHub, with a clear
description (agents and the discovery flow tell mounts apart by description, not
type):

```bash
warden provider enable -path=github-mcp -description="GitHub Copilot MCP" mcp
```

Configure it. **`mcp_url` is required** — point it at GitHub's hosted MCP
endpoint:

```bash
warden write github-mcp/config <<EOF
{
  "mcp_url": "https://api.githubcopilot.com/mcp",
  "auto_auth_path": "auth/jwt/",
  "timeout": "10m",
  "max_body_size": 10485760
}
EOF
```

See [Provider configuration](/provider-backends/configuration/) for the full list of common config fields (`proxy_domains`, `timeout`, `tls_skip_verify`, `ca_data`, and more).

## Step 3: Create a Credential Source and Spec

If you already configured a `github` source + spec for the `github` REST provider,
**reuse them here unchanged** — bind that spec to the role from Step 1 and skip to
Step 4. The credential source holds connection info (`github_url`); the App
private key + installation ID, or the PAT, live on the spec.

```bash
warden cred source create github-src \
  -type=github \
  -rotation-period=0 \
  -config=github_url=https://api.github.com
```

### Option A: GitHub App (Recommended)

Create a GitHub App, note its **App ID**, generate an RSA **private key**, install
it and note the **Installation ID**, and grant it the permissions covering the
tools you'll use. Then:

```bash
warden cred spec create github-ops \
  -source github-src \
  -config auth_method=app \
  -config app_id=<your-app-id> \
  -config private_key=@/path/to/private-key.pem \
  -config installation_id=<your-installation-id>
```

Warden mints a short-lived (1 hour) installation token per request and refreshes
before expiry. The agent never sees the private key or token.

### Option B: Personal Access Token

```bash
warden cred spec create github-ops \
  -source github-src \
  -config auth_method=pat \
  -config token=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

### Option C: OAuth2 Authorization Code Flow (acting as a GitHub user)

To have an agent act **as a specific GitHub user** — access limited to the
intersection of the app's permissions and what the user consented to — use the
OAuth2 authorization-code flow. A human authorizes once in the browser; Warden
seals the refresh token and mints a fresh access token per request.

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
warden cred source create github-oauth-src \
  -type=oauth2 \
  -rotation-period=0 \
  -config=auth_url=https://github.com/login/oauth/authorize \
  -config=token_url=https://github.com/login/oauth/access_token

warden cred spec create github-ops \
  -source github-oauth-src \
  -config auth_method=authorization_code \
  -config client_id=<your-client-id> \
  -config client_secret=@/path/to/client-secret \
  -config redirect_uri=http://127.0.0.1:8765/callback

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
warden cred source update github-oauth-src \
  -config=introspection_url=https://api.github.com/user \
  -config=metadata_fields=login
```

A response audit event then carries both axes — the agent that called and the
GitHub user it acted as — while the token stays salted:

```json
{
  "type": "response",
  "auth": { "principal_id": "agent-alpha", "actors": [{ "subject": "agent-alpha", "verified": true }] },
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
security boundary) and Warden's CBP `mcp { }` block (governance at the gateway).

The `mcp { }` block is **body-authoritative** and **deny-by-default** — Warden
strict-parses the JSON-RPC body and a block grants only what it allow-lists
(`initialize`, `ping`, and `notifications/*` stay exempt for the handshake). See
[Body-Authoritative Authorization](/concepts/mcp/#body-authoritative-authorization)
for the full semantics and [Denial reasons](/concepts/mcp/#denial-reasons) for the
`rule_type` values recorded on each decision.

GitHub-flavored examples:

The simplest policy grants the gateway and leans on token scopes:

```bash
warden policy write mcp-github-access - <<EOF
path "github-mcp/role/+/gateway*" {
  capabilities = ["create", "read", "delete"]
}
EOF
```

Restrict to a vetted set of GitHub tools:

```bash
warden policy write mcp-github-readonly - <<EOF
path "github-mcp/role/+/gateway*" {
  capabilities = ["create", "read", "delete"]
  mcp {
    allowed_methods = ["tools/list","tools/call","resources/list","resources/read"]
    allowed_tools   = ["get_repository","get_pull_request","list_issues","search_code"]
  }
}
EOF
```

Argument-level gate — permit `create_or_update_file` but never on protected
branches:

```bash
warden policy write mcp-github-no-protected-branches - <<EOF
path "github-mcp/role/+/gateway*" {
  capabilities = ["create", "read", "delete"]
  mcp {
    allowed_methods = ["tools/call"]
    allowed_tools   = ["create_or_update_file"]
    condition = <<-CEL
      !has(call.args.branch) || !(
        call.args.branch in ["main", "master", "production"] ||
        call.args.branch.startsWith("release/")
      )
    CEL
  }
}
EOF
```

`capabilities = ["create", "read", "delete"]` covers MCP's three verbs on the
`/gateway/` URL (POST=create, GET=read for the SSE stream, DELETE=delete for
session close). The `mcp { }` block fires only on the POST half.

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
    token_policies="mcp-github-access" \
    cred_spec_name=github-ops

# Point the mount at the cert auth path
warden write github-mcp/config <<EOF
{
  "mcp_url": "https://api.githubcopilot.com/mcp",
  "auto_auth_path": "auth/cert/",
  "timeout": "10m",
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
