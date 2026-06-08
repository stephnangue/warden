# Slack MCP through Warden

This guide walks through exposing the **Slack MCP (Model Context Protocol)
server** to agents via Warden's generic [`mcp`](../README.md) provider. MCP
clients (Claude Code, Cursor, Continue, Cline, Goose, ...) point at Warden
instead of `mcp.slack.com`; Warden authenticates the caller, mints a Slack OAuth
access token bound to the chosen role, injects it as `Authorization: Bearer
<token>`, and streams JSON or SSE responses back unchanged. Agents never hold the
Slack token.

The Slack MCP server authenticates with **OAuth 2.0 (confidential client),
user-level permissions** — there is **no bot-token (`xoxb-…`) path**. A human
authorizes the app once in the browser; Warden seals the resulting refresh token
and mints a fresh access token on each request, scoped to what that user
consented to. This is the `mcp` provider's `oauth_bearer_token` credential shape.

> **This is not the same credential as the `slack` REST provider.** The `slack`
> REST provider injects a static bot token (`xoxb-…`, modelled as `api_key`). The
> Slack **MCP** server does not accept that token — it requires an OAuth user
> token. The two mounts therefore use different credentials and cannot share a
> credspec.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Step 1: Configure JWT Auth and Create a Role](#step-1-configure-jwt-auth-and-create-a-role)
- [Step 2: Mount and Configure the Provider](#step-2-mount-and-configure-the-provider)
- [Step 3: Register a Slack OAuth App and Create the Credential](#step-3-register-a-slack-oauth-app-and-create-the-credential)
- [Step 4: Create a Policy](#step-4-create-a-policy)
- [Step 5: Point an MCP Client at Warden](#step-5-point-an-mcp-client-at-warden)
- [TLS Certificate Authentication](#tls-certificate-authentication)
- [Configuration Reference](#configuration-reference)
- [Token Scopes and Tool Availability](#token-scopes-and-tool-availability)

## Prerequisites

- Docker and Docker Compose installed and running
- A **Slack app that is allowed to use MCP.** Slack restricts MCP to **internal
  apps** (built for and installed in your own workspace/org) or
  **directory-published** (Marketplace) apps — *unlisted apps are prohibited from
  using MCP*. The app must have a **fixed app ID**, and a **workspace admin** must
  approve the MCP client integration.
- That app configured as a **confidential OAuth client** (Client ID + Client
  Secret) with the **user-token scopes** covering the tools you want to expose
  (e.g. `channels:history`, `chat:write`, `search:read.public`), and a redirect
  URL you control registered on it
- An MCP client that supports remote MCP servers over HTTP (Claude Code, Cursor,
  Continue, Cline, Goose, ...)

> **New to Warden?** Follow the standard quickstart flow used by the other
> provider READMEs (the `github` and `slack` READMEs cover it step by step):
> deploy the quickstart compose, install the binary, export `WARDEN_ADDR` and
> `WARDEN_TOKEN`, then return here.

## Step 1: Configure JWT Auth and Create a Role

Set up a JWT auth method and create a role that binds the credential spec and
policy. Clients authenticate directly with their JWT — no separate login step is
needed.

> **Set this up before configuring the provider.** The provider resolves
> `auto_auth_path` per request — writing the config only checks that it is
> non-empty, not that the mount exists — so a gateway call fails with `no auth
> mount registered ... for implicit auth` if the referenced auth mount isn't
> there yet.

```bash
# Enable JWT auth if not already enabled
warden auth enable jwt

# Configure JWT with Hydra's JWKS endpoint (from docker-compose.quickstart.yml)
warden write auth/jwt/config jwks_url=http://localhost:4444/.well-known/jwks.json

# Create a role that binds the credential spec and policy
warden write auth/jwt/role/mcp-user \
    token_policies="mcp-slack-access" \
    user_claim=sub \
    cred_spec_name=slack-mcp-creds
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

Enable the generic `mcp` provider at a path that identifies Slack, with a
description that names the product behind the mount. Because a `mcp` mount can
front any MCP server, the description is how agents and the discovery flow tell
mounts apart — set a clear one:

```bash
warden provider enable -path=slack-mcp -description="Slack MCP — workspace acme, user-consented" mcp
```

Verify the provider is enabled:

```bash
warden provider list
```

Configure the provider. **`mcp_url` is required — there is no default.** Point it
at Slack's MCP endpoint. The default `timeout` is 10 minutes — raise it for agent
sessions that keep an SSE stream open across many tool calls:

```bash
warden write slack-mcp/config <<EOF
{
  "mcp_url": "https://mcp.slack.com/mcp",
  "auto_auth_path": "auth/jwt/",
  "timeout": "10m",
  "max_body_size": 10485760
}
EOF
```

Verify the configuration:

```bash
warden read slack-mcp/config
```

## Step 3: Register a Slack OAuth App and Create the Credential

The Slack MCP server is an OAuth 2.0 **resource server** that consumes
user-scoped access tokens. Warden plays the OAuth client: a human consents once,
Warden seals the refresh token, and mints a fresh access token per request,
injecting it as `Authorization: Bearer <token>`. Slack does **not** support
Dynamic Client Registration, so you register a confidential app up front — and it
only returns a refresh token when the app has **Token Rotation** enabled (step 5
below), so don't skip that.

### Register the Slack app

Slack's MCP overview documents the *requirements* but not the click-by-click app
setup, so the steps below combine the MCP-specific constraints (from Slack's
docs) with Slack's standard app-creation flow. Exact UI labels may shift.

1. **Create the app.** Go to <https://api.slack.com/apps>, sign in to the
   workspace/org that will use it, and click **Create New App → From scratch**.
   Enter a name (e.g. `warden-mcp`) and pick the workspace, then **Create App**.

2. **Enable the app for MCP — this is the gate that bites silently.** In the app
   config under **Agents & AI Apps** (URL `https://api.slack.com/apps/<APP_ID>/app-assistant`),
   enable the Agents & AI Apps feature, then turn on the **Model Context Protocol**
   toggle. Skipping this is *not* caught at consent time — the OAuth flow succeeds
   and tokens mint fine, but every MCP call returns HTTP 400 with
   `{"error":{"code":-32600,"message":"App is not enabled for Slack MCP server access..."}}`.
   Enabling the feature also unlocks the assistant-related scopes.

3. **Keep it internal — this is the MCP gate.** Under **Settings → Manage
   Distribution**, leave **public distribution OFF**. Slack permits **internal**
   apps (installed only in your own org) or **Marketplace-published** apps, and
   **prohibits "unlisted" apps** — one where public distribution is on but the app
   was never listed. So keep it private (internal), or go all the way to a
   Marketplace listing; don't stop in between. If your workspace enforces app
   approval, a **workspace admin** must approve the app (Slack admin console →
   **Manage apps**).

4. **Add the user-token scopes.** Under **OAuth & Permissions → Scopes → User
   Token Scopes** (not *Bot* Token Scopes — the MCP server uses the user-token
   `v2_user` flow), add the scopes for the tools you'll expose, e.g.
   `channels:history`, `channels:read`, `chat:write`, `users:read`,
   `search:read.public`. See
   [Token Scopes and Tool Availability](#token-scopes-and-tool-availability).

5. **Register the redirect URL.** Under **OAuth & Permissions → Redirect URLs →
   Add New Redirect URL**, enter the loopback callback Warden will use — it must
   **exactly match** the `redirect_uri` on the cred spec below, e.g.
   `http://127.0.0.1:8765/callback`. Click **Add → Save URLs**.

6. **Enable Token Rotation.** Under **OAuth & Permissions**, turn on **Token
   Rotation**. This is required for Warden's refresh-on-demand model: *without it,
   Slack issues a long-lived, non-expiring access token and **no refresh token**,*
   so the consent in the next section returns only an access token. With it on,
   the OAuth response carries a 12-hour access token (`xoxe.` prefix,
   `expires_in: 43200`) **and** a refresh token, which Warden seals and rotates.
   ⚠️ **Irreversible** — once enabled, token rotation cannot be turned off, so test
   on a throwaway app first if you're unsure.

7. **Grab the credentials.** Under **Basic Information → App Credentials**, copy
   the **Client ID** and **Client Secret** (and note the **App ID** — Slack
   requires a fixed app ID for MCP). Store the client secret in a file for the
   next step so it never lands in shell history.

8. **Install / get admin approval.** Under **OAuth & Permissions → Install to
   Workspace**, review the requested user scopes and authorize. If admin approval
   is required, an admin approves it in the admin console.

### Create the Warden credential

Slack publishes OAuth server metadata for the MCP endpoint, so you can confirm
the endpoints below via discovery:

- `https://mcp.slack.com/.well-known/oauth-protected-resource`
- `https://mcp.slack.com/.well-known/oauth-authorization-server`

Create the `oauth2` source pointing at Slack's authorize and token endpoints:

```bash
warden cred source create slack-oauth-src \
  -type=oauth2 \
  -rotation-period=0 \
  -config=auth_url=https://slack.com/oauth/v2_user/authorize \
  -config=token_url=https://slack.com/api/oauth.v2.user.access
```

Create the spec carrying the app's OAuth client credentials, the pinned callback,
and the requested scopes. The client secret is read from a file so it never lands
in shell history:

```bash
warden cred spec create slack-mcp-creds \
  -source slack-oauth-src \
  -config auth_method=authorization_code \
  -config client_id=<your-client-id> \
  -config client_secret=@/path/to/client-secret \
  -config redirect_uri=http://127.0.0.1:8765/callback \
  -config scopes="channels:read channels:history chat:write users:read search:read.public"
```

Complete the one-time consent. Warden binds the pinned loopback port, opens the
browser to Slack, captures the authorization code on the redirect, and exchanges
it for tokens server-side — the client secret never leaves the server:

```bash
warden cred spec connect slack-mcp-creds
```

Re-run `connect` whenever you need to re-authorize — after revoking the grant,
changing the app's scopes, or rotating the secret. Add `-force` to replace a live
authorization without the confirmation prompt, or `-no-browser` on a headless
host to print the URL to open elsewhere.

> **Only got an access token, no refresh token?** Slack returns a refresh token
> only when the app has **Token Rotation** enabled (step 5 of *Register the Slack
> app*). With it off, Slack issues a non-expiring access token and no refresh
> token — usable, but a long-lived secret that never auto-rotates. Enable Token
> Rotation on the app, then re-run `warden cred spec connect slack-mcp-creds
> -force` to obtain the rotating access + refresh pair.

Verify:

```bash
warden cred spec read slack-mcp-creds
```

The agent's effective access is the intersection of three things: the app's
configured scopes, what the user granted at consent time, and what the Warden
policy bound to the role permits (the `mcp { }` block — see [Step 4](#step-4-create-a-policy)).
The OAuth token bounds what Slack will allow; the Warden policy can only narrow
it further, never widen it. See
[Token Scopes and Tool Availability](#token-scopes-and-tool-availability).

#### Record the acting user in the audit log

An audit record already captures **who made the request** — the agent identity
(`auth.principal_id` and the verified `auth.actors` chain). With the
authorization-code flow it can also capture **whose Slack identity was
forwarded** — the consenting user — so the two are correlated on every proxied
call.

That second identity travels in a separate, non-secret **`metadata`** block on
the credential, logged *in the clear* — distinct from the credential's `data`
(the raw token), which the audit layer HMAC-salts by default. Two **source-level**
settings control it:

- `metadata_fields` — comma-separated fields to copy into the metadata block
  (default `sub`; empty disables).
- `introspection_url` — Slack user tokens are **opaque** (not JWTs), so Warden
  cannot decode identity locally. Warden GETs this endpoint once per token mint
  with the access token attached and copies **top-level scalar** fields from the
  JSON response.

Slack's `auth.test` needs no extra scope and returns flat `user_id`, `user`,
`team_id`, `team` fields (use it rather than the nested `users.identity`, whose
`user.id`/`user.email` live under a sub-object that the top-level extractor skips):

```bash
warden cred source update slack-oauth-src \
  -config=introspection_url=https://slack.com/api/auth.test \
  -config=metadata_fields=user_id,user,team_id
```

A response audit event for an MCP call then carries both axes — the agent that
called, and the Slack user it acted as — while the token stays salted:

```json
{
  "type": "response",
  "auth": {
    "principal_id": "agent-alpha",
    "actors": [{ "subject": "agent-alpha", "verified": true }]
  },
  "response": {
    "credential": {
      "type": "oauth_bearer_token",
      "source_name": "slack-oauth-src",
      "spec_name": "slack-mcp-creds",
      "metadata": { "user_id": "U12345678", "user": "grace", "team_id": "T12345678" },
      "data": { "api_key": "hmac-sha256:..." }
    }
  }
}
```

> Slack returns HTTP 200 even on auth errors (`{"ok": false, ...}`). Warden's
> introspection is best-effort: a response with no matching fields yields no
> metadata rather than failing the mint. `auth.test` exposes only non-sensitive
> identifiers; if you capture a sensitive field instead, add its path to the audit
> device's `salt_fields` (e.g. `response.credential.metadata.email`) to HMAC it
> rather than log it in the clear.

## Step 4: Create a Policy

MCP traffic passes through two complementary layers of authorization. The minted
Slack access token is the security boundary — its scopes and the consenting
user's workspace permissions bound what the agent can actually do in Slack
regardless of what Warden lets through. On top of that, Warden's CBP policies
support an `mcp { }` block for governance-style restrictions enforced at the
gateway: allow- and deny-lists for JSON-RPC methods, tool names, resource URIs,
prompt names, and selected tool arguments.

Enforcement is **body-authoritative**. When a policy in scope contains an
`mcp { }` block, Warden strict-parses the JSON-RPC request body and matches
against the parsed body. The parser fails closed on any structural problem and
the matcher denies with a specific `rule_type`:

| `rule_type` | Trigger |
|---|---|
| `denied_methods` / `allowed_methods` | JSON-RPC `method` matches a deny pattern, or is absent from a configured allow list |
| `denied_tools` / `allowed_tools` | `tools/call` with a `params.name` matching a deny pattern, or not in the allow list |
| `denied_resources` / `allowed_resources` | `resources/read` with a `params.uri` matching a deny pattern, or not in the allow list |
| `denied_prompts` / `allowed_prompts` | `prompts/get` with a `params.name` matching a deny pattern, or not in the allow list |
| `denied_params` / `allowed_params` | A `tools/call` argument (`params.arguments.<key>`) matches a deny pattern, or — when present — fails an allow-list pattern. Both rules are conditional on presence: missing arguments don't trigger either, matching Vault's `allowed_parameters` semantics. Tools whose argument shape doesn't include the gated key pass through unaffected. |
| `missing_body` | An `mcp { }` block is bound to a path served by a non-MCP-aware backend — an operator misconfiguration. The body-authoritative gate has no descriptor to evaluate and fails closed. |
| `malformed_jsonrpc` | Body on an MCP-enforced POST is absent, unreadable, or not a well-formed JSON-RPC 2.0 envelope (bad version, missing method, unknown top-level key, UTF-8 BOM, etc.) |
| `duplicate_key` | Duplicate object key detected anywhere in the body — Warden rejects ambiguity that Go's standard JSON parser silently last-wins-resolves |
| `oversized_body` | Body exceeds the mount's `max_body_size` |
| `batch_empty` | JSON-RPC batch is `[]` |
| `malformed_params` | A name-bearing method has a missing or wrong-shape selector: `params.name` for `tools/call` and `prompts/get`, or `params.uri` for `resources/read` |

All examples below use `capabilities = ["create", "read", "delete"]`. MCP
Streamable HTTP uses three HTTP verbs on the same `/gateway/` URL: POST for
JSON-RPC requests (mapped by Warden to `create`), GET for the optional server →
client SSE notification stream (`read`), and DELETE for session terminate
(`delete`). All three need to be in the cap list or off-spec MCP clients fail to
connect. The `mcp { }` block only fires on the POST half; GET/DELETE skip
body-authoritative evaluation automatically.

The `allowed_methods` examples list the MCP **protocol** methods every
spec-compliant client uses in its handshake — `initialize`,
`notifications/initialized`, `ping` — alongside the data-plane methods
(`tools/list`, `tools/call`, …). Omitting the lifecycle methods makes
`claude mcp list` (and similar client health checks) hang on connect.

The simplest policy grants the gateway and leans on the OAuth token's scopes for
everything:

```bash
warden policy write mcp-slack-access - <<EOF
path "slack-mcp/role/+/gateway*" {
  capabilities = ["create", "read", "delete"]
}
EOF
```

A policy that restricts the agent to a vetted set of Slack tools:

```bash
warden policy write mcp-slack-readonly - <<EOF
path "slack-mcp/role/+/gateway*" {
  capabilities = ["create", "read", "delete"]
  mcp {
    allowed_methods = [
      "initialize",
      "notifications/initialized",
      "tools/list",
      "tools/call",
      "resources/list",
      "resources/read",
      "ping"
    ]
    allowed_tools   = ["list_channels", "get_messages", "get_thread", "search_messages"]
  }
}
EOF
```

A complementary deny-list shape — permissive by default, blocks dangerous tools:

```bash
warden policy write mcp-slack-safe - <<EOF
path "slack-mcp/role/+/gateway*" {
  capabilities = ["create", "read", "delete"]
  mcp {
    denied_tools = ["delete_*", "remove_*", "archive_channel"]
  }
}
EOF
```

Argument-level gates restrict the *values* passed to `tools/call`. Keys in
`denied_params` / `allowed_params` match against `params.arguments.<key>` from
the parsed body — both rules skip on missing arguments, so a tool that doesn't
take `channel` at all isn't affected. The policy below permits posting, but only
to an approved set of channels:

```bash
warden policy write mcp-slack-approved-channels - <<EOF
path "slack-mcp/role/+/gateway*" {
  capabilities = ["create", "read", "delete"]
  mcp {
    allowed_methods = [
      "initialize",
      "notifications/initialized",
      "tools/call",
      "ping"
    ]
    allowed_tools  = ["post_message"]
    allowed_params = {
      channel_id = ["C0123456789", "C0987654321"]
    }
  }
}
EOF
```

When a request hits the `mcp { }` gate and is denied, Warden returns HTTP 403
with a structured JSON body and an RFC 6750 `WWW-Authenticate` header; MCP client
SDKs surface this to the agent as a tool-call failure with an actionable message.
The audit log records the matched rule and the offending tool/parameter so
operators can debug policy decisions centrally. Policies that omit the `mcp { }`
block keep today's behaviour: Warden passes the request through to Slack
unchanged and the OAuth token's scopes alone enforce authorization.

## Step 5: Point an MCP Client at Warden

Get a JWT from Hydra using one of the quickstart clients:

```bash
export JWT_TOKEN=$(curl -s -X POST http://localhost:4444/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=my-agent&client_secret=agent-secret&scope=api:read api:write" \
  | jq -r '.access_token')
```

Configure your MCP client to point at the Warden mount. The URL pattern is:

```
${WARDEN_ADDR}/v1/slack-mcp/role/{role}/gateway
```

> **No trailing slash after `gateway`.** Slack's MCP endpoint is
> `https://mcp.slack.com/mcp` (no trailing slash) and **301-redirects**
> `…/mcp/`. Warden forwards the path after `gateway` verbatim, so end the URL at
> `gateway` (not `gateway/`) to hit `…/mcp` exactly. This is the opposite of
> GitHub's and GCP's MCP mounts, whose upstreams expect the trailing slash.

For Claude Code, Cursor, Continue, Cline, Goose, and other clients that accept
Streamable HTTP MCP servers via a JSON config block:

```json
{
  "mcpServers": {
    "slack": {
      "type": "http",
      "url": "${WARDEN_ADDR}/v1/slack-mcp/role/mcp-user/gateway",
      "headers": {
        "Authorization": "Bearer ${JWT_TOKEN}"
      }
    }
  }
}
```

> **Heads-up on `${VAR}` in headers.** MCP clients vary in what they substitute
> in `.mcp.json`. Claude Code and Cursor expand `${VAR}` in stdio `env` blocks
> and in the `url` field, but **HTTP-transport `headers` values are a known
> gap** — the literal `${JWT_TOKEN}` string ships on the wire. For the
> `Authorization` header (and the routing headers in the next example), paste the
> actual values instead of `${...}` placeholders, or run the JSON through
> `envsubst` at deploy time.

> **Warden replaces the client-side Slack OAuth flow.** Pointing an MCP client
> straight at `https://mcp.slack.com/mcp` would make the client perform Slack's
> OAuth dance itself. Through Warden the client never sees Slack's OAuth — Warden
> already holds the consented token and injects it. The client only authenticates
> to Warden (JWT/cert).

### Claude Code (CLI)

Add the server straight from the command line instead of hand-editing the JSON.
The shell expands `$JWT_TOKEN` when the command runs, so the token is written into
the config as a literal value — sidestepping the header-substitution gap noted
above:

```bash
claude mcp add --transport http slack \
  "${WARDEN_ADDR}/v1/slack-mcp/role/mcp-user/gateway" \
  --header "Authorization: Bearer ${JWT_TOKEN}"
```

This writes a `local`-scope entry (visible only to you, only in this directory)
by default. Add `--scope project` to write a shared `.mcp.json` you can commit, or
`--scope user` to make it available across all your projects.

Confirm Claude Code registered it and completes the MCP handshake — this is where
a missing lifecycle method in your policy (see Step 4) would surface as a hang:

```bash
claude mcp list
```

Then just ask Claude to use it; it discovers whatever tools your policy and the
consented token allow:

```
> Summarize the last 20 messages in #incidents and list any unresolved threads.
```

The `role` segment in the URL selects which credential spec — and thus which
consented Slack identity — backs the calls, via the role's `cred_spec_name`
binding from Step 1 (here, `slack-mcp-creds`). The Hydra JWT is short-lived —
when it expires, refresh it, then `claude mcp remove slack` and re-add with the
new token.

### Header-routed alternative

Some MCP clients dislike long URLs, or you want one base URL to mux several
Warden providers. Pass the mount path as `X-Warden-Provider`, the namespace as
`X-Warden-Namespace`, and the role as `X-Warden-Role` instead — Warden
synthesises the canonical gateway path from the headers. Look up the mount path by
its description first (several `mcp` mounts may front different products, so match
on `description`, not `type`):

```bash
path=$(warden provider list -o json | jq -r '.[] | select(.description=="Slack MCP — workspace acme, user-consented") | .path' | head -1)
```

The `path` is what `warden provider list` returns (e.g., `slack-mcp/`,
`team-comms/slack-mcp/`), **not** the literal string `mcp` — Warden routes on the
mount path, not the provider type.

```json
{
  "mcpServers": {
    "slack": {
      "type": "http",
      "url": "${WARDEN_ADDR}/",
      "headers": {
        "Authorization": "Bearer ${JWT_TOKEN}",
        "X-Warden-Provider": "slack-mcp/",
        "X-Warden-Namespace": "<namespace>",
        "X-Warden-Role": "mcp-user"
      }
    }
  }
}
```

The same caveat applies here as above: paste the actual mount path, namespace,
role, and (if you're not handing the file to `envsubst`) JWT in the `headers`
map — `${VAR}` placeholders in HTTP-transport headers don't get expanded by the
major clients today.

### Smoke-test with curl

List the tools the server exposes:

```bash
curl -X POST "${WARDEN_ADDR}/v1/slack-mcp/role/mcp-user/gateway" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

Call a tool (the tool name depends on the Slack MCP server's catalog):

```bash
curl -X POST "${WARDEN_ADDR}/v1/slack-mcp/role/mcp-user/gateway" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"post_message","arguments":{"channel":"C0123456789","text":"deploy complete"}}}'
```

End the URL at `gateway` with **no trailing slash** — Warden forwards the path
after `gateway` verbatim, so `gateway` maps to `https://mcp.slack.com/mcp` while
`gateway/` would map to `https://mcp.slack.com/mcp/`, which Slack 301-redirects.

### Troubleshooting

- **`HTTP 400` with `"App is not enabled for Slack MCP server access"`** (JSON-RPC
  `code: -32600`). The Slack app hasn't been enabled for MCP. Open the app's
  **Agents & AI Apps** page (`https://api.slack.com/apps/<APP_ID>/app-assistant`)
  and turn on the **Model Context Protocol** toggle (Step 2 of *Register the Slack
  app*). Warden is working — the request reached Slack and Slack rejected it. The
  error body even links to the exact app settings page.
- **`HTTP 301`.** The upstream URL ended in a trailing slash (`…/mcp/`). Ensure the
  client URL ends at `gateway` (no trailing slash) and `mcp_url` is
  `https://mcp.slack.com/mcp`.
- **Consent returned only an access token, no refresh token.** Token Rotation is
  off on the app — see Step 6 of *Register the Slack app*.

## TLS Certificate Authentication

Steps 1 and 5 above use JWT authentication. Alternatively, you can authenticate
with a TLS client certificate. This is useful for workloads that already have
X.509 certificates — Kubernetes pods with cert-manager, VMs with machine
certificates, or SPIFFE X.509-SVIDs from a service mesh.

> **Prerequisite:** Certificate authentication requires TLS to be enabled on the
> Warden listener so that client certificates can be presented during the TLS
> handshake (mTLS). In dev mode, use `-dev-tls` to enable TLS with auto-generated
> certificates, or provide your own with `-dev-tls-cert-file`,
> `-dev-tls-key-file`, and `-dev-tls-ca-cert-file`. Alternatively, place Warden
> behind a load balancer that terminates TLS and forwards the client certificate
> via the `X-Forwarded-Client-Cert` or `X-SSL-Client-Cert` header.

Steps 2-4 (provider mount, credential, policy) are identical — the
`mcp-slack-access` policy from Step 4 works for either auth method. Replace Steps
1 and 5 with the following.

### Enable Cert Auth

```bash
warden auth enable cert
```

### Configure Trusted CA

Provide the PEM-encoded CA certificate that signs your client certificates:

```bash
warden write auth/cert/config \
    trusted_ca_pem=@/path/to/ca.pem \
    default_role=mcp-user
```

### Create a Cert Role

```bash
warden write auth/cert/role/mcp-user \
    allowed_common_names="agent-*" \
    token_policies="mcp-slack-access" \
    cred_spec_name=slack-mcp-creds
```

The `allowed_common_names` field supports glob patterns. You can also match on
other certificate fields: `allowed_dns_sans`, `allowed_email_sans`,
`allowed_uri_sans`, or `allowed_organizational_units`.

### Configure Provider for Cert Auth

Update the provider config to point at the cert auth mount:

```bash
warden write slack-mcp/config <<EOF
{
  "mcp_url": "https://mcp.slack.com/mcp",
  "auto_auth_path": "auth/cert/",
  "timeout": "10m",
  "max_body_size": 10485760
}
EOF
```

For MCP-client mTLS patterns (local terminating sidecar, or `mcp-remote` as a
Node bridge) and role selection with a certificate, see the equivalent section in
the [generic provider README](../README.md#tls-certificate-authentication) — the
patterns are identical; substitute this mount's `path` (`slack-mcp/`) for the
provider value in the header-routed configs.

## Configuration Reference

### Provider Config

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `mcp_url` | string | — | **Required.** `https://mcp.slack.com/mcp` (must be HTTPS). No default |
| `max_body_size` | int | 10485760 (10 MB) | Maximum request body size in bytes (max 100 MB) |
| `timeout` | duration | `10m` | Session timeout. Raise for long agent sessions that keep an SSE stream open across many tool calls |
| `tls_skip_verify` | bool | `false` | Skip TLS certificate verification (development only) |
| `ca_data` | string | — | Base64-encoded PEM CA certificate for custom/self-signed CAs |
| `auto_auth_path` | string | — | **Required.** Auth mount path for implicit authentication (e.g., `auth/jwt/`, `auth/cert/`) |
| `default_role` | string | — | Fallback role when not specified in URL or header |

### Credential (oauth2 source)

| Field | Where | Description |
|-------|-------|-------------|
| `auth_url` | source | `https://slack.com/oauth/v2_user/authorize` |
| `token_url` | source | `https://slack.com/api/oauth.v2.user.access` |
| `auth_method` | spec | `authorization_code` |
| `client_id` / `client_secret` | spec | The Slack app's OAuth client credentials (`client_secret` via `@file`) |
| `redirect_uri` | spec | Loopback callback registered on the Slack app (e.g. `http://127.0.0.1:8765/callback`) |
| `scopes` | spec | Space-separated Slack **user-token** scopes |

The minted credential type is `oauth_bearer_token`; Warden injects it as
`Authorization: Bearer <token>`.

## Token Scopes and Tool Availability

The Slack MCP server enforces Slack's OAuth model on the user token, so the
**upstream ceiling** on what a tool can do is set by the token's user scopes and
the consenting user's workspace permissions — Warden policy can narrow this but
never widen it. A `tools/call` that fails with a Slack permission error
(`missing_scope`, `not_in_channel`, …) means the app lacks a required user scope
or the consenting user can't see that resource; a `tools/call` denied by Warden
with a `403` + RFC 6750 `WWW-Authenticate` header (and a `rule_type` in the audit
log) means the [Step 4](#step-4-create-a-policy) `mcp { }` block blocked it. Read
the error to tell the two layers apart.

Common mappings (Slack **user-token** scopes):

| Tool family | Slack user scope |
|-------------|------------------|
| List channels | `channels:read`, `groups:read` |
| Read messages / history | `channels:history`, `groups:history` |
| Post messages | `chat:write` |
| Look up users | `users:read` |
| Search | `search:read.public` |

Provision the Slack app with the user scopes covering the intended tool surface.
Because access is user-scoped, an agent acting through this mount can only reach
what the consenting user can — re-run `warden cred spec connect slack-mcp-creds`
to re-consent after changing scopes.

**Rotate the OAuth client secret** by updating the spec, then re-running consent:

```bash
warden cred spec update slack-mcp-creds \
  -config client_secret=@/path/to/new-client-secret
warden cred spec connect slack-mcp-creds -force
```

Then remove the old secret from the Slack app's **OAuth & Permissions** settings.
