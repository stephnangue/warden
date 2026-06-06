# GitHub MCP Provider

The `mcp_github` provider enables proxied access to GitHub's hosted MCP (Model Context Protocol) server through Warden. MCP clients (Claude Code, Cursor, Continue, Cline, Goose, ...) point at Warden instead of `api.githubcopilot.com`; Warden authenticates the caller, injects a GitHub token bound to the chosen role as `Authorization: Bearer <token>`, and streams JSON or SSE responses back unchanged. Agents never hold a GitHub credential.

It supports **GitHub App**, **Personal Access Token (PAT)**, and **OAuth2 authorization-code** authentication. The App and PAT specs used by the `github` REST provider work here unchanged — one role binding grants both REST and MCP reach — while the OAuth2 flow lets an agent act as a specific consenting GitHub user.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Step 1: Configure JWT Auth and Create a Role](#step-1-configure-jwt-auth-and-create-a-role)
- [Step 2: Mount and Configure the Provider](#step-2-mount-and-configure-the-provider)
- [Step 3: Create a Credential Source and Spec](#step-3-create-a-credential-source-and-spec)
- [Step 4: Create a Policy](#step-4-create-a-policy)
- [Step 5: Point an MCP Client at Warden](#step-5-point-an-mcp-client-at-warden)
- [TLS Certificate Authentication](#tls-certificate-authentication)
- [Configuration Reference](#configuration-reference)
- [Auth Method Comparison](#auth-method-comparison)
- [Token Scopes and Tool Availability](#token-scopes-and-tool-availability)

## Prerequisites

- Docker and Docker Compose installed and running
- One of the following:
  - **GitHub App** with a private key and installation ID (recommended — short-lived tokens, auto-refreshed), OR
  - **Personal Access Token** (classic or fine-grained) with the scopes covering the MCP tools you want to expose (e.g., `repo`, `issues`, `pull_requests`), OR
  - **GitHub App** (Client ID + Client Secret) to act as a consenting GitHub user via the authorization-code flow (see [Option C](#option-c-oauth2-authorization-code-flow-acting-as-a-github-user))
- An MCP client that supports remote MCP servers over HTTP (Claude Code, Cursor, Continue, Cline, Goose, ...)

> **New to Warden?** Follow the standard quickstart flow used by the other provider READMEs (the `github` and `slack` READMEs cover it step by step): deploy the quickstart compose, install the binary, export `WARDEN_ADDR` and `WARDEN_TOKEN`, then return here.

## Step 1: Configure JWT Auth and Create a Role

Set up a JWT auth method and create a role that binds the credential spec and policy. Clients authenticate directly with their JWT — no separate login step is needed.

> **Set this up before configuring the provider.** The provider resolves `auto_auth_path` per request — writing the config only checks that it is non-empty, not that the mount exists — so a gateway call fails with `no auth mount registered ... for implicit auth` if the referenced auth mount isn't there yet.

```bash
# Enable JWT auth if not already enabled
warden auth enable jwt

# Configure JWT with Hydra's JWKS endpoint (from docker-compose.quickstart.yml)
warden write auth/jwt/config jwks_url=http://localhost:4444/.well-known/jwks.json

# Create a role that binds the credential spec and policy
warden write auth/jwt/role/mcp-user \
    token_policies="mcp-github-access" \
    user_claim=sub \
    cred_spec_name=github-ops
```

## Step 2: Mount and Configure the Provider

Enable the `mcp_github` provider at a path of your choice:

```bash
warden provider enable mcp_github
```

To mount at a custom path:

```bash
warden provider enable -path=copilot-mcp mcp_github
```

Verify the provider is enabled:

```bash
warden provider list
```

Configure the provider with `auto_auth_path`. The default `timeout` is 10 minutes — raise it for agent sessions that keep an SSE stream open across many tool calls:

```bash
warden write mcp_github/config <<EOF
{
  "mcp_github_url": "https://api.githubcopilot.com/mcp",
  "auto_auth_path": "auth/jwt/",
  "timeout": "10m",
  "max_body_size": 10485760
}
EOF
```

Verify the configuration:

```bash
warden read mcp_github/config
```

## Step 3: Create a Credential Source and Spec

If you already configured a credential source and spec for the `github` REST provider, you can reuse them here unchanged — the same App or PAT works for both flows. Skip to Step 4.

The credential source holds only connection info (`github_url`). Auth credentials (App private key + installation ID, or PAT) live on the credential spec, allowing multiple specs with different identities to share one source.

```bash
warden cred source create github-src \
  -type=github \
  -rotation-period=0 \
  -config=github_url=https://api.github.com
```

Verify the source was created:

```bash
warden cred source read github-src
```

### Option A: GitHub App (Recommended)

1. Go to **Settings > Developer settings > GitHub Apps** and create a new app.
2. Note the **App ID** from the app settings page.
3. Generate a **private key** (RSA, PEM format) and download it.
4. Install the app on your organization or account and note the **Installation ID** from the URL.
5. Grant the app the permissions covering the MCP tools you intend to use (e.g., `Contents: Read`, `Issues: Read/Write`, `Pull requests: Read/Write`).

```bash
warden cred spec create github-ops \
  -source github-src \
  -config auth_method=app \
  -config app_id=<your-app-id> \
  -config private_key=@/path/to/private-key.pem \
  -config installation_id=<your-installation-id>
```

Warden mints a short-lived (1 hour) installation token at request time and auto-refreshes before expiry. The agent never sees the private key or the installation token.

### Option B: Personal Access Token

```bash
warden cred spec create github-ops \
  -source github-src \
  -config auth_method=pat \
  -config token=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

Verify:

```bash
warden cred spec read github-ops
```

### Option C: OAuth2 Authorization Code Flow (acting as a GitHub user)

The App and PAT flows act as an application or a static token. To instead have an
agent act **as a specific GitHub user** — with access limited to the intersection
of the app's permissions and what that user consented to — use the OAuth2
authorization-code flow. A human authorizes once in the browser; Warden seals the
resulting refresh token and mints a fresh access token on each request. The agent
never sees the client secret or the token.

This flow uses its own `oauth2` credential source (not the `github` source created
at the start of Step 3).

Refresh tokens in this flow come only from a **GitHub App** with user-token
expiration enabled. A classic OAuth App issues a non-expiring user token and no
refresh token, so it cannot drive the refresh-on-demand model below.

1. Use a **GitHub App** — the one from Option A works, or create a new one under
   **Settings > Developer settings > GitHub Apps**. Enable **Expire user
   authorization tokens** in its settings so GitHub returns a refresh token. Note
   the **Client ID** and generate a **client secret** (this is the app's OAuth
   client secret, distinct from the private key used in Option A).
2. Set the app's **Callback URL** to a fixed loopback address — GitHub validates
   the redirect against it — for example `http://127.0.0.1:8765/callback`.

The user's effective access is the app's configured **permissions** intersected
with what the user grants at consent time; there is no separate scope list to set.

Create the source pointing at GitHub's authorize and token endpoints:

```bash
warden cred source create github-oauth-src \
  -type=oauth2 \
  -rotation-period=0 \
  -config=auth_url=https://github.com/login/oauth/authorize \
  -config=token_url=https://github.com/login/oauth/access_token
```

Create the spec — it starts empty, with no token until consent — carrying the
app's OAuth client credentials and the pinned callback from step 2. The client
secret is read from a file so it never lands in shell history:

```bash
warden cred spec create github-ops \
  -source github-oauth-src \
  -config auth_method=authorization_code \
  -config client_id=<your-client-id> \
  -config client_secret=@/path/to/client-secret \
  -config redirect_uri=http://127.0.0.1:8765/callback
```

Complete the one-time consent. Warden binds the pinned loopback port, opens the
browser to GitHub, captures the authorization code on the redirect, and exchanges
it for tokens server-side — the client secret never leaves the server:

```bash
warden cred spec connect github-ops
```

Re-run `connect` whenever you need to re-authorize — after revoking the grant,
changing the app's permissions, or rotating the secret. Add `-force` to replace a
live authorization without the confirmation prompt, or `-no-browser` on a headless
host to print the URL to open elsewhere. Bind this spec to the role from Step 1 with
`cred_spec_name=github-ops`; Warden then injects the user's access token as
`Authorization: Bearer <token>` on each MCP request, refreshing it from the sealed
refresh token as needed.

#### Recording the acting user in the audit log

An audit record already captures **who made the request** — the agent identity
(`auth.principal_id` and the verified `auth.actors` chain). With the
authorization-code flow it can also capture **whose GitHub credential was
forwarded** — the consenting user — so the two identities are correlated on every
proxied call.

That second identity travels in a separate, non-secret **`metadata`** block on the
credential, logged *in the clear* — distinct from the credential's `data` (the raw
token), which the audit layer HMAC-salts by default. You choose which identity
fields to record with two **source-level** settings:

- `metadata_fields` — comma-separated fields to copy into the metadata block
  (default `sub`; empty disables).
- `introspection_url` — for **opaque** tokens (GitHub's are opaque), the
  userinfo/introspection endpoint Warden calls once per token mint to fetch those
  fields. For JWT access tokens (Azure AD, Google, Okta, …) leave it unset and
  Warden decodes the claims locally — no extra call.

Both are source-level so the source operator, not a spec author, decides what is
exposed; and `introspection_url` stays under the source SSRF guard. For GitHub,
point at the user endpoint and capture the login:

```bash
warden cred source update github-oauth-src \
  -config=introspection_url=https://api.github.com/user \
  -config=metadata_fields=login
```

A response audit event for an MCP call then carries both axes — the agent that
called, and the GitHub user it acted as — while the token stays salted:

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
      "source_name": "github-oauth-src",
      "spec_name": "github-ops",
      "metadata": { "login": "octocat" },
      "data": { "api_key": "hmac-sha256:..." }
    }
  }
}
```

If a captured field is sensitive (an email, say), add its path to the audit
device's `salt_fields` to HMAC it instead of logging in the clear — e.g.
`response.credential.metadata.email` salts that one field, or
`response.credential.metadata` salts the whole block.

## Step 4: Create a Policy

MCP traffic passes through two complementary layers of authorization. The minted GitHub token is the security boundary — its scopes bound what the agent can actually do at GitHub regardless of what Warden lets through. On top of that, Warden's CBP policies support an `mcp { }` block for governance-style restrictions enforced at the gateway: allow- and deny-lists for JSON-RPC methods, tool names, resource URIs, prompt names, and selected tool arguments.

Enforcement is **body-authoritative**. When a policy in scope contains an `mcp { }` block, Warden strict-parses the JSON-RPC request body and matches against the parsed body. The parser fails closed on any structural problem and the matcher denies with a specific `rule_type`:

| `rule_type` | Trigger |
|---|---|
| `denied_methods` / `allowed_methods` | JSON-RPC `method` matches a deny pattern, or is absent from a configured allow list |
| `denied_tools` / `allowed_tools` | `tools/call` with a `params.name` matching a deny pattern, or not in the allow list |
| `denied_resources` / `allowed_resources` | `resources/read` with a `params.uri` matching a deny pattern, or not in the allow list |
| `denied_prompts` / `allowed_prompts` | `prompts/get` with a `params.name` matching a deny pattern, or not in the allow list |
| `denied_params` / `allowed_params` | A `tools/call` argument (`params.arguments.<key>`) matches a deny pattern, or — when present — fails an allow-list pattern. Both rules are conditional on presence: missing arguments don't trigger either, matching Vault's `allowed_parameters` semantics. Tools whose argument shape doesn't include the gated key pass through unaffected. |
| `missing_body` | An `mcp { }` block is bound to a path served by a non-MCP-aware backend — an operator misconfiguration. The body-authoritative gate has no descriptor to evaluate and fails closed. (An absent or unparseable body on a genuine MCP POST surfaces as `malformed_jsonrpc`, not this.) |
| `malformed_jsonrpc` | Body on an MCP-enforced POST is absent, unreadable, or not a well-formed JSON-RPC 2.0 envelope (bad version, missing method, unknown top-level key, UTF-8 BOM, etc.) |
| `duplicate_key` | Duplicate object key detected anywhere in the body — Warden rejects ambiguity that Go's standard JSON parser silently last-wins-resolves |
| `oversized_body` | Body exceeds the mount's `max_body_size` |
| `batch_empty` | JSON-RPC batch is `[]` |
| `malformed_params` | A name-bearing method has a missing or wrong-shape selector: `params.name` for `tools/call` and `prompts/get`, or `params.uri` for `resources/read` |

All examples below use `capabilities = ["create", "read", "delete"]`. MCP Streamable HTTP uses three HTTP verbs on the same `/gateway/` URL: POST for JSON-RPC requests (mapped by Warden to `create`), GET for the optional server → client SSE notification stream (`read`), and DELETE for session terminate (`delete`). All three need to be in the cap list or off-spec MCP clients fail to connect. The `mcp { }` block only fires on the POST half; GET/DELETE skip body-authoritative evaluation automatically.

The `allowed_methods` examples below list the MCP **protocol** methods every spec-compliant client uses in its handshake — `initialize`, `notifications/initialized`, `ping` — alongside the data-plane methods (`tools/list`, `tools/call`, …). Omitting the lifecycle methods makes `claude mcp list` (and similar client health checks) hang on connect.

The simplest policy grants the gateway and leans on PAT scopes for everything:

```bash
warden policy write mcp-github-access - <<EOF
path "mcp_github/role/+/gateway*" {
  capabilities = ["create", "read", "delete"]
}
EOF
```

A policy that restricts the agent to a vetted set of GitHub tools:

```bash
warden policy write mcp-github-readonly - <<EOF
path "mcp_github/role/+/gateway*" {
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
    allowed_tools   = ["get_repository", "get_pull_request", "list_issues", "search_code"]
  }
}
EOF
```

A complementary deny-list shape — permissive by default, blocks dangerous tools:

```bash
warden policy write mcp-github-safe - <<EOF
path "mcp_github/role/+/gateway*" {
  capabilities = ["create", "read", "delete"]
  mcp {
    denied_tools = ["delete_*", "force_*", "merge_pull_request"]
  }
}
EOF
```

Argument-level gates restrict the *values* passed to `tools/call`. Keys in `denied_params` / `allowed_params` match against `params.arguments.<key>` from the parsed body — both rules skip on missing arguments, so a tool that doesn't take `branch` at all isn't affected. The policy below permits `create_or_update_file` but never on protected branches:

```bash
warden policy write mcp-github-no-protected-branches - <<EOF
path "mcp_github/role/+/gateway*" {
  capabilities = ["create", "read", "delete"]
  mcp {
    allowed_methods = [
      "initialize",
      "notifications/initialized",
      "tools/call",
      "ping"
    ]
    denied_params = {
      branch = ["main", "master", "production", "release/*"]
    }
  }
}
EOF
```

The `mcp { }` block composes with runtime conditions so you can layer environment guards on top of tool-level restrictions:

```bash
warden policy write mcp-github-business-hours - <<EOF
path "mcp_github/role/+/gateway*" {
  capabilities = ["create", "read", "delete"]
  conditions {
    source_ip   = ["10.0.0.0/8"]
    time_window = ["08:00-18:00 UTC"]
    day_of_week = ["Mon", "Tue", "Wed", "Thu", "Fri"]
  }
  mcp {
    allowed_methods = [
      "initialize",
      "notifications/initialized",
      "tools/list",
      "tools/call",
      "ping"
    ]
    allowed_tools   = ["get_*", "list_*", "create_issue_comment"]
  }
}
EOF
```

When a request hits the `mcp { }` gate and is denied, Warden returns HTTP 403 with a structured JSON body and an RFC 6750 `WWW-Authenticate` header; MCP client SDKs surface this to the agent as a tool-call failure with an actionable message. The audit log records the matched rule and the offending tool/parameter so operators can debug policy decisions centrally. Policies that omit the `mcp { }` block keep today's behaviour: Warden passes the request through to GitHub unchanged and the PAT's scopes alone enforce authorization.

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
${WARDEN_ADDR}/v1/mcp_github/role/{role}/gateway/
```

For Claude Code, Cursor, Continue, Cline, Goose, and other clients that accept Streamable HTTP MCP servers via a JSON config block:

```json
{
  "mcpServers": {
    "github": {
      "type": "http",
      "url": "${WARDEN_ADDR}/v1/mcp_github/role/mcp-user/gateway/",
      "headers": {
        "Authorization": "Bearer ${JWT_TOKEN}"
      }
    }
  }
}
```

> **Heads-up on `${VAR}` in headers.** MCP clients vary in what they substitute in `.mcp.json`. Claude Code and Cursor expand `${VAR}` in stdio `env` blocks and in the `url` field, but **HTTP-transport `headers` values are a known gap** — the literal `${JWT_TOKEN}` string ships on the wire. For the `Authorization` header (and the routing headers in the next example), paste the actual values instead of `${...}` placeholders, or run the JSON through `envsubst` at deploy time.

#### Claude Code (CLI)

Add the server straight from the command line instead of hand-editing the JSON.
The shell expands `$JWT_TOKEN` when the command runs, so the token is written into
the config as a literal value — sidestepping the header-substitution gap noted
above:

```bash
claude mcp add --transport http github \
  "${WARDEN_ADDR}/v1/mcp_github/role/mcp-user/gateway/" \
  --header "Authorization: Bearer ${JWT_TOKEN}"
```

This writes a `local`-scope entry (visible only to you, only in this directory) by
default. Add `--scope project` to write a shared `.mcp.json` you can commit, or
`--scope user` to make it available across all your projects.

Confirm Claude Code registered it and completes the MCP handshake — this is where a
missing lifecycle method in your policy (see Step 4) would surface as a hang:

```bash
claude mcp list
```

Then just ask Claude to use it; it discovers whatever tools your policy and the
bound token allow:

```
> List the open issues in myorg/myrepo and summarize the three highest-priority ones.
```

The `role` segment in the URL selects which credential spec — and thus which GitHub
identity — backs the calls, via the role's `cred_spec_name` binding from Step 1
(here, `github-ops`, however you populated it in Step 3). The Hydra JWT is
short-lived — when it expires, refresh it, then `claude mcp remove github` and
re-add with the new token.

#### Header-routed alternative

Some MCP clients dislike long URLs, or you want one base URL to mux several Warden providers. Pass the mount path as `X-Warden-Provider`, the namespace as `X-Warden-Namespace`, and the role as `X-Warden-Role` instead — Warden synthesises the canonical gateway path from the headers. Look up the mount path first:

```bash
path=$(warden provider list -o json | jq -r '.[] | select(.type=="mcp_github") | .path' | head -1)
```

The `path` is what `warden provider list` returns (e.g., `mcp_github/`, `team-data/copilot-mcp/`), **not** the literal string `mcp_github` — Warden routes on the mount path, not the provider type.

```json
{
  "mcpServers": {
    "github": {
      "type": "http",
      "url": "${WARDEN_ADDR}/",
      "headers": {
        "Authorization": "Bearer ${JWT_TOKEN}",
        "X-Warden-Provider": "mcp_github/",
        "X-Warden-Namespace": "<namespace>",
        "X-Warden-Role": "mcp-user"
      }
    }
  }
}
```

The same caveat applies here as above: paste the actual mount path, namespace, role, and (if you're not handing the file to `envsubst`) JWT in the `headers` map — `${VAR}` placeholders in HTTP-transport headers don't get expanded by the major clients today.

### Smoke-test with curl

List the tools the server exposes:

```bash
curl -X POST "${WARDEN_ADDR}/v1/mcp_github/role/mcp-user/gateway/" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

Call a tool:

```bash
curl -X POST "${WARDEN_ADDR}/v1/mcp_github/role/mcp-user/gateway/" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_issues","arguments":{"owner":"myorg","repo":"myrepo"}}}'
```

The trailing slash on `gateway/` matters — GitHub's MCP server lives at exactly one path, and Warden composes the upstream URL as the mount's configured upstream URL plus the gateway suffix.

## TLS Certificate Authentication

Steps 1 and 5 above use JWT authentication. Alternatively, you can authenticate with a TLS client certificate. This is useful for workloads that already have X.509 certificates — Kubernetes pods with cert-manager, VMs with machine certificates, or SPIFFE X.509-SVIDs from a service mesh.

> **Prerequisite:** Certificate authentication requires TLS to be enabled on the Warden listener so that client certificates can be presented during the TLS handshake (mTLS). In dev mode, use `-dev-tls` to enable TLS with auto-generated certificates, or provide your own with `-dev-tls-cert-file`, `-dev-tls-key-file`, and `-dev-tls-ca-cert-file`. Alternatively, place Warden behind a load balancer that terminates TLS and forwards the client certificate via the `X-Forwarded-Client-Cert` or `X-SSL-Client-Cert` header.

Steps 2-4 (provider mount, credential source and spec, policy) are identical — the `mcp-github-access` policy from Step 4 works for either auth method. Replace Steps 1 and 5 with the following.

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

Create a role that binds allowed certificate identities to a credential spec and policy:

```bash
warden write auth/cert/role/mcp-user \
    allowed_common_names="agent-*" \
    token_policies="mcp-github-access" \
    cred_spec_name=github-ops
```

The `allowed_common_names` field supports glob patterns. You can also match on other certificate fields: `allowed_dns_sans`, `allowed_email_sans`, `allowed_uri_sans`, or `allowed_organizational_units`.

### Configure Provider for Cert Auth

Update the provider config to point at the cert auth mount:

```bash
warden write mcp_github/config <<EOF
{
  "mcp_github_url": "https://api.githubcopilot.com/mcp",
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
    -X POST "https://warden.internal/v1/mcp_github/role/mcp-user/gateway/" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json, text/event-stream" \
    -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

#### MCP Client JSON Config (cert auth)

**State of mTLS in MCP clients today.** The MCP specification does not standardize a client-side TLS configuration block, and the major IDE clients (Claude Code, Cursor, Continue) do not currently expose first-class fields for client certificate / key paths in their HTTP server configuration. Until that lands, two portable patterns work — both using header-routed mode so the MCP client only needs to set headers, never a deep URL.

Look up the mount path and namespace first:

```bash
path=$(warden provider list -o json | jq -r '.[] | select(.type=="mcp_github") | .path' | head -1)
namespace=$WARDEN_NAMESPACE   # whatever your default namespace is
```

The `path` is the mount path Warden returns from `warden provider list` (e.g., `mcp_github/`, `team-data/copilot-mcp/`), **not** the literal string `mcp_github`. Same gotcha as the JWT header-routed flow in the skill.

**Pattern A: Local mTLS-terminating sidecar (recommended).** Run a sidecar (Envoy, nginx, stunnel, `mtls-proxy`) on the agent host that holds the client cert/key and the trusted CA. The MCP client talks plain HTTP over loopback to the sidecar; the sidecar terminates client TLS, validates Warden's server cert, and forwards the request over mTLS with the validated client certificate attached as `X-SSL-Client-Cert` (URL-encoded PEM) or `X-Forwarded-Client-Cert`. Warden trusts the forwarded header when the listener is configured to do so.

```json
{
  "mcpServers": {
    "github": {
      "type": "http",
      "url": "http://127.0.0.1:9443/",
      "headers": {
        "X-Warden-Provider": "mcp_github/",
        "X-Warden-Namespace": "<namespace>",
        "X-Warden-Role": "mcp-user"
      }
    }
  }
}
```

Substitute `mcp_github/` with your mount's actual `path` and `<namespace>` with your namespace before saving — see the env-var caveat in Step 5: `${VAR}` placeholders in HTTP-transport `headers` are not expanded by the major MCP clients today. Drop the `X-Warden-Role` header when cert auth's `default_role` already covers the binding.

**Pattern B: `mcp-remote` as a Node-based bridge.** Many MCP installations already use `mcp-remote` (an npx-launched HTTP-to-stdio bridge) for transport-shape reasons. It runs in Node.js, so Node's TLS environment variables flow through: `NODE_EXTRA_CA_CERTS=/path/to/warden-ca.pem` for a custom CA. Client certificate handling via `mcp-remote` requires a custom Node TLS context and is not as turnkey — for most deployments Pattern A is simpler. A typical CA-only setup (Warden's server cert validated by a private CA; mTLS still requires Pattern A) looks like:

```json
{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "https://warden.internal/",
        "--transport", "http-only",
        "--header", "X-Warden-Provider: mcp_github/",
        "--header", "X-Warden-Namespace: <namespace>",
        "--header", "X-Warden-Role: mcp-user"
      ],
      "env": {
        "NODE_EXTRA_CA_CERTS": "/path/to/warden-ca.pem"
      }
    }
  }
}
```

`--header` accepts repeated values for adding custom headers; consult your `mcp-remote` version's docs if it differs. This authenticates Warden's server cert against a private CA but does **not** supply a client cert.

#### Selecting the role with a certificate

With cert auth, the role is resolved (in priority order):

1. `X-Warden-Role` header on the request — what the JSON examples above set
2. `/role/<role>/` segment in the URL path — not used in header-routed mode, but available when an MCP client cannot send custom headers
3. `default_role` set on the cert auth method's config (`auth/cert/config`, shown in [Configure Trusted CA](#configure-trusted-ca) above) — useful when one cert maps 1:1 to one role; the JSON config can drop `X-Warden-Role` entirely

## Configuration Reference

### Provider Config

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `mcp_github_url` | string | `https://api.githubcopilot.com/mcp` | MCP server base URL (must be HTTPS) |
| `max_body_size` | int | 10485760 (10 MB) | Maximum request body size in bytes (max 100 MB) |
| `timeout` | duration | `10m` | Session timeout. Raise for long agent sessions that keep an SSE stream open across many tool calls |
| `tls_skip_verify` | bool | `false` | Skip TLS certificate verification (development only) |
| `ca_data` | string | — | Base64-encoded PEM CA certificate for custom/self-signed CAs |
| `auto_auth_path` | string | — | **Required.** Auth mount path for implicit authentication (e.g., `auth/jwt/`, `auth/cert/`) |
| `default_role` | string | — | Fallback role when not specified in URL |

## Auth Method Comparison

| Method | Credentials | Token Lifetime | Rotation |
|--------|-------------|----------------|----------|
| **App** | Installation token (auto-minted) | 1 hour (auto-refreshed) | Not needed — tokens are ephemeral |
| **PAT** | Static personal access token | No expiration | Not supported — manage PAT lifecycle on GitHub |

**GitHub App** is recommended because:
- Tokens are short-lived (1 hour) and automatically refreshed
- Fine-grained permissions scoped to the app installation
- No long-lived secrets stored after initial setup
- Audit trail tied to the app identity

## Token Scopes and Tool Availability

GitHub's MCP server enforces upstream permissions per tool. The set of MCP tools available through a given mount is determined by the **bound token's permissions**, not by Warden policy. A `403` or `tool not available` response from a `tools/call` request typically means the bound token lacks a required scope.

Common mappings:

| Tool family | GitHub App permission | PAT scope |
|-------------|------------------------|-----------|
| Repository read | `Contents: Read` | `repo` (classic) or `Contents: Read` (fine-grained) |
| Issues | `Issues: Read/Write` | `repo` or `Issues: Read/Write` |
| Pull requests | `Pull requests: Read/Write` | `repo` or `Pull requests: Read/Write` |
| Actions | `Actions: Read/Write` | `workflow` |
| Secrets | `Secrets: Read/Write` | `repo` plus organization secret access |

Provision the App or PAT with permissions covering the intended tool surface, and bind one credential spec per role to give different agents different reach.

**Rotate a PAT** by updating the credential spec:

```bash
warden cred spec update github-ops \
  -config token=ghp-new-personal-access-token
```

Then revoke the old PAT from the [GitHub PAT settings](https://github.com/settings/tokens).

**GitHub App tokens do not require rotation** — installation tokens are auto-minted and expire after 1 hour. To rotate the App's private key, generate a new key in the GitHub App settings, update the spec with `private_key=@/path/to/new-key.pem`, and delete the old key from GitHub.
