# Generic MCP Provider

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
provider.) It accepts every bearer-shaped credential a role may bind:

- **`oauth_bearer_token`** — an OAuth2 token, including the browser-consent
  authorization-code flow (the agent acts as a consenting user, the grant is
  refreshed automatically). What most remote MCP servers require — Cloudflare,
  **Slack** (`https://mcp.slack.com/mcp`), Linear, Sentry, Notion.
- **`api_key`** — a static, long-lived personal or service token, for a server
  that authenticates a fixed bearer rather than running an OAuth flow. Common
  with self-hosted and enterprise MCP servers.
- **`github_token`** — a GitHub App installation token or PAT, the same credspec
  that backs the `github` REST provider. See [`mcp-github.md`](mcp-github.md).
- **`gcp_access_token`** — a short-lived Google Cloud access token, the same
  credspec that backs the `gcp` REST provider.

> **A REST credential is usually not the MCP credential.** Even when an upstream
> has a `<name>` REST provider, its **MCP** server often authenticates
> differently — Slack's REST API takes a static bot token (`xoxb-…`), but its MCP
> server requires an OAuth user token and rejects the bot token. Check the
> upstream's MCP auth before assuming a shared credspec; the per-upstream notes
> in [`mcp-github.md`](mcp-github.md) and [`mcp-slack.md`](mcp-slack.md) record which shape each server uses.

There is **no canonical generic MCP endpoint**, so this provider has **no default
upstream URL** — you must set `mcp_url` before the mount can serve traffic. A
single mount fronts one product; consumers select the right mount by its
operator-set description, not by reading the URL.

> **Per-upstream recipes.** Concrete, copy-pasteable setups for specific MCP
> servers live in the per-upstream pages [`mcp-github.md`](mcp-github.md) and [`mcp-slack.md`](mcp-slack.md).
> This page is the general operator guide; the per-upstream pages layer
> upstream-specific credential, URL, and quirk notes on top.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Step 1: Configure JWT Auth and Create a Role](#step-1-configure-jwt-auth-and-create-a-role)
- [Step 2: Mount and Configure the Provider](#step-2-mount-and-configure-the-provider)
- [Step 3: Create a Credential Source and Spec](#step-3-create-a-credential-source-and-spec)
- [Step 4: Create a Policy](#step-4-create-a-policy)
- [Step 5: Point an MCP Client at Warden](#step-5-point-an-mcp-client-at-warden)
- [TLS Certificate Authentication](#tls-certificate-authentication)
- [Configuration Reference](#configuration-reference)

## Prerequisites

- Docker and Docker Compose installed and running
- A reachable bearer-authenticated MCP server and its base URL
- A credential the upstream accepts: either OAuth2 client/consent details (for
  `oauth_bearer_token`) or a static API token (for `api_key`)
- An MCP client that supports remote MCP servers over HTTP (Claude Code, Cursor,
  Continue, Cline, Goose, ...)

> **New to Warden?** Follow these steps to get a local dev environment running:
>
> **1. Deploy the quickstart stack** — this starts an identity provider ([Ory Hydra](https://www.ory.sh/hydra/)) needed to issue JWTs for authentication in Steps 1 and 5:
> ```bash
> curl -fsSL -o docker-compose.quickstart.yml \
>   https://raw.githubusercontent.com/stephnangue/warden/main/deploy/docker-compose.quickstart.yml
> docker compose -f docker-compose.quickstart.yml up -d
> ```
>
> **2. Download the latest Warden binary:**
> ```bash
> # macOS (Apple Silicon)
> curl -L https://github.com/stephnangue/warden/releases/latest/download/warden_$(curl -s https://api.github.com/repos/stephnangue/warden/releases/latest | grep tag_name | cut -d '"' -f4 | tr -d v)_darwin_arm64.tar.gz | tar xz
>
> # macOS (Intel)
> curl -L https://github.com/stephnangue/warden/releases/latest/download/warden_$(curl -s https://api.github.com/repos/stephnangue/warden/releases/latest | grep tag_name | cut -d '"' -f4 | tr -d v)_darwin_amd64.tar.gz | tar xz
>
> # Linux (x86_64)
> curl -L https://github.com/stephnangue/warden/releases/latest/download/warden_$(curl -s https://api.github.com/repos/stephnangue/warden/releases/latest | grep tag_name | cut -d '"' -f4 | tr -d v)_linux_amd64.tar.gz | tar xz
>
> # Linux (ARM64)
> curl -L https://github.com/stephnangue/warden/releases/latest/download/warden_$(curl -s https://api.github.com/repos/stephnangue/warden/releases/latest | grep tag_name | cut -d '"' -f4 | tr -d v)_linux_arm64.tar.gz | tar xz
> ```
>
> **3. Add the binary to your PATH:**
> ```bash
> export PATH="$PWD:$PATH"
> ```
>
> **4. Start the Warden server** in dev mode:
> ```bash
> warden server -dev -dev-root-token=root
> ```
>
> **5. In another terminal window**, export the environment variables for the CLI:
> ```bash
> export PATH="$PWD:$PATH"
> export WARDEN_ADDR="http://127.0.0.1:8400"
> export WARDEN_TOKEN="root"
> ```

## Step 1: Configure JWT Auth and Create a Role

Set up a JWT auth method and create a role that binds the credential spec and
policy. Clients authenticate directly with their JWT — no separate login step is
needed.

> **This step must come before configuring the provider.** Warden validates at
> configuration time that the auth backend referenced by `auto_auth_path` is
> already mounted.

```bash
# Enable JWT auth if not already enabled
warden auth enable jwt

# Configure JWT with Hydra's JWKS endpoint (from docker-compose.quickstart.yml)
warden write auth/jwt/config jwks_url=http://localhost:4444/.well-known/jwks.json

# Create a role that binds the credential spec and policy
warden write auth/jwt/role/mcp-user \
    token_policies="mcp-access" \
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
decision (the `mcp_decision` for `mcp { }` rules), and the upstream URL.

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
at your MCP server's base URL. The default `timeout` is 10 minutes — raise it for
agent sessions that keep an SSE stream open across many tool calls:

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

Verify the configuration:

```bash
warden read cloudflare-mcp/config
```

## Step 3: Create a Credential Source and Spec

The provider accepts two credential shapes. Pick the one your upstream uses.

### Option A: OAuth2 (authorization-code flow) — e.g. Cloudflare, Slack

Most remote MCP servers use this. The upstream authenticates a browser-consented
OAuth2 grant. Warden stores the refresh token and mints a fresh access token per
request. Create an `oauth2` source and an `authorization_code` spec, then run the
connect flow once to record the user's consent. For the **Slack MCP server**
(`https://mcp.slack.com/mcp`), see [`mcp-slack.md`](mcp-slack.md) for the exact
endpoints and scopes — the Cloudflare example below shows the general shape:

The source holds the upstream's OAuth endpoints; the app's client credentials,
the pinned callback, and the requested scopes live on the spec (the
`client_secret` is read from a file so it never lands in shell history):

```bash
warden cred source create cf-oauth-src \
  -type=oauth2 \
  -rotation-period=0 \
  -config=auth_url=https://oauth.cloudflare.com/authorize \
  -config=token_url=https://oauth.cloudflare.com/token

warden cred spec create mcp-creds \
  -source cf-oauth-src \
  -config auth_method=authorization_code \
  -config client_id=<client-id> \
  -config client_secret=@/path/to/client-secret \
  -config redirect_uri=http://127.0.0.1:8765/callback \
  -config scopes="<space-separated scopes>"

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

### Option B: Static API key

For an MCP server that authenticates a fixed, long-lived bearer token — a
personal access token or a service token, common with self-hosted and enterprise
servers — rather than running an OAuth flow. Warden injects the token as
`Authorization: Bearer <token>`.

```bash
warden cred source create svc-mcp-src \
  -type=api_key \
  -rotation-period=0

warden cred spec create mcp-creds \
  -source svc-mcp-src \
  -config api_key=@/path/to/static-token
```

The minted credential is an `api_key`. This path fits servers that document a
fixed `Authorization: Bearer <token>`; if the server instead expects a token in a
non-`Authorization` header (e.g. `x-api-key`), it needs a dedicated provider, not
this one.

Verify the spec:

```bash
warden cred spec read mcp-creds
```

## Step 4: Create a Policy

MCP traffic passes through two complementary layers of authorization. The minted
bearer token is the security boundary — its scopes bound what the agent can
actually do at the upstream regardless of what Warden lets through. On top of
that, Warden's CBP policies support an `mcp { }` block for governance-style
restrictions enforced at the gateway: allow- and deny-lists for JSON-RPC
methods, tool names, resource URIs, prompt names, and selected tool arguments.

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
| `missing_body` | Request body absent on a path the backend opted into MCP enforcement for. POST/JSON-RPC traffic that fails to parse triggers this; non-POST verbs (GET for the SSE notification stream, DELETE for session terminate) silently skip `mcp { }` evaluation |
| `malformed_jsonrpc` | Body is not a well-formed JSON-RPC 2.0 envelope (bad version, missing method, unknown top-level key, UTF-8 BOM, etc.) |
| `duplicate_key` | Duplicate object key detected anywhere in the body |
| `oversized_body` | Body exceeds the mount's `max_body_size` |
| `batch_empty` | JSON-RPC batch is `[]` |
| `malformed_params` | A name-bearing method (`tools/call`, `resources/read`, `prompts/get`) has a missing or wrong-shape `params.name` / `params.uri` |

MCP Streamable HTTP uses three HTTP verbs on the same `/gateway/` URL: POST for
JSON-RPC requests (mapped by Warden to `create`), GET for the optional server →
client SSE notification stream (`read`), and DELETE for session terminate
(`delete`). All three need to be in the cap list or off-spec MCP clients fail to
connect. The `mcp { }` block only fires on the POST half; GET/DELETE skip
body-authoritative evaluation automatically.

`mcp { }` authorization is **deny-by-default**: an empty or absent
`allowed_methods`/`allowed_tools` denies everything, so a block grants only what
it allow-lists — use `["*"]` to open a family fully. The session-lifecycle
methods `initialize`, `notifications/*`, and `ping` are **exempt**: they always
pass without being listed, so the client handshake works no matter how narrow the
data-plane allow-list is (an explicit `denied_methods` entry can still block them).

The simplest policy grants the gateway and leans on the token's scopes for
everything:

```bash
warden policy write mcp-access - <<EOF
path "cloudflare-mcp/role/+/gateway*" {
  capabilities = ["create", "read", "delete"]
}
EOF
```

A policy that restricts the agent to a vetted set of tools:

```bash
warden policy write mcp-readonly - <<EOF
path "cloudflare-mcp/role/+/gateway*" {
  capabilities = ["create", "read", "delete"]
  mcp {
    allowed_methods = ["tools/list", "tools/call", "resources/list", "resources/read"]
    allowed_tools   = ["search_docs", "list_*", "get_*"]
  }
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
  mcp {
    allowed_methods = ["*"]
    allowed_tools   = ["*"]
    denied_tools    = ["delete_*", "purge_*", "update_*"]
  }
}
EOF
```

When a request hits the `mcp { }` gate and is denied, Warden returns HTTP 403
with a structured JSON body and an RFC 6750 `WWW-Authenticate` header; MCP client
SDKs surface this to the agent as a tool-call failure with an actionable message.
The audit log records the matched rule and the offending tool/parameter.
Policies that omit the `mcp { }` block keep today's behaviour: Warden passes the
request through unchanged and the token's scopes alone enforce authorization.

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

> **Prerequisite:** Certificate authentication requires TLS to be enabled on the
> Warden listener so client certificates can be presented during the TLS
> handshake (mTLS). In dev mode, use `-dev-tls`, or provide your own with
> `-dev-tls-cert-file`, `-dev-tls-key-file`, and `-dev-tls-ca-cert-file`.
> Alternatively, place Warden behind a load balancer that terminates TLS and
> forwards the client certificate via `X-Forwarded-Client-Cert` or
> `X-SSL-Client-Cert`.

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
    token_policies="mcp-access" \
    cred_spec_name=mcp-creds
```

`allowed_common_names` supports glob patterns. You can also match on
`allowed_dns_sans`, `allowed_email_sans`, `allowed_uri_sans`, or
`allowed_organizational_units`.

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

## Configuration Reference

### Provider Config

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `mcp_url` | string | — | **Required.** MCP server base URL (must be HTTPS). No default — there is no canonical generic MCP endpoint |
| `max_body_size` | int | 10485760 (10 MB) | Maximum request body size in bytes (max 100 MB) |
| `timeout` | duration | `10m` | Session timeout. Raise for long agent sessions that keep an SSE stream open across many tool calls |
| `tls_skip_verify` | bool | `false` | Skip TLS certificate verification (development only) |
| `ca_data` | string | — | Base64-encoded PEM CA certificate for custom/self-signed CAs |
| `auto_auth_path` | string | — | **Required.** Auth mount path for implicit authentication (e.g., `auth/jwt/`, `auth/cert/`) |
| `default_role` | string | — | Fallback role when not specified in URL or header |

### Accepted Credential Types

| Credential type | Source type | Injected as | Use for |
|-----------------|-------------|-------------|---------|
| `oauth_bearer_token` | `oauth2` | `Authorization: Bearer <token>` | OAuth2 MCP servers (Slack, Cloudflare, Linear, Sentry, ...) — incl. authorization-code consent flow. The shape most remote MCP servers require |
| `api_key` | `api_key` | `Authorization: Bearer <token>` | MCP servers that authenticate a fixed bearer token (personal/service token; self-hosted & enterprise) |
| `github_token` | `github` | `Authorization: Bearer <token>` | GitHub's hosted MCP server — App token or PAT; same credspec as the `github` REST provider. See [`mcp-github.md`](mcp-github.md) |
| `gcp_access_token` | `gcp` | `Authorization: Bearer <token>` | A Google Cloud MCP server — same credspec as the `gcp` REST provider |

Servers that expect a static key in a non-`Authorization` header (e.g.
`x-api-key`), or that require request signing (AWS SigV4 — use `mcp_aws`), are
**not** served by this provider.
