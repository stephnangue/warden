# GitHub MCP Provider

The `mcp_github` provider enables proxied access to GitHub's hosted MCP (Model Context Protocol) server through Warden. MCP clients (Claude Code, Cursor, Continue, Cline, Goose, ...) point at Warden instead of `api.githubcopilot.com`; Warden authenticates the caller, injects a GitHub token bound to the chosen role as `Authorization: Bearer <token>`, and streams JSON or SSE responses back unchanged. Agents never hold a GitHub credential.

It supports both **GitHub App** and **Personal Access Token (PAT)** authentication. The same credential spec used by the `github` REST provider works here unchanged — one role binding grants both REST and MCP reach.

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
  - **Personal Access Token** (classic or fine-grained) with the scopes covering the MCP tools you want to expose (e.g., `repo`, `issues`, `pull_requests`)
- An MCP client that supports remote MCP servers over HTTP (Claude Code, Cursor, Continue, Cline, Goose, ...)

> **New to Warden?** Follow the standard quickstart flow used by the other provider READMEs (the `github` and `slack` READMEs cover it step by step): deploy the quickstart compose, install the binary, export `WARDEN_ADDR` and `WARDEN_TOKEN`, then return here.

## Step 1: Configure JWT Auth and Create a Role

Set up a JWT auth method and create a role that binds the credential spec and policy. Clients authenticate directly with their JWT — no separate login step is needed.

> **This step must come before configuring the provider.** Warden validates at configuration time that the auth backend referenced by `auto_auth_path` is already mounted.

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

## Step 4: Create a Policy

MCP traffic passes through two complementary layers of authorization. The minted GitHub token is the security boundary — its scopes bound what the agent can actually do at GitHub regardless of what Warden lets through. On top of that, Warden's CBP policies support an `mcp { }` block for governance-style restrictions enforced at the gateway: allow- and deny-lists for JSON-RPC methods, tool names, resource URIs, prompt names, and selected tool arguments.

Enforcement is **body-authoritative**. When a policy in scope contains an `mcp { }` block, Warden strict-parses the JSON-RPC request body and matches against the parsed body. The parser fails closed on any structural problem and the matcher denies with a specific `rule_type`:

| `rule_type` | Trigger |
|---|---|
| `denied_methods` / `allowed_methods` | JSON-RPC `method` matches a deny pattern, or is absent from a configured allow list |
| `denied_tools` / `allowed_tools` | `tools/call` with a `params.name` matching a deny pattern, or not in the allow list |
| `denied_resources` / `allowed_resources` | `resources/read` with a `params.uri` matching a deny pattern, or not in the allow list |
| `denied_prompts` / `allowed_prompts` | `prompts/get` with a `params.name` matching a deny pattern, or not in the allow list |
| `denied_params` / `allowed_params` | A `tools/call` argument (`params.arguments.<key>`) matches a deny pattern, or fails an allow-list pattern (or is missing when required) |
| `missing_body` | Request body absent, or routed to a backend that does not opt into MCP enforcement (typically a non-POST request — operators should not bind `mcp { }` to paths that receive non-POST traffic) |
| `malformed_jsonrpc` | Body is not a well-formed JSON-RPC 2.0 envelope (bad version, missing method, unknown top-level key, UTF-8 BOM, etc.) |
| `duplicate_key` | Duplicate object key detected anywhere in the body — Warden rejects ambiguity that Go's standard JSON parser silently last-wins-resolves |
| `oversized_body` | Body exceeds the mount's `max_body_size` |
| `batch_empty` | JSON-RPC batch is `[]` |
| `malformed_params` | A name-bearing method (`tools/call`, `resources/read`, `prompts/get`) has a missing or wrong-shape `params.name` / `params.uri` |

All examples below use `capabilities = ["create"]`. MCP traffic is HTTP POST and Warden maps POST to the `create` operation. Use `["create", "update"]` if your client also issues PUT to the gateway.

The simplest policy grants the gateway and leans on PAT scopes for everything:

```bash
warden policy write mcp-github-access - <<EOF
path "mcp_github/role/+/gateway*" {
  capabilities = ["create"]
}
EOF
```

A policy that restricts the agent to a vetted set of GitHub tools:

```bash
warden policy write mcp-github-readonly - <<EOF
path "mcp_github/role/+/gateway*" {
  capabilities = ["create"]
  mcp {
    allowed_methods = ["tools/list", "tools/call", "resources/list", "resources/read"]
    allowed_tools   = ["get_repository", "get_pull_request", "list_issues", "search_code"]
  }
}
EOF
```

A complementary deny-list shape — permissive by default, blocks dangerous tools:

```bash
warden policy write mcp-github-safe - <<EOF
path "mcp_github/role/+/gateway*" {
  capabilities = ["create"]
  mcp {
    denied_tools = ["delete_*", "force_*", "merge_pull_request"]
  }
}
EOF
```

Argument-level gates restrict the *values* passed to `tools/call`. Keys in `denied_params` / `allowed_params` match against `params.arguments.<key>` from the parsed body. The policy below permits `create_or_update_file` but never on protected branches:

```bash
warden policy write mcp-github-no-protected-branches - <<EOF
path "mcp_github/role/+/gateway*" {
  capabilities = ["create"]
  mcp {
    allowed_methods = ["tools/call"]
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
  capabilities = ["create"]
  conditions {
    source_ip   = ["10.0.0.0/8"]
    time_window = ["08:00-18:00 UTC"]
    day_of_week = ["Mon", "Tue", "Wed", "Thu", "Fri"]
  }
  mcp {
    allowed_methods = ["tools/list", "tools/call"]
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
