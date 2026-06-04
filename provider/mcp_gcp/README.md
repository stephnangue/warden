# Google Cloud MCP Provider

The `mcp_gcp` provider enables proxied access to a Google Cloud MCP (Model Context Protocol) server through Warden. MCP clients (Claude Code, Cursor, Continue, Cline, Goose, ...) point at Warden instead of the MCP server; Warden authenticates the caller, mints a short-lived GCP access token bound to the chosen role, injects it as `Authorization: Bearer <token>`, and streams JSON or SSE responses back unchanged. Agents never hold a service account key or token.

Unlike GitHub's hosted MCP server, Google Cloud has **no single canonical MCP endpoint**. Operators run MCP servers on Cloud Run, Vertex AI, the genai toolbox, and elsewhere, so this provider has **no default upstream URL** — you must set `mcp_gcp_url` before the mount can serve traffic. A single mount fronts one product; consumers select the right mount by its operator-set description, not by reading the URL.

The same credential spec used by the `gcp` REST provider works here unchanged — one role binding grants both REST and MCP reach.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Step 1: Configure JWT Auth and Create a Role](#step-1-configure-jwt-auth-and-create-a-role)
- [Step 2: Mount and Configure the Provider](#step-2-mount-and-configure-the-provider)
- [Step 3: Create a Credential Source and Spec](#step-3-create-a-credential-source-and-spec)
- [Step 4: Create a Policy](#step-4-create-a-policy)
- [Step 5: Point an MCP Client at Warden](#step-5-point-an-mcp-client-at-warden)
- [TLS Certificate Authentication](#tls-certificate-authentication)
- [Configuration Reference](#configuration-reference)
- [Token Scopes, IAM, and Tool Availability](#token-scopes-iam-and-tool-availability)

## Prerequisites

- Docker and Docker Compose installed and running
- A reachable Google Cloud MCP server (e.g. an MCP server you deployed on Cloud Run, a Vertex AI surface, or the genai toolbox) and its base URL
- A Google Cloud **service account key** (JSON), and the IAM roles covering the MCP tools you want to expose. Optionally a **target service account** to impersonate, so the source key never needs the end permissions directly
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
    token_policies="mcp-gcp-access" \
    user_claim=sub \
    cred_spec_name=gcp-ops
```

## Step 2: Mount and Configure the Provider

Enable the `mcp_gcp` provider with a description that identifies the product behind the mount. Because a `mcp_gcp` mount can front any Google Cloud MCP server, the description is how agents and the discovery flow tell mounts apart — set a clear one:

```bash
warden provider enable -description="Vertex AI MCP (prod)" mcp_gcp
```

To mount at a custom path:

```bash
warden provider enable -path=vertex-mcp -description="Vertex AI MCP (prod)" mcp_gcp
```

Verify the provider is enabled:

```bash
warden provider list
```

Configure the provider. **`mcp_gcp_url` is required — there is no default.** Point it at your MCP server's base URL. The default `timeout` is 10 minutes — raise it for agent sessions that keep an SSE stream open across many tool calls:

```bash
warden write mcp_gcp/config <<EOF
{
  "mcp_gcp_url": "https://my-mcp-server-xxxxxxxx.a.run.app/mcp",
  "auto_auth_path": "auth/jwt/",
  "timeout": "10m",
  "max_body_size": 10485760
}
EOF
```

Verify the configuration:

```bash
warden read mcp_gcp/config
```

## Step 3: Create a Credential Source and Spec

If you already configured a credential source and spec for the `gcp` REST provider, you can reuse them here unchanged — the same key and mint method work for both flows. Skip to Step 4.

> **Token type — access token, not ID token.** The `gcp` source mints an OAuth2 **access token** (`mint_method=access_token` or `impersonated_access_token`). That authenticates to Google Cloud APIs and to MCP servers that validate access tokens at the application layer. It is **not** an OIDC **ID token**, so an MCP server behind IAM-authenticated Cloud Run ingress (`--no-allow-unauthenticated`, which requires an ID token scoped to the service URL) will reject it. For that deployment shape, run the MCP server with unauthenticated ingress and let Warden + the MCP server's app-layer token check enforce access, or front it with a proxy that performs the ID-token exchange.

The credential source holds the service account key Warden uses to mint tokens. The credential spec selects how a token is minted (`mint_method`) and which scopes it carries, so multiple specs with different reach can share one source.

```bash
warden cred source create gcp-src \
  -type=gcp \
  -rotation-period=0 \
  -config=service_account_key=@/path/to/service-account-key.json
```

Verify the source was created:

```bash
warden cred source read gcp-src
```

### Option A: Service Account Access Token

Mints an OAuth2 access token directly for the source service account. Grant that service account the IAM roles covering the MCP tools you intend to use.

```bash
warden cred spec create gcp-ops \
  -source gcp-src \
  -config mint_method=access_token \
  -config scopes=https://www.googleapis.com/auth/cloud-platform
```

### Option B: Impersonated Access Token (Recommended)

Mints a token for a *target* service account by impersonation, so the source key holds only the Token Creator role and never the end permissions. Grant the source service account `roles/iam.serviceAccountTokenCreator` on the target, and grant the target the IAM roles covering the tools.

```bash
warden cred spec create gcp-ops \
  -source gcp-src \
  -config mint_method=impersonated_access_token \
  -config target_service_account=mcp-runtime@my-project.iam.gserviceaccount.com \
  -config scopes=https://www.googleapis.com/auth/cloud-platform
```

Warden mints a short-lived (≈1 hour) access token at request time and refreshes before expiry. The agent never sees the service account key or the access token.

Verify:

```bash
warden cred spec read gcp-ops
```

## Step 4: Create a Policy

MCP traffic passes through two complementary layers of authorization. The minted GCP access token is the security boundary — its scopes and the service account's IAM bindings bound what the agent can actually do at Google Cloud regardless of what Warden lets through. On top of that, Warden's CBP policies support an `mcp { }` block for governance-style restrictions enforced at the gateway: allow- and deny-lists for JSON-RPC methods, tool names, resource URIs, prompt names, and selected tool arguments.

Enforcement is **body-authoritative**. When a policy in scope contains an `mcp { }` block, Warden strict-parses the JSON-RPC request body and matches against the parsed body. The parser fails closed on any structural problem and the matcher denies with a specific `rule_type`:

| `rule_type` | Trigger |
|---|---|
| `denied_methods` / `allowed_methods` | JSON-RPC `method` matches a deny pattern, or is absent from a configured allow list |
| `denied_tools` / `allowed_tools` | `tools/call` with a `params.name` matching a deny pattern, or not in the allow list |
| `denied_resources` / `allowed_resources` | `resources/read` with a `params.uri` matching a deny pattern, or not in the allow list |
| `denied_prompts` / `allowed_prompts` | `prompts/get` with a `params.name` matching a deny pattern, or not in the allow list |
| `denied_params` / `allowed_params` | A `tools/call` argument (`params.arguments.<key>`) matches a deny pattern, or — when present — fails an allow-list pattern. Both rules are conditional on presence: missing arguments don't trigger either, matching Vault's `allowed_parameters` semantics. Tools whose argument shape doesn't include the gated key pass through unaffected. |
| `missing_body` | Request body absent on a path the backend opted into MCP enforcement for. POST/JSON-RPC traffic that fails to parse triggers this; non-POST verbs (GET for the SSE notification stream, DELETE for session terminate) silently skip `mcp { }` evaluation — the body-authoritative gate doesn't apply to body-less verbs. |
| `malformed_jsonrpc` | Body is not a well-formed JSON-RPC 2.0 envelope (bad version, missing method, unknown top-level key, UTF-8 BOM, etc.) |
| `duplicate_key` | Duplicate object key detected anywhere in the body — Warden rejects ambiguity that Go's standard JSON parser silently last-wins-resolves |
| `oversized_body` | Body exceeds the mount's `max_body_size` |
| `batch_empty` | JSON-RPC batch is `[]` |
| `malformed_params` | A name-bearing method (`tools/call`, `resources/read`, `prompts/get`) has a missing or wrong-shape `params.name` / `params.uri` |

All examples below use `capabilities = ["create", "read", "delete"]`. MCP Streamable HTTP uses three HTTP verbs on the same `/gateway/` URL: POST for JSON-RPC requests (mapped by Warden to `create`), GET for the optional server → client SSE notification stream (`read`), and DELETE for session terminate (`delete`). All three need to be in the cap list or off-spec MCP clients fail to connect. The `mcp { }` block only fires on the POST half; GET/DELETE skip body-authoritative evaluation automatically.

The `allowed_methods` examples below list the MCP **protocol** methods every spec-compliant client uses in its handshake — `initialize`, `notifications/initialized`, `ping` — alongside the data-plane methods (`tools/list`, `tools/call`, …). Omitting the lifecycle methods makes `claude mcp list` (and similar client health checks) hang on connect.

The simplest policy grants the gateway and leans on IAM for everything:

```bash
warden policy write mcp-gcp-access - <<EOF
path "mcp_gcp/role/+/gateway*" {
  capabilities = ["create", "read", "delete"]
}
EOF
```

A policy that restricts the agent to a vetted set of tools:

```bash
warden policy write mcp-gcp-readonly - <<EOF
path "mcp_gcp/role/+/gateway*" {
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
    allowed_tools   = ["list_datasets", "get_table", "query", "list_buckets"]
  }
}
EOF
```

A complementary deny-list shape — permissive by default, blocks dangerous tools:

```bash
warden policy write mcp-gcp-safe - <<EOF
path "mcp_gcp/role/+/gateway*" {
  capabilities = ["create", "read", "delete"]
  mcp {
    denied_tools = ["delete_*", "drop_*", "update_iam_policy"]
  }
}
EOF
```

Argument-level gates restrict the *values* passed to `tools/call`. Keys in `denied_params` / `allowed_params` match against `params.arguments.<key>` from the parsed body — both rules skip on missing arguments, so a tool that doesn't take `projectId` at all isn't affected. The policy below permits tool calls but never against production projects:

```bash
warden policy write mcp-gcp-no-prod - <<EOF
path "mcp_gcp/role/+/gateway*" {
  capabilities = ["create", "read", "delete"]
  mcp {
    allowed_methods = [
      "initialize",
      "notifications/initialized",
      "tools/call",
      "ping"
    ]
    denied_params = {
      projectId = ["prod-*", "production-*"]
    }
  }
}
EOF
```

The `mcp { }` block composes with runtime conditions so you can layer environment guards on top of tool-level restrictions:

```bash
warden policy write mcp-gcp-business-hours - <<EOF
path "mcp_gcp/role/+/gateway*" {
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
    allowed_tools   = ["list_*", "get_*", "query"]
  }
}
EOF
```

When a request hits the `mcp { }` gate and is denied, Warden returns HTTP 403 with a structured JSON body and an RFC 6750 `WWW-Authenticate` header; MCP client SDKs surface this to the agent as a tool-call failure with an actionable message. The audit log records the matched rule and the offending tool/parameter so operators can debug policy decisions centrally. Policies that omit the `mcp { }` block keep today's behaviour: Warden passes the request through unchanged and the token's IAM reach alone enforces authorization.

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
${WARDEN_ADDR}/v1/mcp_gcp/role/{role}/gateway/
```

For Claude Code, Cursor, Continue, Cline, Goose, and other clients that accept Streamable HTTP MCP servers via a JSON config block:

```json
{
  "mcpServers": {
    "gcp": {
      "type": "http",
      "url": "${WARDEN_ADDR}/v1/mcp_gcp/role/mcp-user/gateway/",
      "headers": {
        "Authorization": "Bearer ${JWT_TOKEN}"
      }
    }
  }
}
```

> **Heads-up on `${VAR}` in headers.** MCP clients vary in what they substitute in `.mcp.json`. Claude Code and Cursor expand `${VAR}` in stdio `env` blocks and in the `url` field, but **HTTP-transport `headers` values are a known gap** — the literal `${JWT_TOKEN}` string ships on the wire. For the `Authorization` header (and the routing headers in the next example), paste the actual values instead of `${...}` placeholders, or run the JSON through `envsubst` at deploy time.

#### Header-routed alternative

Some MCP clients dislike long URLs, or you want one base URL to mux several Warden providers. Pass the mount path as `X-Warden-Provider`, the namespace as `X-Warden-Namespace`, and the role as `X-Warden-Role` instead — Warden synthesises the canonical gateway path from the headers. Look up the mount path by its description first:

```bash
path=$(warden provider list -o json | jq -r '.[] | select(.description=="<your-mount-description>") | .path' | head -1)
```

The `path` is what `warden provider list` returns (e.g., `mcp_gcp/`, `team-data/vertex-mcp/`), **not** the literal string `mcp_gcp` — Warden routes on the mount path, not the provider type. Select by `description` because several `mcp_gcp` mounts may front different Google Cloud products.

```json
{
  "mcpServers": {
    "gcp": {
      "type": "http",
      "url": "${WARDEN_ADDR}/",
      "headers": {
        "Authorization": "Bearer ${JWT_TOKEN}",
        "X-Warden-Provider": "mcp_gcp/",
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
curl -X POST "${WARDEN_ADDR}/v1/mcp_gcp/role/mcp-user/gateway/" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

Call a tool:

```bash
curl -X POST "${WARDEN_ADDR}/v1/mcp_gcp/role/mcp-user/gateway/" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_datasets","arguments":{"projectId":"my-project"}}}'
```

The trailing slash on `gateway/` matters — Warden composes the upstream URL as the mount's configured upstream URL plus the gateway suffix.

## TLS Certificate Authentication

Steps 1 and 5 above use JWT authentication. Alternatively, you can authenticate with a TLS client certificate. This is useful for workloads that already have X.509 certificates — Kubernetes pods with cert-manager, VMs with machine certificates, or SPIFFE X.509-SVIDs from a service mesh.

> **Prerequisite:** Certificate authentication requires TLS to be enabled on the Warden listener so that client certificates can be presented during the TLS handshake (mTLS). In dev mode, use `-dev-tls` to enable TLS with auto-generated certificates, or provide your own with `-dev-tls-cert-file`, `-dev-tls-key-file`, and `-dev-tls-ca-cert-file`. Alternatively, place Warden behind a load balancer that terminates TLS and forwards the client certificate via the `X-Forwarded-Client-Cert` or `X-SSL-Client-Cert` header.

Steps 2-4 (provider mount, credential source and spec, policy) are identical — the `mcp-gcp-access` policy from Step 4 works for either auth method. Replace Steps 1 and 5 with the following.

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
    token_policies="mcp-gcp-access" \
    cred_spec_name=gcp-ops
```

The `allowed_common_names` field supports glob patterns. You can also match on other certificate fields: `allowed_dns_sans`, `allowed_email_sans`, `allowed_uri_sans`, or `allowed_organizational_units`.

### Configure Provider for Cert Auth

Update the provider config to point at the cert auth mount:

```bash
warden write mcp_gcp/config <<EOF
{
  "mcp_gcp_url": "https://my-mcp-server-xxxxxxxx.a.run.app/mcp",
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
    -X POST "https://warden.internal/v1/mcp_gcp/role/mcp-user/gateway/" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json, text/event-stream" \
    -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

#### MCP Client JSON Config (cert auth)

**State of mTLS in MCP clients today.** The MCP specification does not standardize a client-side TLS configuration block, and the major IDE clients (Claude Code, Cursor, Continue) do not currently expose first-class fields for client certificate / key paths in their HTTP server configuration. Until that lands, two portable patterns work — both using header-routed mode so the MCP client only needs to set headers, never a deep URL.

Look up the mount path and namespace first:

```bash
path=$(warden provider list -o json | jq -r '.[] | select(.description=="<your-mount-description>") | .path' | head -1)
namespace=$WARDEN_NAMESPACE   # whatever your default namespace is
```

The `path` is the mount path Warden returns from `warden provider list` (e.g., `mcp_gcp/`, `team-data/vertex-mcp/`), **not** the literal string `mcp_gcp`. Same gotcha as the JWT header-routed flow in the skill.

**Pattern A: Local mTLS-terminating sidecar (recommended).** Run a sidecar (Envoy, nginx, stunnel, `mtls-proxy`) on the agent host that holds the client cert/key and the trusted CA. The MCP client talks plain HTTP over loopback to the sidecar; the sidecar terminates client TLS, validates Warden's server cert, and forwards the request over mTLS with the validated client certificate attached as `X-SSL-Client-Cert` (URL-encoded PEM) or `X-Forwarded-Client-Cert`. Warden trusts the forwarded header when the listener is configured to do so.

```json
{
  "mcpServers": {
    "gcp": {
      "type": "http",
      "url": "http://127.0.0.1:9443/",
      "headers": {
        "X-Warden-Provider": "mcp_gcp/",
        "X-Warden-Namespace": "<namespace>",
        "X-Warden-Role": "mcp-user"
      }
    }
  }
}
```

Substitute `mcp_gcp/` with your mount's actual `path` and `<namespace>` with your namespace before saving — see the env-var caveat in Step 5: `${VAR}` placeholders in HTTP-transport `headers` are not expanded by the major MCP clients today. Drop the `X-Warden-Role` header when cert auth's `default_role` already covers the binding.

**Pattern B: `mcp-remote` as a Node-based bridge.** Many MCP installations already use `mcp-remote` (an npx-launched HTTP-to-stdio bridge) for transport-shape reasons. It runs in Node.js, so Node's TLS environment variables flow through: `NODE_EXTRA_CA_CERTS=/path/to/warden-ca.pem` for a custom CA. Client certificate handling via `mcp-remote` requires a custom Node TLS context and is not as turnkey — for most deployments Pattern A is simpler. A typical CA-only setup (Warden's server cert validated by a private CA; mTLS still requires Pattern A) looks like:

```json
{
  "mcpServers": {
    "gcp": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "https://warden.internal/",
        "--transport", "http-only",
        "--header", "X-Warden-Provider: mcp_gcp/",
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
| `mcp_gcp_url` | string | — | **Required.** MCP server base URL (must be HTTPS). No default — Google Cloud has no canonical MCP endpoint |
| `max_body_size` | int | 10485760 (10 MB) | Maximum request body size in bytes (max 100 MB) |
| `timeout` | duration | `10m` | Session timeout. Raise for long agent sessions that keep an SSE stream open across many tool calls |
| `tls_skip_verify` | bool | `false` | Skip TLS certificate verification (development only) |
| `ca_data` | string | — | Base64-encoded PEM CA certificate for custom/self-signed CAs |
| `auto_auth_path` | string | — | **Required.** Auth mount path for implicit authentication (e.g., `auth/jwt/`, `auth/cert/`) |
| `default_role` | string | — | Fallback role when not specified in URL or header |

### Credential Spec Config (gcp source)

| Field | Default | Description |
|-------|---------|-------------|
| `mint_method` | `access_token` | `access_token` (token for the source SA) or `impersonated_access_token` (token for a target SA via impersonation) |
| `scopes` | `https://www.googleapis.com/auth/cloud-platform` | Comma-separated OAuth2 scopes the minted token carries |
| `target_service_account` | — | Required when `mint_method=impersonated_access_token`; the SA to impersonate |

## Token Scopes, IAM, and Tool Availability

The upstream MCP server enforces Google Cloud IAM on the minted token. The set of MCP tools that actually succeed through a given mount is determined by the **bound token's scopes and the service account's IAM bindings**, not by Warden policy. A `403` or `permission denied` from a `tools/call` request typically means the bound service account (or impersonated target) lacks a required IAM role, or the token's `scopes` don't cover the API.

Provision IAM with least privilege:

- **Service account access token (Option A):** grant the source service account the IAM roles covering the tools (e.g., `roles/bigquery.dataViewer`, `roles/storage.objectViewer`).
- **Impersonated access token (Option B, recommended):** grant the source service account only `roles/iam.serviceAccountTokenCreator` on the target, and grant the *target* the tool IAM roles. The source key then never holds the end permissions directly, and you can give different roles different reach by pointing specs at different target service accounts.

**Rotate the source key** by updating the credential source:

```bash
warden cred source update gcp-src \
  -config service_account_key=@/path/to/new-key.json
```

Then disable the old key in the Google Cloud console. Minted access tokens are short-lived (≈1 hour) and auto-refreshed, so they require no rotation.
