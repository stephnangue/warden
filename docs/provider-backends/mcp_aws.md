# AWS MCP Provider

The `mcp_aws` provider enables proxied access to AWS-hosted MCP (Model Context Protocol) servers through Warden. MCP clients (Claude Code, Cursor, Continue, Cline, Goose, ...) point at Warden instead of the AWS MCP endpoint; Warden authenticates the caller, mints short-lived STS credentials bound to the chosen role, signs the upstream request with AWS SigV4, and streams JSON or SSE responses back unchanged. Agents never hold an IAM access key.

The same provider fronts both **AWS's hosted MCP Server** (the GA product reached at `aws-mcp.{region}.api.aws/mcp`, which exposes a single `call_aws` tool that gives agents access to every AWS API) and **customer-owned MCP servers hosted on Bedrock AgentCore Runtime or Gateway** (where the tools and their argument shapes are whatever the customer's server exposes). One mount per upstream — describe each mount so operators and agents can pick the right one.

## Why use Warden in front of this?

AWS ships its own client-side helper, `mcp-proxy-for-aws`, that signs MCP requests with SigV4 using credentials it reads from the local AWS configuration (env vars, profile, IMDS, process provider). Running it works, but it pushes the security boundary all the way down to every agent host: an `~/.aws/credentials` file on each laptop, each container, each CI runner. Compromise one host, leak whatever IAM that profile holds.

With Warden in front:

- **Clients present an identity Warden recognizes, never IAM credentials.** That identity is whatever the operator's chosen Warden auth method accepts — a short-lived JWT (issued by an OIDC provider, or a Kubernetes cluster), or a TLS client certificate presented during the mTLS handshake (cert-manager, SPIFFE, machine certificates). No IAM access keys on the agent host. No `~/.aws/credentials`, no `AWS_ACCESS_KEY_ID`, no profile.
- **STS credentials are minted per request** by the `aws` source driver and live inside the Warden server only. They never leave the broker.
- **Revocation is "delete the role"**, not "rotate keys on N machines". The next request mints fresh credentials under the new policy; nothing on the agent side changes.
- **Every signed call lands in CloudTrail** tied to the assumed-role identity and (via Warden's audit log) to the originating Warden session. The audit trail joins both sides.

For a single developer with a laptop and personal AWS creds, `mcp-proxy-for-aws` is fine. For a fleet of agents — production workflows, CI runners, shared dev environments — having Warden broker the credentials is the difference between credential hygiene that scales and a sprawling credential surface.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Step 1: Configure JWT Auth and Create a Role](#step-1-configure-jwt-auth-and-create-a-role)
- [Step 2: Mount and Configure the Provider](#step-2-mount-and-configure-the-provider)
- [Step 3: Create a Credential Source and Spec](#step-3-create-a-credential-source-and-spec)
- [Step 4: Create a Policy](#step-4-create-a-policy)
- [Step 5: Point an MCP Client at Warden](#step-5-point-an-mcp-client-at-warden)
- [TLS Certificate Authentication](#tls-certificate-authentication)
- [Configuration Reference](#configuration-reference)
- [IAM Permissions and Tool Availability](#iam-permissions-and-tool-availability)

## Prerequisites

- Docker and Docker Compose installed and running
- An AWS account with:
  - An IAM role the broker can assume on the agent's behalf (with permissions covering the AWS operations the agent will make), and
  - Permanent IAM credentials (access key + secret) for an identity that has `sts:AssumeRole` on the target role — these stay inside Warden's credential source and never reach the agent
- An MCP client that supports remote MCP servers over HTTP (Claude Code, Cursor, Continue, Cline, Goose, ...)

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

Set up a JWT auth method and create a role that binds the credential spec and policy. Clients authenticate directly with their JWT — no separate login step is needed.

> **This step must come before configuring the provider.** Warden validates at configuration time that the auth backend referenced by `auto_auth_path` is already mounted.

```bash
# Enable JWT auth if not already enabled
warden auth enable jwt

# Configure JWT with Hydra's JWKS endpoint (from docker-compose.quickstart.yml)
warden write auth/jwt/config jwks_url=http://localhost:4444/.well-known/jwks.json

# Create a role that binds the credential spec and policy
warden write auth/jwt/role/s3-reader \
    token_policies="mcp-aws-s3-readonly" \
    user_claim=sub \
    cred_spec_name=aws-s3-reader
```

## Step 2: Mount and Configure the Provider

Enable the `mcp_aws` provider at a path of your choice:

```bash
warden provider enable mcp_aws
```

To mount at a custom path — useful when you intend to mount more than one (one per AWS deployment pattern, or one per region):

```bash
warden provider enable -path=aws-mcp -description "AWS MCP Server (us-east-1) — S3+DynamoDB reach" mcp_aws
```

Verify the provider is enabled:

```bash
warden provider list
```

Configure the provider. For the GA AWS MCP Server, the default URL resolves the signing region automatically; for Bedrock AgentCore or non-standard hosts, you may need to set `region` explicitly.

```bash
warden write mcp_aws/config <<EOF
{
  "mcp_aws_url": "https://aws-mcp.us-east-1.api.aws/mcp",
  "auto_auth_path": "auth/jwt/",
  "timeout": "10m",
  "max_body_size": 10485760
}
EOF
```

For a customer-owned MCP server on Bedrock AgentCore Runtime:

```bash
warden write mcp_aws/config <<EOF
{
  "mcp_aws_url": "https://runtime.bedrock-agentcore.us-east-1.amazonaws.com/agents/myMcp/invocations",
  "auto_auth_path": "auth/jwt/",
  "timeout": "10m",
  "max_body_size": 10485760
}
EOF
```

For hosts where the signing region cannot be inferred from the URL (GovCloud, China partition, custom test hosts), set `region` explicitly:

```bash
warden write mcp_aws/config <<EOF
{
  "mcp_aws_url": "https://my-mcp.example.com/mcp",
  "region": "us-west-2",
  "auto_auth_path": "auth/jwt/",
  "timeout": "10m",
  "max_body_size": 10485760
}
EOF
```

Verify the configuration:

```bash
warden read mcp_aws/config
```

## Step 3: Create a Credential Source and Spec

If you already configured an `aws` credential source for another provider (the [`aws` REST provider's README](aws.md) walks through the IAM-user setup in full), you can reuse it here unchanged — `mcp_aws` consumes the same source-and-spec shape. Skip to Step 4 if so.

The credential source holds the permanent IAM access key Warden uses to call STS; credential specs on top of it define which role each Warden role assumes. The agent never sees either the source's permanent keys or the minted STS credentials.

```bash
warden cred source create aws-src \
  -type aws \
  -rotation-period 24h \
  -config access_key_id=<AccessKeyId> \
  -config secret_access_key=<SecretAccessKey> \
  -config region=us-east-1
```

`-rotation-period` is how often Warden rotates the source's IAM access keys. Longer periods are acceptable when the IAM user only has `sts:AssumeRole` (no direct resource access); shorter periods (`12h`-`24h`) suit stricter environments. See the [`aws` provider README](aws.md) for a full discussion of the IAM-user policy shape required here.

Verify:

```bash
warden cred source read aws-src
```

Create a credential spec that assumes a target IAM role via STS. The role's permissions are what gate which AWS calls the agent can actually make:

```bash
warden cred spec create aws-s3-reader \
  -source aws-src \
  -config mint_method=sts_assume_role \
  -config role_arn=arn:aws:iam::<ACCOUNT_ID>:role/s3-reader-role \
  -config ttl=1h \
  -min-ttl 600s \
  -max-ttl 2h
```

Each request mints a fresh STS session bound to the target role. The session lives `ttl` (clamped by `-min-ttl` / `-max-ttl`); subsequent requests mint new sessions. SigV4 imposes a separate 15-minute clock on the signed request itself — see the "Quirks" section of the skill for what that means for long-running tool calls.

The source's IAM user must have `sts:AssumeRole` permission on every `role_arn` any spec built on top of the source references. Multiple specs over the same source give different Warden roles different reach — e.g. one spec per assumed-role ARN, one Warden role bound to each spec.

Verify:

```bash
warden cred spec read aws-s3-reader
```

## Step 4: Create a Policy

MCP traffic passes through two complementary layers of authorization. The IAM role's permissions are the security boundary — they bound what the agent can actually do at AWS regardless of what Warden lets through. On top of that, Warden's CBP policies support an `mcp { }` block for governance-style restrictions enforced at the gateway: allow- and deny-lists for JSON-RPC methods, tool names, resource URIs, prompt names, and selected tool arguments.

Enforcement is **body-authoritative**. When a policy in scope contains an `mcp { }` block, Warden strict-parses the JSON-RPC request body and matches against the parsed body. The parser fails closed on any structural problem and the matcher denies with a specific `rule_type`:

| `rule_type` | Trigger |
|---|---|
| `denied_methods` / `allowed_methods` | JSON-RPC `method` matches a deny pattern, or is absent from a configured allow list |
| `denied_tools` / `allowed_tools` | `tools/call` with a `params.name` matching a deny pattern, or not in the allow list |
| `denied_resources` / `allowed_resources` | `resources/read` with a `params.uri` matching a deny pattern, or not in the allow list |
| `denied_prompts` / `allowed_prompts` | `prompts/get` with a `params.name` matching a deny pattern, or not in the allow list |
| `missing_body` | Request body absent on a path the backend opted into MCP enforcement for. POST/JSON-RPC traffic that fails to parse triggers this; non-POST verbs (GET for the SSE notification stream, DELETE for session terminate) silently skip `mcp { }` evaluation — the body-authoritative gate doesn't apply to body-less verbs. |
| `malformed_jsonrpc` | Body is not a well-formed JSON-RPC 2.0 envelope (bad version, missing method, unknown top-level key, UTF-8 BOM, etc.) |
| `duplicate_key` | Duplicate object key detected anywhere in the body — Warden rejects ambiguity that Go's standard JSON parser silently last-wins-resolves |
| `oversized_body` | Body exceeds the mount's `max_body_size` |
| `batch_empty` | JSON-RPC batch is `[]` |
| `malformed_params` | A name-bearing method (`tools/call`, `resources/read`, `prompts/get`) has a missing or wrong-shape `params.name` / `params.uri` |

All examples below use `capabilities = ["create", "read", "delete"]`. MCP Streamable HTTP uses three HTTP verbs on the same `/gateway` URL: POST for JSON-RPC requests (mapped by Warden to `create`), GET for the optional server → client SSE notification stream (`read`), and DELETE for session terminate (`delete`). All three need to be in the cap list or off-spec MCP clients fail to connect. The `mcp { }` block only fires on the POST half; GET/DELETE skip body-authoritative evaluation automatically.

`mcp { }` authorization is **deny-by-default**: an empty or absent `allowed_methods`/`allowed_tools` denies everything, so a block grants only what it allow-lists — use `["*"]` to open a family fully. The session-lifecycle methods `initialize`, `notifications/*`, and `ping` are **exempt**: they always pass without being listed, so the client handshake works no matter how narrow the data-plane allow-list is (an explicit `denied_methods` entry can still block them).

The simplest policy grants the gateway and leans on IAM for everything:

```bash
warden policy write mcp-aws-access - <<EOF
path "mcp_aws/role/+/gateway*" {
  capabilities = ["create", "read", "delete"]
}
EOF
```

A policy that restricts the agent to the `call_aws` tool but only against a vetted set of AWS services. The AWS MCP Server prefixes every tool name with `aws___` (three underscores) — confirm via `tools/list` on the live server. The tool takes `service_name`, `operation_name`, and `region_name` arguments — a per-call CEL `condition` over `call.args` gates those argument values:

```bash
warden policy write mcp-aws-s3-readonly - <<EOF
path "mcp_aws/role/+/gateway*" {
  capabilities = ["create", "read", "delete"]
  mcp {
    allowed_methods = ["tools/list", "tools/call"]
    allowed_tools   = ["aws___call_aws"]
    condition = "!has(call.args.service_name) || call.args.service_name in ['s3', 'dynamodb']"
  }
}
EOF
```

An open-then-subtract shape — allow every method and tool, then block dangerous operations regardless of which service they target. Under deny-by-default the `["*"]` allow-lists are required; the `condition` reads `call.args.operation_name` and denies the dangerous prefixes/names on top:

```bash
warden policy write mcp-aws-safe - <<EOF
path "mcp_aws/role/+/gateway*" {
  capabilities = ["create", "read", "delete"]
  mcp {
    allowed_methods = ["*"]
    allowed_tools   = ["*"]
    condition = <<-CEL
      !has(call.args.operation_name) || !(
        call.args.operation_name.startsWith("delete_") ||
        call.args.operation_name.startsWith("terminate_") ||
        call.args.operation_name in ["put_bucket_policy", "put_role_policy", "put_user_policy"]
      )
    CEL
  }
}
EOF
```

Argument-level gates restrict the *values* passed to `tools/call`. One `condition` can constrain both which services may be called and within what regions:

```bash
warden policy write mcp-aws-us-only - <<EOF
path "mcp_aws/role/+/gateway*" {
  capabilities = ["create", "read", "delete"]
  mcp {
    allowed_methods = ["tools/list", "tools/call"]
    allowed_tools   = ["aws___call_aws"]
    condition = <<-CEL
      (!has(call.args.service_name) || call.args.service_name in ["s3", "dynamodb", "lambda"]) &&
      (!has(call.args.region_name) || call.args.region_name in ["us-east-1", "us-east-2", "us-west-2"])
    CEL
  }
}
EOF
```

The `mcp { }` block composes with runtime conditions so you can layer environment guards on top of tool-level restrictions:

```bash
warden policy write mcp-aws-business-hours - <<EOF
path "mcp_aws/role/+/gateway*" {
  capabilities = ["create", "read", "delete"]
  condition = <<-CEL
    cidrContains("10.0.0.0/8", request.client_ip) &&
    now.getHours("UTC") >= 8 && now.getHours("UTC") < 18 &&
    now.getDayOfWeek("UTC") in [1, 2, 3, 4, 5]
  CEL
  mcp {
    allowed_methods = ["tools/list", "tools/call"]
    allowed_tools   = ["aws___call_aws"]
  }
}
EOF
```

When a request hits the `mcp { }` gate and is denied, Warden returns HTTP 403 with a structured JSON body and an RFC 6750 `WWW-Authenticate` header; MCP client SDKs surface this to the agent as a tool-call failure with an actionable message. The audit log records the matched rule and the offending tool/parameter so operators can debug policy decisions centrally.

These Warden-level denials are **distinct** from AWS-side `AccessDeniedException` errors. The latter come from the upstream MCP server when the IAM role lacks a required permission; they stream back as native AWS error responses inside the tool-call result. Operators debugging permission issues should check `error_description` (or the response body shape) to tell the two layers apart.

Policies that omit the `mcp { }` block keep the simplest behavior: Warden passes the request through to AWS unchanged and the IAM role alone enforces authorization.

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
${WARDEN_ADDR}/v1/mcp_aws/role/{role}/gateway
```

**Note no trailing slash on `gateway`.** AWS's hosted MCP Server (and Bedrock AgentCore) lives at exactly `/mcp` and rejects `/mcp/` with a JSON-RPC `-32600 Invalid request path`. This is the opposite convention from GitHub's hosted MCP server, where the trailing slash is required.

For Claude Code, Cursor, Continue, Cline, Goose, and other clients that accept Streamable HTTP MCP servers via a JSON config block:

```json
{
  "mcpServers": {
    "aws": {
      "type": "http",
      "url": "${WARDEN_ADDR}/v1/mcp_aws/role/s3-reader/gateway",
      "headers": {
        "Authorization": "Bearer ${JWT_TOKEN}"
      }
    }
  }
}
```

> **Heads-up on `${VAR}` in headers.** MCP clients vary in what they substitute in `.mcp.json`. Claude Code and Cursor expand `${VAR}` in stdio `env` blocks and in the `url` field, but **HTTP-transport `headers` values are a known gap** — the literal `${JWT_TOKEN}` string ships on the wire. For the `Authorization` header (and the routing headers in the next example), paste the actual values instead of `${...}` placeholders, or run the JSON through `envsubst` at deploy time.

#### Claude Code CLI

Rather than hand-editing `.mcp.json`, Claude Code can register the server from the command line. Because the command runs in your shell, `${WARDEN_ADDR}` and `${JWT_TOKEN}` are expanded before they're written to config — sidestepping the `${VAR}`-in-headers gap above:

```bash
claude mcp add --transport http aws \
  "${WARDEN_ADDR}/v1/mcp_aws/role/s3-reader/gateway" \
  --header "Authorization: Bearer ${JWT_TOKEN}"
```

`--transport http` selects the Streamable HTTP transport (not the default stdio); `--header` is repeatable. Add `--scope user` to make the server available across every project (the default `local` scope binds it to the current directory). Keep the `gateway` suffix **without** a trailing slash, as in the URL-pattern note above.

To use header-routed mode instead (see the next section for when), pass each routing header with its own `--header` flag against the base URL:

```bash
claude mcp add --transport http aws "${WARDEN_ADDR}/" \
  --header "Authorization: Bearer ${JWT_TOKEN}" \
  --header "X-Warden-Provider: mcp_aws/" \
  --header "X-Warden-Namespace: <namespace>" \
  --header "X-Warden-Role: s3-reader"
```

Confirm the handshake and list the exposed tools with `claude mcp list`; remove the server with `claude mcp remove aws`.

#### Header-routed alternative

Some MCP clients dislike long URLs, or you want one base URL to mux several Warden providers. Pass the mount path as `X-Warden-Provider`, the namespace as `X-Warden-Namespace`, and the role as `X-Warden-Role` instead — Warden synthesises the canonical gateway path from the headers. Look up the mount path first:

```bash
path=$(warden provider list -o json | jq -r '.[] | select(.type=="mcp_aws") | .path' | head -1)
```

When more than one `mcp_aws` mount exists, replace `head -1` with a `select(.description=="...")` matching the mount you want — the `path` alone doesn't tell you which IAM role or region the mount fronts.

The `path` is what `warden provider list` returns (e.g., `mcp_aws/`, `team-data/aws-mcp/`), **not** the literal string `mcp_aws` — Warden routes on the mount path, not the provider type.

```json
{
  "mcpServers": {
    "aws": {
      "type": "http",
      "url": "${WARDEN_ADDR}/",
      "headers": {
        "Authorization": "Bearer ${JWT_TOKEN}",
        "X-Warden-Provider": "mcp_aws/",
        "X-Warden-Namespace": "<namespace>",
        "X-Warden-Role": "s3-reader"
      }
    }
  }
}
```

The same caveat applies here as above: paste the actual mount path, namespace, role, and (if you're not handing the file to `envsubst`) JWT in the `headers` map — `${VAR}` placeholders in HTTP-transport headers don't get expanded by the major clients today.

### Smoke-test with curl

List the tools the server exposes:

```bash
curl -X POST "${WARDEN_ADDR}/v1/mcp_aws/role/s3-reader/gateway" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

Call a tool. For AWS's hosted MCP Server, every AWS API call goes through the single `call_aws` tool — the JSON-RPC arguments select the service, operation, and target region:

```bash
curl -X POST "${WARDEN_ADDR}/v1/mcp_aws/role/s3-reader/gateway" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"call_aws","arguments":{"service_name":"s3","operation_name":"list_buckets","region_name":"us-east-1","parameters":{}}}}'
```

The `region_name` inside the tool arguments selects which AWS region's API to call. This is independent of the mount's signing region — a single mount fronting `aws-mcp.us-east-1.api.aws` already serves agents operating against any AWS region's APIs, as long as the bound IAM role's permissions cover those operations.

For a Bedrock AgentCore-hosted MCP server, the available tools and their argument shapes come from whatever the customer's server exposes — discover them via `tools/list`.

The **absence** of a trailing slash on `gateway` matters — Warden composes the upstream URL as the mount's configured base + whatever follows `gateway` in the inbound path. For AWS's hosted MCP Server and Bedrock AgentCore, `/mcp/` returns JSON-RPC `-32600 Invalid request path`; only `/mcp` is accepted. This is the opposite convention from GitHub's hosted MCP server, where the trailing slash is required.

## TLS Certificate Authentication

Steps 1 and 5 above use JWT authentication. Alternatively, you can authenticate with a TLS client certificate. This is useful for workloads that already have X.509 certificates — Kubernetes pods with cert-manager, VMs with machine certificates, or SPIFFE X.509-SVIDs from a service mesh.

> **Prerequisite:** Certificate authentication requires TLS to be enabled on the Warden listener so that client certificates can be presented during the TLS handshake (mTLS). In dev mode, use `-dev-tls` to enable TLS with auto-generated certificates, or provide your own with `-dev-tls-cert-file`, `-dev-tls-key-file`, and `-dev-tls-ca-cert-file`. Alternatively, place Warden behind a load balancer that terminates TLS and forwards the client certificate via the `X-Forwarded-Client-Cert` or `X-SSL-Client-Cert` header.

Steps 2-4 (provider mount, credential source and spec, policy) are identical — the `mcp-aws-access` policy from Step 4 works for either auth method. Replace Steps 1 and 5 with the following.

### Enable Cert Auth

```bash
warden auth enable cert
```

### Configure Trusted CA

Provide the PEM-encoded CA certificate that signs your client certificates:

```bash
warden write auth/cert/config \
    trusted_ca_pem=@/path/to/ca.pem \
    default_role=s3-reader
```

### Create a Cert Role

Create a role that binds allowed certificate identities to a credential spec and policy:

```bash
warden write auth/cert/role/s3-reader \
    allowed_common_names="agent-*" \
    token_policies="mcp-aws-access" \
    cred_spec_name=aws-s3-reader
```

The `allowed_common_names` field supports glob patterns. You can also match on other certificate fields: `allowed_dns_sans`, `allowed_email_sans`, `allowed_uri_sans`, or `allowed_organizational_units`.

### Configure Provider for Cert Auth

Update the provider config to point at the cert auth mount:

```bash
warden write mcp_aws/config <<EOF
{
  "mcp_aws_url": "https://aws-mcp.us-east-1.api.aws/mcp",
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
    -X POST "https://warden.internal/v1/mcp_aws/role/s3-reader/gateway" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json, text/event-stream" \
    -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

#### MCP Client JSON Config (cert auth)

**State of mTLS in MCP clients today.** The MCP specification does not standardize a client-side TLS configuration block, and the major IDE clients (Claude Code, Cursor, Continue) do not currently expose first-class fields for client certificate / key paths in their HTTP server configuration. Until that lands, two portable patterns work — both using header-routed mode so the MCP client only needs to set headers, never a deep URL.

Look up the mount path and namespace first:

```bash
path=$(warden provider list -o json | jq -r '.[] | select(.type=="mcp_aws") | .path' | head -1)
namespace=$WARDEN_NAMESPACE   # whatever your default namespace is
```

The `path` is the mount path Warden returns from `warden provider list` (e.g., `mcp_aws/`, `team-data/aws-mcp/`), **not** the literal string `mcp_aws`. Same gotcha as the JWT header-routed flow in the skill.

**Pattern A: Local mTLS-terminating sidecar (recommended).** Run a sidecar (Envoy, nginx, stunnel, `mtls-proxy`) on the agent host that holds the client cert/key and the trusted CA. The MCP client talks plain HTTP over loopback to the sidecar; the sidecar terminates client TLS, validates Warden's server cert, and forwards the request over mTLS with the validated client certificate attached as `X-SSL-Client-Cert` (URL-encoded PEM) or `X-Forwarded-Client-Cert`. Warden trusts the forwarded header when the listener is configured to do so.

```json
{
  "mcpServers": {
    "aws": {
      "type": "http",
      "url": "http://127.0.0.1:9443/",
      "headers": {
        "X-Warden-Provider": "mcp_aws/",
        "X-Warden-Namespace": "<namespace>",
        "X-Warden-Role": "s3-reader"
      }
    }
  }
}
```

Substitute `mcp_aws/` with your mount's actual `path` and `<namespace>` with your namespace before saving — see the env-var caveat in Step 5: `${VAR}` placeholders in HTTP-transport `headers` are not expanded by the major MCP clients today. Drop the `X-Warden-Role` header when cert auth's `default_role` already covers the binding.

**Pattern B: `mcp-remote` as a Node-based bridge.** Many MCP installations already use `mcp-remote` (an npx-launched HTTP-to-stdio bridge) for transport-shape reasons. It runs in Node.js, so Node's TLS environment variables flow through: `NODE_EXTRA_CA_CERTS=/path/to/warden-ca.pem` for a custom CA. Client certificate handling via `mcp-remote` requires a custom Node TLS context and is not as turnkey — for most deployments Pattern A is simpler. A typical CA-only setup (Warden's server cert validated by a private CA; mTLS still requires Pattern A) looks like:

```json
{
  "mcpServers": {
    "aws": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "https://warden.internal/",
        "--transport", "http-only",
        "--header", "X-Warden-Provider: mcp_aws/",
        "--header", "X-Warden-Namespace: <namespace>",
        "--header", "X-Warden-Role: s3-reader"
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
3. `default_role` set on the cert auth method's config — useful when one cert maps 1:1 to one role; the JSON config can drop `X-Warden-Role` entirely

## Configuration Reference

### Provider Config

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `mcp_aws_url` | string | `https://aws-mcp.us-east-1.api.aws/mcp` | MCP server base URL (must be HTTPS). Drives the SigV4 service and signing-region inference. |
| `region` | string | inferred from URL | SigV4 signing region. Required when the host doesn't yield one via DNS-label inference (e.g. GovCloud, China partition, custom test hosts). Independent of which AWS region the agent's API calls actually target. |
| `max_body_size` | int | 10485760 (10 MB) | Maximum request body size in bytes (max 100 MB) |
| `timeout` | duration | `10m` | Session timeout. Raise for long agent sessions that keep an SSE stream open across many tool calls. |
| `tls_skip_verify` | bool | `false` | Skip TLS certificate verification (development only) |
| `ca_data` | string | — | Base64-encoded PEM CA certificate for custom/self-signed CAs |
| `auto_auth_path` | string | — | **Required.** Auth mount path for implicit authentication (e.g., `auth/jwt/`, `auth/cert/`) |
| `default_role` | string | — | Fallback role when not specified in URL |

### Region behavior

The mount's `region` is the **SigV4 signing region for the upstream MCP endpoint**, not a restriction on which AWS region the agent's API calls target. AWS's MCP Server makes API calls in any region; the agent picks the target region via `region_name` inside the tool arguments. One mount fronting `aws-mcp.us-east-1.api.aws/mcp` already serves agents operating against every AWS region's APIs.

A second mount is only needed when the operator specifically wants the MCP server itself in another region — for latency, data sovereignty, or failover.

## IAM Permissions and Tool Availability

The upstream MCP server enforces permissions per call against the assumed-role identity. The set of operations available through a given mount is determined by the **bound IAM role's policy**, not by Warden policy. An `AccessDeniedException` from a `tools/call` request typically means the bound role lacks a required permission.

Provision the IAM role with permissions covering the intended operation surface, and bind one credential spec per Warden role to give different agents different reach.

Common patterns:

| Role's intent | IAM policy shape |
|---------------|-------------------|
| Read-only S3 reach | `s3:ListBucket`, `s3:GetObject`, `s3:GetBucketLocation` on the target buckets |
| DynamoDB query / scan | `dynamodb:Query`, `dynamodb:Scan`, `dynamodb:GetItem` on the target tables |
| Lambda invocation | `lambda:InvokeFunction` on the target functions |
| EC2 inventory | `ec2:Describe*` (read-only inventory of regions and instances) |
| CloudWatch logs read | `logs:DescribeLogGroups`, `logs:GetLogEvents` on the target log groups |

The CloudTrail entry for each AWS API call captures both the assumed-role identity and (via Warden's audit log linkage) the originating Warden session. Treat the IAM role as the security boundary and the `mcp { }` block as governance over which JSON-RPC shapes ever reach AWS.

**Rotate** the source's permanent credentials by updating the source config:

```bash
warden cred source update aws-src \
  -config=access_key_id=AKIA-new... \
  -config=secret_access_key=...
```

Then revoke the old access key from the IAM console. STS sessions minted before the rotation continue to work until they expire (per `ttl` on the spec); new sessions use the new source credentials.
