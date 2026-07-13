# Providers

A **provider** is a mounted backend that fronts an upstream system. A workload
sends its request to a Warden provider mount **as if Warden were the upstream** —
the LLM API, the cloud control plane, the Git host — and Warden authenticates the
caller, checks the request against [policy](policies.md), injects the right
[credential](credentials.md), proxies the request to the real upstream, and
streams the response back unchanged.

This is the gateway at the center of Warden: the workload talks to a familiar
API surface, holds no upstream secret, and every call passes through one point
where identity is checked, a credential is injected, and the request is
[audited](audit.md).

## The Gateway Model

A provider exposes a **gateway**: the mount stands in for the upstream's base
URL, and Warden proxies each call through to the real upstream, streaming the
response back byte-for-byte. Whatever form the client uses, Warden resolves the
request to one internal path built from four parts:

```
<mount>/role/<role>/gateway/<upstream-api-path>
```

- `<mount>` — the provider mount that fronts the upstream.
- `role/<role>` — the [role](roles.md) the request runs as. Omitted when the
  role is supplied another way — the mount's `default_role`, or a
  provider-specific extractor (for example, `aws` and other SigV4 providers take
  the role from the access-key ID in the request signature).
- `gateway/` — a fixed marker dividing Warden's routing prefix from the upstream
  call.
- `<upstream-api-path>` — the upstream's own API path, proxied through unchanged.

A client can produce this internal path two ways — spelled out in the URL, or
supplied through headers — described in
[Path routing vs. header routing](#path-routing-vs-header-routing) below.

So a request an agent would normally send to `https://api.openai.com/v1/chat/completions`
becomes a call to the OpenAI mount: Warden authenticates the caller, injects the
credential, rebuilds the upstream URL, and proxies the request. The provider is
transparent to the client beyond the change of address.

### Path routing vs. header routing

The mount, role, and `gateway/` marker do not have to live in the URL. There are
two ways to route the same request. The examples below all reach GitHub's
`GET /user/repos` through a `github/` mount, authenticating the workload with a
JWT.

**Path routing** encodes everything in the URL. The mount comes first, then an
optional `role/<role>` segment, then the `gateway/` marker, then the upstream's
API path:

```bash
# With the role in the path
curl $WARDEN_ADDR/v1/github/role/ci-readonly/gateway/user/repos \
  -H "Authorization: Bearer $WORKLOAD_JWT"

# No role in path or header — the mount's default_role applies
curl $WARDEN_ADDR/v1/github/gateway/user/repos \
  -H "Authorization: Bearer $WORKLOAD_JWT"
```

Warden strips `github/role/ci-readonly/gateway/`, proxies `GET /user/repos` to
`https://api.github.com`, and injects the brokered GitHub token. In the second
request none of the higher-precedence sources apply — no `X-Warden-Role` header,
no role in the path, and `github` has no role extractor — so the mount's
`default_role` is used; if no role resolves at all, the request is denied (see
[How a request flows](#how-a-request-flows) for the full precedence).

**Header routing** moves the mount and role into headers and lets the URL stay
the upstream's **literal path** — no `gateway/` segment, and with
`X-Warden-Provider` set the `/v1/` API prefix becomes optional too:

```bash
curl $WARDEN_ADDR/user/repos \
  -H "X-Warden-Provider: github" \
  -H "X-Warden-Role: ci-readonly" \
  -H "Authorization: Bearer $WORKLOAD_JWT"
```

Here `$WARDEN_ADDR/user/repos` carries GitHub's own path verbatim — Warden
prepends the `/v1/` prefix, reads `X-Warden-Provider`, synthesizes
`github/role/ci-readonly/gateway/user/repos` internally, and routes it exactly as
the path-routed form. This is what lets a client point an existing SDK or tool's
base URL straight at `$WARDEN_ADDR` and issue the upstream's exact requests,
adding only the headers — it works even for clients that can only inject headers
and cannot rewrite the path, such as a git client using `http.extraheader`.
(The `/v1/` prefix is dropped only for `X-Warden-Provider` requests; path-routed
requests still need it, and `sys/` targets are rejected.)

The role header also works *with* path routing: sending `X-Warden-Role` on a
path-routed request overrides whatever role is baked into the URL. (This is a
mechanism for clients that control their own headers — a programmatic caller, a
sidecar, or git via `http.extraheader`. An **LLM's MCP tool call cannot** set it
— its client's headers are fixed — so an agent selects a role by the URL
instead; see [MCP and Non-MCP Providers](#mcp-and-non-mcp-providers).)

```bash
# Path says ci-readonly, header wins → ci-admin
curl $WARDEN_ADDR/v1/github/role/ci-readonly/gateway/user/repos \
  -H "X-Warden-Role: ci-admin" \
  -H "Authorization: Bearer $WORKLOAD_JWT"
```

Header routing is **not** available for SigV4-signed requests (`aws`, `alicloud`,
`mcp_aws`) — rewriting the URL would invalidate the client's signature — and is
ignored on `sys/` paths. Use the path-routed form there.

### Namespace in the request

A mount lives in a [namespace](namespaces.md), and — like the role — the
namespace can be given in the path or in a header. It sits right after the `/v1/`
API prefix, ahead of the mount:

```bash
# In the path
curl $WARDEN_ADDR/v1/team-a/github/role/ci-readonly/gateway/user/repos \
  -H "Authorization: Bearer $WORKLOAD_JWT"

# In a header, leaving it out of the URL
curl $WARDEN_ADDR/v1/github/role/ci-readonly/gateway/user/repos \
  -H "X-Warden-Namespace: team-a" \
  -H "Authorization: Bearer $WORKLOAD_JWT"
```

Warden prepends the `X-Warden-Namespace` value to the request path before
resolving the namespace, so the two forms are equivalent — and a path already
under a namespace combines with the header rather than conflicting. The root
namespace needs neither. The CLI sets the header from `WARDEN_NAMESPACE`.

### How a request flows

1. **Authenticate.** With no `X-Warden-Token`, the provider authenticates the
   caller transparently against the auth mount named by its `auto_auth_path`
   config (see [Authentication](authentication.md)). The caller's identity — a
   JWT or client certificate — is often
   [channelled by a sidecar](authentication.md#channelling-identity-with-a-sidecar)
   (Robin or ghostunnel) rather than attached by the workload itself.
2. **Resolve the role.** Warden picks the role from — in order — the
   `X-Warden-Role` header, the `role/<role>/gateway/` path segment, a
   provider-specific extractor (e.g. the access-key ID in an AWS SigV4
   `Authorization` header, or a Basic-Auth username), then the mount's
   `default_role` (see [Selecting a Role](roles.md#selecting-a-role)).
3. **Authorize.** Warden evaluates the request against the [policies](policies.md)
   on the caller's token before any credential is minted. Providers that need to
   gate on request content can have the body parsed for this check; a denied
   request never reaches the upstream.
4. **Inject the credential.** The role's token carries a credential spec; Warden
   mints (or reuses) that [credential](credentials.md) and injects it into the
   proxied request — a bearer token, an `X-Vault-Token` header, a re-computed
   AWS SigV4 signature, or whatever the upstream expects.
5. **Proxy and stream.** Warden forwards the request to the upstream and streams
   the response back. The credential lives only inside this hop; the workload
   never receives it.

Some read-only or protocol-negotiation paths can be served without
authentication (for example, a Git smart-HTTP probe that needs the upstream's
`WWW-Authenticate` challenge before the client retries with credentials).

## MCP and Non-MCP Providers

Server-side every provider is the same gateway. What differs is **how an agent
talks to it** — and that splits providers into two kinds:

- **MCP providers** (`mcp`, `mcp_aws`) front an upstream **MCP server**. The
  agent reaches them with an **MCP client** pointed at the gateway URL, which
  the operator wires up ahead of time (for Claude Code, `claude mcp add`) — one
  attachment per role. The agent doesn't build the URL at runtime; it calls the
  attached server whose role fits the task. This pre-wiring has a cost: for MCP,
  role/URL setup is pre-distributed config, and runtime discovery is *advisory*
  rather than connective (see
  [Discovery → Connective for non-MCP, advisory for MCP](discovery-and-skills.md#connective-for-non-mcp-advisory-for-mcp)).
- **Non-MCP providers** (everything else — `vault`, `github`, `openai`, `aws`,
  `rds`, `rest`, …) front a REST, DB, or cloud API. The agent makes the
  **request itself over HTTP**, to the gateway URL it reads from the role's
  description (see [Discovery and Skills](discovery-and-skills.md)), presenting
  its identity on each call.

Either way the **role** rides in the gateway URL (`…/role/<role>/gateway/`, or
the `AWS_ACCESS_KEY_ID` slot / `?role=` query for the SigV4 and access
providers), so an agent selects a role by **targeting that role's URL** — for
MCP, by choosing the attached server; for non-MCP, by using the role's URL from
`list_roles`. An LLM's **MCP tool call** can't set the `X-Warden-Role` header
(its client's headers are fixed and no role rides in the call), so the URL is the
selector; the header stays a routing override for clients that control their own
headers ([Path routing vs. header routing](#path-routing-vs-header-routing)).
Each provider's [skill](discovery-and-skills.md) spells out the exact mechanics.

## Enabling a Provider

Enable a provider with `provider enable`, naming the provider type. By default
the mount path matches the type; override it with `-path` to mount several
instances of the same type:

```bash
warden provider enable openai
warden provider enable rest -path=internal-api/ -description="Internal billing API"
```

Providers are mounted under `sys/providers/<path>` and scoped to the current
[namespace](namespaces.md); the namespace is baked into the agent-facing URL
(`/v1/<namespace>/<mount>/...`). The full command surface:

```bash
warden provider enable <type> [-path=<path>] [-description=<text>]
warden provider list
warden provider read    <path>
warden provider tune    <path> -description=<text>   # update description in place
warden provider disable <path>
```

### Configuring a mount

A provider's behaviour is set at its own `config` path. Transparent auth requires
`auto_auth_path`; `default_role` is the fallback role:

```bash
warden write <mount>/config \
  auto_auth_path=auth/jwt/ \
  default_role=api-reader
```

Each provider adds its own config keys — an upstream address, TLS options, and so
on. The brokered credential is *never* part of mount config; the mount only says
where to send traffic and how to authenticate the caller.

> **Identifying a mount by description.** When several mounts of the same type
> exist, match them by the operator-set **mount description**, not by sniffing
> the upstream URL from config. The description states what the operator intends
> the mount for (which account, which region, which model); the URL is a backend
> detail that can change without changing meaning.

## How Credentials Are Bound

A provider does not name a credential spec. It only declares which credential
*type* it can inject and reads `req.Credential` at request time. The binding
comes from identity: a [role](roles.md)'s `cred_spec_name` puts a credential spec
on the issued [token](tokens.md), and Warden resolves and mints that
[credential](credentials.md) when the gateway request arrives. The same mount
therefore serves different access levels depending on the role the caller
presents — without any per-mount credential configuration.

## Built-in Providers

Warden ships built-in providers for many common upstreams. A few representative
ones, by area:

| Area | Providers |
|------|-----------|
| AI / LLM | `anthropic`, `openai`, `cohere`, `mistral` |
| [Model Context Protocol](mcp.md) | `mcp`, `mcp_aws` |
| Cloud platforms | `aws`, `azure`, `gcp`, `alicloud`, `ibmcloud`, `ovh`, `scaleway` |
| Databases (IAM auth) | `rds`, `redshift` |
| Source / CI | `github`, `gitlab`, `tfe`, `ansible_tower` |
| Observability | `datadog`, `dynatrace`, `newrelic`, `grafana`, `honeycomb`, `prometheus`, `sentry`, `splunk` |
| Collaboration / ITSM | `slack`, `pagerduty`, `servicenow`, `atlassian` |
| Infrastructure | `vault`, `kubernetes`, `elastic`, `cloudflare` |
| Generic | `rest` |

Most inject a bearer token or an API key; cloud providers (`aws`, `alicloud`,
`mcp_aws`) re-sign the request with freshly minted credentials rather than
setting a header.

### The generic REST provider

The `rest` provider fronts **any single-token REST API** through configuration
alone — no bespoke provider code. Point it at an upstream and tell it where to
put the token:

```bash
warden provider enable rest -path=internal-api/
warden write internal-api/config \
  base_url=https://api.internal.example.com \
  token_header=X-API-Key \
  token_prefix="" \
  auto_auth_path=auth/jwt/ \
  default_role=api-reader
```

| Config key | Meaning |
|------------|---------|
| `base_url` | Upstream API base URL (required). |
| `token_header` | Header the brokered token is injected into (default `Authorization`). |
| `token_prefix` | Prefix prepended to the token (default `Bearer `; set empty for a raw token). |
| `headers` | Static `name=value` headers added to every proxied request. |

The token value itself is never stored in the mount configuration — it is minted
per request and injected into the configured header.

## Provider Skills

A provider may ship an agent-facing **skill** — a markdown guide describing how
to drive it — seeded into the skill registry when the provider is first mounted.
This is how an AI agent learns to use a mount it has been granted. See
[Discovery and Skills](discovery-and-skills.md).

## See Also

- [Authentication](authentication.md) — how a gateway request is authenticated.
- [Roles](roles.md) — how the role on each request selects access and credential.
- [Credentials](credentials.md) — what gets injected into the proxied request.
- [Namespaces](namespaces.md) — the scope a provider mount lives in.
- [Discovery and Skills](discovery-and-skills.md) — how agents find and use mounts.
