# Agent end-to-end flow

How an AI agent goes from "I have a task" to "I successfully called an
upstream service through Warden" — every step, every call, every response
shape, and where each piece of knowledge comes from.

This document is for two audiences:

- **Operators** who deployed Warden and connected it to an identity issuer
  (OIDC provider, mTLS CA, …) for agent workloads, and want to trace what an
  agent does end-to-end — from the JWT its runtime obtained from that issuer,
  through discovery, to the upstream call.
- **Agent / runtime developers** wiring Warden into Claude Code, Goose, or a
  homegrown harness.

Discovery happens entirely over MCP: Warden runs its own MCP server at
`/v1/sys/mcp` with two tools, `list_roles` and `get_skill`. The provider
recipes an agent follows live in the skill registry (`get_skill`); this doc
is the system-side view of the same contract.

## 1. The runtime contract

The agent does **not** authenticate against an identity provider, fetch
tokens, or hard-code endpoints. The runtime that spawns the agent wires two
things:

1. **Identity.** A bearer JWT (from CI's per-job OIDC token, an OAuth
   `client_credentials` JWT minted at spawn, …) or an mTLS client
   certificate. The agent inherits it and never sees an upstream API key.
2. **MCP client attachments.** The runtime attaches the agent's MCP client to
   Warden's discovery server (and to any MCP-provider gateways), passing the
   identity as the connection's `Authorization` header (and
   `X-Warden-Namespace` for a sub-namespace). For Claude Code that is
   `claude mcp add`.

`$WARDEN_ADDR` — the Warden server URL, one cluster per environment — is the
base the agent prepends when it calls a **non-MCP** gateway over HTTP.

That's the whole onboarding ceremony.

## 2. Bootstrap

There is no CLI loop to learn. The runtime attaches the discovery server; the
agent's first move is to call **`list_roles`** on it. The two discovery tools
are self-describing (each carries a `description`), so the agent needs no
pre-loaded knowledge — it connects, lists its roles, and reads the skill each
one names.

## 3. The discovery loop

Every step is a call to the MCP discovery server at `/v1/sys/mcp`; the agent
chains them before touching any upstream.

### Step 1 — List assumable roles

`list_roles` (no arguments) introspects the caller's identity vehicle (JWT or
client cert) and returns the roles that identity can assume in the current
namespace, each with `{name, description}`:

```json
{"roles": [
  {"name": "read-repo",    "description": "search & read any repo (skill: github)"},
  {"name": "read-secret",  "description": "read app secrets (skill: vault, url: /v1/team-data/vault/role/read-secret/gateway/)"},
  {"name": "post-update",  "description": "post to the team channel (skill: slack)"}
], "warnings": []}
```

Each `description` is **operator-set free text** — how operators communicate
intent at runtime. By convention it carries the machine-readable hints the
agent needs: the **skill name** for the role's provider, and — for a
**non-MCP** provider — the role's **gateway URL** (relative). The agent reads
descriptions and matches them to the task; it does not memorize role names.

### Step 2 — Match task → role

Read the descriptions and pick the role that fits. Prefer the **most-scoped**
option (a role described as "read-only X" over "admin"); when two roles look
equivalent, surface to the user rather than guess.

### Step 3 — Get the skill

`get_skill{skill: "<name>"}` — the name read out of the chosen role's
description — returns the agent-facing recipe in markdown: how to reach the
provider, how to present identity, the role-selection mechanic, and quirks.

If `get_skill` reports *skill "aws" not found*, the cluster has no AWS
provider (a provider skill is seeded the first time a provider of that type is
mounted). The agent surfaces the gap; it does not fabricate an endpoint.

### Step 4 — Act under the chosen role

The role a request runs as is the `role/<role>/` segment of its gateway URL, so
the agent picks a role by **targeting that role's URL** — the selector that works
for every client (an MCP attachment, an SDK `base_url`, a raw request).
`X-Warden-Role` is a header override, usable only where the client sets per-call
headers — not an MCP tool call. The two kinds differ only in *how the agent
reaches them*:

- **MCP providers** are already attached to the agent's MCP client, **one
  attachment per role** (the operator wired each at `claude mcp add` time) — the
  agent calls the attached server whose role fits the task.
- **Non-MCP providers** are driven over HTTP: the agent takes the role's gateway
  URL from its description, prepends `$WARDEN_ADDR`, presents its identity on
  each call, and targets another role's URL to act under another role.

## 4. Worked example — read an S3 bucket through AWS (non-MCP)

The runtime spawns the agent with a JWT (OIDC, from CI), `$WARDEN_ADDR`, and
its MCP client attached to `/v1/sys/mcp` under namespace `team-data`.

User asks: *"Show me the keys in the staging-events S3 bucket."*

**Agent's actions:**

1. **`list_roles`** — finds `data-reader` (*"read-only data-warehouse & S3
   access (skill: aws, url: /v1/team-data/aws/gateway)"*).
2. **Match** — `data-reader` fits. No ambiguity.
3. **`get_skill{skill: "aws"}`** — gets the recipe: the role travels in
   `AWS_ACCESS_KEY_ID`, the JWT in the SigV4 secret/session slots, the
   endpoint pointed at the gateway URL:

   ```bash
   export AWS_ACCESS_KEY_ID="data-reader"                 # role, not an AWS key
   export AWS_SECRET_ACCESS_KEY="<jwt>"
   export AWS_SESSION_TOKEN="<jwt>"                       # Warden detects "eyJ"
   export AWS_ENDPOINT_URL="$WARDEN_ADDR/v1/team-data/aws/gateway"   # the url from the description
   aws s3 ls s3://staging-events
   ```

The SDK signs with SigV4 as usual. Warden's AWS provider verifies the
signature, reads the role out of `AWS_ACCESS_KEY_ID`, looks up the credential
spec bound to it, mints fresh AWS credentials, re-signs, and proxies to
`s3.amazonaws.com`. The real AWS credentials never leave Warden's process.

## 5. What changes per provider type

Steps 1–3 are universal. Step 4's recipe varies by type; `get_skill` surfaces
the exact one:

| Provider type | Kind | Recipe shape | How the role is passed |
|---|---|---|---|
| `mcp`, `mcp_aws` | MCP | Pre-attached MCP server, one per role; the agent calls the attached server for its role. | Role in the attached URL's `role/<role>/` segment (fixed per attachment). |
| `github`, `gitlab`, `openai`, `slack`, `vault`, `rest`, `atlassian`, `ansible_tower` | Non-MCP HTTP | Point the client/SDK at `$WARDEN_ADDR<gateway-url>` (from the description) with the JWT as the bearer (or the provider's native header). | Role in the URL path segment `…/role/<role>/gateway/…`; another role = another URL. |
| `aws`, `scaleway` | Non-MCP HTTP (SigV4) | SDK env vars: role in `AWS_ACCESS_KEY_ID`, JWT in the secret/session slot, endpoint at the gateway URL. | Role in `AWS_ACCESS_KEY_ID` (extracted from the SigV4 header). |
| `rds` | Non-MCP (access) | One-shot call mints a short-lived DB connection string with an embedded IAM token; the agent then connects to the DB directly (no proxy in the data path). | Query parameter `…/access/<grant>?role=<role>`. |

The skill body for each type explains the exact substitution, the quirks
(AWS wildcard DNS for S3 virtual-hosted buckets, JWT-expiry manifesting as
SigV4 `SignatureDoesNotMatch`, …), and any service-specific caveats.

## 6. Error handling

The `troubleshooting` skill (`get_skill{skill: "troubleshooting"}`) maps the
errors an agent sees to a cause and a retry policy. Two surfaces:

- **Discovery** — `list_roles` erroring with *"requires a JWT bearer token or
  TLS client certificate"* means no identity reached the endpoint (the MCP
  client connection lost/omitted it); an empty role list means the identity is
  bound to no role — ask the operator. `get_skill` *"not found"* means the
  provider isn't enabled.
- **Gateways** — branch on the HTTP status (or MCP tool error): **401** =
  identity missing or JWT expired (typical TTL 5–60 min) → refresh; **403**
  with `WWW-Authenticate: Bearer` = the role's policy forbids the call → switch
  role or ask the operator; **404** = wrong gateway URL/mount/namespace →
  re-read the URL from the role description; **5xx** = Warden or upstream →
  read the body, bounded backoff. SigV4 providers surface an expired JWT as
  `SignatureDoesNotMatch` rather than 401.

## 7. Caching strategy

Skills change rarely; agents can cache them. Every skill record carries a
`version` integer bumped on every update. A long-running agent caches the
skills it has fetched and re-fetches only when a version changes. Roles are
also stable-ish — re-run `list_roles` every N minutes or on a `403`/`404`,
whichever comes first.

## 8. The big picture

### Setup — one-time, by the operator

```
┌─────────────────────────┐                ┌─────────────────────────┐
│ Identity issuer         │ ◄─── trust ──► │ Warden cluster          │
│ (OIDC, mTLS CA, SPIRE…) │                │  • providers mounted    │
└─────────────────────────┘                │  • roles + policy       │
                                           │  • skill catalog seeded │
                                           └─────────────────────────┘
```

The operator configures the trust relationship (JWKS endpoint or CA bundle),
mounts providers, defines roles (embedding the skill name and, for non-MCP
providers, the gateway URL in each role's description), writes policies, and
attaches the agent runtime's MCP client to `/v1/sys/mcp` and the MCP-provider
gateways. After this, the operator is not in the per-call loop.

### Per-call — every time an agent makes an upstream call

```
        ┌──────────────────────┐
        │ Identity issuer      │
        └─────────┬────────────┘
                  │ ① mint JWT (per job, per spawn, …)
                  ▼
        ┌──────────────────────┐
        │ Runtime              │   attaches the MCP client to /v1/sys/mcp
        │ (CI, harness, …)     │   and gateways, identity in the headers
        └─────────┬────────────┘
                  │ ② spawn
                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Agent                                                               │
│                                                                     │
│  ③ Discovery — MCP calls on /v1/sys/mcp                             │
│       list_roles → pick a role → get_skill                          │
│                                                                     │
│  ④ Upstream call                                                    │
│       MCP gateway: tools/call on the attached server                │
│       non-MCP:     $WARDEN_ADDR<gateway-url> + identity             │
└─────────────────────────────────┬───────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Warden                                                              │
│   ⑤ auth      validate the JWT against the issuer's JWKS / CA       │
│   ⑥ policy    resolve role; check namespace + policy permit the call│
│   ⑦ credmint  mint a short-lived real upstream credential           │
│   ⑧ proxy     re-sign / inject the credential; forward to upstream  │
└─────────────────────────────────┬───────────────────────────────────┘
                                  │ ⑨ call with real upstream creds
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Upstream (AWS, OpenAI, Vault, RDS, GitHub, …)                       │
│   sees: a normal call from Warden with valid real credentials       │
│   does NOT see: the agent's JWT, the agent's namespace, role name   │
└─────────────────────────────────────────────────────────────────────┘
```

Responses flow back along the same path. Warden does not cache real upstream
credentials in storage — they're minted per call (or short-lived per the
credential spec's TTL) and held only in memory for the proxied request.

## 9. What the agent never does

- **Authenticate to an identity provider.** The runtime hands it a JWT (or a
  client cert).
- **Hold long-lived upstream credentials.** Warden mints them per call.
- **Memorize role names, provider paths, or endpoint URLs.** Every fact comes
  from a live `list_roles`/`get_skill` call.
- **Decide on its own that "the system is broken."** A structured MCP tool
  error or an HTTP status maps deterministically to an action (retry, switch
  role, surface to the user). Ambiguous failures get surfaced, not papered
  over.

## 10. Where to go next

- The seeded and provider skills themselves — reachable via `get_skill` — are
  the authoritative agent-facing source. This doc is the system view of the
  same contract.
- For the discovery interface and skill model, see
  [Discovery and Skills](concepts/discovery-and-skills.md) and
  [MCP](concepts/mcp.md).
- For the proxy/gateway internals (how Warden re-signs SigV4, validates JWTs
  against the OIDC issuer, etc.), see [architecture.md](architecture.md).
- For the per-provider catalog (what each type supports and how it's
  configured), see [provider-backends/README.md](provider-backends/README.md).
