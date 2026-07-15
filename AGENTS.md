# Warden — agent guide

This file orients an autonomous agent (LLM, AI assistant, automation
script) that needs to *call services through Warden*. Operators looking to
set up Warden, mount providers, or onboard credentials should read the docs
— start with [Providers](https://wardengateway.com/concepts/providers/) and the per-backend
guides under [docs/provider-backends/](https://wardengateway.com/provider-backends/); this tree
is for the *consumer* side.

## Where to start

Warden runs its own **MCP discovery server** at `/v1/sys/mcp`. Point your
MCP client at it (for Claude Code, `claude mcp add`), presenting your
identity — a bearer JWT (`Authorization: Bearer <jwt>`) or an mTLS client
certificate — and, for a sub-namespace, the `X-Warden-Namespace` header.
It needs no role: it authorizes on the identity you present. It exposes
two tools:

- **`list_roles`** — the roles your identity can assume, each with an
  operator-written `description`. This is your menu.
- **`get_skill`** — given a skill name, returns that skill: the markdown
  recipe for driving the role's provider.

The `description` on each role carries what you need: the **skill name**,
and — for a **non-MCP** provider — the role's **gateway URL** (relative;
prepend `$WARDEN_ADDR`). For example:
*"read app secrets (skill: vault, url: /v1/vault/role/read-secret/gateway/)"*.

## The agent loop

```
[ connect MCP client to /v1/sys/mcp ]   ← identity in the connection
       │
       ▼
[ list_roles ]                          ← which roles can I assume?
       │
       ▼
[ match task → pick a role ]            ← read descriptions; choose the fit
       │
       ▼
[ get_skill <name-from-description> ]   ← the per-provider recipe
       │
       ▼
[ act under the chosen role ]
```

How you act depends on the provider kind. Your role is the `role/<role>/`
segment of the gateway URL, so you pick a role by **targeting that role's URL** —
the selector that works for every client. (`X-Warden-Role` is a header override,
usable only where the client sets per-call headers — not an MCP tool call, whose
headers are fixed and which carries no role.)

- **MCP providers** are already attached to your MCP client, **one attachment
  per role** (the operator wired each at `claude mcp add` time) — call the
  attached server whose role fits the task.
- **Non-MCP providers** are driven over HTTP: read the role's gateway URL from
  its description, prepend `$WARDEN_ADDR`, present your identity on each call,
  and use another role's URL to act under another role.

## Provider skills

Each provider type ships a skill (`provider/<type>/skill.md`) that is seeded
into the cluster's registry the **first time a provider of that type is
mounted**. Fetch one by name with `get_skill` — the name is the provider
type embedded in a role's description (`aws`, `vault`, `github`, `openai`,
`slack`, `mcp`, …). If `get_skill` reports *skill "<name>" not found*, no
provider of that type is enabled — the honest signal that the capability
does not exist, not an endpoint to fabricate.

## Adding a skill for a new provider

When a new provider lands under `provider/<name>/`, ship a matching
`provider/<name>/skill.md` with the same shape as the existing ones, and add
`<name>.Skill()` to the `providerSkills` map in `cmd/server/server.go`. The
skill is seeded into the registry on the first mount of that provider type.

```yaml
---
name: <name>
description: "<one line: what does this provider expose>"
category: provider-guide
provider: <name>
requires: []
upstream: "<service name>"
---
```

Body sections, in order:
1. **What it does** — one paragraph.
2. **Configure the CLI/SDK** — for a non-MCP provider, how to build the
   request from the gateway URL in the role description (`$WARDEN_ADDR` +
   `<gateway-url>`), how to present identity, and that the role is the URL's
   `role/<role>/` segment (use another role's URL to switch); for an MCP
   provider, that the server is pre-attached, one per role. The actionable part.
3. **Examples** — three to five copy-paste commands or SDK snippets.
4. **Quirks** — provider-specific gotchas, unsupported operations,
   DNS requirements.

Aim for 50–80 lines. Skills are runbooks, not tutorials.
