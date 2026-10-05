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

- **`list_roles`** — the roles your identity can assume. This is your menu.
  Each role carries:
  - `description` — operator-written prose: what the role is for;
  - `provider` — the type of provider it is used with (`vault`, `aws`, `mcp`, …);
  - `skill` — the `skill://<name>/SKILL.md` URI of the recipe for it;
  - `url` — where to call it, relative to Warden's address (prepend
    `$WARDEN_ADDR`).
- **`read_skill`** — given a role's `skill` URI, returns that SKILL.md: the
  markdown recipe for driving the role's provider. The structured output
  carries it whole as `markdown`.

A client that supports the MCP Skills extension can use `skills/list`,
`skills/get`, and `resources/read` on the same `skill://` URIs instead of
`read_skill`.

For example:

```json
{
  "name": "read-secret",
  "description": "read app secrets",
  "provider": "vault",
  "skill": "skill://vault/SKILL.md",
  "url": "/v1/vault/role/read-secret/gateway/"
}
```

A role listed without a `url` or a `skill` is not wired to a provider yet;
the `warnings` in the same response say why. Don't build a URL for it — pick
another role or ask the operator.

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
[ read_skill <the role's skill URI> ]   ← the recipe, plus what it requires
       │
       ▼
[ act under the chosen role ]           ← its url, or its attached MCP server
```

Read the skill of the role you are about to use, not every skill on the
menu. A skill whose frontmatter lists `requires` depends on those skills:
read each one before acting.

How you act depends on the provider kind. Your role is the `role/<role>/`
segment of the gateway URL, so you pick a role by **targeting that role's URL** —
the selector that works for every client. (`X-Warden-Role` is a header override,
usable only where the client sets per-call headers — not an MCP tool call, whose
headers are fixed and which carries no role.)

- **MCP providers** are already attached to your MCP client, **one attachment
  per role** (the operator wired each at `claude mcp add` time) — call the
  attached server whose role fits the task.
- **Non-MCP providers** are driven over HTTP: take the role's `url`, prepend
  `$WARDEN_ADDR`, present your identity on each call, and use another role's
  `url` to act under another role.

## Provider skills

Each provider type that ships a skill (`provider/<type>/skill.md`) has it
seeded into the cluster's registry the **first time a provider of that type is
mounted**. A role uses its provider's skill unless the operator points it at
one of their own. The discovery server serves you only the skills your roles
lead to, plus the shared ones such as `troubleshooting`. If `read_skill`
reports *not found*, the skill is gone or none of your roles leads to it —
the honest signal that the capability does not exist for you, not an
endpoint to fabricate.

## Adding a skill for a new provider

When a new provider lands under `provider/<type>/`, ship a matching
`provider/<type>/skill.md` with the same shape as the existing ones, and add
`"<type>": <package>.Skill()` to the `providerSkills` map in
`cmd/server/server.go`. The skill is seeded into the registry on the first
mount of that provider type.

The skill's `name` is the provider type with every underscore turned into a
hyphen — skill names allow only lowercase letters, digits and single hyphens
— while `provider` keeps the type as it is. Seeding refuses a name that does
not match. For the `mcp_aws` type:

```yaml
---
name: mcp-aws
description: "<one line: what does this provider expose>"
category: provider-guide
provider: mcp_aws
requires: []
upstream: "<service name>"
---
```

Body sections, in order:
1. **What it does** — one paragraph.
2. **Configure the CLI/SDK** — for a non-MCP provider, how to build the
   request from the role's `url` in `list_roles` (`$WARDEN_ADDR` + `url`), how
   to present identity, and that the role is the URL's `role/<role>/` segment
   (use another role's `url` to switch); for an MCP provider, that the server
   is pre-attached, one per role. The actionable part.
3. **Examples** — three to five copy-paste commands or SDK snippets.
4. **Quirks** — provider-specific gotchas, unsupported operations,
   DNS requirements.

Aim for 50–80 lines. Skills are runbooks, not tutorials.
