---
title: "Discovery and Skills"
---

For an AI agent, the hard part of using Warden is not making the request — it is
knowing *what it is allowed to do* and *how to do it*. Warden makes both
answerable at runtime, **over MCP**. An authenticated agent points its MCP client
at Warden's own discovery server and asks which [roles](/concepts/roles/) it can assume
and how to drive each one — with **no pre-distributed configuration**. Nothing is
hard-coded into the agent; every fact comes from a live call.

This has two halves:

- **Discovery** — live, identity-scoped introspection of what the caller can
  assume: the roles available to its identity. It happens entirely through
  Warden's MCP discovery interface.
- **Skills** — agent-facing markdown recipes that teach an agent how to drive a
  role's provider once it has discovered it.

## The Discovery Interface

Warden runs its own MCP server at `/v1/sys/mcp` — always on, and needing no role:
it authorizes on the identity the agent presents (a bearer JWT or an mTLS client
certificate), exactly like the rest of Warden's introspection. A caller in a
sub-namespace selects its scope with the usual `X-Warden-Namespace` header. This
is the single surface an agent uses to discover what it can do. It exposes two
tools:

- **`list_roles`** — the roles the caller's identity can assume, each with an
  operator-written description.
- **`get_skill`** — the markdown recipe for a skill, by name.

Together they are the MCP-native form of role introspection and skill reading.
An agent never needs role names, endpoints, or keys handed to it out of band — it
connects, and asks. (See
[MCP → Warden as an MCP Server](/concepts/mcp/#warden-as-an-mcp-server-discovery-interface).)

## The Discovery Loop

An agent runs this loop before touching any upstream. Every step is a call to the
MCP discovery server; each chains into the next:

1. **Connect** — point the MCP client at `/v1/sys/mcp`, presenting the agent's
   identity (bearer JWT or client certificate) and, for a sub-namespace, the
   `X-Warden-Namespace` header.
2. **List roles** — `list_roles` returns every role the identity can assume, each
   with its description. This is the agent's menu.
3. **Match task → role** — the agent reads the descriptions, picks the
   most-scoped role for the step, and surfaces to the user rather than guessing
   when it is ambiguous.
4. **Get the skill** — the chosen role's description names a skill; `get_skill`
   returns that recipe.
5. **Act** — the agent follows the recipe. The role a request runs as is the
   `role/<role>/` segment of its gateway URL, so an agent picks a role by
   **targeting that role's URL** — the selector that works for every client
   (an MCP attachment, an SDK `base_url`, a raw request alike). (`X-Warden-Role`
   is a header override, so it only helps clients that set per-call headers — not
   an MCP tool call.) The two provider kinds differ only in *how the agent
   reaches them*:
   - **MCP providers** are already attached to the agent's MCP client (via
     `claude mcp add`), one attachment per role. The agent calls the attached
     server whose role fits the task; it can't change the role of an attachment.
   - **Non-MCP providers** are driven over HTTP: the operator embeds the role's
     **gateway URL** in the description, so the agent reads it, prepends
     `$WARDEN_ADDR`, presents its identity, and — to use another role — targets
     that other role's URL from `list_roles`.

The role is the unit of discovery. Because a [role](/concepts/roles/) is a view over a
provider — it decides what the caller may do and which credential is minted — the
agent never enumerates raw providers or keys. It discovers *roles*, and each
role's description carries what it needs: the skill name, and (for a non-MCP
provider) the gateway URL.

### Connective for non-MCP, advisory for MCP

Be clear-eyed about what discovery buys you, because it differs by provider kind:

- **Non-MCP providers — connective.** The agent isn't wired to anything in
  advance. It learns the gateway URL from `list_roles` at runtime and builds the
  call itself. This is discovery in its full sense: an identity in, a working
  upstream call out, with **no pre-distributed configuration**.
- **MCP providers — advisory.** An MCP client can't attach a server or set a
  role header at runtime, so the operator must **pre-attach one server per role**
  ahead of time. The agent is therefore *already connected*; `list_roles` doesn't
  reach a new gateway, it helps the agent **choose** among the servers it already
  holds. That is real pre-distributed configuration — the very thing the non-MCP
  path avoids.

Discovery still earns its keep for MCP, just not as a connector. `list_roles` is
the **live, identity-scoped** view of which roles are actually usable *now* — an
attached server whose role the identity can no longer assume would `403`, and
`list_roles` simply won't list it — and the description carries the operator's
**intent** that a bare attached-server name doesn't. But the honest trade-off is
that for MCP, discovery narrows from *discover-and-connect* to
*understand-and-select*. (Closing that gap — letting an agent act under any
discovered role through a single attachment — would require a role selector an
LLM can pass at call time, which MCP does not offer today.)

## Discovering Roles

`list_roles` answers *"which roles can **I** assume?"* It is identity-scoped:
Warden detects the caller's credential form — a TLS client certificate, a generic
JWT, or a Kubernetes ServiceAccount JWT — and fans out only to the auth mounts in
the namespace that accept that form, returning the **union** of the roles each
reports. Each entry is `{name, description}`; a role the identity cannot assume
never appears, so the menu is exactly the caller's reachable surface — and a
mount that fails introspection surfaces as a warning rather than hiding the rest.

The description is operator-set free text — how operators communicate intent —
and by convention it carries the machine-readable hints the agent needs: the
**skill name** for the role's provider, and, for a **non-MCP** provider, the
role's **gateway URL** (relative — the agent prepends `$WARDEN_ADDR`). For
example: *"read app secrets (skill: vault, url: /v1/vault/role/read-secret/gateway/)"*.
The agent reads the skill name out and feeds it to `get_skill`, and drives the URL
directly. An MCP-provider role carries only the skill name — its gateway URL lives
in the MCP client config, wired at `claude mcp add` time.

> **Identify a role by its description, not its name.** Role names are slugs; the
> operator-set **description** is the reliable signal of what a role is for and
> which skill drives it. Several roles can front the same provider with different
> access — the description is how they are told apart. When it is ambiguous, an
> agent should ask rather than guess.

## Skills

A **skill** is an agent-facing markdown document, stored in a single global
registry, that teaches an agent how to drive a role once it has been discovered.
`get_skill` returns one by name. Each skill is markdown with structured
frontmatter:

| Field | Meaning |
|-------|---------|
| `name` | Unique slug — the name embedded in a role description and passed to `get_skill`. Warden's default provider guides use the provider type (e.g. `aws`), but a name you author can be anything. |
| `description` | One-line summary an agent reads to decide relevance. |
| `category` | `agent-flow`, `shared`, `provider-guide`, `troubleshooting`, or `custom`. |
| `requires` | Names of other skills this one depends on (often empty). |
| `upstream` | The upstream system the skill is about, when applicable. |
| `provider` | Provider type a `provider-guide` describes. |
| `body` | The markdown recipe itself. |
| `version` | Incremented on every change — agents use it to invalidate caches. |

The `body` is a self-contained recipe: how to reach the role's gateway, which
headers to send, and the provider's quirks (an AWS skill notes that an expired
JWT surfaces as a SigV4 `SignatureDoesNotMatch`; a Slack skill notes that HTTP
200 does not mean success — check the `ok` field).

### Skills are yours to write

Skills are not a fixed, built-in catalogue — they are **plain markdown you author
and own**. Warden seeds a sensible default guide for each provider type so an
agent has something to read out of the box, but nothing about a skill is frozen:
you can edit a seeded one, override it wholesale, or add entirely new skills of
your own — an internal runbook, a house convention, a guide narrowed to a single
workflow. The defaults are a starting point, not a ceiling, and a role's
description can point at whichever skill name you choose.

This authoring freedom is what lets you **scope a skill to a role** rather than to
a whole provider. For a non-MCP provider that is what keeps a skill small:
instead of embedding the provider's entire OpenAPI surface, a role-scoped skill
documents only the handful of endpoints that role actually exposes — often just
three or four operations. The role narrows the API down to its task; you write a
skill that covers exactly that slice. One provider can then be fronted by several
roles, each paired with its own tight, purpose-built skill. This is a large part
of why roles matter for REST/OpenAPI providers: they let skills stay small,
focused, and cheap for an agent to read.

### Where skills come from

- **Default provider skills** ship alongside each provider's code and are seeded
  into the registry the **first time a provider of that type is mounted**. Seeding
  is idempotent: mounting a second instance does not overwrite your edits, and a
  skill that fails to seed never blocks the mount.
- **The `troubleshooting` skill** is seeded into every server on first unseal —
  a shared guide to Warden's error model.
- **Your own skills** — anything you author through the system API (below),
  including overrides of the seeded defaults.

So if `get_skill` reports *skill "aws" not found*, no AWS provider has been
enabled on the server (and no one has authored a skill by that name) — the honest
signal to an agent that the capability does not exist, rather than an endpoint to
fabricate.

### Authoring skills

Skills are read over MCP with `get_skill`, but they are *authored* by operators
through the system API. Create a new custom skill, override a seeded one, or
remove one you added:

```bash
warden skill create -name=oncall-runbook -category=custom \
  -description="on-call response" -body-file=./runbook.md
warden skill update aws -description="our AWS override"
warden skill delete oncall-runbook
```

Point a role's description at a skill by embedding its `name` (e.g.
`skill: oncall-runbook`), and any agent that discovers the role reads your recipe
verbatim. Reads are open in any namespace; **mutations (`create`/`update`/`delete`)
are restricted to the root namespace** — a sub-namespace request is rejected with
*"skill mutations are restricted to the root namespace."*

## Everything Is Identity-Scoped

Discovery never reveals more than the caller can actually use. `list_roles`
returns only roles reachable by the caller's credential type in the caller's
namespace, and it runs before any role is chosen — it needs no role token, only
the identity the agent already holds. An agent's view of the system *is* its
access, which is what lets it self-onboard safely without an operator hand-feeding
it endpoints, role names, or keys.

## See Also

- [MCP](/concepts/mcp/) — the discovery interface, and how a role's gateway is driven.
- [Roles](/concepts/roles/) — the view a `list_roles` entry stands for, one per step.
- [Authentication](/concepts/authentication/) — the identity discovery is scoped to.
- [Namespaces](/concepts/namespaces/) — the boundary every discovery call respects.
