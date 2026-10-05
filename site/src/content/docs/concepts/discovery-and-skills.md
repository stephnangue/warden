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
  operator-written description, its provider, the `skill://` URI of its skill,
  and the URL to call it at.
- **`read_skill`** — the skill at a `skill://` URI, as markdown.

It also serves the same skills through the
[MCP Skills extension](#the-mcp-skills-extension), for clients that support it.

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
   with its description, provider, skill and URL. This is the agent's menu.
3. **Match task → role** — the agent reads the descriptions, picks the
   most-scoped role for the step, and surfaces to the user rather than guessing
   when it is ambiguous.
4. **Read the skill** — `read_skill` with the chosen role's `skill` URI returns
   that recipe, and the agent reads any skill it `requires` too.
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
   - **Non-MCP providers** are driven over HTTP: the agent takes the role's
     `url`, prepends `$WARDEN_ADDR`, presents its identity, and — to use another
     role — targets that other role's `url` from `list_roles`.

The role is the unit of discovery. Because a [role](/concepts/roles/) is a view over a
provider — it decides what the caller may do and which credential is minted — the
agent never enumerates raw providers or keys. It discovers *roles*, and each
role's entry carries what it needs: a skill to read, and where to call.

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
reports. A role the identity cannot assume never appears, so the menu is exactly
the caller's reachable surface — and a mount that fails introspection surfaces as
a warning rather than hiding the rest.

Each entry looks like this:

```json
{
  "name": "read-secret",
  "description": "read app secrets",
  "provider": "vault",
  "skill": "skill://vault/SKILL.md",
  "url": "/v1/vault/role/read-secret/gateway/"
}
```

| Field | Where it comes from |
|---|---|
| `name` | The role's name. |
| `description` | The role's `description`: operator-written prose saying what the role is for. |
| `provider` | The type of the provider mounted at the role's `provider_path`. |
| `skill` | The `skill://<name>/SKILL.md` URI of the role's `skill`, or, when the role sets none, of the skill its provider type ships. |
| `url` | Where to call the provider under this role, relative to the Warden address. It already carries the namespace. |

The operator wires a role into discovery with two fields on the role itself,
available on the jwt, cert, kubernetes and spiffe auth methods:

- **`provider_path`** — the mount path of the provider the role is used with,
  relative to the role's namespace (for example `vault/`).
- **`skill`** — the skill that teaches an agent to use the role. Leave it unset
  to use the provider's own skill; set it to point the role at a skill you
  wrote.

```bash
warden write auth/jwt/role/read-secret \
  description="read app secrets" \
  provider_path=vault/
```

A role write updates only the fields it names, so adding `provider_path` to an
existing role leaves the rest of it alone.

Warden lists a role's `url` only when it can vouch for it: `provider_path` names a
provider mount in the namespace, and that provider's `auto_auth_path` resolves to
the auth mount the role lives on. Otherwise the role is listed without `url` and
`provider`, and a line in `warnings` says why. A role with neither field is listed
with its name and description only. An agent must not build a URL for a role that
came without one.

The URL's shape depends on the provider: most take the role in the path
(`/v1/vault/role/read-secret/gateway/`), AWS reads it from the SigV4 access key and
serves every role at one URL (`/v1/aws/gateway`), and an access provider such as
RDS takes it as a query parameter (`/v1/rds/access/`). The role's skill explains
how to use it. An MCP-provider role's `url` is the address its attachment points
at; the agent still calls the attached server rather than connecting to it.

> **Identify a role by its description, not its name.** Role names are slugs; the
> operator-set **description** is the reliable signal of what a role is for.
> Several roles can front the same provider with different access — the
> description is how they are told apart. When it is ambiguous, an agent should
> ask rather than guess.

## Skills

A **skill** is an agent-facing markdown document, stored in a single global
registry, that teaches an agent how to drive a role once it has been discovered.
On the discovery server each skill is a `SKILL.md` at `skill://<name>/SKILL.md`,
with frontmatter in the Agent Skills format. A skill
record has these fields:

| Field | Meaning |
|-------|---------|
| `name` | Unique name: lowercase letters, digits and single hyphens, with no leading or trailing hyphen, at most 64 characters. Warden's default provider guides are named after the provider type, with any underscore turned into a hyphen (`aws`, `mcp-aws`). Name the skills you author `<provider>-<purpose>`, such as `aws-s3-read-only`. |
| `description` | One-line summary an agent reads to decide relevance. |
| `category` | `agent-flow`, `shared`, `provider-guide`, `troubleshooting`, or `custom`. |
| `requires` | Names of other skills this one depends on (often empty). The served SKILL.md lists them as `skill://` URIs. |
| `upstream` | The upstream system the skill is about, when applicable. |
| `provider` | Provider type a `provider-guide` describes. |
| `body` | The markdown recipe itself. |
| `version` | Incremented on every change. |

The `body` is a self-contained recipe: how to reach the role's gateway, which
headers to send, and the provider's quirks (an AWS skill notes that an expired
JWT comes back as the AWS protocol's own authentication error — such as
`InvalidAccessKeyId` from S3 — rather than a 401; a Slack skill notes that HTTP
200 does not mean success — check the `ok` field).

### Reading a skill

`read_skill` takes the `skill://` URI from a role's `skill` field and returns the
whole SKILL.md, frontmatter included. It returns it twice: as the tool's text, and
as `markdown` in its structured output, next to the `uri` and the parsed
`frontmatter`. Some clients read only a tool's structured output when it declares
one, so the `markdown` field is what guarantees the recipe reaches the agent.

A skill's `requires` are part of it: the agent reads each one before acting. It
need not read the skills of roles it is not about to use.

### Skill reads are identity-bound

The discovery server serves an identity only the skills it can reach:

- the skill of every role it can assume, as `list_roles` gives it;
- the skills every identity sees: the `shared`, `agent-flow` and
  `troubleshooting` categories, such as the seeded `troubleshooting` guide;
- every skill those name in `requires`, and what those require in turn.

Any other skill is answered exactly like one that does not exist. So when
`read_skill` reports *not found*, either the skill is gone or none of the caller's
roles leads to it — the honest signal to an agent that the capability is not
there, rather than an endpoint to fabricate. Because the answer depends on who
asks, Warden marks skill listings and resource reads private, so no shared cache
serves one caller's answer to another.

The [`sys/skills` API and `warden skill`](/cli/skill/) are not identity-bound
this way: they are the operator's view of the whole catalog.

### The MCP Skills extension

The discovery server implements the MCP Skills extension
(`io.modelcontextprotocol/skills`, SEP-2640), so a client that supports it can
work with skills as resources instead of calling a tool:

- **`skills/list`** returns every skill the identity can read, each with its URI,
  its frontmatter, and its one resource — the SKILL.md — with a `sha256:` digest
  and size. A client can cache a skill and re-read it only when the digest
  changes.
- **`skills/get`** returns one of those entries by URI.
- **`resources/read`** on a `skill://<name>/SKILL.md` URI returns the SKILL.md as
  `text/markdown`, the same bytes `read_skill` returns.

All three apply the same identity-bound visibility as `read_skill`.

### Skills are yours to write

Skills are not a fixed, built-in catalogue — they are **plain markdown you author
and own**. Warden seeds a sensible default guide for each provider type so an
agent has something to read out of the box, but nothing about a skill is frozen:
you can edit a seeded one, override it wholesale, or add entirely new skills of
your own — an internal runbook, a house convention, a guide narrowed to a single
workflow. The defaults are a starting point, not a ceiling, and a role's `skill`
field can name whichever skill you choose.

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
  skill that fails to seed never blocks the mount. Not every provider type ships
  one; a role on such a provider gets a `skill` only when you set one.
- **The `troubleshooting` skill** is seeded into every server on first unseal —
  a shared guide to Warden's error model.
- **Your own skills** — anything you author through the system API (below),
  including overrides of the seeded defaults.

### Authoring skills

Skills are read over MCP, but they are *authored* by operators through the system
API. Create a new custom skill, override a seeded one, or remove one you added:

```bash
warden skill create -name=oncall-runbook -category=custom \
  -description="on-call response" -body-file=./runbook.md
warden skill update aws -description="our AWS override"
warden skill delete oncall-runbook
```

Point a role at a skill by setting the role's `skill` field, and any agent that
discovers the role reads your recipe verbatim:

```bash
warden write auth/jwt/role/on-call skill=oncall-runbook
```

Reads are open in any namespace; **mutations (`create`/`update`/`delete`) are
restricted to the root namespace** — a sub-namespace request is rejected with
*"skill mutations are restricted to the root namespace."*

## Everything Is Identity-Scoped

Discovery never reveals more than the caller can actually use. `list_roles`
returns only roles reachable by the caller's credential type in the caller's
namespace, and the skills it can read are only those its roles lead to. It runs
before any role is chosen — it needs no role token, only the identity the agent
already holds. An agent's view of the system *is* its access, which is what lets
it self-onboard safely without an operator hand-feeding it endpoints, role names,
or keys.

## See Also

- [MCP](/concepts/mcp/) — the discovery interface, and how a role's gateway is driven.
- [Roles](/concepts/roles/) — the view a `list_roles` entry stands for, one per step.
- [Agent end-to-end flow](/agent-flow/) — the loop traced call by call.
- [`warden skill`](/cli/skill/) — authoring and managing skills.
- [Authentication](/concepts/authentication/) — the identity discovery is scoped to.
- [Namespaces](/concepts/namespaces/) — the boundary every discovery call respects.
