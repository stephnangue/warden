---
title: "Centralized governance"
sidebar:
  order: 5
---

_One control plane for every system an agent touches._

## Every system in its own silo

A useful agent does not reach one system; it reaches dozens — a cloud control
plane, a Git host, half a dozen observability tools, a database or two, an
incident manager, a handful of MCP servers. Each of those was built with its own
idea of identity, its own credential format, its own way of writing policy, and its
own audit log. Wire an agent into all of them and you have not built one access
model; you have inherited fifteen.

The cost is not abstract. There is no single place to ask "what can this agent
reach?", because the answer is scattered across fifteen consoles. There is no
single place to *change* that answer, so tightening a policy or offboarding an
agent means fifteen edits, and the one you forget is the one that leaks. Rotation
is fifteen schedules. MCP makes it worse, pushing a separate credential for each
tool into the agent's environment. And when two teams share the same infrastructure,
nothing keeps one team's policies, secrets, and mistakes from reaching the other.

What you end up governing is not the fleet of agents but the sprawl of integrations
underneath them — and that sprawl grows with every system you add, until the
operational weight of managing access is the thing that limits how many agents you
can safely run.

## Identity, policy, and audit in one place

Warden is the single point every agent request passes through, so it is the single
place those concerns live. One agent identity is validated once and carried to
every upstream the policy permits. One [policy](/identity/policies/) surface,
written in one language, governs access across every system — the same default-deny
rules whether the agent is calling a cloud API, a Git host, or an MCP server. One
[audit log](/concepts/audit/) records every request to every upstream. The
[providers](/concepts/providers/) Warden ships front clouds, databases, code
hosts, observability stacks, SaaS, and MCP servers alike, so adding a system means
mounting a provider, not standing up another access model.

The agent itself has a record to govern. Register it as an
[entity](/identity/entities/) and it carries a description of what it does, a
[sponsor](/identity/sponsors/) — the team that answers for it — and a state:
active, suspended or retired. A registered agent holds roles only through the
[static groups](/identity/groups/) that list it, and only while it is sponsored,
described and active. Suspending the entity stops the agent on its next request,
through every mount and every upstream, with no token to revoke. A namespace can
also refuse agents nobody registered.

Upstream credentials are governed in one place too. Warden
[federates](/federation/keyless-credentials/) with upstreams that trust its identity, so
there is no secret to keep; [chains](/federation/credential-chaining/) the ones that only
issue secrets from the store that already manages them; and, for secrets it holds itself,
[rotates](/concepts/credentials/#rotation) them on a schedule it manages, staging the
change for upstreams that need time to propagate a new key — so upstream credentials stay
fresh without per-integration coordination. For MCP, one
gateway fronts every tool a server exposes, replacing the per-tool-credential-in-env
model with a single policy surface.

Where independence matters, [namespaces](/concepts/namespaces/) give it. Each
team, product, or environment gets a hard boundary: its mounts, identities, and
policies are invisible to every other namespace, and a policy in one can never grant
access in another. One Warden serves many tenants on shared infrastructure without
their access models bleeding together.

## Benefits

- **One policy surface** — set, review, and answer access for every upstream in one
  place and one language, instead of across a dozen consoles.
- **An owner for every agent** — each registered agent names the team that answers
  for it, and one state change stops it everywhere.
- **Hard tenant isolation** — namespaces give each team or environment a sealed
  boundary on shared infrastructure.
- **Secrets stay fresh on their own** — Warden federates, chains, or holds and
  rotates the upstream credentials centrally, so rotation is not N schedules to chase.

## In practice

A platform team runs one Warden for the whole company. Agents across several teams
reach AWS, GitHub, Datadog, a production database, and a set of MCP servers — all
through Warden, all under policies the platform team writes in one place. Each team
works inside its own namespace, so `team-a`'s mounts and secrets are invisible to
`team-b`. AWS and the database are reached by federation, Datadog's key is chained from
the company's secret store, and the few secrets Warden holds itself rotate on schedule —
without any team touching a key. Each agent is an entity its team sponsors. Onboarding a
new upstream is one provider mount; offboarding an agent is one entity retired — not a
sweep across fifteen systems.

## See Also

- [Providers](/concepts/providers/) — the mounts that front every upstream
  behind one gateway.
- [Namespaces](/concepts/namespaces/) — the hard isolation boundary for mounts,
  policies, and tokens.
- [Entities](/identity/entities/) and [Sponsors](/identity/sponsors/) — registering
  an agent, and the team that answers for it.
- [Keyless credentials](/federation/keyless-credentials/) and
  [credential chaining](/federation/credential-chaining/) — reaching upstreams without
  storing their secrets in Warden.
- [Credentials](/concepts/credentials/#rotation) — how Warden rotates the
  secrets it holds, centrally.
- [Runtime authorization](/use-cases/runtime-authorization/) — the per-call decisions this
  one policy surface enforces.
- [Audit & attribution](/use-cases/audit-attribution/) — the single log every governed
  request lands in.
