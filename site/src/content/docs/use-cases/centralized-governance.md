---
title: "Centralized governance"
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
every upstream the policy permits. One [policy](/concepts/policies/) surface,
written in one language, governs access across every system — the same default-deny
rules whether the agent is calling a cloud API, a Git host, or an MCP server. One
[audit log](/concepts/audit/) records every request to every upstream. The
[providers](/concepts/providers/) Warden ships front clouds, databases, code
hosts, observability stacks, SaaS, and MCP servers alike, so adding a system means
mounting a provider, not standing up another access model.

The secrets stay in one place too. Warden holds the privileged upstream credentials
and [rotates](/concepts/credentials/#rotation) them on a schedule it manages,
staging the change for upstreams that need time to propagate a new key — so the
broker's own secrets stay fresh without per-integration coordination. For MCP, one
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
- **Hard tenant isolation** — namespaces give each team or environment a sealed
  boundary on shared infrastructure.
- **Secrets stay fresh on their own** — Warden holds and rotates the upstream
  credentials centrally, so rotation is not N schedules to chase.

## In practice

A platform team runs one Warden for the whole company. Agents across several teams
reach AWS, GitHub, Datadog, a production database, and a set of MCP servers — all
through Warden, all under policies the platform team writes in one place. Each team
works inside its own namespace, so `team-a`'s mounts and secrets are invisible to
`team-b`, and the upstream credentials Warden holds rotate on schedule without any
team touching a key. Onboarding a new upstream is one provider mount; offboarding an
agent is one identity removed — not a sweep across fifteen systems.

## See Also

- [Providers](/concepts/providers/) — the mounts that front every upstream
  behind one gateway.
- [Namespaces](/concepts/namespaces/) — the hard isolation boundary for mounts,
  policies, and tokens.
- [Credentials](/concepts/credentials/#rotation) — how Warden rotates the
  secrets it holds, centrally.
- [Runtime authorization](/use-cases/runtime-authorization/) — the per-call decisions this
  one policy surface enforces.
- [Audit & attribution](/use-cases/audit-attribution/) — the single log every governed
  request lands in.
