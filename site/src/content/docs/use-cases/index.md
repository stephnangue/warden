---
title: "Use Cases"
---

An agent only earns its keep when it can reach real systems — clouds, code hosts,
databases, observability stacks, MCP servers. That reach is also exactly what makes
an agent dangerous: a program that decides what to do by reading text, holding
credentials to production. These five pages are the problems that tension creates,
and how Warden answers each. They are not alternatives — a single deployment relies
on all five at once.

| Use case | The problem | What Warden does |
|----------|-------------|------------------|
| [Access brokering](/use-cases/access-brokering/) | Every integration puts another secret in the agent, where it leaks. | Holds the upstream secret and injects a scoped credential per request; the agent carries only its identity. |
| [Breach containment](/use-cases/breach-containment/) | A prompt-injected or hijacked agent can do anything its broad credential allows. | Leaves no secret to steal, bounds every call by policy, and expires the access it grants. |
| [Runtime authorization](/use-cases/runtime-authorization/) | Reaching a system means doing anything in it — every tool, every argument, for anyone the agent fronts. | Authorizes each call at runtime, down to the tool and parameter and on whose behalf it acts, default-deny. |
| [Centralized governance](/use-cases/centralized-governance/) | Dozens of systems, each with its own identity, policy, secrets, and audit. | One control plane — one identity, one policy surface, one audit log, central rotation. |
| [Audit & attribution](/use-cases/audit-attribution/) | Shared identities and shared MCP servers erase who actually acted. | Ties every request to a real identity and its on-behalf-of chain, secrets hashed. |

The five build on one another: [access brokering](/use-cases/access-brokering/) keeps the
credential out of the agent, which is what makes [breach
containment](/use-cases/breach-containment/) possible; [runtime
authorization](/use-cases/runtime-authorization/) decides what each call may do;
[centralized governance](/use-cases/centralized-governance/) is where all of that is
operated from one place; and [audit & attribution](/use-cases/audit-attribution/) records
what happened.

## See Also

- [Concepts](/concepts/) — how Warden works, end to end.
- [Architecture](/architecture/) — the broker in the request path, at a glance.
- [Agent Flow](/agent-flow/) — the path an agent takes once its identity is
  established.
- [Agent Identity](/agent-identity/) — how an agent presents the
  identity Warden brokers from.
