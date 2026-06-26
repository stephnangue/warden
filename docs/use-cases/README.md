# Use Cases

An agent only earns its keep when it can reach real systems — clouds, code hosts,
databases, observability stacks, MCP servers. That reach is also exactly what makes
an agent dangerous: a program that decides what to do by reading text, holding
credentials to production. These five pages are the problems that tension creates,
and how Warden answers each. They are not alternatives — a single deployment relies
on all five at once.

| Use case | The problem | What Warden does |
|----------|-------------|------------------|
| [Access brokering](access-brokering.md) | Every integration puts another secret in the agent, where it leaks. | Holds the upstream secret and injects a scoped credential per request; the agent carries only its identity. |
| [Breach containment](breach-containment.md) | A prompt-injected or hijacked agent can do anything its broad credential allows. | Leaves no secret to steal, bounds every call by policy, and expires the access it grants. |
| [Runtime authorization](runtime-authorization.md) | Reaching a system means doing anything in it — every tool, every argument. | Authorizes each call at runtime, down to the tool and parameter, default-deny. |
| [Centralized governance](centralized-governance.md) | Dozens of systems, each with its own identity, policy, secrets, and audit. | One control plane — one identity, one policy surface, one audit log, central rotation. |
| [Audit & attribution](audit-attribution.md) | Shared identities and shared MCP servers erase who actually acted. | Ties every request to a real identity and its on-behalf-of chain, secrets hashed. |

The five build on one another: [access brokering](access-brokering.md) keeps the
credential out of the agent, which is what makes [breach
containment](breach-containment.md) possible; [runtime
authorization](runtime-authorization.md) decides what each call may do;
[centralized governance](centralized-governance.md) is where all of that is
operated from one place; and [audit & attribution](audit-attribution.md) records
what happened.

## See Also

- [Concepts](../concepts/index.md) — how Warden works, end to end.
- [Architecture](../architecture.md) — the broker in the request path, at a glance.
- [Agent Flow](../agent-flow.md) — the path an agent takes once its identity is
  established.
- [Agent Identity](../agent-identity/README.md) — how an agent presents the
  identity Warden brokers from.
