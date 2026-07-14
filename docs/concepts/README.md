# Warden Concepts

A guided tour of how Warden works. The pages are ordered for a first read — top to
bottom takes you from running a server, through the identity and authorization
model, into how it brokers access and the agent-facing features, and out to
multi-tenancy and production operations. Every page is cross-linked, so you can
also jump straight to a topic.

## Getting started

- [Dev Server](dev-server.md) — spin up an in-memory Warden in one command to
  follow along.
- [CLI Reference](../cli/README.md) — the `warden` command: connecting to a
  server, global flags, output formats, and a page per command.

## Identity and access

How a caller proves who it is and what that lets it do.

- [Authentication](authentication.md) — the three credential forms, transparent
  authentication, and identity-channelling sidecars.
- [Auth Methods](../auth-methods/README.md) — per-method setup guides for the
  certificate, JWT/OIDC, Kubernetes, and SPIFFE backends.
- [Tokens](tokens.md) — what authentication produces: session and transparent
  tokens, and the root token.
- [Roles](roles.md) — how a validated credential maps to policies and access,
  resolved per request.
- [Policies](policies.md) — capability-based authorization, path matching, and
  request-content rules.
- [CEL Condition Cookbook](cel-conditions.md) — 20 worked examples for the
  `condition` expression, from a numeric cap to a full payments stanza.

## Brokering access

What Warden actually does: hold the privileged secret and inject a scoped credential
into each proxied request, so the workload reaches the upstream without ever holding
a credential of its own.

- [Credentials](credentials.md) — sources, specs, drivers, lifetime, and
  rotation.
- [Credential drivers](../credential-drivers/README.md) — a reference page per
  driver: config keys, mint methods, credential types, and rotation behaviour.
- [Providers](providers.md) — the gateway mounts that authenticate, authorize,
  inject a credential, and proxy to an upstream.
- [Model Context Protocol](mcp.md) — fronting MCP servers and authorizing
  individual tool calls.

## For AI agents

- [Agent Identity](../agent-identity/README.md) — how an agent presents its
  identity to Warden: sidecar-presented or agent-presented, and the four
  approaches under each.
- [Discovery and Skills](discovery-and-skills.md) — how an agent learns, at
  runtime, what it may do and how.
- [Delegation](delegation.md) — carrying the on-behalf-of chain into the audit
  trail.

## Multi-tenancy and audit

- [Namespaces](namespaces.md) — the hard isolation boundary for every mount,
  policy, and token.
- [Audit](audit.md) — the forensic record of every request, with secrets hashed.
- [Audit Devices](../audit-devices/README.md) — setup guides for enabling and
  configuring the sinks that receive the audit log.

## Running in production

- [Seal and Unseal](seal-unseal.md) — the barrier, auto-unseal, and the seal
  types.
- [Storage](storage.md) — the encrypted-at-rest backend.
- [High Availability](high-availability.md) — active/standby clustering over the
  shared storage backend.

---

For how these pieces fit together at a glance, see the
[Architecture](../architecture.md) overview.
