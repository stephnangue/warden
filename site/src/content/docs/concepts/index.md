---
title: "Warden Concepts"
---

A guided tour of how Warden works. The pages are ordered for a first read — top to
bottom takes you from running a server, through the identity and authorization
model, into how it brokers access and the agent-facing features, and out to
multi-tenancy and production operations. Every page is cross-linked, so you can
also jump straight to a topic.

## Getting started

- [Dev Server](/concepts/dev-server/) — spin up an in-memory Warden in one command to
  follow along.
- [CLI Reference](/cli/) — the `warden` command: connecting to a
  server, global flags, output formats, and a page per command.

## Identity and access

How a caller proves who it is and what that lets it do.

- [Authentication](/concepts/authentication/) — the three credential forms, transparent
  authentication, and identity-channelling sidecars.
- [Auth Methods](/auth-methods/) — per-method setup guides for the
  certificate, JWT/OIDC, Kubernetes, and SPIFFE backends.
- [Tokens](/concepts/tokens/) — what authentication produces: session and transparent
  tokens, and the root token.
- [Roles](/concepts/roles/) — how a validated credential maps to policies and access,
  resolved per request.
- [Policies](/concepts/policies/) — capability-based authorization, path matching, and
  request-content rules.
- [CEL Condition Cookbook](/concepts/cel-conditions/) — 20 worked examples for the
  `condition` expression, from a numeric cap to a full payments stanza.

## Brokering access

What Warden actually does: hold the privileged secret and inject a scoped credential
into each proxied request, so the workload reaches the upstream without ever holding
a credential of its own.

- [Credentials](/concepts/credentials/) — sources, specs, drivers, lifetime, and
  rotation.
- [Credential drivers](/credential-drivers/) — a reference page per
  driver: config keys, mint methods, credential types, and rotation behaviour.
- [Providers](/concepts/providers/) — the gateway mounts that authenticate, authorize,
  inject a credential, and proxy to an upstream.
- [Model Context Protocol](/concepts/mcp/) — fronting MCP servers and authorizing
  individual tool calls.

## For AI agents

- [Agent Identity](/agent-identity/) — how an agent presents its
  identity to Warden: sidecar-presented or agent-presented, and the four
  approaches under each.
- [Discovery and Skills](/concepts/discovery-and-skills/) — how an agent learns, at
  runtime, what it may do and how.
- [Delegation](/concepts/delegation/) — carrying the on-behalf-of chain into the audit
  trail.

## Multi-tenancy and audit

- [Namespaces](/concepts/namespaces/) — the hard isolation boundary for every mount,
  policy, and token.
- [Audit](/concepts/audit/) — the forensic record of every request, with secrets hashed.
- [Audit Devices](/audit-devices/) — setup guides for enabling and
  configuring the sinks that receive the audit log.

## Running in production

- [Seal and Unseal](/concepts/seal-unseal/) — the barrier, auto-unseal, and the seal
  types.
- [Storage](/concepts/storage/) — the encrypted-at-rest backend.
- [High Availability](/concepts/high-availability/) — active/standby clustering over the
  shared storage backend.

---

For how these pieces fit together at a glance, see the
[Architecture](/architecture/) overview.
