---
title: Getting started
description: A placeholder page proving the docs pipeline. Replaced by the full docs tree in PR 2.
---

This is a placeholder page that proves the documentation build, sidebar, and search all work.
The full documentation — Concepts, Use Cases, Providers, Credential Drivers, Auth Methods, CLI,
Quickstarts, Tutorials, and Install — arrives in the next change, when the existing `docs/` tree
is migrated into the site.

## What Warden is

Warden sits in the request path between an AI agent and the systems it needs. The agent points
at Warden as if it were the upstream and presents only its own identity. For each request Warden
authenticates the identity, evaluates the call against policy at request time, injects the real
upstream credential, and proxies it — streaming the response back unchanged.

The credential belongs to Warden, never the agent, and is short-lived wherever the upstream
supports it. The agent holds no secrets, gets exactly the access its policy permits — no more —
and every call is tied to its identity in the audit log.

For now, the complete documentation lives in the
[GitHub repository](https://github.com/stephnangue/warden).
