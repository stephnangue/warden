---
title: "Securing agents on the workstation — a Warden tutorial series"
---

These three hands-on tutorials take a local AI coding agent (**Claude Code**) and, one
credential at a time, **remove every secret from your laptop** — without changing how the
agent works. By the end, the workstation holds *zero* long-lived credentials, yet the agent
can still call its LLM and its tools.

Why bother? A credential on the workstation is three problems at once: it's **stored on the
machine** in plaintext (readable by any dependency, script, or tool that runs as you), it has
**no central policy** (the raw key or token grants everything it can, with no per-task limits),
and it leaves **no central audit** (calls hit the provider directly, with no record of who did
what). Each rung moves a credential into Warden, which fixes all three: the secret leaves the
laptop, every request is policy-checked, and every call is audited under the caller's identity.
And each rung *shows* the last two — it turns on the audit log and watches a request get denied
by policy, rather than just asserting it.

## Warden in a nutshell

Warden is a **secure gateway for AI agents**. Your agent talks to Warden; Warden authenticates
the caller, **enforces policy on the request** (which roles, which upstreams, even which
parameters are allowed), injects the *real* upstream credential (an LLM API key, an OAuth
token, cloud creds) **server-side**, proxies the request, and audits it. The secret lives in
Warden, never on the workstation. A local **ghostunnel** sidecar gives the agent a
cryptographic identity (an mTLS client certificate, or a SPIFFE SVID) that Warden uses to
decide what it may reach.

![Architecture: Using SPIFFE X.509 SVID as identity to make inference calls and MPC tool calls](./03-spiffe-llm-mcp/image/spiffe-llm-mcp.png)

## The ladder

The series climbs **two axes**, one credential at a time:

- **Identity** — how the workstation proves who it is: a **X.509 certificate** (whose private
  key sits on disk) → a **SPIFFE SVID** (keyless, held in memory).
- **Upstreams** — what the agent reaches through Warden: **the LLM** → **the LLM + an MCP server**.

Each rung only ever *adds* a removal, so the laptop holds strictly less after every step:

| # | Identity | Upstreams | Credential it removes (on top of the previous rung) | Time |
|---|----------|-----------|-----------------------------------------------------|------|
| [01](/quickstarts/workstation/01-cert-llm/) | mTLS cert · *key on disk* | LLM (Anthropic) | the **LLM API key** | ~15 min |
| [02](/quickstarts/workstation/02-cert-llm-mcp/) | mTLS cert · *key on disk* | LLM + **GitHub MCP** | + the **GitHub MCP token** | ~20 min |
| [03](/quickstarts/workstation/03-spiffe-llm-mcp/) | SPIFFE SVID · *keyless* | LLM + **GitHub MCP** | + the **mTLS private key** → **nothing left** | ~30 min |

### Workstation credential scorecard

What remains on disk *after* finishing each rung (✅ = no longer on the workstation). Each
column is a strict superset of the one before it:

| Credential | 01 cert+LLM | 02 cert+LLM+MCP | 03 spiffe+LLM+MCP |
|------------|:-----------:|:---------------:|:-----------------:|
| LLM API key (Anthropic) | ✅ | ✅ | ✅ |
| GitHub MCP token | on disk | ✅ | ✅ |
| Client **private key** | on disk | on disk | ✅ |

By **03** the workstation holds **no long-lived credentials at all** — the identity is a
keyless, auto-rotating SVID, and every upstream secret lives only in Warden.

## Prerequisites (the whole series)

The host needs almost nothing — everything runs in containers from published images:

| You need | For | Notes |
|----------|-----|-------|
| **Docker** (Desktop or Engine) with Compose v2 | all rungs | `docker compose version` (v2.23.1+ for 03) |
| **Claude Code** CLI | all rungs | `claude --version` |
| An **Anthropic API key** | 01–03 | from [console.anthropic.com](https://console.anthropic.com); it stays inside Warden |
| A **GitHub PAT** (classic) | 02, 03 | `repo` + `read:org` scope; it stays inside Warden |

Nothing to compile — `docker compose` pulls the published Warden and ghostunnel images. The only
host binary is the **Warden CLI** for admin commands; each tutorial's prerequisites download it
and point it at Warden through ghostunnel's plaintext port (so there's nothing for the CLI to
TLS-verify).

> **One honest caveat, true at every rung.** The hop from Claude Code to the local ghostunnel
> is plain HTTP over loopback. That's inherent to the sidecar pattern; it's safe on a
> single-user workstation because ghostunnel binds `127.0.0.1` only, so no other host can ride
> the tunnel. SPIFFE doesn't change this — what it removes is the *private key on disk*.

## Where to start

Start at **[01](/quickstarts/workstation/01-cert-llm/)** even if SPIFFE is your goal — it introduces the
ghostunnel/Warden/compose mechanics every later rung reuses, and each rung builds on the last.

## What comes next

This is the first of three series. After the workstation, the same gateway pattern moves to
where agents really run:

- **Agents on Kubernetes** — workload identity from the cluster (projected SA tokens / SPIRE),
  no secrets in pod specs or env.
- **Agents in CI/CD** — pipeline identity (OIDC from the CI platform), no long-lived tokens in
  repo or runner secrets.

