---
title: "Access brokering"
---

_Give agents access without giving them secrets._

## Every integration is one more secret in the agent

An agent only earns its keep when it can reach real systems — a Git host, a cloud
control plane, a database, an MCP server. Each of those wants a credential, so the
usual answer is to hand the agent one: an API key in an environment variable, a
token in a `.env` file, a service-account key baked into the image. Every new
integration adds another long-lived secret, and every one of them now lives
wherever the agent lives.

That is exactly where secrets are hardest to protect. A key in the agent's
environment is a key in its process memory, its logs, its crash dumps, and its
chat context — one stray log line or one poisoned prompt away from leaking. And
because these credentials are long-lived and broadly scoped, a single leak is not
a momentary lapse; it is standing access that an attacker can use for as long as
the key remains valid, from anywhere, with nothing tying it back to the agent that
lost it.

The cost compounds with scale. Ten agents reaching ten systems is a hundred places
a secret can sit, each on its own rotation schedule, each a thing to provision when
an agent is created and revoke when it is retired. The work of distributing and
rotating those keys quietly becomes the dominant cost of running agents at all.

## Warden holds the secret; the agent carries only an identity

Warden's purpose is to keep secrets out of workloads. Instead of handing the agent
a key, Warden **brokers access**: it holds the privileged upstream secret itself
and, at request time, mints or retrieves a scoped, short-lived
[credential](/concepts/credentials/) for the upstream the agent is trying to
reach — then injects it into the proxied request rather than handing it over. The
agent presents **only its own identity** and never receives a credential of its
own.

The identity is something the agent already has — a JWT, an mTLS client
certificate, or a SPIFFE SVID. The agent points an ordinary client at a Warden
[provider](/concepts/providers/) mount as if Warden were the upstream;
Warden validates that identity through
[transparent authentication](/concepts/authentication/#transparent-authentication),
resolves what it may draw, mints the credential, injects it, and streams the
response back. The credential lives only inside that one hop, and the privileged
secret that minted it never leaves Warden.

Because the same identity is what reaches *every* upstream, there are no per-system
keys to distribute and none to rotate per integration — the agent runs
**secretless**, carrying an identity rather than a wallet of credentials. That
identity is also what every [policy](/concepts/policies/) decision and
[audit](/concepts/audit/) entry ties back to, so access is attributable to the
agent that used it rather than to a shared key.

## Benefits

- **No secret in the agent** — there is nothing in the process, the environment,
  or the chat context to leak, log, or commit, because the agent never holds an
  upstream credential.
- **One identity, every system** — the agent authenticates as itself everywhere,
  so there are no per-integration keys to provision, distribute, or rotate.
- **Short-lived by default** — Warden mints a scoped credential per request and
  injects it for a single hop, so access does not outlive the work it was minted
  for.

## In practice

A coding agent needs to push to GitHub. It runs with a SPIFFE SVID and speaks
plain HTTPS to a `github` mount; it holds no GitHub token and no app key. When it
makes the call, Warden validates the SVID, resolves the role, mints a short-lived
GitHub App **installation token** from the private key it holds, injects it into
the push, and streams GitHub's response back. No long-lived GitHub credential ever
lands in the agent's environment or its repository secrets — the agent acted as
itself, and Warden brokered the rest.

## See Also

- [Breach containment](/use-cases/breach-containment/) — the containment brokering makes
  possible: no secret in the agent means nothing to exfiltrate.
- [Runtime authorization](/use-cases/runtime-authorization/) — deciding what the brokered
  identity may actually do, on every call.
- [Credentials](/concepts/credentials/) — sources, specs, drivers, lifetime,
  and rotation.
- [Authentication](/concepts/authentication/) — transparent auth and the
  credential forms an agent presents.
- [Agent Identity](/agent-identity/) — how an agent presents the
  identity Warden brokers from.
