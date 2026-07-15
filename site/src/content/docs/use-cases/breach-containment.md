---
title: "Breach containment"
---

_When an agent is compromised, keep the damage small._

## One bad step under a broad credential

An agent is a program that decides what to do by reading text — and text is
exactly what an attacker controls. A document it summarizes, a webpage it browses,
an issue it triages can all carry instructions the model cannot reliably tell apart
from its real task. Prompt injection, jailbreaks, and plain hallucination are not
edge cases; they are the normal failure modes of the technology. The question is
not whether an agent will occasionally try to do the wrong thing, but how much one
wrong step is allowed to cost.

Under the usual setup, the answer is: a great deal. If the agent holds a
long-lived, broadly scoped credential, then whoever steers the agent for a moment
inherits everything that credential can reach. A compromised agent with write
access to a production database or an admin API can cause irreversible damage in
the seconds between exploitation and notice — drop tables, delete repositories,
exfiltrate the very keys it was given. The blast radius is not "what the agent was
asked to do"; it is "everything the agent *could* do," and with a broad credential
those are worlds apart.

What makes this acute is that you cannot fix it by trusting the agent more. The
model has no reliable boundary between content and command, so "be more careful"
is not an enforcement mechanism. Containment has to come from outside the agent, or
it does not exist.

## Nothing to steal, every call bounded, access that expires

Warden contains a compromised agent along three independent axes, so a breach is a
bounded event rather than a catastrophic one:

- **Nothing to steal.** Because [access is brokered](/use-cases/access-brokering/), the
  agent never holds an upstream credential. A compromised agent can leak only what
  it has, and all it has is its own identity — useless to an attacker without
  Warden in front of it.
- **Every call is still bounded.** Authority rides on each request and is checked
  at runtime against the agent's [policy](/concepts/policies/), which is
  **default-deny**. A request that exceeds what the agent is allowed is refused
  before it reaches the upstream — no matter what the prompt, the memory, or the
  chat history says. There is no ambient, pre-granted access sitting on the
  connection to be turned against you.
- **Access expires.** The credential Warden injects carries a short
  [lease](/concepts/credentials/#lifetime-and-revocation), so even an allowed
  call buys only a brief window; where the upstream supports it, Warden also
  revokes early. And because [roles are
  per-request](/concepts/roles/#roles-are-per-request), an agent that needs
  elevated access for one step names a higher-privilege role only for that call,
  rather than carrying the elevation through everything else it does.

The same mechanics turn ordinary mistakes into **recoverable** ones. A hallucinated
request that overruns the agent's scope is denied and recorded, with no state
change — an observable non-event in the [audit log](/concepts/audit/) instead
of an incident to clean up.

## Benefits

- **Nothing to exfiltrate** — no upstream secret ever sits in the agent, so a
  hijack finds no keys to steal.
- **Every call stays in bounds** — out-of-scope requests are denied at request
  time, whatever the agent has been talked into.
- **Mistakes become recoverable** — a hallucinated or injected action is a denied,
  logged non-event, not an outage.

## In practice

An incident-response agent reaching a `grafana` mount is prompt-injected by a
malicious annotation in a dashboard it reads: the embedded text tells it to delete
every dashboard and copy an API key to an external host. Neither lands. There is no
Grafana API key in the agent's environment to copy — Warden holds it — and the
agent's role grants only `read` on the mount, so the `DELETE` calls are refused
before they reach Grafana, each recorded as a denied attempt with no state change.
The injection becomes a logged non-event the on-call engineer reviews later, not an
outage to recover from.

## See Also

- [Access brokering](/use-cases/access-brokering/) — why there is no secret in the agent to
  exfiltrate in the first place.
- [Runtime authorization](/use-cases/runtime-authorization/) — the per-call boundary that
  refuses an out-of-scope request.
- [Credentials](/concepts/credentials/#lifetime-and-revocation) — lease,
  expiry, and revocation that cap even an allowed call.
- [Roles](/concepts/roles/#roles-are-per-request) — per-request role binding
  that narrows each step.
- [Audit & attribution](/use-cases/audit-attribution/) — where the contained attempt is
  recorded.
