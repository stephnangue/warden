---
title: "Per-User Access Delegation for AI Agents, on OpenBao"
description: "How Warden leverages OpenBao to enforce access delegation: an AI agent calls GitHub as a specific human, and the vault refuses any agent the user never authorized."
publishDate: 2026-09-17
tags: [openbao, delegation, identity, mcp]
heroImage: /images/blog/warden-blog-openbao-access-delegation-for-ai-agent.png
---

Almost every "the agent acts on behalf of the user" system built today is
**impersonation, not delegation**. The distinction is RFC 8693's own (§1.1): under
impersonation the agent becomes indistinguishable from the person, because it is
holding their credential. Three things stop being true the moment that happens.
You cannot say who an action was *for*. You cannot revoke one person's access
without revoking everyone's. And you cannot stop the agent doing for Bob what
only Alice authorized.

The usual fix is a gateway. The agent no longer holds the credential; the gateway
does — stored locally, or fetched from a vault per request — and injects it on the
way out. That is a real improvement, and it is where most deployments stop.

But look at how that gateway talks to the vault: with a **shared service account**.
One AppRole, one static token, one identity for every request it will ever make.
The vault sees the same caller whether the request is for Alice or for Bob, and
three consequences follow. Its policy engine collapses to a single yes/no — *may
the gateway read secrets?* — because there is no per-user identity to scope on.
Its audit log records the gateway, not the human, which is the attribution problem
returning by another route. And the one credential that can read *everyone's*
secrets now sits in one process.

**The vault has been demoted from policy decision point to filing cabinet** — not
because it lacks the features, but because nobody tells it who is asking. The gap
is identity propagation, not storage.

This post shows how to close that gap with **OpenBao and Warden**, and implement
access delegation properly: an AI agent reaching GitHub as a specific human, with
every authorization decision made inside OpenBao and no long-lived credential
anywhere else.

## The gateway and the vault

**Warden** sits between the agent and the system it wants to reach. A request
passes through four stages, and each one matters here:

1. **Auth methods** authenticate the caller. There are two here, kept separate —
   one for the agent, one for the human — so a request states both who is calling
   and who it is for, and a token good for one leg is not good for the other.
2. The **policy engine** decides whether that caller may make this call. Path
   capabilities and MCP call rules are separate policy types, and access is the
   intersection of both.
3. The **credential engine** obtains the credential to inject. This is the stage
   that talks to OpenBao, and it holds no standing token of its own.
4. The **`mcp` provider** proxies the JSON-RPC call to GitHub's hosted MCP server
   at `api.githubcopilot.com/mcp`, with the credential attached as
   `Authorization: Bearer`. The agent never sees it.

**OpenBao** does the deciding that stage 3 depends on. Four of its capabilities
each take a job:

- **transit** holds the signing key for Warden's OIDC issuer. Warden signs
  assertions by calling `transit/sign/`, and never reads the key.
- **`auth/jwt` with a CEL login role** verifies the assertion and runs a program
  over its claims to decide what the login becomes. CEL roles have no equivalent
  in Vault, and they are why the central check below is expressible at all.
- **the OAuth app secret engine** holds each person's GitHub refresh token, after
  a one-time browser consent, and mints a fresh access token per read.
- **a templated ACL policy** scopes that read to one person's row, using the
  identity the CEL role just established.

<p align="center"><img alt="An agent presents a user ID token and its own identity to Warden, which builds an assertion carrying both principals, signs it with a key held in OpenBao's transit engine, logs in to OpenBao where a CEL role evaluates it, reads a per-user GitHub credential from the OAuth app secret engine, and injects the resulting access token into a call to the GitHub MCP server" src="/images/blog/warden-blog-openbao-access-delegation-for-ai-agent.png" width="860"></p>

## How one request flows

The agent calls a tool. The numbers below are the hops in the diagram above, and
the ones that matter are where OpenBao decides something.

**Steps 1–2 — the agent presents two identities.** Its own token, and the token of the person
it is acting for. Warden's **auth methods** verify each one separately, against the
issuer configured for that leg. Two principals now exist on the request, neither
derived from the other.

So why not just forward one of those tokens to OpenBao and be done?

Forward the **agent's** token and OpenBao sees only the agent — the shared service
account problem moved one rung closer to the work, still blind to who the request
is for. Forward the **person's** token and OpenBao sees only the person, with no
evidence of which agent turned up holding it; anything that stole that token would
look identical.

You cannot forward both, because a login takes one token. And the shape that *does*
carry both — a delegation token with `sub` for the person and `act` for the agent —
fails for a worse reason: to forward it, the agent has to be holding it, and that
token is one OpenBao accepts. The agent could skip the gateway entirely and read
secrets straight out of the vault. Handing an agent a vault-usable credential is
the exact thing this exercise exists to avoid.

So the token OpenBao sees has to name both parties and be minted by something the
agent never holds. That is the assertion.

**Steps 3–4 — Warden mints it.** The **credential engine** builds a five-minute token in which
`sub` is the agent and the human sits nested under `warden_user`, carrying only the
claims the credential spec opted into. It exists for one login and is never handed
to the agent. It is signed by calling `transit/sign/` — the key was created inside
OpenBao, Warden has never read it, and Warden refuses one marked exportable. So
OpenBao verifies a token signed by a key it controls itself.

**Steps 5–6 — OpenBao decides what the login becomes.** The assertion goes to
`auth/jwt/cel/login`, where a **CEL login role** runs a program over its claims:

```json
{
  "bound_audiences": ["openbao-demo"],
  "cel_program": {
    "variables": [
      {"name": "user",
       "expression": "has(claims.warden_user) ? string(claims.warden_user.sub) : ''"},
      {"name": "authorized",
       "expression": "has(claims.warden_user.authorized_agent) && claims.warden_user.authorized_agent == claims.warden_sub"}
    ],
    "expression": "user == '' ? 'assertion carries no delegated user' : (authorized ? pb.Auth{ policies: ['github-delegated'], alias: logical.Alias{name: user}, metadata: {'warden_agent': string(claims.warden_sub)} } : 'this user has not authorized this agent to act for them')"
  }
}
```

The attestation it leans on comes from the identity provider, not the caller:
Keycloak builds nested JSON from dotted claim names, so a mapper named
`may_act.sub` puts `{"may_act":{"sub":"agent-1"}}` on Alice's token — her IdP
stating which agent may act for her, somewhere no agent can forge it.

Three things come out of that program.

First, the decision itself — and this is where delegation is enforced. The
assertion says the calling agent is `agent-1`. Alice's own token said, through an
RFC 8693 `may_act` claim her identity provider put there, that `agent-1` may act
for her. The program compares those two claims **to each other**. That is the one
thing a declarative role cannot do: `bound_claims` matches a claim against fixed
values, and here the value being matched is another claim. Get this wrong and you
have impersonation with extra steps.

Second, the **entity alias**, which the program sets to the person. OpenBao now has
a per-user identity for a login that arrived carrying two principals — and that
identity is what the next step scopes on.

Third, **token metadata** naming the agent, so OpenBao's own audit log records who
acted as well as who was acted for.

> **The same invariant can be enforced at the gateway.** Warden's policy engine
> expresses it as a CEL condition —
> `user.present && user.metadata.authorized_agent == agent.principal` — so the
> pairing can be required before a credential is ever requested. See
> [binding the user to the agent acting for them](https://wardengateway.com/concepts/cel-conditions/#9-bind-the-user-to-the-agent-acting-for-them).
> Enforcing it in both places is worth it for different reasons: at the gateway it
> fails early and cheaply, and in OpenBao it holds even when the gateway's rule was
> never written.

**Steps 7–8 — the credential is read, scoped to one person.** Warden now has an
OpenBao token and has to decide what to ask for. The credential spec names the path
with a template of its own:

```hcl
credential_name = "{{user.sub}}"
```

That resolves per request, against the user principal established back at step 1 —
so one spec serves everybody, and a request made for Alice reads
`github/creds/alice`. Without templating you would need a spec per person, which is
the same explosion as a policy per person.

OpenBao does not take Warden's word for it. The token that login produced carries a
policy templated on its side too, against the entity alias the CEL program set:

```hcl
path "github/creds/{{identity.entity.aliases.<accessor>.name}}" {
  capabilities = ["read"]
}
```

Two templates, one on each side, resolving independently and having to agree. Ask
for someone else's path and the read is refused — the scoping is enforced by
OpenBao rather than trusted to the gateway's path construction.

They cannot drift, either, because one map inside Warden feeds both the assertion's
`warden_user` claim and the `{{user.sub}}` template. The name the policy binds and
the name Warden asks for come from the same value.

The OpenBao side keys on the alias **name**, not alias metadata: metadata is shared
per alias and last-write-wins, so an alias keyed on the *agent* would collapse every
user behind it into one entity and race between concurrent requests.

What sits at that path is the **OAuth app secret engine**, rather than a KV entry
holding a personal access token, and that choice is deliberate too. What you want
is a credential that genuinely belongs to the person and dies with their access,
which is what three-legged OAuth produces — and its durable half, the refresh
token, is exactly the thing that must never leave the vault. So the engine keeps
the grant from Alice's one-time consent and mints a short-lived access token on
each read.

**Step 9 — Warden injects and forwards.** The **`mcp` provider** attaches the token as
`Authorization: Bearer` and proxies the JSON-RPC call onward. The agent gets a tool
result, never a credential.

## Run it, and watch it refuse

You need Docker, `python3`, and a GitHub OAuth App registered with the callback
`http://127.0.0.1:8765/callback`. Warden runs inside the stack, so there is no
binary to install.

**1. Clone it.**

```bash
git clone https://github.com/stephnangue/warden-tuto
cd warden-tuto/access-delegation-openbao
```

**2. Add the OAuth App's credentials** — `GH_CLIENT_ID` and `GH_CLIENT_SECRET`:

```bash
cp .env.example .env
```

**3. Bring the stack up.** This starts OpenBao, Keycloak and Warden, then does every
piece of wiring described above: the transit keys, the CEL role, the templated
policy, the OAuth mount, and Warden's two auth mounts, credential spec and MCP
provider.

```bash
./up.sh
```

**4. Enroll alice.** The one-time browser consent. Whichever GitHub account approves
the prompt is the one alice's requests will use from then on; its refresh token goes
into OpenBao, and nothing is written to Warden.

```bash
./enroll.py alice
```

**5. Point an MCP client at the gateway.** This prints the `.mcp.json` block for
Claude Code.

```bash
./mcp-config.sh alice
```

Now ask it to call `get_me`:

```json
{"login":"stephnangue","id":20239139,
 "details":{"name":"Stephane Nangue","public_repos":32,"owned_private_repos":11}}
```

That is the GitHub account that approved the prompt in step 4 — mine, on this run.
The two names have no reason to match: `alice` is who Keycloak says she is, and what
ties her to a GitHub account is the enrollment, which put that account's refresh
token at `github/creds/alice` — the path `{{user.sub}}` resolves to. In a real
deployment the mapping is the same, and just as arbitrary.

However it is spelled, the agent holds no GitHub credential and the gateway holds no
OpenBao token.

**6. Now do the same as bob**, whose identity provider authorized `agent-9` rather
than the agent that turns up.

```bash
./mcp-config.sh bob
```

```
CEL role 'access-delegation' blocked authorization with message:
this user has not authorized this agent to act for them
```

bob's token is genuine. The agent is legitimate and its own token is genuine. Both
authenticated. **OpenBao refused at login**, before any policy was evaluated, in the
program's own words. Possession of a valid user token is not enough — which is the
confused-deputy vector closed, and a decision a shared service account cannot even
pose, because it has no user identity to ask about.

Drop the user's token entirely and the refusal comes earlier and from the other
side: Warden answers `401` before an assertion is ever minted, because the
credential spec requires a user principal and none was presented.

`./down.sh` stops everything and discards all state.

Everything above was run on OpenBao 2.6.2, the OAuth app plugin v3.4.0 and Warden
v0.20.0. The
[example](https://github.com/stephnangue/warden-tuto/tree/main/access-delegation-openbao)
is a compose file and two scripts; its README carries the eight things that cost me
an afternoon, so they cost you none.
