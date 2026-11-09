---
title: "Identity & access"
---

Every request that reaches Warden answers two questions before anything is
forwarded: **who is calling**, and **what may they do on this request**. Warden
answers both on the request itself. Nothing is decided at login and kept: a
caller presents a credential, Warden checks it, works out which roles the
caller holds right now, and authorizes the call under the one it asked for.

This section explains that model, in the order a request meets it.

## The path of a request

1. **Authenticate.** An [auth mount](/identity/authentication/) verifies the
   credential — a JWT, a client certificate, a Kubernetes service account
   token, a SPIFFE SVID — or Warden checks a person's sign-in ticket. What
   was verified is recorded as **facts** (the issuer, the subject, a scope, a
   namespace), and one verified value becomes the caller's **native
   identity**.
2. **Resolve.** Warden works out which roles the caller holds for this
   request. If an **entity** in Warden's identity store claims the native
   identity, the caller is a registered agent, and only the
   [static groups](/identity/groups/) that list its entity count — and only
   while it is governed and active. Otherwise **virtual groups** match the
   facts with rules. Registering agents is optional; a namespace can also
   require it.
3. **Authorize.** The [role](/identity/roles/) the request asks for must be
   one the caller holds; a role no group grants is refused. The role's
   [policies](/identity/policies/) then decide the call, and its
   [credential spec](/concepts/credentials/) is what Warden injects upstream.

A change to a group, a role or an entity applies from the next request: no
token carries a role, so there is no grant to revoke.

## Three callers, three walks

**A new agent, not registered.** Its credential is admitted, and virtual
groups match the facts its mount verified. Give virtual groups the floor — the
low-privilege roles any agent from that mount may hold.

<p align="center"><img alt="A new agent with no entity asks for the role sandbox. Authenticate: the jwt auth mount verifies its identity and records facts. Resolve: virtual groups, which have no members, match those facts and resolve the roles sandbox and llm-basic. Authorize: sandbox is among them, so the request is authorized." src="/images/warden-agent-virtual-group.png" width="860"></p>

**A registered agent.** Once an entity claims its native identity, the agent
holds only what its entity's static groups grant, and only while the entity is
governed and active. Virtual groups no longer apply to it.

<p align="center"><img alt="A registered agent asks for the role deployer. Authenticate: the jwt auth mount verifies its identity. Resolve: its entity, Entity A, is listed by static groups that resolve the roles deployer and secret-reader. Authorize: deployer is among them, so the request is authorized." src="/images/warden-agent-static-group.png" width="860"></p>

**A person.** People sign in with `warden login` and carry a ticket. They are
not entities: virtual groups match the claims their identity provider
verified, such as the IdP groups they belong to.

<p align="center"><img alt="A person, who has no entity, presents a ticket token and asks for the role warden-viewer. Authenticate: Warden checks the ticket. Resolve: virtual groups match the facts it carries and resolve warden-viewer. Authorize: warden-viewer is among them, so the request is authorized." src="/images/warden-human-virtual-group.png" width="860"></p>

## Words used in this section

| Term | Meaning |
|---|---|
| **Admission** | What the Authenticate step produces: the auth mount's acceptance of a credential, with the facts it verified and the native identity it chose. A mount *admits* a credential. |
| **Fact** | A verified value an auth mount records, such as a JWT claim or a service account's namespace. Groups match on facts. |
| **Native identity** | The value a mount verified that identifies the caller — a JWT `sub`, a certificate name, a service account, a SPIFFE ID. In Warden's commands and fields it is an *alias*. |
| **Entity** | A registered agent in Warden's identity store. It claims the agent's native identity and carries a description, a state and a sponsor. |
| **Sponsor** | The group of people who answer for an entity. An entity with an accepted sponsor and a description is **governed**. |
| **Virtual group** | Grants roles to callers whose facts match its rules. It has no members. |
| **Static group** | Grants roles to the entities it lists. |
| **Role** | What a caller may do: policies, an optional credential spec, and how discovery describes it. Granted per request. |
| **Ticket** | A person's signed-in session, issued by `warden login`. It carries their verified identity and no role. |

## Observe, then enforce

Registering agents does not have to happen all at once. By default a
namespace **observes**: unregistered agents are admitted as before, and the
audit log records, for each request, why enforcement would have refused it.
Register the agents that show up one at a time, then switch the namespace to
**deny** — from then on, an agent nobody registered or nobody sponsors is
refused.

Registering an agent changes what it holds straight away, in either mode:
once its entity claims its native identity, only static groups grant it
roles, and only while it is governed. So sponsor the entity and add it to a
static group before you claim the agent's native identity.
[Entities](/identity/entities/#rolling-out) walks through the rollout.

## In this section

**Authenticate**

- [Authentication](/identity/authentication/) — auth mounts, the credentials they admit, and the facts they record.
- [Tokens](/identity/tokens/) — service tokens, identity tokens and tickets.

**Resolve**

- [Groups](/identity/groups/) — virtual and static groups, and how they grant roles.
- [Entities](/identity/entities/) — the identity store, registering agents, and enforcing registration.
- [Sponsors](/identity/sponsors/) — the people who answer for an agent.

**Authorize**

- [Roles](/identity/roles/) — what a role names, and how a request selects one.
- [Policies](/identity/policies/) — the rules a role names, and the built-in policies every request runs under.
- [CEL conditions](/identity/cel-conditions/) — conditions on a policy, with a cookbook of recipes.

**People and operators**

- [Human operators](/identity/human-operators/) — `warden login`, tickets, and roles from your identity provider.
- [Built-in roles](/identity/built-in-roles/) — the four operator roles Warden defines for you.

Coming from v0.21.0, where roles were bound at login? See
[Upgrading from v0.21.0](/upgrade/from-v0-21/).
