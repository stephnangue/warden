---
title: "Register every agent, and refuse the ones nobody claimed"
description: "Warden v0.22.0 adds agent identity and governance: every agent is registered with the team that answers for it, roles are granted per request instead of held, and agents nobody claimed can be refused."
publishDate: 2026-11-06
tags: [release, identity, governance]
---

Ask who answers for an agent in production, and the usual answer is a credential.
The agent presents a JWT, a SPIFFE ID or a Kubernetes service account, the gateway
verifies it, and the request goes through. That proves which workload is calling. It
does not say whether anyone meant it to run, which team to page when it misbehaves,
or whether the team that built it still exists. An agent started months ago on a key
nobody remembers passes exactly the same check as the one deployed this morning.

These are shadow agents, and verification alone cannot find them: every one of them
has a valid identity. What they lack is a record that someone answers for them.
Warden v0.22.0 adds that record, and lets you refuse every agent without one.

## Register the agent

Registered agents live in Warden's **identity store**, the per-namespace inventory
other products call an agent registry. Each agent is an *entity*: what it does, the
team that sponsors it, and the identity it presents, which Warden calls its native
identity:

```bash
warden identity entity create billing-agent -json '{
  "description": "Reconciles supplier invoices against purchase orders",
  "profile": {
    "purpose": "billing",
    "runtime": "langgraph"
  }
}'
warden identity entity sponsor propose billing-agent -json '{
  "group": "billing-team"
}'
```

<p align="center"><img alt="The governance model of one agent: the entity billing-agent, with its name, description, ID, state active, sponsor billing-team and creation time, sits in the middle; above it, the Sponsoring Group billing-team, made of people; beside it, the Entitlements Group billing-operators, which grants the roles invoice-reader and invoice-matcher and, through them, their policies; below it, the one runtime principal it claims, the agent workload's SPIFFE ID spiffe://actor/billing-team/agent-1." src="/images/warden-agent-governance-model.png" width="860"></p>

The sponsor is a group of people, and a member of it accepts the proposal. From then
on the team can suspend its agent, or hand it to another team, without holding any
Warden role. An entity with a description and an accepted sponsor is *governed*.
`warden identity entity list -ungoverned` shows the ones still waiting for one.

## Roles are granted, never held

A role names what an agent may do: its policies, and the credential Warden mints for
it. No agent holds one. On every request Warden authenticates the caller, resolves
which roles its groups grant it right now, and authorizes the call against the role it
asked for. Nothing carries over to the next request.

Groups come in two kinds. A **virtual** group matches what the caller's credential
proved, such as the mount it came through or a claim in its token. It is quick to set
up, and fine for trying a provider, but it grants the role to every caller that
matches:

<p align="center"><img alt="A new agent with no entity asks for the role sandbox. Authenticate: the jwt auth mount verifies its identity and records facts. Resolve: virtual groups, which have no members, match those facts and resolve the roles sandbox and llm-basic. Authorize: sandbox is among them, so the request is authorized." src="/images/warden-agent-virtual-group.png" width="860"></p>

A **static** group lists entities by name. Once an agent's native identity is claimed
by its entity, virtual groups no longer apply to it: it holds only what its static
groups grant, and only while it is governed and active. Mark a role `governed_only`
and no virtual group can grant it at all.

```bash
warden identity group create billing-operators -json '{
  "type": "static",
  "description": "Billing agents governed by Warden",
  "members": ["billing-agent"],
  "roles": ["invoice-reader", "invoice-matcher"]
}'
warden identity alias add -json '{
  "mount": "auth/spiffe/",
  "name": "spiffe://actor/billing-team/agent-1",
  "to": "billing-agent"
}'
```

<p align="center"><img alt="A registered agent asks for the role deployer. Authenticate: the jwt auth mount verifies its identity. Resolve: its entity, Entity A, is listed by static groups that resolve the roles deployer and secret-reader. Authorize: deployer is among them, so the request is authorized." src="/images/warden-agent-static-group.png" width="860"></p>

The claim comes last, so the agent never loses a role on the way over.

## People sign in with their company login

Operators are not entities. They sign in with the new `oidc` auth method, from the
command line through their browser, and hold roles through virtual groups over their
identity provider's claims, so who may run Warden is decided where the rest of the
company's access is:

```bash
warden login
```

<p align="center"><img alt="A person, who has no entity, presents a ticket token and asks for the role warden-viewer. Authenticate: Warden checks the ticket. Resolve: virtual groups match the facts it carries and resolve warden-viewer. Authorize: warden-viewer is among them, so the request is authorized." src="/images/warden-human-virtual-group.png" width="860"></p>

Four built-in roles cover running Warden itself: `warden-admin`, `warden-provider-admin`,
`warden-security-admin` and `warden-viewer`. Nobody holds them until a group grants
them, and they never reach the data path.

## Observe, then deny

No agent is refused for being unregistered until you say so. Every namespace starts in
`observe`: unregistered agents keep working, and each request records in the audit log why `deny` would refuse it.
Register the agents you rely on, give each a sponsor, watch the log until it is quiet,
then switch:

```bash
warden identity config write -unknown-aliases=deny
```

From then on, an agent nobody claimed is refused before any role is considered,
whichever role it asks for. So is a registered agent whose team stepped away, or that
its sponsor suspended. Suspension takes effect on the agent's next request, with no
token to revoke.

## The rest of the release

- Agent discovery runs under the namespace's built-in policies, and is audited.
- Agents call Microsoft Graph as the signed-in person they act for, through Entra
  on-behalf-of, and Azure apps can authenticate with a certificate instead of a secret.
- Amazon Bedrock works keyless, with no model API key stored anywhere.
- The token and credential caches are sized in real bytes, with a budget you set.
- A transit seal configured in the server's file works on its own.
- Twelve breaking changes: auth mounts no longer bind roles, and agent mounts require an
  audience. Read the upgrade guide before you upgrade.

## Read next

- [Getting started](/getting-started/) — the playground, then
  [Governing an agent](/tutorials/identity/govern-an-agent/) in the same playground.
- [Identity and access](/identity/) — the model, page by page.
- [Release notes](https://github.com/stephnangue/warden/releases/tag/v0.22.0).
- [Upgrading from v0.21.0](/upgrade/from-v0-21/).
