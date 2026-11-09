---
title: "Sponsors"
---

An entity's **sponsor** is the team of people who answer for the agent. It is
the second half of governance: an [entity](/identity/entities/) is
**governed** once it has an accepted sponsor and a description, and only a
governed entity's agent holds roles.

A sponsor is not a name typed into a field. It is a group of people, it is set
only once one of them accepts it, and its members can act on the agent
themselves — read it, stop it, hand it to another team — without holding any
Warden role.

## The model

- A sponsor is a **virtual group of humans**: a [group](/identity/groups/)
  whose rules match people signed in through a mount that admits humans, such
  as the [oidc](/identity/human-operators/) mount. A static group cannot be a
  sponsor.
- The group belongs to the **entity's namespace or one of its ancestors**. A
  sibling's or a child's group is refused.
- An entity has **at most one sponsor and at most one pending handover** — a
  proposed sponsor that no member has accepted yet. The pending handover never
  counts toward governance; the current sponsor stays until it is accepted.
- The sponsor is recorded by group ID as well as name, so a group deleted and
  created again under the same name is never taken for the old one.
- Each entry records who proposed it and who accepted it (their mount, native
  identity and principal) and when.
- An entity is created **without** a sponsor; one is proposed afterwards.

Membership is decided where the person signed in: a group of the root
namespace matches people signed in at the root's mount, a group of `team-a`
people signed in at `team-a`'s. Keep sponsor groups where your people sign in,
usually the root namespace, and point to them with `-group-namespace /`.

A sponsor group needs no roles. Assuming the oidc mount publishes the identity
provider's `groups` claim as a fact:

```bash
warden identity group create billing-team -json '{
  "type": "virtual",
  "description": "The billing team, signed in through the company identity provider",
  "rules": [
    {
      "mount": ["auth/oidc/"],
      "kind": ["human"],
      "groups": ["billing-team"]
    }
  ]
}'
```

## One group or two

A sponsor answers for an agent; it grants the agent nothing. The agent's roles
come from the [static groups](/identity/groups/) that list its entity. These
are different groups with different jobs:

| | Sponsoring group | Entitlements group |
|---|---|---|
| Type | Virtual, matching people | Static, listing entities |
| Answers | Who is accountable for this agent? | What may this agent do? |
| Effect on the agent | Makes it governed, with a description | Grants its roles, while it is governed and active |
| Changed by | Its members (handover) or an admin | An admin with sudo on groups |

So the team that answers for `billing-agent` (`billing-team`) and the group
that grants it `invoice-reader` and `invoice-matcher` (`billing-operators`)
are kept apart, and can be reviewed by different people. The sponsor group
may still grant roles to its own members — the same virtual group can give
the billing team their console role — or you can keep a dedicated group that
grants nothing and exists only for accountability.

## Proposing and accepting

An admin with sudo on `sys/identity/entity` proposes a group:

```bash
warden -n team-a identity entity sponsor propose billing-agent -json '{
  "group": "billing-team",
  "namespace": "/"
}'
```

What happens depends on who proposes:

- **A member of the group**, signed in with `warden login`: the group is the
  sponsor at once, accepted by the proposer, replacing any earlier sponsor in
  the same write.
- **Anyone else**: the group becomes the pending handover, replacing any
  earlier pending one. The current sponsor, if any, stays. A member of the
  group then reads the entity and accepts:

  ```bash
  warden -n team-a identity sponsor read billing-agent
  warden -n team-a identity sponsor accept billing-agent
  ```

- **Root** is a member of no group, so its proposals are always pending, and
  root cannot accept one either. An entity becomes governed only when a person
  in the sponsor group has agreed to it.

A proposal is never refused for who can act on it, but it warns about a group
that cannot work as a sponsor: when no auth mount of the group's namespace admits humans, when no
rule of the group can match a human, or when a rule trusts a mount that admits
agents.

Admins can also remove the sponsor, which leaves the entity ungoverned at
once, or cancel a pending handover:

```bash
warden identity entity sponsor remove billing-agent
warden identity entity sponsor remove billing-agent -pending
```

## The commands

Sponsor commands live in two trees, one for admins and one for sponsors:

| Command | Who | Does |
|---|---|---|
| `warden identity entity sponsor propose <entity>` | Admin (sudo on `sys/identity/entity`) | Propose a group: accepted at once for a member, pending otherwise. |
| `warden identity entity sponsor remove <entity>` | Admin | Remove the sponsor; with `-pending`, cancel the handover. |
| `warden identity sponsor read <entity>` | Member of the sponsor group, or of the pending one | Read the entity, so a team never accepts an agent blind. |
| `warden identity sponsor suspend <entity>` | Member of the sponsor group | Suspend the agent. |
| `warden identity sponsor handover <entity>` | Member of the sponsor group | Offer the agent to another group (`-group`, `-group-namespace`), or withdraw the offer (`-cancel`). |
| `warden identity sponsor accept <entity>` | Member of the pending group | Take the agent over; the earlier sponsor is replaced in the same write. |

```bash
warden identity sponsor suspend billing-agent
warden -n team-a identity sponsor handover billing-agent -group finance-oncall -group-namespace /
warden identity sponsor handover billing-agent -cancel
```

A handover by someone who is a member of both groups is accepted at once.

## What sponsors can and cannot do

Members of a sponsor group act with **no Warden role**: they sign in with
[`warden login`](/identity/human-operators/), and the groups of their session
decide which agents they sponsor. Only a person's ticket reaches the sponsor
commands; an agent's credential, a service token and root do not.

Sponsors **can** read their agents, suspend them, hand them over, cancel a
handover, and accept an agent handed to their team.

Sponsors **cannot** make a suspended agent active again, remove their own
sponsorship, change the description or profile, claim or release native
identities, retire or delete the entity, or grant it roles. Those are admin
writes. Stopping an agent should be easy for the people who answer for it;
starting it again goes through an admin.

Every refusal on the sponsor commands is the same `403`:

```text
no sponsored agent by that name
```

whatever the cause — no such entity, not a member, no pending handover, a
retired entity, or a concurrent change. Someone with no role cannot use these
commands to learn which agents exist.

## The `default-sponsor` policy

The sponsor commands are reached through `default-sponsor`, one of the
built-in [policies](/identity/policies/) every namespace holds. It applies to
every request that is not a root request, and grants only the four sponsor
paths, by their exact shape. The commands themselves decide who sponsors what.

```hcl
path "sys/identity/sponsor/+" {
  capabilities = ["read"]
}

path "sys/identity/sponsor/+/suspend" {
  capabilities = ["create", "update"]
}

path "sys/identity/sponsor/+/handover" {
  capabilities = ["create", "update"]
}

path "sys/identity/sponsor/+/accept" {
  capabilities = ["create", "update"]
}
```

The policy can be edited but not deleted. Emptying it turns the sponsor
commands off in that namespace, and leaves the admin commands untouched:

```bash
warden -n team-a policy write default-sponsor - <<EOF
# Sponsors act through admins in this namespace.
EOF
```

## Deleting a sponsor group

Deleting a group that sponsors entities, or that a pending handover names, in
any namespace, is refused with a count. Hand the agents over first. With
`-sponsored`, the delete goes through anyway: the handovers are cancelled, the
entities lose their sponsor, and the response names them.

```bash
warden identity group delete data-platform-leads -sponsored -force
```

Those entities are ungoverned from that moment, so their agents hold no role
on their next request. Find them, and any other agent nobody answers for:

```bash
warden identity entity list -ungoverned
warden identity entity list -sponsor-state pending
warden identity entity list -sponsor billing-team
```

## Audit

A successful sponsor command records the group the person acted through as
`auth.sponsored_by`, such as `group:billing-team`, beside the person's ticket,
the oidc mount that admitted them, and the built-in policies that let the
request through. Admin writes on an entity are audited like any other request.
See [Audit](/concepts/audit/).

## Related

- [Entities](/identity/entities/) — the identity store and governance.
- [Groups](/identity/groups/) — virtual groups of people, static groups of agents.
- [Human operators](/identity/human-operators/) — `warden login` and tickets.
- [Built-in roles](/identity/built-in-roles/) — operator roles for the admin side.
