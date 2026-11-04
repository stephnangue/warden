---
title: "Entities"
---

An **entity** is a registered agent: a record that says what the agent is, who
answers for it, whether it may run, and which native identities belong to it. Entities are
optional. An agent nobody registered is still admitted and still gets its roles
from [virtual groups](/identity/groups/). Registering agents is how you make
sure that each one has a description and a team behind it, can be stopped in
one place, and, if you choose, that no other agent runs.

## The identity store

Each namespace keeps its entities in its **identity store**: the inventory of
the agents registered there. It is what other products call an agent registry.
It is not a discovery catalog: it lists no endpoints or capabilities (agents
find those through [discovery](/concepts/discovery-and-skills/)). Entities are
created and changed in Warden, through the commands on this page.

To see what the store holds:

```bash
warden identity entity list                 # every entity in the namespace
warden identity entity list -ungoverned     # entities nobody answers for yet
# which entity claims this native identity
warden identity entity lookup -mount=auth/spiffe/ -name=spiffe://actor/billing-team/agent-1
```

Agents that are not registered are not in the store. They show up in the
[audit log](/concepts/audit/): their entries carry an `alias_name` and no
`entity_id` (see [Rolling out](#rolling-out)).

<p align="center"><img alt="The governance model of one agent: the entity billing-agent, with its name, description, ID, state active, sponsor billing-team and creation time, sits in the middle; above it, the Sponsoring Group billing-team, made of people; beside it, the Entitlements Group billing-operators, which grants the roles invoice-reader and invoice-matcher and, through them, their policies; below it, the one runtime principal it claims, the agent workload's SPIFFE ID spiffe://actor/billing-team/agent-1." src="/images/warden-agent-governance-model.png" width="860"></p>

In Warden's terms:

- the **Sponsoring Group** is the entity's [sponsor](/identity/sponsors/): a
  virtual group of people who answer for the agent;
- the **Entitlements Group** is a [static group](/identity/groups/) that lists
  the entity and grants it [roles](/identity/roles/);
- the **Runtime principal** is the entity's **native identity**: what the
  agent's credential proves, here its SPIFFE ID.

## Native identities

Every credential an [auth mount](/identity/authentication/) admits carries one
**native identity**: the verified value that names the caller. Each mount picks
it with `alias_name_source` — for example the `sub` claim of a JWT, the `cn` or
a SAN of a certificate, a Kubernetes service account's username, or a SPIFFE
ID. In Warden's commands and fields a native identity is an **alias**; it is
always named together with its mount, as `(mount, name)`.

A credential whose chosen value is missing or unusable carries no native
identity. It is still admitted, but no entity can claim it.

**Register one entity per deployment, claiming one native identity.** Whatever
an entity's static groups grant applies to every native identity it claims, so
an entity that claims an on-premises SPIFFE ID and a cloud service account at
once gives each credential the other's access: the weaker trust anchor gates
both, and you can neither scope nor suspend one without the other. Replicas of
one deployment need nothing more, since they present the same native identity.
An agent that runs in two places is two entities — they can share a sponsor —
each in the static groups its own deployment needs.

An entity can claim several native identities (at most 32). Use that for a
migration: when an agent moves to a new auth mount, its entity claims the new
identity, and you remove the old one with `alias remove` once the cutover is
done.

## What an entity holds

| Field | Meaning |
|---|---|
| `name` | Unique in the namespace. Renamed with `new_name`; the ID stays. |
| `id` | Set at creation, never changes. `entity read -id` reads by it. |
| `kind` | `agent`, the only kind so far. Fixed at creation. |
| `description` | What the agent does, up to 1024 bytes. Needed to be governed. |
| `profile` | Descriptive: `purpose`, `runtime`, `publisher`. Nothing is enforced on it. |
| `metadata` | Free-form string labels. |
| `state` | `active`, `suspended` or `retired`. See [Lifecycle](#lifecycle). |
| `sponsor` | The group that answers for the entity, once a member accepted it. See [Sponsors](/identity/sponsors/). |
| `pending_sponsor` | A handover to another group that no member has accepted yet. |
| `governed_by` | Derived, never written: `warden` when governed, empty otherwise. |
| `ungoverned_reason` | What an ungoverned entity lacks, such as `no sponsor and no description`. |
| `aliases` | The native identities it claims, each a `mount` and a `name`. At most 32. |
| `groups`, `roles` | On reads: the static groups that list it, and the roles they grant. |
| `created_at`, `updated_at` | Timestamps. |
| `hash` | The entity's content hash. Pass it back as `expected_hash` (`-expected-hash`) to apply a write only if nobody changed the entity since you read it. |

An entity is **governed** when it has an accepted sponsor and a non-empty
description. A pending handover does not count. Governance is what lets a
registered agent hold roles at all, so an entity that loses its sponsor or its
description stops working on its next request. A namespace holds at most
50,000 entities; `warden identity usage` shows the count against the cap.

## Registering an agent

Create the entity with a description, the native identities it claims, and
any profile or metadata:

```bash
warden identity entity create billing-agent -json '{
  "description": "Reconciles supplier invoices against purchase orders",
  "profile": {
    "purpose": "billing",
    "runtime": "langgraph",
    "publisher": "corp-finance-eng"
  },
  "metadata": {
    "team": "billing"
  },
  "aliases": [
    { "mount": "auth/spiffe/", "name": "spiffe://actor/billing-team/agent-1" }
  ]
}'
```

An entity is always created `active` and without a sponsor. Propose one next;
a member of the group accepts it, or the proposal is accepted at once when you
are a member yourself ([Sponsors](/identity/sponsors/) explains the flow):

```bash
warden identity entity sponsor propose billing-agent -json '{
  "group": "billing-team",
  "namespace": "/"
}'
```

Then list the entity in a static group that grants its roles:

```bash
warden identity group create billing-operators -json '{
  "type": "static",
  "description": "Billing agents governed by Warden",
  "members": ["billing-agent"],
  "roles": ["invoice-reader", "invoice-matcher"]
}'
```

### What a claim changes

Claiming a native identity changes where that caller's roles come from, at
once and in every mode:

- **Virtual groups no longer apply** to a claimed caller, whatever its state.
- It holds only the roles its entity's **static groups** grant, and only while
  the entity is **governed and active**. Until then it holds no role, and its
  requests are refused with a message saying the entity is not governed.

Every new claim warns about this. To move an agent over without a gap, create
its entity **without** `aliases`, give it a sponsor and a static group, and
claim its native identities last with `warden identity alias add`.

A role marked `governed_only` goes further: only a static group can grant it,
so only a governed agent ever holds it. See [Roles](/identity/roles/).

## Claiming, moving and releasing native identities

A native identity belongs to at most one entity per namespace. Claims are
managed with `warden identity alias`:

```bash
# Claim: refused if another entity holds it (unless that entity is retired)
warden identity alias add -json '{
  "mount": "auth/jwt/",
  "name": "repo:corp/billing-agent:ref:refs/heads/main",
  "to": "billing-agent"
}'

# Move: take it from whichever entity holds it; the output names that entity
warden identity alias move -mount=auth/jwt/ -name=repo:corp/x -to=invoice-agent

# Release: the native identity is unclaimed again
warden identity alias remove -mount=auth/jwt/ -name=repo:corp/x -from=invoice-agent
```

- A mount that admits people (one whose `entity_kind` is `human`, such as the
  [oidc](/identity/human-operators/) mount) cannot be claimed: people are never
  entities.
- While any of a mount's native identities are claimed, changing how the mount
  derives them (`alias_name_source`, `entity_kind`, or the facts behind them)
  and disabling the mount are refused unless forced. A forced disable leaves
  the claims behind; `warden identity entity list -orphaned` lists them, and
  `alias remove -mount-accessor` releases them.

## Lifecycle

| State | Effect |
|---|---|
| `active` | In service. |
| `suspended` | Refused on every request, in every mode, through every mount. Reversible. |
| `retired` | Refused like suspended, and final. The record becomes read-only and keeps its native identities claimed, so no other entity takes them unnoticed; they can still be moved to another entity. |

```bash
warden identity entity state billing-agent suspended
warden identity entity state billing-agent active
warden identity entity state old-batch-agent retired
```

Suspension is the kill switch: it takes effect on the agent's next request,
with no token to revoke. Members of the entity's sponsor group can suspend it
themselves, with no Warden role; making it active again is an admin's write.

Deleting an entity releases its native identities: its agent is unclaimed
again, so under `observe` virtual groups apply to it once more. To stop an
agent, suspend or retire it instead. A retired entity is deleted only with
`-retired`:

```bash
warden identity entity delete ci-runner -force
warden identity entity delete old-batch-agent -retired -force
```

## Requiring registration

How a namespace treats a caller by its native identity is set in its
**identity config**, before any role is considered:

- `unknown_aliases`: `observe` (the default) admits callers no entity claims,
  as before. `deny` refuses them, and also refuses claimed callers whose
  entity is not governed.
- `exempt_mounts`: auth mounts `deny` never applies to, such as a CI mount
  whose callers are anonymous by design. Given by path.

```bash
warden identity config read
warden identity config write -json '{
  "unknown_aliases": "deny",
  "exempt_mounts": ["auth/github-oidc/"]
}'
warden identity config reset
```

What each caller gets:

| Caller | `observe` | `deny` (mount not exempt) |
|---|---|---|
| Unclaimed, or presents no native identity | Admitted; virtual groups apply | Refused |
| Claimed, entity not governed | Admitted, but holds no role | Refused |
| Claimed, governed and active | Its static groups' roles | Its static groups' roles |
| Claimed, entity suspended or retired | Refused | Refused |

People signed in with `warden login` are never judged by their native
identity, and neither are tokens no auth mount issued, such as root. A
refusal names what the caller presented, and nothing more:

```text
native identity (auth/jwt/, repo:corp/scratch:ref:refs/heads/test) is unclaimed; unknown_aliases=deny
native identity (auth/jwt/, agent-1) belongs to entity "billing-agent", which is suspended
native identity (auth/jwt/, agent-1) belongs to entity "billing-agent", which is not governed; it holds no role until it is
```

Two safeguards keep an operator from locking themselves out:

- A config that would refuse the writer's own requests is refused unless you
  pass `-force`. The same guard applies to writes an agent makes to its own
  entity or its own native identity.
- Root is never judged, so it is always the way back. A stored config that
  cannot be read runs as `deny` with nothing exempt, and `config read` warns,
  until a write or a reset replaces it.

## Rolling out

1. **Observe.** Leave `unknown_aliases` at `observe`. Every agent request
   records `auth.identity_status` in the audit log: the reason `deny` would
   refuse it (`unclaimed`, `no native identity`, `entity not governed`,
   `entity suspended`, `entity retired`), or nothing when its identity is
   accounted for.
2. **Find the unregistered callers.** They are the entries with an
   `alias_name` and no `entity_id`. With a file audit device:

   ```bash
   jq -r 'select(.auth.identity_status == "unclaimed")
          | [.auth.mount_accessor, .auth.alias_name] | @tsv' \
     /var/log/warden/audit.log | sort -u
   ```

   A `no native identity` status means the mount's `alias_name_source` names
   a value those credentials do not carry: fix the mount, or exempt it.
   (If your audit device salts or omits `alias_name`, read it from a device
   that does not.)
3. **Register them**: an entity per agent, claiming its native identities,
   with a static group for its roles (see [What a claim changes](#what-a-claim-changes)).
4. **Sponsor them**, and close the gaps that
   `warden identity entity list -ungoverned` shows.
5. **Deny.** Once `identity_status` is empty for the callers you expect,
   write `"unknown_aliases": "deny"`, with the mounts that stay anonymous in
   `exempt_mounts`.

## In policies and audit

A [CEL condition](/concepts/cel-conditions/) reads the caller's native identity
as `agent.alias`, and its entity, when one claims it, as `agent.entity`, with
`id`, `name`, `kind`, `state`, `governed_by`, `metadata` and `profile`. Guard
with `has()`; an unguarded read on an unclaimed caller fails closed:

```hcl
path "aws/role/+/gateway/*" {
  capabilities = ["create", "read", "update", "delete"]
  condition    = "has(agent.entity) && agent.entity.metadata.team == 'billing'"
}
```

The [audit log](/concepts/audit/) records, under `auth`, the admitting mount
(`mount_accessor`), the native identity (`alias_name`), the entity that claims
it (`entity_id`, `entity_name`, `governed_by`), `identity_status`, and
`role_group_type` (`virtual` or `static`) for the group that granted the role.
