---
title: "Groups"
---

A **group** is how a caller comes to hold a [role](/identity/roles/): a caller
holds a role only when a group grants it. On every request, once the caller is
authenticated, Warden resolves which groups it belongs to and which roles they
grant. A request under a role no group grants is refused.

A group lives in a namespace at `sys/identity/group/<name>`. It names the roles
its membership grants, and its **type** says where that membership comes from:

| | Virtual group | Static group |
|---|---|---|
| **Members** | none listed: a caller is a member when its verified facts match one of the group's rules | listed by name: [entities](/identity/entities/) of the same namespace |
| **Who it applies to** | unclaimed callers: agents no entity claims, and humans | callers whose native identity an entity claims, while that entity is governed and active |
| **How membership ends** | the credential stops matching, the rule changes, or `valid_until` passes | the member is removed, its `until` passes, the entity stops being governed or active, or `valid_until` passes |
| **Can list its members** | no | yes |
| **Grants a `governed_only` role** | never | yes |

The type is required when the group is created and never changes. Every later
write names it again, and a write naming the wrong type is refused.

The groups a caller belongs to on a request are recorded in the audit log
(`groups`, with `role_granted_by` and `role_group_type` for the grant) and are
available to [CEL conditions](/concepts/cel-conditions/) as `agent.groups`, so
a policy can say `'ci-deployers' in agent.groups`.

## Virtual groups

A virtual group matches what an auth mount verified about the caller's
credential. A new agent with no entity presents its credential, the auth method
verifies it, and the facts it verified are matched against the namespace's
virtual groups. The roles of every group that matches are the roles the caller
may assume on that request.

<p align="center"><img alt="A new agent with no entity asks for the role sandbox. Authenticate: the jwt auth mount verifies its identity and records facts. Resolve: virtual groups, which have no members, match those facts and resolve the roles sandbox and llm-basic. Authorize: sandbox is among them, so the request is authorized." src="/images/warden-agent-virtual-group.png" width="860"></p>

The figure labels virtual groups a *low-privilege ceiling*. That is advice, not
something Warden enforces: a virtual group may grant any role that is not
[`governed_only`](/identity/roles/#governed-only-roles). For agents, keep it
small: nobody reviews the agents a rule matches one at a time, so a broader
grant belongs on a static group that lists a registered, sponsored agent. For
people, virtual groups are the normal way to grant roles, operator roles
included — who belongs to which IdP group is reviewed in the identity
provider.

### Rules and selectors

A virtual group has 1 to 16 **rules**. A caller is a member when **any one**
rule matches. A rule is a set of **selectors**, each a fact name with the values
it may take, and it matches when **every** selector finds one of its values:
AND across selectors, any-of within one.

| Part | Meaning |
|---|---|
| `mount` | Required in every rule: the auth mounts the rule trusts, by path (`auth/github-oidc/`). A fact verified by any other mount never matches. |
| `kind` | Answered by every admission: `agent` or `human`, from the auth mount. |
| any other name | A fact the listed mounts verify: built in, or mapped in the mount's `facts`. See [Authentication](/identity/authentication/). |

Values are exact strings unless they hold an unescaped `*` or `?`:

| Pattern | Matches |
|---|---|
| `*` | any run of characters except `/`, possibly empty |
| `**` | any run of characters, `/` included |
| `?` | exactly one character except `/` |
| `\*`, `\?`, `\\` | the character itself |

So `acme/*` matches `acme/api` but not `acme/api/v2`, and `auth/*/` matches every
auth mount one level deep. A `mount` value holding `**` trusts every auth mount
it reaches, including ones enabled later; it is accepted with a warning.

This group, from the CLI help, admits two kinds of CI caller: GitHub Actions
runs on `main` of any `acme` repository, and the `deployer` workload on the
`ci` cluster, through either Kubernetes or SPIFFE:

```bash
warden identity group create ci-deployers -json '{
  "type": "virtual",
  "description": "CI deployers from GitHub and the ci cluster",
  "roles": ["deploy", "read-secrets"],
  "rules": [
    {
      "mount": ["auth/github-oidc/"],
      "repo": ["acme/*"],
      "ref": ["refs/heads/main"]
    },
    {
      "mount": ["auth/kubernetes/", "auth/spiffe/"],
      "workload": [
        "system:serviceaccount:ci:deployer",
        "spiffe://corp.example/ns/ci/sa/deployer"
      ]
    }
  ],
  "valid_until": "2026-12-31T23:59:59Z",
  "metadata": {
    "owner": "platform"
  }
}'
```

The write is checked against the namespace's auth mounts. A `mount` that names no
mount, a fact none of the rule's mounts produces, a `kind` value that is neither
`agent` nor `human`, and a role that does not exist yet are each accepted with a
warning on stderr: the group starts matching once the mount, the fact mapping or
the role exists.

### valid_until

`valid_until` (RFC 3339) ends the group. It grants through that instant and
nothing after, on the first request past it, even for a caller whose admission
Warden still holds. Another group may still grant the same role. A time in the
past is accepted with a warning: the group grants nothing.

How old a caller's credential may be is not the group's to say. That is a bound
of the auth mount.

## Static groups

A static group lists its members: entities of its namespace, by name, each
optionally with an `until` (RFC 3339) after which its membership ends. A known
agent, one whose native identity an entity claims, authenticates the same way,
but its roles come from the static groups that list its entity.

<p align="center"><img alt="A registered agent asks for the role deployer. Authenticate: the jwt auth mount verifies its identity. Resolve: its entity, Entity A, is listed by static groups that resolve the roles deployer and secret-reader. Authorize: deployer is among them, so the request is authorized." src="/images/warden-agent-static-group.png" width="860"></p>

```bash
warden identity group create local-ops -json '{
  "type": "static",
  "description": "Operations agents governed by Warden",
  "members": [
    "billing-agent",
    { "name": "release-bot", "until": "2026-10-26T18:00:00Z" }
  ],
  "roles": ["ops", "deploy"]
}'
```

A static group has no rules, and a virtual group lists no members: either is
refused. Members are stored by entity ID and shown by the entity's current name,
so renaming an entity keeps its memberships, and an entity deleted and created
again under the same name is not taken for the old one.

### Changing members

`member add` and `member remove` change one member and keep the rest. Each reads
the group, edits its list, and writes it back only if nobody changed the group in
between, trying once more if someone did.

```bash
warden identity group member add local-ops invoice-agent
warden identity group member add local-ops release-bot -for 72h
warden identity group member add local-ops release-bot -until 2026-12-31T23:59:59Z
warden identity group member remove local-ops release-bot
```

`-for` (a duration from now) and `-until` (an instant) end the membership: it
grants through that instant and nothing after. Adding a member already listed
replaces its `until`; adding it again with neither flag makes it permanent. A
removed member loses the group's roles on its next request.

A member past its `until` grants nothing, but is listed as expired until a write
of the group drops it. `prune` is that write:

```bash
warden identity group prune local-ops
```

To find the static groups that list an entity:

```bash
warden identity group list -member billing-agent
```

## The claim rule

Once an entity claims a caller's native identity, that caller is a known agent,
and only its entity's static groups apply to it:

- It holds only the roles its entity's static groups grant.
- It holds them only while the entity is **governed** (it has an accepted
  [sponsor](/identity/sponsors/) and a description) and **active** (not
  suspended or retired).
- Virtual groups never apply to it, whatever its facts match, in any state.

A claimed agent whose entity is not governed holds no role at all. Claiming a
native identity therefore takes away every role virtual groups gave it, on its
next request; the claim warns that this will happen. Give the entity a static
group before you claim, or the agent stops working.

Humans are never claimed, so virtual groups always apply to them. See
[Human operators](/identity/human-operators/).

## A baseline group

A common shape is a floor: a low-privilege role every agent from your auth
mounts may assume, so a new agent can discover what it may do and do the
harmless part of its job before anyone has reviewed it.

```bash
warden identity group create baseline -json '{
  "type": "virtual",
  "description": "Every agent admitted through our auth mounts",
  "roles": ["sandbox"],
  "rules": [
    {
      "mount": ["auth/jwt/", "auth/kubernetes/"],
      "kind": ["agent"]
    }
  ]
}'
```

A rule may carry only `mount` and `kind`: every caller those mounts admit as an
agent matches. Keep three things in mind:

- **Make the role small.** Every agent of those mounts holds it. The policy
  behind `sandbox` is the whole of what an unreviewed agent can do.
- **Claimed agents do not get it.** The claim rule takes virtual groups away from
  them. If known agents need the floor too, list `sandbox` in a static group
  they belong to.
- **Name mounts, not `**`.** A `mount` pattern with `**` trusts mounts enabled
  later, by anyone who can enable one.

## Reading, updating and deleting

```bash
warden identity group list
warden identity group list -role deploy
warden identity group list -type virtual
warden identity group read ci-deployers
warden identity group read ci-deployers -o json
```

`read` shows a group's rules one line each (`#i  mount=…  name=v1|v2`), its rule
and selector counts, and the `hash` a conditional write passes back.

An update replaces each field you pass, including with an empty value
(`"roles": []` stops the group granting anything), and keeps each field you
leave out. `rules` is replaced whole. Pass `expected_hash` to apply it only if
nobody changed the group since you read it; otherwise the server answers 409.

```bash
warden identity group update ci-deployers -json '{
  "type": "virtual",
  "rules": [
    {
      "mount": ["auth/github-oidc/"],
      "repo": ["acme/infra"],
      "ref": ["refs/heads/main"]
    }
  ],
  "expected_hash": "<hash from warden identity group read>"
}'
```

Deleting a group takes its roles from its members on their next request, unless
another group grants them too. A group that sponsors entities is refused until
they are handed over; `-sponsored` deletes it anyway and leaves those entities
ungoverned.

```bash
warden identity group delete ci-deployers -type virtual -force
```

Every change applies on the caller's next request. Nothing about membership is
held on a token.

### Separating who edits which type

Group writes need `sudo` on `sys/identity/group`. Because every write names the
type, one condition limits a holder to virtual groups, leaving static groups to
whoever governs entities:

```hcl
path "sys/identity/group/*" {
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
  condition    = "has(request.data.type) && request.data.type == 'virtual'"
}
```

The condition gates reads too, and an unconditional stanza on the same path
lifts it, so give the holder no other stanza there. Such a holder passes
`-type virtual` to `read`, `list`, `update` and `delete`. See
[Policies](/concepts/policies/).

## Caps

Groups are matched on the request path, so their size is bounded. A write past a
cap is refused with the current usage.

| Bound | Cap |
|---|---|
| Roles a group grants | 64 |
| Rules in a virtual group | 16 |
| Selectors in a rule | 32 |
| Values in a selector | 32 |
| Fact name | 64 bytes |
| Selector value | 1024 bytes |
| Description | 1024 bytes |
| Virtual groups in a namespace | 8000 |
| Selectors across a namespace's virtual groups (`mount` included) | 16000 |
| Static groups in a namespace | 8000 |
| Members in one static group (expired ones included until a write drops them) | 1000 |
| Memberships across a namespace's static groups | 250000 |

The membership cap is counted net of what a write replaces, so a write that adds
no member is never refused. `warden identity usage` shows how much of each cap
the namespace uses. It needs `read` on `sys/identity/usage`, no `sudo`:

```bash
warden identity usage
warden identity usage -o json | jq .groups.virtual
```

```text
GROUPS
  TYPE      COUNT          SELECTORS          MEMBERS
  virtual   <count>/<max>  <selectors>/<max>  -
  static    <count>/<max>  -                  <members>/<max> (at most <max> a group)
  total     <count>
```

## What changed

If you are upgrading from v0.21, see
[Upgrading from v0.21](/upgrade/from-v0-21/) for how roles are granted now.
