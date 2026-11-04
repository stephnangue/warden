---
title: "identity"
---

Manage the identity objects of the current namespace: the
[groups](/identity/groups/) that grant roles, the [entities](/identity/entities/)
in the identity store and the native identities they claim, their
[sponsors](/identity/sponsors/), and the identity config that decides how the
namespace treats a caller by its native identity.

## Usage

```text
warden identity <subcommand> [options]
```

Global flags apply to every subcommand — see the [CLI overview](/cli/#global-flags).
Every command acts in the current namespace; set another with `-n`.

## Subcommands

| Subcommand | Description |
|---|---|
| [`group`](#identity-group) | Manage the groups that grant roles. |
| [`entity`](#identity-entity) | Manage the entities of the identity store, and propose or remove their sponsor. |
| [`alias`](#identity-alias) | Claim, move and release native identities. |
| [`sponsor`](#identity-sponsor) | Act on the entities your team sponsors. No role needed. |
| [`config`](#identity-config) | Read or write the namespace's identity config. |
| [`usage`](#identity-usage) | Show how much of its caps the namespace's identity objects use. |

A native identity is the verified value that names a caller on an auth mount.
Commands and fields call it an **alias**, always named with its mount, as
`mount` and `name`.

### Permissions

| Commands | Needs |
|---|---|
| `group …` | sudo on `sys/identity/group` |
| `entity …`, `alias …` | sudo on `sys/identity/entity` |
| `entity lookup` | sudo on `sys/identity/lookup` |
| `config …` | sudo on `sys/identity/config` |
| `usage` | read on `sys/identity/usage` (no sudo) |
| `sponsor …` | no role: a [`warden login`](/cli/login/) session whose groups make you a member of the sponsor group |

### Input forms

Commands that take a payload accept it two ways, which are mutually exclusive:

- **`-json` (`-j`)**: the full payload, as inline JSON (`'<json>'`), a file
  (`@file.json`), or stdin (`-`).
- **Typed flags**: one flag per field, listed with each command.

Commands that write accept the global `-dry-run`, which validates the payload
locally and sends nothing.

Several writes take `-expected-hash`: pass the `hash` from a read, and the write
applies only if nobody changed the object since. Otherwise the server answers
`409` and you read again.

## `identity group`

Manage the groups of the current namespace. A group lists the roles its
membership grants. Its type says where membership comes from and never
changes: a **virtual** group's members are the unclaimed callers whose
verified facts match one of its rules; a **static** group lists its members,
entities of this namespace. See [Groups](/identity/groups/).

| Subcommand | Description |
|---|---|
| `create <name>` | Create a group. |
| `read <name>` | Read a group. |
| `update <name>` | Update a group. |
| `delete <name>` | Delete a group. |
| `list` | List the groups. |
| `member add <group> <entity>` | Add an entity to a static group, or change its `until`. |
| `member remove <group> <entity>` | Remove an entity from a static group. |
| `prune <group>` | Drop a static group's expired members. |

### `group create`

Create a group. `type` is required: `virtual` or `static`. Every rule of a
virtual group must include a `mount` selector, the auth mounts it trusts. A
role that does not exist yet, a fact none of the listed mounts produces, or a
`mount` value holding `**` is accepted with a warning on stderr. A write past
the namespace's caps is refused with the current usage.

**Usage:** `warden identity group create <name> [options]`

**Flags:**

| Flag | Default | Description |
|---|---|---|
| `-type` | *(none)* | `virtual` or `static`. Required. Never changes. |
| `-description` | *(none)* | What the group is for. |
| `-roles` | *(none)* | Roles membership grants. Repeat or comma-separate. |
| `-rule` | *(none)* | One rule as a JSON object of selectors, each a fact name with its values (a list, or one string), including `mount`. Repeatable; any one rule matching makes a member. Virtual groups. |
| `-member` | *(none)* | An entity the group lists, by name, or `'{"name": "release-bot", "until": "2026-12-31T23:59:59Z"}'` for a membership that ends. Repeatable. Static groups. |
| `-valid-until` | *(none)* | RFC 3339 instant after which the group grants nothing. A time in the past is accepted with a warning. |
| `-metadata` | *(none)* | Free-form label, `key=value`. Repeatable. |
| `-json`, `-j` | *(none)* | Full JSON payload: `'<json>'`, `@file.json`, or `-` for stdin. |

**Examples:**

```bash
# A virtual group: callers matching any one rule
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

# A static group: the entities it lists
warden identity group create local-ops -json '{
  "type": "static",
  "description": "Operations agents governed by Warden",
  "members": [
    "billing-agent",
    { "name": "release-bot", "until": "2026-10-26T18:00:00Z" }
  ],
  "roles": ["ops", "deploy"]
}'

# From a file, or from stdin
warden identity group create ci-deployers -json @ci-deployers.json
cat ci-deployers.json | warden identity group create ci-deployers -json -

# Typed flags
warden identity group create ci-deployers \
  -type=virtual \
  -roles=deploy \
  -rule='{"mount": ["auth/kubernetes/"], "service_account_namespace": ["ci"]}' \
  -valid-until=2026-12-31T23:59:59Z

warden identity group create local-ops \
  -type=static \
  -roles=ops,deploy \
  -member=billing-agent \
  -member='{"name": "release-bot", "until": "2026-10-26T18:00:00Z"}'
```

### `group read`

Read one group: its type, the roles it grants, its rules (one line each,
`#i  mount=…  name=v1|v2`), its members, its rule and selector counts,
`valid_until`, metadata, and the `hash` a conditional update or delete passes
back.

**Usage:** `warden identity group read <name> [-type <type>]`

| Flag | Default | Description |
|---|---|---|
| `-type` | *(none)* | The group's type. Refused if it is not the stored type. Pass it when your policy only lets you read groups of one type. |

```bash
warden identity group read ci-deployers
warden identity group read ci-deployers -type virtual
warden identity group read ci-deployers -o json
warden identity group read ci-deployers -fields hash
```

### `group update`

Update a group. A field you pass replaces the stored value, including with an
empty one (`"roles": []` stops the group granting anything); a field you leave
out keeps its value. `rules` and `members` are replaced whole. The change
applies to callers on their next request.

The server requires the group's type on every write. Without `type` (or
`-type`) the command reads the group to learn it; pass it when your policy only
lets you write and read groups of one type.

**Usage:** `warden identity group update <name> [options]`

**Flags:** the typed flags of [`group create`](#group-create), plus:

| Flag | Default | Description |
|---|---|---|
| `-type` | *(read from the server)* | Must equal the stored type. |
| `-expected-hash` | *(none)* | Apply the update only if the group still has this hash. With `-json`, pass `expected_hash` in the payload instead. |
| `-json`, `-j` | *(none)* | Full JSON payload: `'<json>'`, `@file.json`, or `-` for stdin. |

On update, `-roles=""` and `-valid-until=""` clear the field.

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

warden identity group update ci-deployers -json @patch.json
warden identity group update ci-deployers -roles=deploy,read-secrets
warden identity group update ci-deployers -roles=""
warden identity group update ci-deployers -valid-until=2026-12-31T23:59:59Z
warden identity group update ci-deployers -valid-until=""
warden identity group update ci-deployers \
  -rule='{"mount": ["auth/kubernetes/"], "workload": ["ci"]}'
```

### `group delete`

Delete a group. Its members lose the roles it granted on their next request,
unless another group grants them too. On a terminal the command asks for
confirmation unless you pass `-force`; in scripts it does not ask.

A group that sponsors entities, or that a pending handover names, in any
namespace, is refused with a count of them. `-sponsored` deletes it anyway:
the handovers are cancelled and the entities lose their sponsor, so they are
ungoverned.

**Usage:** `warden identity group delete <name> [options]`

| Flag | Default | Description |
|---|---|---|
| `-force`, `-f` | `false` | Skip the confirmation prompt. |
| `-sponsored` | `false` | Delete a group that sponsors entities. |
| `-expected-hash` | *(none)* | Delete only if the group still has this hash. |
| `-type` | *(read from the server)* | The group's type. Pass it when your policy only lets you write and read groups of one type. |

```bash
warden identity group delete ci-deployers
warden identity group delete ci-deployers -type virtual -force
warden identity group delete data-platform-leads -sponsored -force
warden identity group delete ci-deployers -force \
  -expected-hash "$(warden identity group read ci-deployers -o json | jq -r .hash)"
```

### `group list`

List the groups of the current namespace, optionally filtered.

**Usage:** `warden identity group list [options]`

| Flag | Default | Description |
|---|---|---|
| `-role` | *(none)* | Only the groups that grant this role. |
| `-type` | *(none)* | Only the groups of this type. Needed when your policy only lets you see groups of one type. |
| `-member` | *(none)* | Only the static groups that list this entity. |

With `-o json`, each item carries `name`, `type`, `description`, `roles`,
`rules`, `members`, `rule_count`, `selector_count`, `valid_until`, `metadata`
and `hash`; `-o ndjson` prints one group per line.

```bash
warden identity group list
warden identity group list -role deploy
warden identity group list -type virtual
warden identity group list -member billing-agent
warden identity group list -o ndjson | jq -r .name
```

### `group member add`

Add an entity of this namespace to a static group, keeping the other members.
Its membership counts only while the entity is governed and active. `-until` or
`-for` ends it: it grants through that instant and nothing after. Adding a
member already listed replaces its `until`; adding it again with neither flag
makes it permanent.

The command reads the group, changes its member list, and writes it back only
if nobody changed the group in between, trying once more if someone did. A
group that is not static is refused.

**Usage:** `warden identity group member add <group> <entity> [-until <RFC 3339> | -for <duration>]`

| Flag | Default | Description |
|---|---|---|
| `-until` | *(none)* | RFC 3339 instant after which the membership ends. Must be in the future. |
| `-for` | `0` | How long the membership lasts from now, such as `72h`. Mutually exclusive with `-until`. |

```bash
warden identity group member add local-ops invoice-agent
warden identity group member add local-ops release-bot -for 72h
warden identity group member add local-ops release-bot -until 2026-12-31T23:59:59Z
```

### `group member remove`

Remove an entity from a static group, keeping the other members. It loses the
roles the group grants on its next request. An entity the group does not list
is reported as not found.

**Usage:** `warden identity group member remove <group> <entity>`

```bash
warden identity group member remove local-ops release-bot
```

### `group prune`

Drop the members of a static group whose `until` has passed. Any write of the
group drops them too. An expired member already grants nothing, and is listed
as expired until a write drops it. The warning names the members dropped.

**Usage:** `warden identity group prune <group>`

```bash
warden identity group prune local-ops
```

## `identity entity`

Manage the entities of the current namespace. An entity records what an agent
does (`description`, `profile`), the team that answers for it (its sponsor),
its lifecycle state (`active`, `suspended`, `retired`), and the native
identities it claims. `governed_by` is derived: `warden` once the entity has an
accepted sponsor and a description. See [Entities](/identity/entities/).

| Subcommand | Description |
|---|---|
| `create <name>` | Create an entity. |
| `read [<name>]` | Read an entity, by name or `-id`. |
| `update <name>` | Update an entity's description, profile, metadata or name. |
| `delete <name>` | Delete an entity. |
| `list` | List the entities. |
| `lookup` | Look up the entity that claims a native identity. |
| `state <entity> <active\|suspended\|retired>` | Change an entity's lifecycle state. |
| `sponsor propose <entity>` | Propose a group as the entity's sponsor. |
| `sponsor remove <entity>` | Remove the sponsor, or cancel the pending handover. |

### `entity create`

Create an entity. It is created `active` and without a sponsor: propose one
afterwards with [`entity sponsor propose`](#entity-sponsor-propose). `aliases`
claims native identities, each by its mount's path and its name as the mount
derives it (`alias_name_source`). A native identity another entity claims is
refused (use [`alias move`](#alias-move)), and a mount that admits humans cannot
be claimed.

**Usage:** `warden identity entity create <name> [options]`

| Flag | Default | Description |
|---|---|---|
| `-kind` | `agent` | Kind of entity. `agent` is the only kind yet. Never changes. |
| `-description` | *(none)* | What the agent does. With a sponsor, it makes the entity governed. |
| `-profile` | *(none)* | Descriptive data: `purpose=…`, `runtime=…`, `publisher=…`. Repeatable. |
| `-metadata` | *(none)* | Free-form label, `key=value`. Repeatable. |
| `-alias` | *(none)* | A native identity the entity claims, as `<mount>=<name>`. Repeatable. |
| `-json`, `-j` | *(none)* | Full JSON payload: `'<json>'`, `@file.json`, or `-` for stdin. |

```bash
warden identity entity create billing-agent -json '{
  "kind": "agent",
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
    { "mount": "auth/kubernetes/", "name": "system:serviceaccount:billing:agent" }
  ]
}'

warden identity entity create billing-agent -json @billing-agent.json

warden identity entity create billing-agent \
  -description="Reconciles supplier invoices" \
  -profile=runtime=langgraph \
  -alias=auth/kubernetes/=system:serviceaccount:billing:agent
```

### `entity read`

Read one entity, by name or by ID (which never changes): its kind and state,
`governed_by` (or why it is ungoverned), its sponsor and any pending handover,
profile, metadata, the native identities it claims (one line each,
`<mount>  <name>`; a mount disabled since shows by accessor), and the `hash` a
conditional write passes back.

**Usage:** `warden identity entity read <name>` or `warden identity entity read -id <id>`

| Flag | Default | Description |
|---|---|---|
| `-id` | *(none)* | Read the entity with this ID instead of by name. Not with a name. |

```bash
warden identity entity read billing-agent
warden identity entity read -id 6f1c0d2e-…
warden identity entity read billing-agent -o json
warden identity entity read billing-agent -fields hash
```

### `entity update`

Update an entity's description, profile and metadata. A field you pass
replaces the stored value, including with an empty one (an empty description
leaves the entity ungoverned); a field you leave out keeps its value.
`new_name` renames it; its ID does not change. The native identities change
through [`alias`](#identity-alias), the sponsor through
[`entity sponsor`](#entity-sponsor-propose), and the state through
[`entity state`](#entity-state).

**Usage:** `warden identity entity update <name> [options]`

| Flag | Default | Description |
|---|---|---|
| `-description` | *(none)* | What the agent does. |
| `-profile` | *(none)* | Descriptive data, `key=value`. Repeatable. |
| `-metadata` | *(none)* | Free-form label, `key=value`. Repeatable. |
| `-new-name` | *(none)* | Rename the entity. Its ID does not change. |
| `-expected-hash` | *(none)* | Apply the update only if the entity still has this hash. With `-json`, pass `expected_hash` in the payload instead. |
| `-json`, `-j` | *(none)* | Full JSON payload: `'<json>'`, `@file.json`, or `-` for stdin. |

```bash
warden identity entity update ci-runner -json '{
  "description": "Builds and deploys the billing service",
  "metadata": {
    "team": "billing"
  }
}'

warden identity entity update billing-agent -description="Reconciles supplier invoices"
warden identity entity update billing-agent -new-name=invoice-agent
```

### `entity delete`

Delete an entity. The native identities it claims are released: they are
unclaimed again. On a terminal the command asks for confirmation unless you
pass `-force`; in scripts it does not ask.

A retired entity keeps its native identities claimed, so that no other entity
takes them unnoticed. Deleting it is refused unless you pass `-retired`, which
releases them. To keep them claimed elsewhere, move them first with
[`alias move`](#alias-move).

**Usage:** `warden identity entity delete <name> [options]`

| Flag | Default | Description |
|---|---|---|
| `-force`, `-f` | `false` | Skip the confirmation prompt. |
| `-retired` | `false` | Delete a retired entity, releasing the native identities it keeps claimed. |
| `-expected-hash` | *(none)* | Delete only if the entity still has this hash. |

```bash
warden identity entity delete ci-runner
warden identity entity delete ci-runner -force
warden identity entity delete old-batch-agent -retired -force
```

### `entity list`

List the entities of the current namespace, sorted by name. Filters combine.

**Usage:** `warden identity entity list [options]`

| Flag | Default | Description |
|---|---|---|
| `-kind` | *(none)* | Only entities of this kind. |
| `-state` | *(none)* | Only entities in this state: `active`, `suspended` or `retired`. |
| `-governed-by` | *(none)* | Only entities governed by this authority (`warden`). |
| `-sponsor` | *(none)* | Only entities whose sponsor is the group of this name. |
| `-sponsor-state` | *(none)* | `accepted`: entities with a sponsor. `pending`: entities with a handover no member has accepted yet. |
| `-ungoverned` | `false` | Only entities without a sponsor or a description. |
| `-orphaned` | `false` | Only entities claiming a native identity on an auth mount that no longer exists (disabled with `-force`). |

With `-o json`, each item carries `name`, `id`, `kind`, `state`,
`governed_by`, `ungoverned_reason`, `description`, `sponsor`,
`pending_sponsor`, `profile`, `metadata`, `aliases` and `hash`; `-o ndjson`
prints one entity per line.

```bash
warden identity entity list
warden identity entity list -ungoverned
warden identity entity list -sponsor-state pending
warden identity entity list -sponsor billing-leads
warden identity entity list -state suspended
warden identity entity list -orphaned -o ndjson | jq -r .name
```

### `entity lookup`

Answer which entity claims a native identity: its name, ID, kind, state and
`governed_by`. Name the mount by path (`mount`) or by accessor
(`mount_accessor`). An unclaimed native identity is not found.

**Usage:** `warden identity entity lookup [options]`

| Flag | Default | Description |
|---|---|---|
| `-mount` | *(none)* | The auth mount the native identity is presented through, by path, such as `auth/kubernetes/`. |
| `-mount-accessor` | *(none)* | The auth mount by accessor instead of `-mount`. It also names a mount disabled since. |
| `-name` | *(none)* | The native identity, as the mount derives it. Required. |
| `-json`, `-j` | *(none)* | Full JSON payload with `mount` or `mount_accessor`, and `name`. |

```bash
warden identity entity lookup -json '{
  "mount": "auth/kubernetes/",
  "name": "system:serviceaccount:billing:agent"
}'

warden identity entity lookup \
  -mount=auth/jwt/ \
  -name=repo:corp/billing-agent:ref:refs/heads/main

warden identity entity lookup -mount=auth/jwt/ -name=repo:corp/x -o json | jq -r .entity
```

### `entity state`

Move an entity to a lifecycle state: `active`, `suspended` (reversible) or
`retired` (final: the record becomes read-only and keeps its native identities
claimed).

**Usage:** `warden identity entity state <entity> <active|suspended|retired> [options]`

| Flag | Default | Description |
|---|---|---|
| `-expected-hash` | *(none)* | Change the state only if the entity still has this hash. |

```bash
warden identity entity state billing-agent suspended
warden identity entity state billing-agent active
warden identity entity state old-batch-agent retired
```

### `entity sponsor propose`

Propose a virtual group of humans as an entity's sponsor. The group belongs to
the entity's namespace (the request's, set with `-n`), or to an ancestor's with
`-group-namespace` (`/` for the root namespace; `namespace` in the payload).

When you are a member of the group, signed in with
[`warden login`](/cli/login/), the proposal is accepted at once and replaces the
current sponsor in the same write. Otherwise it is a pending handover,
replacing any earlier one, which a member accepts with
[`sponsor accept`](#sponsor-accept). Root is a member of no group, so its
proposals are always pending. See [Sponsors](/identity/sponsors/).

**Usage:** `warden identity entity sponsor propose <entity> [options]`

| Flag | Default | Description |
|---|---|---|
| `-group` | *(none)* | The virtual group proposed as the sponsor, by name. Required. |
| `-group-namespace` | *(the entity's)* | The group's namespace: the entity's, or an ancestor (`/` for the root namespace). |
| `-expected-hash` | *(none)* | Propose only if the entity still has this hash. |
| `-json`, `-j` | *(none)* | Full JSON payload with `group`, and optionally `namespace` and `expected_hash`. |

```bash
warden identity entity sponsor propose billing-agent -json '{
  "group": "billing-leads",
  "namespace": "/"
}'

warden identity entity sponsor propose billing-agent -group finance-oncall
warden -n team-a identity entity sponsor propose billing-agent -group billing-leads -group-namespace /
```

### `entity sponsor remove`

Remove an entity's sponsor: it is ungoverned until another is accepted. A
pending handover stays, for a member of its group to accept. With `-pending`,
cancel the pending handover instead.

**Usage:** `warden identity entity sponsor remove <entity> [options]`

| Flag | Default | Description |
|---|---|---|
| `-pending` | `false` | Cancel the pending handover instead of removing the sponsor. |
| `-expected-hash` | *(none)* | Remove only if the entity still has this hash. |

```bash
warden identity entity sponsor remove billing-agent
warden identity entity sponsor remove billing-agent -pending
```

## `identity alias`

Manage which entity claims a native identity: the identity a credential
presents through an auth mount, as the mount derives it
(`alias_name_source`). A native identity is claimed by one entity in a
namespace. See [Entities](/identity/entities/#claiming-moving-and-releasing-native-identities).

| Subcommand | Description |
|---|---|
| `add` | Claim a native identity for an entity. |
| `move` | Move a native identity to another entity. |
| `remove` | Release a native identity from its entity. |

### `alias add`

Claim a native identity for an entity. One another entity claims is refused
(use [`alias move`](#alias-move)), unless that entity is retired. A mount that
admits humans cannot be claimed by an agent.

**Usage:** `warden identity alias add [options]`

| Flag | Default | Description |
|---|---|---|
| `-mount` | *(none)* | The auth mount, by path, such as `auth/kubernetes/`. Required. |
| `-name` | *(none)* | The native identity, as the mount derives it. Required. |
| `-to` | *(none)* | The entity that claims it. Required. |
| `-json`, `-j` | *(none)* | Full JSON payload with `mount`, `name` and `to`. |

```bash
warden identity alias add -json '{
  "mount": "auth/jwt/",
  "name": "repo:corp/billing-agent:ref:refs/heads/main",
  "to": "billing-agent"
}'

warden identity alias add \
  -mount=auth/kubernetes/ \
  -name=system:serviceaccount:billing:agent \
  -to=billing-agent
```

### `alias move`

Claim a native identity for an entity, taking it from the entity that claims
it now, if any. The output names the entity it was taken from.

**Usage:** `warden identity alias move [options]`

**Flags:** the same as [`alias add`](#alias-add).

```bash
warden identity alias move -json '{
  "mount": "auth/cert/",
  "name": "spiffe://corp.example/billing-agent",
  "to": "invoice-agent"
}'

warden identity alias move -mount=auth/jwt/ -name=repo:corp/x -to=invoice-agent
```

### `alias remove`

Release a native identity from the entity `from`: it is unclaimed again. If
`from` does not claim it, nothing changes and the server answers that it is
not claimed; [`entity lookup`](#entity-lookup) names the entity that does. Name
the mount by accessor to release a claim on a mount disabled since (see
`entity list -orphaned`). A retired entity keeps its native identities: move
them instead.

**Usage:** `warden identity alias remove [options]`

| Flag | Default | Description |
|---|---|---|
| `-mount` | *(none)* | The auth mount, by path. |
| `-mount-accessor` | *(none)* | The auth mount by accessor instead of `-mount`. It also names a mount disabled since. |
| `-name` | *(none)* | The native identity, as the mount derives it. Required. |
| `-from` | *(none)* | The entity that claims it now. Any other is refused. Required. |
| `-json`, `-j` | *(none)* | Full JSON payload with `mount` or `mount_accessor`, `name` and `from`. |

```bash
warden identity alias remove -json '{
  "mount": "auth/jwt/",
  "name": "repo:corp/billing-agent:ref:refs/heads/main",
  "from": "billing-agent"
}'

warden identity alias remove \
  -mount-accessor=jwt_8f3a2c1d \
  -name=repo:corp/billing-agent:ref:refs/heads/main \
  -from=billing-agent
```

## `identity sponsor`

Act, as a member of an entity's sponsor group, on the entity your team answers
for: read it, suspend it, hand it over to another team, or accept one handed
over to yours. No Warden role is needed: sign in with
[`warden login`](/cli/login/), and your session's groups decide what you
sponsor. See [Sponsors](/identity/sponsors/#what-sponsors-can-and-cannot-do).

Every refusal reads `no sponsored agent by that name`, whatever its cause.
Making an entity active again and removing its sponsor are admin writes
([`entity state`](#entity-state), [`entity sponsor remove`](#entity-sponsor-remove)).

| Subcommand | Description |
|---|---|
| `read <entity>` | Read an entity your team sponsors, or is offered. |
| `suspend <entity>` | Suspend an entity your team sponsors. |
| `handover <entity>` | Hand an entity your team sponsors over to another group, or cancel the handover. |
| `accept <entity>` | Accept an entity handed over to your team. |

### `sponsor read`

Read an entity as a member of its sponsor group, or of the group it is being
handed over to, so you see what you are asked to accept.

**Usage:** `warden identity sponsor read <entity>`

```bash
warden identity sponsor read billing-agent
```

### `sponsor suspend`

Suspend an entity as a member of its sponsor group: its requests are refused
until an admin makes it active again.

**Usage:** `warden identity sponsor suspend <entity>`

```bash
warden identity sponsor suspend billing-agent
```

### `sponsor handover`

Offer an entity your team sponsors to another virtual group of humans, of the
entity's namespace (the request's, set with `-n`) or an ancestor's with
`-group-namespace`. A member of that group accepts it; your team stays the
sponsor until then. When you are a member of both groups, the handover is
accepted at once.

**Usage:** `warden identity sponsor handover <entity> -group <name> [-group-namespace <path>]`
or `warden identity sponsor handover <entity> -cancel`

| Flag | Default | Description |
|---|---|---|
| `-group` | *(none)* | The virtual group the entity is handed over to. Required unless `-cancel`. |
| `-group-namespace` | *(the entity's)* | The group's namespace: the entity's, or an ancestor (`/` for the root namespace). |
| `-cancel` | `false` | Cancel the pending handover instead. Takes no `-group` or `-group-namespace`. |

```bash
warden -n team-a identity sponsor handover billing-agent -group finance-oncall -group-namespace /
warden identity sponsor handover billing-agent -cancel
```

### `sponsor accept`

Accept, as a member of the group an entity is being handed over to, that your
team now sponsors it. It replaces the earlier sponsor in the same write.

**Usage:** `warden identity sponsor accept <entity>`

```bash
warden identity sponsor read billing-agent
warden identity sponsor accept billing-agent
```

## `identity config`

The identity config decides how the namespace treats a caller by its native
identity, before any role is considered:

| Field | Values |
|---|---|
| `unknown_aliases` | `observe` (the default): callers no entity claims are admitted. `deny`: they are refused, and so is a claimed caller whose entity is not governed, unless their mount is exempt. |
| `exempt_mounts` | Auth mounts `deny` never applies to, by path, such as a CI mount whose callers are anonymous by design. |

A claimed caller whose entity is suspended or retired is refused in every
mode. People signed in with `warden login` are never refused for their native
identity. See [Entities](/identity/entities/#requiring-registration).

| Subcommand | Description |
|---|---|
| `read` | Read the identity config. |
| `write` | Write the identity config. |
| `reset` | Restore the defaults. |

### `config read`

**Usage:** `warden identity config read`

```bash
warden identity config read
```

### `config write`

Write the fields you name; the others keep their value. `-exempt-mount`
replaces the whole list: repeat it, or pass `-exempt-mount=""` to clear it. A
config that would refuse your own requests is refused unless you pass `-force`.

**Usage:** `warden identity config write [options]`

| Flag | Default | Description |
|---|---|---|
| `-unknown-aliases` | *(none)* | `observe` or `deny`. |
| `-exempt-mount` | *(none)* | An auth mount `deny` never applies to, by path. Repeatable; replaces the list. |
| `-force` | `false` | Write a config that would refuse your own requests. |
| `-json`, `-j` | *(none)* | Full JSON payload with `unknown_aliases`, `exempt_mounts` (a list) and `force` (a boolean). |

```bash
warden identity config write -json '{
  "unknown_aliases": "deny",
  "exempt_mounts": ["auth/github-oidc/"]
}'

warden identity config write -unknown-aliases=deny -exempt-mount=auth/github-oidc/
warden identity config write -unknown-aliases=observe
```

### `config reset`

Restore the defaults of the namespace's identity config.

**Usage:** `warden identity config reset`

```bash
warden identity config reset
```

## `identity usage`

Count the current namespace's identity objects against their caps. Groups:
every group, the virtual groups with the selectors of their rules (`mount`
included), and the static groups with the members they list (expired ones
included until a write drops them). Identities: the entities, and the native
identities they claim.

**Usage:** `warden identity usage`

The table shows each count against its cap as `used/max`:

```text
GROUPS
  TYPE      COUNT          SELECTORS          MEMBERS
  virtual   <count>/<max>  <selectors>/<max>  -
  static    <count>/<max>  -                  <members>/<max> (at most <max> a group)
  total     <count>

IDENTITIES
  entities  <count>/<max>
  aliases   <count>
```

With `-o json` it prints the server's data as is: `groups` (`total`,
`virtual` with `count`, `max`, `selectors`, `max_selectors`, and `static` with
`count`, `max`, `members`, `max_members`, `max_group_members`) and
`identities` (`entities`, `max_entities`, `aliases`).

```bash
warden identity usage
warden identity usage -o json | jq .groups.virtual
warden identity usage -o json | jq .identities
```

## See Also

- [Groups](/identity/groups/) — virtual and static groups, rules and caps.
- [Entities](/identity/entities/) — the identity store, native identities and governance.
- [Sponsors](/identity/sponsors/) — proposing, accepting and handing over.
- [Roles](/identity/roles/) — what a group grants.
- [login](/cli/login/) — sign in for the sponsor commands.
- [CLI overview](/cli/) — global flags, output formats, exit codes.
