---
title: "Roles"
---

A **role** is what a caller acts as on one request. It names what the caller may
do there, the [policies](/identity/policies/) Warden authorizes the request
against and the [credential spec](/concepts/credentials/) it mints from, and how
[discovery](/concepts/discovery-and-skills/) describes it to agents.

A role lives in a namespace at `sys/roles/<name>`. On its own it grants nothing.
A [group](/identity/groups/) grants it, and the caller names it on each request
it wants to use it for.

## A role is asserted, not held

A caller never holds a role. It presents its own credential (a JWT, a client
certificate) on every request and names the role it wants for that request:
*"I am acting as `read-repo` for this call."* Warden then decides, on that
request:

1. which groups the caller belongs to, from what its auth method verified and
   the entity that claims it, if any;
2. whether one of those groups grants the role it named;
3. if so, the request runs with that role's policies, and any credential
   Warden mints comes from that role's spec.

Nothing of that is kept for the next request. Warden caches the caller's
admission per credential and auth mount so it does not verify the same
credential twice, but the role is decided again on every request, against the
groups and roles as they are now. Remove a member, edit a group's roles, delete
a role or let a `valid_until` pass, and the caller's very next request is
refused. A Warden token presented in place of the credential is refused too: the
grant is never carried on a token.

Contrast this with a cloud `AssumeRole`. It also resolves a role against an
identity, but it hands back session credentials the caller keeps for an hour,
everywhere it goes. In Warden the assumption never turns into something the
caller holds.

This is what lets one agent with one credential work under least privilege. It
names a narrow role for routine steps and a wider one only for the step that
needs it, on the next request, without logging in again.

<p align="center"><img alt="An agent given one goal calls list_roles, and Warden returns the roles it may assume, read-repo, write-issue, clone-repo, push-repo and send-message, each with its description" src="/images/warden-role-role-list.png" width="520"></p>

The agent does not need the role names in advance. The discovery server's
`list_roles` returns the roles groups grant it, each with its description,
skill and URL; the agent picks one per step. See
[Discovery and skills](/concepts/discovery-and-skills/).

## What a role names

| Field | Meaning |
|---|---|
| `policies` | The policies a request under the role is authorized against. `root` is refused. A policy that does not exist yet is accepted with a warning. |
| `cred_spec_name` | Optional. The credential spec Warden mints from for a request under the role. A spec that does not exist yet is accepted with a warning. |
| `description` | What the role is for, in prose an agent reads to choose it (up to 1024 bytes). |
| `skill` | Optional. The skill discovery hands an agent for this role; without one the role uses its provider's skill. |
| `provider_path` | Optional. The provider mount the role is used with, relative to the namespace (`aws/`). Discovery builds the role's URL from it, and checks an agent's credential at the auth mount that provider's `auto_auth_path` names. |
| `governed_only` | `false` by default. See [governed_only roles](#governed-only-roles). |
| `metadata` | Free-form labels (up to 32 keys). |

:::note[Making sure agents find a role]
Give the role a `provider_path` whose provider sets an `auto_auth_path`, or set
the namespace's `auto_auth_path`. A role with neither is never listed to an
agent, though it still exists; Warden warns when such a role is written, and
`warden role list -all` shows every role of the namespace to an operator. See
[Discovering roles](/concepts/discovery-and-skills/#discovering-roles).
:::

A role name uses letters, digits, `_`, `-` and `.`, starting and ending with a
letter, digit or `_`. Names starting `warden-` are reserved for the
[built-in operator roles](/identity/built-in-roles/).

## Creating a role

Role writes need `sudo` on `sys/roles`.

```bash
warden role create deploy -json '{
  "description": "Deploys from acme CI",
  "policies": ["deploy"],
  "cred_spec_name": "deploy-role",
  "skill": "aws",
  "provider_path": "aws/",
  "metadata": {
    "team": "platform"
  }
}'
```

The same with typed flags:

```bash
warden role create deploy \
    -description="Deploys from acme CI" \
    -policies=deploy \
    -cred-spec-name=deploy-role \
    -provider-path=aws/
```

Nobody can use `deploy` yet. Grant it with a group:

```bash
warden identity group create deployers -json '{
  "type": "virtual",
  "roles": ["deploy"],
  "rules": [
    {
      "mount": ["auth/kubernetes/"],
      "service_account_namespace": ["ci"],
      "service_account_name": ["deployer"]
    }
  ]
}'
```

A group may list a role before it exists, with a warning; it grants the role
once it does.

## How a request selects a role

A request names one role. Where it puts the name depends on where the request
goes.

**On a provider's gateway**, highest first:

| Source | Example |
|---|---|
| `X-Warden-Role` header | `X-Warden-Role: deploy` |
| The URL | `/v1/aws/role/deploy/gateway/…`, or `?role=deploy` on an access backend's paths |
| The provider's own carrier, where it has one | the access key ID of a SigV4 signature; the username of Git's Basic auth |
| The provider's `default_role` | a role of the namespace, set on the provider |

**On Warden's own API** (`sys/…` and other operations paths) there is no
provider, so no `default_role`: `?role=deploy` first, then `X-Warden-Role`.

The header overrides a role in the URL, and Warden rewrites the URL to match, so
policies always see the role in force. Its value must be a valid role name;
anything else is refused with `400 invalid X-Warden-Role`.

Discovery gives each role a `url` that already holds `role/<name>/`. Targeting
that URL is the selector that works for every client, including MCP clients,
whose headers are fixed when the server is attached.

## How a role is granted

A request under a role runs only if one of the caller's groups grants it:

- An **unclaimed** caller, an agent no entity claims or a human, belongs to the
  virtual groups whose rules match the facts its auth method verified.
- A **claimed** caller, an agent whose native identity an
  [entity](/identity/entities/) claims, belongs only to the static groups that
  list its entity, and only while the entity is governed and active.

The groups and the rule syntax are on [Groups](/identity/groups/). A grant is
recorded in the audit log as `role_granted_by` (the group) and
`role_group_type`; a refusal as `role_denied_reason`.

## governed_only roles

Some roles should never be held through a rule over credential facts: a
production deploy, a payment API. Mark them `governed_only`:

```bash
warden role create prod-deploy -json '{
  "description": "Deploys to production",
  "policies": ["prod-deploy"],
  "cred_spec_name": "prod-deploy-role",
  "provider_path": "aws/",
  "skill": "aws",
  "governed_only": true
}'
```

Only a static group listing a governed, active entity grants such a role.
No virtual group does, so neither an unclaimed agent nor a human holds it:

- A virtual group that lists it is refused at write.
- Setting the flag on an existing role is never refused. The write warns, naming
  the virtual groups that list the role and no longer grant it, and the writer's
  own request if it holds the role through one. Their callers are refused on
  their next request.
- Discovery never offers the role through a virtual grant.

`warden role update prod-deploy -governed-only=false` clears the flag.

## Listing and reading roles

`warden role list` shows the roles **granted to you**: every role of the
namespace a group grants the identity you present, each checked at the auth
mount a request for it would authenticate through.

```bash
warden role list
warden role list -o ndjson | jq -r .name
```

`warden role list -all` shows **every role of the namespace**, with the groups
that grant each one (`granted_by`). It needs `sudo` on `sys/roles`, and on
`sys/identity/group` for `granted_by`.

```bash
warden role list -all
warden role list -all -provider-path aws/
```

`warden role read` shows one role: its policies, credential spec, discovery
fields, metadata, `granted_by`, and the `hash` a conditional update or delete
passes back. A built-in operator role reads with the `policy_document` it
grants.

```bash
warden role read deploy
warden role read deploy -fields hash
```

## Choosing a role as a human

A human signed in with `warden login` picks the role the CLI's commands run
under with `warden role use`. With no name it lists the roles you may assume and
lets you pick; the choice is saved in the session, and `-role` or `WARDEN_ROLE`
still override it for one command.

```bash
warden role use
warden role use auditor
```

See [Human operators](/identity/human-operators/).

## Updating and deleting

An update replaces each field you pass, including with an empty value, and keeps
each field you leave out. With `expected_hash` it applies only if nobody changed
the role since you read it; otherwise the server answers 409.

```bash
warden role update deploy -json '{
  "policies": ["deploy", "audit-read"],
  "expected_hash": "<hash from warden role read>"
}'
```

Deleting a role takes effect on the next request of every caller using it:

```bash
warden role delete deploy -force
```

- Groups that list the role keep it, and the delete warns:
  `groups still list "deploy": deployers (they grant nothing until the role is re-created)`.
  A role created again under that name is granted by them again.
- A provider whose `default_role` names the role is not warned about; its
  requests that select no other role are refused with `role "deploy" not found`.
- A built-in role cannot be deleted or written.

## Refusals

A request that selects no role is refused before its credential is checked,
with **400**:

| Where | Message |
|---|---|
| A provider's gateway | `no role selected: put the role in the URL (role/<name>/), set X-Warden-Role, or set the provider's default_role` |
| Warden's own API, an access backend's paths | `no role selected: set the role query parameter (?role=<name>) or X-Warden-Role` |

A Git smart-HTTP request gets 401 instead, so Git retries with the role as its
Basic username.

A role that is selected but not granted is refused with **403**. The message
names the role and the mount, never a group, fact or selector value:

| Cause | Message |
|---|---|
| No such role | `role "deploy" not found` |
| No group grants it (unclaimed caller) | `role "deploy" is not assumable through auth/jwt/: no group grants it to this caller` |
| No static group of its entity grants it (claimed caller) | `role "deploy" is not assumable: the caller's entity holds no static group granting it` |
| Granted only through a virtual group | `role "prod-deploy" requires governed membership: only a static group listing a governed entity grants it` |
| A Warden token presented instead of the credential | `admission token presented explicitly; present the credential instead` |

A claimed caller whose entity is not governed, suspended or retired is refused
before any role is considered, with a message naming its entity. See
[Entities](/identity/entities/).

## What changed

If you are upgrading from v0.21, see
[Upgrading from v0.21](/upgrade/from-v0-21/) for how roles are defined and
granted now.
