---
title: "role"
---

Manage the [roles](/identity/roles/) of a namespace, see which ones you are
granted, and choose the role your `warden login` session runs under. A role
names the policies and the credential spec a request runs with. On its own it
grants nothing: a [group](/identity/groups/) grants it, and each request names
the role it wants. On any command, name one with the global `-r/--role` flag
or `WARDEN_ROLE`.

## Usage

```text
warden role <subcommand> [options]
```

Global flags apply to every subcommand — see the [CLI overview](/cli/#global-flags).

## Subcommands

| Subcommand | Description |
|---|---|
| `create <name>` | Create a role in the current namespace. |
| `read <name>` | Show one role, with the groups that grant it. |
| `update <name>` | Change some fields of a role. |
| `delete <name>` | Delete a role. |
| `list` | List the roles granted to you, or every role with `-all`. |
| `use [name]` | Choose the role your `warden login` session runs under. |

`create`, `read`, `update`, `delete` and `list -all` need `sudo` on
`sys/roles`.

### `role create`

Create a role. A policy or credential spec that does not exist yet is accepted,
with a warning on stderr. The `root` policy is refused. Names starting
`warden-` are reserved for the [built-in roles](/identity/built-in-roles/).

**Usage:** `warden role create <name> [options]`

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

# The same with typed flags
warden role create deploy \
    -description="Deploys from acme CI" \
    -policies=deploy \
    -cred-spec-name=deploy-role \
    -provider-path=aws/

# From a file or stdin
warden role create deploy -json @deploy-role.json
cat deploy-role.json | warden role create deploy -json -
```

**Flags** (shared with `update`):

| Flag | Payload key | Description |
|---|---|---|
| `-description` | `description` | What the role is for. Discovery shows it to agents. |
| `-policies` | `policies` | Policies a request under the role is authorized against. Repeat, or comma-separate. |
| `-cred-spec-name` | `cred_spec_name` | Credential spec Warden mints from for a request under the role. |
| `-skill` | `skill` | Skill that teaches an agent to use the role. |
| `-provider-path` | `provider_path` | Mount path of the provider the role is used with, such as `aws/`. |
| `-metadata` | `metadata` | Free-form label, `key=value`. Repeatable. |
| `-governed-only` | `governed_only` | Grant the role only through static groups of governed entities. |
| `-j`, `-json` | | Full JSON payload: `<json>`, `@file.json`, or `-` for stdin. Mutually exclusive with the typed flags. |

Combine with `-D/--dry-run` to check the payload without creating the role.

#### `governed_only`

A `governed_only` role is granted only by a static group that lists a governed,
active [entity](/identity/entities/). No virtual group grants it, so neither an
unregistered agent nor a person holds it.

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

A virtual group that lists such a role is refused when it is written. Setting
the flag on an existing role is never refused: the write warns, naming the
virtual groups that list the role and stop granting it. Their callers are
refused from their next request. `-governed-only=false` clears the flag.

### `role read`

Show one role: its policies, credential spec, discovery fields, metadata,
`governed_only`, the groups that grant it (`granted_by`), and the `hash` a
conditional update or delete passes back. Listing `granted_by` also needs
`sudo` on `sys/identity/group`; without it the role is shown alone, with a
warning.

**Usage:** `warden role read <name>`

```bash
warden role read deploy
warden role read deploy -o json
warden role read deploy -F hash
warden role read warden-viewer -F policy_document
```

A built-in role reads as built-in, with the `policy_document` it grants. It
cannot be changed: copy the document into a policy and a role of your own.

### `role update`

A field you pass replaces the stored value, even with an empty one; a field you
leave out keeps its value. With an expected hash, the update applies only if
nobody changed the role since you read it; otherwise the server answers 409 and
the CLI exits 9.

**Usage:** `warden role update <name> [options]`

```bash
warden role update deploy -json '{
  "policies": ["deploy", "audit-read"],
  "expected_hash": "<hash from warden role read>"
}'

warden role update deploy -policies=deploy,audit-read
warden role update deploy -cred-spec-name=""     # clear the credential spec
warden role update prod-deploy -governed-only=false
```

Takes the same flags as `create`, plus:

| Flag | Description |
|---|---|
| `-expected-hash` | Apply the update only if the role still has this hash. With `-json`, put `expected_hash` in the payload instead. |

At least one field is required.

### `role delete`

Delete a role. Every caller using it is refused from its next request.

**Usage:** `warden role delete <name> [options]`

```bash
warden role delete deploy
warden role delete deploy -force
warden role delete deploy -force -expected-hash "$(warden role read deploy -o json | jq -r .hash)"
```

| Flag | Description |
|---|---|
| `-f`, `-force` | Skip the confirmation prompt. |
| `-expected-hash` | Delete only if the role still has this hash. |

On a terminal the command asks for confirmation unless `-force` is set. When
stdin is not a terminal it does not ask, so pass `-force` to make the intent
explicit.

Groups that list the role keep it, and the delete warns on stderr, naming them:

```text
warning: groups still list "deploy": deployers (they grant nothing until the role is re-created)
```

A role created again under that name is granted by those groups again. A
built-in role cannot be deleted.

### `role list`

By default, list the roles **granted to you**: every role of the namespace that
a group grants the identity you present, each checked at the auth mount a
request for it would authenticate through. You do not need to know the role
names in advance.

**Usage:** `warden role list [options]`

```bash
warden role list
warden role list -o json
warden role list -o ndjson | jq -r .name
```

The identity is a JWT, a TLS client certificate, or your `warden login`
session. A service token, such as the root token, is not an identity to grant
roles to: the server answers 401. Use `-all` with it instead.

An auth mount that cannot decide (not configured, its verifier unreachable) is
reported as a warning on stderr, and the command still exits 0, so one failing
mount does not hide the rest.

With `-all`, list **every role of the namespace**, built-in roles included,
each with the groups that grant it (`granted_by`). `-all` needs `sudo` on
`sys/roles`, and on `sys/identity/group` for `granted_by`.

```bash
warden role list -all
warden role list -all -provider-path aws/
```

| Flag | Description |
|---|---|
| `-all` | List every role of the namespace instead of the ones granted to you. |
| `-provider-path` | With `-all`, list only the roles used with this provider mount, such as `aws/`. Built-in roles are left out. |

| Output | Fields per role |
|---|---|
| default | `name`, `description`, and `provider_path` and `skill` when the role sets them |
| `-all` | `name`, `description`, `granted_by`, `policies`, `cred_spec_name`, `provider_path`, `skill`, `governed_only`, `metadata`, `builtin` |

### `role use`

Choose the role the commands of your `warden login` session run under. With a
name, the CLI checks that you are granted it and uses it. Without one, it lists
the roles you are granted and lets you pick (arrows to move, type to filter,
Enter to select, Esc to keep the current one). When only one role is granted,
it is used. Without a terminal, the roles are listed on stderr.

**Usage:** `warden role use [name]`

```bash
warden role use
warden role use warden-viewer
```

The choice is saved in the session; you do not sign in again. `-role` and
`WARDEN_ROLE` still override it for one command. `role use` needs a session:
with `WARDEN_TOKEN` set it is refused, and you name the role with `-role` or
`WARDEN_ROLE` instead. See [`warden login`](/cli/login/) and
[Human operators](/identity/human-operators/).

## Removed paths

A request to a role path Warden no longer serves answers **410 Gone**, with a
message naming what replaced it, and the CLI exits 11. If you manage roles
from scripts written for v0.21.0, see
[Upgrading from v0.21.0](/upgrade/from-v0-21/).

## See Also

- [Roles](/identity/roles/) — how a request selects a role, and the refusals.
- [Groups](/identity/groups/) — how groups grant roles.
- [Built-in roles](/identity/built-in-roles/) — the four operator roles.
- [`warden identity`](/cli/identity/) — groups and entities from the CLI.
- [CLI overview](/cli/) — global flags, output formats, exit codes.
