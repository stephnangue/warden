---
title: "namespace"
---

Manage [namespaces](/concepts/namespaces/) — the isolation boundary that
separates one tenant's providers, auth methods, and policies from another's.

## Usage

```text
warden namespace <subcommand> [options]
```

Global flags apply to every subcommand — see the [CLI overview](/cli/#global-flags).
Namespaces nest: a `<path>` like `org/engineering` creates a child under `org`,
which must already exist. The path is relative to the namespace the command
runs in, so `warden namespace create engineering -n org` does the same. A path
with an empty, `.` or `..` segment is refused with 400, and the CLI exits 3
(it refuses `..` before sending anything).

A namespace's record is written from its parent, never from inside the
namespace itself: `create` and `update` of `org/engineering` run in `org/` or
above. A write from inside a namespace to itself is refused with 400.

## Subcommands

| Subcommand | Description |
|---|---|
| `create <path>` | Create a namespace. |
| `list` | List namespaces. |
| `read <path>` | Show a namespace's information. |
| `update <path>` | Update a namespace's metadata. |
| `delete <path>` | Delete a namespace. |

### `namespace create`

Create a namespace at `<path>`. Optionally attach custom metadata.

**Usage:** `warden namespace create <path> [options]`

**Examples:**

```bash
warden namespace create my-team
warden namespace create org/engineering
warden namespace create my-team --metadata=environment=prod --metadata=team=platform
warden namespace create acme --enable-builtin-roles

# Agent-friendly: full JSON payload
warden namespace create acme --json '{
  "custom_metadata": {
    "team": "platform"
  },
  "enable_builtin_roles": true
}'
warden namespace create my-team --json @ns.json
```

**Flags:**

| Flag | Default | Description |
|---|---|---|
| `--metadata` | *(none)* | Custom `KEY=VALUE` metadata; repeatable. |
| `--enable-builtin-roles` | `false` | Give the namespace the [built-in roles](/identity/built-in-roles/). Its children do not inherit it. |
| `-j`, `--json` | *(none)* | Full JSON payload: `<json>`, `@file.json`, or `-` for stdin. Mutually exclusive with the typed flags. |

The root namespace always has the built-in roles. Any other namespace has them
only when its parent sets `enable_builtin_roles`, and since the parent writes
the record, a namespace cannot turn them on for itself.

### `namespace list`

List namespaces.

**Usage:** `warden namespace list`

```bash
warden namespace list
warden namespace list -R                 # every namespace below, too
warden namespace list -include-parent    # include the namespace the command runs in
```

Each entry reports `enable_builtin_roles`; root's is always `true`.

### `namespace read`

Show information about the namespace at `<path>`.

**Usage:** `warden namespace read <path>`

```bash
warden namespace read my-team
```

The output includes `enable_builtin_roles`, with the ID, UUID, path, custom
metadata, `locked` and `tainted`.

### `namespace update`

Replace the custom metadata of an existing namespace, or turn its built-in
roles on or off. Mounted backends and configuration are unaffected.
`--metadata` or `--enable-builtin-roles` is required (or use `--json`).

**Usage:** `warden namespace update <path> [options]`

```bash
warden namespace update my-team --metadata=environment=staging --metadata=team=devops
warden namespace update acme --enable-builtin-roles
warden namespace update acme --enable-builtin-roles=false

# Clear the metadata
warden namespace update my-team --json '{
  "custom_metadata": {}
}'
```

**Flags:**

| Flag | Default | Description |
|---|---|---|
| `--metadata` | *(none)* | Custom `KEY=VALUE` metadata; repeatable. Replaces the stored metadata. |
| `--enable-builtin-roles` | *(unchanged)* | Turn the built-in roles on; `--enable-builtin-roles=false` turns them off. |
| `-j`, `--json` | *(none)* | Full JSON payload. Mutually exclusive with the typed flags. |

Turning the built-in roles off is refused while a group of the namespace
still grants one. The refusal names each group, its type and the role:

```text
enable_builtin_roles cannot be turned off: groups still grant
built-in roles: platform-admins (virtual, warden-admin)
```

### `namespace delete`

Delete the namespace at `<path>`.

**Usage:** `warden namespace delete <path>`

```bash
warden namespace delete my-team
warden namespace delete my-team -f    # skip the confirmation prompt
```

## See Also

- [Namespaces](/concepts/namespaces/) — the isolation model and inheritance rules.
- [Built-in roles](/identity/built-in-roles/) — what `enable_builtin_roles` turns on.
- [Centralized Governance](/use-cases/centralized-governance/) — namespaces in a multi-tenant setup.
- [CLI overview](/cli/) — global flags, output formats, exit codes.
