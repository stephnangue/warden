---
title: "namespace"
---

Manage [namespaces](/concepts/namespaces/) — the isolation boundary that
separates one tenant's providers, auth methods, and policies from another's.

## Table of Contents

- [Usage](#usage)
- [Subcommands](#subcommands)
- [`namespace create`](#namespace-create)
- [`namespace list`](#namespace-list)
- [`namespace read`](#namespace-read)
- [`namespace update`](#namespace-update)
- [`namespace delete`](#namespace-delete)
- [See Also](#see-also)

## Usage

```text
warden namespace <subcommand> [options]
```

Global flags apply to every subcommand — see the [CLI overview](/cli/#global-flags).
Namespaces nest: a `<path>` like `org/engineering` creates a child under `org`.

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

# Agent-friendly: full JSON payload
warden namespace create my-team --json @ns.json
```

**Flags:**

| Flag | Default | Description |
|---|---|---|
| `--metadata` | *(none)* | Custom `KEY=VALUE` metadata; repeatable. |
| `-j`, `--json` | *(none)* | Full JSON payload: `<json>`, `@file.json`, or `-` for stdin. Mutually exclusive with `--metadata`. |

### `namespace list`

List namespaces.

**Usage:** `warden namespace list`

```bash
warden namespace list
```

### `namespace read`

Show information about the namespace at `<path>`.

**Usage:** `warden namespace read <path>`

```bash
warden namespace read my-team
```

### `namespace update`

Replace the custom metadata of an existing namespace. Mounted backends and
configuration are unaffected. `--metadata` is required (or use `--json`);
`--metadata=""` clears it.

**Usage:** `warden namespace update <path> [options]`

```bash
warden namespace update my-team --metadata=environment=staging --metadata=team=devops
warden namespace update my-team --metadata=""    # clear
```

**Flags:**

| Flag | Default | Description |
|---|---|---|
| `--metadata` | *(none)* | Custom `KEY=VALUE` metadata; repeatable. |
| `-j`, `--json` | *(none)* | Full JSON payload. Mutually exclusive with `--metadata`. |

### `namespace delete`

Delete the namespace at `<path>`.

**Usage:** `warden namespace delete <path>`

```bash
warden namespace delete my-team
```

## See Also

- [Namespaces](/concepts/namespaces/) — the isolation model and inheritance rules.
- [Centralized Governance](/use-cases/centralized-governance/) — namespaces in a multi-tenant setup.
- [CLI overview](/cli/) — global flags, output formats, exit codes.
