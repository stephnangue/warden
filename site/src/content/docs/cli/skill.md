---
title: "skill"
---

Browse and manage the global agent **skill registry** — the agent-facing recipes
that describe how to use Warden's capabilities (a foundation flow plus one record
per provider type). See [Discovery & Skills](/concepts/discovery-and-skills/).

> **Reads are open** to any namespace token; **writes (`create`, `update`,
> `delete`) require a root-namespace token.** Running a mutation from a
> sub-namespace surfaces the server's 403.

## Table of Contents

- [Usage](#usage)
- [Subcommands](#subcommands)
- [`skill list`](#skill-list)
- [`skill read`](#skill-read)
- [`skill create`](#skill-create)
- [`skill update`](#skill-update)
- [`skill delete`](#skill-delete)
- [See Also](#see-also)

## Usage

```text
warden skill <subcommand> [options]
```

Global flags apply to every subcommand — see the [CLI overview](/cli/#global-flags).

## Subcommands

| Subcommand | Description |
|---|---|
| `list` | List every skill in the catalog. |
| `read <name>` | Print one skill's markdown body. |
| `create [NAME]` | Create a skill (root only). |
| `update <name>` | Update a skill (root only). |
| `delete <name>` | Delete a skill (root only). |

### `skill list`

List every skill in the registry.

**Usage:** `warden skill list`

```bash
warden skill list
```

### `skill read`

Print the full markdown body of the skill named `<name>`. Pass `--raw` to emit the
body verbatim (no envelope), useful for piping into a file or an agent.

**Usage:** `warden skill read <name> [--raw]`

```bash
warden skill read aws
warden skill read aws --raw
```

### `skill create`

Create a skill. The name comes from the positional `NAME`, the `--name` flag, or
the payload's `name` field. Required fields (typed or via payload): `name`,
`description`, `category`, `body`. A `provider-guide` skill also requires
`provider`.

**Usage:** `warden skill create [NAME] [options]`

**Examples:**

```bash
# Typed flags
warden skill create --name=my-runbook --category=custom \
    --description="ops on-call" --body-file=./runbook.md

# Agent-friendly: full JSON payload
warden skill create my-runbook --json @skill.json
cat skill.json | warden skill create my-runbook --json -
```

**Flags:**

| Flag | Default | Description |
|---|---|---|
| `--name` | *(from arg/payload)* | Skill name (unique slug, `[a-z0-9_-]{2,64}`). |
| `--description` | *(none)* | One-line summary (required). |
| `--category` | *(none)* | One of `agent-flow`, `shared`, `provider-guide`, `troubleshooting`, `custom`. |
| `--requires` | *(none)* | Names of skills this one depends on; repeatable or comma-separated. |
| `--upstream` | *(none)* | Reference to an upstream system, when applicable. |
| `--provider` | *(none)* | Provider type (required when `--category=provider-guide`). |
| `--body-file` | *(none)* | Path to the markdown body file. |
| `-j`, `--json` | *(none)* | Full JSON payload. Mutually exclusive with all typed flags above. |

### `skill update`

Update an existing skill (root namespace only). Mirrors `create`'s flag set.

**Usage:** `warden skill update <name> [options]`

### `skill delete`

Delete the skill named `<name>` (root namespace only).

**Usage:** `warden skill delete <name>`

```bash
warden skill delete my-runbook
```

## See Also

- [Discovery & Skills](/concepts/discovery-and-skills/) — what skills are and how agents fetch them.
- [CLI overview](/cli/) — global flags, output formats, exit codes.
