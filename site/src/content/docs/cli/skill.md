---
title: "skill"
---

Browse and manage the global agent **skill registry** — the agent-facing recipes
that describe how to use Warden's capabilities (a shared troubleshooting guide, one
record per provider type mounted, and any skills you write). See
[Discovery & Skills](/concepts/discovery-and-skills/).

This is the operator's view of the whole catalog. Agents read skills through the
discovery server instead, which serves each identity only the skills its roles
lead to.

> **Reads are open** to any namespace token; **writes (`create`, `update`,
> `delete`) require a root-namespace token.** Running a mutation from a
> sub-namespace surfaces the server's 403.

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
| `--name` | *(from arg/payload)* | Skill name, unique: lowercase letters, digits and single hyphens, no leading or trailing hyphen, at most 64 characters. See [Skill names](#skill-names). |
| `--description` | *(none)* | One-line summary (required). |
| `--category` | *(none)* | One of `agent-flow`, `shared`, `provider-guide`, `troubleshooting`, `custom`. |
| `--requires` | *(none)* | Names of skills this one depends on; repeatable or comma-separated. |
| `--upstream` | *(none)* | Reference to an upstream system, when applicable. |
| `--provider` | *(none)* | Provider type (required when `--category=provider-guide`). |
| `--body-file` | *(none)* | Path to the markdown body file. |
| `-j`, `--json` | *(none)* | Full JSON payload. Mutually exclusive with all typed flags above. |

### Skill names

A skill name follows the Agent Skills rule: lowercase letters, digits and single
hyphens only, with no leading or trailing hyphen, at most 64 characters. An
underscore is refused. The name is the last segment of the skill's
`skill://<name>/SKILL.md` URI.

Name the skills you write `<provider>-<purpose>`, such as `aws-s3-read-only` or
`gh-repo-reader`, so a name says which provider it drives and what for.

A provider's own skill is named after its type with any underscore turned into a
hyphen: the `mcp_aws` provider ships `mcp-aws`, and `ansible_tower` ships
`ansible-tower`. Provider type names keep their underscores.

Skills stored under an older name with an underscore are renamed once, the first
time the active node unseals on v0.21.0: `mcp_aws` becomes `mcp-aws`,
`ansible_tower` becomes `ansible-tower`, and so does any skill you created with an
underscore. A `requires` entry naming a renamed skill is rewritten with it. If the
new name is already taken by a different skill, or is still invalid (two
underscores in a row, say), the old skill is left in place and the server logs a
warning. Rename it by hand — read it, create it under a valid name, then delete
the old one — since a name that is not a valid skill URI cannot be served to
agents.

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
