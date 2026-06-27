# `warden policy`

Manage [policies](../concepts/policies.md) — the capability-based rules that
control what an identity may do on which paths. A policy grants a set of
`capabilities` (`create`, `read`, `update`, `delete`, `list`, …) on path globs;
[roles](../concepts/roles.md) bind policies to authenticated identities.

## Table of Contents

- [Usage](#usage)
- [Subcommands](#subcommands)
- [`policy write`](#policy-write)
- [`policy read`](#policy-read)
- [`policy list`](#policy-list)
- [`policy delete`](#policy-delete)
- [See Also](#see-also)

## Usage

```text
warden policy <subcommand> [options]
```

Global flags apply to every subcommand — see the [CLI overview](README.md#global-flags).

## Subcommands

| Subcommand | Description |
|---|---|
| `write <name> <policy_file>` | Create or update a policy. |
| `read <name>` | Print a policy's contents. |
| `list` | List policy names. |
| `delete <name>` | Delete a policy. |

### `policy write`

Create or update the policy named `<name>` from a file, or from stdin by passing
`-` as the filename.

**Usage:** `warden policy write <name> <policy_file>`

**Examples:**

```bash
# From a file
warden policy write my-policy ./policy.hcl

# From stdin
warden policy write my-policy - <<EOF
path "secret/data/myapp/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "secret/metadata/myapp/*" {
  capabilities = ["list", "read", "delete"]
}
EOF
```

### `policy read`

Print the contents of the policy named `<name>`.

**Usage:** `warden policy read <name>`

```bash
warden policy read my-policy
```

### `policy list`

List the names of all policies.

**Usage:** `warden policy list`

```bash
warden policy list
```

### `policy delete`

Delete the policy named `<name>`.

**Usage:** `warden policy delete <name>`

```bash
warden policy delete my-policy
```

## See Also

- [Policies](../concepts/policies.md) — the capability model and policy syntax.
- [Roles](../concepts/roles.md) — how policies attach to an identity.
- [CLI overview](README.md) — global flags, output formats, exit codes.
