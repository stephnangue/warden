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
- [Conditions (CEL)](#conditions-cel)
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

## Conditions (CEL)

A `path` rule may carry a **`condition`** — a [CEL](https://cel.dev) expression
that must evaluate to `true` for the rule to apply. It refines a capability grant
with request context, caller identity, and value logic (source IP, time of day,
token attributes, numeric/string/set comparisons, MCP tool arguments).

Conditions are **validated and cost-bounded when the policy is written**: a
malformed, non-boolean, or too-expensive expression makes `warden policy write`
fail with a directed error, so a broken condition never reaches the request path.
At request time evaluation is **fail-closed** — a `false` result or any error
(missing field, type mismatch) denies.

```bash
warden policy write pin-model - <<'EOF'
path "anthropic/role/+/gateway*" {
  capabilities = ["create", "update"]
  condition    = "request.data.model == 'claude-sonnet-4-5'"
}
EOF
```

A bad expression is rejected at write time rather than silently denying later:

```bash
# non-boolean expression → write fails
warden policy write bad - <<'EOF'
path "secret/*" { capabilities = ["read"] condition = "1 + 1" }
EOF
# Error: ... condition must evaluate to bool
```

For the full variable namespaces, functions, and 20 worked examples, see
[Fine-grained access](../concepts/policies.md#fine-grained-access) and the
[CEL Condition Cookbook](../concepts/cel-conditions.md).

## See Also

- [Policies](../concepts/policies.md) — the capability model and policy syntax.
- [CEL Condition Cookbook](../concepts/cel-conditions.md) — condition recipes, simple to complex.
- [Roles](../concepts/roles.md) — how policies attach to an identity.
- [CLI overview](README.md) — global flags, output formats, exit codes.
