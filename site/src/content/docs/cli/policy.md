---
title: "policy"
---

Manage [policies](/concepts/policies/) — the rules that control what an identity
may do. Warden has **two policy types**, and every subcommand selects one with
`-type`:

| Type | Governs | Stored at |
|---|---|---|
| `cbp` *(default)* | Paths and operations. Grants `capabilities` (`create`, `read`, `update`, …) on path globs. | `sys/policies/cbp/<name>` |
| `mcp` | Individual [MCP](/concepts/mcp/) calls — methods, tool/resource/prompt names, and arguments. | `sys/policies/mcp/<name>` |

[Roles](/concepts/roles/) bind capability policies to authenticated identities.
MCP policies are purely restrictive: access is the **intersection** of both types,
so an MCP policy can only narrow what a capability policy already grants.

Names are unique across both types — an MCP policy cannot reuse a capability
policy's name.

## Usage

```text
warden policy <subcommand> [options]
```

Global flags apply to every subcommand — see the [CLI overview](/cli/#global-flags).

## Subcommands

| Subcommand | Description |
|---|---|
| `write <name> <policy_file>` | Create or update a policy. |
| `read <name>` | Print a policy's contents. |
| `list` | List policy names. |
| `delete <name>` | Delete a policy. |

### Flags

| Flag | Default | Description |
|---|---|---|
| `-type` | `cbp` | Which policy type the subcommand acts on: `cbp` or `mcp`. |

### `policy write`

Create or update the policy named `<name>` from a file, or from stdin by passing
`-` as the filename.

**Usage:** `warden policy write [-type=cbp|mcp] <name> <policy_file>`

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

An MCP policy uses `-type mcp` and a different grammar — family blocks rather
than `capabilities`:

```bash
warden policy write -type mcp github-tools - <<'EOF'
path "mcp/gateway/github/*" {
  methods { allowed = ["tools/list", "tools/call"] }
  tools {
    allowed = ["get_repository", "list_issues"]
    denied  = ["delete_*"]
  }
  condition = "call.args.?env.orValue('') != 'prod'"
}
EOF
```

:::note[One argument per single-line block]
HCL allows only a single argument in a one-line block, so
`tools { allowed = [...] denied = [...] }` is a parse error. Write a block with
both `allowed` and `denied` across multiple lines, as above.
:::

### `policy read`

Print the contents of the policy named `<name>`.

**Usage:** `warden policy read [-type=cbp|mcp] <name>`

```bash
warden policy read my-policy
warden policy read -type mcp github-tools
```

### `policy list`

List the names of all policies of the selected type.

**Usage:** `warden policy list [-type=cbp|mcp]`

```bash
warden policy list
warden policy list -type mcp
```

### `policy delete`

Delete the policy named `<name>`.

**Usage:** `warden policy delete [-type=cbp|mcp] <name>`

```bash
warden policy delete my-policy
warden policy delete -type mcp github-tools
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
[Fine-grained access](/concepts/policies/#fine-grained-access) and the
[CEL Condition Cookbook](/concepts/cel-conditions/).

## See Also

- [Policies](/concepts/policies/) — the capability model and policy syntax.
- [CEL Condition Cookbook](/concepts/cel-conditions/) — condition recipes, simple to complex.
- [Roles](/concepts/roles/) — how policies attach to an identity.
- [CLI overview](/cli/) — global flags, output formats, exit codes.
