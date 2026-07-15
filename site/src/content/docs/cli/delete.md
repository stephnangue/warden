---
title: "delete"
---

Delete data at any path on the server. `delete` is the generic counterpart to the
typed delete subcommands. It asks for confirmation by default.

## Usage

```text
warden delete [PATH] [flags]
```

The `PATH` may be given positionally or via `--path` — pick one.

**Path format:** `provider_mount/resource`, `auth/auth_mount/resource`, or
`sys/path/to/resource`.

## Examples

```bash
# Delete a JWT auth role (prompts for confirmation)
warden delete auth/jwt/role/developer
warden delete --path=auth/jwt/role/developer

# Skip the confirmation prompt
warden delete sys/providers/aws -f

# Delete a namespace
warden delete sys/namespaces/test
```

## Flags

| Flag | Default | Description |
|---|---|---|
| `-f`, `--force` | `false` | Skip the confirmation prompt. |
| `--path` | *(none)* | API path (alternative to the positional `PATH`). |

Under `-D/--dry-run`, `delete` validates the path against the schema and exits
before any prompt or HTTP call — a non-mutating preview needs no confirmation.

## See Also

- [`warden read`](/cli/read/) · [`warden write`](/cli/write/) · [`warden list`](/cli/list/) — the rest of the generic data family.
- [CLI overview](/cli/) — global flags, output formats, exit codes.
