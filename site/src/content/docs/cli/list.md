---
title: "list"
---

List data at any path on the server. `list` enumerates the keys under a path —
the generic counterpart to the typed `list` subcommands.

## Usage

```text
warden list [PATH]
```

The `PATH` may be given positionally or via `--path` — pick one.

**Path format:** `provider_mount/resource`, `auth/auth_mount/resource`, or
`sys/path/to/resource`.

## Examples

```bash
# Auth roles
warden list auth/jwt/role
warden list --path=auth/jwt/role

# Providers
warden list sys/providers

# Namespaces
warden list sys/namespaces
```

In `table` mode the keys print as a simple list; other formats render the full
response and honour `-F/--fields`.

## Flags

| Flag | Default | Description |
|---|---|---|
| `--path` | *(none)* | API path (alternative to the positional `PATH`). |

## See Also

- [`warden read`](/cli/read/) · [`warden write`](/cli/write/) · [`warden delete`](/cli/delete/) — the rest of the generic data family.
- [CLI overview](/cli/) — global flags, output formats, exit codes.
