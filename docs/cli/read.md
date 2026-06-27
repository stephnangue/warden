# `warden read`

Read data from any path on the server. `read` is the generic counterpart to the
typed commands — it works against provider, auth, and `sys` paths alike, and is
what you reach for when no dedicated subcommand exists.

## Usage

```text
warden read [PATH]
```

The `PATH` may be given positionally or via `--path` — pick one; combining both is
rejected.

**Path format:** `provider_mount/resource`, `auth/auth_mount/resource`, or
`sys/path/to/resource`. The CLI converts it to the corresponding API path.

## Examples

```bash
# Provider configuration
warden read aws/config
warden read --path=aws/config

# Auth method configuration
warden read auth/jwt/config

# System mounts
warden read sys/mounts

# Project specific fields
warden read aws/config -F proxy_domains,timeout
```

## Flags

| Flag | Default | Description |
|---|---|---|
| `--path` | *(none)* | API path (alternative to the positional `PATH`). |

## See Also

- [`warden write`](write.md) · [`warden list`](list.md) · [`warden delete`](delete.md) — the rest of the generic data family.
- [`warden path-help`](path-help.md) — discover what a path accepts.
- [CLI overview](README.md) — global flags, output formats, exit codes.
