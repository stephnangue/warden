---
title: "auth"
---

Manage [auth methods](/auth-methods/) — the backends that validate a
caller's credential and resolve it to an identity. Use these subcommands to
enable a method, inspect it, and tear it down. The credential validation itself
(roles, claim mapping, transparent auth) is configured by writing to the mount's
paths; see [Authentication](/concepts/authentication/) and the per-method
guides.

## Usage

```text
warden auth <subcommand> [options]
```

Global flags (`-n/--namespace`, `-o/--output`, `-D/--dry-run`, …) apply to every
subcommand — see the [CLI overview](/cli/#global-flags).

## Subcommands

| Subcommand | Description |
|---|---|
| `enable TYPE` | Enable an auth method. |
| `list` | List enabled auth methods. |
| `read [PATH]` | Show one auth method's configuration. |
| `disable [PATH]` | Disable an auth method. |

### `auth enable`

Enable an auth method of the given `TYPE` (`jwt`, `cert`, `kubernetes`,
`spiffe`). The mount path defaults to `TYPE`; override it with `--path`.

**Usage:** `warden auth enable [options] TYPE`

**Examples:**

```bash
# Enable JWT auth at the default jwt/ path
warden auth enable jwt

# Mount at a custom path with a description
warden auth enable --path=jwt-prod --description="Hydra OIDC" jwt

# Agent-friendly: full JSON payload from a file or stdin
warden auth enable jwt --json @auth-jwt.json
cat auth-jwt.json | warden auth enable jwt --json -
```

**Flags:**

| Flag | Default | Description |
|---|---|---|
| `--description` | *(none)* | Human-friendly description of the mount. |
| `--path` | `TYPE` | Custom mount path. |
| `-j`, `--json` | *(none)* | Full JSON payload: `<json>`, `@file.json`, or `-` for stdin. Mutually exclusive with `--description`. |

If the JSON payload carries a `type` field it must match `TYPE`. Combine with
`-D/--dry-run` to validate without enabling.

### `auth list`

List the enabled auth methods, with path, type, accessor, and description.

**Usage:** `warden auth list`

```bash
warden auth list
warden auth list -o json
```

### `auth read`

Show the configuration of the auth method at `PATH`.

**Usage:** `warden auth read [PATH]`

```bash
warden auth read jwt/
warden auth read --path=jwt/
```

The path may be given positionally or via `--path` — pick one.

### `auth disable`

Disable the auth method at `PATH` and remove its configuration.

**Usage:** `warden auth disable [PATH]`

```bash
warden auth disable jwt/
warden auth disable --path=jwt/
```

## See Also

- [Auth Methods](/auth-methods/) — setup guides for cert, JWT, Kubernetes, and SPIFFE.
- [Authentication](/concepts/authentication/) — credential forms and transparent auth.
- [Roles](/concepts/roles/) — how a validated identity maps to policies.
- [CLI overview](/cli/) — global flags, output formats, exit codes.
