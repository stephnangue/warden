---
title: "auth"
---

Manage [auth methods](/auth-methods/) — the backends that verify a caller's
credential and record what they verified as facts and a native identity. Use
these subcommands to enable a method, inspect it, and tear it down. What a
mount verifies, and the facts it records, are configured by writing to its
`config` path; see [Authentication](/identity/authentication/) and the
per-method guides. Roles are not configured on an auth mount:
[groups](/identity/groups/) grant them on each request.

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
`spiffe`, `oidc`). The mount path defaults to `TYPE`; override it with `--path`.
`oidc` is the method people sign in through with
[`warden login`](/cli/login/); the others admit agents.

**Usage:** `warden auth enable [options] TYPE`

**Examples:**

```bash
# Enable JWT auth at the default jwt/ path
warden auth enable jwt

# Enable sign-in for people at auth/oidc/
warden auth enable oidc

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

If the JSON payload carries a `type` field it must match `TYPE`. A config that
sets a key Warden removed or reserves is refused with 400, naming each key.
Combine with `-D/--dry-run` to validate without enabling.

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

`auth list` and `auth read` warn on stderr about a mount whose storage still
holds settings from v0.21.0 that Warden no longer uses. A read of a mount's
config (`warden read auth/jwt/config`) warns the same way about each stored key
it ignores; any write to the config removes them. The warnings stay in the
`json` output. See [Upgrading from v0.21.0](/upgrade/from-v0-21/).

### `auth disable`

Disable the auth method at `PATH` and remove its configuration.

**Usage:** `warden auth disable [PATH] [options]`

```bash
warden auth disable jwt/
warden auth disable --path=jwt/
warden auth disable jwt/ --force
```

| Flag | Description |
|---|---|
| `--path` | Mount path, in place of the positional `PATH`. |
| `--force` | Disable even while entities claim native identities on the mount. |

- **Claimed native identities.** A mount on which
  [entities](/identity/entities/) claim native identities is refused with
  409 (exit 9): a mount
  enabled again at the same path is a new mount, and the claims would be left
  on this one. Move or release them first with `warden identity alias move`
  or `remove` (see [`warden identity`](/cli/identity/)), or pass `--force`; the claims are
  then orphaned, and `warden identity entity list -orphaned` lists them.
- **Groups that name the mount.** When group rules name the mount in their
  `mount` selector, the disable warns on stderr how many groups do. Those
  rules match nothing until a mount is enabled there again. The warning names
  no group.

Disabling an `oidc` mount ends every session it issued.

## See Also

- [Auth Methods](/auth-methods/) — setup guides for cert, JWT, Kubernetes, SPIFFE, and OIDC.
- [Authentication](/identity/authentication/) — credential forms and transparent auth.
- [Groups](/identity/groups/) — how the facts a mount verifies grant roles.
- [`warden login`](/cli/login/) — signing people in through an `oidc` mount.
- [CLI overview](/cli/) — global flags, output formats, exit codes.
