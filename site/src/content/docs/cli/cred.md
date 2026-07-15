---
title: "cred"
---

Manage [credentials](/concepts/credentials/) — the **sources** Warden draws
from and the **specs** that shape what gets minted and injected into a proxied
request. A source holds the upstream connection and root credential; a spec binds
to a source and defines type, TTLs, and rotation. The `cred` command groups two
subcommand families: `cred source` and `cred spec`.

## Table of Contents

- [Usage](#usage)
- [`cred source`](#cred-source)
- [`cred spec`](#cred-spec)
- [`cred spec connect`](#cred-spec-connect)
- [See Also](#see-also)

## Usage

```text
warden cred source <subcommand> [options]
warden cred spec   <subcommand> [options]
```

Global flags apply to every subcommand — see the [CLI overview](/cli/#global-flags).
The `create` subcommands accept either typed flags or a full `--json` payload
(`<json>`, `@file.json`, or `-` for stdin), mutually exclusive with the typed
flags, and honour `-D/--dry-run`. `--config` values support `@file` references to
read a value from disk (e.g. a PEM key).

## `cred source`

A credential source holds an upstream's type, configuration, and rotation policy.

| Subcommand | Description |
|---|---|
| `create <name>` | Create a source. |
| `list` | List sources. |
| `read <name>` | Show a source's configuration. |
| `update <name>` | Update a source. |
| `delete <name>` | Delete a source. |

### `cred source create`

**Usage:** `warden cred source create <name> [flags]`

```bash
warden cred source create my-aws \
    --type=aws \
    --config=access_key_id=... \
    --config=secret_access_key=... \
    --config=region=us-east-1 \
    --rotation-period=24h

# Agent-friendly: full JSON payload
warden cred source create my-aws --json @aws-source.json
```

| Flag | Default | Description |
|---|---|---|
| `--type` | *(none)* | Source type (required unless `--json`). |
| `--config` | *(none)* | Source configuration `KEY=VALUE`; repeatable. Values may use `@file`. |
| `--rotation-period` | *(none)* | Rotation period for the source's root credential, e.g. `24h` (required unless `--json`). |
| `-j`, `--json` | *(none)* | Full JSON payload. Mutually exclusive with the typed flags. |

## `cred spec`

A credential spec binds to a source and defines what callers receive.

| Subcommand | Description |
|---|---|
| `create <name>` | Create a spec. |
| `list` | List specs. |
| `read <name>` | Show a spec's configuration. |
| `update <name>` | Update a spec. |
| `delete <name>` | Delete a spec. |
| `connect <name>` | Complete interactive OAuth2 consent for a spec. |

### `cred spec create`

**Usage:** `warden cred spec create <name> [flags]`

```bash
warden cred spec create developer \
    --source=my-aws \
    --config=mint_method=sts_assume_role \
    --config=role_arn=arn:aws:iam::1234:role/dev \
    --min-ttl=1h --max-ttl=24h

# Agent-friendly: full JSON payload
warden cred spec create developer --json @spec.json
```

| Flag | Default | Description |
|---|---|---|
| `--type` | *(inferred from source)* | Credential type; usually omitted. |
| `--source` | *(none)* | Source name to bind to (required unless `--json`). |
| `--config` | *(none)* | Type-specific configuration `KEY=VALUE`; repeatable. Values may use `@file`. |
| `--min-ttl` | `1h` | Minimum credential TTL. |
| `--max-ttl` | `24h` | Maximum credential TTL. |
| `--rotation-period` | *(none)* | Rotation period for credentials stored in the spec, e.g. `24h`. Empty means no rotation. |
| `-j`, `--json` | *(none)* | Full JSON payload. Mutually exclusive with the typed flags. |

## `cred spec connect`

Complete the one-time human consent for a spec that uses the OAuth2
`authorization_code` flow. The command binds a loopback listener, opens the
provider's consent page in a browser, captures the authorization code on the
loopback redirect, and hands it to the server — which exchanges it (using the
client secret it holds) and seals the resulting refresh token into the spec. The
client secret never touches your machine.

**Usage:** `warden cred spec connect <name> [flags]`

```bash
warden cred spec connect gh-oauth

# Print the URL instead of launching a browser (e.g. on a headless host)
warden cred spec connect gh-oauth --no-browser
```

| Flag | Default | Description |
|---|---|---|
| `--port` | `0` (ephemeral) | Loopback port to listen on. Must match the spec's pinned `redirect_uri` port when one is set. |
| `--timeout` | `3m` | How long to wait for the browser consent callback. |
| `--no-browser` | `false` | Print the authorize URL instead of opening a browser. |
| `--force` | `false` | Replace an existing authorization without confirmation. |

By default the listener binds an ephemeral `127.0.0.1` port; when the spec pins a
`redirect_uri`, the command binds that fixed port instead. Re-running on an
already-connected spec requires `--force`.

## See Also

- [Credentials](/concepts/credentials/) — the source → spec → credential model.
- [Delegation](/concepts/delegation/) — how minted credentials carry the caller's identity.
- [Provider Backends](/provider-backends/) — source/spec configuration per provider.
- [CLI overview](/cli/) — global flags, output formats, exit codes.
