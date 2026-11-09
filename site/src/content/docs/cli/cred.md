---
title: "cred"
---

Manage [credentials](/concepts/credentials/) — the **sources** Warden draws
from and the **specs** that shape what gets minted and injected into a proxied
request. A source holds the upstream connection and how Warden authenticates to it —
a keyless federation trust, a secret chained from your own store, or a stored root
credential; a spec binds to a source and defines type, TTLs, and rotation. The `cred` command groups two
subcommand families: `cred source` and `cred spec`.

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
| `keyless-plan <name>` | Print the keyless replacement for a source that stores a secret, and for its specs. Writes nothing. See [keyless-plan](#keyless-plan). |

`read` and `list` show **Stored Secrets** — the names of the secret fields a source
holds (`stored_secrets` in JSON output), or `none`. Values are never shown: a secret
field reads back masked, and one an update cleared reads back as `""`.

### `cred source create`

**Usage:** `warden cred source create <name> [flags]`

```bash
warden cred source create my-aws \
    --type=aws \
    --config=auth_method=oidc_federation \
    --config=region=us-east-1

# Agent-friendly: full JSON payload
warden cred source create my-aws -json '{
  "type": "aws",
  "config": {
    "auth_method": "oidc_federation",
    "region": "us-east-1"
  }
}'
```

A write that would leave a secret stored in Warden — an inline access key, say — returns
a warning under `warnings`, or is refused when the server runs with
[`keyless_enforcement_level=enforce`](/federation/keyless-credentials/#keyless-enforcement).

| Flag | Default | Description |
|---|---|---|
| `--type` | *(none)* | Source type (required unless `--json`). |
| `--config` | *(none)* | Source configuration `KEY=VALUE`; repeatable. Values may use `@file`. |
| `--rotation-period` | *(none)* | Rotation period for the source's stored root credential, e.g. `24h`. Required by some source types (such as an AppRole-backed `hvault`); refused on a federated (`oidc_federation`) source. |
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
| `keyless-plan <name>` | Print the keyless replacement for a spec that stores its own secret. Writes nothing. See [keyless-plan](#keyless-plan). |

`read` and `list` show **Stored Secrets**, as for sources.

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

Consent seals a refresh token into the spec, so it stores a secret in Warden: under
`keyless_enforcement_level=enforce`, `connect` is refused before the provider is
reached.

## `keyless-plan`

Plan the move off a stored secret. Nothing is written: the plan prints the upstream
trust to set up, the keyless objects to create **next to** the keyed ones, the role
changes, and what to delete once roles use the new objects. Until then the keyed objects
keep working, so there is nothing to roll back.

**Usage:**

```text
warden cred source keyless-plan <name> [flags]
warden cred spec   keyless-plan <name> [flags]
```

A **source** plan covers the source and every spec bound to it, through federation
(`aws`, `azure`, `gcp`, `alicloud`, `kubernetes`, `hvault`) or chaining (`elastic`,
`grafana`, `ibm`, `ovh`, `scaleway`, `gitlab`, `oauth2`, `token_exchange`). A **spec**
plan covers a spec that stores its own secret, replacing it with one that fetches the
secret through `secret_spec`.

```bash
warden cred source keyless-plan aws-prod

# Inputs the plan cannot derive, for the source and for a bound spec
warden cred source keyless-plan vault-prod -json '{
  "new_name": "vault-wif",
  "target": {
    "jwt_role": "warden",
    "audience": "vault"
  },
  "specs": {
    "app-db": {
      "name": "app-db-wif"
    }
  }
}'

warden cred spec keyless-plan github-pat -json '{
  "target": {
    "secret_spec": "github-pat-from-vault"
  }
}'
```

| Flag | Default | Description |
|---|---|---|
| `--new-name` | `<name>-keyless` | Name for the keyless source or spec. |
| `--input` | *(none)* | An input for the keyless source or spec, `KEY=VALUE`; repeatable. |
| `--spec-input` | *(none)* | Source plans only: an input for a bound spec, `<spec>/<key>=<value>`; its `name` key names the spec's replacement. |
| `-j`, `--json` | *(none)* | The whole request — `new_name`, `target`, `specs` — as `<json>`, `@file.json` or `-`. Mutually exclusive with the other flags. |

A plan that needs more from you is **blocked**, and lists what it needs under
**Blockers**; it is ready when there are none. Secret fields are refused as inputs: a
keyless object never sets one.

## See Also

- [Credentials](/concepts/credentials/) — the source → spec → credential model.
- [Delegation](/concepts/delegation/) — how minted credentials carry the caller's identity.
- [Provider Backends](/provider-backends/) — source/spec configuration per provider.
- [CLI overview](/cli/) — global flags, output formats, exit codes.
