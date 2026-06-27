# Warden CLI

The `warden` binary is both the server and the client. As a client, every
command talks to a running Warden server over its HTTP API, authenticates the
caller, and renders the response. This page covers the behaviour shared by every
command — how to reach a server, the global flags, environment variables, output
formats, and exit codes — then indexes the per-command reference pages.

For what the server *does* with these calls, see [Concepts](../concepts/README.md).

## Table of Contents

- [Connecting to a server](#connecting-to-a-server)
- [Global flags](#global-flags)
- [Environment variables](#environment-variables)
- [Output formats](#output-formats)
- [Field projection](#field-projection)
- [Dry run](#dry-run)
- [Exit codes](#exit-codes)
- [Command index](#command-index)
- [See Also](#see-also)

## Connecting to a server

Two environment variables decide which server a command talks to and as whom:

| Variable | Default | Purpose |
|---|---|---|
| `WARDEN_ADDR` | `http://127.0.0.1:8400` | URL of the Warden server. May be `http://`, `https://`, or a `unix://` socket. |
| `WARDEN_TOKEN` | *(none)* | The credential presented on each request. |

```bash
export WARDEN_ADDR=https://warden.example.com:8400
export WARDEN_TOKEN=s.xxxxxxxxxxxxxxxxxxxx
warden status
```

There is no `login` subcommand and no `~/.warden-token` file — the token is read
from the environment. A first token comes from [`warden operator init`](operator.md),
which prints a root token and an `export WARDEN_TOKEN=…` line to paste.

`WARDEN_TOKEN` accepts two credential shapes. A Warden session token is sent in
the `X-Warden-Token` header. A **JWT** (any value beginning with `eyJ`) is instead
sent as `Authorization: Bearer …`, so the server's transparent-auth path can
resolve it against the namespace's configured auth method. mTLS is also supported
— set `WARDEN_CLIENT_CERT` / `WARDEN_CLIENT_KEY` and the server authenticates the
client certificate directly. See [Authentication](../concepts/authentication.md).

## Global flags

These persistent flags are accepted by every command. Each has an environment
variable equivalent; the flag wins when both are set.

| Flag | Env | Description |
|---|---|---|
| `-n`, `--namespace` | `WARDEN_NAMESPACE` | [Namespace](../concepts/namespaces.md) to scope the command to. |
| `-r`, `--role` | `WARDEN_ROLE` | [Role](../concepts/roles.md) to assume for the command. |
| `-o`, `--output` | `WARDEN_OUTPUT` | Output format: `table`, `json`, `ndjson`, or `text`. |
| `-F`, `--fields` | `WARDEN_FIELDS` | Comma-separated dot-paths to project from structured output. |
| `-D`, `--dry-run` | `WARDEN_DRY_RUN` | Validate the payload locally against the server schema and exit without sending. |

Single-dash long flags are accepted as well as double-dash (`-namespace` and
`--namespace` are equivalent), matching the Vault/OpenBao CLI convention used
throughout these docs.

## Environment variables

Beyond the global-flag variables above, the client reads the following. All are
optional; defaults apply when unset.

**Connection & identity**

| Variable | Default | Purpose |
|---|---|---|
| `WARDEN_ADDR` | `http://127.0.0.1:8400` | Server URL. |
| `WARDEN_TOKEN` | *(none)* | Auth token (session token or JWT). |
| `WARDEN_NAMESPACE` | *(none)* | Namespace scope (`X-Warden-Namespace` header). |
| `WARDEN_ROLE` | *(none)* | Role to assume (`X-Warden-Role` header). |

**TLS**

| Variable | Default | Purpose |
|---|---|---|
| `WARDEN_CACERT` | *(none)* | Path to a PEM CA certificate to verify the server. |
| `WARDEN_CACERT_BYTES` | *(none)* | PEM CA certificate as an inline string. |
| `WARDEN_CAPATH` | *(none)* | Path to a directory of PEM CA certificates. |
| `WARDEN_CLIENT_CERT` | *(none)* | Path to a client certificate for mTLS. |
| `WARDEN_CLIENT_KEY` | *(none)* | Path to the client private key for mTLS. |
| `WARDEN_SKIP_VERIFY` | `false` | Disable TLS verification (insecure; testing only). |
| `WARDEN_TLS_SERVER_NAME` | *(none)* | SNI server name for the TLS handshake. |

**Networking**

| Variable | Default | Purpose |
|---|---|---|
| `WARDEN_CLIENT_TIMEOUT` | `60s` | Per-request timeout. |
| `WARDEN_MAX_RETRIES` | `0` on the CLI | Retries on 5xx / 429 / 412. The CLI disables retries unless this is set. |
| `WARDEN_SRV_LOOKUP` | `false` | Resolve the server address via DNS SRV records. |
| `WARDEN_HTTP_PROXY` | *(none)* | HTTP(S) proxy URL. |
| `WARDEN_PROXY_ADDR` | *(none)* | Proxy URL; supersedes `WARDEN_HTTP_PROXY`. |
| `WARDEN_RATE_LIMIT` | *(none)* | Client-side rate limit, `rate[:burst]` (e.g. `10.5:20`). |

## Output formats

Structured commands render in one of four formats:

| Format | Shape |
|---|---|
| `table` | Human-readable table. **Default when stdout is a terminal.** |
| `json` | Pretty-printed JSON. **Default when stdout is not a terminal** (pipes, files). |
| `ndjson` | One JSON record per line — stream-friendly for `jq` and agents. |
| `text` | Logfmt-style `key=value` lines. |

Resolution order: the `-o/--output` flag, then `WARDEN_OUTPUT`, then TTY
autodetect. Because non-TTY defaults to `json`, piping any command already yields
machine-readable output without a flag:

```bash
warden auth list                  # table on your terminal
warden auth list | jq '.[].type'  # json when piped
warden status -o json
```

## Field projection

`-F/--fields` (or `WARDEN_FIELDS`) narrows structured output to a comma-separated
list of dot-paths. `*` is a wildcard over every key of a map or element of a list.
Paths that don't match are silently omitted.

```bash
warden status -o json -F sealed,is_leader,leader_address
warden read aws/config -o json -F proxy_domains,timeout
warden auth list -o json -F '*.type'
```

Projection applies to `json`, `ndjson`, and `text`. In `table` mode it falls back
to a generic key/value layout and prints a hint to use `-o json` for the
structured form.

## Dry run

`-D/--dry-run` (or `WARDEN_DRY_RUN`) validates a mutating command's payload
against the server's published schema (`/v1/sys/schema`) and exits **without
sending the request**. It catches unknown or mistyped parameters before they hit
the wire — useful in CI and for agents composing requests. Supported by the
write/create/enable/tune family and by `delete` (which also skips its confirmation
prompt under dry-run).

```bash
warden provider enable aws -D
warden write aws/config token_ttl=1h -D
```

## Exit codes

Every invocation exits with a stable, category-based code. Agents and scripts can
branch on these without parsing stderr; in `json`/`ndjson` mode failures also emit
a `{"error":{"code":…,"message":…,"hint":…}}` envelope on stderr.

| Code | Name | Meaning |
|---|---|---|
| 0 | OK | Success. |
| 1 | Unknown | Uncategorised error. |
| 2 | Usage | CLI usage error (unknown flag, bad arg count). |
| 3 | InvalidInput | Validation error / unprocessable 4xx. |
| 4 | Auth | Authentication required (HTTP 401). |
| 5 | Forbidden | Access denied (HTTP 403). |
| 6 | NotFound | Resource not found (HTTP 404). |
| 7 | Network | Transport error (DNS, refused, timeout, TLS). |
| 8 | Server | Server error (HTTP 5xx). |
| 9 | Conflict | Resource conflict (HTTP 409). |
| 10 | Sealed | Warden is sealed or uninitialized. |

## Command index

### Server & operations

| Command | Description |
|---|---|
| [`server`](server.md) | Start a Warden server. |
| [`status`](status.md) | Show initialization, seal, and HA state. |
| [`operator`](operator.md) | Administrative operations — initialize and generate a root token. |

### Auth, audit & policy

| Command | Description |
|---|---|
| [`auth`](auth.md) | Manage auth methods (enable, disable, list, read). |
| [`audit`](audit.md) | Manage audit devices (enable, disable, list, read). |
| [`policy`](policy.md) | Manage capability-based policies. |

### Providers & credentials

| Command | Description |
|---|---|
| [`provider`](provider.md) | Manage providers (enable, disable, list, read, tune). |
| [`cred`](cred.md) | Manage credential specs and sources. |

### Namespaces & roles

| Command | Description |
|---|---|
| [`namespace`](namespace.md) | Manage namespaces. |
| [`role`](role.md) | Discover roles the presented identity can assume. |

### Skills & schema

| Command | Description |
|---|---|
| [`skill`](skill.md) | Manage the global agent skill registry. |
| [`schema`](schema.md) | Inspect the server's OpenAPI schema. |

### Generic data access

| Command | Description |
|---|---|
| [`read`](read.md) | Read data from a path. |
| [`write`](write.md) | Write data to a path. |
| [`list`](list.md) | List data at a path. |
| [`delete`](delete.md) | Delete data at a path. |
| [`path-help`](path-help.md) | Show backend-provided help for a path. |

## See Also

- [Concepts](../concepts/README.md) — how Warden works, end to end.
- [Auth Methods](../auth-methods/README.md) — per-method setup guides.
- [Provider Backends](../provider-backends/README.md) — per-provider setup guides.
- [Audit Devices](../audit-devices/README.md) — audit logging configuration.
