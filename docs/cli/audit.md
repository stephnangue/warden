# `warden audit`

Manage [audit devices](../audit-devices/README.md) — the backends that log every
request and response for compliance and forensics.

> **Fail-closed at serve time:** once any audit device is registered, every
> request must be successfully audited or it is rejected. Disabling the *last*
> device is **not** blocked, though — it drops the server to zero registered
> devices, which fails *open* (serves unaudited) so a fresh cluster can bootstrap
> one. Re-enable a device promptly. Devices declared in HCL config cannot be
> disabled via the API.

## Table of Contents

- [Usage](#usage)
- [Subcommands](#subcommands)
- [`audit enable`](#audit-enable)
- [`audit list`](#audit-list)
- [`audit read`](#audit-read)
- [`audit disable`](#audit-disable)
- [See Also](#see-also)

## Usage

```text
warden audit <subcommand> [options]
```

Global flags apply to every subcommand — see the [CLI overview](README.md#global-flags).

## Subcommands

| Subcommand | Description |
|---|---|
| `enable TYPE` | Enable an audit device. |
| `list` | List enabled audit devices. |
| `read [PATH]` | Show one device's configuration. |
| `disable [PATH]` | Disable an audit device. |

### `audit enable`

Enable an audit device of the given `TYPE` (currently only `file`). Each device
is assigned a unique HMAC salt for hashing sensitive values in the log; the salt
is generated on enable and lost on disable.

> `--path` is the device's **mount path**; `--file-path` is the **audit log file
> location**. They are distinct.

**Usage:** `warden audit enable [options] TYPE`

**Examples:**

```bash
# File device writing to a log path
warden audit enable --file-path=/var/log/warden-audit.log file

# Custom mount path
warden audit enable --path=prod-audit --file-path=/var/log/audit.log file

# Agent-friendly: full JSON payload
warden audit enable file --json @audit-file.json
cat audit-file.json | warden audit enable file --json -
```

**Flags:**

| Flag | Default | Description |
|---|---|---|
| `--description` | *(none)* | Human-friendly description of the device. |
| `--file-path` | *(none)* | Path to the audit log file (required for the `file` type). |
| `--format` | `json` | Log format (currently only `json` is supported). |
| `--path` | `TYPE` | Custom mount path. |
| `-j`, `--json` | *(none)* | Full JSON payload: `<json>`, `@file.json`, or `-` for stdin. Mutually exclusive with the typed flags. |

If the JSON payload carries a `type` field it must match `TYPE`. Combine with
`-D/--dry-run` to validate without enabling.

### `audit list`

List the enabled audit devices.

**Usage:** `warden audit list`

```bash
warden audit list
```

### `audit read`

Show the configuration of the audit device at `PATH`.

**Usage:** `warden audit read [PATH]`

```bash
warden audit read file/
```

### `audit disable`

Disable the audit device at `PATH`. Disabling the last device is allowed — the
server then runs unaudited until you re-enable one. Only devices declared in HCL
config are rejected (remove the block from the server config instead).

**Usage:** `warden audit disable [PATH]`

```bash
warden audit disable file/
```

## See Also

- [Audit Devices](../audit-devices/README.md) — overview and the file device guide.
- [Audit Attribution](../use-cases/audit-attribution.md) — what the log captures and why.
- [CLI overview](README.md) — global flags, output formats, exit codes.
