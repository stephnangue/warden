---
title: "provider"
---

Manage [providers](/concepts/providers/) — the mounted gateways that front an
upstream system (an LLM API, a cloud control plane, a Git host, …). Use these
subcommands to mount, inspect, retune, and unmount a provider. The upstream
connection details and credential wiring are configured by writing to the mount's
paths; see the [provider backend guides](/provider-backends/).

## Table of Contents

- [Usage](#usage)
- [Subcommands](#subcommands)
- [`provider enable`](#provider-enable)
- [`provider list`](#provider-list)
- [`provider read`](#provider-read)
- [`provider tune`](#provider-tune)
- [`provider disable`](#provider-disable)
- [See Also](#see-also)

## Usage

```text
warden provider <subcommand> [options]
```

Global flags apply to every subcommand — see the [CLI overview](/cli/#global-flags).

## Subcommands

| Subcommand | Description |
|---|---|
| `enable TYPE` | Mount a provider. |
| `list` | List enabled providers. |
| `read [PATH]` | Show one provider's configuration. |
| `tune [PATH]` | Update a provider's description. |
| `disable [PATH]` | Unmount a provider. |

### `provider enable`

Mount a provider of the given `TYPE` (`aws`, `azure`, `gcp`, `anthropic`,
`github`, …). The mount path defaults to `TYPE`; override it with `--path` to run
several mounts of the same type.

**Usage:** `warden provider enable [options] TYPE`

**Examples:**

```bash
warden provider enable aws
warden provider enable --path=azure-prod azure
warden provider enable --description="Production AWS" aws

# Agent-friendly: full JSON payload
warden provider enable aws --json @provider-aws.json
cat provider-aws.json | warden provider enable aws --json -
```

**Flags:**

| Flag | Default | Description |
|---|---|---|
| `--description` | *(none)* | Human-friendly description of the mount. |
| `--path` | `TYPE` | Custom mount path. |
| `-j`, `--json` | *(none)* | Full JSON payload: `<json>`, `@file.json`, or `-` for stdin. Mutually exclusive with `--description`. |

> The mount **description** is significant: multi-product provider types (e.g. the
> MCP provider) are identified by their operator-set description, so set it
> meaningfully. See the relevant provider guide.

### `provider list`

List the enabled providers.

**Usage:** `warden provider list`

```bash
warden provider list
```

### `provider read`

Show the configuration of the provider at `PATH`, including its type, accessor,
mount URL, and config.

**Usage:** `warden provider read [PATH]`

```bash
warden provider read aws/
```

### `provider tune`

Update the description of an existing provider. This is a partial update: omitting
`--description` leaves the current value unchanged, while `--description=""`
clears it.

**Usage:** `warden provider tune [options] [PATH]`

```bash
warden provider tune aws/ --description="Production AWS"
warden provider tune aws/ --json @tune.json
```

**Flags:**

| Flag | Default | Description |
|---|---|---|
| `--description` | *(unchanged)* | New description. |
| `--path` | *(none)* | Mount path (alternative to the positional `PATH`). |
| `-j`, `--json` | *(none)* | Full JSON payload. Mutually exclusive with `--description`. |

### `provider disable`

Unmount the provider at `PATH`.

**Usage:** `warden provider disable [PATH]`

```bash
warden provider disable aws/
```

## See Also

- [Provider Backends](/provider-backends/) — per-provider setup guides.
- [Providers](/concepts/providers/) — the gateway model.
- [Credentials](/concepts/credentials/) — what a provider injects into the proxied request.
- [CLI overview](/cli/) — global flags, output formats, exit codes.
