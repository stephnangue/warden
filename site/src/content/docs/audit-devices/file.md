---
title: "File Audit Device"
---

The **file** device writes the audit log to a local file, one JSON object per line.
Writes are buffered for throughput and flushed on an interval, and the file rotates
by size, by day, or both, with old files pruned automatically. It is the device you
reach for when you want a durable on-disk trail you can tail during an incident,
rotate with your usual tooling, and ship to a SIEM or log collector.

This page is the operational guide: how to enable the device, every configuration
key it accepts, how rotation and retention behave, and how to troubleshoot it. For
*what* ends up in each entry — the request/response fields, HMAC salting of
secrets, and the fail-open→fail-closed guarantee — see the
[Audit](/concepts/audit/) concept page.

Audit devices are a **root-namespace, operator-level** concern: they are global,
and every namespace's traffic is logged to the same set of devices.

## Contents

- [Enable it](#enable-it)
  - [CLI](#cli)
  - [Declarative (HCL)](#declarative-hcl)
  - [HTTP API](#http-api)
- [Configuration reference](#configuration-reference)
- [Rotation and retention](#rotation-and-retention)
- [Salting and omission](#salting-and-omission)
- [Troubleshooting](#troubleshooting)
- [See Also](#see-also)

## Enable it

A device is identified by its **mount path** (where it lives in `sys/audit/`) and
configured with the keys in the [reference](#configuration-reference) below. The
only required key for the file device is `file_path` — the location of the log file
on disk. Note that the *mount path* and the *file path* are two different things:
the mount path names the device, the file path is where it writes.

There are three ways to enable a device. The CLI and HTTP API create devices at
runtime; HCL declares them in server config and registers them at startup.

### CLI

Enable a file device with the typed flags:

```bash
# Mount path defaults to the type ("file"); -file-path is the log location.
warden audit enable -file-path=/var/log/warden/audit.log file

# A custom mount path, so you can run more than one file device.
warden audit enable -path=prod-audit -file-path=/var/log/warden/audit.log file
```

The `enable` flags are `-file-path`, `-description`, `-format`, `-path`, and
`-json`. For richer configuration (rotation, buffering, salting), pass a full JSON
payload instead of the typed flags — `-json` is mutually exclusive with
`-description` / `-file-path` / `-format`:

```bash
warden audit enable file -json @audit-file.json
cat audit-file.json | warden audit enable file -json -
```

Add `-dry-run` to validate a payload locally without enabling anything. Inspect and
remove devices with:

```bash
warden audit list            # all enabled devices
warden audit read   file/    # one device's config (hmac_key is masked)
warden audit disable file/   # remove a device by mount path
```

### Declarative (HCL)

Declare devices in the server config with the two-label `audit "TYPE" "NAME"`
syntax. The labels are the device type and the mount name:

```hcl
audit "file" "default" {
  description = "primary file audit"
  options = {
    file_path = "/var/log/warden/audit.log"
  }
}
```

A few things specific to declared devices:

- **They register at startup, before the API listener accepts traffic.** A
  misconfigured sink — unwritable path, missing parent directory, permission
  denied — **fails startup** rather than leaving a half-initialized server.
- **They are immutable from the API.** A device declared in HCL cannot be modified
  or deleted via `sys/audit/`; edit the file and restart instead. Declared and
  API-enabled devices coexist at their own mount paths.
- **All `options` values are strings.** Non-string knobs such as `rotate_size` and
  `rotate_daily` are best tuned through the HTTP API (below) for now.
- **Declare at least two devices in production.** With zero devices the server
  fail-opens (so a fresh server can serve `sys/audit/` long enough to bootstrap
  one); a single device that wedges can otherwise block traffic.

### HTTP API

The CLI is a thin wrapper over the `sys/audit/` endpoints, which you can call
directly:

```bash
# Enable (returns the device accessor); config carries the keys below.
curl -X POST "$WARDEN_ADDR/v1/sys/audit/file" \
  -H "X-Warden-Token: $WARDEN_TOKEN" \
  -d '{"type":"file","config":{"file_path":"/var/log/warden/audit.log"}}'

curl "$WARDEN_ADDR/v1/sys/audit/"        # list devices
curl -X DELETE "$WARDEN_ADDR/v1/sys/audit/file"   # disable a device
```

To check whether a known plaintext appears in the log, hash it with a device's salt
via `sys/audit-hash/<path>` and compare against the `hmac-sha256:…` values in the
log:

```bash
warden write sys/audit-hash/file input="AKIA...EXAMPLE"
```

## Configuration reference

These keys go in the CLI `-json` payload, the HTTP `config` object, or — as strings
— an HCL `options` block. Defaults are what the device applies when you omit a key.

| Key | Default | Purpose |
|-----|---------|---------|
| `file_path` | `warden_audit.log` | File to write to. Required; the parent directory must exist and be writable. |
| `file_mode` | `0600` | Octal permissions on the log file. |
| `format` | `json` | Serialization format. Only `json` is supported. |
| `rotate_size` | `104857600` (100 MB) | Rotate when the file reaches this many bytes. `0` disables size-based rotation. |
| `rotate_daily` | `true` | Also rotate at UTC midnight. |
| `max_backups` | `5` | Number of rotated files to keep; older ones are pruned. |
| `buffer_size` | `100` | Entries buffered before a flush. |
| `flush_period` | `5s` | Maximum time between flushes. |
| `hmac_key` | _(auto-generated)_ | The salt key for hashing sensitive fields. Generated if you don't supply one; masked on read. |
| `salt_fields` | `["response.credential.data"]` | Dot-paths to HMAC instead of logging in clear. |
| `omit_fields` | `["request.data","request.headers","response.data","response.headers"]` | Dot-paths to drop entirely. |
| `prefix` | _(none)_ | Optional string prefixed to each log line. |
| `enabled` | `true` | Whether the device is active. |
| `skip_test` | `false` | Skip the write-test performed when the device is created. |

Validation bounds (a value outside these is rejected at enable time):

- `buffer_size`: 1 – 100000
- `flush_period`: 100ms – 1h
- `rotate_size`: 0 – 100 GB (`0` means no size-based rotation)
- `max_backups`: 1 – 1000

## Rotation and retention

The file device rotates on two independent triggers:

- **Size** — when the active file reaches `rotate_size` bytes (default 100 MB). Set
  `rotate_size` to `0` to turn this off.
- **Daily** — when `rotate_daily` is `true` (the default), the file also rotates at
  UTC midnight regardless of size.

On each rotation the active file is rolled to a timestamped backup and a fresh file
is opened. Warden keeps the most recent `max_backups` files (default 5) and prunes
the rest. If you ship logs off-box with an external collector, size the buffer and
backups so a collector hiccup doesn't lose entries before they're forwarded.

## Salting and omission

Two knobs control which fields are protected. See
[Audit → Secrets Are Never Logged in Clear](/concepts/audit/#secrets-are-never-logged-in-clear)
for the reasoning; the operational summary:

- **`salt_fields`** — dot-paths whose values are replaced with
  `hmac-sha256:<hex>` instead of plaintext. The default,
  `response.credential.data`, salts every secret Warden injects (access keys,
  tokens, passwords). Extend it to hash more, e.g. `auth.token_id`,
  `request.data.password`, or the inputs a policy `condition` referenced — a whole
  map (`auth.policy_results.condition.inputs`) or a single key
  (`auth.policy_results.condition.inputs.request.data.model`).
- **`omit_fields`** — dot-paths dropped from the entry entirely. The defaults drop
  request and response bodies and headers, which are noisy and often sensitive.

The hash is deterministic under a given device's key, so the same value always
produces the same hash and you can correlate occurrences without the log revealing
the plaintext. A device's salt is **not preserved across disable→enable** — a
re-enabled device gets a fresh key, so hashes from before no longer correlate.

## Troubleshooting

- **Server won't start after adding an HCL `audit` block.** A declared device that
  can't write fails startup by design. Check that `file_path`'s parent directory
  exists and is writable by the Warden process, and that `file_mode` is a valid
  octal string.
- **`enable` returns an error instead of failing startup.** API- and CLI-created
  devices surface the same write/permission problems as an error response rather
  than a crash — fix the path or permissions and retry.
- **Can't disable a device** (`cannot disable the last audit device`). Once any
  device is enabled, Warden runs fail-closed and refuses to remove the last one,
  which would silently stop auditing. Enable a replacement first, then disable.
- **`hmac_key` reads back masked.** Expected — the salt is never returned. Use
  `sys/audit-hash/<path>` to hash a known value under the device's key.
- **`only 'json' format is supported`.** `format` must be `json`; no other format
  exists yet.

## See Also

- [Audit](/concepts/audit/) — the recording model, HMAC salting, and fail-open/closed.
- [Audit Devices](/audit-devices/) — the section overview.
- [Policies](/concepts/policies/) — the authorization decisions recorded in each entry.
- [Credentials](/concepts/credentials/) — what "credential issued" in the log refers to.
- [High Availability](/concepts/high-availability/) — audit continuity across leader failover.
