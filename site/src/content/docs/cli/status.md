---
title: "status"
---

Show the server's initialization, seal, and HA/cluster state. A thin wrapper over
the server's health endpoint.

## Usage

```text
warden status
```

`status` takes no arguments. It honours the global output and field flags.

## Examples

```bash
warden status
warden status -o json
warden status -o json -F sealed,is_leader,leader_address
```

## Output fields

`initialized`, `sealed`, `standby`, `ha_enabled`, `is_leader`, `server_time`, and
(when reported) `version`. Under HA, `leader_address` and `active_time` are
included when set.

## Exit codes

`status` returns a narrowed set of [exit codes](/cli/#exit-codes) so scripts
can gate on readiness:

| Code | Meaning |
|---|---|
| 0 | Initialized and unsealed (active or standby). |
| 7 | Transport / connection error. |
| 10 | Sealed or uninitialized. |

```bash
warden status >/dev/null 2>&1 && echo "ready" || echo "not ready (exit $?)"
```

## See Also

- [Seal / Unseal](/concepts/seal-unseal/) — what sealed vs. unsealed means.
- [High Availability](/concepts/high-availability/) — leader/standby state.
- [`warden operator init`](/cli/operator/) — initialize an uninitialized server.
- [CLI overview](/cli/) — global flags, output formats, exit codes.
