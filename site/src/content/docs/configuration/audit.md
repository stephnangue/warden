---
title: "Audit"
---

> Server config stanza: `audit "<type>" "<path>"`

An `audit` stanza declares an audit device that is registered **at startup**,
before the API listener accepts traffic. The stanza takes two labels — the device
`type` and a `path` that names it — and may be repeated. See
[Audit](/concepts/audit/) for the audit log model.

```hcl
audit "file" "default" {
  description = "primary file audit"
  options = {
    file_path = "/var/log/warden/audit.log"
  }
}
```

The only device type is `file`.

## Parameters

| Key | Default | Description |
|-----|---------|-------------|
| `description` | *(none)* | Human-readable description of the device. |
| `options` | `{}` | Device-specific settings (see below). |

The `path` label must not contain slashes or spaces, and each `(type, path)` pair
must be unique.

## File device options

Set inside `options = { ... }`:

| Option | Default | Description |
|--------|---------|-------------|
| `file_path` | `warden_audit.log` | Path to the audit log file. |
| `format` | `json` | Log entry format. |
| `prefix` | *(none)* | String prepended to every line. |
| `file_mode` | `0600` | File permission mode. |
| `hmac_key` | *(generated)* | Key used to HMAC sensitive fields. |

Because HCL `options` values are **strings only** in this version, numeric and
boolean knobs — rotation size, daily rotation, backup count, buffer size — cannot
be set here. Tune those through the `sys/audit/{path}` API after startup.

## Startup semantics

- A device declared here is registered **before** the listener accepts traffic. A
  misconfigured sink (unwritable path, missing parent directory, permission
  denied) **fails startup** rather than leaving a half-initialized cluster.
- Config-declared devices **cannot** be modified or deleted through the API — edit
  the file and restart instead. They coexist at different paths with devices
  enabled at runtime via `sys/audit/{path}`.
- With **zero** audit devices the broker fail-opens, so a fresh cluster can serve
  `sys/audit/{path}` long enough to bootstrap one. In production, declare **two or
  more** devices so a single wedged sink cannot lock the cluster out.

## See Also

- [Audit](/concepts/audit/) — the audit log model and HMAC of sensitive fields.
- [File audit device](/audit-devices/file/) — the runtime-managed counterpart.
