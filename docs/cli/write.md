# `warden write`

Write data to any path on the server. `write` is the generic counterpart to the
typed commands — it works against provider, auth, and `sys` paths and accepts data
in several forms.

## Usage

```text
warden write [PATH] [DATA...]
```

The `PATH` may be given positionally or via `--path` — pick one. When `--path` is
used, all remaining positional arguments are treated as `DATA`.

**Path format:** `provider_mount/resource`, `auth/auth_mount/resource`, or
`sys/path/to/resource`.

## Data forms

`DATA` can be supplied three ways:

**JSON via stdin**

```bash
warden write aws/config <<EOF
{
  "proxy_domains": ["localhost", "warden"],
  "max_body_size": 10485760,
  "timeout": "60s"
}
EOF
```

**`key=value` pairs** (types are inferred — numbers, booleans, and JSON
arrays/objects are parsed; everything else is a string)

```bash
warden write aws/config token_ttl=1h proxy_domains='["localhost","warden"]'
warden write --path=aws/config token_ttl=1h
```

**`@file` references** read a value from a file — handy for PEM certificates and
large payloads

```bash
warden write auth/cert/config trusted_ca_pem=@/path/to/ca.pem default_role=my-role
```

## Flags

| Flag | Default | Description |
|---|---|---|
| `--path` | *(none)* | API path (alternative to the positional `PATH`). |

Combine with `-D/--dry-run` to validate the payload against the server schema
without writing.

## See Also

- [`warden read`](read.md) · [`warden list`](list.md) · [`warden delete`](delete.md) — the rest of the generic data family.
- [`warden schema`](schema.md) — inspect what fields a path accepts.
- [Dry run](README.md#dry-run) — catch bad parameters before they hit the wire.
- [CLI overview](README.md) — global flags, output formats, exit codes.
