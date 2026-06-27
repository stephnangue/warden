# `warden schema`

Inspect the OpenAPI schema of the running server. `schema` hits the server's
schema endpoint and projects the OpenAPI document into a shape that's easy for
both humans and agents to read — the parameters a path accepts, its methods, and
its response shape. It's the machine-readable companion to
[`path-help`](path-help.md), and the same schema backs `-D/--dry-run` validation.

## Usage

```text
warden schema PATH        # describe a single path
warden schema --list      # enumerate every path
```

`PATH` and `--list` are mutually exclusive; one of them is required.

## Examples

```bash
# Describe a single path (friendly projection):
#   { path, methods, description, parameters, response_schema, auth_required }
warden schema sys/auth

# Enumerate every available path (NDJSON-friendly)
warden schema --list

# Raw OpenAPI fragment for tooling (Stainless, openapi-typescript, oapi-codegen)
warden schema sys/auth --raw
```

## Flags

| Flag | Default | Description |
|---|---|---|
| `--list` | `false` | List every path in the schema. Cannot be combined with `PATH`. |
| `--raw` | `false` | Emit the raw OpenAPI fragment instead of the friendly projection. |

## Notes

The endpoint is namespace-scoped: `-n/--namespace` (or `WARDEN_NAMESPACE`)
controls which mounts are visible, so a tenant cannot enumerate another tenant's
backends. Authentication is required — set `WARDEN_TOKEN`, an mTLS client cert, or
pass an `Authorization: Bearer` JWT.

## See Also

- [`warden path-help`](path-help.md) — human-readable help for a path or backend.
- [Dry run](README.md#dry-run) — local payload validation against this schema.
- [CLI overview](README.md) — global flags, output formats, exit codes.
