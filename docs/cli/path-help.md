# `warden path-help`

Display backend-provided help for a path or mount. Where [`schema`](schema.md)
returns the machine-readable OpenAPI projection, `path-help` returns the prose
help a backend ships for itself — gateway behaviour, request format, and
configuration options.

## Usage

```text
warden path-help PATH
```

`PATH` is required. The trailing slash is significant: `aws/` returns the
**backend's overall help**, while `aws/config` returns help for that **specific
path**.

## Examples

```bash
# Backend-level help for the AWS provider
warden path-help aws/

# Help for a specific path
warden path-help aws/config
warden path-help auth/jwt/config

# JSON envelope for agent consumption
warden path-help aws/ -o json
```

## Output

In TTY/table mode the help text is printed verbatim. In `json`/`ndjson`/`text`
mode the response is returned as `{"help": "..."}` so it can be piped into `jq`.

## See Also

- [`warden schema`](schema.md) — the machine-readable schema for a path.
- [Provider Backends](../provider-backends/README.md) — per-provider setup guides.
- [CLI overview](README.md) — global flags, output formats, exit codes.
