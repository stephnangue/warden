---
name: warden-shared
description: "Foundation: auth env vars, global CLI flags, output framework, exit codes, and the introspection commands every agent uses."
category: shared
---

# Warden foundation for agents

Read this first. Every other skill assumes you know the global flags
and the env vars below.

## Authentication

The agent's identity vehicle (a JWT or an X.509 client certificate)
is **provided by the runtime** that started the agent — the agent
doesn't fetch it from an identity provider. Just read it from the
expected environment slot and pass it to Warden. Internal Warden
tokens (the `X-Warden-Token` form) are for operators; agents don't
issue them and don't need to.

| Vehicle | How the agent presents it |
|---|---|
| JWT (bearer) | `WARDEN_TOKEN=eyJ…` — the CLI auto-detects the JWT prefix and sends `Authorization: Bearer <jwt>` so identity-introspection endpoints (`warden roles`) work |
| mTLS client cert | `WARDEN_CLIENT_CERT=<pem-path>` and `WARDEN_CLIENT_KEY=<pem-path>` |

The Warden server address is `WARDEN_ADDR=https://...` and is
**also provided by the runtime** — the agent shouldn't hard-code it.
Read it from the env and use it as a base URL.

Namespace scope is `WARDEN_NAMESPACE=<ns>` (or `-n` per call). All
introspection calls (`warden roles`, `warden list sys/providers`)
and all provider calls are scoped to this namespace; without it you
land in the root namespace, which usually has none of the providers
you need. The operator tells you which namespace to use.

## Global CLI flags

Every command honors these. Each has an env var fallback.

| Flag | Env var | What it does |
|---|---|---|
| `-o`, `--output` | `WARDEN_OUTPUT` | `table` (TTY default) / `json` (pipe default) / `ndjson` / `text` |
| `-F`, `--fields` | `WARDEN_FIELDS` | comma-separated dot-paths to project (`name,metadata.created_at`) |
| `-n`, `--namespace` | `WARDEN_NAMESPACE` | namespace scope for the request |
| `-r`, `--role` | `WARDEN_ROLE` | role to assume for the request |

Defaults are TTY-aware: `--output=json` automatically when stdout is
piped, so `warden read foo | jq` works without flags.

## Introspection commands

Live, server-rendered. Prefer these over any cached knowledge.

| Command | Returns |
|---|---|
| `warden roles -o json` | `[{name, description, auth_path}]` for every role your identity can assume in the current namespace |
| `warden list sys/providers -o json` | `{ <mount>: {type, description, accessor, config} }` for every provider in the namespace |
| `warden read sys/providers/<mount>` | the same record for one mount (config has sensitive fields masked) |

## Exit codes and error envelopes

In `--output=json|ndjson` modes every failure produces a structured
envelope on stderr:

```json
{"error": {"code": "<code>", "message": "<msg>", "hint": "<actionable hint>"}}
```

The `code` strings and exit codes are stable:

| Exit | Code | Meaning |
|---:|---|---|
| `0` | — | success |
| `1` | `unknown` | uncategorized |
| `2` | `usage` | bad flag combination, missing args, unknown flag |
| `3` | `invalid_input` | payload validation failed (path traversal, type mismatch, unknown field, …) |
| `4` | `auth_required` | missing or invalid token / cert / JWT |
| `5` | `forbidden` | identity OK but policy denies |
| `6` | `not_found` | path / resource doesn't exist |
| `7` | `network` | transport-level failure (timeout, refused, TLS) |
| `8` | `server` | 5xx from upstream |
| `9` | `conflict` | resource already exists, name collision |

Branch on `code` for retryable categories (`auth_required` →
re-authenticate; `network` → backoff + retry; `not_found` /
`forbidden` → ask an operator).

## Sensitive fields

`warden schema <mount>/<path> -o json` marks parameters with
`sensitive: true`. Never log a payload that contains those values.
Read responses also have sensitive fields masked server-side, but
treat any field that *was* sensitive on input as secret regardless of
how you got it back.
