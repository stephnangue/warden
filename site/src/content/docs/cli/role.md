---
title: "role"
---

Discover the [roles](/concepts/roles/) the presented identity can assume. A
role selects the policies and credential a request runs with; pass one on any
command with the global `-r/--role` flag (or `WARDEN_ROLE`).

## Usage

```text
warden role <subcommand> [options]
```

Global flags apply to every subcommand — see the [CLI overview](/cli/#global-flags).

## Subcommands

| Subcommand | Description |
|---|---|
| `list` | List the roles the presented identity can assume. |

### `role list`

List the roles available to the caller. The server fans out to every auth mount
matching the caller's identity type (JWT or certificate) in the current namespace
and returns the union of roles each mount reports the identity can assume.

**Usage:** `warden role list`

```bash
warden role list
warden role list -o json
```

Introspection identifies the caller from the credential itself, so it requires a
**JWT bearer token or a TLS client certificate** — a plain session token isn't
enough. Present a JWT via `WARDEN_TOKEN` (any value beginning with `eyJ` is sent
as `Authorization: Bearer`) or configure `WARDEN_CLIENT_CERT` / `WARDEN_CLIENT_KEY`
for mTLS, and set `-n/--namespace` as needed before running.

## See Also

- [Roles](/concepts/roles/) — how a role selects policies and a credential.
- [Authentication](/concepts/authentication/) — how the identity is established.
- [CLI overview](/cli/) — global flags, output formats, exit codes.
