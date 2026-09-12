---
title: "protected-resource"
description: "Publish RFC 9728 protected resource metadata so a client knows where to authenticate a user."
---

Configure the **protected resource metadata** Warden publishes for its mounts, per
[RFC 9728](https://www.rfc-editor.org/rfc/rfc9728). A client that receives a `401` with a
`WWW-Authenticate: Bearer` challenge reads this document to discover *which authorization
server* to send the user to, then retries with a user credential.

It is the discovery half of the [user principal](/concepts/delegation/): a policy
condition that requires a user answers `401` with a `resource_metadata` parameter pointing
at one of these documents, so the client can complete the exchange without out-of-band
configuration.

Each mount with a `user_auth_path` gets a document at:

```text
/.well-known/oauth-protected-resource/v1/<namespace>/<mount>
```

Configuration is **deployment-wide** and **root-namespace only** — one setting describes
how the whole deployment is reached.

## Usage

```text
warden protected-resource <subcommand> [options]
```

Global flags apply to every subcommand — see the [CLI overview](/cli/#global-flags).

## Subcommands

| Subcommand | Description |
|---|---|
| `configure` | Set the metadata configuration. Writes are partial. |
| `read` | Print the current configuration. |
| `disable` | Stop publishing the documents. |

### `protected-resource configure`

**Usage:** `warden protected-resource configure [flags]`

| Flag | Description |
|---|---|
| `-resource-url` | The master switch. The external HTTPS address clients actually reach Warden at. |
| `-authorization-server` | Override the issuer advertised for a mount. Repeatable. |
| `-documentation` | A documentation URL to advertise alongside the metadata. |
| `-cache-ttl` | How long clients may cache a document. |
| `-json` | Full JSON payload; mutually exclusive with the typed flags. |

```bash
warden protected-resource configure -resource-url=https://warden.example.com
```

Writes are **partial** — a flag you omit keeps its stored value. Combine with `-dry-run`
to preview the request without sending it.

:::caution[`resource-url` must be the address clients really use]
Each document's `resource` field is this URL joined with the mount's API path, and clients
compare it **literally** against the resource they are calling. Warden deliberately never
derives it from a request's `Host` header, which the client controls — so a wrong value
here produces documents every client rejects.
:::

Leave `-authorization-server` unset in the usual case: Warden derives each mount's issuer
from the auth method at that mount's `user_auth_path`. Set it only when the derived value
is wrong — an identity provider behind a proxy, say, where the issuer clients must reach
differs from the one Warden talks to.

```bash
warden protected-resource configure \
  -resource-url=https://warden.example.com \
  -documentation=https://docs.example.com/mcp \
  -cache-ttl=1h
```

The same write as a JSON payload:

```bash
warden protected-resource configure -json '{
  "resource_url": "https://warden.example.com",
  "documentation": "https://docs.example.com/mcp",
  "cache_ttl": "1h"
}'
```

### `protected-resource read`

**Usage:** `warden protected-resource read`

```bash
warden protected-resource read
```

### `protected-resource disable`

Stops publishing the documents. The mounts keep working — only discovery goes away, so a
client that receives a `401` has no machine-readable way to find the authorization server.

**Usage:** `warden protected-resource disable`

```bash
warden protected-resource disable
```

## See Also

- [Delegation](/concepts/delegation/) — the user principal and the `401` challenge that
  points here.
- [Authentication](/concepts/authentication/) — how the two credentials arrive on one
  request.
- [CEL Conditions](/concepts/cel-conditions/#8-require-a-user-behind-the-agent) — writing a
  condition that requires a user.
