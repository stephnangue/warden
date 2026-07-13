---
name: troubleshooting
description: "Common agent failures on Warden: what each error means, what to retry, and what means 'ask the operator'."
category: shared
requires: []
---

# Troubleshooting

You reach Warden two ways: the **discovery** MCP server (`/v1/sys/mcp`,
tools `list_roles` and `get_skill`) and the **gateways** that do the work
(an MCP gateway pre-attached to your MCP client, or a non-MCP gateway you
call over HTTP). Errors surface as MCP tool errors or HTTP status codes —
branch on those, not on prose.

## Discovery errors (`list_roles` / `get_skill`)

| Symptom | Meaning | Action |
|---|---|---|
| `list_roles` errors: *"requires a JWT bearer token or TLS client certificate"* | no identity reached the endpoint | the identity is configured on the MCP client connection (the `Authorization` header set at attach time); it is missing or the JWT expired — refresh/re-attach |
| `list_roles` returns an empty list | your identity is bound to no role in this namespace | ask the operator to bind your identity; don't guess role names |
| `get_skill` returns *skill "&lt;x&gt;" not found* | no provider of that type is enabled, or the name is wrong | the capability doesn't exist — surface it, don't fabricate an endpoint. The name is the one embedded in a role's description |

Discovery authorizes on identity alone (no role), so a failure here is
almost always the presented credential, not a policy.

## Gateway errors (doing the work)

Whether you drive an MCP gateway (via the tools your client already exposes)
or a non-MCP gateway over HTTP, the authorization model is the same — the
role's policy decides. Branch on the status:

| Status | Meaning | Retry? |
|---|---|---|
| **401** (or MCP *"unauthorized"*) | identity missing or **JWT expired** (typical TTL 5–60 min; agents that hold a token for hours WILL hit this) | yes, after refreshing the token / re-attaching |
| **403** with `WWW-Authenticate: Bearer` and an `error_description` naming a tool/method | the role's policy doesn't allow that call | only after switching to a role whose description matches the operation; if none fits, ask the operator — don't escalate |
| **404** | wrong gateway URL, mount, or namespace | no — re-read the gateway URL from the role's description (non-MCP) or the client config (MCP) before retrying |
| **5xx** | Warden or the upstream failed; the body often carries the upstream's text verbatim | bounded retry with backoff on transient upstream errors; a genuine Warden 500 is a bug to report |

**Policy-filtered `tools/list`:** an MCP gateway lists only the tools the
role allows. Fewer tools than you expected is not an error — it *is* the
role's grant. If the tool you need isn't listed, that role can't call it.

**SigV4 providers (AWS, Scaleway S3):** a stale JWT surfaces upstream as
`SignatureDoesNotMatch`, not 401, because the SDK signed with a
now-rejected token. Same fix: refresh and retry.

## Sensitive-field handling

Treat any value that was sensitive on the way in as secret on the way out —
never log request bodies or echo credentials into your context; responses
are masked server-side, but a leaked input can still surface.
