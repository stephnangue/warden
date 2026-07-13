---
name: rest
description: "Call an arbitrary single-token REST API through Warden — the specific upstream is set by the operator per mount; identify it from the mount's description, never from the provider type."
category: provider-guide
provider: rest
requires: []
upstream: Operator-defined (see the mount description)
---

# A REST API through Warden

## What it does

Warden proxies requests to a single-token REST API. The agent calls a
Warden URL; Warden authenticates the caller (JWT/cert), looks up the
upstream token bound to the chosen role, injects it into the header the
operator configured, and forwards the request. The agent **never holds
the upstream token**.

## Which upstream is this?

The `rest` type is **generic** — one mount fronts Stripe, another fronts
an internal billing API, another fronts Algolia. You **cannot** tell the
upstream from the provider type, and you **must not** guess it from the
mount path or config.

Read the role's **`description`** from the `list_roles` discovery tool
to learn:
- which service this mount proxies, and
- its base path / which API routes are in scope.

If the description does not make the upstream clear, stop and ask — do not
assume. Two `rest` mounts are interchangeable only if their descriptions
say so.

## Configure the CLI/SDK

`<gateway-url>` comes from the role you chose: the `list_roles` discovery tool
returns each role with a `description`, and for a non-MCP provider the operator
embeds the role's **gateway URL** in it — a relative path
`/v1/<namespace>/<mount>/role/<role>/gateway/`, with the namespace, mount, and role already baked in. Prepend `$WARDEN_ADDR` (the address you already
used to discover your roles).

The `role/<role>/` segment in `<gateway-url>` is the role this call runs under.
To act under a *different* role, use the `<gateway-url>` of that role from
`list_roles` — each role provides its own role-bearing URL in its description.

Present your identity on every call: `Authorization: Bearer <jwt>`, or an mTLS
client certificate. A `401` means the JWT expired (typical TTL 5–60 min) —
refresh and retry.

```
URL pattern : $WARDEN_ADDR<gateway-url><upstream-path>
Auth header : Authorization: Bearer <jwt>
```

Rewrite the upstream host to
`$WARDEN_ADDR<gateway-url>` and add your Warden token as
the bearer. Everything after `/gateway/` — path, query string, method,
body — is forwarded verbatim to the upstream. Warden injects the upstream
credential for you; do not send the upstream's own token.

## Examples

(Examples use a concrete `<gateway-url>` of `/v1/billing-api/role/finance/gateway/`,
fronting an internal REST API per its description; substitute the one from your
role's `list_roles` description.)

GET a resource:
```bash
curl -H "Authorization: Bearer <jwt>" \
  $WARDEN_ADDR/v1/billing-api/role/finance/gateway/v1/invoices?status=open
```

POST a resource:
```bash
curl -X POST -H "Authorization: Bearer <jwt>" \
  -H "Content-Type: application/json" \
  -d '{"customer":"acme","amount":4200}' \
  $WARDEN_ADDR/v1/billing-api/role/finance/gateway/v1/invoices
```

If the operator pinned extra headers (tenant id, API version, app id) on
the mount, Warden adds them automatically — you do not send them.

## Notes

- All HTTP methods and status codes pass through unchanged; handle the
  upstream's native error bodies as documented by that upstream.
- 401 from Warden (not the upstream) means the caller/role isn't allowed
  or no upstream credential is bound to the role — re-check discovery.
