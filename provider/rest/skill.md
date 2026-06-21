---
name: rest
description: "Call an arbitrary single-token REST API through Warden — the specific upstream is set by the operator per mount; identify it from the mount's description, never from the provider type."
category: provider-guide
provider: rest
requires: [foundation, discovery]
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

Read the mount's **`description`** from discovery (`warden provider list`)
to learn:
- which service this mount proxies, and
- its base path / which API routes are in scope.

If the description does not make the upstream clear, stop and ask — do not
assume. Two `rest` mounts are interchangeable only if their descriptions
say so.

## Configure the CLI/SDK

`<mount-url>` and `<role>` come from the discovery flow:
- `<mount-url>` is the chosen mount's `mount_url` from
  `warden provider list` (e.g. `/v1/billing-api/`).
- `<role>` is the role you picked from `warden role list` for this task —
  it goes in the URL path.

```
URL pattern : $WARDEN_ADDR<mount-url>role/<role>/gateway/<upstream-path>
Auth header : Authorization: Bearer $WARDEN_TOKEN
```

Rewrite the upstream host to
`$WARDEN_ADDR<mount-url>role/<role>/gateway` and add your Warden token as
the bearer. Everything after `/gateway/` — path, query string, method,
body — is forwarded verbatim to the upstream. Warden injects the upstream
credential for you; do not send the upstream's own token.

## Examples

(Assume `mount_url = /v1/billing-api/` and role `finance`, fronting an
internal REST API per its description; substitute yours.)

GET a resource:
```bash
curl -H "Authorization: Bearer $WARDEN_TOKEN" \
  $WARDEN_ADDR/v1/billing-api/role/finance/gateway/v1/invoices?status=open
```

POST a resource:
```bash
curl -X POST -H "Authorization: Bearer $WARDEN_TOKEN" \
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
