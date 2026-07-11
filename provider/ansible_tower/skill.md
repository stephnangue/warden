---
name: ansible_tower
description: "Call the Ansible Tower / AWX / AAP REST API through Warden — launch job templates, read inventories, check job status — without holding a PAT."
category: provider-guide
provider: ansible_tower
requires: []
upstream: Ansible Tower / AWX / AAP REST API (api/v2)
---

# Ansible Tower through Warden

## What it does

Warden proxies Ansible Tower REST API requests. The agent calls a
Warden URL; Warden authenticates the caller (JWT/cert), looks up the
Ansible Tower Personal Access Token bound to the chosen role, injects
it as `Authorization: Bearer <pat>`, and forwards to Tower. The agent
**never holds a PAT**.

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

```bash
URL pattern : $WARDEN_ADDR<gateway-url>api/v2/<endpoint>
Auth header : Authorization: Bearer <jwt>
```

Tower's API path (`/api/v2/…`) is part of the upstream URL — Warden
does not strip or prepend it. Write the upstream path verbatim after
`/gateway/`.

## Examples

(Examples use a concrete `<gateway-url>` of
`/v1/ansible_tower/role/ansible-ops/gateway/`; substitute the one from your
role's `list_roles` description.)

Ping (health check):
```bash
curl -H "Authorization: Bearer <jwt>" \
  $WARDEN_ADDR/v1/ansible_tower/role/ansible-ops/gateway/api/v2/ping/
```

Current user (verifies the injected PAT is valid):
```bash
curl -H "Authorization: Bearer <jwt>" \
  $WARDEN_ADDR/v1/ansible_tower/role/ansible-ops/gateway/api/v2/me/
```

List job templates:
```bash
curl -H "Authorization: Bearer <jwt>" \
  $WARDEN_ADDR/v1/ansible_tower/role/ansible-ops/gateway/api/v2/job_templates/
```

Launch a job template with extra_vars (replace `42` with the template id):
```bash
curl -X POST -H "Authorization: Bearer <jwt>" \
  -H "Content-Type: application/json" \
  -d '{"extra_vars":{"target_host":"web01","deploy_version":"1.2.3"}}' \
  $WARDEN_ADDR/v1/ansible_tower/role/ansible-ops/gateway/api/v2/job_templates/42/launch/
```

Check job status (`<id>` comes from the launch response's `job` field):
```bash
curl -H "Authorization: Bearer <jwt>" \
  $WARDEN_ADDR/v1/ansible_tower/role/ansible-ops/gateway/api/v2/jobs/<id>/
```

List inventories:
```bash
curl -H "Authorization: Bearer <jwt>" \
  $WARDEN_ADDR/v1/ansible_tower/role/ansible-ops/gateway/api/v2/inventories/
```

## Quirks

- **Trailing slashes matter.** Tower's REST API requires a trailing
  `/` on collection and detail URLs (`…/jobs/`, `…/jobs/17/`). Without
  it Tower returns a `301` redirect that the gateway does not follow,
  so the agent sees an empty body or a `301`. Always include the
  trailing slash.
- **`/launch/` is POST even with no overrides.** Use `POST` with an
  empty `{}` body if you have no `extra_vars`. A `GET` on the launch
  endpoint returns the template's launch metadata, not a job run.
- **PATs are static.** Tower Personal Access Tokens do not auto-rotate;
  the operator rotates them out-of-band via the Tower UI/API and
  updates the credential spec. Your agent does not need to handle
  token refresh.
- **AAP platform gateway uses a different path prefix.** Self-hosted
  Red Hat AAP behind the platform gateway exposes the controller API
  at `/api/controller/v2/`, not `/api/v2/`. If the operator pointed
  `ansible_tower_url` at the platform gateway, swap the prefix in
  your URLs accordingly; AWX and AAP-direct both use `/api/v2/`.
- **Policies can restrict request body fields.** Warden parses the
  request body, so an operator's policy may allow only specific
  `extra_vars` keys, job template IDs, or inventory IDs. If a request
  is rejected before reaching Tower, the error comes from Warden, not
  Tower.
