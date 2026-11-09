---
name: ansible-tower
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

`<gateway-url>` is the `url` of the role you chose, as returned by the
`list_roles` discovery tool. Prepend `$WARDEN_ADDR` (the address you already
used to discover your roles). Each role has its own `url`: to act under a
*different* role, use that role's `url`.

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
`/v1/ansible_tower/role/ansible-ops/gateway/`; substitute your role's `url`.)

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
