---
name: scaleway
description: "Call the Scaleway REST API and Scaleway Object Storage (S3-compatible) through Warden — one provider, two patterns auto-detected."
category: provider-guide
provider: scaleway
requires: []
upstream: Scaleway REST API + Object Storage
---

# Scaleway through Warden

## What it does

Scaleway is a *dual-mode* provider. The same mount handles both:

- **Scaleway REST API** (compute, IAM, networking, etc.) — proxied
  with Warden injecting `X-Auth-Token: <secret-key>`.
- **Scaleway Object Storage (S3-compatible)** — proxied with SigV4
  verification + re-signing, exactly like the AWS provider.

Warden detects which kind of request the agent sent (signed vs
unsigned) and dispatches automatically. The agent typically only
cares about *one* of the two modes per task.

## Configure the CLI/SDK

You need two values:
- `<gateway-url>` is the gateway URL for the role you chose, embedded in
  the role's `description` returned by the `list_roles` MCP tool. It is a
  **relative** path `/v1/<namespace>/<mount>/role/<role>/gateway/`
  (e.g. `/v1/scaleway/role/cloud-reader/gateway/`,
  `/v1/team-data/scaleway-prod/role/cloud-reader/gateway/`) — prepend
  `$WARDEN_ADDR`. REST mode appends the Scaleway API path after it; S3
  mode uses it as the endpoint.
- `<role>` is the same role name. S3 mode also puts it in
  `AWS_ACCESS_KEY_ID` (Warden reads it from the SigV4 header).

**Choosing a role.** The role rides in the URL path (the `role/<role>` segment
of `<gateway-url>`, or `AWS_ACCESS_KEY_ID` for S3). To act as a different role,
use that role's `<gateway-url>` from `list_roles` — each role provides its own
role-bearing URL in its description. If the operator has set a mount
`default_role`, a request with no role at all falls back to it.

Present identity as `Authorization: Bearer <jwt>` for REST, or as the JWT
in the SigV4 secret slots for S3 (below); an mTLS client cert also works.
A `401` on REST — or a stale-JWT `SignatureDoesNotMatch` on S3 — means the
JWT expired (typical TTL 5–60 min); refresh and retry.

### REST API (HTTP, Bearer-style)

```bash
URL pattern : $WARDEN_ADDR<gateway-url><scaleway-api-path>
Auth header : Authorization: Bearer <jwt>
```

The official Scaleway CLI (`scw`) authenticates via `X-Auth-Token`
and **cannot be pointed at Warden's transparent mode** as-is — use
an HTTP client that lets you set `Authorization: Bearer` instead.
The natural choices are `curl`, the language's native HTTP library
(Python `requests`, Node `fetch`, Go `net/http`), or the Scaleway
language SDK with a custom HTTP client that injects the bearer
header.

`curl`:
```bash
curl -H "Authorization: Bearer <jwt>" \
  $WARDEN_ADDR/v1/scaleway/role/cloud-reader/gateway/instance/v1/zones/fr-par-1/servers
```

Python (using `requests`):
```python
import os, requests
jwt = "<jwt>"   # the Warden JWT for the role you chose
base = f"{os.environ['WARDEN_ADDR']}/v1/scaleway/role/cloud-reader/gateway"
r = requests.get(
    f"{base}/instance/v1/zones/fr-par-1/servers",
    headers={"Authorization": f"Bearer {jwt}"},
)
r.raise_for_status()
servers = r.json()["servers"]
```

### Object Storage (S3-compatible — works with the AWS CLI/SDK)

Point an AWS S3 SDK at the Warden gateway, exactly like the AWS
provider but pointing at this mount:

```bash
export AWS_ACCESS_KEY_ID="<role-name>"
export AWS_SECRET_ACCESS_KEY="<jwt>"
export AWS_SESSION_TOKEN="<jwt>"
export AWS_ENDPOINT_URL="$WARDEN_ADDR<gateway-url>"
```

Then any AWS S3-compatible CLI/SDK works:

```bash
aws s3 ls s3://my-scaleway-bucket/ --region fr-par
aws s3 cp local.txt s3://my-scaleway-bucket/path/
```

Warden re-signs to `s3.<region>.scw.cloud` with real Scaleway access
keys.

## Examples

(Examples use `<gateway-url>` = `/v1/scaleway/role/<role>/gateway/`.)

Read your IAM users (REST):
```bash
curl -H "Authorization: Bearer <jwt>" \
  $WARDEN_ADDR/v1/scaleway/role/iam-reader/gateway/iam/v1alpha1/users
```

List instances in a zone (REST):
```bash
curl -H "Authorization: Bearer <jwt>" \
  $WARDEN_ADDR/v1/scaleway/role/compute/gateway/instance/v1/zones/fr-par-1/servers
```

Object upload (S3):
```bash
aws s3 cp ./report.csv s3://analytics-bucket/2026/05/report.csv \
  --region nl-ams
```

## Quirks

- **Auto-detection is by request shape**, not URL path. A SigV4-signed
  request on `…/gateway/<bucket>/<key>` is treated as S3; an
  unsigned (or Bearer-only) request is treated as REST. **Don't mix
  the two patterns in one client config.**
- **S3 regions are hardcoded** to Scaleway's known list:
  `fr-par`, `nl-ams`, `pl-waw`, `it-mil`. Other values get rejected.
- **REST and S3 use different credentials internally.** The cred
  spec maps `static_keys` (long-lived API key) or `dynamic_keys`
  (short-lived) — an operator/config detail on the mount, not something
  the agent sets.

