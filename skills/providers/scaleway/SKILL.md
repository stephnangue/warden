---
name: scaleway
description: "Call the Scaleway REST API and Scaleway Object Storage (S3-compatible) through Warden — one provider, two patterns auto-detected."
category: provider-guide
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

`<mount>`, `<role>`, and (for S3 mode) `<role-name>` below come from
the discovery flow:
- `<mount>` is the chosen provider's path from `warden list sys/providers`
  (e.g. `scaleway/`, `scaleway-prod/`).
- `<role>` / `<role-name>` is the role you picked from `warden roles`
  for this task — REST mode puts it in the URL path; S3 mode puts the
  same value in `AWS_ACCESS_KEY_ID`.

### REST API (HTTP, Bearer-style)

```bash
URL pattern : $WARDEN_ADDR/v1/<mount>/role/<role>/gateway/<scaleway-api-path>
Auth header : Authorization: Bearer <JWT>
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
curl -H "Authorization: Bearer $JWT" \
  $WARDEN_ADDR/v1/scaleway/role/cloud-reader/gateway/instance/v1/zones/fr-par-1/servers
```

Python (using `requests`):
```python
import os, requests
base = f"{os.environ['WARDEN_ADDR']}/v1/scaleway/role/cloud-reader/gateway"
r = requests.get(
    f"{base}/instance/v1/zones/fr-par-1/servers",
    headers={"Authorization": f"Bearer {os.environ['JWT']}"},
)
r.raise_for_status()
servers = r.json()["servers"]
```

### Object Storage (S3-compatible — works with the AWS CLI/SDK)

Point an AWS S3 SDK at the Warden gateway, exactly like the AWS
provider but pointing at this mount:

```bash
export AWS_ACCESS_KEY_ID="<role-name>"
export AWS_SECRET_ACCESS_KEY="$JWT"
export AWS_SESSION_TOKEN="$JWT"
export AWS_ENDPOINT_URL="$WARDEN_ADDR/v1/<mount>/role/<role>/gateway"
```

Then any AWS S3-compatible CLI/SDK works:

```bash
aws s3 ls s3://my-scaleway-bucket/ --region fr-par
aws s3 cp local.txt s3://my-scaleway-bucket/path/
```

Warden re-signs to `s3.<region>.scw.cloud` with real Scaleway access
keys.

## Examples

(All examples assume mount `scaleway/`; substitute yours.)

Read your IAM users (REST):
```bash
curl -H "Authorization: Bearer $JWT" \
  $WARDEN_ADDR/v1/scaleway/role/iam-reader/gateway/iam/v1alpha1/users
```

List instances in a zone (REST):
```bash
curl -H "Authorization: Bearer $JWT" \
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
  (short-lived) — operator decision; check `warden read scaleway/config`.

