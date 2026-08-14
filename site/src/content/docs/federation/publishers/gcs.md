---
title: "GCS"
description: "Publish the OIDC issuer's public keys to a Google Cloud Storage bucket."
---

> `set-publisher -type=gcs`

Publishes the discovery + JWKS documents to a **Google Cloud Storage** bucket,
authenticated by a stored service-account JSON key Warden can **self-rotate**.

```bash
warden oidc-issuer set-publisher -type=gcs -rotation-period=720h \
  -config=bucket=my-jwks \
  -config=credentials_json=@/run/secrets/sa.json
```

## Parameters

| Key | Required | Description |
|---|---|---|
| `bucket` | yes | GCS bucket name. |
| `credentials_json` | yes | Service-account JSON key (masked; use `@file`). |
| `prefix` | no | Object-name prefix. |
| `endpoint` | no | Storage API endpoint override. |
| `rotation_period` | no | Self-rotate the service-account key on this cadence (minimum 24h). Requires the service account to hold `iam.serviceAccountKeys.create`/`delete` on itself. |

## See also

- [Publishers](/federation/publishers/) — what a publisher does and the two rotations.
- [`warden oidc-issuer`](/cli/oidc-issuer/) — the CLI.
