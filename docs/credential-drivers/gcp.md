# GCP Driver

> Source `type`: `gcp`

The GCP driver brokers **Google Cloud** access. It holds a **service-account JSON key**
in the **source** config and exchanges that key for short-lived **OAuth2 access tokens**,
either for the source service account itself or, by **impersonation**, for another service
account it is authorized to act as. The minted token is what Warden injects into the
workload's Google Cloud API request.

The privileged secret — the SA key — lives only in the source config and is masked on
read. Each **spec** selects a `mint_method` and the scopes, target account, and lifetime
of the token to issue. An operator reaches for this driver to hand workloads scoped,
expiring Google Cloud tokens without ever exposing the underlying key.

## Source config

Keys for `warden cred source create <name> -type=gcp -config=key=value ...`:

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `service_account_key` | Yes | — | GCP service-account key in JSON format; must contain `client_email` and `private_key` (secret, masked on read) |
| `ca_data` | No | — | Base64-encoded PEM CA certificate for custom/self-signed CAs (secret, masked on read) |
| `tls_skip_verify` | No | `false` | Skip TLS certificate verification (development only) |

## Specs and mint methods

| `mint_method` | Issues | Notable spec config |
|---------------|--------|---------------------|
| `access_token` (default) | OAuth2 access token for the source SA | `scopes` |
| `impersonated_access_token` | OAuth2 access token for a target SA via IAM | `target_service_account`, `scopes`, `lifetime` |

Spec-config keys set with `warden cred spec create ... -config=key=value`:

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `mint_method` | No | `access_token` | Which token to mint (see table above) |
| `scopes` | No | `https://www.googleapis.com/auth/cloud-platform` | Comma-separated OAuth2 scopes |
| `target_service_account` | Yes (impersonation only) | — | Email of the service account to impersonate |
| `lifetime` | No | `3600s` | Requested token lifetime (impersonation only) |

## Credential issued

Both mint methods issue a credential of type `gcp_access_token`. It is **dynamic** — it
carries the token's natural expiry as its TTL — but it is **not revocable**: a GCP access
token cannot be invalidated early and simply expires. See
[the lifetime model](../concepts/credentials.md#lifetime-and-revocation).

## Capabilities

- **Source rotation** — **slow**: stages a freshly created service-account key (minted
  via the IAM API against the source SA) and waits ~2 minutes (default, tunable via the
  source's `activation_delay`) for GCP IAM propagation before destroying the old key.
  Rotation requires the SA to hold `iam.serviceAccountKeys.create` and
  `iam.serviceAccountKeys.delete` on itself.

No spec verification.

## Example

```bash
warden cred source create prod-gcp \
  -type=gcp \
  -config=service_account_key=@sa-key.json \
  -rotation-period=720h

warden cred spec create bigquery-reader \
  -source=prod-gcp \
  -config=mint_method=impersonated_access_token \
  -config=target_service_account=bq-reader@my-project.iam.gserviceaccount.com \
  -config=scopes=https://www.googleapis.com/auth/bigquery.readonly \
  -config=lifetime=1800s
```

## See Also

- [Credentials](../concepts/credentials.md) — the source, spec, and credential model.
- [GCP provider](../provider-backends/gcp.md) — full operator setup guide.
- [Credential drivers](README.md) — every driver.
