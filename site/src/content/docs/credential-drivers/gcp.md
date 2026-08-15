---
title: "GCP"
---

> Source `type`: `gcp`

:::tip[Prefer keyless]
This driver supports a **keyless mode** — use it instead of storing a secret inline. A stored secret is attack surface; keyless holds nothing. See [Keyless (OIDC federation)](#keyless-oidc-federation).
:::

The GCP driver brokers **Google Cloud** access. It holds a **service-account JSON key**
in the **source** config and exchanges that key for short-lived **OAuth2 access tokens**,
either for the source service account itself or, by **impersonation**, for another service
account it is authorized to act as. The minted token is what Warden injects into the
workload's Google Cloud API request.

The privileged secret — the SA key — lives only in the source config and is masked on
read. Each **spec** selects a `mint_method` and the scopes, target account, and lifetime
of the token to issue. An operator reaches for this driver to hand workloads scoped,
expiring Google Cloud tokens without ever exposing the underlying key.

## Keyless (OIDC federation)

Set `auth_method = "oidc_federation"` on the source to hold **no service-account key**:
Warden exchanges an [identity assertion](/federation/oidc-issuer/) through **Workload
Identity Federation** at `sts.googleapis.com` for a Google access token. Set the full
`workload_identity_provider` resource name on the source; the spec's `mint_method` is
`access_token` or `impersonated_access_token` (the latter impersonates a
`target_service_account`), and it sets `subject_token_source` (`warden_identity` or
`agent_identity`). See [Keyless credential sources](/federation/keyless-credentials/).

## Credential issued

Both mint methods issue a credential of type `gcp_access_token`. It is **dynamic** — it
carries the token's natural expiry as its TTL — but it is **not revocable**: a GCP access
token cannot be invalidated early and simply expires. See
[the lifetime model](/concepts/credentials/#lifetime-and-revocation).

## Capabilities

- **Source rotation** — **slow**: stages a freshly created service-account key (minted
  via the IAM API against the source SA) and waits ~2 minutes (default, tunable via the
  source's `activation_delay`) for GCP IAM propagation before destroying the old key.
  Rotation requires the SA to hold `iam.serviceAccountKeys.create` and
  `iam.serviceAccountKeys.delete` on itself.

No spec verification.

## Examples

### Keyless (recommended)

The source stores no service-account key; Warden exchanges an identity assertion through Workload Identity Federation.

```bash
warden cred source create gcp-keyless \
  -type=gcp \
  -config=auth_method=oidc_federation \
  -config=workload_identity_provider=//iam.googleapis.com/projects/123456/locations/global/workloadIdentityPools/warden/providers/warden

warden cred spec create viewer-token \
  -source=gcp-keyless \
  -config=mint_method=access_token \
  -config=subject_token_source=warden_identity
```

### Inline secret (discouraged)

One source holds the service-account JSON key; each spec below picks a `mint_method`.

```bash
warden cred source create prod-gcp \
  -type=gcp \
  -config=service_account_key=@sa-key.json \
  -rotation-period=720h
```

**Access token** — an OAuth2 token for the source service account itself:

```bash
warden cred spec create platform-token \
  -source=prod-gcp \
  -config=mint_method=access_token \
  -config=scopes=https://www.googleapis.com/auth/cloud-platform
```

**Impersonated access token** — a token for another service account via IAM:

```bash
warden cred spec create bigquery-reader \
  -source=prod-gcp \
  -config=mint_method=impersonated_access_token \
  -config=target_service_account=bq-reader@my-project.iam.gserviceaccount.com \
  -config=scopes=https://www.googleapis.com/auth/bigquery.readonly \
  -config=lifetime=1800s
```

## Source config

Keys for `warden cred source create <name> -type=gcp -config=key=value ...`:

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `auth_method` | No | `static` | How the source authenticates: `static` (stored SA key) or `oidc_federation` ([keyless](/federation/keyless-credentials/) — Workload Identity Federation). |
| `service_account_key` | For `static` | — | GCP service-account key in JSON format; must contain `client_email` and `private_key` (masked). Omit for keyless. |
| `workload_identity_provider` | For keyless | — | Full WIF provider resource name; must start with `//iam.googleapis.com/` (e.g. `//iam.googleapis.com/projects/…/locations/global/workloadIdentityPools/…/providers/…`). |
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
| `subject_token_source` | For keyless | — | On an `oidc_federation` source: the federated subject — `warden_identity` or `agent_identity`. |
| `scopes` | No | `https://www.googleapis.com/auth/cloud-platform` | Comma-separated OAuth2 scopes |
| `target_service_account` | Yes (impersonation only) | — | Email of the service account to impersonate |
| `lifetime` | No | `3600s` | Requested token lifetime (impersonation only) |

A `subject_token_source=warden_identity` spec also accepts the assertion-shaping keys
(`assertion_audience`, `assertion_resource`, `assertion_metadata_claims`,
`assertion_user_claims`, `assertion_algorithm`) — see
[Assertion claims](/federation/assertion-claims/).

## See Also

- [Credentials](/concepts/credentials/) — the source, spec, and credential model.
- [GCP provider](/provider-backends/gcp/) — full operator setup guide.
- [Credential drivers](/credential-drivers/) — every driver.
