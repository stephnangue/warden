---
title: "Grafana"
---

> Source `type`: `grafana`

The Grafana driver mints **Grafana service-account tokens** by talking to the Grafana HTTP API. For every mint it creates a **temporary service account**, generates a bounded-TTL token on it, and hands the token to the workload; on **revoke** it deletes that service account (and with it every token), so minted credentials are fully revocable.

The privileged secret lives in the **source**: an `admin_token` (an admin service-account token with permission to create and delete service accounts) plus the `grafana_url` to reach. Each **spec** decides the shape of what gets minted — the role granted, the naming prefix, an optional org, and the token TTL. An operator reaches for this driver to grant workloads short-lived, least-privilege Grafana access without ever sharing the standing admin token.

## Source config

Keys for `warden cred source create <name> -type=grafana -config=key=value ...`:

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `grafana_url` | Yes | — | Grafana API base URL, e.g. `https://mystack.grafana.net`. Must be `https://` (or `http://` only with `tls_skip_verify`). |
| `admin_token` | Yes | — | Admin service-account token with ServiceAccount admin permissions (secret, masked on read). |
| `ca_data` | No | — | Base64-encoded PEM CA certificate for custom/self-signed CAs (secret, masked on read). |
| `tls_skip_verify` | No | `false` | Skip TLS certificate verification (development only). |

## Specs and mint methods

A single mint method: each mint creates a service account and issues one token on it. Keys operators set with `warden cred spec create ... -config=key=value`:

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `role` | No | `Viewer` | Role granted to the service account: `Viewer`, `Editor`, or `Admin`. |
| `name_prefix` | No | `warden-` | Prefix for the generated service-account name. |
| `org_id` | No | — | Grafana organization ID to scope the service account to; omit for the default org. |
| `token_expiry` | No | `1h` | TTL of the minted token. |

## Credential issued

Issues a credential of type `api_key`. It is **dynamic** — it carries a lease and a TTL equal to `token_expiry` — and it is **revocable**: revoking deletes the backing service account and invalidates the token. See [the lifetime model](/concepts/credentials/#lifetime-and-revocation).

## Capabilities

- **Spec verification** — validates the source's admin token at spec create/update time with a lightweight service-account listing call.

Mint and revoke otherwise; no source or spec rotation. Create the source with `-rotation-period=0`.

## Example

```bash
warden cred source create grafana-cloud \
  -type=grafana \
  -config=grafana_url=https://mystack.grafana.net \
  -config=admin_token=glsa_xxxxxxxxxxxxxxxxxxxx \
  -rotation-period=0

warden cred spec create grafana-dashboards \
  -source=grafana-cloud \
  -config=role=Viewer \
  -config=name_prefix=warden- \
  -config=token_expiry=1h
```

## See Also

- [Credentials](/concepts/credentials/) — the source, spec, and credential model.
- [Grafana provider](/provider-backends/grafana/) — full operator setup guide.
- [Credential drivers](/credential-drivers/) — every driver.
