---
title: "IBM Cloud"
---

> Source `type`: `ibm`

:::tip[Prefer keyless]
This driver supports a **keyless mode** — use it instead of storing a secret inline. A stored secret is attack surface; keyless holds nothing. See [Keyless (via chaining)](#keyless-via-chaining).
:::

The IBM Cloud driver brokers access to **IBM Cloud** by exchanging a long-lived **IBM Cloud API key** for short-lived **IAM bearer tokens**. The privileged API key lives in the **source** config; each **spec** decides whether a workload receives a bare bearer token or that token paired with static **Cloud Object Storage (COS)** HMAC keys. IAM tokens expire on their own, so nothing is left behind after use.

An operator reaches for this driver when workloads need to call IBM Cloud APIs (or COS S3-compatible endpoints) without holding the account API key themselves. Warden can also rotate the source API key on a schedule, minting a fresh key for the same IAM identity and retiring the old one.

## Keyless (via chaining)

The IBM Cloud API key does not have to be stored on the source: set `secret_spec` to fetch
it from another cred spec via [credential chaining](/federation/credential-chaining/) at
mint time, so nothing is stored at Warden.

What the chained material means depends on the mint method: `iam_token` reads an
`api_key` / `apikey` to exchange for a bearer token, while `access_keys` reads the COS
HMAC pair and serves it. Use `secret_field` to disambiguate a multi-key payload.

## Credential issued

`iam_token` issues an `oauth_bearer_token` and is **dynamic** — the credential carries the IAM token's remaining TTL as its lease. `access_keys` issues `ibmcloud_keys`, serving a pair it sources by chaining; its lifetime follows the chained material, not an IAM token. They are **not revocable**: IAM tokens expire naturally and revoke is a no-op. See [the lifetime model](/concepts/credentials/#lifetime-and-revocation).

## Capabilities

- **Spec verification** — validates a spec at create/update time with a lightweight IAM token exchange.
- **Source rotation** — **slow**: stages a newly created API key for the same IAM identity and waits ~2 minutes (default, tunable via the source's `activation_delay`) so it propagates before the old key is deleted. What rotates is the source `api_key`. Rotation is available only when the key's IAM identity was discovered and can create/delete API keys.

## Examples

### Keyless (via chaining, recommended)

The source stores no secret: the IBM Cloud API key — or, for `access_keys`, the COS HMAC pair is fetched from a keyless-federated
vault per request.

The **consumer** is the same whichever producer you use — only the `secret_spec` name
changes:

```bash
warden cred source create ibm-keyless \
  -type=ibm \
  -config=secret_spec=ibm-apikey-in-vault

warden cred spec create ibm-bearer \
  -source=ibm-keyless \
  -config=mint_method=iam_token
```

The **producer** is the spec that yields that secret. Any of the three below can serve it;
pick the one where the secret already lives. Each is itself keyless, so nothing is stored
at either hop.

**OpenBao / Vault — `kv2_read`**

```bash
warden cred spec create ibm-apikey-in-vault \
  -source=vault-keyless \
  -config=mint_method=kv2_read \
  -config=kv2_mount=secret \
  -config=secret_path=ibm/api-key \
  -config=subject_token_source=warden_identity
```

**AWS Secrets Manager — `secret_read`**

```bash
warden cred spec create ibm-apikey-in-asm \
  -source=aws-keyless \
  -config=mint_method=secret_read \
  -config=secret_id=prod/ibm/api-key \
  -config=role_arn=arn:aws:iam::123456789012:role/SecretReader \
  -config=subject_token_source=warden_identity
```

**GCP Secret Manager — `secret_read`**

```bash
warden cred spec create ibm-apikey-in-sm \
  -source=gcp-keyless \
  -config=mint_method=secret_read \
  -config=secret_name=ibm-api-key \
  -config=project=my-project \
  -config=subject_token_source=warden_identity
```

`vault-keyless`, `aws-keyless` and `gcp-keyless` are ordinary
[keyless sources](/federation/keyless-credentials/) — the producer holds no secret either.

**Scoped secrets: A COS credential per analyst, inside their team.** A producer's locator key templates on verified
claims, so one spec resolves to a different secret per caller. Object-storage access is attributed to the person, not the workload — but the bucket belongs to their team. **Both namespaces template into one path**: the agent supplies the team, the verified user supplies the analyst.

```bash
warden cred spec create ibm-cos-per-analyst \
  -source=vault-keyless \
  -config=mint_method=kv2_read \
  -config=kv2_mount=secret \
  -config=secret_path=cos/{{agent.metadata.team}}/analysts/{{user.email}}/hmac \
  -config=subject_token_source=warden_identity \
  -config=assertion_metadata_claims=team \
  -config=assertion_user_claims=email
```

A claim is only resolvable if the spec projects it: `assertion_metadata_claims` for the
agent, `assertion_user_claims` for the user. Resolution is fail-closed at mint — a missing
claim fails the request rather than falling back to a shared secret, and a `{{user.…}}`
template on a request with no user fails too, so a per-user secret cannot be reached
without a user.

See [credential chaining](/federation/credential-chaining/#producers).

### Inline secret (discouraged)

One source holds the IBM Cloud API key; each spec below picks a `mint_method`.

```bash
warden cred source create ibm-prod \
  -type=ibm \
  -config=api_key=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx \
  -config=account_id=abcdef1234567890abcdef1234567890 \
  -rotation-period=720h
```

**IAM token** — a bare IAM bearer token for IBM Cloud APIs:

```bash
warden cred spec create ibm-api \
  -source=ibm-prod \
  -config=mint_method=iam_token
```

**COS HMAC keys** — the S3-compatible pair, served from a spec that sources it by
[chaining](/federation/credential-chaining/) rather than storing it:

```bash
warden cred spec create ibm-cos \
  -source=ibm-prod \
  -config=mint_method=access_keys \
  -config=secret_spec=cos-hmac-in-vault
```

`access_keys` **requires** `secret_spec` — there is no inline form. The pair is served
from the referenced spec, never minted here.

:::caution[Removed in v0.20.0]
The `iam_with_cos` mint method is gone. It bundled two unrelated credentials into one
spec; split it into a bearer spec (`iam_token`) and an `access_keys` spec that sources
the COS HMAC pair, ideally by chaining. See
[Upgrading from v0.19.0](/upgrade/from-v0-19/#7-ibm-iam_with_cos-is-removed).
:::

## Source config

Keys for `warden cred source create <name> -type=ibm -config=key=value ...`:

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `api_key` | Yes* | — | IBM Cloud API key (secret, masked on read). |
| `account_id` | No | discovered from the API key | IBM Cloud account ID; auto-filled from the key's details when omitted. |
| `iam_endpoint` | No | `https://iam.cloud.ibm.com` | IAM endpoint; must use `https` unless `tls_skip_verify` is set. |
| `ca_data` | No | — | Base64-encoded PEM CA bundle for custom/self-signed CAs (secret, masked on read). |
| `tls_skip_verify` | No | `false` | Skip TLS certificate verification (development only). |

\* Required only when the source is **not** keyless. A source that sets
`secret_spec` (chaining) or `auth_method=oidc_federation` must **omit** it — setting
both is rejected at write. See [Keyless](#keyless-via-chaining).

## Specs and mint methods

The `mint_method` spec key selects what is issued:

| `mint_method` | Issues | Notable spec config |
|---------------|--------|---------------------|
| `iam_token` (default) | IAM bearer token | none |
| `access_keys` | COS HMAC access/secret key pair | `secret_spec` (**required**) |

Spec-config keys set with `warden cred spec create ... -config=key=value`:

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `mint_method` | No | `iam_token` | Selects the mint method (`iam_token` or `access_keys`). |

## See Also

- [Credentials](/concepts/credentials/) — the source, spec, and credential model.
- [IBM Cloud provider](/provider-backends/ibmcloud/) — full operator setup guide.
- [Credential drivers](/credential-drivers/) — every driver.
