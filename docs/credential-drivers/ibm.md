# IBM Cloud Driver

> Source `type`: `ibm`

The IBM Cloud driver brokers access to **IBM Cloud** by exchanging a long-lived **IBM Cloud API key** for short-lived **IAM bearer tokens**. The privileged API key lives in the **source** config; each **spec** decides whether a workload receives a bare bearer token or that token paired with static **Cloud Object Storage (COS)** HMAC keys. IAM tokens expire on their own, so nothing is left behind after use.

An operator reaches for this driver when workloads need to call IBM Cloud APIs (or COS S3-compatible endpoints) without holding the account API key themselves. Warden can also rotate the source API key on a schedule, minting a fresh key for the same IAM identity and retiring the old one.

## Source config

Keys for `warden cred source create <name> -type=ibm -config=key=value ...`:

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `api_key` | Yes | — | IBM Cloud API key (secret, masked on read). |
| `account_id` | No | discovered from the API key | IBM Cloud account ID; auto-filled from the key's details when omitted. |
| `iam_endpoint` | No | `https://iam.cloud.ibm.com` | IAM endpoint; must use `https` unless `tls_skip_verify` is set. |
| `ca_data` | No | — | Base64-encoded PEM CA bundle for custom/self-signed CAs (secret, masked on read). |
| `tls_skip_verify` | No | `false` | Skip TLS certificate verification (development only). |

## Specs and mint methods

The `mint_method` spec key selects what is issued:

| `mint_method` | Issues | Notable spec config |
|---------------|--------|---------------------|
| `iam_token` (default) | IAM bearer token | none |
| `iam_with_cos` | IAM bearer token plus optional static COS HMAC keys | `access_key_id`, `secret_access_key` |

Spec-config keys set with `warden cred spec create ... -config=key=value`:

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `mint_method` | No | `iam_token` | Selects the mint method (`iam_token` or `iam_with_cos`). |
| `access_key_id` | No | — | COS HMAC access key ID; only used by `iam_with_cos`. Both keys must be present to be included. |
| `secret_access_key` | No | — | COS HMAC secret access key; only used by `iam_with_cos`. |

## Credential issued

`iam_token` issues an `oauth_bearer_token`; `iam_with_cos` issues `ibmcloud_keys`. Both are **dynamic** — the credential carries the IAM token's remaining TTL as its lease. They are **not revocable**: IAM tokens expire naturally and revoke is a no-op. See [the lifetime model](../concepts/credentials.md#lifetime-and-revocation).

## Capabilities

- **Spec verification** — validates a spec at create/update time with a lightweight IAM token exchange.
- **Source rotation** — **slow**: stages a newly created API key for the same IAM identity and waits ~2 minutes (default, tunable via the source's `activation_delay`) so it propagates before the old key is deleted. What rotates is the source `api_key`. Rotation is available only when the key's IAM identity was discovered and can create/delete API keys.

## Example

```bash
warden cred source create ibm-prod \
  -type=ibm \
  -config=api_key=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx \
  -config=account_id=abcdef1234567890abcdef1234567890 \
  -rotation-period=720h

warden cred spec create ibm-cos \
  -source=ibm-prod \
  -config=mint_method=iam_with_cos \
  -config=access_key_id=AKIAEXAMPLE \
  -config=secret_access_key=wJalrEXAMPLEKEY
```

## See Also

- [Credentials](../concepts/credentials.md) — the source, spec, and credential model.
- [IBM Cloud provider](../provider-backends/ibmcloud.md) — full operator setup guide.
- [Credential drivers](README.md) — every driver.
