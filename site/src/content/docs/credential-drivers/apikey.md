---
title: "Static API Key"
---

> Source `type`: `apikey`

:::tip[Prefer keyless]
This driver supports a **keyless mode** — use it instead of storing a secret inline. A stored secret is attack surface; keyless holds nothing. See [Keyless (via chaining)](#keyless-via-chaining).
:::

:::note[The fallback driver — reach for it when nothing else fits]
Most drivers exist because an upstream offers a **dynamic-credential API** worth speaking
to: STS, an OAuth token endpoint, a secrets engine. `apikey` is the one that assumes
none of that. It serves a credential the upstream minted out-of-band, to **any** HTTP API
that authenticates with a header.

That makes it the driver of last resort **and** the one with the widest reach. Most of the
world's APIs authenticate with a header token and nothing more, so when no purpose-built
driver models your upstream, this is the answer — not a gap to be filled later. Paired
with the generic [`rest`](/provider-backends/rest/) or [`mcp`](/provider-backends/mcp/)
provider, it brokers an upstream Warden has never heard of without a line of new code.

Being the fallback does not make it second-class. With
[chaining](#keyless-via-chaining) it is **keyless**, exactly like the cloud drivers, and
`credential_fields` lets it model multi-part credentials rather than only single tokens.
:::

The **static API key** driver serves a long-lived **API key** to any HTTP API — OpenAI, Anthropic, Datadog, or any service that authenticates with a header token. Unlike most drivers, the privileged secret does not live on the **source**: the `api_key` is supplied per **credential spec**, so one source can describe the shape of an API (its base URL, how to attach the key, how to verify it) while many specs each carry a different key. This lets a single source back several teams or projects that hit the same API with distinct keys.

At mint time the key is returned as-is with **no TTL and no lease** — Warden stores it (or
fetches it per request when chained), verifies it, and injects it. The source config also
controls an optional verification call so a bad key is caught the moment a spec is
created, rather than on the first request that matters.

**`credential_fields`** is the key that carries most of the generality: it lets a spec
describe a credential that is not a single token — Datadog's application key, the email
half of an Atlassian Basic login — and carries those parts through to the provider
alongside the key itself.

**`auth_header_type`** / **`auth_header_name`** shape only the driver's own
**verification** call, not the proxied request. How the key reaches the upstream is the
provider's business: the [`rest`](/provider-backends/rest/) provider takes `token_header`
and `token_prefix`, and a purpose-built provider injects whatever its API expects.

## Keyless (via chaining)

The API key does not have to be stored in the spec: set `secret_spec` to source it from
another cred spec via [credential chaining](/federation/credential-chaining/). Warden
fetches the key from a keyless-federated vault at mint time and injects it, so nothing is
stored at Warden.

The referenced credential's `api_key` field is used by default; name a different one with
`secret_field`.

## Credential issued

Issues a credential of type `api_key`. It is **static** — no lease, no TTL — and **not revocable**: revocation is a no-op because the key is owned and rotated outside Warden. See [the lifetime model](/concepts/credentials/#lifetime-and-revocation).

## Capabilities

- **Spec verification** — if `verify_endpoint` is set, creating or updating a spec triggers a light call to `api_url` + `verify_endpoint` using the configured method and auth header, retried on HTTP 429 or 500. A key that fails the call is rejected. With no `verify_endpoint`, verification is skipped.

No rotation of any kind — the key is static and managed upstream.

## Examples

### Keyless (via chaining, recommended)

The key is not stored on the spec; it is fetched from a keyless-federated vault per
request.

```bash
warden cred spec create datadog-key \
  -source=datadog-src \
  -config=secret_spec=datadog-key-in-vault
```

Chaining composes with `credential_fields`, and the **whole** credential can come from the
vault — not just the key. The referenced spec's entire payload is passed to the driver,
and `credential_fields` decides which of its other fields travel into the credential. So
a two-part credential stored as one vault secret needs nothing on the spec at all:

```bash
warden cred source create datadog \
  -type=apikey \
  -config=api_url=https://api.datadoghq.com \
  -config=auth_header_type=custom_header \
  -config=auth_header_name=DD-API-KEY \
  -config=credential_fields=application_key

# the vault secret holds both api_key and application_key
warden cred spec create datadog-rw \
  -source=datadog \
  -config=secret_spec=datadog-creds-in-vault
```

Each declared field resolves **material first, spec second**: if the chained payload
carries `application_key`, that value is used; if it does not, the spec's value is the
fallback. That lets a shared key live in the vault while a per-team field stays on the
spec:

```bash
warden cred spec create datadog-team-a \
  -source=datadog \
  -config=secret_spec=datadog-key-in-vault \
  -config=application_key=abc123...
```

The resolved `api_key` is never overwritten by a declared field, even when the payload
happens to carry another one — otherwise a chained mint could quietly serve a different
secret than `secret_field` selected.

**Basic auth from two fields** — Atlassian Cloud signs in with `email:token`, so the email
has to reach the provider alongside the key. Chained, neither half is stored on the spec:

```bash
warden cred source create atlassian \
  -type=apikey \
  -config=api_url=https://your-site.atlassian.net \
  -config=credential_fields=email

warden cred spec create jira-bot \
  -source=atlassian \
  -config=secret_spec=atlassian-creds-in-vault
```

`credential_fields` is a comma-separated list, so a credential with several adjunct parts
(`organization_id,project_id`) works the same way — each named field is taken from the
chained payload, or from the spec when the payload omits it.

A spec that sets a credential field its source does not carry is **rejected at write**:

```
spec sets credential field(s) application_key that source 'datadog' does not carry:
add them to the source's credential_fields (currently "")
```

That check exists because the alternative is worse than an error. A credential minted
quietly missing its second field does not fail loudly — the provider takes its fallback
branch, and the mount looks like it is working.

The check applies only to fields the credential type actually models. A key it has never
heard of is left alone on the spec, since it may belong to a mechanism this type does not
describe.

The **producer** is the spec that yields that secret. Any of the three below can serve it;
pick the one where the secret already lives. Each is itself keyless, so nothing is stored
at either hop.

**OpenBao / Vault — `kv2_read`**

```bash
warden cred spec create api-key-in-vault \
  -source=vault-keyless \
  -config=mint_method=kv2_read \
  -config=kv2_mount=secret \
  -config=secret_path=datadog/api-key \
  -config=subject_token_source=warden_identity
```

**AWS Secrets Manager — `secret_read`**

```bash
warden cred spec create api-key-in-asm \
  -source=aws-keyless \
  -config=mint_method=secret_read \
  -config=secret_id=prod/datadog/api-key \
  -config=role_arn=arn:aws:iam::123456789012:role/SecretReader \
  -config=subject_token_source=warden_identity
```

**GCP Secret Manager — `secret_read`**

```bash
warden cred spec create api-key-in-sm \
  -source=gcp-keyless \
  -config=mint_method=secret_read \
  -config=secret_name=datadog-api-key \
  -config=project=my-project \
  -config=subject_token_source=warden_identity
```

`vault-keyless`, `aws-keyless` and `gcp-keyless` are ordinary
[keyless sources](/federation/keyless-credentials/) — the producer holds no secret either.

**Scoped secrets: A Datadog key per user, within a team account.** A producer's locator key templates on verified
claims, so one spec resolves to a different secret per caller. Dashboards and monitors are attributed to the key that created them. **Both namespaces template into one name**: the agent's team selects the account, the verified user selects their key within it.

```bash
warden cred spec create datadog-key-per-user \
  -source=gcp-keyless \
  -config=mint_method=secret_read \
  -config=secret_name=datadog-{{agent.metadata.team}}-{{user.username}} \
  -config=project=my-project \
  -config=subject_token_source=warden_identity \
  -config=assertion_metadata_claims=team \
  -config=assertion_user_claims=username
```

A claim is only resolvable if the spec projects it: `assertion_metadata_claims` for the
agent, `assertion_user_claims` for the user. Resolution is fail-closed at mint — a missing
claim fails the request rather than falling back to a shared secret, and a `{{user.…}}`
template on a request with no user fails too, so a per-user secret cannot be reached
without a user.

See [credential chaining](/federation/credential-chaining/#producers).

### Inline secret (discouraged)

One source describes the API; each spec carries a different key. Here two teams share the same OpenAI source with distinct keys:

```bash
warden cred source create openai \
  -type=apikey \
  -config=api_url=https://api.openai.com \
  -config=verify_endpoint=/v1/models \
  -config=verify_method=GET \
  -config=auth_header_type=bearer \
  -config=credential_fields=organization_id \
  -config=display_name=OpenAI \
  -rotation-period=0

warden cred spec create openai-team-a \
  -source=openai \
  -config=api_key=sk-proj-abc123... \
  -config=organization_id=org-XXXX

warden cred spec create openai-team-b \
  -source=openai \
  -config=api_key=sk-proj-def456... \
  -config=organization_id=org-YYYY
```

## Source config

Keys for `warden cred source create <name> -type=apikey -config=key=value ...`:

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `api_url` | Yes* | — | API base URL. Must be `https://` (or `http://` when `tls_skip_verify` is set). *Not enforced by config validation, but a source cannot mint or verify without it. |
| `verify_endpoint` | No | — | Path appended to `api_url` for spec verification. If empty, verification is skipped. |
| `verify_method` | No | `GET` | HTTP method for the verification call — `GET` or `POST`. |
| `auth_header_type` | No | `bearer` | How the key is attached when verifying: `bearer`, `token`, or `custom_header`. |
| `auth_header_name` | No* | — | Header name to carry the key. *Required when `auth_header_type=custom_header`. |
| `extra_headers` | No | — | Additional static headers as comma-separated `key:value` pairs. |
| `credential_fields` | No | — | Comma-separated spec-config field names to copy into the minted credential data. |
| `display_name` | No | `API Key` | Human-readable label used in logs and errors. |
| `ca_data` | No | — | Base64-encoded PEM CA bundle for custom/self-signed CAs. (secret, masked on read) |
| `tls_skip_verify` | No | `false` | Skip TLS certificate verification (development only). |

:::caution[Renamed in v0.20.0]
The `credential_fields` key above was named `optional_metadata` before v0.20.0. The old name is **rejected on write** with an error
naming the new one — there is no alias, so rename it on every `apikey` source.

The mechanism also works now: the declared fields previously never reached the
provider, so a source that looked correct silently carried nothing. A spec written
against the old behaviour may start behaving differently — correctly — once renamed.
This is what makes Datadog's `application_key` and Atlassian's `email` reachable.
See [Upgrading from v0.19.0](/upgrade/from-v0-19/#6-apikey-sources-rename-optional_metadata-to-credential_fields).
:::

## Specs and mint methods

There is a single mint path. The spec carries the actual key plus whatever fields the source named in `credential_fields`.

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `api_key` | Yes | — | The API key to serve. Returned verbatim as the credential. |
| *fields from `credential_fields`* | No | — | Any field named in the source's `credential_fields` (e.g. `organization_id`, `project_id`) is copied into the credential data when present. |

## See Also

- [Credentials](/concepts/credentials/) — the source, spec, and credential model.
- [`local`](/credential-drivers/local/) — static secrets with no upstream verification.
- [Credential drivers](/credential-drivers/) — every driver.
