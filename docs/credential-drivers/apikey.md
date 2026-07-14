# Static API Key Driver

> Source `type`: `apikey`

The **static API key** driver serves a long-lived **API key** to any HTTP API — OpenAI, Anthropic, or any service that authenticates with a header token. Unlike most drivers, the privileged secret does not live on the **source**: the `api_key` is supplied per **credential spec**, so one source can describe the shape of an API (its base URL, how to attach the key, how to verify it) while many specs each carry a different key. This lets a single source back several teams or projects that hit the same API with distinct keys.

An operator reaches for this driver when the upstream has no dynamic-credential API — the key is minted out-of-band and Warden simply stores it, verifies it, and injects it. At mint time the key is returned as-is with **no TTL and no lease**. The source config also controls an optional verification call so a bad key is caught the moment a spec is created.

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
| `optional_metadata` | No | — | Comma-separated spec-config field names to copy into the minted credential data. |
| `display_name` | No | `API Key` | Human-readable label used in logs and errors. |
| `ca_data` | No | — | Base64-encoded PEM CA bundle for custom/self-signed CAs. (secret, masked on read) |
| `tls_skip_verify` | No | `false` | Skip TLS certificate verification (development only). |

## Specs and mint methods

There is a single mint path. The spec carries the actual key plus whatever fields the source named in `optional_metadata`.

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `api_key` | Yes | — | The API key to serve. Returned verbatim as the credential. |
| *fields from `optional_metadata`* | No | — | Any field named in the source's `optional_metadata` (e.g. `organization_id`, `project_id`) is copied into the credential data when present. |

## Credential issued

Issues a credential of type `api_key`. It is **static** — no lease, no TTL — and **not revocable**: revocation is a no-op because the key is owned and rotated outside Warden. See [the lifetime model](../concepts/credentials.md#lifetime-and-revocation).

## Capabilities

- **Spec verification** — if `verify_endpoint` is set, creating or updating a spec triggers a light call to `api_url` + `verify_endpoint` using the configured method and auth header, retried on HTTP 429 or 500. A key that fails the call is rejected. With no `verify_endpoint`, verification is skipped.

No rotation of any kind — the key is static and managed upstream.

## Example

```bash
warden cred source create openai \
  -type=apikey \
  -config=api_url=https://api.openai.com \
  -config=verify_endpoint=/v1/models \
  -config=verify_method=GET \
  -config=auth_header_type=bearer \
  -config=optional_metadata=organization_id \
  -config=display_name=OpenAI \
  -rotation-period=0

warden cred spec create openai-team-a \
  -source=openai \
  -config=api_key=sk-proj-abc123... \
  -config=organization_id=org-XXXX
```

## See Also

- [Credentials](../concepts/credentials.md) — the source, spec, and credential model.
- [`local`](local.md) — static secrets with no upstream verification.
- [Credential drivers](README.md) — every driver.
