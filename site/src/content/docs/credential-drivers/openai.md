---
title: "OpenAI"
description: "Mint short-lived OpenAI access tokens through workload identity federation — no stored API key."
---

> Source `type`: `openai`

:::tip[Keyless only]
This driver holds no secret: federation is its only mode. A static OpenAI API key
belongs on an [`apikey`](/credential-drivers/apikey/) source instead — preferably
[chained](/federation/credential-chaining/) from your secret store.
:::

The OpenAI driver mints short-lived **OpenAI access tokens** through OpenAI's
**workload identity federation**. On each credential-cache miss, Warden signs an
[identity assertion](/federation/oidc-issuer/) for the caller and exchanges it at
OpenAI's auth host for a token that acts as one OpenAI **service account**. The
[OpenAI provider](/provider-backends/openai/) injects it as a bearer token.

The **source** names the OpenAI **identity provider** that trusts Warden's issuer. Each
**spec** names the service account the token acts as. One source can back many specs, one
per service account. An operator reaches for this driver to give agents OpenAI access
with no API key anywhere: not in Warden, not on the agent.

## How the exchange works

The exchange is an RFC 8693 token exchange, sent as JSON to
`<openai_auth_url>/oauth/token` — OpenAI's auth host, not the API host the mount proxies
to. It presents the assertion as a JWT `subject_token`, with the source's
`identity_provider_id` and the spec's `service_account_id`. There is **no client
authentication**: the assertion, checked against the identity provider, is the whole
proof.

On the OpenAI side, register Warden's issuer as a workload identity provider that
accepts the assertion's audience (the source's `audience`), and allow it to act as the
service account. Only the JWT subject-token variant is supported; OpenAI's X.509 variant
needs a client certificate, which the driver does not present.

## Credential issued

The credential type is **`oauth_bearer_token`**, inferred from the source. It is
**dynamic**: its lifetime is what OpenAI returns (capped at one hour, or 60 seconds when
OpenAI gives none), and Warden refreshes it 60 seconds before it expires, never past the
spec's `max_ttl`. It is **not revocable** — revocation is a no-op and the token simply
expires. See [the lifetime model](/concepts/credentials/#lifetime-and-revocation).

The token is issued for one service account, which already belongs to one organization
and one project, so the provider sends it **without** `OpenAI-Organization` or
`OpenAI-Project` headers.

## Capabilities

- **No rotation** — the source holds no secret, so it refuses a `rotation_period`.
- **No spec verification** — a spec is exercised on its first request, since the
  exchange needs a caller.

## Examples

```bash
warden cred source create openai-wif -json '{
  "type": "openai",
  "config": {
    "auth_method": "oidc_federation",
    "identity_provider_id": "<identity-provider-id>",
    "audience": "https://warden.example.com/openai"
  }
}'

warden cred spec create gpt-agents -json '{
  "source": "openai-wif",
  "config": {
    "subject_token_source": "warden_identity",
    "service_account_id": "<service-account-id>"
  }
}'
```

**Several service accounts** — one spec each, on the same source:

```bash
warden cred spec create gpt-batch -json '{
  "source": "openai-wif",
  "config": {
    "subject_token_source": "warden_identity",
    "service_account_id": "<another-service-account-id>"
  }
}'
```

## Source config

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `auth_method` | Yes | — | Must be `oidc_federation`, the only mode. It is required, not defaulted, so the source is recognised as federated. |
| `identity_provider_id` | Yes | — | OpenAI workload identity provider that trusts Warden's issuer. |
| `audience` | No | — | Audience the assertion is minted with — the one the identity provider expects. When unset, every spec must set `assertion_audience`. |
| `openai_auth_url` | No | `https://auth.openai.com` | Where the token exchange is sent. |
| `ca_data` | No | — | Base64-encoded PEM CA certificate for custom/self-signed CAs (masked on read). |
| `tls_skip_verify` | No | `false` | Skip TLS certificate verification (development only). |

`service_account_id` is refused on the source: it names one exchange target, and a
source serves many.

## Spec config

There is no `mint_method`: the exchange yields one kind of credential.

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `subject_token_source` | Yes | — | Must be `warden_identity`: the identity provider trusts a Warden-signed assertion. |
| `service_account_id` | Yes | — | Service account the token acts as. |

A spec refuses keys that would be read by nothing: `identity_provider_id` (it belongs on
the source), `audience` (override it with `assertion_audience`), `organization_id` and
`project_id` (the service account already fixes both), and the Anthropic keys
`federation_rule_id` and `workspace_id`. It accepts the other assertion-shaping keys
(`assertion_profile`, `assertion_metadata_claims`, `assertion_user_claims`,
`assertion_resource`, `assertion_algorithm`, `assertion_ttl`) — see
[Assertion claims](/federation/assertion-claims/). The derived `warden_resource` is
`openai:<service_account_id>`.

## See Also

- [OpenAI provider](/provider-backends/openai/) — the gateway that injects the token.
- [Keyless credential sources](/federation/keyless-credentials/) — the federation model.
- [Warden as an OIDC issuer](/federation/oidc-issuer/) — the issuer OpenAI must trust.
- [Credential drivers](/credential-drivers/) — every driver.
