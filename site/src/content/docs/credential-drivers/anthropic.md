---
title: "Anthropic"
description: "Mint short-lived Anthropic API tokens through workload identity federation — no stored API key."
---

> Source `type`: `anthropic`

:::tip[Keyless only]
This driver holds no secret: federation is its only mode. A static Anthropic API key
belongs on an [`apikey`](/credential-drivers/apikey/) source instead — preferably
[chained](/federation/credential-chaining/) from your secret store.
:::

The Anthropic driver mints short-lived **Anthropic API tokens** through Anthropic's
**workload identity federation**. On each credential-cache miss, Warden signs an
[identity assertion](/federation/oidc-issuer/) for the caller and exchanges it at
Anthropic's token endpoint for a token that acts as one Anthropic **service account**.
The [Anthropic provider](/provider-backends/anthropic/) injects it as a bearer token.

The **source** names the Anthropic organization whose federation issuer trusts Warden.
Each **spec** names the **federation rule** the assertion must satisfy and the service
account the token acts as — and, when the rule covers more than one, the workspace. One
source can back many specs, one per service account. An operator reaches for this driver
to give agents Anthropic access with no API key anywhere: not in Warden, not on the agent.

## How the exchange works

The exchange is an RFC 7523 `jwt-bearer` grant, sent as JSON to
`<anthropic_url>/v1/oauth/token`. The assertion is itself the grant, so the request
carries **no client authentication** — there is no client secret to hold. It sends the
assertion with the source's `organization_id` and the spec's `federation_rule_id`,
`service_account_id` and, when set, `workspace_id`.

On the Anthropic side, register Warden's issuer URL as a federation issuer in the
organization, and a federation rule that matches the assertion — its audience (the
source's `audience`) and subject — and names the service account it may act as.

## Credential issued

The credential type is **`oauth_bearer_token`**, inferred from the source. It is
**dynamic**: its lifetime is what Anthropic returns (capped at 24 hours, or 60 seconds
when Anthropic gives none), and Warden refreshes it 60 seconds before it expires, never
past the spec's `max_ttl`. It is **not revocable** — revocation is a no-op and the token
simply expires. See [the lifetime model](/concepts/credentials/#lifetime-and-revocation).

The credential's metadata records the `organization_id`, `federation_rule_id`,
`service_account_id`, `workspace_id` when set, the token's `expiration`, and the subject
it was minted for.

## Capabilities

- **No rotation** — the source holds no secret, so it refuses a `rotation_period`.
- **No spec verification** — a spec is exercised on its first request, since the
  exchange needs a caller.

## Examples

```bash
warden cred source create anthropic-wif -json '{
  "type": "anthropic",
  "config": {
    "auth_method": "oidc_federation",
    "organization_id": "4f8b2c1e-9a3d-4e6f-8b7a-2c5d1e0f9a3b",
    "audience": "https://warden.example.com/anthropic"
  }
}'

warden cred spec create claude-agents -json '{
  "source": "anthropic-wif",
  "config": {
    "subject_token_source": "warden_identity",
    "federation_rule_id": "fdrl_01AbCdEfGhIjKlMn",
    "service_account_id": "svac_01AbCdEfGhIjKlMn"
  }
}'
```

**A rule that covers several workspaces** — name the one the token acts in:

```bash
warden cred spec create claude-research -json '{
  "source": "anthropic-wif",
  "config": {
    "subject_token_source": "warden_identity",
    "federation_rule_id": "fdrl_01AbCdEfGhIjKlMn",
    "service_account_id": "svac_01AbCdEfGhIjKlMn",
    "workspace_id": "wrkspc_01AbCdEfGhIjKlMn"
  }
}'
```

## Source config

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `auth_method` | Yes | — | Must be `oidc_federation`, the only mode. It is required, not defaulted, so the source is recognised as federated. |
| `organization_id` | Yes | — | Anthropic organization the federation issuer and rules are registered in (a UUID). |
| `audience` | No | — | Audience the assertion is minted with — the one the federation rule matches. When unset, every spec must set `assertion_audience`. |
| `anthropic_url` | No | `https://api.anthropic.com` | Where the token exchange is sent. |
| `ca_data` | No | — | Base64-encoded PEM CA certificate for custom/self-signed CAs (masked on read). |
| `tls_skip_verify` | No | `false` | Skip TLS certificate verification (development only). |

`federation_rule_id`, `service_account_id` and `workspace_id` are refused on the source:
each names one exchange target, and a source serves many.

## Spec config

There is no `mint_method`: the exchange yields one kind of credential.

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `subject_token_source` | Yes | — | Must be `warden_identity`: the federation rule trusts a Warden-signed assertion. |
| `federation_rule_id` | Yes | — | Federation rule the assertion must satisfy; starts with `fdrl_`. |
| `service_account_id` | Yes | — | Service account the token acts as; starts with `svac_`. |
| `workspace_id` | No | — | Workspace the token acts in, needed only when the rule covers more than one; starts with `wrkspc_`. |

`organization_id` belongs on the source and `audience` is not read on a spec — override
the source's audience with `assertion_audience`. A spec also accepts the other
assertion-shaping keys (`assertion_profile`, `assertion_metadata_claims`,
`assertion_user_claims`, `assertion_resource`, `assertion_algorithm`, `assertion_ttl`) —
see [Assertion claims](/federation/assertion-claims/). The derived `warden_resource` is
`anthropic:<service_account_id>`.

## See Also

- [Anthropic provider](/provider-backends/anthropic/) — the gateway that injects the token.
- [Keyless credential sources](/federation/keyless-credentials/) — the federation model.
- [Warden as an OIDC issuer](/federation/oidc-issuer/) — the issuer Anthropic must trust.
- [Credential drivers](/credential-drivers/) — every driver.
