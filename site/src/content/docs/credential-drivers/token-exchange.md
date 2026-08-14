---
title: "Token Exchange"
description: "Broker a downstream bearer token by exchanging the caller's identity — RFC 8693, RFC 7523, ID-JAG."
---

> Source `type`: `token_exchange`

:::tip[Prefer keyless]
This driver supports a **keyless mode** — use it instead of storing a secret inline. A stored secret is attack surface; keyless holds nothing. See [Keyless (by chaining the client secret)](#sourcing-the-client-secret-keylessly).
:::

The **token-exchange driver** brokers a downstream bearer token by **exchanging a
caller's identity** at an identity provider's token endpoint — RFC 8693 token-exchange,
RFC 7523 `jwt-bearer` (Microsoft Entra OBO), or the ID-JAG cross-app-access flow. The
workload presents only its own identity to Warden; Warden exchanges that identity for a
scoped token for the upstream and injects it, so a downstream token never passes through
the agent.

It is **exchange-only**: it never mints from static source config. Every spec declares
where the subject comes from, and the driver mints solely from that caller-derived
subject (and an optional actor). The token endpoint, client identity, and grant live on
the **source**; the target audience, scope, and token-exchange wiring live on the
**spec**.

## Sourcing the client secret keylessly

The token endpoint requires client authentication (`client_secret_*` or a
`private_key_jwt` client assertion). Rather than storing that secret inline, a source can
**chain it**: set `secret_spec` (and optional `secret_field`) to fetch the `client_secret`
— or the `private_key` for `client_auth=private_key_jwt` — from another cred spec at mint
time. `client_id` stays in config and the inline secret is omitted, so the exchange
becomes **keyless at Warden**. The same keys cover `client_secret_basic`/`_post`,
`private_key_jwt`, and both legs of an ID-JAG exchange. See
[credential chaining](/federation/credential-chaining/).

## Grant modes

- **`rfc8693`** — `grant_type=urn:ietf:params:oauth:grant-type:token-exchange` with
  `subject_token`, `subject_token_type`, `audience`/`scope`/`resources`, and (for
  delegation) `actor_token`.
- **`jwt_bearer`** — `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer` with the
  subject as `assertion`. Entra OBO adds `token_param.requested_token_use=on_behalf_of`.
- **`id_jag`** — two legs inside one mint: leg 1 exchanges the subject at `token_url` for
  an ID-JAG assertion (`requested_token_type=…:id-jag`, `audience`=the resource AS); leg 2
  redeems the ID-JAG at `resource_token_url` via `jwt_bearer`. Only the final access token
  is returned.

## Subject and actor: identities by source

:::caution[Upgrading from v0.18.0]
`auth_token` is renamed to `agent_identity`; the `header` source, the
`subject_token_header` / `actor_token_header` keys, and the `subject_issuer` /
`subject_audience` / `subject_jwks_url` / `subject_oidc_discovery_url` trust keys are
removed. See [Upgrading from v0.18.0](/upgrade/from-v0-18/#3-rfc-8693-token-exchange-reshaped-around-the-user).
:::

Every exchange has a **subject** — the identity the new token will *represent* — and may
name an **actor** — a second identity recorded as *acting on behalf of* the subject.
Whether the minted token names an actor decides the outcome (RFC 8693 §1.1): a token with
no actor is **impersonation**; one that carries an `act` claim is **delegation**.

Each identity is drawn from a **source**, and every source is trusted at origin (there is
no caller-supplied, per-request-validated token path):

| `subject_token_source` | The subject is |
|---|---|
| `agent_identity` | The agent's own verified inbound JWT (the identity it authenticated to Warden with). |
| `user_identity` | The [user principal's](/concepts/delegation/) own auth-method-validated credential — the human the agent acts for. Valid only on a `token_exchange` source. |
| `warden_identity` | A [Warden-minted assertion](/federation/oidc-issuer/) for the caller. |
| `none` | No subject. |

`actor_token_source` is `agent_identity`, `warden_identity`, or `none`. An actor is only
meaningful in the delegation shape, so **`actor_token_source ≠ none` requires
`subject_token_source=user_identity`.**

The canonical **agent-on-behalf-of-user** delegation is therefore:

```
subject_token_source=user_identity   # sub = the user
actor_token_source=warden_identity    # act = the agent
```

→ a downstream token with `sub`=user, `act`=agent, and no stored secret. The
[Delegation page](/concepts/delegation/) is the canonical reference for the dual-principal
model and how the user principal is presented; this page covers the exchange mechanics.

> **Delegation is `rfc8693`-only.** The `jwt_bearer`/Entra grant has no slot for an actor
> token, so an actor is rejected there. Impersonation works with both grants. A subject
> that is *itself* already a delegated token (it carries an embedded `act`) yields a
> delegation result on its own.

## Credential issued

Always `oauth_bearer_token`. It is **dynamic** when the token endpoint returns an expiry
(re-minted on expiry) and non-revocable — bearer tokens expire naturally, so revocation is
a no-op. See [the lifetime model](/concepts/credentials/#lifetime-and-revocation). The
credential's audit metadata records the exchanged `subject`.

## Security

- Caller tokens are forwarded to the configured IdP — the IdP must be trusted to receive them.
- `client_secret` and `private_key` are masked (or sourced via `secret_spec`); subject/actor/minted tokens are never logged.
- `tls_skip_verify` is for development only (a cleartext IdP would expose caller tokens).

## Examples

### Keyless (recommended)

**Chained client secret (`private_key_jwt`)** — Warden signs a client assertion with a private key fetched from another cred spec, so no secret is stored inline.

```bash
warden cred source create idp-pkjwt \
  -type=token_exchange \
  -config=token_url=https://idp.example.com/oauth2/v1/token \
  -config=client_auth=private_key_jwt \
  -config=client_id=warden-gateway \
  -config=secret_spec=idp-client-key
```

### Inline secret (discouraged)

**RFC 8693 OBO of the agent's own identity** — the agent's verified inbound JWT is exchanged for a token scoped to an internal API.

```bash
warden cred source create idp-exchange \
  -type=token_exchange \
  -config=token_url=https://idp.example.com/oauth2/v1/token \
  -config=client_auth=client_secret_post \
  -config=client_id=warden-gateway \
  -config=client_secret="$OAUTH_CLIENT_SECRET"

warden cred spec create internal-api \
  -source=idp-exchange \
  -config=subject_token_source=agent_identity \
  -config=audience=https://api.internal.example.com \
  -config=scope=read:orders \
  -config=resources="https://api.internal.example.com https://reports.internal.example.com"
```

`resources` is a space-separated list of RFC 8707 resource indicators, sent as repeated
`resource` parameters so the exchanged token can be bound to one or more downstream APIs.

**Agent acting for a user (delegation)** — the user principal is the subject; the agent is the actor. The minted token carries an `act` chain.

```bash
warden cred spec create internal-api-deleg \
  -source=idp-exchange \
  -config=subject_token_source=user_identity \
  -config=actor_token_source=warden_identity \
  -config=audience=https://api.internal.example.com
```

The user is presented via secondary transparent authentication — see
[Delegation](/concepts/delegation/) for how `user_auth_path` and `X-Warden-User-Token` are
configured.

**Microsoft Entra OBO (`jwt_bearer`)** — the subject is sent as `assertion` with Entra's on-behalf-of flag.

```bash
warden cred source create entra-obo \
  -type=token_exchange \
  -config=token_url=https://login.microsoftonline.com/$TENANT/oauth2/v2.0/token \
  -config=grant=jwt_bearer \
  -config=client_auth=client_secret_post \
  -config=client_id=$CLIENT_ID \
  -config=client_secret="$CLIENT_SECRET" \
  -config=token_param.requested_token_use=on_behalf_of

warden cred spec create graph \
  -source=entra-obo \
  -config=subject_token_source=agent_identity \
  -config=scope=https://graph.microsoft.com/.default
```

**ID-JAG cross-app access** — two legs in one mint: an ID-JAG from the home IdP, redeemed at the resource authorization server.

```bash
warden cred source create crossapp \
  -type=token_exchange \
  -config=grant=id_jag \
  -config=token_url=https://idp.example.com/oauth2/v1/token \
  -config=resource_token_url=https://auth.resourceapp.example.com/oauth2/token \
  -config=client_auth=private_key_jwt \
  -config=client_id=warden-gateway \
  -config=private_key="$(cat client-key.pem)"

warden cred spec create resource-api \
  -source=crossapp \
  -config=subject_token_source=agent_identity \
  -config=audience=https://auth.resourceapp.example.com \
  -config=scope=files:read \
  -config=resources=https://files.resourceapp.example.com
```

For `id_jag`, `resources` is sent on **leg 2** (the resource-AS redemption), so it scopes
the final access token — `audience` still binds the ID-JAG to the resource authorization
server on leg 1.

## Source config

Keys for `warden cred source create <name> -type=token_exchange -config=key=value ...`:

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `token_url` | Yes | — | Token endpoint (HTTPS) of the STS/IdP performing the exchange. |
| `grant` | No | `rfc8693` | Exchange grant: `rfc8693`, `jwt_bearer`, or `id_jag`. |
| `client_auth` | No | `client_secret_post` | How Warden authenticates to the token endpoint: `client_secret_basic`, `client_secret_post`, or `private_key_jwt`. |
| `client_id` | Yes | — | OAuth2 client ID Warden presents to the token endpoint. |
| `client_secret` | For secret auth | — | Client secret (masked on read). Omit when sourced via `secret_spec`. |
| `private_key` | For `private_key_jwt` | — | PEM RSA private key that signs the client assertion (masked). Omit when sourced via `secret_spec`. |
| `secret_spec` | No | — | Source the `client_secret`/`private_key` from another cred spec via [credential chaining](/federation/credential-chaining/) instead of storing it inline. |
| `secret_field` | No | — | Field of the referenced `secret_spec`'s credential holding the secret (when its payload has multiple keys). |
| `secret_cache_ttl` | No | *(off)* | Cache the chained secret for a bounded TTL, keyed on the source. |
| `client_assertion_alg` | No | `RS256` | Signing algorithm for the client assertion. |
| `client_assertion_kid` | No | — | Optional `kid` header for the client assertion. |
| `resource_token_url` | For `id_jag` | — | Resource authorization-server token endpoint (HTTPS) for ID-JAG leg 2. |
| `ca_data` | No | — | Base64-encoded PEM CA certificate for custom/self-signed CAs (masked). |
| `tls_skip_verify` | No | `false` | Skip TLS certificate verification (development only). |

Vendor-specific token-endpoint parameters go through `token_param.*` (e.g.
`token_param.requested_token_use=on_behalf_of`); they may not override a core exchange
field.

## Spec config

Every `token_exchange` spec **must** set `subject_token_source`. Keys operators set with
`warden cred spec create ... -config=key=value`:

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `subject_token_source` | Yes | — | Subject origin: `agent_identity`, `user_identity`, `warden_identity`, or `none`. |
| `subject_token_type` | No | `…:token-type:jwt` | RFC 8693 subject token type. Some STSs are strict — e.g. Keycloak's Standard Token Exchange accepts only `urn:ietf:params:oauth:token-type:access_token`. |
| `actor_token_source` | No | `none` | Delegation actor: `none`, `agent_identity`, or `warden_identity`. Non-`none` requires `subject_token_source=user_identity`. |
| `actor_token_type` | No | `…:token-type:jwt` | RFC 8693 actor token type. |
| `audience` | No | — | Target audience for the exchanged token (the resource AS for `id_jag`). |
| `scope` | No | — | Scope requested for the exchanged token. |
| `resources` | No | — | RFC 8707 resource indicator(s) — space-separated absolute URIs, sent as repeated `resource` parameters. For `id_jag`, on leg 2 (the final access token). |

## See Also

- [Delegation](/concepts/delegation/) — the dual-principal model and the user principal.
- [Credential chaining](/federation/credential-chaining/) — sourcing the client secret keylessly.
- [Credentials](/concepts/credentials/) — the source / spec / credential model.
