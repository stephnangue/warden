---
title: "Token Exchange"
---

> Source `type`: `token_exchange`

The **token-exchange driver** brokers a downstream bearer token by **exchanging a caller's identity** at an identity provider's token endpoint — RFC 8693 token-exchange, RFC 7523 `jwt-bearer` (Microsoft Entra OBO), or the ID-JAG cross-app-access flow. The workload presents only its own identity to Warden; Warden exchanges that identity for a scoped token for the upstream and injects it, so a downstream token never passes through the agent.

It is **exchange-only**: it never mints from static source config. Every spec must declare where the subject comes from, and the driver mints solely from that caller-derived subject (and an optional actor). The token endpoint, client identity, and grant live on the **source**; the target audience, scope, and token-exchange wiring live on the **spec**.

## Grant modes

- **`rfc8693`** — `grant_type=urn:ietf:params:oauth:grant-type:token-exchange` with `subject_token`, `subject_token_type`, `audience`/`scope`/`resource`, and (for delegation) `actor_token`.
- **`jwt_bearer`** — `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer` with the subject as `assertion`. Entra OBO adds `token_param.requested_token_use=on_behalf_of`.
- **`id_jag`** — two legs inside one mint: leg 1 exchanges the subject at `token_url` for an ID-JAG assertion (`requested_token_type=…:id-jag`, `audience`=the resource AS); leg 2 redeems the ID-JAG at `resource_token_url` via `jwt_bearer`. Only the final access token is returned.

## Impersonation vs delegation

RFC 8693 §1.1 distinguishes two outcomes by whether the **minted token carries an `act` claim** (delegation — an acting party is recorded) or not (impersonation — only the subject). An `act` claim arises two ways: Warden sends an `actor_token`, **or** the subject token already carries an embedded `act`.

**Warden sends no actor token** (`actor_token_source=none`) — forwards only a subject; works with `rfc8693` and `jwt_bearer`.
- Normally **impersonation** — the minted token represents only the subject:
  - `subject_token_source=auth_token` — act as the caller's own verified identity.
  - `subject_token_source=header` — act as a distinct identity the agent carries (e.g. a user token).
- **Pre-delegated subject:** if the subject token *already carries an embedded `act`* (it is itself a delegated token), the minted token inherits that chain, so the **result is delegation** even though Warden sent no actor token. This holds for either subject source, including `subject_token_source=auth_token`.

**Warden sends an actor token** (`actor_token_source=auth_token` or `header`) — adds an acting party, so the minted token carries an `act` chain ("agent acting for user"). **`rfc8693` only** (jwt-bearer has no actor slot).
- Preferred: `subject_token_source=header` (user token) + `actor_token_source=auth_token` (the agent's verified inbound JWT — sent once, not re-validated).
- `actor_token_source=header` when the actor is a distinct token the agent supplies.

`subject_token_source=auth_token` requires JWT-based inbound auth. `actor_token_source=auth_token` requires `subject_token_source=header` (one inbound token cannot be both subject and actor).

## Origin trust model

The driver receives one trust signal per token: its **origin**.

- **Verified** — the token is the caller's inbound JWT that Warden already authenticated at the auth mount (`…_token_source=auth_token`). Forwarded as-is.
- **Unverified** — the token was supplied on a request header (`…_token_source=header`). The driver **must** validate it — signature (via `subject_jwks_url`/`subject_oidc_discovery_url`), `subject_issuer`, `subject_audience`, and expiry — before forwarding, and **fails closed** if that validation config is absent. An unvalidated caller token never reaches the token endpoint.

Warden authenticates the caller on the verified token, not on a self-asserted `act` claim. The `act` chain a token carries is surfaced to [policy conditions](/concepts/policies/) and the audit trail — see the [on-behalf-of chain](/concepts/delegation/).

## Credential issued

Always `oauth_bearer_token`. It is **dynamic** when the token endpoint returns an expiry (re-minted on expiry) and non-revocable — bearer tokens expire naturally, so revocation is a no-op. See [the lifetime model](/concepts/credentials/#lifetime-and-revocation). The credential's audit metadata records the exchanged `subject` and `subject_verified`.

## Security

- Caller tokens are forwarded to the configured IdP — the IdP must be trusted to receive them.
- Unverified (header-sourced) subject and actor tokens are validated or the mint fails closed.
- `X-Warden-Subject-Token` / `X-Warden-Actor-Token` are stripped before any upstream forwarding.
- `client_secret` and `private_key` are masked; subject/actor/minted tokens are never logged.
- `tls_skip_verify` is for development only (a cleartext IdP would expose caller tokens).

## Examples

**RFC 8693 OBO of the caller's own identity** — the agent's verified inbound JWT is exchanged for a token scoped to an internal API.

```bash
warden cred source create idp-exchange \
  -type=token_exchange \
  -config=token_url=https://idp.example.com/oauth2/v1/token \
  -config=client_auth=client_secret_post \
  -config=client_id=warden-gateway \
  -config=client_secret="$OAUTH_CLIENT_SECRET"

warden cred spec create internal-api \
  -source=idp-exchange \
  -config=subject_token_source=auth_token \
  -config=audience=https://api.internal.example.com \
  -config=scope=read:orders
```

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
  -config=subject_token_source=auth_token \
  -config=scope=https://graph.microsoft.com/.default
```

**Header-sourced subject (a carried user token)** — the agent supplies a user's token in `X-Warden-Subject-Token`; the source's `subject_*` keys let the driver validate it before exchanging.

```bash
warden cred source create partner-idp \
  -type=token_exchange \
  -config=token_url=https://idp.example.com/oauth2/v1/token \
  -config=client_auth=client_secret_post \
  -config=client_id=warden-gateway \
  -config=client_secret="$OAUTH_CLIENT_SECRET" \
  -config=subject_jwks_url=https://login.example.com/keys \
  -config=subject_issuer=https://login.example.com/ \
  -config=subject_audience=api://warden

warden cred spec create internal-api \
  -source=partner-idp \
  -config=subject_token_source=header \
  -config=audience=https://api.internal.example.com
```

**`private_key_jwt` client authentication** — Warden signs a client assertion instead of sending a secret.

```bash
warden cred source create idp-pkjwt \
  -type=token_exchange \
  -config=token_url=https://idp.example.com/oauth2/v1/token \
  -config=client_auth=private_key_jwt \
  -config=client_id=warden-gateway \
  -config=private_key="$(cat client-key.pem)"
```

**Delegation — agent acting for a user** — the user's token is the subject (header); the agent's own verified inbound JWT is the actor. The minted token carries an `act` chain.

```bash
warden cred spec create internal-api-deleg \
  -source=idp-exchange \
  -config=subject_token_source=header \
  -config=actor_token_source=auth_token \
  -config=audience=https://api.internal.example.com
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
  -config=subject_token_source=auth_token \
  -config=audience=https://auth.resourceapp.example.com \
  -config=scope=files:read
```

## Source config

Keys for `warden cred source create <name> -type=token_exchange -config=key=value ...`:

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `token_url` | Yes | — | Token endpoint (HTTPS) of the STS/IdP performing the exchange. |
| `grant` | No | `rfc8693` | Exchange grant: `rfc8693`, `jwt_bearer`, or `id_jag`. |
| `client_auth` | No | `client_secret_post` | How Warden authenticates to the token endpoint: `client_secret_basic`, `client_secret_post`, or `private_key_jwt`. |
| `client_id` | Yes | — | OAuth2 client ID Warden presents to the token endpoint. |
| `client_secret` | For secret auth | — | Client secret (secret, masked on read). |
| `private_key` | For `private_key_jwt` | — | PEM RSA private key that signs the client assertion (secret, masked on read). |
| `client_assertion_alg` | No | `RS256` | Signing algorithm for the client assertion (RS256). |
| `client_assertion_kid` | No | — | Optional `kid` header for the client assertion. |
| `resource_token_url` | For `id_jag` | — | Resource authorization-server token endpoint (HTTPS) for ID-JAG leg 2. |
| `subject_oidc_discovery_url` | For `header` subjects | — | OIDC discovery URL of the issuer that signs caller-supplied tokens. |
| `subject_jwks_url` | For `header` subjects | — | JWKS URL for caller-supplied token signature validation. |
| `subject_issuer` | For `header` subjects | — | Expected `iss` of a caller-supplied token. |
| `subject_audience` | For `header` subjects | — | Expected `aud` of a caller-supplied token. |
| `ca_data` | No | — | Base64-encoded PEM CA certificate for custom/self-signed CAs (secret, masked on read). |
| `tls_skip_verify` | No | `false` | Skip TLS certificate verification (development only). |

Vendor-specific token-endpoint parameters go through `token_param.*` (e.g. `token_param.requested_token_use=on_behalf_of`); they may not override a core exchange field.

## Spec config

Every `token_exchange` spec **must** set `subject_token_source`. Keys operators set with `warden cred spec create ... -config=key=value`:

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `subject_token_source` | Yes | — | Subject origin: `auth_token` (the caller's verified inbound JWT) or `header` (`X-Warden-Subject-Token`, validated by the driver). |
| `subject_token_type` | No | `…:token-type:jwt` | RFC 8693 subject token type. Some STSs are strict — e.g. Keycloak's Standard Token Exchange accepts only `urn:ietf:params:oauth:token-type:access_token`, so set this explicitly for them. |
| `actor_token_source` | No | `none` | Delegation actor: `none`, `auth_token` (the agent's inbound JWT), or `header` (`X-Warden-Actor-Token`). |
| `actor_token_type` | No | `…:token-type:jwt` | RFC 8693 actor token type. |
| `audience` | No | — | Target audience for the exchanged token (the resource AS for `id_jag`). |
| `scope` | No | — | Scope requested for the exchanged token. |
| `resource` | No | — | RFC 8707 resource indicator. |
