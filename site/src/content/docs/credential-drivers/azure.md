---
title: "Azure"
---

> Source `type`: `azure`

:::tip[Prefer keyless]
This driver supports a **keyless mode** — use it instead of storing a secret inline. A stored secret is attack surface; keyless holds nothing. See [Keyless (OIDC federation)](#keyless-oidc-federation).
:::

The Azure driver brokers credentials against **Entra ID** (Azure AD) and **Azure Key
Vault**. A **spec** mints short-lived **Entra bearer tokens** for a workload service
principal, exchanges a signed-in user's Entra token for a **delegated token** through
[on-behalf-of](#on_behalf_of--delegated-user-tokens), or reads a **Key Vault secret** — for
an agent, or as the producer at the far end of a
[credential chain](/federation/credential-chaining/). An operator reaches for this driver
to hand workloads scoped Azure access tokens without distributing a long-lived client
secret, to let an agent call Microsoft Graph as the user it works for, or to read secrets
out of Key Vault on demand.

A source authenticates to Entra in one of three ways. Keyless, neither the source nor its
specs hold a secret: each request presents a Warden identity assertion to Entra in place
of a client secret. With a [certificate](#certificate-authentication), the source signs a
client assertion with a certificate registered on the app, and its key can stay in a KMS.
With a stored secret, the
**source** holds a privileged service-principal login (tenant, client id and client
secret) that Warden uses to authenticate to Entra and to call **Microsoft Graph**, and a
bearer-token spec carries its own workload service principal's `client_id` and
`client_secret`. In that mode the driver rotates **both** its own source secret **and**
the secret embedded in a spec, through Microsoft Graph — the only driver that rotates a
spec's own secret.

## Keyless (OIDC federation)

Set `auth_method = "oidc_federation"` on the source to hold **no Azure secret**: instead
of a `client_secret`, Warden presents an [identity assertion](/federation/oidc-issuer/)
to Entra as a `client_assertion` (JWT-bearer grant). Every mint method federates:

- **`bearer_token`** — a short-lived Entra token for the spec's workload app.
- **`secret_read`** — a Key Vault read, authenticated as the app registration the spec
  names.
- **`on_behalf_of`** — a delegated token for the user. The user's token is the grant's
  assertion, and the Warden assertion, in the actor slot, authenticates the app.

The source may set `audience` (default `api://AzureADTokenExchange`); the spec sets
`subject_token_source` (`warden_identity` or `agent_identity`), and the `client_id` and
`tenant_id` of the app registration whose federated credential trusts Warden's issuer.
See [Keyless credential sources](/federation/keyless-credentials/).

An Entra federated identity credential matches `iss`, `sub` and `aud` exactly and reads no
other claim, so a new federated spec is written with
[`assertion_profile=minimal`](/federation/assertion-claims/#the-minimal-profile): the
registered claims only. The `sub` is the agent's composite `wid:…` subject — Entra cannot
bind a user, so none is ever disclosed to it.

## Certificate authentication

Set `auth_method = "certificate"` when the tenant allows neither of the other two: an app
management policy blocks new client secrets, or Entra cannot reach Warden's issuer, or an
app would need more than 20 federated credentials. The app proves itself with a
certificate registered on it.

Every call that authenticates as the source's app uses the certificate: source tokens for
Resource Manager, Graph and Key Vault, on-behalf-of exchanges, and the Graph token for
spec rotation. Each sends a fresh client assertion, signed **PS256**, valid five minutes,
that names the certificate by its SHA-256 thumbprint (`x5t#S256`). No secret is sent.

The source holds `tenant_id`, `client_id` and `certificate`, a single PEM leaf with an RSA
key of at least 2048 bits, valid now. The key is held one of two ways:

- **A local key**: `private_key`, PKCS#1 or PKCS#8, masked on read and counted as a stored
  secret. A key that does not match the certificate is refused.
- **A KMS-held key**: no `private_key`. The source's `secret_spec` names a
  [`transit_signer`](/credential-drivers/vault/#transit_signer--signing-without-the-key)
  spec with `signing_alg=PS256` and `payload.client_id` set to the source's `client_id`.
  Each mint fetches a signing capability through that spec, as the caller, and the KMS
  signs the assertion, so Warden never holds the key. `secret_cache_ttl` may bound how
  long a fetched capability is reused. Before first use of each key version, Warden checks
  the key against the certificate.

A KMS-held key signs only during a mint, so such a source serves `secret_read` and
`on_behalf_of`. A `bearer_token` spec on it is refused, `Create` makes no probe call, and
spec rotation is not available.

A certificate source refuses `client_secret`, `secret_id` and `audience`. A source read
adds `certificate_info`: the certificate's `subject`, `not_before`, `not_after`,
`days_remaining`, `x5t_s256` and `thumbprint_sha1`, so you can match it against the
thumbprint Entra lists for the app. Warden logs a warning when the certificate expires
within 30 days, and an error within 7 days, at most once a day.

:::caution[Certificates are not rotated]
`rotation_period` is refused on a certificate source. Roll the certificate over by hand,
without downtime: register the new certificate on the app next to the old one, update the
source's `certificate` (and `private_key`, for a local key), then remove the old one from
the app. An expired certificate fails every mint, and Warden reports the expiry itself
rather than sending a request Entra would refuse. Entra answers `AADSTS700027` when the
certificate is not registered on the app, has expired there, or does not match the key;
Warden's error names the certificate's `x5t#S256`.
:::

## Credential issued

The default `bearer_token` method issues an `azure_bearer_token` — a **dynamic**
credential that carries the token's Entra TTL, and is **not revocable**: Azure bearer
tokens expire naturally, so revocation is a no-op. `on_behalf_of` issues an
`azure_bearer_token` too, delegated by the user, and cached per user token: it never
outlives the user's own token entry. The `secret_read` method issues a
`key_value` credential — the secret's payload under its own key names, with no lease,
bounded by the secret's own `exp` when it has one. See
[the lifetime model](/concepts/credentials/#lifetime-and-revocation).

:::caution[`key_vault_secret` is removed]
The former `mint_method=key_vault_secret` fails every mint, and a write naming it is
refused. Read Key Vault secrets with **`secret_read`** (type `key_value`) instead. Writes
also refuse `azure_db_iam_token`, the retired `scopes` key (set `resource_uri`), and a
`client_id` or `tenant_id` that is not a UUID. See
[Upgrading from v0.20.0](/upgrade/from-v0-20/#6-azure-key_vault_secret-specs-fail-every-mint).
:::

## Capabilities

- **Source rotation** — **slow**: stages a new source `client_secret` (a fresh Azure AD
  password credential added via Microsoft Graph) and waits ~5m (default, tunable via the
  source's `activation_delay`) so it propagates across Azure AD before the old secret is
  destroyed. Requires the source service principal to hold `Application.ReadWrite.All`.
- **Spec rotation** — **slow**: rotates the workload service principal's `client_secret`
  stored in the spec, again through Microsoft Graph and with the same propagation wait.
  This is the only driver that rotates a spec's own embedded secret.

A certificate source rotates nothing of its own (see
[Certificate authentication](#certificate-authentication)); with a local key, it still
rotates its specs' secrets. No spec verification.

## Examples

### Keyless (recommended)

The source stores no client secret; Warden presents an identity assertion to Entra as a
`client_assertion`.

```bash
warden cred source create azure-keyless -json '{
  "type": "azure",
  "config": {
    "auth_method": "oidc_federation"
  }
}'
```

**Bearer token** — a short-lived Entra token for Azure Resource Manager:

```bash
warden cred spec create arm-token -json '{
  "source": "azure-keyless",
  "config": {
    "mint_method": "bearer_token",
    "subject_token_source": "warden_identity",
    "tenant_id": "00000000-0000-0000-0000-000000000000",
    "client_id": "22222222-2222-2222-2222-222222222222",
    "resource_uri": "https://management.azure.com/"
  }
}'
```

The spec's `client_id` is the **workload** app — the Entra app registration that trusts
Warden's issuer as a federated credential. It carries no `client_secret`; the assertion is
presented as its `client_assertion`.

**Key Vault secret** — read a secret keylessly, for an agent or as a chaining producer:

```bash
warden cred spec create datadog-keys -json '{
  "source": "azure-keyless",
  "config": {
    "mint_method": "secret_read",
    "subject_token_source": "warden_identity",
    "tenant_id": "00000000-0000-0000-0000-000000000000",
    "client_id": "33333333-3333-3333-3333-333333333333",
    "vault_name": "acme-prod-kv",
    "secret_name": "datadog-keys"
  }
}'
```

The app registration needs read access to secrets in the vault. A consumer spec on
another driver names `datadog-keys` as its `secret_spec`, and the secret never sits in
Warden — see [credential chaining](/federation/credential-chaining/).

**On-behalf-of** — a delegated Microsoft Graph token for the user the agent works for:

```bash
warden cred spec create graph-obo -json '{
  "source": "azure-keyless",
  "config": {
    "mint_method": "on_behalf_of",
    "subject_token_source": "user_identity",
    "actor_token_source": "warden_identity",
    "tenant_id": "00000000-0000-0000-0000-000000000000",
    "client_id": "44444444-4444-4444-4444-444444444444",
    "resource_uri": "https://graph.microsoft.com/"
  }
}'
```

The user's Entra token must be issued for app `client_id`, and that app's federated
credential must trust Warden's issuer. The provider mount needs a `user_auth_path`; see
the [Microsoft Graph provider](/provider-backends/msgraph/).

### Certificate

With a **local key**, build the payload with `jq`, since PEM values span lines:

```bash
jq -n --rawfile cert app-cert.pem --rawfile key app-key.pem '{
  "type": "azure",
  "config": {
    "auth_method": "certificate",
    "tenant_id": "00000000-0000-0000-0000-000000000000",
    "client_id": "44444444-4444-4444-4444-444444444444",
    "certificate": $cert,
    "private_key": $key
  }
}' | warden cred source create azure-cert -json -
```

With a **KMS-held key**, first create the signer spec on a `hvault` source, then name it
as the source's `secret_spec`. The certificate is issued for the transit key's public
half:

```bash
warden cred spec create graph-cert-signer -json '{
  "source": "vault-keyless",
  "config": {
    "mint_method": "transit_signer",
    "subject_token_source": "warden_identity",
    "jwt_role": "warden-signer",
    "transit_mount": "transit",
    "transit_key": "graph-app-cert",
    "signing_alg": "PS256",
    "payload.client_id": "44444444-4444-4444-4444-444444444444"
  }
}'

jq -n --rawfile cert app-cert.pem '{
  "type": "azure",
  "config": {
    "auth_method": "certificate",
    "tenant_id": "00000000-0000-0000-0000-000000000000",
    "client_id": "44444444-4444-4444-4444-444444444444",
    "certificate": $cert,
    "secret_spec": "graph-cert-signer",
    "secret_cache_ttl": "5m"
  }
}' | warden cred source create azure-cert-kms -json -
```

An on-behalf-of spec over either source names no actor, and its `client_id` and
`tenant_id` are the source's:

```bash
warden cred spec create graph-obo-cert -json '{
  "source": "azure-cert",
  "config": {
    "mint_method": "on_behalf_of",
    "subject_token_source": "user_identity",
    "tenant_id": "00000000-0000-0000-0000-000000000000",
    "client_id": "44444444-4444-4444-4444-444444444444"
  }
}'
```

Read the source to see `certificate_info`:

```bash
warden cred source read azure-cert
```

### Inline secret (discouraged)

With a stored secret, one source holds the privileged service-principal login; each
bearer-token spec carries its own workload service-principal credentials.

```bash
warden cred source create azure-prod \
  -type=azure \
  -config=tenant_id=00000000-0000-0000-0000-000000000000 \
  -config=client_id=11111111-1111-1111-1111-111111111111 \
  -config=client_secret=s3cr3t-value \
  -config=secret_id=22222222-2222-2222-2222-222222222222 \
  -rotation-period=720h
```

**Rotating bearer token** — a spec whose embedded `client_secret` Warden rotates on a
schedule through Microsoft Graph:

```bash
warden cred spec create graph-token \
  -source=azure-prod \
  -config=mint_method=bearer_token \
  -config=client_id=55555555-5555-5555-5555-555555555555 \
  -config=client_secret=workload-s3cr3t \
  -config=secret_id=66666666-6666-6666-6666-666666666666 \
  -config=resource_uri=https://graph.microsoft.com/ \
  -rotation-period=720h
```

**Key Vault secret** — on a static source, the source's own service principal reads:

```bash
warden cred spec create db-password \
  -source=azure-prod \
  -config=mint_method=secret_read \
  -config=vault_name=prod-kv \
  -config=secret_name=db-connection-string
```

## Source config

Keys for `warden cred source create <name> -type=azure`:

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `auth_method` | No | `static` | How the source authenticates: `static` (stored client secret), `oidc_federation` ([keyless](/federation/keyless-credentials/) — presents an assertion to Entra as a `client_assertion`) or `certificate` (a [certificate](#certificate-authentication) registered on the app). |
| `tenant_id` | For `static`, `certificate` | — | Entra tenant ID (UUID). |
| `client_id` | For `static`, `certificate` | — | Application (client) ID of the source service principal (UUID). |
| `client_secret` | For `static` | — | Client secret for the source service principal (masked). Refused for keyless and `certificate`. |
| `secret_id` | For `static` | — | Key ID of the current client secret, tracked so rotation can retire the old one. Refused for keyless and `certificate`. |
| `certificate` | For `certificate` | — | PEM certificate registered on the app: one leaf, RSA of at least 2048 bits, valid now. Public, shown on read. |
| `private_key` | For `certificate`, unless `secret_spec` | — | PEM RSA private key of the certificate, PKCS#1 or PKCS#8 (masked). Must match the certificate. |
| `secret_spec` | No | — | `certificate` only: a `transit_signer` spec with `signing_alg=PS256` that signs with the certificate's KMS-held key. Exclusive with `private_key`. |
| `secret_cache_ttl` | No | — | With `secret_spec` only: how long a fetched signing capability is reused. |
| `audience` | No | `api://AzureADTokenExchange` | Audience minted into the `warden_identity` assertion (`oidc_federation` only; refused on a `static` or `certificate` source). |
| `activation_delay` | No | `5m` | How long a rotated client secret propagates through Entra before Warden switches to it. |
| `login_endpoint` | No | `https://login.microsoftonline.com` | Override the Entra authority host every token request goes to. |
| `key_vault_endpoint` | No | `https://<vault_name>.vault.azure.net` | Override the Key Vault base URL for every vault this source reads. |
| `ca_data` | No | — | Base64-encoded PEM CA bundle for custom/self-signed CAs (secret, masked on read). |
| `tls_skip_verify` | No | `false` | Skip TLS certificate verification (development only). |

A source that sets `login_endpoint` or `key_vault_endpoint` cannot set a
`rotation_period`: rotation manages client secrets in the real tenant through Microsoft
Graph, which those overrides do not redirect. A `certificate` source cannot set one either.

## Specs and mint methods

| `mint_method` | Issues | Notable spec config |
|---------------|--------|---------------------|
| `bearer_token` (default) | `azure_bearer_token` — an Entra bearer token for a resource | `client_id`, `tenant_id` (keyless), `client_secret` + `secret_id` (static), `resource_uri` |
| `secret_read` | `key_value` — a Key Vault secret's payload | `vault_name`, `secret_name`, `client_id` + `tenant_id` (keyless) |
| `on_behalf_of` | `azure_bearer_token` — a token delegated by the user | `subject_token_source=user_identity`, `actor_token_source` (keyless), `client_id`, `tenant_id`, `resource_uri` |

**`bearer_token`** keys:

| Key | Required | Default | Meaning |
|-----|----------|---------|---------|
| `mint_method` | No | `bearer_token` | Which credential to mint. |
| `subject_token_source` | For keyless | — | On an `oidc_federation` source: the federated subject — `warden_identity` or `agent_identity`. |
| `client_id` | Yes | — | Workload app's application (client) ID (UUID). |
| `tenant_id` | For keyless | source `tenant_id` | Tenant of the workload app (UUID). |
| `client_secret` | For static | — | Workload service-principal client secret. **Refused for keyless** — the assertion is the `client_assertion`. |
| `secret_id` | For static | — | Key ID of the spec's client secret, tracked for spec rotation. |
| `resource_uri` | No | `https://management.azure.com/` | Resource the token targets; the grant asks for its `.default` scope. |

**`secret_read`** keys (type `key_value`, inferred from the mint method):

| Key | Required | Default | Meaning |
|-----|----------|---------|---------|
| `vault_name` | Yes | — | Key Vault name: 3–24 letters, digits and hyphens. Not templatable. |
| `secret_name` | Yes | — | Secret name. Accepts `{{user.<claim>}}` and `{{agent.<claim>}}` templating. |
| `secret_version` | No | current | Pin a 32-character version identifier. A pinned spec does not follow rotation. |
| `json_key_map` | No | — | Comma-separated `srcKey=destKey` selection of the payload's fields; unnamed keys are not vended. Omit to vend the payload verbatim. |
| `subject_token_source` | For keyless | — | `warden_identity` or `agent_identity`. |
| `client_id`, `tenant_id` | For keyless | — | The app registration the caller's token is exchanged at (UUIDs). Refused without `subject_token_source` — a static source reads as itself. |

A disabled secret, one before its `nbf` or past its `exp`, and a value over 25 KB are
refused at read.

### `on_behalf_of` — delegated user tokens

`on_behalf_of` exchanges the user's own Entra access token, issued for the app the spec
names, for a delegated token to `resource_uri`, with Entra's on-behalf-of grant. The
upstream sees the user's own permissions. The user's token is only ever the grant's
`assertion`, never the app's credential. What authenticates the app depends on the
source:

| Source `auth_method` | The app authenticates with | `actor_token_source` | `client_id`, `tenant_id` |
|---|---|---|---|
| `oidc_federation` | A Warden assertion of the agent, checked by the app's federated identity credential | `warden_identity`, required | Any app whose federated credential trusts Warden |
| `certificate` | A certificate assertion | Refused | The source's own |
| `static` | The source's client secret | Refused | The source's own |

| Key | Required | Default | Meaning |
|-----|----------|---------|---------|
| `mint_method` | Yes | — | `on_behalf_of`. |
| `subject_token_source` | Yes | — | Must be `user_identity`: the user's token, admitted on the provider's `user_auth_path`. |
| `actor_token_source` | For keyless | — | `warden_identity`. Its assertion uses the `minimal` profile by default, and its `sub` is the agent's composite subject, which the federated credential must name. |
| `client_id` | No | source `client_id` | The app the user's token was issued for (UUID). |
| `tenant_id` | Yes | — | The app's tenant (UUID). |
| `resource_uri` | No | `https://graph.microsoft.com/` | Resource the delegated token targets; the grant asks for its `.default` scope. |

A spec write refuses `client_secret`, `secret_id`, `assertion_user_claims`,
`subject_token_type` and `actor_token_type`. A source update is checked against the
on-behalf-of specs bound to it, so switching a source between keyless and static cannot
strand them. A request that carries no user is answered `401`.

Entra's response also carries a refresh token, and sometimes an ID token. Warden decodes
only the access token and its lifetime, so neither reaches the credential, its metadata,
a log or the audit trail. The credential's metadata names the user (`subject`: the token's
`oid`, else `sub`) and, keyless, the agent (`actor`: the assertion's `sub`).

Entra's refusals are sorted by their `AADSTS` codes. Entra's free-text description is never
read:

| Entra code | Warden answers |
|---|---|
| `50079`, `50076`, or a claims challenge | `401` with an `insufficient_claims` challenge carrying the claims, which MSAL reads to re-acquire the user's token |
| `interaction_required` without claims | `401` `invalid_token`, `error_description="interaction_required"`: the user must sign in interactively |
| `50013`, `500133` on the user's token | `401` `invalid_token`: the user's token is expired, or for the wrong audience |
| `65001` | `403`: admin consent is missing for the app and scope |
| `70021`, `700211`–`700213` | `403`: the federated credential was refused; check its issuer, subject and audience |
| `7000215`, `7000222` | `403`: the client secret was refused, wrong or expired |
| `700027` | `403`: the certificate was refused, named by its `x5t#S256` |

`500133` filed under `invalid_client` is the client assertion's validity window, not the
user's token, so Warden does not ask the user to sign in again; over a certificate source,
its error says to check Warden's clock. A throttled token endpoint (`429`) answers `503`.

A `subject_token_source=warden_identity` spec also accepts the assertion-shaping keys
(`assertion_profile` — `minimal` by default on a new spec — `assertion_audience`,
`assertion_metadata_claims`, `assertion_user_claims`, `assertion_algorithm`,
`assertion_ttl`) — see [Assertion claims](/federation/assertion-claims/). Under `minimal`,
`assertion_resource` is refused.

## See Also

- [Credentials](/concepts/credentials/) — the source, spec, and credential model.
- [Azure provider](/provider-backends/azure/) — full operator setup guide.
- [Microsoft Graph provider](/provider-backends/msgraph/) — Graph as the user, through
  on-behalf-of, or as the app.
- [Credential drivers](/credential-drivers/) — every driver.
