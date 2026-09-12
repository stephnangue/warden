---
title: "Credential chaining"
description: "Source a provider's secret from another cred spec per request — keyless secret-backed providers, nothing stored at rest."
---

Some upstreams still require a **long-lived secret** — an API key, a client secret, a
token — with no short-lived-token option. Normally that means *something* has to keep that
secret on hand. **Credential chaining** lets that something stay the **external vault you
already trust to hold secrets**, instead of Warden.

Rather than copying the secret into Warden, you point Warden at **where the secret already
lives**. On each request Warden **fetches the secret just in time, uses it to serve that one
request, and immediately forgets it** — nothing is ever written to Warden's own storage.

**What makes this especially powerful: Warden holds no secret to reach the vault, either.**
It authenticates to the vault with a **per-request proof of identity** — a short-lived,
signed [identity assertion](/federation/oidc-issuer/) — not a stored vault token or password.
So there is no "secret to get the secret," no bootstrap credential to steal. And because that
proof carries the **real caller's identity**, the vault sees *who* read the secret — the
actual agent, and the user when one is present — so the read is **attributable on the vault
side**, not an anonymous pull by a shared service account.

**Why it matters.** Warden becomes a **pass-through, not a vault**. Breach it and there is no
upstream secret sitting inside to take — and no vault credential either; the secret stays in
the system built to protect it, and every fetch is a per-request, authorized event, audited on
**both** sides. This is what turns an otherwise secret-storing driver into a **keyless** one —
the second on-ramp to [keyless federation](/federation/keyless-credentials/): where a cloud
source federates for a credential the cloud issues, a secret-backed source **chains** its
secret from a keyless-federated vault.

**In Warden's terms.** The spec that needs the secret points at another spec that produces
it, using the `secret_spec` setting. At request time Warden runs that referenced spec **as
the same caller**, takes the secret it yields, hands it to the driver that needed it, and
keeps nothing. (The rest of this page uses "consuming spec" for the one that needs the
secret and "referenced spec" for the one that supplies it.)

**Without chaining.** Warden holds the provider's secret in its own barrier — a stored secret to protect and rotate.

<p align="center"><img alt="Without chaining, Warden stores the provider secret in its own barrier" src="/images/warden-cred-chaining-without-cred-chaining.png" width="760"></p>

**With chaining.** The consuming driver fetches the secret from the referenced spec at mint time and injects it — nothing is stored at rest.

<p align="center"><img alt="With credential chaining, the consuming driver fetches its secret from the referenced spec at mint time and injects it, storing nothing at rest" src="/images/warden-cred-chaining-with-cred-chaining.png" width="760"></p>

## Keyless end-to-end

The referenced spec is typically itself keyless/federated. When it is a
[keyless OpenBao/Vault source](/federation/keyless-credentials/), the fetch works like
this:

1. Warden mints the referenced spec **as the same caller**.
2. To read the vault, it authenticates with a **per-request, agent-derived
   [identity assertion](/federation/oidc-issuer/)** (`warden_identity` via OIDC
   federation) — a very short-lived token, **no standing vault secret**. The assertion is
   itself signed by a key that can live in an [external KMS](/configuration/signer/), so
   Warden need not even hold the signing key.
3. It reads the material (for example a `kv2_read`) and returns the field.

So nothing is stored anywhere in the chain: not the upstream secret, not a vault
credential, not the signing key. The only secret material that ever exists is a
per-request assertion.

## What can be chained

### Consumers

Ten drivers can source their standing secret this way, so a secret-backed provider
becomes keyless at Warden: **`elastic`**, **`github`**, **`gitlab`**, **`grafana`**,
**`ibm`**, **`oauth2`**, **`ovh`**, **`scaleway`**, **`apikey`**, and
**`token_exchange`**.

Two are worth calling out because what they chain is not a generic "the secret":

- **`token_exchange`** chains the **client credential** — its `client_secret`, or the
  `private_key` for `private_key_jwt` — instead of storing it inline, which makes the
  exchange itself keyless. See
  [Token Exchange](/credential-drivers/token-exchange/#sourcing-the-client-secret-keylessly).
- **`oauth2`** chains the **whole client credential**, both `client_id` and
  `client_secret`, on the *source*. `client_credentials` grant only; chaining a refresh
  token is not supported.

### Producers

The referenced spec produces the material. Four mint methods can sit at that end:

| Producer | Mint method | What it yields |
|---|---|---|
| OpenBao / Vault KV v2 | `kv2_read` | The secret, with the **`key_value`** credential type — the payload is preserved verbatim (no forced primary field), so it rides under its natural key names. |
| AWS Secrets Manager | `secret_read` | The stored secret's payload, verbatim. |
| GCP Secret Manager | `secret_read` | The stored secret's payload. Federation-first, with optional `target_service_account` impersonation. |
| OpenBao / Vault transit | `transit_signer` | **Not a secret at all** — a scoped signing *capability*. |

`transit_signer` is the one that changes the shape of the guarantee. Instead of moving
key material, it mints a short-lived token that may do nothing but sign with one named
transit key, plus the coordinates naming that key. The consumer chains it and asks the
KMS to sign, so the private key is read by nobody — including Warden. Its consumer is
`token_exchange` with `client_auth=kms_private_key_jwt`, which signs its RFC 7523 client
assertion remotely; the method is exchange-path-only and requires a spec-level
`jwt_role`.

A producer can itself be keyless — an AWS or GCP `secret_read` on an `oidc_federation`
source, or a Vault source using per-request JWT login — which is what makes a chain
keyless end to end, with nothing standing stored at either hop.

## Configuration

Set these on the **consuming** source/spec:

| Key | Description |
|---|---|
| `secret_spec` | The cred spec to mint and read the secret from. |
| `secret_field` | Which field of the referenced spec's credential holds the secret, when its payload has multiple keys. |
| `secret_cache_ttl` | Opt-in: cache the fetched material for a bounded TTL to avoid re-fetching every request. The cache entry is **per caller** (keyed on the namespace, referenced spec, and the agent identity — plus the user when present), not a single shared entry. Off unless set. |

:::caution[The inline secret must be omitted]
Setting `secret_spec` **and** the driver's own inline secret is rejected at write — for
example `api_key` on an `elastic` source, `admin_token` on `grafana`,
`management_access_key` on `scaleway`, or `client_id`/`client_secret` on `oauth2`. The
referenced spec supplies the material, and rotation belongs to whoever owns it; keeping a
stale copy on the consuming source would defeat the point. Each driver names its own key
in the error.
:::

## Guarantees

- **Nothing stored at rest** — a chained spec keeps no secret in Warden's barrier; the
  material transits memory at mint time and every read is a per-request, authorized,
  **audited** event attributed to the real caller.
- **Single hop** — chaining is bounded to one level (`MaxSecretChainDepth = 1`), so a
  chain cannot fan out.
- **In-use protection** — a referenced spec cannot be deleted while another spec chains
  it (`ErrSpecInUse`).

Together these defeat the "key-trove" class, where a compromised broker leaks a pile of
standing secrets: there is no pile to leak.

## Per-user chaining

Chaining composes with the [user principal](/concepts/delegation/): a `kv2_read`
`secret_path` (and the `oauth2` mint method's `credential_name`) may template
`{{user.<claim>}}`, so the secret fetched is scoped to the verified user. That per-user
model — including using OpenBao/Vault templated policies to act on behalf of a user at
scale — is documented on the [Delegation](/concepts/delegation/) page.

**Per-user, keyless.** A short-lived assertion carrying the user reads a privileged secret from the vault, which Warden uses to mint an access token scoped to that user and injects into the upstream — no standing secret anywhere in the chain.

<p align="center"><img alt="A per-user keyless flow: the driver presents a short-lived identity assertion carrying the user and agent, reads the user's secret from the vault, and injects it" src="/images/warden-cred-keyless-chaining-per-user-service.png" width="760"></p>

## See also

- [Keyless credential sources](/federation/keyless-credentials/) — the federation on-ramp chaining pairs with.
- [Token Exchange](/credential-drivers/token-exchange/) — chaining the exchange client secret.
- [Delegation](/concepts/delegation/) — per-user chaining and acting on behalf of a human.
