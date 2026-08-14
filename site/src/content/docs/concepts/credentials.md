---
title: "Credentials"
description: "How Warden brokers a scoped, short-lived credential for an upstream — the source/spec/credential model, keyless federation, chaining, and rotation."
---

Warden's purpose is to keep secrets out of workloads. Instead of handing an agent a
static API key, Warden **brokers access**: at request time it obtains a scoped, usually
short-lived credential for the upstream the caller is reaching, then injects it into the
request rather than handing it over. The workload presents only its
[identity](/concepts/authentication/); it never holds a credential of its own.

How Warden obtains that credential is a spectrum, best to worst by *what Warden stores*:

- **Keyless** — Warden stores nothing. It federates a short-lived
  [identity assertion](/federation/oidc-issuer/) for a credential the upstream issues, or
  [chains](/federation/credential-chaining/) the needed secret from a keyless-federated
  vault per request. **Recommended**, and coming to every driver.
- **Inline secret** — Warden holds a stored secret and either mints a short-lived
  credential with it (*dynamic*) or injects it directly (*static*). A stored secret is
  attack surface, so this is a fallback.

Whether the upstream sees a service identity or the *caller's* identity (on-behalf-of) is
a separate, orthogonal choice — see [Delegation](/concepts/delegation/). The full picture
of both axes lives in the [credential-driver reference](/credential-drivers/).

## The Model: Source, Spec, Credential

Three objects, in a chain, describe how a credential is produced:

```
role.cred_spec_name ─▶ credential spec ─▶ credential source ─▶ driver ─▶ upstream
                            (what)             (where)        (how)
```

- A **credential source** is the *upstream account* Warden reaches — an AWS account, a
  Vault cluster, a GitHub org, an OAuth2 provider — and **how Warden authenticates to it**:
  a stored privileged secret, a keyless federation trust (`auth_method=oidc_federation`,
  no stored secret), or a secret it **chains** from another spec (`secret_spec`, so it
  stores nothing either). It names the **driver** type that knows how to talk to the
  upstream.

- A **credential spec** is a *recipe* that says what to mint from a source. It references
  a source by name and adds type-specific parameters — which IAM role to assume, which
  Vault token role to use, which GitHub installation. One source can back many specs.

- A **credential** is the *result*: the minted, typed secret Warden injects into the
  workload's upstream request — an STS session, a Vault token, an installation token —
  with a lease and a TTL when the upstream supports it.

A [role](/concepts/roles/) ties this to identity. Its `cred_spec_name` field names the
spec a caller of that role will draw from — but naming the spec is all authentication
does. Issuance is lazy: the credential is minted only when the workload actually makes a
request to the upstream through a [provider](/concepts/providers/), at which point Warden
resolves the role's spec and mints (or reuses) the credential. Because
[roles are per-request](/concepts/roles/#roles-are-per-request), the same workload can
draw from different specs — different upstream access — by naming a different role on each
request.

### Sources

A source is created with a name, a `type` (the driver), and a `config` map holding the
upstream connection and how Warden authenticates. There are three ways to authenticate,
and the first two store no secret:

**Keyless federation** — set `auth_method=oidc_federation` and the federation trust
details; the config holds no secret:

```bash
warden cred source create aws-prod \
  -type=aws \
  -config=auth_method=oidc_federation \
  -config=region=us-east-1
```

**Chained** — the source **chains** the secret it needs from another spec with
`secret_spec` (for example, a token-exchange client secret), so it stores nothing at rest
either. See [credential chaining](/federation/credential-chaining/).

**Inline secret** — the config carries the privileged secret and a `rotation_period` to
keep it fresh (`0` disables rotation):

```bash
warden cred source create aws-legacy \
  -type=aws \
  -config=access_key_id=AKIA... \
  -config=secret_access_key=... \
  -config=region=us-east-1 \
  -rotation-period=24h
```

Sources live at `sys/cred/sources/<name>`, scoped to the current
[namespace](/concepts/namespaces/). `-rotation-period` is **required** where Warden rotates
a stored secret in place — an AppRole-backed OpenBao/Vault source, and specs whose credential
type embeds a rotatable secret — and is **not needed for a keyless or chained source** (no
stored secret to rotate), nor for a per-request exchange spec (where it is rejected). Config
fields that hold secrets are masked on read.

### Specs

A spec references a source and describes what to mint, plus TTL constraints and its own
optional `rotation_period`:

```bash
warden cred spec create aws-app \
  -source=aws-prod \
  -config=mint_method=sts_assume_role \
  -config=subject_token_source=warden_identity \
  -config=role_arn=arn:aws:iam::123456789012:role/app \
  -min-ttl=15m -max-ttl=1h
```

Specs live at `sys/cred/specs/<name>`. Only `-source` is required; the credential type is
inferred from the source and config (multi-type sources like Vault use a config key such
as `mint_method` to disambiguate). `-min-ttl` and `-max-ttl` default to `1h` and `24h`,
and `-rotation-period` is optional. A spec can also **chain** a secret it needs from
another spec with `secret_spec` — see [credential chaining](/federation/credential-chaining/).

### The minted credential

Every minted credential carries, alongside its secret `Data`, the bookkeeping Warden needs
to manage and audit it:

| Field | Meaning |
|-------|---------|
| `Data` | The secret fields themselves (e.g. `access_key_id`, `secret_access_key`, `session_token`; or `token`). HMAC-salted in audit logs. |
| `Type` / `Category` | The credential type and a routing category. |
| `LeaseTTL` / `LeaseID` | Lease lifetime, and the upstream revocation handle. `LeaseTTL` is `0` for static credentials; `LeaseID` is empty when there is nothing to revoke — which includes dynamic-but-not-revocable credentials. |
| `TokenID` | The [token](/concepts/tokens/) — session or transparent — the credential is bound to and expires with. |
| `SourceName` / `SourceType` / `SpecName` | Provenance, for revocation and audit. |
| `Revocable` | Whether the credential can be revoked upstream. |
| `Metadata` | Non-secret attributes (e.g. `subject`), logged in clear. |

## Lifetime and Revocation

Two *independent* properties describe how a credential ends: whether it **expires**, and
whether it can be **revoked** early.

**Dynamic vs. static — expiry.**

- A **dynamic** credential is minted on demand and carries a lease (`LeaseTTL > 0`); it
  ages out on its own. STS sessions, Vault tokens, OAuth2 access tokens, and database IAM
  auth tokens are dynamic.
- A **static** credential has no lease (`LeaseTTL = 0`) and stays valid until changed
  upstream. A pre-shared API key or a stored Personal Access Token is static;
  [rotation](#rotation), where the upstream supports it, is how static secrets are kept
  fresh.

**Revocable vs. not — early termination.** Independently of expiry, a credential is
**revocable** only if the upstream offers a way to invalidate it before it expires. Warden
records this as `Revocable`:

- **Revocable** — Warden can destroy the credential upstream ahead of its TTL, and does so
  when the bound token ends. Vault and GitLab tokens are revocable.
- **Not revocable** — Warden holds no revocation handle for the credential, so it can only
  run out its TTL. GCP, Azure, and Kubernetes access tokens, database IAM tokens, and
  **GitHub App installation tokens** are **dynamic but not revocable** — short-lived by
  design, yet Warden cannot end them early (GitHub's ~1h tokens are simply left to expire).

So a dynamic credential **need not be revocable**: a short TTL and active revocation are
separate guarantees. The two axes combine into three real combinations:

| Kind | Expires | `Revocable` | Ends by | Examples |
|------|---------|-------------|---------|----------|
| Dynamic, revocable | yes | `true` | expiry **or** early revocation | Vault, GitLab tokens |
| Dynamic, not revocable | yes | `false` | expiry only | GCP, Azure, Kubernetes, GitHub App tokens |
| Static | no | `false` | rotation or manual change upstream | API keys, stored PATs |

(There is no static-and-revocable kind: with no lease there is nothing to revoke.) When
revocation isn't available, the short lease *is* the containment mechanism.

## How a credential is obtained

The **driver** (selected by the source `type`) does the obtaining. Every driver is placed
on two orthogonal axes, and a driver supports more than one point on each — the
[credential-driver reference](/credential-drivers/) is the authoritative map, with a
capability matrix and per-driver pages.

- **Storage — what Warden holds.** *Keyless* (federate an assertion, or chain the secret)
  vs. *inline secret* (dynamic or static). Keyless is recommended; inline is a fallback.
  [Chaining](/federation/credential-chaining/) is the transition that moves a driver from
  inline to keyless by sourcing its secret from a keyless-federated vault per request.
- **Identity — whose identity the upstream sees.** A shared service identity, the
  [agent (± user) via a federation assertion](/federation/keyless-credentials/), or the
  [user on-behalf-of via delegation](/concepts/delegation/).

Warden ships drivers for:

| Driver `type` | Upstream |
|---------------|----------|
| `hvault` | HashiCorp Vault / OpenBao |
| `aws` | AWS IAM / STS |
| `azure` | Azure AD / Microsoft Graph |
| `gcp` | Google Cloud IAM |
| `github` | GitHub (PATs, App installation tokens) |
| `gitlab` | GitLab |
| `oauth2` | Generic OAuth2 providers |
| `token_exchange` | RFC 8693 / RFC 7523 exchange at any OAuth2 STS |
| `kubernetes` | Kubernetes API |
| `local` | Static secrets stored in the spec itself |
| `apikey` | Generic static API keys |
| `ibm`, `elastic`, `grafana`, `honeycomb`, `alicloud`, `scaleway`, `ovh` | The respective SaaS / cloud APIs |

Each driver has a reference page under [Credential drivers](/credential-drivers/) covering
its config keys, mint methods, credential types, and rotation behaviour.

## Rotation

Rotation applies to **inline-secret** sources and specs — a keyless or chained source holds
nothing to rotate. Where a `rotation_period` is set, Warden rotates on a schedule using a
**two-stage, asynchronous** model that tolerates upstreams which take time to propagate a
new credential. It never rotates in the request path.

The two stages are **prepare** and **activate**:

1. **Prepare** — mint a *new* credential while the old one stays valid. The driver returns
   the new config, the data needed to later destroy the old credential, and an
   `activateAfter` delay.
2. **Activate** — after the delay, persist the new config, switch the driver over to it,
   and destroy the old credential (best-effort, with retries).

The delay is what makes this robust across upstreams with different consistency models:

- **Fast path** (`activateAfter = 0`) — upstreams with immediate consistency, like Vault,
  prepare and activate in a single step.
- **Slow path** (`activateAfter > 0`) — eventually-consistent upstreams, like AWS and
  Azure, stage the new credential and wait (about five minutes by default) before
  activating, so the new secret has propagated before the old one is destroyed.

If a stage fails it is retried with exponential backoff and jitter; a cleanup that keeps
failing is persisted and retried daily for up to a week before being abandoned with an
error. Source rotation rotates the privileged secret Warden authenticates *with*; spec
rotation rotates a secret a source manages *on behalf of* a workload.

## Delivering a Credential

Credentials are delivered by **injection**. The workload sends its request to a Warden
[provider](/concepts/providers/) mount as if Warden were the upstream. Warden obtains the
credential and injects it into the proxied request — signing it with AWS SigV4, setting
the upstream token header, and so on — then streams the upstream response back.

The workload never receives the credential. It only ever lives inside the proxied hop, and
any privileged secret that mints it never leaves Warden. That is the whole point: a
compromised workload has no upstream secret to leak, because it never held one.

## OAuth2 Consent

OAuth2 specs that use the authorization-code flow need a one-time interactive consent to
obtain a refresh token. Warden drives this without holding server-side session state:

```bash
warden cred spec connect <name>
```

The command opens the provider's authorize URL, captures the authorization code on a
loopback redirect, and hands it back to Warden, which exchanges it for tokens and seals
them into the spec. State and PKCE values are supplied by the client across the two calls,
so nothing needs to be retained between them.

## Managing Credentials from the CLI

Sources and specs share a consistent command surface:

```bash
# Sources
warden cred source create <name> -type=<driver> -config=k=v ... [-rotation-period=<dur>]
warden cred source read   <name>
warden cred source list
warden cred source update <name> -config=k=v ...
warden cred source delete <name>

# Specs
warden cred spec create <name> -source=<source> -config=k=v ...
warden cred spec read   <name>
warden cred spec list
warden cred spec update <name> -config=k=v ...
warden cred spec delete <name>
warden cred spec connect <name>   # OAuth2 authorization-code consent
```

Both commands also accept a full payload via `-json` (`-json @file.json`, `-json '<json>'`,
or `-json -` for stdin) as an agent-friendly alternative to the typed flags.

Both sources and specs are namespace-scoped: each [namespace](/concepts/namespaces/) has
its own credential configuration, with no inheritance across boundaries.

## See Also

- [Credential drivers](/credential-drivers/) — the two-axis map and a reference page per driver.
- [Keyless credential sources](/federation/keyless-credentials/) — the recommended `oidc_federation` mode.
- [Credential chaining](/federation/credential-chaining/) — sourcing a secret keylessly per request.
- [Delegation](/concepts/delegation/) — acting on behalf of a user.
- [Roles](/concepts/roles/) — how `cred_spec_name` binds a spec to an identity.
- [Providers](/concepts/providers/) — the mounts that inject or return credentials.
- [Tokens](/concepts/tokens/) — the token a credential is bound to and expires with.
