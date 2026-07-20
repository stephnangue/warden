---
title: "Credentials"
---

Warden's purpose is to keep secrets out of workloads. Instead of
handing an agent a static API key, Warden **brokers access**: it holds the
privileged secret itself and, at request time, mints or retrieves a scoped,
often short-lived credential for the upstream the caller is trying to reach — then
injects it into the request rather than handing it over. The workload presents only
its [identity](/concepts/authentication/); it never holds a credential of its own.

This document describes the credential model end to end — the three configuration
objects that define where credentials come from, the drivers that talk to
upstreams, how a credential is delivered, and how secrets are rotated.

## The Model: Source, Spec, Credential

Three objects, in a chain, describe how a credential is produced:

```
role.cred_spec_name ─▶ credential spec ─▶ credential source ─▶ driver ─▶ upstream
                            (what)             (where)        (how)
```

- A **credential source** is the *upstream account* Warden authenticates to —
  an AWS account, a Vault cluster, a GitHub org, an OAuth2 provider. It holds
  the privileged, long-lived secret (an access key, an AppRole, a client
  secret) and names the **driver** type that knows how to talk to it.

- A **credential spec** is a *recipe* that says what to mint from a source. It
  references a source by name and adds type-specific parameters — which IAM role
  to assume, which Vault token role to use, which GitHub installation. One source
  can back many specs.

- A **credential** is the *result*: the minted, typed secret Warden injects into
  the workload's upstream request — an STS session, a Vault token, an
  installation token — with a lease and a TTL when the upstream supports it.

A [role](/concepts/roles/) ties this to identity. Its `cred_spec_name` field names the
spec a caller of that role will draw from — but naming the spec is all
authentication does. Issuance is lazy: the credential is minted only when the
workload actually makes a request to the upstream through a [provider](/concepts/providers/),
at which point Warden resolves the role's spec and mints (or reuses) the
credential for it. Because [roles are per-request](/concepts/roles/#roles-are-per-request),
the same workload can draw from different specs — different upstream access — by
naming a different role on each request.

### Sources

A source is created with a name, a `type` (the driver), a `config` map holding
the upstream connection and the credentials the driver uses — a privileged secret,
or the client credentials for an identity exchange — and a required `rotation_period`
(pass `0` to disable rotation):

```bash
warden cred source create aws-prod \
  -type=aws \
  -config=access_key_id=AKIA... \
  -config=secret_access_key=... \
  -config=region=us-east-1 \
  -rotation-period=24h
```

Sources live at `sys/cred/sources/<name>`, scoped to the current
[namespace](/concepts/namespaces/). `-type` and `-rotation-period` are required (use
`-rotation-period=0` for no rotation); each `-config` flag adds one `key=value`
entry. Config fields that hold secrets are masked on read.

### Specs

A spec references a source and describes what to mint, plus TTL constraints and
its own optional `rotation_period`:

```bash
warden cred spec create aws-app \
  -source=aws-prod \
  -type=aws_access_keys \
  -config=mint_method=sts_assume_role \
  -config=role_arn=arn:aws:iam::123456789012:role/app \
  -min-ttl=15m -max-ttl=1h
```

Specs live at `sys/cred/specs/<name>`. Only `-source` is required; `-type` can
often be inferred from the source and config (multi-type sources like Vault use a
config key such as `mint_method` to disambiguate). `-min-ttl` and `-max-ttl`
default to `1h` and `24h`, and `-rotation-period` is optional (empty means no
rotation).

### The minted credential

Every minted credential carries, alongside its secret `Data`, the bookkeeping
Warden needs to manage and audit it:

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

Two *independent* properties describe how a credential ends: whether it
**expires**, and whether it can be **revoked** early.

**Dynamic vs. static — expiry.**

- A **dynamic** credential is minted on demand and carries a lease
  (`LeaseTTL > 0`); it ages out on its own. STS sessions, Vault tokens, OAuth2
  access tokens, and database IAM auth tokens are dynamic.
- A **static** credential has no lease (`LeaseTTL = 0`) and stays valid until
  changed upstream. A pre-shared API key or a stored Personal Access Token is
  static; [rotation](#rotation), where the upstream supports it, is how static
  secrets are kept fresh.

**Revocable vs. not — early termination.** Independently of expiry, a credential
is **revocable** only if the upstream offers a way to invalidate it before it
expires. Warden records this as `Revocable`:

- **Revocable** — Warden can destroy the credential upstream ahead of its TTL,
  and does so when the bound token ends. Vault, GitHub, and GitLab tokens are
  revocable.
- **Not revocable** — the upstream gives no way to cancel an issued credential,
  so it can only run out its TTL. GCP, Azure, and Kubernetes access tokens and
  database IAM tokens are **dynamic but not revocable** — short-lived by design,
  yet Warden cannot end them early.

So a dynamic credential **need not be revocable**: a short TTL and active
revocation are separate guarantees. The two axes combine into three real
combinations:

| Kind | Expires | `Revocable` | Ends by | Examples |
|------|---------|-------------|---------|----------|
| Dynamic, revocable | yes | `true` | expiry **or** early revocation | Vault, GitHub, GitLab tokens |
| Dynamic, not revocable | yes | `false` | expiry only | GCP, Azure, Kubernetes access tokens |
| Static | no | `false` | rotation or manual change upstream | API keys, stored PATs |

(There is no static-and-revocable kind: with no lease there is nothing to
revoke.) When revocation isn't available, the short lease *is* the containment
mechanism.

Minimizing exposure is the point of the system. The workload never receives the
upstream credential at all: Warden mints it and injects it into the proxied
request itself (see [Delivering a Credential](#delivering-a-credential)). A short
lease shrinks the window further still — revocable or not — and the privileged
secret that mints it never leaves Warden.

## Drivers

A **driver** is the pluggable component that talks to a specific upstream. The
source's `type` selects the driver. Warden ships drivers for:

| Driver `type` | Upstream |
|---------------|----------|
| `hvault` | HashiCorp Vault / OpenBao |
| `aws` | AWS IAM / STS |
| `azure` | Azure AD / Microsoft Graph |
| `gcp` | Google Cloud IAM |
| `github` | GitHub (PATs, App installation tokens) |
| `gitlab` | GitLab |
| `oauth2` | Generic OAuth2 providers |
| `kubernetes` | Kubernetes API |
| `local` | Static secrets stored in the spec itself |
| `apikey` | Generic static API keys |
| `ibm`, `elastic`, `grafana`, `honeycomb`, `alicloud`, `scaleway`, `ovh` | The respective SaaS / cloud APIs |

Each driver has a reference page under [Credential drivers](/credential-drivers/)
covering its config keys, mint methods, credential types, and rotation behaviour.

Every driver implements a small core contract — mint a credential from a spec,
revoke a lease, and clean up — and may opt into additional capabilities:

- **Spec verification** — validate a spec's credentials with a lightweight
  upstream call at *create/update* time (not on the hot path), so a wrong PAT or
  bad app ID fails early rather than at the gateway.
- **Source rotation** — rotate the source's *own* privileged secret (e.g. a
  Vault AppRole secret ID, an AWS IAM key).
- **Spec rotation** — use the source's elevated permissions to rotate a
  credential embedded in a spec (e.g. an Azure source rotating a workload service
  principal's client secret via Graph).
- **OAuth2 authorization-code consent** — drive an interactive consent flow (see
  [OAuth2 consent](#oauth2-consent)).

## Rotation

Sources and specs can both carry a `rotation_period`. Warden rotates them on a
schedule using a **two-stage, asynchronous** model that tolerates upstreams
which take time to propagate a new credential. It never rotates in the request
path.

The two stages are **prepare** and **activate**:

1. **Prepare** — mint a *new* credential while the old one stays valid. The
   driver returns the new config, the data needed to later destroy the old
   credential, and an `activateAfter` delay.
2. **Activate** — after the delay, persist the new config, switch the driver
   over to it, and destroy the old credential (best-effort, with retries).

The delay is what makes this robust across upstreams with different consistency
models:

- **Fast path** (`activateAfter = 0`) — upstreams with immediate consistency,
  like Vault, prepare and activate in a single step.
- **Slow path** (`activateAfter > 0`) — eventually-consistent upstreams, like
  AWS and Azure, stage the new credential and wait (about five minutes by
  default) before activating, so the new secret has propagated before the old
  one is destroyed.

If a stage fails it is retried with exponential backoff and jitter; a cleanup
that keeps failing is persisted and retried daily for up to a week before being
abandoned with an error. Source rotation rotates the privileged secret Warden
authenticates *with*; spec rotation rotates a secret a source manages *on behalf
of* a workload.

## Delivering a Credential

Credentials are delivered by **injection**. The workload sends its request to a
Warden [provider](/concepts/providers/) mount as if Warden were the upstream. Warden
mints the credential and injects it into the proxied request — signing it with
AWS SigV4, setting the upstream token header, and so on — then streams the
upstream response back.

The workload never receives the credential. It only ever lives inside the
proxied hop, and the privileged secret that mints it never leaves Warden at all.
That is the whole point: a compromised workload has no upstream secret to leak,
because it never held one.

## OAuth2 Consent

OAuth2 specs that use the authorization-code flow need a one-time interactive
consent to obtain a refresh token. Warden drives this without holding
server-side session state:

```bash
warden cred spec connect <name>
```

The command opens the provider's authorize URL, captures the authorization code
on a loopback redirect, and hands it back to Warden, which exchanges it for
tokens (using the client secret it holds) and seals them into the spec. State and
PKCE values are supplied by the client across the two calls, so nothing needs to
be retained between them.

## Managing Credentials from the CLI

Sources and specs share a consistent command surface:

```bash
# Sources
warden cred source create <name> -type=<driver> -config=k=v ... -rotation-period=<dur>
warden cred source read   <name>
warden cred source list
warden cred source update <name> -config=k=v ...
warden cred source delete <name>

# Specs
warden cred spec create <name> -source=<source> [-type=<type>] -config=k=v ...
warden cred spec read   <name>
warden cred spec list
warden cred spec update <name> -config=k=v ...
warden cred spec delete <name>
warden cred spec connect <name>   # OAuth2 authorization-code consent
```

Both commands also accept a full payload via `-json` (`-json @file.json`,
`-json '<json>'`, or `-json -` for stdin) as an agent-friendly alternative to the
typed flags.

Both sources and specs are namespace-scoped: each [namespace](/concepts/namespaces/) has
its own credential configuration, with no inheritance across boundaries.

## See Also

- [Credential drivers](/credential-drivers/) — a reference page per driver.
- [Roles](/concepts/roles/) — how `cred_spec_name` binds a spec to an identity.
- [Providers](/concepts/providers/) — the mounts that inject or return credentials.
- [Tokens](/concepts/tokens/) — the token a credential is bound to and expires with.
- [Namespaces](/concepts/namespaces/) — the isolation boundary for sources and specs.
