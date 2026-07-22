---
title: "Credential Drivers"
---

A **driver** is the component responsible for minting the credential that Warden
injects into the outbound request. A [credential source](/concepts/credentials/)
names a driver through its `type`; when a workload's request reaches a
[provider](/concepts/providers/) mount, the driver produces the scoped credential
for that upstream and Warden injects it into the proxied call. The workload
presents only its [identity](/concepts/authentication/) — it never holds the
credential itself.

See [Credentials](/concepts/credentials/) for the source / spec / credential model
these pages build on.

## Driver families

Drivers fall into two families by *how* they obtain the credential.

### Service account

The driver authenticates to the upstream as Warden's own service identity, using a
secret held on the source. The caller's identity selects which credential to mint
but is never forwarded upstream.

**Static** — the driver holds a long-lived secret and injects it into the outbound
request unchanged.

<p align="center"><img alt="An agent presents its identity to Warden; the driver injects a static key into the request to the LLM API" src="/images/warden-cred-service-account-static.png" width="760"></p>

**Dynamic** — the driver holds a secret it uses to mint a short-lived credential
from the upstream's security token service, then injects that. The held secret can
itself be [rotated](/concepts/credentials/#rotation) on a schedule.

<p align="center"><img alt="The driver uses a dynamic key to call AWS STS, receives a short-lived token, and injects it into the request to the AWS API" src="/images/warden-cred-service-account-dynamic.png" width="760"></p>

### Token exchange

The driver forwards the **caller's own identity** and exchanges it, at an identity
provider or security token service, for a downstream credential scoped to that
caller. The source holds only the client credentials that authenticate the
exchange — not a privileged upstream secret.

**RFC 7523 — JWT bearer.** The driver exchanges the caller's ID token for an access
token at the identity provider.

<p align="center"><img alt="The driver sends the caller's ID token to the identity provider, receives an access token, and injects it into the request to the MCP server" src="/images/warden-cred-token-exchange-rfc7523.png" width="760"></p>

**RFC 8693 — token exchange (on-behalf-of).** The driver presents the user's
subject token together with the agent's actor token; the returned access token
preserves the on-behalf-of chain.

<p align="center"><img alt="The driver presents the user's subject token and the agent's actor token to the identity provider and receives an access token for the MCP server" src="/images/warden-cred-token-exchange-rfc8693.png" width="760"></p>

**ID-JAG — identity assertion authorization grant.** The identity provider issues
an ID-JAG from the user and agent identities; the driver presents it to the
resource's authorization server for the final access token.

<p align="center"><img alt="The identity provider issues an ID-JAG from the user and agent identities; the driver exchanges it at the authorization server for an access token to reach the MCP server" src="/images/warden-cred-token-exchange-id-jag.png" width="820"></p>

## Choosing a family

Start from what the *upstream* accepts, and whether downstream authorization must
reflect the caller's own identity.

| Use | When |
|-----|------|
| **Service account — static** | The upstream only accepts a long-lived pre-shared secret — an API key or PAT — with no short-lived-token mechanism. Simplest to set up; keep the secret fresh with [rotation](/concepts/credentials/#rotation). |
| **Service account — dynamic** | The upstream exposes a security token service (AWS STS, GCP IAM, Vault, the Kubernetes TokenRequest API). Prefer this over static whenever it is available: every request gets a short-lived credential that expires on its own, shrinking the blast radius of a leak. |
| **Token exchange** | Downstream authorization must reflect the *caller's* identity — per-user scoping, on-behalf-of, or audit at the resource itself — and the upstream speaks OAuth2 / OIDC. |

The dividing line is whose identity the upstream sees. With a **service account**,
every caller of a spec shares Warden's own upstream identity and permissions — the
caller's identity only selects *which* spec to use. With **token exchange**, the
upstream sees the actual caller.

Within token exchange, pick the flow the upstream supports:

- **RFC 7523** — you hold the caller's ID token and the identity provider will
  exchange it directly for an access token (a single identity, no delegation chain).
- **RFC 8693** — you must preserve an on-behalf-of chain: a user subject acting
  through an agent actor.
- **ID-JAG** — the resource's authorization server is distinct from the identity
  provider, and the grant must cross that boundary (cross-app / enterprise
  delegation).

## Reference

Every driver has its own page covering config keys, mint methods, credential
types, and rotation behaviour.

### Generic

| Driver | `type` | Upstream |
|--------|--------|----------|
| [Local](/credential-drivers/local/) | `local` | static secrets stored directly in the spec |
| [Static API Key](/credential-drivers/apikey/) | `apikey` | a static API key, held in the spec, for any HTTP API |

### Platform

| Driver | `type` | Upstream |
|--------|--------|----------|
| [HashiCorp Vault](/credential-drivers/vault/) | `hvault` | Vault / OpenBao — KV, AWS/GCP/IBM engines, tokens, OAuth2 |
| [Kubernetes](/credential-drivers/kubernetes/) | `kubernetes` | ServiceAccount tokens via the TokenRequest API |
| [OAuth2](/credential-drivers/oauth2/) | `oauth2` | generic OAuth2 providers |
| [Token Exchange](/credential-drivers/token-exchange/) | `token_exchange` | RFC 8693 / RFC 7523 exchange at any OAuth2 STS (Entra OBO, ID-JAG) |

### Cloud

| Driver | `type` | Upstream |
|--------|--------|----------|
| [AWS](/credential-drivers/aws/) | `aws` | STS, Secrets Manager, RDS / Redshift IAM tokens |
| [Azure](/credential-drivers/azure/) | `azure` | Azure AD bearer tokens, Key Vault secrets |
| [GCP](/credential-drivers/gcp/) | `gcp` | IAM access tokens, service-account impersonation |
| [IBM Cloud](/credential-drivers/ibm/) | `ibm` | IAM bearer tokens, COS keys |
| [Alibaba Cloud](/credential-drivers/alicloud/) | `alicloud` | STS AssumeRole |
| [Scaleway](/credential-drivers/scaleway/) | `scaleway` | IAM static or dynamic API keys |
| [OVHcloud](/credential-drivers/ovh/) | `ovh` | OAuth2 bearer tokens, dynamic S3 credentials |

### SaaS

| Driver | `type` | Upstream |
|--------|--------|----------|
| [GitHub](/credential-drivers/github/) | `github` | App installation tokens and PATs (auth in the spec) |
| [GitLab](/credential-drivers/gitlab/) | `gitlab` | project and group access tokens |
| [Elasticsearch](/credential-drivers/elastic/) | `elastic` | `/_security` API keys |
| [Grafana](/credential-drivers/grafana/) | `grafana` | service-account tokens |
| [Honeycomb](/credential-drivers/honeycomb/) | `honeycomb` | V2 API keys |

## See Also

- [Credentials](/concepts/credentials/) — the source, spec, and credential model, plus lifetime, revocation, and rotation.
- [Provider backends](/provider-backends/) — end-to-end operator setup guides per upstream.
- [Roles](/concepts/roles/) — how a spec binds to an identity.
- [`warden cred`](/cli/cred/) — the CLI for sources and specs.
