---
title: "Credential Drivers"
---

A **driver** is the pluggable component that knows how to talk to one kind of
upstream. A [credential source](/concepts/credentials/) names a driver through
its `type` and holds whatever that driver needs to obtain credentials — usually a
privileged secret, though some drivers instead **exchange the caller's own
identity** for a downstream credential and hold only the client credentials to
authenticate to an STS. The driver then mints or retrieves the scoped credential a
workload needs — an STS session, a Vault token, a GitHub installation token, a
token exchanged from the caller's identity — which Warden injects into the proxied
request.

Every driver implements the same core contract — **mint** a credential from a spec,
**revoke** a lease, and **clean up** — and may opt into extra capabilities:

- **Spec verification** — validate a spec's credentials with a light upstream call
  at create/update time, so a bad key fails early rather than at the gateway.
- **Source rotation** — rotate the source's *own* privileged secret on a schedule.
  A driver is **fast** (prepare and activate in one step) when its upstream is
  immediately consistent, or **slow** (stage the new secret and wait for it to
  propagate before destroying the old one) when it is eventually consistent. The
  wait is tunable per source via `activation_delay`.
- **Spec rotation** — use the source's elevated permissions to rotate a credential
  embedded in a spec.
- **OAuth2 authorization-code consent** — drive a one-time interactive consent flow.
- **Token exchange** — mint from caller-derived RFC 8693 inputs (a subject token,
  and optionally an actor token) rather than the source's own secret, exchanging
  the caller's identity for a scoped downstream credential.

See [Credentials](/concepts/credentials/) for the source / spec / credential
model these pages build on.

## Generic and static

| Driver | `type` | Serves | Capabilities |
|--------|--------|--------|--------------|
| [Local](/credential-drivers/local/) | `local` | static secrets stored directly in the spec | mint only |
| [Static API Key](/credential-drivers/apikey/) | `apikey` | a static API key (in the spec) for any HTTP API | spec verification |

## Platform

| Driver | `type` | Upstream | Capabilities |
|--------|--------|----------|--------------|
| [HashiCorp Vault](/credential-drivers/vault/) | `hvault` | Vault / OpenBao — KV, AWS/GCP/IBM engines, tokens, OAuth2 | source rotation (fast) |
| [Kubernetes](/credential-drivers/kubernetes/) | `kubernetes` | ServiceAccount tokens via the TokenRequest API | spec verification · source rotation (fast) |
| [OAuth2](/credential-drivers/oauth2/) | `oauth2` | generic OAuth2 providers | spec verification · OAuth2 consent |
| [Token Exchange](/credential-drivers/token-exchange/) | `token_exchange` | RFC 8693 / RFC 7523 exchange at any OAuth2 STS (Entra OBO, ID-JAG) | token exchange |

## Cloud

| Driver | `type` | Upstream | Capabilities |
|--------|--------|----------|--------------|
| [AWS](/credential-drivers/aws/) | `aws` | STS, Secrets Manager, RDS / Redshift IAM tokens | source rotation (slow, ~5m) |
| [Azure](/credential-drivers/azure/) | `azure` | Azure AD bearer tokens, Key Vault secrets | source rotation (slow, ~5m) · **spec rotation** |
| [GCP](/credential-drivers/gcp/) | `gcp` | IAM access tokens, service-account impersonation | source rotation (slow, ~2m) |
| [IBM Cloud](/credential-drivers/ibm/) | `ibm` | IAM bearer tokens, COS keys | spec verification · source rotation (slow, ~2m) |
| [Alibaba Cloud](/credential-drivers/alicloud/) | `alicloud` | STS AssumeRole | spec verification · source rotation (slow, ~5m) |
| [Scaleway](/credential-drivers/scaleway/) | `scaleway` | IAM static or dynamic API keys | spec verification · source rotation (slow, ~30s) |
| [OVHcloud](/credential-drivers/ovh/) | `ovh` | OAuth2 bearer tokens, dynamic S3 credentials | spec verification |

## SaaS

| Driver | `type` | Upstream | Capabilities |
|--------|--------|----------|--------------|
| [GitHub](/credential-drivers/github/) | `github` | App installation tokens and PATs (auth in the spec) | spec verification |
| [GitLab](/credential-drivers/gitlab/) | `gitlab` | project and group access tokens | source rotation (fast) |
| [Elasticsearch](/credential-drivers/elastic/) | `elastic` | `/_security` API keys | spec verification · source rotation (slow, ~10s) |
| [Grafana](/credential-drivers/grafana/) | `grafana` | service-account tokens | spec verification |
| [Honeycomb](/credential-drivers/honeycomb/) | `honeycomb` | V2 API keys | spec verification |

## See Also

- [Credentials](/concepts/credentials/) — the source, spec, and credential model, plus lifetime, revocation, and rotation.
- [Provider backends](/provider-backends/) — end-to-end operator setup guides per upstream.
- [Roles](/concepts/roles/) — how a spec binds to an identity.
- [`warden cred`](/cli/cred/) — the CLI for sources and specs.
