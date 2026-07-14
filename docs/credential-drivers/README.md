# Credential Drivers

A **driver** is the pluggable component that knows how to talk to one kind of
upstream. A [credential source](../concepts/credentials.md) names a driver through
its `type`, holds the privileged secret, and the driver mints or retrieves the
scoped credential a workload needs — an STS session, a Vault token, a GitHub
installation token — which Warden injects into the proxied request.

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

See [Credentials](../concepts/credentials.md) for the source / spec / credential
model these pages build on.

## Generic and static

| Driver | `type` | Serves | Capabilities |
|--------|--------|--------|--------------|
| [Local](local.md) | `local` | static secrets stored directly in the spec | mint only |
| [Static API Key](apikey.md) | `apikey` | a static API key (in the spec) for any HTTP API | spec verification |

## Platform

| Driver | `type` | Upstream | Capabilities |
|--------|--------|----------|--------------|
| [HashiCorp Vault](vault.md) | `hvault` | Vault / OpenBao — KV, AWS/GCP/IBM engines, tokens, OAuth2 | source rotation (fast) |
| [Kubernetes](kubernetes.md) | `kubernetes` | ServiceAccount tokens via the TokenRequest API | spec verification · source rotation (fast) |
| [OAuth2](oauth2.md) | `oauth2` | generic OAuth2 providers | spec verification · OAuth2 consent |

## Cloud

| Driver | `type` | Upstream | Capabilities |
|--------|--------|----------|--------------|
| [AWS](aws.md) | `aws` | STS, Secrets Manager, RDS / Redshift IAM tokens | source rotation (slow, ~5m) |
| [Azure](azure.md) | `azure` | Azure AD bearer tokens, Key Vault secrets | source rotation (slow, ~5m) · **spec rotation** |
| [GCP](gcp.md) | `gcp` | IAM access tokens, service-account impersonation | source rotation (slow, ~2m) |
| [IBM Cloud](ibm.md) | `ibm` | IAM bearer tokens, COS keys | spec verification · source rotation (slow, ~2m) |
| [Alibaba Cloud](alicloud.md) | `alicloud` | STS AssumeRole | spec verification · source rotation (slow, ~5m) |
| [Scaleway](scaleway.md) | `scaleway` | IAM static or dynamic API keys | spec verification · source rotation (slow, ~30s) |
| [OVHcloud](ovh.md) | `ovh` | OAuth2 bearer tokens, dynamic S3 credentials | spec verification |

## SaaS

| Driver | `type` | Upstream | Capabilities |
|--------|--------|----------|--------------|
| [GitHub](github.md) | `github` | App installation tokens and PATs (auth in the spec) | spec verification |
| [GitLab](gitlab.md) | `gitlab` | project and group access tokens | source rotation (fast) |
| [Elasticsearch](elastic.md) | `elastic` | `/_security` API keys | spec verification · source rotation (slow, ~10s) |
| [Grafana](grafana.md) | `grafana` | service-account tokens | spec verification |
| [Honeycomb](honeycomb.md) | `honeycomb` | V2 API keys | spec verification |

## See Also

- [Credentials](../concepts/credentials.md) — the source, spec, and credential model, plus lifetime, revocation, and rotation.
- [Provider backends](../provider-backends/README.md) — end-to-end operator setup guides per upstream.
- [Roles](../concepts/roles.md) — how a spec binds to an identity.
- [`warden cred`](../cli/cred.md) — the CLI for sources and specs.
