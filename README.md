<p align="center">
  <img src="./warden.png" alt="Warden" width="200" />
  <br/>
  <a href="https://openbao.org/ecosystem/integrators/">
    <img src="https://img.shields.io/badge/OpenBao-Integrator-purple" alt="OpenBao Integrator" />
  </a>
  <a href="https://github.com/stephnangue/warden/actions/workflows/ci.yml">
    <img src="https://github.com/stephnangue/warden/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI" />
  </a>
  <a href="https://github.com/stephnangue/warden/releases/latest">
    <img src="https://img.shields.io/github/v/release/stephnangue/warden" alt="Latest Release" />
  </a>
  <a href="https://goreportcard.com/report/github.com/stephnangue/warden">
    <img src="https://goreportcard.com/badge/github.com/stephnangue/warden" alt="Go Report Card" />
  </a>
  <a href="https://pkg.go.dev/github.com/stephnangue/warden">
    <img src="https://pkg.go.dev/badge/github.com/stephnangue/warden.svg" alt="Go Reference" />
  </a>
  <a href="https://codecov.io/gh/stephnangue/warden">
    <img src="https://codecov.io/gh/stephnangue/warden/branch/main/graph/badge.svg" alt="codecov" />
  </a>
  <a href="https://github.com/stephnangue/warden/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/stephnangue/warden" alt="License" />
  </a>
  <a href="https://img.shields.io/github/go-mod/go-version/stephnangue/warden">
    <img src="https://img.shields.io/github/go-mod/go-version/stephnangue/warden" alt="Go Version" />
  </a>
</p>

# Warden

**The secure gateway connecting AI agents to the enterprise systems they need to do real work.**

Agents discover what they're allowed to access. Warden brokers every connection. Operators get one control plane for identity, policy, and audit — across every cloud, code-host, observability stack, database, and SaaS the agent reaches.

---

## The enterprise problem

Agents are useful only when they reach real systems: cloud accounts, code repositories, observability stacks, databases, ITSM, secrets backends. Today, pointing an agent at production means handing it over-scoped, long-lived credentials, with no per-request policy and no identity-tied audit. Each new system is another credential in the agent's environment, governed by nothing in the request path.

The control gap, not the credential, is the headline. **MCP servers** make it acute — every server wraps one upstream API and holds one credential in process env, so an agent with a dozen tools has a dozen static secrets scattered across a dozen processes, none of them rotating, none of them governed.

Warden closes the gap by sitting in the path: the agent identifies itself, Warden decides what it can reach, and Warden brokers the connection.

## How Warden works: discover then connect

```
┌──────────────┐                    ┌──────────────┐                     ┌──────────────┐
│              │   1. Discover      │              │                     │              │
│              │ ─────────────────▶ │              │                     │ AWS, Azure   │
│   AI Agent   │   what can I do?   │              │                     │ GCP, GitHub  │
│  MCP Server  │                    │    Warden    │   real credentials  │ Anthropic    │
│              │   2. Connect       │              │ ──────────────────▶ │ OpenAI, RDS  │
│              │ ─────────────────▶ │              │                     │ Slack, K8s   │
│              │   identity only    │              │                     │ ...          │
└──────────────┘                    └──────────────┘                     └──────────────┘
                                    • Identity ✓
                                    • Policy ✓
                                    • Audit ✓
```

**Discover.** The agent presents its identity — a JWT or TLS client certificate — and asks Warden which roles it is permitted to assume. Warden answers with the set of roles open to that exact identity, each with a human-readable description. The agent learns what it can do without anyone shipping a config file or distributing role names out of band.

**Connect.** The agent picks a role and points at Warden as if it were the upstream. Warden authenticates the identity, applies the role's policy at request time, and attaches the upstream credential before forwarding — or vends a scoped grant directly, such as a database auth token or a pre-signed URL. The credential belongs to Warden, never to the agent — and is ephemeral wherever the upstream supports it.

## The enterprise control plane

What an enterprise gets from putting Warden in the path:

- **Discovery** — identity-scoped introspection. Agents learn which systems and roles are open to them; nothing has to be pre-loaded into the agent's environment.
- **Policy with runtime conditions** — role and path checks plus `source_ip`, `time_window`, and `day_of_week` predicates evaluated at request time.
- **Identity-bound access** — JWT (including SPIFFE JWT-SVID) or TLS client certificate (including SPIFFE X.509-SVID); same internal session either way.
- **Audit** — every request tied to the original identity, the role used, and the upstream called.
- **Credentials never leave Warden** — a prompt-injected agent has nothing to leak; there is no credential in its environment to exfiltrate.

## Providers

33 providers across LLMs, cloud, code-hosting, observability, ITSM, Kubernetes, secrets, and databases. Follow a provider link below to configure your first endpoint, or see [docs/providers.md](docs/providers.md) for the full list.

| Category | Providers | Warden does | Status |
|---|---|---|---|
| LLM APIs | [Anthropic](provider/anthropic/README.md), [OpenAI](provider/openai/README.md), [Mistral](provider/mistral/README.md), [Cohere](provider/cohere/README.md) | Injects API key | ✅ |
| Cloud infrastructure | [AWS](provider/aws/README.md), [Azure](provider/azure/README.md), [GCP](provider/gcp/README.md), [Alicloud](provider/alicloud/README.md), [IBM Cloud](provider/ibmcloud/README.md), [OVH](provider/ovh/README.md), [Scaleway](provider/scaleway/README.md), [Cloudflare](provider/cloudflare/README.md) | Temporary credentials / Bearer tokens | ✅ |
| Code hosting & CI/CD | [GitHub](provider/github/README.md), [GitLab](provider/gitlab/README.md), [Atlassian](provider/atlassian/README.md), [Ansible Tower](provider/ansible_tower/README.md), [Terraform Enterprise](provider/tfe/README.md) | Injects App token, PAT, or Bearer token | ✅ |
| Observability | [Datadog](provider/datadog/README.md), [Dynatrace](provider/dynatrace/README.md), [Elastic](provider/elastic/README.md), [Grafana](provider/grafana/README.md), [Honeycomb](provider/honeycomb/README.md), [New Relic](provider/newrelic/README.md), [Prometheus](provider/prometheus/README.md), [Sentry](provider/sentry/README.md), [Splunk](provider/splunk/README.md) | Injects API key / proxies metrics | ✅ |
| Incident & ITSM | [PagerDuty](provider/pagerduty/README.md), [ServiceNow](provider/servicenow/README.md), [Slack](provider/slack/README.md) | Injects Bearer token | ✅ |
| Kubernetes | [Kubernetes](provider/kubernetes/README.md) | Injects service account token | ✅ |
| Secrets backend | [HashiCorp Vault / OpenBao](provider/vault/README.md) | Mints short-lived tokens | ✅ |
| Databases | [AWS RDS / Aurora](provider/rds/README.md), [AWS Redshift](provider/redshift/README.md) | Issues IAM database auth token | ✅ |

## Use cases

**SRE agents** — incident-response agents reaching Prometheus, Grafana, Kubernetes, and PagerDuty under one policy layer. Warden scopes each call to the agent's identity — query dashboards but not delete them, restart a pod but not modify IAM. Every action during an incident is tied to the agent's identity in the audit log.

**Agentic coding** — code agents that push to GitHub, deploy to AWS, and read from artifact stores all through one identity. Warden enforces which repos they push to, which buckets they read, and logs every action.

**RAG pipelines** — retrieval agents reaching production databases and object stores under per-request grants. Warden vends a database auth token or pre-signed URL scoped to the exact query or object the agent needs.

**Multi-model orchestration** — an agent reaching Anthropic for reasoning, OpenAI for embeddings, and Mistral for classification through one identity, one policy layer, and one audit log across all three.

**MCP servers** — point the MCP server at Warden instead of the upstream API. The MCP server authenticates with its identity, Warden brokers the connection, and the same gateway covers every tool the server exposes — replacing the per-tool-credential-in-env model with one identity and one policy surface.

**Autonomous workflows** — long-running agents that reach systems over hours or days with time-scoped access. Warden issues credentials per request, so no token outlives the work it was minted for.

Warden also secures non-agent workloads — CI/CD pipelines, microservices, developer machines — with the same identity-based model.

## Authentication methods

Warden supports multiple methods for verifying caller identity.

| Method | Identity Source | Best For |
|--------|----------------|----------|
| **JWT** | Signed JWT token or SPIFFE JWT-SVID | AI agents, MCP servers, agentic frameworks, any workload with an OIDC/JWT issuer or SPIFFE runtime |
| **TLS Certificate** | X.509 client certificate or SPIFFE X.509-SVID | Agents in service mesh environments, Kubernetes pods, VMs with machine certificates |

SPIFFE is supported in both methods — JWT-SVIDs via JWT auth and X.509-SVIDs via certificate auth. Both methods produce the same internal session. Once authenticated, the caller interacts with Warden identically regardless of how they proved their identity.

## Tutorial: one identity, three systems, zero credentials

A walk-through of the discover-then-connect model end to end:

- A Goose AI agent audits OpenBao ACL policies for hygiene — dead-mount references, orphan bindings, duplicates, least-privilege smells.
- Three egress legs: OpenBao (read), an Anthropic-compatible LLM (reason), Slack (deliver as a channel canvas).
- One Forgejo OIDC JWT covers all three legs, with three independently scoped Warden policies governing what each leg may do.
- The agent holds zero credentials.

See [docs/tutorials/vault-policy-hygiene/README.md](docs/tutorials/vault-policy-hygiene/README.md) for the full walk-through.

## Architecture

See [docs/architecture.md](docs/architecture.md) for Warden's design decisions, high availability model, and deployment configuration.

## Contributing

We welcome contributions! See the [contributing guide](CONTRIBUTING.md) for setup instructions, build commands, testing conventions, and submission guidelines.

## License

[MPL-2.0](LICENSE)
