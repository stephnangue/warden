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

**Discover.** The agent presents its identity — a JWT or TLS client certificate — and runs three introspection calls against Warden:

1. `warden role list` — which roles is this identity permitted to assume in this namespace?
2. `warden provider list` — which upstream systems are mounted here?
3. `warden skill read <type>` — for the chosen system, fetch the agent-facing recipe (env vars, endpoint URL, role-selection idiom).

Each response is human-readable JSON or markdown. The agent matches the task to a role and provider by reading operator-set descriptions — no config files, no role names distributed out of band, no SDK to rebuild when a new provider is mounted.

**Connect.** The agent picks a role and points at Warden as if it were the upstream. Warden authenticates the identity, applies the role's policy at request time, and attaches the upstream credential before forwarding — or vends a scoped grant directly, such as a database auth token or a pre-signed URL. The credential belongs to Warden, never to the agent — and is ephemeral wherever the upstream supports it.

## The enterprise control plane

What an enterprise gets from putting Warden in the path:

- **Per-call least privilege** — the agent asks Warden what systems and roles are open to it, then **switches roles mid-task**, picking the narrowest fit for each operation by reading operator-set descriptions. A read-scoped role for reads, a write-scoped role only when a write is intended — the agent's posture changes step by step, not session by session.
- **Hallucination containment** — LLMs make routine mistakes, and a single mistake under a broad credential can cause real damage. Per-call role binding constrains what the agent can do at every step; a hallucinated request that exceeds the role's scope is denied upstream — observable in the audit log, with no state change. LLM errors become recoverable instead of catastrophic.
- **Compromise containment** — because Warden holds the upstream credentials and the agent never does, a prompt-injected, jailbroken, or otherwise compromised agent has nothing to exfiltrate. Any call it does issue is still bounded by Warden's policy at request time — regardless of what's in the agent's memory or chat history.
- **Fine-grained access policy** — per-action capabilities and parameter filters, evaluated at request time against caller IP, time of day, and day of week.
- **Identity-bound access** — JWT (including SPIFFE JWT-SVID) or TLS client certificate (including SPIFFE X.509-SVID); the same identity reaches every upstream the policy permits — no per-system credential sprawl, no API keys handed to agents, nothing to rotate per integration.
- **Audit** — every request tied to the original identity, the role used, and the upstream called.

## Supported systems

33 systems across LLMs, cloud, code-hosting, observability, ITSM, Kubernetes, secrets, and databases. Follow any link below to configure your first endpoint, or see [docs/providers.md](docs/providers.md) for the full list.

| Category | Providers | Warden does |
|---|---|---|
| LLM APIs | [Anthropic](provider/anthropic/README.md), [OpenAI](provider/openai/README.md), [Mistral](provider/mistral/README.md), [Cohere](provider/cohere/README.md) | Injects API key |
| Cloud infrastructure | [AWS](provider/aws/README.md), [Azure](provider/azure/README.md), [GCP](provider/gcp/README.md), [Alicloud](provider/alicloud/README.md), [IBM Cloud](provider/ibmcloud/README.md), [OVH](provider/ovh/README.md), [Scaleway](provider/scaleway/README.md), [Cloudflare](provider/cloudflare/README.md) | Temporary credentials / Bearer tokens |
| Code hosting & CI/CD | [GitHub](provider/github/README.md), [GitLab](provider/gitlab/README.md), [Atlassian](provider/atlassian/README.md), [Ansible Tower](provider/ansible_tower/README.md), [Terraform Enterprise](provider/tfe/README.md) | Injects App token, PAT, or Bearer token |
| Observability | [Datadog](provider/datadog/README.md), [Dynatrace](provider/dynatrace/README.md), [Elastic](provider/elastic/README.md), [Grafana](provider/grafana/README.md), [Honeycomb](provider/honeycomb/README.md), [New Relic](provider/newrelic/README.md), [Prometheus](provider/prometheus/README.md), [Sentry](provider/sentry/README.md), [Splunk](provider/splunk/README.md) | Injects API key / proxies metrics |
| Incident & ITSM | [PagerDuty](provider/pagerduty/README.md), [ServiceNow](provider/servicenow/README.md), [Slack](provider/slack/README.md) | Injects Bearer token |
| Kubernetes | [Kubernetes](provider/kubernetes/README.md) | Injects service account token |
| Secrets backend | [HashiCorp Vault / OpenBao](provider/vault/README.md) | Mints short-lived tokens |
| Databases | [AWS RDS / Aurora](provider/rds/README.md), [AWS Redshift](provider/redshift/README.md) | Issues IAM database auth token |

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

| Method | Identity Source | How the agent presents the credential to its SDK |
|--------|----------------|----|
| **JWT** | Signed JWT token or SPIFFE JWT-SVID | The **same JWT** goes in whichever credential slot the upstream SDK natively expects (`AWS_SECRET_ACCESS_KEY`, `OPENAI_API_KEY`, `X-Vault-Token`, `Authorization: Bearer`, …). Warden detects it, validates the identity, and swaps in the real upstream credential. Existing SDK code keeps working — only the base URL changes. |
| **TLS Certificate** | X.509 client certificate or SPIFFE X.509-SVID | Identity is proven at the TLS handshake (or forwarded by a TLS-terminating proxy via `X-SSL-Client-Cert`). The SDK's credential slot is filled with any placeholder value — Warden ignores it once cert auth has proven the identity. Role selection follows the same per-provider conventions as JWT mode. |

This is the design property that makes Warden a *drop-in* layer rather than a rewrite tax: a pre-existing boto3, openai-python, Vault CLI, or curl-against-GitHub script becomes Warden-mediated by setting the base URL to Warden and putting the JWT where the secret used to go. It also separates Warden from MCP (which adds a protocol the agent host must speak) and from dedicated auth proxies (which typically require client libraries).

## Tutorials

**AWS access hygiene — per-call least privilege, mid-task.** A
Goose agent audits IAM in a sandbox AWS account through four
read-only lenses (inventory, recent usage, external exposure,
effective access) and publishes findings to Security Hub and a
Slack canvas — switching Warden roles between every call so each
operation runs under exactly the role it needs and nothing more. A
hallucinated `securityhub:BatchImportFindings` attempted under the
read intent is denied at AWS by the assumed role's narrow IAM
policy — not by Warden — and surfaces in the audit log as the
declared intent on a mismatched action. See
[the walk-through](docs/tutorials/aws-access-hygiene/README.md).

**Vault policy hygiene — one identity, three systems, zero
credentials.** A Goose agent audits OpenBao ACL policies, reasons
over them with an Anthropic-compatible LLM, and publishes the
report to Slack — all under one Forgejo OIDC JWT, all through
Warden. Sibling demo of the same discover-and-connect pattern,
exercising the *across-providers* axis (one Vault role for the
audit, one Slack role for delivery). See
[the walk-through](docs/tutorials/vault-policy-hygiene/README.md).

In both tutorials the agent's recipe contains no URLs, no role
names, no channel IDs, no account IDs. The runtime hands it three
env vars and a JWT; the agent asks Warden what's wired up for its
identity and picks the right combination by reading operator-set
descriptions. Rename a role, swap the LLM, move to a different
cluster — the recipe doesn't change.

For the system-side reference — the runtime contract, the discovery
loop, error handling — see [docs/agent-flow.md](docs/agent-flow.md).

## Architecture

See [docs/architecture.md](docs/architecture.md) for Warden's design decisions, high availability model, and deployment configuration.

## Kubernetes

A first-party Helm chart deploys Warden as a 3-replica HA cluster on any Kubernetes 1.27+ cluster — bring your own Postgres, your own TLS certificate, and either a Vault Transit endpoint for auto-unseal or a static seal key for development. The chart ships production-leaning defaults; a quickstart values file shrinks the install to a single replica for kind or minikube.

See [docs/deployment/kubernetes.md](docs/deployment/kubernetes.md) for the full guide.

## Contributing

We welcome contributions! See the [contributing guide](CONTRIBUTING.md) for setup instructions, build commands, testing conventions, and submission guidelines.

## License

[MPL-2.0](LICENSE)
