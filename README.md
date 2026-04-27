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

**The open-source egress gateway for AI agents — every API call is authenticated, authorized, and audited. No credentials ever reach the agent.**

---

AI agents need to call cloud APIs, read files, query databases, and interact with third-party services. Today, that means embedding API keys, cloud credentials, or database passwords into the agent's environment — where a single prompt injection can exfiltrate them.

The same credential-exposure problem hits **MCP servers** — each one wraps an external API and holds its credential in process env, one per tool, never rotating.

Warden sits at the egress point. Your agent or MCP server authenticates with its identity. Warden enforces your access policy, injects ephemeral credentials, and forwards the request. The caller never sees a secret.

```
┌──────────────┐                    ┌──────────────┐                     ┌──────────────┐
│              │      Identity      │              │    Scoped Access    │ AWS, Azure   │
│   AI Agent   │───────────────────▶│    Warden    │───────────────────▶ │ GitHub, GCP  │
│  MCP Server  │   no credentials   │              │  real credentials   │ Anthropic    │
│              │                    │              │                     │ OpenAI, S3   │
│              │                    │              │                     │ RDS, ...     │
└──────────────┘                    └──────────────┘                     └──────────────┘
                                    • Identity ✓
                                    • Policy ✓
                                    • Audit ✓
```

## The problem

AI agents are the most credential-exposed workloads in your stack:

- **Prompt injection exfiltration** — an agent with API keys in its environment is one adversarial prompt away from leaking them
- **Over-scoped access** — agents get broad cloud credentials with no per-request policy on what they can actually call
- **No audit trail** — when an agent calls an API, there is no record tying that specific request to that specific agent identity
- **Hardcoded secrets** — agent frameworks and MCP servers require API keys in environment variables or config files. Every MCP server wraps one external API and holds one credential baked into its process env. Static secrets, one per tool, never rotating
- **Multi-provider sprawl** — an agent calling Anthropic, AWS, and GitHub needs three separate API keys in a single `.env`. An agent with a dozen MCP servers has this at N× — every credential for every tool, scattered across process envs

The common thread: **the credential exists in the agent's environment — with more scope than needed, for longer than necessary, and no policy governing its use.**

Warden eliminates the credential from the agent entirely. Your agent authenticates with its identity. Warden handles every credential.

## What Warden covers
 
| Your client needs | Warden handles |
|---|---|
| Call LLM APIs (Anthropic, OpenAI, Mistral...) | Request forwarding, with injected API keys |
| Call cloud APIs (AWS, GCP, Azure, GitHub, GitLab...) | Request forwarding, with injected ephemeral credentials |
| Query databases (RDS, Cloud SQL, Redshift, Snowflake...) | Ephemeral database auth tokens — replacing static passwords entirely |
| Read and write files (S3, GCS, Azure Blob...) | Pre-signed URLs, scoped to exactly one object and operation |

One binary. One policy model. One audit log. Across every API your agent touches.

## Providers

Warden supports 31 providers across LLMs, cloud, observability, secrets, and more. Follow a provider link below to configure your first endpoint, or see [docs/providers.md](docs/providers.md) for the full list.

| Provider | Category | Warden does | Status |
|---|---|---|---|
| [Anthropic](provider/anthropic/README.md), [OpenAI](provider/openai/README.md), [Mistral](provider/mistral/README.md), [Cohere](provider/cohere/README.md) | LLM APIs | Injects API key | ✅ |
| [AWS](provider/aws/README.md), [Azure](provider/azure/README.md), [GCP](provider/gcp/README.md) | Cloud infrastructure | Temporary credentials | ✅ |
| [GitHub](provider/github/README.md), [GitLab](provider/gitlab/README.md) | Code hosting & CI/CD | Injects App token or PAT | ✅ |
| [Datadog](provider/datadog/README.md), [Grafana](provider/grafana/README.md), [Prometheus](provider/prometheus/README.md) | Observability | Injects API key / proxies metrics | ✅ |
| [HashiCorp Vault / OpenBao](provider/vault/README.md) | Secrets backend | Mints short-lived tokens | ✅ |
| [Kubernetes](provider/kubernetes/README.md) | Infrastructure automation | Injects service account token | ✅ |
| [AWS RDS / Aurora](provider/rds/README.md) | Database | Issues IAM auth token | 🔜 |


## Use Cases

**SRE agents** — incident response agents that query Prometheus, read logs from Grafana, restart services, and page on-call need broad infrastructure access. Warden scopes each API call to the agent's identity and policy — the agent can query dashboards but can't delete them, can restart a pod but can't modify IAM roles. Full audit trail of every action taken during an incident.

**Agentic coding** — code agents that push to GitHub, deploy to AWS, and read from S3 authenticate once with their identity. Warden enforces which repos they can push to, which buckets they can read, and logs every action.

**RAG pipelines** — retrieval agents that query databases and read from object storage get scoped, ephemeral credentials for each request. No database password in the agent's config. No S3 keys in the environment.

**Multi-model orchestration** — an agent calling Anthropic for reasoning, OpenAI for embeddings, and Mistral for classification has three API keys today. With Warden, it has zero — one identity, one policy layer, one audit log across all providers.

**MCP servers** — an MCP server that wraps the GitHub API or the AWS SDK holds a credential per tool. Point it at Warden instead: the MCP server authenticates with its identity, Warden injects the credential per request, and a prompt injection in the agent above cannot exfiltrate anything — there is nothing in the MCP process to exfiltrate.

**Autonomous workflows** — long-running agents that operate over hours or days get time-scoped access. Warden issues ephemeral credentials per request — no long-lived tokens that accumulate risk over the lifetime of the workflow.

Warden also secures non-agent workloads — CI/CD pipelines, microservices, developer machines — with the same identity-based model.


## Authentication Methods

Warden supports multiple methods for verifying caller identity.

| Method | Identity Source | Best For |
|--------|----------------|----------|
| **JWT** | Signed JWT token or SPIFFE JWT-SVID | AI agents, MCP servers, agentic frameworks, any workload with an OIDC/JWT issuer or SPIFFE runtime |
| **TLS Certificate** | X.509 client certificate or SPIFFE X.509-SVID | Agents in service mesh environments, Kubernetes pods, VMs with machine certificates |

SPIFFE is supported in both methods — JWT-SVIDs via JWT auth and X.509-SVIDs via certificate auth. Both methods produce the same internal session. Once authenticated, the caller interacts with Warden identically regardless of how they proved their identity.

## How clients interact with Warden

Your agent or MCP server points at Warden's endpoint instead of the provider's and includes its identity token (JWT) in the request — or connects via mTLS. Warden authenticates the caller, checks the access policy, injects ephemeral credentials, and forwards the request to the provider. For databases and storage, Warden returns an access grant (auth token, pre-signed URL) directly. No Warden-specific SDK, no login step — just swap the base URL.

## Architecture

See [docs/architecture.md](docs/architecture.md) for Warden's design decisions, high availability model, and deployment configuration.

## Tutorials

End-to-end walkthroughs that combine Warden with real-world workloads:

- [Vault policy hygiene](docs/tutorials/vault-policy-hygiene/README.md) — a Goose AI agent that audits OpenBao ACL policies for hygiene (dead-mount references, orphan bindings, duplicates, least-privilege smells). All three egress legs — OpenBao inspection, Anthropic-compatible inference, and Slack delivery as a channel canvas — flow through Warden, gated by per-job Forgejo OIDC JWTs. The agent holds zero credentials.

## Contributing

We welcome contributions! See the [contributing guide](CONTRIBUTING.md) for setup instructions, build commands, testing conventions, and submission guidelines.

## License

[MPL-2.0](LICENSE)
