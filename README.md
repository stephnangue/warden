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

Warden sits at the egress point. Your agent authenticates with its identity. Warden enforces your access policy, injects ephemeral credentials, and forwards the request. The agent never sees a secret.

```
┌──────────────┐                    ┌──────────────┐                     ┌──────────────┐
│              │      Identity      │              │    Scoped Access    │ AWS, Azure   │
│   AI Agent   │───────────────────▶│    Warden    │───────────────────▶ │ GitHub, GCP  │
│              │   no credentials   │              │  real credentials   │ Anthropic    │
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
- **Hardcoded secrets** — agent frameworks require API keys in environment variables or config files, creating static secrets that never rotate
- **Multi-provider sprawl** — an agent calling Anthropic, AWS, and GitHub needs three separate API keys in a single `.env`

The common thread: **the credential exists in the agent's environment — with more scope than needed, for longer than necessary, and no policy governing its use.**

Warden eliminates the credential from the agent entirely. Your agent authenticates with its identity. Warden handles every credential.

## Quickstart

Follow a provider guide to configure your first endpoint:

- [Anthropic](provider/anthropic/README.md)
- [OpenAI](provider/openai/README.md)
- [Mistral](provider/mistral/README.md)
- [AWS](provider/aws/README.md)
- [GCP](provider/gcp/README.md)
- [Azure](provider/azure/README.md)
- [GitHub](provider/github/README.md)
- [GitLab](provider/gitlab/README.md)
- [Vault / OpenBao](provider/vault/README.md)
- [AWS RDS / Aurora](provider/rds/README.md)

## What Warden covers
 
| Your agent needs | Warden handles |
|---|---|
| Call LLM APIs (Anthropic, OpenAI, Mistral...) | Request forwarding, with injected API keys |
| Call cloud APIs (AWS, GCP, Azure, GitHub, GitLab...) | Request forwarding, with injected ephemeral credentials |
| Query databases (RDS, Cloud SQL, Redshift, Snowflake...) | Ephemeral database auth tokens — replacing static passwords entirely |
| Read and write files (S3, GCS, Azure Blob...) | Pre-signed URLs, scoped to exactly one object and operation |

One binary. One policy model. One audit log. Across every API your agent touches.

## Supported Providers

| Provider | Warden does | Status |
|---|---|---|
| AWS | Injects credentials | ✅ |
| GCP | Injects credentials | ✅ |
| Azure | Injects credentials | ✅ |
| GitHub | Injects credentials | ✅ |
| GitLab | Injects credentials | ✅ |
| Anthropic | Injects credentials | ✅ |
| Mistral | Injects credentials | ✅ |
| OpenAI | Injects credentials | ✅ |
| HashiCorp Vault / OpenBao | Injects credentials | ✅ |
| AWS RDS / Aurora | Issues database auth token | 🔜 |
| AWS Redshift | Issues database auth token | 🔜 |
| GCP Cloud SQL | Issues database auth token | 🔜 |
| Azure SQL | Issues database auth token | 🔜 |
| Snowflake | Issues database auth token | 🔜 |
| AWS S3 | Issues pre-signed URL | 🔜 |
| GCP Cloud Storage | Issues pre-signed URL | 🔜 |
| Azure Blob Storage | Issues pre-signed URL | 🔜 |
 

## Use Cases

**SRE agents** — incident response agents that query Prometheus, read logs from Grafana, restart services, and page on-call need broad infrastructure access. Warden scopes each API call to the agent's identity and policy — the agent can query dashboards but can't delete them, can restart a pod but can't modify IAM roles. Full audit trail of every action taken during an incident.

**Agentic coding** — code agents that push to GitHub, deploy to AWS, and read from S3 authenticate once with their identity. Warden enforces which repos they can push to, which buckets they can read, and logs every action.

**RAG pipelines** — retrieval agents that query databases and read from object storage get scoped, ephemeral credentials for each request. No database password in the agent's config. No S3 keys in the environment.

**Multi-model orchestration** — an agent calling Anthropic for reasoning, OpenAI for embeddings, and Mistral for classification has three API keys today. With Warden, it has zero — one identity, one policy layer, one audit log across all providers.

**Tool-use agents** — agents with MCP tools that call arbitrary cloud APIs get per-tool, per-request policy enforcement. The agent can only reach the APIs your policy allows, regardless of what a prompt tells it to do.

**Autonomous workflows** — long-running agents that operate over hours or days get time-scoped access. Warden issues ephemeral credentials per request — no long-lived tokens that accumulate risk over the lifetime of the workflow.

Warden also secures non-agent workloads — CI/CD pipelines, microservices, developer machines — with the same identity-based model.


## Authentication Methods

Warden supports multiple methods for verifying caller identity.

| Method | Identity Source | Best For |
|--------|----------------|----------|
| **JWT** | Signed JWT token or SPIFFE JWT-SVID | AI agents, agentic frameworks, any workload with an OIDC/JWT issuer or SPIFFE runtime |
| **TLS Certificate** | X.509 client certificate or SPIFFE X.509-SVID | Agents in service mesh environments, Kubernetes pods, VMs with machine certificates |

SPIFFE is supported in both methods — JWT-SVIDs via JWT auth and X.509-SVIDs via certificate auth. Both methods produce the same internal session. Once authenticated, the caller interacts with Warden identically regardless of how they proved their identity.

## How agents interact with Warden

Your agent points at Warden's endpoint instead of the provider's and includes its identity token (JWT) in the request — or connects via mTLS. Warden authenticates the agent, checks the access policy, injects ephemeral credentials, and forwards the request to the provider. For databases and storage, Warden returns an access grant (auth token, pre-signed URL) directly. No Warden-specific SDK, no login step — just swap the base URL.

## Architecture

Warden is a Go service that sits between workloads and providers. Providers are registered as either streaming backends (which proxy traffic to upstream services) or access backends (which vend credentials directly without proxying). Each backend has its own credential source driver, authentication flow, and policy rules.

**Key design decisions:**
- **Seal/unseal model** — Like Vault, Warden protects secrets at rest using envelope encryption. Supports dev mode (in-memory) and production mode with multiple seal types (Shamir, Transit, AWS KMS, GCP KMS, Azure Key Vault, OCI KMS, PKCS11, KMIP) and PostgreSQL storage.
- **Active/standby HA** — See [High Availability](#high-availability) below.
- **Access grants over proxying for databases** — For providers like RDS where Warden doesn't need to sit in the data path, access backends return ready-to-use connection strings with short-lived tokens. This avoids the latency and complexity of proxying database traffic while preserving identity-based access control and audit attribution.
- **Namespace isolation** — Every credential source, policy, and mount point is scoped to a namespace with hard boundaries. Policies cannot leak across namespaces.

### High Availability

Warden supports active/standby HA. Multiple nodes share the same storage backend and use PostgreSQL advisory locks for leader election. One node becomes the active leader; the rest are hot standbys that automatically promote on leader failure.

**How it works:**

- **Standby forwarding** — Standby nodes forward all write and read requests to the active leader via mTLS reverse proxy. Clients can send requests to any node; the response is the same regardless of which node receives it.
- **Automatic failover** — If the leader fails, a standby acquires the lock and promotes itself. Standby nodes detect the leader change and redirect their forwarding proxy to the new leader.
- **Sealed node protection** — Sealed nodes are prevented from acquiring the leadership lock, ensuring only fully operational nodes can become leader.

**Configuration** — each node needs `api_addr` (its own API address, used by the leader to advertise itself), `cluster_addr` (its mTLS cluster address for inter-node communication), and a shared storage backend with `ha_enabled`:

```hcl
api_addr     = "http://10.0.1.1:8400"
cluster_addr = "https://10.0.1.1:8401"

storage "postgres" {
  connection_url = "postgres://warden:password@db:5432/warden?sslmode=require"
  table          = "warden_store"
  ha_table       = "warden_ha_locks"
  ha_enabled     = "true"
}

listener "tcp" {
  address     = "0.0.0.0:8400"
  tls_enabled = false
}
```

### Configuration

Warden uses HCL configuration files. See `deploy/config/warden.local.hcl` for a full example covering storage backend, listener, providers, and auth methods.

## Contributing

We welcome contributions! See the [contributing guide](CONTRIBUTING.md) for setup instructions, build commands, testing conventions, and submission guidelines.

## License

[MPL-2.0](LICENSE)
