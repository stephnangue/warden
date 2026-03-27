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
  <a href="https://github.com/stephnangue/warden/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/stephnangue/warden" alt="License" />
  </a>
  <a href="https://img.shields.io/github/go-mod/go-version/stephnangue/warden">
    <img src="https://img.shields.io/github/go-mod/go-version/stephnangue/warden" alt="Go Version" />
  </a>
</p>

# Warden

**Every team that ships code has credentials it shouldn't have.**
 
**Developers with AWS keys on their laptops. Data pipelines with Snowflake passwords in config files. AI agents with ambient cloud access and no policy. CI pipelines with secrets that never rotate.**
 
**Warden is the single layer that eliminates all of it.**
 
---

Your workload authenticates to Warden with its identity. Warden verifies who is calling, checks the policy, and issues ephemeral request-scoped access — either by forwarding the request with access token injected, returning a database auth token, or returning a pre-signed URL. Your workload has no secrets to leak.

```
┌──────────────┐                    ┌──────────────┐                     ┌──────────────┐
│  Developer   │      Identity      │              │    Scoped Access    │ AWS, Azure   │
│  K8s pod     │───────────────────▶│    Warden    │───────────────────▶ │ GitHub, GCP  │
│  Pipeline    │   no credentials   │              │  real credentials   │ Anthropic    │
│  AI agent    │                    │              │                     │ Mistral      │
│              │                    │              │                     │ RDS, S3...   │
└──────────────┘                    └──────────────┘                     └──────────────┘
                                    • Auth ✓
                                    • Policy ✓
                                    • Audit ✓
```

## The problem
 
Exposed credentials are the root cause of most cloud security incidents:
 
- An AI agent with ambient cloud credentials — no policy on what it can call, no audit trail of what it did
- A `DATABASE_URL` in a `.env` — one accidental commit away from being in your repository forever
- A developer laptop with a `~/.aws/credentials` — production access on a device that gets lost, stolen, or compromised
- An AWS key in a Lambda environment variable — visible in plaintext to anyone with console access or a logging misconfiguration
- A GitHub PAT in a CI environment variable — a bearer token any compromised runner can extract and use from any IP
 
The common thread: **the credential exists somewhere it shouldn't, with more scope than needed, for longer than necessary.**
 
Warden eliminates the credential from the equation entirely. Your workloads authenticate with their identity. Warden handles the credential.

## Quickstart

Follow a provider guide to configure your first endpoint:

- [AWS](provider/aws/README.md)
- [Azure](provider/azure/README.md)
- [GCP](provider/gcp/README.md)
- [GitHub](provider/github/README.md)
- [GitLab](provider/gitlab/README.md)
- [Vault / OpenBao](provider/vault/README.md)
- [Anthropic](provider/anthropic/README.md)
- [Mistral](provider/mistral/README.md)
- [OpenAI](provider/openai/README.md)
- [AWS RDS / Aurora](provider/rds/README.md)

## What Warden covers
 
| Your workload needs | Warden handles |
|---|---|
| Call cloud APIs (AWS, GCP, Azure, GitHub, GitLab...) | Request forwarding, with injected ephemeral credentials |
| Connect to a database (RDS, Cloud SQL, Redshift, Azure SQL, Snowflake...) | Ephemeral database auth tokens — replacing static passwords entirely |
| Read and write files (S3, GCS, Azure Blob...) | Pre-signed URLs, scoped to exactly one object and operation |

One binary. One policy model. One audit log. Across your entire stack.

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
 
**AI agents** — agents authenticate with their identity and can only reach the APIs your policy allows. Every file read, every API call, every database query is logged with the agent's identity. Prompt injection can't exfiltrate credentials that don't exist in the agent's environment.
 
**CI/CD pipelines** — pipelines authenticate with their OIDC token (GitHub Actions, GitLab CI, Kubernetes). No credentials stored as CI secrets. Per-job audit trail across every cloud and SaaS API the pipeline touches.
 
**Data pipelines** — dbt, Airflow, Spark, and custom ELT jobs touch more external services per run than almost any other workload. With Warden, each pipeline run authenticates with its job identity and gets scoped, ephemeral credentials for every source database, data warehouse, and staging bucket it needs. No shared Snowflake passwords in `profiles.yml`. No Redshift user shared across 30 DAGs. Full per-run audit trail of every query and file operation.
 
**Developer machines** — developers authenticate with a mTLS certificate or short-lived JWT. No static keys on disk. Full per-developer audit trail in production-like environments.
 
**Microservices** — each service authenticates with its Kubernetes service account JWT or SPIFFE SVID. Gets exactly the credentials it needs. Credential sprawl — one IAM user per service — is eliminated at the architecture level.
 
**Database access** — no static password in your `DATABASE_URL`. Your workload asks Warden for a database auth token when it needs one. It expires in 15 minutes. Nothing to leak, nothing to rotate, nothing to store.
 
**Storage access** — no AWS credentials in your Lambda to generate pre-signed URLs. Your backend calls Warden with the object path and gets a pre-signed URL valid for 5 minutes, scoped to exactly that object and operation.
 
**Multi-provider workloads** — a single service that calls AWS for storage, GCP for ML inference, GitHub for source access, and Anthropic for LLM completions has four separate credential problems today. With Warden, it has one: authenticate once with its identity, and let Warden handle every provider behind a single policy layer and a single audit log.


## Authentication Methods

Warden supports multiple methods for verifying caller identity.

| Method | Identity Source | Best For |
|--------|----------------|----------|
| **JWT** | Signed JWT token or SPIFFE JWT-SVID | CI/CD pipelines, AI agents, any workload with an OIDC/JWT issuer or SPIFFE runtime |
| **TLS Certificate** | X.509 client certificate or SPIFFE X.509-SVID | Developers, Kubernetes pods, service mesh workloads, VMs with machine certificates |

SPIFFE is supported in both methods — JWT-SVIDs via JWT auth and X.509-SVIDs via certificate auth. Both methods produce the same internal session. Once authenticated, the caller interacts with Warden identically regardless of how they proved their identity.

## How workloads interact with Warden

Your tool points at Warden's endpoint and makes a normal HTTP request with a JWT in the `Authorization` header (for AWS, the JWT is embedded in the SigV4 signing flow), or via mTLS. Warden authenticates, injects credentials, and either forwards the request to the provider or returns an access grant (database auth token, pre-signed URL) directly. No Warden-specific SDK or login step is required.

## Why not just use the cloud provider's native tooling?
 
AWS IRSA, GCP Workload Identity, and Azure Managed Identity each let workloads authenticate to their respective cloud without static secrets — but none of them:

- Keep cloud credentials out of the workload entirely — the workload still receives and handles cloud credentials (e.g., an STS token injected into the pod). With Warden, the workload only uses its own identity (JWT or certificate)
- Work across multiple cloud providers from a single policy layer
- Cover databases and storage with the same identity and audit model
- Give you request-level audit tied to the specific workload identity — not just the IAM role shared by many workloads
- Work for GitHub, GitLab, or any SaaS API
- Can be deployed on-premises or in air-gapped environments

Warden is the layer that makes workload identity work everywhere, for every credential type, from a single control plane you own.

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

Warden uses HCL configuration files. See `warden.local.hcl` for a full example covering storage backend, listener, providers, and auth methods.

## Contributing

We welcome contributions! See the [contributing guide](CONTRIBUTING.md) for setup instructions, build commands, testing conventions, and submission guidelines.

## License

[MPL-2.0](LICENSE)
