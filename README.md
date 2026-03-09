# Warden

**No credentials. Full audit. Every cloud API.**

Warden is an identity-aware egress gateway that replaces cloud credentials with zero-trust access.

With Warden, developers, pipelines, AI agents, and Kubernetes workloads access cloud APIs using identity — whether a JWT, a TLS certificate, or a SPIFFE SVID — while every API call is governed and audited.

Warden sits in the request path between your workloads and the services they call — cloud APIs (AWS, GitHub, Azure), SaaS platforms, and AI providers (Mistral, OpenAI, Anthropic). It authenticates callers by identity, injects credentials on the fly, enforces fine-grained policies on every request, and logs every API call. Your workloads never touch a secret.

```
┌──────────────┐                    ┌──────────────┐                     ┌──────────────┐
│  Developer   │      Identity      │              │    Scoped Access    │ AWS, Azure   │
│  K8s pod     │───────────────────▶│    Warden    │───────────────────▶ │ GitHub, GCP  │
│  Pipeline    │   no credentials   │              │  real credentials   │ Mistral      │
│  AI agent    │                    │              │                     │ OpenAI  ...  │
└──────────────┘                    └──────────────┘                     └──────────────┘
                                    • Auth ✓
                                    • Policy ✓
                                    • Audit ✓
```

## Supported Providers

### Cloud & SaaS Providers

| Provider | Status | Credential Source |
|----------|--------|-------------------|
| **AWS** | ✅ GA | Direct from AWS STS or via Vault AWS secrets engine |
| **Azure** | ✅ GA | Service principal credentials |
| **GCP** | ✅ GA | Service account credentials |
| **GitHub** | ✅ GA | PATs, GitHub App tokens |
| **GitLab** | ✅ GA | PATs, Deploy tokens |
| **Vault / OpenBao** | ✅ GA | Token-based |

### AI Providers

| Provider | Status | Credential Source |
|----------|--------|-------------------|
| **Mistral** | ✅ GA | API key |
| **OpenAI** | ✅ GA | API key |
| Anthropic | Planned | — |
| Cohere | Planned | — |

The roadmap targets 100+ cloud and SaaS providers and all major AI providers.

## Why Warden?

### Zero Credential Exposure

Your workloads never see API keys or cloud credentials. Warden intercepts requests, injects credentials on the fly, and forwards them to providers. No secrets in environment variables, no keys in config files, no credential leaks — even if a workload is compromised, there are no credentials to exfiltrate.

### Request-Level Audit Trail

Warden doesn't just log who received credentials — it logs what they did with them. Every API call — whether an AI inference or a cloud operation — produces a structured audit entry capturing identity, policy result, credential used, request details, and response status.

```
# Typical:  "pipeline-X was granted AWS credentials at 14:32"
# Warden:   "pipeline-X (role: deploy-ops) called PUT .../resourcegroups/my-rg → 201, using
#           credential: azure-source/azure-cred-spec (ttl: 3599s)"
#
# Warden:   "agent-Y (role: mistral-ops) called POST /v1/chat/completions
#           (model: mistral-large, max_tokens: 4096) → 200, using
#           credential: mistral-src/mistral-ops"
```

### Fine-Grained Policy Enforcement

Warden constrains what a workload can do by controlling which APIs it can reach, which operations it can perform, and — for AI providers — which models and parameters it can use.

A GitHub fine-grained PAT with `contents: read` lets the holder read *every file* in a repo. Warden can restrict a pipeline to `src/` while blocking `.github/workflows/` and `.env` — something GitHub simply cannot express. For AWS, destructive operations can be blocked at the gateway regardless of what the underlying IAM role permits. A Mistral API key grants access to every model. Warden can restrict an agent to `mistral-small-latest` only, enforce max_tokens limits, and require streaming mode — cost control that API key scoping alone cannot provide.

Policies also support **runtime conditions** — source IP restrictions, time-of-day windows, and day-of-week constraints — that deny requests even when capabilities match. This enables scenarios like restricting production deployments to office hours from trusted networks only.

### AI Request Governance

Warden parses AI request bodies and evaluates policies against inference parameters. This enables cost control and usage governance at the gateway layer:

- **Model access control** — restrict which models each agent identity can use
- **Token budgets** — enforce max_tokens limits per role
- **Streaming requirements** — require streaming mode for real-time cost visibility
- **Full inference audit** — every completion request is logged with model, parameters, and response status

### Zero Client Modification

Point your existing tools at Warden's endpoint instead of the provider's. The AWS CLI, Terraform, GitHub CLI, Mistral SDK, OpenAI SDK, or any HTTP client — if it supports a custom base URL or endpoint override, it works with Warden. No code changes, no special libraries, no proxy configuration.

### Identity-Based Access

Every request is tied to a verified identity — via JWT, TLS client certificate, or SPIFFE SVID. Whether it's a developer authenticating with a client certificate from their laptop, a Kubernetes pod identified by its SPIFFE SVID, a CI/CD pipeline deploying to AWS, or an AI agent calling Mistral, Warden knows exactly who is making each API call and applies policies accordingly.

### Unified Identity Across Providers

Every provider has its own identity system — AWS IAM, Azure Entra ID, GitHub Apps, Mistral API keys. Multi-provider means multi-identity: different auth flows, different credential formats, different rotation strategies. Warden collapses all of that behind a single identity layer. Your workloads authenticate once — with a JWT or a client certificate — and Warden translates to each provider's native auth on the fly. One identity plane, regardless of how many providers sit behind it.

```
                                     ┌─── AWS (SigV4)
                                     │
                                     ├─── Azure (Bearer + Entra ID)
                                     │
  Workload ── JWT / cert ──▶ Warden ─┼─── GitHub (Installation token)
                                     │
                                     ├─── Mistral (Bearer + API key)
                                     │
                                     └─── OpenAI (Bearer + API key)
```

## Use Cases

### Terraform / Infrastructure as Code

No more AWS credentials on the machine running `terraform apply`. Terraform points at Warden, authenticates with a JWT or TLS cer, and Warden signs requests with just-in-time credentials scoped to the pipeline's identity. Full audit trail of every API call Terraform makes.

### CI/CD Pipelines

Pipelines store credentials as CI secrets — each one a potential leak, each one painful to rotate. With Warden, pipelines authenticate with their workload identity (Kubernetes SA, OIDC token) and access cloud and SaaS APIs through the gateway. No secrets to distribute, no credentials to rotate.

### Kubernetes & Service Mesh

Pods authenticate to Warden using their SPIFFE identity — either an X.509-SVID via certificate auth or a JWT-SVID via JWT auth. No sidecar agents, no mounted secrets, no token distributors. Warden validates the SVID, extracts the SPIFFE ID, and grants scoped access to upstream APIs. A pod in the `payment` namespace can reach the payment secrets in Vault, and nothing else.

### AI Agents — Inference Governance

AI agents call AI providers autonomously — choosing models, setting token limits, running completions. Without Warden, an API key grants unlimited access to every model. With Warden, each agent identity has scoped model access, enforced token limits, and every inference call is audited with full request parameters.

```bash
# Agent can only use mistral-small-latest, max_tokens capped, streaming required
curl -X POST https://warden.internal/v1/mistral/role/agent-role/gateway/v1/chat/completions \
  -H "Authorization: Bearer <jwt>" \
  -d '{"model": "mistral-small-latest", "messages": [...], "stream": true}'
```

### AI Agents — Tool Use Governance

When agents call cloud APIs — reading GitHub repos, writing to S3, deploying to Azure — Warden governs every tool action. Full audit trail of every file read, every PR created, every cloud resource touched.

> *Marc Brooker, AWS Principal Engineer, [argues](https://brooker.co.za/blog/2026/01/12/agent-box.html) that agent safety requires a deterministic gateway outside the agent that enforces policy on every tool call. Warden is that gateway.*

### Multi-Provider Workloads

A workload that reads from GitHub, writes to S3, deploys to Azure, and calls Mistral for inference needs four different credential types, four different auth flows, four different rotation strategies. Without Warden, each integration is its own identity problem. With Warden, the workload gets one JWT and one endpoint pattern. It doesn't matter whether the target is AWS, GitHub, or Mistral — the auth flow is identical. Add a new provider and existing workloads gain access without changing a single line of code.

## Authentication Methods

Warden supports multiple methods for verifying caller identity.

| Method | Identity Source | Best For |
|--------|----------------|----------|
| **JWT** | Signed JWT token or SPIFFE JWT-SVID | CI/CD pipelines, AI agents, any workload with an OIDC/JWT issuer or SPIFFE runtime |
| **TLS Certificate** | X.509 client certificate or SPIFFE X.509-SVID | Developers, Kubernetes pods, service mesh workloads, VMs with machine certificates |

SPIFFE is supported in both methods — JWT-SVIDs via JWT auth and X.509-SVIDs via certificate auth. Both methods produce the same internal session. Once authenticated, the caller interacts with Warden identically regardless of how they proved their identity.

## Authentication Modes

Warden supports two modes for how callers interact with the gateway. The availability of each mode depends on the provider.

### Transparent Mode

The caller sends a request with a JWT in the `Authorization` header (or authenticates via TLS client certificate) and includes the target role in the URL. Warden authenticates the caller, mints an IP-bound session on the first request, and injects provider credentials — all in a single round trip. The session persists until JWT expiry and is bound to the caller's IP (requests from a different IP are denied, not re-authenticated).

```bash
# Single request — caller authenticates and reaches GitHub in one round trip
curl -H "Authorization: Bearer <your-jwt>" \
  https://warden.internal/github/role/my-role/gateway/repos/acme/frontend/contents/README.md

# What happens behind the scenes:
#   1. Warden verifies the caller's identity and checks policies for role "my-role"
#   2. Mints a short-lived GitHub token scoped to that role
#   3. Forwards the request to https://api.github.com/repos/acme/frontend/contents/README.md
```

Transparent mode works with any provider that uses bearer tokens: **Azure, GCP, GitHub, GitLab, Vault, Mistral, OpenAI**. It's the simplest integration path — no code changes, no token exchange, one HTTP call.

### Explicit Mode

The caller first authenticates to Warden and receives an IP-bound session token pair, then uses it for subsequent API calls. The token pair mimics AWS credential format so standard AWS tools work out of the box, but the keys are only valid through Warden's gateway, bound to the caller's IP, and expire with the JWT. This two-step flow is required for providers where Warden needs to sign the request itself rather than inject a bearer token.

```bash
# Step 1: Authenticate and get an IP-bound session token pair from Warden
CREDS=$(curl -s -X POST \
  -H "Content-Type: application/json" \
  -d '{"jwt": "<your-jwt>", "role": "my-role"}' \
  https://warden.internal/v1/auth/jwt/login)

export AWS_ACCESS_KEY_ID=$(echo "$CREDS" | jq -r '.data.data.access_key_id')
export AWS_SECRET_ACCESS_KEY=$(echo "$CREDS" | jq -r '.data.data.secret_access_key')

# Step 2: Point AWS tools at Warden — Warden verifies the session and re-signs with real credentials
export AWS_ENDPOINT_URL=https://warden.internal/v1/aws/gateway
aws s3 ls s3://my-bucket
```

Explicit mode is **required for AWS** (SigV4 request signing means Warden must hold credentials and sign the entire request). It's also available as an option for all other providers.

| Provider | Transparent | Explicit |
|----------|:-----------:|:--------:|
| **AWS** | — | ✅ |
| **Azure** | ✅ | ✅ |
| **GCP** | ✅ | ✅ |
| **GitHub** | ✅ | ✅ |
| **GitLab** | ✅ | ✅ |
| **Vault / OpenBao** | ✅ | ✅ |
| **Mistral** | ✅ | ✅ |
| **OpenAI** | ✅ | ✅ |

## How It Compares

|  | **Warden** | **Portkey** | **Aembit** |
|---|---|---|---|
| Credential isolation | Credentials never leave Warden | Virtual keys stored in Portkey vault | Credentials pass through edge component |
| Audit granularity | Every API request logged | Logs + cost analytics (Enterprise) | Access grant logged |
| Policy enforcement | HTTP path + method + runtime conditions (IP, time, day) + AI parameters | Guardrails (PII, jailbreak) | Workload-to-service level |
| Cloud provider support | AWS, Azure, GCP, GitHub, GitLab, Vault | N/A — AI providers only | Per-provider integration |
| AI inference governance | Model, token, and parameter policies | Guardrails + rate limiting | N/A |
| Client modification | Change base URL | Portkey SDK or Universal API | Deploy sidecar agents |
| Data residency | Fully self-hosted, your infrastructure | SaaS or airgapped (Enterprise) | SaaS only |
| Deployment | Single self-hosted gateway | SaaS, hybrid, or airgapped | SaaS + edge agents |
| Open source | Yes (MPL-2.0) | Gateway only (MIT) | No |
| Credential rotation | Two-stage async (prepare → activate) | N/A — virtual keys only | Automated via SaaS |
| Streaming support | Full HTTP streaming (SSE, chunked) | Yes | N/A |
| High availability | Active/standby with automatic failover | SaaS-managed | SaaS-managed |
| Identity model | JWT, TLS certificate, or SPIFFE SVID for all providers | RBAC + SSO (Enterprise) | Per-provider identity mapping |

## Architecture

Warden is a reverse proxy written in Go. Each provider is registered as a streaming backend with its own credential source driver, authentication flow, and policy rules.

**Key design decisions:**

- **Inline proxy over credential vending** — Vault hands credentials to the caller. Warden sits in the request path, injecting credentials on the fly. This costs latency and infrastructure, but is what makes per-request audit and per-request policy enforcement possible.
- **IP-bound sessions** — Sessions are tied to the caller's IP. A stolen session token is useless from a different machine.
- **Two-stage credential rotation** — Rotation is split into PREPARE (mint new credentials while old ones remain valid) and ACTIVATE (commit new credentials, destroy old ones). For eventually-consistent providers like AWS and Azure, Warden defers activation by a configurable propagation delay, eliminating the polling loops that cloud SDKs typically require.
- **Seal/unseal model** — Like Vault, Warden protects secrets at rest using envelope encryption. Supports dev mode (in-memory) and production mode with multiple seal types (Shamir, Transit, AWS KMS, GCP KMS, Azure Key Vault, OCI KMS, PKCS11, KMIP) and PostgreSQL storage.
- **Active/standby HA** — Multiple Warden nodes share a storage backend and use lock-based leader election. One node is active; the rest are hot standbys that forward requests and automatically promote on leader failure. Sealed nodes are prevented from acquiring the leadership lock, eliminating cluster stalls.
- **Namespace isolation** — Every credential source, policy, and mount point is scoped to a namespace with hard boundaries. Policies cannot leak across namespaces.

## Getting Started

### Quick Start (Dev Mode)

Dev mode runs Warden entirely in-memory with automatic initialization and unsealing. No external dependencies — perfect for exploring and testing.

**1. Download the latest release:**

```bash
# macOS (Apple Silicon)
curl -L https://github.com/stephnangue/warden/releases/latest/download/warden_$(curl -s https://api.github.com/repos/stephnangue/warden/releases/latest | grep tag_name | cut -d '"' -f4 | tr -d v)_darwin_arm64.tar.gz | tar xz

# macOS (Intel)
curl -L https://github.com/stephnangue/warden/releases/latest/download/warden_$(curl -s https://api.github.com/repos/stephnangue/warden/releases/latest | grep tag_name | cut -d '"' -f4 | tr -d v)_darwin_amd64.tar.gz | tar xz

# Linux (x86_64)
curl -L https://github.com/stephnangue/warden/releases/latest/download/warden_$(curl -s https://api.github.com/repos/stephnangue/warden/releases/latest | grep tag_name | cut -d '"' -f4 | tr -d v)_linux_amd64.tar.gz | tar xz

# Linux (ARM64)
curl -L https://github.com/stephnangue/warden/releases/latest/download/warden_$(curl -s https://api.github.com/repos/stephnangue/warden/releases/latest | grep tag_name | cut -d '"' -f4 | tr -d v)_linux_arm64.tar.gz | tar xz
```

**2. Start the server:**

```bash
# Using the binary
./warden server --dev

# Or using Docker
docker run --rm -p 8400:8400 ghcr.io/stephnangue/warden:latest server --dev
```

**3. In another terminal, use the Warden client:**

```bash
export WARDEN_ADDR="http://127.0.0.1:8400"
export WARDEN_TOKEN="<root-token-from-output>"

./warden --help
```

Once Warden is running, follow a provider guide to configure your first endpoint:

**Cloud & SaaS Providers:**
- [AWS](provider/aws/README.md)
- [Azure](provider/azure/README.md)
- [GCP](provider/gcp/README.md)
- [GitHub](provider/github/README.md)
- [GitLab](provider/gitlab/README.md)
- [Vault / OpenBao](provider/vault/README.md)

**AI Providers:**
- [Mistral](provider/mistral/README.md)
- [OpenAI](provider/openai/README.md)

> **Warning**: Dev mode stores all data in-memory. Everything is lost on restart. Do not use in production.

### Production Setup

Production mode requires a configuration file and external dependencies (PostgreSQL for storage, and a seal that suits your need).

```bash
./warden server --config=./warden.hcl
```

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

## Roadmap

**Cloud & SaaS Providers** — Enterprise cloud (Oracle, IBM, Alibaba), specialized cloud (DigitalOcean, Hetzner, OVH), government cloud (GovCloud, Azure Gov), AI/GPU cloud (CoreWeave, Lambda, RunPod), DevOps SaaS (Terraform Cloud, Datadog, Cloudflare), data SaaS (Snowflake, Databricks, MongoDB Atlas), productivity SaaS (Slack, Jira, Notion)

**AI Providers** — Anthropic, Cohere, Google AI (Gemini), xAI, Replicate, Hugging Face, Together AI

**AI Governance** — Per-model cost budgets, token usage tracking, prompt/response audit, rate limiting per agent per model

**Auth** — Kubernetes, cloud machine identities (AWS IAM, Azure MI, GCP SA), OIDC, LDAP, SAML

**Observability** — Structured audit log export (OpenTelemetry, SIEM), new audit device types, Prometheus metrics, distributed tracing

**Security** — Rate limiting per identity, mTLS to upstream providers, audit log tamper detection, additional policy conditions (max request rate, required headers)

**Operations** — Helm chart, Docker Compose quick start, Terraform module

**Developer experience** — Web UI, Swagger/OpenAPI spec, MCP server for AI agent frameworks, SDKs (Go, Python, TypeScript)

## Contributing

We welcome contributions! See the [contributing guide](CONTRIBUTING.md) for setup instructions, build commands, testing conventions, and submission guidelines.

**Quick reference:**

```bash
make deps-up          # Start development dependencies
make brd-fast         # Build and run (skip tests)
make dev-watch        # Hot reload for development
make test-unit        # Run unit tests with race detection
make test-e2e         # Run e2e tests (3-node HA cluster)
```

## License

[MPL-2.0](LICENSE)
