# Warden

**Identity-aware egress gateway for Cloud and SaaS services.**

Your workloads need credentials. They shouldn't have them.

Warden eliminates credential exposure by sitting in the request path between your workloads and external APIs. It authenticates callers by their identity, injects short-lived credentials on the fly, enforces fine-grained policies, and logs every API call. Your applications, AI agents, and pipelines never touch a secret.

```
┌──────────────┐                  ┌──────────────┐                  ┌──────────────┐
│  Your app    │                  │              │                  │              │
│  AI agent    │──── JWT auth ───▶│    Warden    │──── Real creds ─▶│  Cloud/SaaS  │
│  Terraform   │   no credentials │              │   signed request │   Provider   │
│  CI/CD       │                  │              │                  │              │
└──────────────┘                  └──────────────┘                  └──────────────┘
                                   • Auth ✓
                                   • Policy ✓
                                   • Audit ✓
```

## Supported Providers

| Provider | Status | Credential Source |
|----------|--------|-------------------|
| **AWS** | ✅ GA | Direct from AWS STS or via Vault AWS secrets engine |
| **Azure** | ✅ GA | Service principal credentials |
| **GCP** | ✅ GA | Service account credentials |
| **GitHub** | ✅ GA | PATs, GitHub App tokens |
| **GitLab** | ✅ GA | PATs, Deploy tokens |
| **Vault / OpenBao** | ✅ GA | Token-based |

The roadmap targets 100+ cloud and SaaS providers.

## Authentication Modes

Warden supports two modes for how callers interact with the gateway. The availability of each mode depends on the provider.

### Transparent Mode

The caller sends a request with a JWT in the `Authorization` header and includes the target role in the URL. Warden authenticates the caller, mints an IP-bound session on the first request, and injects provider credentials — all in a single round trip. The session persists until JWT expiry and is bound to the caller's IP (requests from a different IP are denied, not re-authenticated).

```bash
# Single request — caller authenticates and reaches GitHub in one round trip
curl -H "Authorization: Bearer <your-jwt>" \
  https://warden.internal/github/role/my-role/gateway/repos/acme/frontend/contents/README.md

# What happens behind the scenes:
#   1. Warden verifies the JWT and checks policies for role "my-role"
#   2. Mints a short-lived GitHub token scoped to that role
#   3. Forwards the request to https://api.github.com/repos/acme/frontend/contents/README.md
```

Transparent mode works with any provider that uses bearer tokens: **Azure, GCP, GitHub, GitLab, Vault**. It's the simplest integration path — no code changes, no token exchange, one HTTP call.

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

## Why Warden?

### Zero Credential Exposure

Workloads never see or store credentials. Warden intercepts requests, injects short-lived credentials on the fly, and forwards them to providers. No secrets in environment variables, no keys in config files, no credential leaks.

### Request-Level Audit Trail

Warden doesn't just log who received credentials — it logs what they did with them. Every API call is recorded with the caller's identity, the target service, the HTTP method and path, and a timestamp.

```
# What Vault logs:          "agent-X was granted AWS credentials at 14:32"
# What Warden logs:         "agent-X called GET /repos/acme/frontend/contents/src/auth.ts at 14:32:07"
#                           "agent-X called POST /repos/acme/frontend/pulls/42/reviews at 14:32:09"
```

### Fine-Grained Policy Enforcement

Warden constrains what a workload can do by controlling which APIs it can reach and which operations it can perform — at the HTTP path and method level. This is a layer of granularity that providers don't natively offer.

A GitHub fine-grained PAT with `contents: read` lets the holder read *every file* in a repo. Warden can restrict an agent to `src/` while blocking `.github/workflows/` and `.env` — something GitHub simply cannot express. A GitLab `read_repository` token can clone, list branches, and compare commits. Warden can limit it to file reads only. For AWS, Warden adds defense-in-depth: destructive operations can be blocked at the gateway regardless of what the underlying IAM role permits.

### Zero Client Modification

Point your SDK, CLI, or tool at Warden's endpoint instead of the provider's. No code changes, no special libraries, no proxy configuration. If your tool supports a custom endpoint URL, it works with Warden.

### Identity-Based Access

Every request is tied to a verified identity via JWT. Whether it's a CI/CD pipeline, an AI agent, a Terraform run, or a Kubernetes pod, Warden knows exactly who is making each API call and applies policies accordingly.

### Unified Identity Across Providers

Every cloud and SaaS provider has its own identity system — AWS IAM, Azure Entra ID, GCP IAM, GitHub Apps, GitLab tokens. Multi-cloud means multi-identity: different auth flows, different credential formats, different rotation strategies per provider. Warden collapses all of that into a single JWT. Your workloads authenticate once, with one identity, and Warden translates to each provider's native auth on the fly. One identity plane, regardless of how many providers sit behind it.

```
                                  ┌─── AWS (SigV4)
                                  │
  Workload ── JWT ──▶  Warden  ───┼─── Azure (Bearer + Entra ID)
                                  │
                                  ├─── GCP (Bearer + SA key)
                                  │
                                  └─── GitHub (Installation token)
```

## Use Cases

### AI Agents

AI agents are autonomous, use broad permissions, and operate opaquely. Without Warden, you give agents long-lived credentials and hope for the best. With Warden, agents authenticate with a scoped JWT and you get a full audit trail of every API call — every file read, every PR created, every cloud resource touched.

> *Marc Brooker, AWS Principal Engineer, [argues](https://brooker.co.za/blog/2026/01/12/agent-box.html) that agent safety requires a deterministic gateway outside the agent that enforces policy on every tool call. Warden is that gateway.*

### Terraform / Infrastructure as Code

No more AWS credentials on the machine running `terraform apply`. Terraform points at Warden, authenticates with a JWT, and Warden signs requests with just-in-time credentials scoped to the pipeline's identity. Full audit trail of every API call Terraform makes.

### CI/CD Pipelines

Pipelines store credentials as CI secrets — each one a potential leak, each one painful to rotate. With Warden, pipelines authenticate with their workload identity (Kubernetes SA, OIDC token) and access cloud and SaaS APIs through the gateway. No secrets to distribute, no credentials to rotate.

### Multi-Cloud / Multi-Provider

An AI agent that reads from GitHub, writes to S3, and deploys to Azure needs three different credential types, three different auth flows, three different rotation strategies. Without Warden, each integration is its own identity problem. With Warden, the agent gets one JWT and one endpoint pattern. It doesn't matter whether the target is AWS, Azure, or GitHub — the auth flow is identical. Add a new provider and existing workloads gain access without changing a single line of code. The identity complexity is Warden's problem, not the application's.

## How It Compares

|  | **Warden** | **Vault** | **Aembit** | **IAM Roles** |
|---|---|---|---|---|
| Credential isolation | Credentials never leave Warden | App receives and holds credentials | Credentials pass through edge component | App assumes role directly |
| Audit granularity | Every API request logged | Credential issuance logged | Access grant logged | CloudTrail only |
| Policy enforcement | HTTP path + method level | Credential scope level | Workload-to-service level | IAM policy level |
| Client modification | Change base URL | Integrate SDK / API call | Deploy sidecar agents | Per-cloud configuration |
| Deployment | Single gateway | Server cluster | SaaS + edge agents | Per-cloud setup |
| Open source | Yes (MPL-2.0) | Yes (BSL) | No | N/A |
| Multi-provider | 6 today, 100+ planned | Per-engine configuration | Per-provider integration | Single cloud only |
| Identity model | Single JWT for all providers | Per-engine auth config | Per-provider identity mapping | Per-cloud IAM |

Warden complements Vault — Vault manages credential lifecycle, Warden adds runtime visibility and policy enforcement. Warden can use Vault as a credential source for AWS.

## Architecture

Warden is a reverse proxy written in Go. Each provider is registered as a streaming backend with its own credential source driver, authentication flow, and policy rules.

**Key design decisions:**

- **Inline proxy over credential vending** — Vault hands credentials to the caller. Warden sits in the request path, injecting credentials on the fly. This costs latency and infrastructure, but is what makes per-request audit and per-request policy enforcement possible.
- **IP-bound sessions** — Sessions are tied to the caller's IP. A stolen session token is useless from a different machine.
- **Two-stage credential rotation** — Rotation is split into PREPARE (mint new credentials while old ones remain valid) and ACTIVATE (commit new credentials, destroy old ones). For eventually-consistent providers like AWS and Azure, Warden defers activation by a configurable propagation delay, eliminating the polling loops that cloud SDKs typically require.
- **Seal/unseal model** — Like Vault, Warden protects secrets at rest using envelope encryption. Supports dev mode (in-memory) and production mode with multiple seal types (Shamir, Transit, AWS KMS, GCP KMS, Azure Key Vault, OCI KMS, PKCS11, KMIP) and PostgreSQL storage.
- **Namespace isolation** — Every credential source, policy, and mount point is scoped to a namespace with hard boundaries. Policies cannot leak across namespaces.

## Getting Started

### Prerequisites

- Go 1.25.1 or later
- Make

### Quick Start (Dev Mode)

Dev mode runs Warden entirely in-memory with automatic initialization and unsealing. No external dependencies — perfect for exploring and testing.

```bash
# Clone and build
git clone https://github.com/stephnangue/warden.git
cd warden
go build -o warden ./cmd

# Start Warden in dev mode
./warden server --dev

# In another terminal
export WARDEN_ADDR="http://127.0.0.1:8400"
export WARDEN_TOKEN="<root-token-from-output>"

# Explore
./warden --help
```

Once Warden is running, follow a provider guide to configure your first endpoint:

- [AWS](provider/aws/README.md)
- [Azure](provider/azure/README.md)
- [GCP](provider/gcp/README.md)
- [GitHub](provider/github/README.md)
- [GitLab](provider/gitlab/README.md)
- [Vault / OpenBao](provider/vault/README.md)

> **Warning**: Dev mode stores all data in-memory. Everything is lost on restart. Do not use in production.

### Production Setup

Production mode requires a configuration file and external dependencies (PostgreSQL for storage, and a seal that suits your need).

```bash
# Start dependencies (OpenBao, PostgreSQL)
make deps-up

# Build and run
make brd
```

Or manually:

```bash
go build -o warden ./cmd
./warden server --config=./warden.local.hcl
```

### Configuration

Warden uses HCL configuration files. See `warden.local.hcl` for a full example covering storage backend, listener, providers, and auth methods.

## Roadmap

**Auth** — Kubernetes, SPIFFE, TLS certificates, cloud machine identities (AWS IAM, Azure MI, GCP SA), OIDC, LDAP, SAML

**Providers** — Enterprise cloud (Oracle, IBM, Alibaba), specialized cloud (DigitalOcean, Hetzner, OVH), government cloud (GovCloud, Azure Gov), AI/GPU cloud (CoreWeave, Lambda, RunPod), DevOps SaaS (Terraform Cloud, Datadog, Cloudflare), data SaaS (Snowflake, Databricks, MongoDB Atlas), AI SaaS (OpenAI, Anthropic, Cohere), productivity SaaS (Slack, Jira, Notion)

**Observability** — Structured audit log export (OpenTelemetry, SIEM), new audit device types, Prometheus metrics, distributed tracing

**Security** — Rate limiting per identity, mTLS to upstream providers, audit log tamper detection

**Operations** — Active/standby HA, Helm chart, Docker Compose quick start, Terraform module

**Developer experience** — Web UI, Swagger/OpenAPI spec, MCP server for AI agent frameworks, SDKs (Go, Python, TypeScript)

## Contributing

We welcome contributions! See the [contributing guide](CONTRIBUTING.md) for setup instructions, build commands, testing conventions, and submission guidelines.

**Quick reference:**

```bash
make deps-up          # Start development dependencies
make brd-fast         # Build and run (skip tests)
make dev-watch        # Hot reload for development
make test-unit        # Run unit tests with race detection
```

## License

[MPL-2.0](LICENSE)