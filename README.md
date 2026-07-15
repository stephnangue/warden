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

Agents discover what they're allowed to access. Warden brokers every connection. Operators get one control plane for identity, policy, and audit — across every MCP server, cloud, code-host, observability stack, database, and SaaS the agent reaches.

---

## The problem

Agents are useful only when they reach real systems: cloud accounts, code repositories, observability stacks, databases, ITSM, secrets backends. Today, pointing an agent at production means handing it over-scoped, long-lived credentials, with no per-request policy and no identity-tied audit. Each new system is another credential in the agent's environment, governed by nothing in the request path.

The control gap, not the credential, is the headline. MCP servers make it acute — every server wraps one upstream API and holds one credential in process env, so an agent with a dozen tools has a dozen static secrets scattered across a dozen processes, none of them rotating, none of them governed.

## How Warden works

Warden sits in the request path between an agent and the systems it needs. The agent presents its own identity — a JWT, TLS client certificate, SPIFFE SVID, or Kubernetes service-account token — and points at Warden as if it were the upstream.

```
┌──────────────┐                      ┌──────────────┐                      ┌──────────────┐
│              │    identity only     │              │   real credentials   │ MCP servers  │
│   AI Agent   │ ───────────────────▶ │    Warden    │ ───────────────────▶ │ Cloud · LLMs │
│              │ ◀─────────────────── │              │ ◀─────────────────── │ Code · SaaS  │
│              │       response       │              │       response       │ ...          │
└──────────────┘                      └──────────────┘                      └──────────────┘
                                      • Identity ✓
                                      • Policy ✓
                                      • Audit ✓
```

For each request, Warden authenticates the identity, evaluates the call against policy at request time, injects the real upstream credential, and proxies it — streaming the response back unchanged. The credential belongs to Warden, never the agent, and is short-lived wherever the upstream supports it. The agent holds no secrets, gets exactly the access its policy permits — no more — and every call is tied to its identity in the audit log.

Agents don't need that access wired in ahead of time. They can ask Warden which roles and systems are open to them and read a per-system recipe at runtime, then connect — so a newly mounted system is reachable without redistributing config or rebuilding an SDK. See [the agent flow](https://wardengateway.com/agent-flow/) for the full loop.

## Use cases

- **Access brokering** — Warden holds the upstream secret and injects a scoped, short-lived credential into each request; the agent presents only its own identity — a JWT, a TLS client certificate, or a SPIFFE SVID — and never holds a key. The same identity reaches every upstream the policy permits, so there's no per-system credential sprawl, nothing to rotate per integration, and nothing in the agent to leak.
- **Breach containment** — a prompt-injected, jailbroken, or otherwise compromised agent has nothing to exfiltrate, because it never holds a credential. Every call it issues is still bounded by policy at request time and backed by short-lived access, so one bad step — or one hallucination — stays a contained, recoverable event instead of a broad compromise.
- **Runtime authorization** — every call is authorized the moment it happens, down to the action and its arguments, evaluated against caller IP, time of day, day of week, and on whose behalf the agent is acting — the verified attributes its identity carries, so a shared agent still admits one principal and refuses another. For MCP traffic the policy reaches inside each tool call — which tools an agent may invoke and which arguments it may pass — so the agent gets the narrowest fit for each step, not a session-wide grant.
- **Centralized governance** — one control plane for every system an agent touches: one identity, one policy surface, and one audit log across clouds, code hosts, observability, databases, SaaS, and MCP servers. Namespaces isolate teams on shared infrastructure, and Warden rotates the upstream secrets it holds on a schedule, so they stay fresh without operator coordination.
- **Audit & attribution** — every request tied to the real identity behind it, the role used, the policy decision, and the upstream called — including the decision recorded on each MCP tool call. A shared MCP server acting for many agents still resolves to the specific agent it acted for, and secrets are never written to the log in the clear.

See [the use-case guides](https://wardengateway.com/use-cases/) for the full write-ups.

## Supported systems

Warden fronts systems across MCP servers, LLMs, cloud, code-hosting, observability, ITSM, Kubernetes, secrets, and databases. Follow any link below to configure your first endpoint, or see [docs/provider-backends/README.md](https://wardengateway.com/provider-backends/) for the full list.

| Category | Providers | Warden does |
|---|---|---|
| MCP servers | [Generic](https://wardengateway.com/provider-backends/mcp/) — GitHub, Google Cloud, Slack, Cloudflare, …; [AWS](https://wardengateway.com/provider-backends/mcp_aws/) (SigV4) | Proxies tool calls — injects credentials, enforces tool-level policy |
| LLM APIs | [Anthropic](https://wardengateway.com/provider-backends/anthropic/), [OpenAI](https://wardengateway.com/provider-backends/openai/), [Mistral](https://wardengateway.com/provider-backends/mistral/), [Cohere](https://wardengateway.com/provider-backends/cohere/) | Injects API key |
| Cloud infrastructure | [AWS](https://wardengateway.com/provider-backends/aws/), [Azure](https://wardengateway.com/provider-backends/azure/), [GCP](https://wardengateway.com/provider-backends/gcp/), [Alicloud](https://wardengateway.com/provider-backends/alicloud/), [IBM Cloud](https://wardengateway.com/provider-backends/ibmcloud/), [OVH](https://wardengateway.com/provider-backends/ovh/), [Scaleway](https://wardengateway.com/provider-backends/scaleway/), [Cloudflare](https://wardengateway.com/provider-backends/cloudflare/) | Temporary credentials / Bearer tokens |
| Code hosting & CI/CD | [GitHub](https://wardengateway.com/provider-backends/github/), [GitLab](https://wardengateway.com/provider-backends/gitlab/), [Atlassian](https://wardengateway.com/provider-backends/atlassian/), [Ansible Tower](https://wardengateway.com/provider-backends/ansible_tower/), [Terraform Enterprise](https://wardengateway.com/provider-backends/tfe/) | Injects App token, PAT, or Bearer token |
| Observability | [Datadog](https://wardengateway.com/provider-backends/datadog/), [Dynatrace](https://wardengateway.com/provider-backends/dynatrace/), [Elastic](https://wardengateway.com/provider-backends/elastic/), [Grafana](https://wardengateway.com/provider-backends/grafana/), [Honeycomb](https://wardengateway.com/provider-backends/honeycomb/), [New Relic](https://wardengateway.com/provider-backends/newrelic/), [Prometheus](https://wardengateway.com/provider-backends/prometheus/), [Sentry](https://wardengateway.com/provider-backends/sentry/), [Splunk](https://wardengateway.com/provider-backends/splunk/) | Injects API key / proxies metrics |
| Incident & ITSM | [PagerDuty](https://wardengateway.com/provider-backends/pagerduty/), [ServiceNow](https://wardengateway.com/provider-backends/servicenow/), [Slack](https://wardengateway.com/provider-backends/slack/) | Injects Bearer token |
| Kubernetes | [Kubernetes](https://wardengateway.com/provider-backends/kubernetes/) | Injects service account token |
| Secrets backend | [HashiCorp Vault / OpenBao](https://wardengateway.com/provider-backends/vault/) | Mints short-lived tokens |
| Databases | [AWS RDS / Aurora](https://wardengateway.com/provider-backends/rds/), [AWS Redshift](https://wardengateway.com/provider-backends/redshift/) | Issues IAM database auth token |

## Authentication methods

Warden supports multiple methods for verifying caller identity.

| Method | Identity Source | How the agent presents the credential to its SDK |
|--------|----------------|----|
| **JWT** | Signed JWT token | The **same JWT** goes in whichever credential slot the upstream SDK natively expects (`AWS_SECRET_ACCESS_KEY`, `OPENAI_API_KEY`, `X-Vault-Token`, `Authorization: Bearer`, …). Warden detects it, validates the identity, and swaps in the real upstream credential. Existing SDK code keeps working — only the base URL changes. |
| **TLS Certificate** | X.509 client certificate | Identity is proven at the TLS handshake (or forwarded by a TLS-terminating proxy via `X-SSL-Client-Cert`). The SDK's credential slot is filled with any placeholder value — Warden ignores it once cert auth has proven the identity. Role selection follows the same per-provider conventions as JWT mode. |
| **SPIFFE** | SPIFFE X.509-SVID or JWT-SVID | First-class SPIFFE identity on a single mount: a workload presents an X.509-SVID at the TLS handshake (or forwarded by a TLS-terminating proxy) or a JWT-SVID as a bearer token, and Warden verifies it against the trust domain's bundle — with federation across trust domains and periodic refresh. It relies on short-lived SVIDs and bundle rotation rather than revocation lists, so it suits workloads already issued identities by a SPIFFE provider such as SPIRE. |
| **Kubernetes** | Kubernetes ServiceAccount token (projected SA JWT) | The pod's ServiceAccount token goes in the SDK's credential slot exactly as in JWT mode. Warden validates it by calling the issuing cluster's TokenReview API — no JWKS endpoint or public keys to distribute — and matches a role bound to the ServiceAccount's namespace and name. |

## Tutorials

**Securing agents on the workstation — from one secret on disk to
zero.** A three-part, hands-on series that takes a local coding
agent (Claude Code) and removes every credential from the laptop,
one rung at a time, without changing how the agent works:

- **Certificate → LLM** — the agent's model calls flow through
  Warden under an mTLS client-certificate identity; the LLM API key
  never touches the workstation.
- **Certificate → LLM + MCP** — a hosted MCP server (GitHub) joins
  the same identity, and its token lives only in Warden too.
- **SPIFFE → LLM + MCP** — the identity becomes a keyless,
  auto-rotating SPIFFE SVID, so even the private key leaves the
  disk. Zero long-lived credentials remain on the machine.

Every rung makes the same three wins concrete — and demonstrates
them, not just asserts them: the secret leaves the workstation, and
each rung turns on the audit log and watches a request get denied by
policy. See [the series](https://wardengateway.com/quickstarts/workstation/).

## Architecture

See [docs/architecture.md](https://wardengateway.com/architecture/) for Warden's design decisions, high availability model, and deployment configuration.

## Kubernetes

A first-party Helm chart deploys Warden as a 3-replica HA cluster on any Kubernetes 1.27+ cluster — bring your own Postgres, your own TLS certificate, and either a Vault Transit endpoint for auto-unseal or a static seal key for development. The chart ships production-leaning defaults; a quickstart values file shrinks the install to a single replica for kind or minikube.

See [docs/install/kubernetes.md](https://wardengateway.com/install/kubernetes/) for the full guide.

## Contributing

We welcome contributions! See the [contributing guide](CONTRIBUTING.md) for setup instructions, build commands, testing conventions, and submission guidelines.

## License

[MPL-2.0](LICENSE)
