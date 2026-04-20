## Warden v0.11.0

Warden is the open-source egress gateway for AI agents and MCP servers — every API call is authenticated, authorized, and audited, and no credentials ever reach the caller. Your agent or MCP server authenticates to Warden with its own identity (a JWT from your identity provider or a TLS certificate). Warden verifies who is calling, evaluates fine-grained capability-based policies, and issues ephemeral request-scoped access: forwarding API requests with short-lived credentials injected, returning database auth tokens, or vending pre-signed URLs. Credentials are minted on demand, scoped to the request, and never exposed to the caller. Every API call is logged with caller identity, target service, and full request context. No secrets ever reach your applications.

### What's New

**Agent role introspection.** Autonomous agents typically talk to many external systems, and each system requires its own role (roles bind to credential specs). Until now, agents needed those role names distributed out-of-band — which does not scale. This release introduces a self-describing API: an agent presents only its identity vehicle (JWT bearer or TLS client certificate) and gets back the roles it could assume, with human-readable descriptions to help pick the right role per task. Shipped in three layers: a new `description` field on JWT and cert roles (#162), a per-backend `GET /v1/auth/{mount}/introspect/roles` endpoint that reuses login-time constraint matchers (#163), and a system-backend aggregator at `GET /v1/sys/introspect/roles` that fans out to all matching mounts in the caller's namespace (#166).

**`dualgateway` framework for dual-mode providers.** A new shared framework for providers that auto-detect between REST API proxying and S3-compatible object storage (SigV4 verify/re-sign/forward) on a per-request basis. Providers supply a `ProviderSpec` describing auth strategy, S3 endpoint format, and credential type; the framework handles transport, token extraction, transparent auth, config CRUD, and the SigV4 lifecycle. (#148, #149)

**Seven new providers.** Scaleway (#148), Sentry (#153), Grafana (#155), Atlassian (#157), Prometheus (#158), Honeycomb (#159), and IBM Cloud (#161) — bringing Warden's provider count from 24 to 31. Scaleway, Atlassian, and IBM Cloud ship as dual-mode providers out of the gate. Grafana and Honeycomb include dedicated source drivers that programmatically provision and rotate service-account tokens.

**OVH upgraded to dual-mode with a new source driver.** The OVH provider (introduced in v0.10.0 as REST-only) now operates in dual-mode via `dualgateway`, and ships with a new OVH source driver that mints credentials via OAuth2. (#149, #151)

**Cloudflare upgraded to dual-mode with R2 S3 support.** The Cloudflare provider now proxies Cloudflare R2's S3-compatible API alongside the REST endpoints. (#150)

**Bug fixes.** Dynamic S3 credentials now have a TTL bounded by the authorizing OAuth2 token's lifetime, closing a credential-exposure window (#152). The Grafana source driver's leaseID now encodes `orgID` to prevent service-account collisions across tenants (#156).

### Providers

| Provider | Gateway | Credential Type |
|----------|:---:|---|
| AWS | Streaming (SigV4) | Access keys via STS or static |
| Azure | Streaming | OAuth2 tokens |
| GCP | Streaming | OAuth2 tokens (native or via Vault) |
| GitHub | Streaming | Installation tokens |
| GitLab | Streaming | Project/group tokens |
| Vault / OpenBao | Streaming | Dynamic Vault tokens |
| Anthropic | Streaming | API keys (native or via Vault) |
| OpenAI | Streaming | API keys (native or via Vault) |
| Mistral | Streaming | API keys (native or via Vault) |
| Slack | Streaming | API keys (native or via Vault) |
| PagerDuty | Streaming | API keys / OAuth2 (native or via Vault) |
| ServiceNow | Streaming | API keys / OAuth2 (native or via Vault) |
| RDS | Access | IAM auth tokens |
| OVH | Dual-mode (REST + S3) | OAuth2 tokens (native or via Vault) |
| Datadog | Streaming | API keys (native or via Vault) |
| Cohere | Streaming | API keys (native or via Vault) |
| Elastic | Streaming | API keys (native, rotated, or via Vault) |
| Dynatrace | Streaming | API tokens / OAuth2 (native or via Vault) |
| Splunk | Streaming | Bearer tokens (native or via Vault) |
| New Relic | Streaming | API keys (native or via Vault) |
| Kubernetes | Streaming | ServiceAccount tokens (TokenRequest API) |
| TFE / HCP Terraform | Streaming | Bearer tokens (native or via Vault) |
| Cloudflare | Dual-mode (REST + R2 S3) | API tokens (native or via Vault) |
| Ansible Tower | Streaming | PAT / Bearer tokens (native or via Vault) |
| Scaleway | Dual-mode (REST + S3) | API keys (native or via Vault) |
| Sentry | Streaming | Bearer tokens (native or via Vault) |
| Grafana | Streaming | Service-account tokens (native, rotated, or via Vault) |
| Atlassian | Dual-mode (Cloud + Data Center) | API tokens / PAT (native or via Vault) |
| Prometheus | Streaming | Bearer tokens (native or via Vault) |
| Honeycomb | Streaming | API keys (native, rotated, or via Vault) |
| IBM Cloud | Dual-mode (REST + S3) | IAM tokens via `ibm` driver or Vault |

- **Streaming providers** proxy requests through Warden, injecting credentials in-flight.
- **Dual-mode providers** auto-detect between REST API proxying and S3-compatible object storage on a per-request basis.
- **Access providers** vend credentials directly (database auth tokens, pre-signed URLs).

### Getting Started

You need two things: the **Warden binary** (from the assets below) and the **quick start compose file** (starts an identity provider with pre-configured OAuth2 clients).

```bash
# 1. Download the binary for your platform from the assets below and make it executable
chmod +x warden
export PATH="$PWD:$PATH"

# 2. Download the quick start compose file
curl -fsSL -o docker-compose.quickstart.yml \
  https://raw.githubusercontent.com/stephnangue/warden/main/docker-compose.quickstart.yml

# 3. Start the identity provider (Ory Hydra with pre-configured clients)
docker compose -f docker-compose.quickstart.yml up -d

# 4. Start Warden in dev mode
./warden server --dev
```

In a second terminal:

```bash
export PATH="$PWD:$PATH"
export WARDEN_ADDR="http://127.0.0.1:8400"
export WARDEN_TOKEN="root"
```

Follow any [provider README](https://github.com/stephnangue/warden#providers) to set up JWT auth, mount a provider, and make your first gateway request.

**Pre-configured OAuth2 clients:**

| Client ID | Secret | Use case |
|-----------|--------|----------|
| `my-agent` | `agent-secret` | AI agent or automation |
| `my-pipeline` | `pipeline-secret` | CI/CD pipeline |
| `my-admin` | `admin-secret` | Admin / operator |

To stop and clean up: `docker compose -f docker-compose.quickstart.yml down -v`

See the [README](https://github.com/stephnangue/warden#readme) for full documentation and provider guides.

### License

[MPL-2.0](https://github.com/stephnangue/warden/blob/main/LICENSE)
