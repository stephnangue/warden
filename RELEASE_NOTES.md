## Warden v0.10.0

Warden is an identity-based access layer for cloud APIs, SaaS platforms, databases, and AI providers. It eliminates static credentials from your workloads entirely. Your workload authenticates to Warden with its own identity — a JWT from your identity provider or a TLS certificate. Warden verifies who is calling, evaluates fine-grained capability-based policies, and issues ephemeral request-scoped access: forwarding API requests with short-lived credentials injected, returning database auth tokens, or vending pre-signed URLs. Credentials are minted on demand, scoped to the request, and never exposed to the caller. Every API call is logged with caller identity, target service, and full request context. No secrets ever reach your applications.

### What's New

**11 new providers.** This release adds support for OVH, Datadog, Cohere, Elastic, Dynatrace, Splunk, New Relic, Kubernetes, Terraform Enterprise (TFE), Cloudflare, and Ansible Tower — bringing Warden's provider count from 13 to 24. Each provider ships with a full quickstart guide, configuration reference, and policy examples.

**Kubernetes provider with automatic token rotation.** The Kubernetes provider mints short-lived ServiceAccount tokens via the TokenRequest API. Tokens are audience-scoped for multi-tenant security with configurable TTL (10m–48h, default 1h).

**Elastic provider with programmatic key rotation.** The Elastic provider supports a dedicated `elastic` credential driver that programmatically creates and rotates Elasticsearch API keys with configurable expiration and role descriptors for scoped permissions.

**IBM Cloud credential driver.** New `ibm` source type mints IAM bearer tokens from IBM Cloud API keys via the IAM token exchange endpoint. Supports automatic source API key rotation with a 2-minute default activation delay.

**Custom CA certificates and TLS skip verify everywhere.** All providers and credential drivers now support `ca_data` (inline PEM CA certificate) and `tls_skip_verify` config options via a shared TLS helper. Self-hosted instances with private CAs or development environments using HTTP are now supported out of the box. (#140)

**Extra OAuth2 token form parameters.** The OAuth2 credential driver now supports arbitrary additional form parameters via `token_param.*` config keys (e.g., `token_param.resource=urn:dtaccount:123`). This enables providers like Dynatrace that require non-standard OAuth2 form fields. (#131)

**Lazy transport initialization.** Transport creation has been refactored from eager package-level initialization to lazy initialization via a `sync.Once` factory pattern. Transports are only created when a provider is actually mounted, eliminating unnecessary startup overhead and background goroutines. (#138)

**httpproxy reliability fixes.** Resolved data races, an HTTP/2 regression caused by TLS finalization ordering, and validation gaps (`max_body_size=0` rejection, 100 MB cap). The Bearer token extractor is now case-insensitive per RFC 7235. (#143)

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
| OVH | Streaming | OAuth2 tokens (native or via Vault) |
| Datadog | Streaming | API keys (native or via Vault) |
| Cohere | Streaming | API keys (native or via Vault) |
| Elastic | Streaming | API keys (native, rotated, or via Vault) |
| Dynatrace | Streaming | API tokens / OAuth2 (native or via Vault) |
| Splunk | Streaming | Bearer tokens (native or via Vault) |
| New Relic | Streaming | API keys (native or via Vault) |
| Kubernetes | Streaming | ServiceAccount tokens (TokenRequest API) |
| TFE / HCP Terraform | Streaming | Bearer tokens (native or via Vault) |
| Cloudflare | Streaming | API tokens (native or via Vault) |
| Ansible Tower | Streaming | PAT / Bearer tokens (native or via Vault) |

- **Streaming providers** proxy requests through Warden, injecting credentials in-flight.
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
