## Warden v0.7.0

Warden is an identity-based access layer for cloud APIs, SaaS platforms, databases, and AI providers. It eliminates static credentials from your workloads entirely. Your workload authenticates to Warden with its own identity — a JWT from your identity provider or a TLS certificate. Warden verifies who is calling, evaluates fine-grained capability-based policies, and issues ephemeral request-scoped access: forwarding API requests with short-lived credentials injected, returning database auth tokens, or vending pre-signed URLs. Credentials are minted on demand, scoped to the request, and never exposed to the caller. Every API call is logged with caller identity, target service, and full request context. No secrets ever reach your applications.

### What's New

**PagerDuty provider with dual credential modes.** The new PagerDuty provider proxies requests to the PagerDuty REST API v2 with automatic credential injection. Two credential modes are supported: static API tokens (for simple setups) and OAuth2 client credentials (for production deployments with auto-refreshing bearer tokens).

**Generic HTTP proxy framework.** All streaming providers now share a single `httpproxy.ProviderSpec`-based implementation. Adding a new provider requires ~30 lines of configuration instead of ~500 lines of boilerplate.

**Credential type inference.** The `--type` flag on `warden cred spec create` is now optional — the type is inferred from the source driver automatically.

### Providers

| Provider | Gateway | Credential Type |
|----------|:---:|---|
| AWS | Streaming (SigV4) | Access keys via STS or static |
| Azure | Streaming | OAuth2 tokens |
| GCP | Streaming | OAuth2 tokens |
| GitHub | Streaming | Installation tokens |
| GitLab | Streaming | Project/group tokens |
| Vault / OpenBao | Streaming | Dynamic Vault tokens |
| Anthropic | Streaming | API keys |
| OpenAI | Streaming | API keys |
| Mistral | Streaming | API keys |
| Slack | Streaming | API keys |
| **PagerDuty** *(new)* | **Streaming** | **API keys / OAuth2 bearer tokens** |
| RDS | Access | IAM auth tokens |

- **Streaming providers** proxy requests through Warden, injecting credentials in-flight.
- **Access providers** vend credentials directly (database auth tokens, pre-signed URLs).

### New Features

- **PagerDuty Provider** — Streaming gateway for PagerDuty REST API v2. Supports static API tokens (`pagerduty` source) and OAuth2 client credentials (`pagerduty_oauth2` source) with automatic token minting and refresh.
- **Slack Provider** — Streaming gateway for Slack Web API with policy evaluation on request fields (channel, text, user).
- **Generic OAuth2 Client Credentials Driver** — Reusable credential driver for any OAuth2 provider using the client credentials grant. PagerDuty is the first consumer; future OAuth2 providers can reuse it with config only.
- **OAuth Bearer Token Credential Type** — New `oauth_bearer_token` type for dynamically minted OAuth2 bearer tokens with TTL-based lifecycle.
- **HTTP Proxy Framework** — Shared `httpproxy.ProviderSpec` eliminates per-provider boilerplate across all streaming providers.
- **Credential Type Inference** — `--type` on `warden cred spec create` is now optional; inferred from the source driver.
- **`?role=` Query Parameter** — Non-gateway backends accept `?role=` as an alternative to `X-Warden-Role` header.

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
