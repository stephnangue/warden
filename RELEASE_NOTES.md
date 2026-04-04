## Warden v0.8.0

Warden is an identity-based access layer for cloud APIs, SaaS platforms, databases, and AI providers. It eliminates static credentials from your workloads entirely. Your workload authenticates to Warden with its own identity — a JWT from your identity provider or a TLS certificate. Warden verifies who is calling, evaluates fine-grained capability-based policies, and issues ephemeral request-scoped access: forwarding API requests with short-lived credentials injected, returning database auth tokens, or vending pre-signed URLs. Credentials are minted on demand, scoped to the request, and never exposed to the caller. Every API call is logged with caller identity, target service, and full request context. No secrets ever reach your applications.

### What's New

**Generic credential source drivers.** The `apikey` and `oauth2` driver types replace all per-provider credential source types. Adding a new API key or OAuth2 provider no longer requires code changes — configure everything at source creation time.

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
| PagerDuty | Streaming | API keys / OAuth2 bearer tokens |
| RDS | Access | IAM auth tokens |

- **Streaming providers** proxy requests through Warden, injecting credentials in-flight.
- **Access providers** vend credentials directly (database auth tokens, pre-signed URLs).

### Breaking Changes

- **`apikey` replaces per-provider source types** — The source types `anthropic`, `openai`, `mistral`, `slack`, and `pagerduty` have been replaced by a single `apikey` type. Existing sources must be recreated with `--type=apikey` and explicit config fields (`api_url`, `verify_endpoint`, `auth_header_type`, etc.).

- **`oauth2` replaces `pagerduty_oauth2`** — The `pagerduty_oauth2` source type has been replaced by a generic `oauth2` type. Existing OAuth2 sources must be recreated with `--type=oauth2` and explicit `token_url`.

### New Features

- **Generic API Key Driver (`apikey`)** — Single config-driven driver replaces five per-provider API key drivers. Supports configurable auth header injection (`bearer`, `token`, `custom_header`), extra static headers (e.g., `anthropic-version:2023-06-01`), optional metadata field forwarding, and configurable verification endpoints.

- **Generic OAuth2 Driver (`oauth2`)** — Single config-driven driver for any OAuth2 client credentials provider. All provider-specific config (token URL, verification endpoint, auth header type, scopes) is set at source creation time.

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
