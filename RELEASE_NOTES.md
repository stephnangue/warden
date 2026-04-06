## Warden v0.9.1

Warden is an identity-based access layer for cloud APIs, SaaS platforms, databases, and AI providers. It eliminates static credentials from your workloads entirely. Your workload authenticates to Warden with its own identity — a JWT from your identity provider or a TLS certificate. Warden verifies who is calling, evaluates fine-grained capability-based policies, and issues ephemeral request-scoped access: forwarding API requests with short-lived credentials injected, returning database auth tokens, or vending pre-signed URLs. Credentials are minted on demand, scoped to the request, and never exposed to the caller. Every API call is logged with caller identity, target service, and full request context. No secrets ever reach your applications.

### What's New

**`--type` flag is now truly optional on `cred spec create`.** The CLI previously enforced `--type` as required, even though the server has been able to infer the credential type from the source driver since v0.7.0. The flag is now optional — when omitted, the type is inferred automatically.

**AWS provider: Vault/OpenBao credential source.** The AWS provider README now documents how to use `hvault` as a credential source with `static_aws` (static credentials from KV v2) and `dynamic_aws` (temporary credentials from the Vault AWS secrets engine) mint methods.

**Quickstart path fix.** All provider READMEs now reference the correct docker-compose quickstart file path.

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
