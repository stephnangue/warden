## Warden v0.6.0

Warden is an identity-based access layer for cloud APIs, SaaS platforms, databases, and AI providers. It eliminates static credentials from your workloads entirely. Your workload authenticates to Warden with its own identity — a JWT from your identity provider or a TLS certificate. Warden verifies who is calling, evaluates fine-grained capability-based policies, and issues ephemeral request-scoped access: forwarding API requests with short-lived credentials injected, returning database auth tokens, or vending pre-signed URLs. Credentials are minted on demand, scoped to the request, and never exposed to the caller. Every API call is logged with caller identity, target service, and full request context. No secrets ever reach your applications.

### What's New

**Transparent mode is the only mode.** There is no longer a separate "explicit login" flow. Clients pass their JWT or certificate directly to the gateway endpoint — Warden handles authentication implicitly on every request.

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
| **RDS** *(new)* | **Access** | **IAM auth tokens** |

- **Streaming providers** proxy requests through Warden, injecting credentials in-flight.
- **Access providers** vend credentials directly (database auth tokens, pre-signed URLs).

### Breaking Changes

- **`token_type` removed** — The `token_type` field on auth method configs and roles no longer exists. All roles use the transparent type (`jwt_role` or `cert_role`) automatically.
- **Explicit login blocked** — `/auth/jwt/login` and `/auth/cert/login` return `400`. Use the gateway endpoint directly.
- **`transparent_mode` config removed** — Remove `"transparent_mode": true` from provider configs. The `auto_auth_path` field (required) controls authentication.
- **`warden_crypto_token` removed** — Self-contained encrypted tokens are no longer supported.

### New Features

- **AWS Transparent Mode** — AWS SDK clients authenticate via JWT or TLS certificate. Warden intercepts SigV4-signed requests, verifies the client signature, then re-signs with real AWS credentials. Supports `aws-chunked` streaming uploads.
- **RDS Provider** — Issues short-lived IAM authentication tokens for PostgreSQL and MySQL on RDS/Aurora.
- **TLS in Dev Mode** — `--dev-tls` generates a self-signed certificate at startup for HTTPS development.

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
