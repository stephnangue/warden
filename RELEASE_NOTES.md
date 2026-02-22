## Warden v0.1.0 — Initial Release

Warden is an identity-aware egress gateway for cloud and SaaS services. Your workloads authenticate with a single JWT; Warden injects short-lived credentials on the fly, enforces fine-grained policies, and logs every API call. No secrets ever reach your applications.

### Providers

| Provider | Transparent Mode | Explicit Mode |
|----------|:---:|:---:|
| AWS | — | Yes |
| Azure | Yes | Yes |
| GCP | Yes | Yes |
| GitHub | Yes | Yes |
| GitLab | Yes | Yes |
| Vault / OpenBao | Yes | Yes |

- **Transparent mode** — Single round-trip: JWT in, provider API response out. Works for any provider that uses bearer tokens.
- **Explicit mode** — Two-step flow required for AWS (SigV4 signing). The caller authenticates first, receives an IP-bound session token pair, then uses it for subsequent requests.

### Core Features

- **Zero credential exposure** — Credentials never leave Warden. Workloads never see or store secrets.
- **Request-level audit trail** — Every API call is logged with caller identity, target service, HTTP method/path, and timestamp. Supports file, syslog, and socket audit sinks.
- **Fine-grained policy enforcement** — Capability-based policies at the HTTP path and method level. Restrict a GitHub token to `src/` while blocking `.github/workflows/`, or block destructive AWS operations regardless of IAM permissions.
- **Unified identity model** — One JWT authenticates across all providers. No per-provider identity mapping.
- **IP-bound sessions** — Sessions are tied to the caller's IP address. Stolen tokens are useless from a different machine.
- **Two-stage credential rotation** — PREPARE (mint new) then ACTIVATE (commit and destroy old). Configurable propagation delay for eventually-consistent providers (AWS, Azure).
- **Seal/unseal model** — Envelope encryption for secrets at rest. Dev mode (in-memory) and production mode with Shamir, Transit, AWS KMS, GCP KMS, Azure Key Vault, OCI KMS, PKCS11, and KMIP seal types.
- **Namespace isolation** — Credential sources, policies, and mount points are scoped to namespaces with hard boundaries.

### Authentication

- JWT auth method with configurable JWKS validation

### Storage Backends

- In-memory (dev mode)
- File
- PostgreSQL (production)

### Operations

- CLI with `server`, `operator`, `login`, `providers`, `auth`, `audit`, `namespaces`, `policies`, and `cred` commands
- Docker image based on distroless (published to `ghcr.io/stephnangue/warden`)
- HCL configuration files
- Dev mode for quick exploration (in-memory, auto-init, auto-unseal)

### Binaries

Pre-built binaries are available for:
- Linux (amd64, arm64)
- macOS (amd64, arm64)
- Windows (amd64)

### Getting Started

You need two things: the **Warden binary** (from the assets below) and the **quick start compose file** (starts an identity provider with pre-configured OAuth2 clients).

```bash
# 1. Download the binary for your platform from the assets below and make it executable
chmod +x warden

# 2. Download the quick start compose file
curl -fsSL -o docker-compose.quickstart.yml \
  https://raw.githubusercontent.com/stephnangue/warden/main/docker-compose.quickstart.yml

# 3. Start the identity provider (Ory Hydra with pre-configured clients)
docker compose -f docker-compose.quickstart.yml up -d

# 4. Start Warden in dev mode
./warden server --dev

# 5. In another terminal, get a JWT from Hydra
curl -s -X POST http://localhost:4444/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=my-agent&client_secret=agent-secret&scope=api:read api:write"

# 6. Use the JWT with Warden
export WARDEN_ADDR="http://127.0.0.1:8400"
export WARDEN_TOKEN="<root-token-from-warden-output>"
./warden --help
```

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
