## Warden v0.12.0

**Warden is the secure gateway connecting AI agents to the enterprise systems they need to do real work.** Agents discover what they're allowed to access, Warden brokers every connection, and operators get one control plane for identity, policy, and audit — across every cloud, code-host, observability stack, database, and SaaS the agent reaches. No upstream credentials ever reach the agent: Warden authenticates the caller (JWT or TLS certificate), evaluates fine-grained policy at request time, and injects short-lived credentials before forwarding — or vends scoped grants like database auth tokens directly.

### What's New

**Skill registry — agent-facing capability catalog served by the cluster.** New `/v1/sys/skills` API and `warden skill {list, read, create, update, delete}` CLI. Foundation skills (`discovery`, `foundation`, `troubleshooting`) seed at first unseal; per-provider skills (aws, vault, openai, github, rds, scaleway) seed the first time a provider of that type is mounted — the catalog reflects what the cluster actually exposes, and agents discover it at runtime instead of having it shipped out-of-band. Reads are open to any namespace token; writes are root-only.

**`mount_url` field on `/v1/sys/providers` responses.** Returns the relative URL path with namespace and mount baked in (e.g., `/v1/team-data/aws/`). Agents prepend `$WARDEN_ADDR` plus the per-provider suffix from the matching skill (`gateway`, `role/<role>/gateway`, `access/<grant>`) — no string surgery on `$WARDEN_NAMESPACE`.

**Agent CLI ergonomics.** A consistent surface for agents and scripts: `--json` payloads on every mutating typed command (literal, `@file`, or `-` for stdin); `--dry-run` for local schema validation with "did you mean" hints, no server round-trip; `--output` with TTY autodetect (`table` on a terminal, `json` when piped); `--fields` for context-window discipline; structured JSON error envelopes with stable exit codes. Three new agent-facing commands: `warden role list`, `warden schema`, and `warden path-help` (now honors the output framework).

**Server-side OpenAPI 3.0 schema endpoint** at `GET /v1/sys/schema` and the Vault-compatible alias `GET /v1/sys/internal/specs/openapi`. Returns a namespace-scoped document covering `sys/*` plus every framework-based mount in the caller's namespace; `?path=<path>` projects to a single operation.

**Bug fix.** Resolved an AB-BA deadlock in the namespace deletion path where concurrent create + cleanup could wedge a node. `persistMounts` now reads the namespace from `ctx` instead of calling `ListNamespaces` while holding `mountsLock`.

### Breaking Changes

- `--format` / `-f` replaced by the global `--output` / `-o`.
- CLI success and empty-list messages are now JSON envelopes in non-table modes (`-o table` keeps the human form).
- Top-level `skills/` directory removed — fetch skills via the runtime registry (`warden skill read <name> --raw` or `GET /v1/sys/skills/<name>`).

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
| Alicloud | Dual-mode (REST + OSS S3) | API keys (native or via Vault) |
| Redshift | Access | IAM database auth tokens |

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
