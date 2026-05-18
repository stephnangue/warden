## Warden v0.13.1

**Warden is the secure gateway connecting AI agents to the enterprise systems they need to do real work.** Agents discover what they're allowed to access, Warden brokers every connection, and operators get one control plane for identity, policy, and audit — across every cloud, code-host, observability stack, database, and SaaS the agent reaches. No upstream credentials ever reach the agent: Warden authenticates the caller (JWT or TLS certificate), evaluates fine-grained policy at request time, and injects short-lived credentials before forwarding — or vends scoped grants like database auth tokens directly.

A patch release focused on the Kubernetes path. The 0.13.0 Helm chart shipped with three template defects that surfaced the first time anyone tried to install it on a clean cluster — none of them caught by `helm lint` or `helm template`, all of them only visible once a pod actually tried to run. v0.13.1 fixes the chart and ships it as `0.1.1`.

### Bug Fixes — Helm chart

- **Default image tag now resolves to a published image.** The release workflow strips the leading `v` from `appVersion` while `.goreleaser.yaml` publishes Docker tags as `v{{ .Version }}`. The chart's default tag derivation therefore resolved to `ghcr.io/stephnangue/warden:0.13.0` — `ImagePullBackOff`. The default is now `v` + `.Chart.AppVersion`, aligning with the existing tag convention without churning any historical tags.

- **HCL env-interpolation no longer crashes on boot.** `api_addr` and `cluster_addr` were rendered through Helm's `| quote`, which backslash-escaped the inner double quotes of `{{ env "POD_NAME" }}` and produced HCL the warden binary's env-interpolation pass rejected (`unexpected "\" in operand`). The strings are now hand-quoted, matching the pattern already used for `WARDEN_POSTGRES_URL`.

- **First-time init can create the default audit device under `readOnlyRootFilesystem: true`.** Warden's core registers a default file audit device at the relative path `warden-audit.log`, which resolved against the container's `/app` working directory — read-only when the chart's restricted security context is in effect, so init failed with `failed to create default audit backend: failed to open file: open warden-audit.log: read-only file system`. The container now runs from `/tmp` (writable emptyDir) with an explicit `command: [/app/warden]` so the relative-path entrypoint still finds the binary. Audit logs in `/tmp` are ephemeral by design; operators who need durable auditing should mount a PVC and create an explicit audit device after init.

### Upgrading

```bash
helm upgrade warden oci://ghcr.io/stephnangue/charts/warden \
  --version 0.1.1 \
  -n warden --reuse-values
```

The chart's value surface is unchanged from 0.1.0; existing values files apply as-is.

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

### Getting Started — Local Quickstart

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

### Getting Started — Kubernetes

```bash
helm install warden oci://ghcr.io/stephnangue/charts/warden \
  --version 0.1.1 \
  -n warden --create-namespace \
  --set tls.existingSecret=warden-tls \
  --set storage.existingSecret=warden-db \
  --set seal.transit.address=https://vault.internal:8200 \
  --set seal.transit.keyName=warden-unseal \
  --set seal.transit.existingSecret=warden-seal-token
```

See [docs/deployment/kubernetes.md](https://github.com/stephnangue/warden/blob/main/docs/deployment/kubernetes.md) for the full guide, including the dev quickstart on kind, PostgreSQL recipes, and the first-time initialization runbook.

See the [README](https://github.com/stephnangue/warden#readme) for full documentation and provider guides.

### License

[MPL-2.0](https://github.com/stephnangue/warden/blob/main/LICENSE)
