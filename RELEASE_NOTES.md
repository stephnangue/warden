## Warden v0.13.0

**Warden is the secure gateway connecting AI agents to the enterprise systems they need to do real work.** Agents discover what they're allowed to access, Warden brokers every connection, and operators get one control plane for identity, policy, and audit — across every cloud, code-host, observability stack, database, and SaaS the agent reaches. No upstream credentials ever reach the agent: Warden authenticates the caller (JWT or TLS certificate), evaluates fine-grained policy at request time, and injects short-lived credentials before forwarding — or vends scoped grants like database auth tokens directly.

This release makes Warden a first-class Kubernetes citizen. The platform team's deployment workflow now ends at a single `helm install` command.

### What's New

**First-party Helm chart with HA defaults.** A new chart at `deploy/helm/warden/` deploys a 3-replica active/standby cluster — `StatefulSet` with parallel pod startup, a ClusterIP API Service that gates sealed and uninitialized pods out of its endpoints, a headless Service for inter-node mTLS forwarding and operator access pre-init, dedicated ServiceAccount with the auto-mount token suppressed, `PodDisruptionBudget`, topology spread across zones, and the Pod Security Standards "restricted" profile out of the box. Bring your own PostgreSQL (Bitnami, CloudNativePG, or managed); bring your own TLS Secret; bring your own Vault Transit endpoint for auto-unseal. Preflight validation refuses to render manifests until the required values are set — install errors point at the missing flag, not at a crash-looping pod.

**Install from an OCI registry — no source checkout needed.** Every release tag now publishes the chart to `oci://ghcr.io/stephnangue/charts/warden`, with the `appVersion` pinned to the tag and the same tarball attached to the GitHub Release for air-gapped clusters. End users install with one command:

```bash
helm install warden oci://ghcr.io/stephnangue/charts/warden \
  --version 0.1.0 \
  -n warden --create-namespace \
  -f your-values.yaml
```

The release workflow refuses to publish a chart version that already exists in the registry, so a Warden binary release that does not bump the chart cannot silently clobber a previously published chart artifact.

**`--config-dir` flag on `warden server`.** Merges every `*.hcl` file in a directory in lexical order, later files overriding earlier ones. The Helm chart uses it to drop in a base file (listener, storage shape, HA tuning) and a conditional seal-overlay file. Operators can stack their own overlays without rebuilding the chart.

**Environment-variable interpolation in HCL.** Config files pass through a Go-template stage exposing a single `env` function — `{{ env "POD_NAME" }}` resolves at load time. The Helm chart uses this to template per-pod `api_addr` / `cluster_addr` from the downward API, and to source the postgres connection URL and Vault Transit token from Kubernetes Secrets without baking them into the rendered ConfigMap. HCL's native `${...}` syntax is intentionally left untouched.

**Bug fix — `/v1/sys/health` override precedence.** The `?standbyok=true` query parameter — the standard knob for telling load balancers and readiness probes that "standby is fine" — used to return 200 even when the pod was sealed or uninitialized. Sealed pods carry `standby=true` because they cannot acquire the HA lock, so a Kubernetes readiness probe with `?standbyok=true` would silently mark sealed pods Ready and route traffic to them. Overrides are now applied in severity order (uninit > sealed > standby), and a more severe condition cannot be masked by a less severe override.

### Kubernetes deployment guide

See [docs/deployment/kubernetes.md](https://github.com/stephnangue/warden/blob/main/docs/deployment/kubernetes.md) for the end-to-end story: three install methods (OCI registry, release tarball, source repo), dev quickstart on kind in under five minutes, production install with Vault Transit auto-unseal, PostgreSQL recipes for Bitnami and CloudNativePG, the first-time initialization runbook (init is intentionally not auto-run — auto-storing the root token in etcd is a footgun), rolling upgrade procedure, seal-token rotation, and troubleshooting for the common failure modes.

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
  --version 0.1.0 \
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
