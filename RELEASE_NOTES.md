## Warden v0.13.2

**Warden is the secure gateway connecting AI agents to the enterprise systems they need to do real work.** Agents discover what they're allowed to access, Warden brokers every connection, and operators get one control plane for identity, policy, and audit — across every cloud, code-host, observability stack, database, and SaaS the agent reaches. No upstream credentials ever reach the agent: Warden authenticates the caller (JWT or TLS certificate), evaluates fine-grained policy at request time, and injects short-lived credentials before forwarding — or vends scoped grants like database auth tokens directly.

v0.13.2 broadens the agent-facing skill catalog (Slack, Ansible Tower, and Atlassian), streamlines the Kubernetes TLS path with opt-in cert-manager support, and fixes a CLI auth-header bug that was silently breaking every `sys/*` discovery call when `WARDEN_TOKEN` held a JWT. The vault-policy-hygiene tutorial is fully rewritten around the discover-and-connect model — the recipe now contains no URLs, role names, or channel IDs.

### New Features

- **Three new agent-facing provider skills.** Slack (URL pattern, bearer auth, POST-only convention, `ok`-field error handling, body-parsing policies, static-token rotation), Ansible Tower (with the slug validator loosened to accept the underscore in `ansible_tower`), and Atlassian — one provider type covering Jira Cloud, Confluence Cloud v2, and Bitbucket Cloud. The agent disambiguates between the three Atlassian products by reading the operator-set mount description, and the skill flags the gotchas each product reliably trips on (Jira v3 ADF, Confluence v2 numeric `spaceId`, the `GET /search` → `POST /search/jql` deprecation, per-product pagination shapes). All three follow the existing seed-on-first-mount registry pattern.

- **Opt-in cert-manager integration for the Helm chart's TLS listener.** Set `tls.certManager.enabled=true` and the chart renders a `cert-manager.io/v1` `Certificate` resource that produces the Secret the StatefulSet already mounts — no more `openssl` plus `kubectl create secret` ceremony in dev, and a clear production path that rotates automatically. Defaults are production-leaning: ECDSA P-256 with `rotationPolicy: Always`, 90-day duration / 15-day `renewBefore`, dnsNames auto-derived from the API and headless Service names, `usages: [server auth]` (plus client auth when `tls.requireClientCert=true`). The Issuer/ClusterIssuer must already exist; the chart deliberately does not render one, since Issuer choice is environment policy. Existing `tls.existingSecret` installs are unaffected. Chart version `0.1.1` → `0.2.0`.

### Bug Fixes

- **CLI sends JWTs only via `Authorization: Bearer`, never as `X-Warden-Token`.** When `WARDEN_TOKEN` held a JWT, the CLI was setting both headers. The server's transparent-auth gate only fires when `X-Warden-Token` is empty, so implicit JWT auth was being skipped for every `sys/*` call: the JWT was treated as a Warden session token, failed the token-store lookup, and `sys/*` requests landed without an identity and were denied at the policy layer. Affected `warden role list`, `warden provider list`, and `warden skill read <name>` — every agent discovery call. Gateway URLs (`<mount>/role/<role>/gateway/...`) go through the streaming branch and were never affected.

- **CI runs the full check suite on release-tag pushes.** On a tag push the tag sits on the same commit as `main`, so `dorny/paths-filter` was computing `main...refs/tags/vX.Y.Z` as zero changed files and every filter returned false — `unit`, `helm-lint`, and `e2e` were all skipped on the one ref where the full suite matters most. The `changes` job now force-emits `code=true` and `helm=true` for any ref under `refs/tags/*` before the filter runs; PR and main-branch path-filter gating is unchanged.

### Documentation

- **Vault-policy-hygiene tutorial rewritten around discover-and-connect.** The flagship demonstration of the model. The mechanics are unchanged — a Goose agent audits OpenBao ACL policies, runs inference against an Anthropic-compatible LLM, and publishes the report to a Slack channel canvas, all under one Forgejo OIDC JWT — but the recipe now contains no URLs, role names, or channel IDs. The workflow exports three env vars (`WARDEN_ADDR`, `WARDEN_NAMESPACE`, `WARDEN_TOKEN`) plus an `ANTHROPIC_HOST` for Goose's own LLM SDK; the agent then asks Warden which roles its JWT can assume, which upstreams are mounted, picks the right combination for each step by reading operator-set descriptions, and fetches each upstream's skill for the exact call shape.

- **Skill catalog refinements driven by the tutorial rewrite.** `discovery.md` documents the `mount_url` no-re-prefix contract (with the failing-URL example agents tend to construct) and adds an "If a call fails" recovery section with one-line summaries per error code, short-circuiting the runaway-retry loop. The Vault skill teaches "use whichever of `vault` or `bao` is on PATH" with a probe snippet, since some environments install one and some the other. The Slack skill ships a full worked example for publishing a channel canvas.

- **Kubernetes deployment guide gains a Cleanup section.** `helm uninstall` and what it does and does not delete (the chart owns its rendered objects; the namespace, operator-managed Secrets, and PostgreSQL are deliberately outside that scope so a reinstall picks the cluster back up without re-running `sys/init`); dev cleanup for the kind quickstart; production cleanup as a per-resource decision table that calls out the data-loss risk of deleting the Transit unseal key or seal token without rekeying first. Also documents `helm rollback` as the way to undo a chart upgrade without touching state.

### Upgrading

```bash
helm upgrade warden oci://ghcr.io/stephnangue/charts/warden \
  --version 0.2.0 \
  -n warden --reuse-values
```

The chart's value surface is additive — a new optional `tls.certManager` subtree, defaulting to `enabled: false`. Existing values files apply as-is; no migration step.

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
  --version 0.2.0 \
  -n warden --create-namespace \
  --set tls.existingSecret=warden-tls \
  --set storage.existingSecret=warden-db \
  --set seal.transit.address=https://vault.internal:8200 \
  --set seal.transit.keyName=warden-unseal \
  --set seal.transit.existingSecret=warden-seal-token
```

See [docs/deployment/kubernetes.md](https://github.com/stephnangue/warden/blob/main/docs/deployment/kubernetes.md) for the full guide, including the dev quickstart on kind, PostgreSQL recipes, the new cert-manager TLS path, the first-time initialization runbook, and the cleanup procedures.

See the [README](https://github.com/stephnangue/warden#readme) for full documentation and provider guides.

### License

[MPL-2.0](https://github.com/stephnangue/warden/blob/main/LICENSE)
