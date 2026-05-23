# Changelog

All notable changes to Warden are documented in this file.

## [Unreleased]

### New Features

- **`warden status` subcommand.** New top-level CLI command that reports server health (initialized, sealed, standby, HA cluster role, leader address, active-since timestamp, server version) by wrapping `GET /v1/sys/health`. Honours the existing `--output table|json|ndjson|text` and `--fields` flags. Exit code is `0` on a healthy unsealed node (active or standby), `7` on a transport error, and `10` when the server reports sealed or uninitialized — scriptable so `if warden status; then ...` works in operator playbooks. The matching `(*api.Sys).Health` / `HealthWithContext` methods are added for SDK callers; the client allow-list now treats `429/501/503` from `/v1/sys/health` as decodable operational states instead of HTTP errors. (this PR)

- **`/v1/sys/health` now returns cluster-aware fields.** The response body grows additively to include `ha_enabled`, `is_leader`, `leader_address`, `active_time` (RFC3339, only set on the active leader), and `version` (server build, surfaced through a new `HandlerProperties.Version` plumbed from `cmd.SetVersion`). Operators no longer need three round-trips (`/sys/health`, `/sys/leader`, `/sys/seal-status`) to assemble a status view. Leader lookup is gated on `!sealed && ha_enabled`, so a sealed HA node no longer logs an error on every k8s probe. (this PR)

### Breaking Changes

- **`/v1/sys/health` and `/v1/sys/leader`: `is_self` is renamed to `is_leader`.** The Vault legacy name was confusing in isolation ("self relative to what?") and the new name is symmetric across both endpoints. Any external script that grepped for `"is_self":` against these endpoints needs to be updated. (this PR)

- **`/v1/sys/health`: `server_time_utc` (int64 Unix seconds) is replaced with `server_time` (RFC3339 string).** The new format is human-readable and sortable as text. The old integer field is gone, not aliased. (this PR)

- **Audit devices declared in the HCL server config.** New `audit "TYPE" "PATH" { description = "..." options = { ... } }` block, parsed alongside `listener`, `storage`, and `seal`. Devices declared this way are registered during unseal *before the API listener accepts traffic* — a misconfigured sink (unwritable path, missing parent directory, permission denied) is a hard startup error, not a half-initialized cluster. Declarative (HCL) and imperative (API-enabled) devices coexist at different paths; an HCL block colliding with an API-enabled path refuses to start, and declarative devices cannot be modified or deleted via `sys/audit/{path}` (operators edit HCL and restart instead). The reconciler on every unseal handles add / refresh-options / drop-from-config transitions, preserving each entry's accessor and HMAC salt across restarts so audit-log HMACs stay stable. `GET /v1/sys/audit` and `GET /v1/sys/audit/{path}` responses now expose a `declarative` boolean so operators can tell the two origins apart. The auto-create-default-on-first-unseal logic is **removed** — the Helm chart ships a working `audit "file"` block by default, dev mode (`warden server -dev`) intentionally ships no audit, and bare-binary operators add a one-line block to their HCL (or accept zero-audit + bootstrap via API). (this PR)

### Bug Fixes

- **Audit broker is fail-open at zero registered devices.** Previously `auditManager.LogRequest/LogResponse` returned `(continue=false, nil)` when no devices were registered, causing the request handler to block every non-streaming request with HTTP 500 — including `sys/audit/{path}`, so a freshly-installed cluster with no audit had no way to bootstrap one via the API. The broker now short-circuits to `(true, nil)` when zero devices are registered, and traffic flows. Once any device is registered (HCL or API) the broker becomes fail-closed again; running ≥2 devices is recommended to avoid wedge-lockout if one sink blocks. Devices that are registered but currently disabled (`Enabled()==false`) still fail-closed — that's an operator opt-in to "no audit," not the bootstrap window. (this PR)

- **`POST /v1/sys/audit/{path}` (disable) no longer refuses to remove the last audit device.** The previous "cannot disable the last audit device: fail-closed mode" gate is gone — with the broker now fail-opening at zero, removing the last device is a valid operator choice (intentional unaudited bootstrap state). Declarative HCL-owned devices remain protected: those still error with "owned by an HCL audit declaration; edit the server config and restart instead." (this PR)

### Documentation

- **Tutorials updated for the audit-config redesign.** Both [vault-policy-hygiene](docs/tutorials/vault-policy-hygiene/README.md) and [aws-access-hygiene](docs/tutorials/aws-access-hygiene/README.md) used to rely on the auto-default audit device that's gone in this PR. Their `warden-init.sh` wiring scripts now call `warden audit enable --type=file --file-path=./warden-audit.log audit-default` as their first step (idempotent, no-op on re-runs), and the README prose was rewritten to explain the broker fail-open posture instead of "no audit enable command needed." Existing `jq` walkthroughs that tail `warden-audit.log` continue to work unchanged. (this PR)

- **AWS access hygiene tutorial added.** End-to-end demo of the *within-provider* dimension of discover-and-connect: a Goose agent audits IAM in a sandbox AWS account through four read-only lenses (inventory, recent usage, external exposure, effective access), publishes findings to Security Hub as ASFF, and posts a summary canvas to Slack — switching Warden roles between calls within a single AWS mount, with each role assuming a distinct narrowly-scoped IAM role via STS. Warden holds only the broker IAM user's static keys; the agent declares per-call intent via `AWS_ACCESS_KEY_ID`, and the audit log records each declared intent as `auth.role_name`. A hallucinated cross-role write — e.g. `BatchImportFindings` under the `iam-reader` intent — is denied at AWS by the assumed role's narrow IAM policy, not by Warden's gateway policy, and surfaces as an anomaly signature in the audit log. Tutorial ships as a four-script setup (`aws-init.sh`, `warden-init.sh`, `seed-aws.sh`, plus a Forgejo Actions workflow that runs Goose under a per-job OIDC JWT) with a thirteen-section README covering the operator setup, the discovery loop, the lens-based recipe, and a `jq`-driven audit-log walkthrough including a negative test. (#222, #223, #225, this PR)

- **Root-README enterprise-control-plane bullets reworked.** Replaced "Discovery" with "Per-call least privilege" (the actual headline benefit — the agent picks a different role for every call). Renamed "Compromise-resilient" → "Compromise containment" with the WHY now upfront (Warden holds the upstream credentials, the agent never does). Added "Hallucination containment" between Audit and Compromise containment to cover the ambient-LLM-mistake case the original list didn't. Dropped "Self-describing capabilities" — its load-bearing claim (no SDK rebuild) is implicit in the per-call framing. (#224)

## [v0.13.2] — 2026-05-21

### New Features

- **Three new agent-facing provider skills wired into the registry.** Slack — URL pattern, bearer auth, POST-only convention, the `ok`-field error handling that Slack uses instead of HTTP status codes, body-parsing policies, static-token rotation (#215). Ansible Tower — registered behind a tightened slug-validation rule that now accepts underscores so `ansible_tower` validates (#219). Atlassian — one provider type covering Jira Cloud, Confluence Cloud v2, and Bitbucket Cloud, with the agent told to disambiguate via the operator-set mount description and the gotchas each product reliably trips on (Jira v3 ADF descriptions, Confluence v2 numeric `spaceId`, the `GET /search` → `POST /search/jql` deprecation, per-product pagination shapes) (#220). All three follow the existing seed-on-first-mount pattern.

- **Opt-in cert-manager integration for the Helm chart's TLS listener.** Setting `tls.certManager.enabled=true` renders a `cert-manager.io/v1` `Certificate` that produces the Secret the StatefulSet already mounts. Defaults are production-leaning: ECDSA P-256 with `rotationPolicy: Always`, 90-day duration / 15-day `renewBefore`, dnsNames auto-derived from the API and headless Service names, and `usages: [server auth]` (plus client auth when `tls.requireClientCert=true`). The Issuer/ClusterIssuer must already exist — the chart deliberately does not render one. Existing `tls.existingSecret` installs are unaffected; preflight validation rejects setting both `tls.existingSecret` and `tls.certManager.enabled` at once, and rejects `certManager` enabled with an empty `issuerRef.name`. Chart version `0.1.1` → `0.2.0`. (#214)

### Bug Fixes

- **CLI sends JWTs only via `Authorization: Bearer`, never as `X-Warden-Token`.** When `WARDEN_TOKEN` held a JWT, the CLI was setting both headers. The server's transparent-auth gate only fires when `X-Warden-Token` is empty, so implicit JWT auth was being skipped for every `sys/*` call: the JWT was treated as a Warden session token, failed the token-store lookup, and left `sys/*` requests without an identity. Affected `warden role list`, `warden provider list`, and `warden skill read <name>` — i.e. every agent discovery call. Gateway URLs (`<mount>/role/<role>/gateway/...`) went through the streaming branch and were unaffected. The fix detects the `eyJ` JWT prefix, sets `Authorization`, and calls `client.ClearToken()` so `X-Warden-Token` is never sent. (#216)

- **CI now runs the full check suite on release-tag pushes.** On a tag push, the tag sits on the same commit as `main`, so `dorny/paths-filter` computed `main...refs/tags/vX.Y.Z` as zero changed files and every filter returned false. `unit`, `helm-lint`, and `e2e` were then skipped via their `needs.changes.outputs.* == 'true'` gates — on the one ref where the full suite matters most. The `changes` job now force-emits `code=true` and `helm=true` for any ref under `refs/tags/*` before the filter runs. Non-tag pushes and pull requests keep the existing path-based gating intact. (#210)

### Documentation

- **Vault-policy-hygiene tutorial rewritten around the discover-and-connect model.** The mechanics are unchanged — a Goose agent audits OpenBao ACL policies, runs inference against an Anthropic-compatible LLM, and publishes the report to a Slack channel canvas, all under one Forgejo OIDC JWT — but the recipe now contains no URLs, role names, or channel IDs. The workflow exports three env vars (`WARDEN_ADDR`, `WARDEN_NAMESPACE`, `WARDEN_TOKEN`) plus an `ANTHROPIC_HOST`; the agent then asks Warden which roles its JWT can assume, which upstreams are mounted, picks the right combination for each step by reading operator-set descriptions, and fetches each upstream's skill for the exact call shape. (#218)

- **Skill catalog refinements driven by the tutorial rewrite.** `discovery.md` documents the `mount_url` no-re-prefix contract (with the failing-URL example agents tend to construct, `/v1/<ns>/<ns>/<mount>/...`) and adds an "If a call fails" recovery section with one-line summaries per error code, short-circuiting the runaway-retry loop. The Vault skill teaches "use whichever of `vault` or `bao` is on PATH" with a probe snippet, since some environments install one and some the other (both honour `VAULT_*` env vars). The Slack skill ships a full worked example for publishing a channel canvas. (#217)

- **Kubernetes deployment guide gains a Cleanup section.** Three concrete teardown flows: `helm uninstall` and what it does and does not delete (the chart owns its rendered objects; the namespace, operator-managed Secrets, and PostgreSQL are deliberately outside that scope so a reinstall picks the cluster back up without re-running `sys/init`); dev cleanup for the kind quickstart; production cleanup as a per-resource decision table calling out the data-loss risk of deleting the Transit unseal key or seal token without rekeying first. Also documents `helm rollback` as the way to undo a chart upgrade without touching state. (#211)

### Dependencies

- `azure/setup-helm` 4 → 5 in CI workflows. (#212)
- `github.com/aws/aws-sdk-go-v2/service/redshift` 1.62.7 → 1.62.8. (#213)

## [v0.13.1] — 2026-05-18

### Bug Fixes

- **Helm chart can now bring up a fresh deployment cleanly.** Three template defects in chart 0.1.0 prevented `helm install` from reaching a working pod on a clean cluster. (1) The chart's default image tag derivation produced `ghcr.io/stephnangue/warden:0.13.0` — `ImagePullBackOff` — because the release workflow strips the leading `v` from `appVersion` while `.goreleaser.yaml` publishes Docker tags as `v{{ .Version }}`. The default now resolves to `v` + `.Chart.AppVersion`, lining up with the published tag convention without touching any existing image tags. (2) `api_addr` and `cluster_addr` were rendered through Helm's `| quote`, which backslash-escaped the inner double quotes of `{{ env "POD_NAME" }}` and crashed the warden binary's env-interpolation pass at boot with `unexpected "\" in operand`. The strings are now hand-quoted, matching the working pattern already used for `WARDEN_POSTGRES_URL`. (3) The default file audit device created on first init writes the relative path `warden-audit.log`, which resolved against the container's `/app` working directory — read-only under `readOnlyRootFilesystem: true`, so init failed with `read-only file system`. The container now runs from `/tmp` (writable emptyDir) with an explicit `command: [/app/warden]` so the relative-path entrypoint still finds the binary. (#208)

### Chart

- Chart version bumped `0.1.0` → `0.1.1`. No app/binary or template-API changes beyond the three bug fixes above; configuration values are fully backward-compatible.

## [v0.13.0] — 2026-05-16

### New Features

- **First-party Helm chart for Kubernetes deployments.** New chart at `deploy/helm/warden/` deploys a 3-replica HA cluster as a `StatefulSet` with `podManagementPolicy: Parallel`, a ClusterIP API Service plus a `publishNotReadyAddresses: true` headless Service for per-pod DNS resolution of `api_addr` / `cluster_addr` and operator access pre-init, a dedicated `ServiceAccount` with `automountServiceAccountToken: false`, a `PodDisruptionBudget` with `maxUnavailable: 1`, topology spread across zones, and the Pod Security Standards "restricted" profile (`runAsNonRoot`, `readOnlyRootFilesystem`, `seccompProfile: RuntimeDefault`, all capabilities dropped). Production-leaning defaults plus a `values-dev.yaml` quickstart profile for kind / minikube. (#206)

- **OCI chart publishing on every release tag.** The release workflow now packages the chart, pins its `appVersion` to the git tag, pushes the OCI artifact to `oci://ghcr.io/stephnangue/charts`, and attaches the same tarball to the GitHub Release for air-gapped users. Refuses to publish a chart version that already exists in the registry. End users install with `helm install warden oci://ghcr.io/stephnangue/charts/warden --version 0.1.0` — no `helm repo add`, no source checkout. (#206)

- **`--config-dir` flag on `warden server`.** Merges every `*.hcl` file in a directory in lexical order, with later files overriding earlier ones. Enables a Kubernetes ConfigMap + Secret split where each owns a disjoint subset of HCL blocks without sacrificing single-file simplicity. Mutually exclusive with `--config` and `--dev`. (#204)

- **Environment-variable interpolation in HCL config files.** Config files are pre-processed through a Go-template pass exposing a single `env` function — `{{ env "POD_NAME" }}` resolves at load time from `os.Getenv`. Missing variables expand to the empty string (matches shell semantics). HCL's native `${...}` interpolation syntax is intentionally left untouched. (#204)

- **Helm-chart preflight validation.** `helm install` and `helm template` fail at template-render time with actionable messages when `tls.existingSecret`, the postgres connection URL, the Vault Transit address / keyName / token, or the static seal Secret is missing — instead of producing manifests that crash-loop at pod startup. (#206)

### Bug Fixes

- **`/v1/sys/health` query-parameter overrides are now applied in severity order (uninit > sealed > standby).** Previously, `?standbyok=true` returned 200 unconditionally for any standby pod — including sealed pods, which naturally have `standby=true` because they cannot acquire the HA lock. Kubernetes readiness probes using `?standbyok=true` would silently mark sealed pods Ready and route traffic to them. The duplicated parsing / range-check logic across overrides was also extracted into a single helper. (#205)

- **Anchored the `warden` binary `.gitignore` rule to the repo root.** The previous unanchored `warden` pattern was matching the `deploy/helm/warden/` chart directory in addition to the intended root binary, hiding the entire chart from version control. Changed to `/warden`. (#206)

### Documentation

- **Kubernetes deployment guide** at `docs/deployment/kubernetes.md`. Architecture overview, prerequisites, three install methods (OCI registry, release tarball, source repo), dev quickstart on kind, production install with Vault Transit auto-unseal, PostgreSQL options (Bitnami subchart, CloudNativePG cluster, managed Postgres), first-time `/v1/sys/init` runbook, rolling-upgrade and seal-token-rotation procedures, and troubleshooting for the common failure modes. README gets a short Kubernetes section pointing at the guide. (#206)

- **`{{ env "VAR" }}` interpolation example** added to the commented HCL at `deploy/config/warden.hcl`. (#204)

### Testing

- **Filled in the previously-empty `config` package test surface** — `LoadConfig` validation rules (rotation-period bounds, `ip_binding_policy`, listener TLS, `cluster_addr` URL format, cluster-tuning duration fields), `DevConfig` defaults, `GetListenerByType`, `StorageBlock.Config` and `KMS.Config` map serialization, `KMS.IsDisabled` semantics, and direct `mergeConfig` behavior (scalar override, pointer / slice replace-wholesale, bool one-way, int non-zero override). Package coverage went from 0 % to 75 %. (#204)

- **`TestParseHealthStatusOverrides` grew from 8 to 16 sub-cases**, with the new ones covering the precedence pairs that the bug fix introduces (`standbyok` no longer masks sealed, `sealedcode` no longer masks uninit, etc.). (#205)

- **Helm-chart lint job in CI** running `helm lint` and `helm template ... | kubeconform -strict` against both the production and dev value profiles. Path-filter-gated so Go-only changes do not trigger it. (#206)

## [v0.12.0] — 2026-05-13

### Breaking Changes

- **`--format` / `-f` flag removed.** Replaced by a global persistent `--output` / `-o` flag (`table`, `json`, `ndjson`, `text`). Autodetects `table` on a TTY, `json` when piped or redirected. Honors `WARDEN_OUTPUT`.
- **CLI success and empty-list messages are now JSON in non-table modes.** Plain-text strings like `Success! Enabled ...`, `Successfully deleted ...`, and `No providers enabled` become structured envelopes (`{"path": "...", "enabled": true}`, `{"deleted": true}`, `[]`). Scripts that grep the human strings need to update; agents already parse JSON. Pass `-o table` to keep the human form.
- **Top-level `skills/` directory removed.** Foundation skills moved to embedded seed data; provider skills moved into their owning provider package (`provider/<type>/skill.md`). Agents fetch skills from the runtime registry — `warden skill read <name> --raw` or `GET /v1/sys/skills/<name>` — rather than reading them from a repo checkout. `AGENTS.md` was rewritten to point at the new surface.

### New Features

- **Skill registry — agent-facing capability catalog served by the cluster.** New `/v1/sys/skills` API and `warden skill {list, read, create, update, delete}` CLI. Foundation skills (`discovery`, `foundation`, `troubleshooting`) seed at first unseal; per-provider skills (`aws`, `vault`, `openai`, `github`, `rds`, `scaleway`) seed the first time a provider of that type is mounted — the catalog reflects what the cluster actually exposes. Reads are open to any namespace token; writes are root-only. Operator edits and deletions are sticky across restarts.
- **`mount_url` field on `/v1/sys/providers` responses.** Returns the relative URL path with namespace and mount baked in (e.g., `/v1/team-data/aws/`). Agents prepend `$WARDEN_ADDR` plus the per-provider suffix from the skill (`gateway`, `role/<role>/gateway`, `access/<grant>`) — no string surgery on `$WARDEN_NAMESPACE`. Surfaced on `MountOutput.MountURL` and through `warden provider list` / `read`.
- **`--json` payload on every mutating typed command.** Accepts a JSON literal, `@file.json`, or `-` (stdin) on `cred source create/update`, `cred spec create/update`, `auth enable`, `audit enable`, `namespace create/update`, `provider enable`. Mutually exclusive with the typed flags (combining errors with exit `2`). Composes with `--dry-run`.
- **Global `--dry-run` / `-D` flag — local schema validation, no server round-trip.** Fetches the operation's schema from `/v1/sys/schema?path=<path>`, validates the payload structurally (required fields, unknown-field detection with "did you mean" hints, type and enum checks), and exits without sending the request. Catches hallucinated parameters before they hit the wire. Honors `WARDEN_DRY_RUN`. Wired into every mutating CLI command.
- **`warden role list` CLI command.** Agent-facing role introspection over `/v1/sys/introspect/roles`. Lists `{name, description, auth_path}` for every role the caller's identity (JWT or TLS client cert) can assume in the namespace. Composes with `--output` and `--fields`; per-mount failures surface on stderr without changing the exit code.
- **`warden schema` CLI command.** Agent-facing OpenAPI projection. Three modes: `warden schema PATH` (single path, friendly shape with merged body fields and `sensitive` flags); `warden schema --list` (every path in the namespace, NDJSON-friendly); `warden schema PATH --raw` (raw OpenAPI fragment for codegen tools).
- **`warden path-help` honors the `--output` framework.** Returns `{"help": "..."}` in `json`/`ndjson`/`text` modes; prose in `table` mode. Missing help exits `6` (`not_found`) instead of silently exiting `0`.
- **Server-side OpenAPI 3.0 schema endpoint** at `GET /v1/sys/schema` (and the Vault-compatible alias `GET /v1/sys/internal/specs/openapi`). Returns a namespace-scoped document covering `sys/*` plus every framework-based mount reachable in the caller's namespace. `?path=<path>` projects to a single operation.
- **Input hardening at the CLI boundary.** Three validators in `cmd/helpers/path.go` reject malformed inputs before any HTTP call, classified as exit `3` (`invalid_input`): `ValidatePath` (path traversal, absolute paths, control bytes, `?`/`#`/`%`); `ValidateHeaderValue` (CR/LF injection in `--namespace` / `--role`); `ValidateIdentifier` (`--type` on cred-source/spec create).
- **Global `--output` / `-o` flag with TTY autodetect.** Persistent flag for `table`, `json`, `ndjson`, `text`. Defaults to `table` on a terminal, `json` when piped — agents and scripts get machine-readable output without configuration.
- **Global `--fields` / `-F` flag for context-window discipline.** Comma-separated dot-paths project structured output to only the requested fields (e.g., `--fields name,rules.*.path`; `*` matches every key/element at a level). Honors `WARDEN_FIELDS`. Keeps agent context windows small.
- **Structured JSON errors and stable exit codes.** Every CLI failure produces a category-specific exit code and (in JSON/NDJSON modes) a `{"error": {code, message, hint}}` envelope on stderr. Stable codes: `usage` (2), `invalid_input` (3), `auth_required` (4), `forbidden` (5), `not_found` (6), `network` (7), `server` (8), `conflict` (9), `unknown` (1).

### Bug Fixes

- **AB-BA deadlock in the namespace deletion path.** Rapid namespace create/delete cycles could wedge a node: cleanup held `mountsLock` and needed the `NamespaceStore` lock via `persistMounts → ListNamespaces`, while a concurrent `CreateNamespace` held them in the opposite order. `persistMounts` now uses the namespace already in `ctx` when removing a single mount instead of calling `ListNamespaces`. Fallback to the "list all" behavior is preserved for the unusual case where `ctx` carries no namespace.

### Documentation

- **`docs/agent-flow.md` — system-side reference for the agent end-to-end flow.** Runtime contract, bootstrap prompt, five-step discovery loop, per-provider recipe variability, error handling, caching, and a trust-boundary diagram. Complements the in-binary `discovery` / `foundation` / `troubleshooting` skills.
- **README polish.** Discover-then-connect section expanded to all three introspection calls. New "Self-describing capabilities" bullet. Identity-bound-access bullet reframed around one-identity-for-all-upstreams. Compromise-resilient bullet leads with the prompt-injection / jailbreak threat model. Auth-method table's "Best For" column replaced with "How the agent presents the credential to its SDK" — the JWT goes in whichever slot the upstream SDK expects (AWS_SECRET_ACCESS_KEY, OPENAI_API_KEY, X-Vault-Token, Authorization: Bearer); cert mode uses a placeholder once TLS proves identity.

### Removed

- **`warden login` CLI command.** Deleted along with its `cmd/login` package. The server-side `/auth/jwt/login` and `/auth/cert/login` endpoints have returned `400` since v0.6.0; clients have authenticated implicitly (`WARDEN_TOKEN`, `WARDEN_CLIENT_CERT`/`KEY`, or `Authorization: Bearer`) since then. The lower-level `api/auth/jwt` and `api/auth/cert` packages remain.

## [v0.11.0] — 2026-04-20

### New Features

- **Agent Role Introspection** — New self-describing API that lets an autonomous agent discover the roles it may assume by presenting only its identity vehicle (JWT bearer or TLS client certificate). Removes the need to distribute role names to agents out-of-band, which does not scale for agents that interact with many external systems. Shipped in three layers:
  - `description` free-text field on JWT and certificate roles, plumbed through role CRUD and surfaced to introspection consumers. Backwards compatible with roles persisted before the field existed. (#162)
  - `GET /v1/auth/{mount}/introspect/roles` on both JWT and certificate backends. Each backend iterates its own roles and reuses its login-time constraint matchers (bound claims and URI patterns for JWT, cert constraint checks for cert), returning only the roles the presented credential could actually satisfy within that mount. Factored a shared `matchRole` helper so login and introspection cannot drift on which claims are enforced. (#163)
  - `GET /v1/sys/introspect/roles` system-backend aggregator that detects the caller's credential type, collects all matching auth mounts in the caller's namespace, fans out to each mount's per-backend introspect path in parallel (capped at 10 concurrent goroutines), and returns the aggregated, sorted role set with a per-mount `warnings[]` channel. Mounts that do not implement introspection are silently skipped so support can roll out incrementally. (#166)

- **`dualgateway` framework for dual-mode gateway providers** — New shared framework for providers that auto-detect between REST API proxying and S3-compatible object storage (SigV4 verify/re-sign/forward) on a per-request basis. Providers supply a `ProviderSpec` describing their differences (auth strategy, S3 endpoint format, credential type); the framework handles transport, token extraction, transparent auth, config CRUD, and SigV4 lifecycle. Introduced alongside the Scaleway and OVH dual-mode providers. (#148, #149)

- **Scaleway Provider** — New dual-mode (REST + S3) provider for the Scaleway API, built on `dualgateway`. Object-storage requests are verified and re-signed via SigV4 to Scaleway's S3-compatible endpoints. (#148)

- **Sentry Provider** — New streaming gateway provider for the Sentry REST API. (#153)

- **Grafana Provider** — New streaming gateway provider for the Grafana HTTP API, plus a source driver that programmatically provisions and rotates service-account tokens scoped by `orgID`. (#155)

- **Atlassian Provider** — New dual-mode gateway provider with auth for both Atlassian Cloud and Data Center deployments. (#157)

- **Prometheus Provider** — New streaming gateway provider for the Prometheus HTTP API. (#158)

- **Honeycomb Provider** — New streaming gateway provider for the Honeycomb REST API, plus a matching source driver. (#159)

- **IBM Cloud Provider** — New dual-mode gateway provider for the IBM Cloud APIs, paired with the `ibm` credential driver introduced in v0.10.0 and with dynamic Vault/OpenBao credential sourcing. (#161)

- **OVH Provider upgraded to dual-mode** — The OVH provider (introduced in v0.10.0 as REST-only) now operates in dual-mode via `dualgateway`, and ships with a new OVH source driver that mints OVH credentials via OAuth2. (#149, #151)

- **Cloudflare Provider upgraded to dual-mode with R2 S3 support** — The Cloudflare provider (introduced in v0.10.0) now operates in dual-mode via `dualgateway` and adds proxying for Cloudflare R2's S3-compatible API. (#150)

### Bug Fixes

- **Dynamic S3 credentials now have a TTL tied to the OAuth2 token lifetime** — Previously, dynamic S3 credentials could outlive the OAuth2 token that authorized them. The TTL is now bounded by the token lifetime, closing a credential-exposure window. (#152)

- **Grafana leaseID now encodes `orgID` to prevent service-account leak** — The Grafana source driver's leaseID derivation omitted the organization ID, which could cause lease collisions across tenants and, in the worst case, return another tenant's service account. leaseID now incorporates `orgID`. (#156)

### Infrastructure

- **Dependency updates** — Bumped Go minor/patch dependencies in two batches (#154: 3 updates, #164: 7 updates).

### Documentation

- **README revamp for AI-agent audience** — Rewrote the primary README to position Warden as infrastructure for autonomous AI agents. Motivating examples and Getting Started flow refactored accordingly. (#160)

- **Architecture and provider reference split into `docs/`** — Extracted detailed architecture and provider descriptions out of the README into standalone docs under `docs/`. Expanded the MCP server framing. (#165)

## [v0.10.0] — 2026-04-09

### New Features

- **OVH Provider** — New streaming gateway provider for the OVHcloud REST API. Proxies requests to account info, cloud projects, domains, and IPs with automatic credential injection. Supports OAuth2 client credentials and Vault/OpenBao credential sources. Multi-region support (EU, Canada, US). (#127)

- **Datadog Provider** — New streaming gateway provider for the Datadog REST API. Proxies requests to metrics, monitors, dashboards, logs, and events. Injects `DD-API-KEY` and `DD-APPLICATION-KEY` headers. Multi-site support (US1, US3, US5, EU1, AP1, AP2, US1-FED). Supports static API keys and Vault/OpenBao credential sources. (#129)

- **Cohere Provider** — New streaming gateway provider for the Cohere API. Proxies requests to chat, embed, rerank, generate, and models endpoints. Bearer token auth with support for v1 and v2 API endpoints, streaming chat, and request-body policies for model and token restrictions. (#130)

- **Elastic Provider** — New streaming gateway provider for the Elasticsearch REST API. Proxies requests to search, index, cluster, and security endpoints. Supports three credential modes: static API keys, Elasticsearch driver with programmatic key rotation (72-hour default), and Vault/OpenBao. Role descriptor support for scoped permissions. (#132)

- **Dynatrace Provider** — New streaming gateway provider for the Dynatrace REST API. Proxies requests to entities, metrics, logs, problems, settings, and tokens. Supports API token auth (`Api-Token` header) and OAuth2 client credentials. Covers both Environment API and Platform API. (#133)

- **Splunk Provider** — New streaming gateway provider for the Splunk REST API. Proxies requests to search jobs, saved searches, dashboards, indexes, and token management. Bearer token auth with HTTPS validation. Supports namespace-scoped endpoints (`/servicesNS/`). Compatible with Splunk Enterprise (v7.3+) and Splunk Cloud (v8.0.2007+). (#135)

- **New Relic Provider** — New streaming gateway provider for the New Relic REST API v2 and NerdGraph (GraphQL) API. Injects `Api-Key` header. Supports NRQL queries, entity search, and dashboard management. Multi-datacenter support (US, EU). (#135, #136)

- **Kubernetes Provider** — New streaming gateway provider for the Kubernetes API server. Proxies requests to pods, deployments, services, and namespaces. Mints short-lived ServiceAccount tokens via the TokenRequest API with automatic rotation. Audience-scoped tokens for multi-tenant security. Configurable TTL (10m–48h, default 1h). (#137)

- **TFE Provider** — New streaming gateway provider for Terraform Enterprise and HCP Terraform. Proxies requests to organizations, workspaces, runs, state versions, variables, and projects. Bearer token auth with JSON:API (`application/vnd.api+json`) support. Supports user, team, and organization token types. (#142)

- **Cloudflare Provider** — New streaming gateway provider for the Cloudflare API v4. Proxies requests to zones, DNS records, workers, and accounts. API token auth with token verification via `/user/tokens/verify`. (#144)

- **Ansible Tower Provider** — New streaming gateway provider for the Ansible Tower/AWX/AAP REST API. Proxies requests to job templates, jobs, inventories, projects, hosts, and workflow templates. Bearer auth with Personal Access Tokens (PAT). Supports Ansible Tower (v3.5+), AWX (v18.0+), and Red Hat Ansible Automation Platform (v2.0+). (#145)

- **IBM Cloud Credential Driver (`ibm`)** — New credential source driver for IBM Cloud. Mints IAM bearer tokens from IBM Cloud API keys via the IAM token exchange endpoint. Supports automatic source API key rotation with a 2-minute default activation delay. Account ID discovery from API key. (#128)

- **Extra OAuth2 Token Form Parameters** — The OAuth2 credential driver now supports arbitrary additional form parameters via `token_param.*` config keys (e.g., `token_param.resource=urn:dtaccount:123`). Core fields (`grant_type`, `client_id`, `client_secret`) are protected from override. Enables providers like Dynatrace that require non-standard OAuth2 form fields. (#131)

- **`ca_data` and `tls_skip_verify` across all providers and drivers** — Standardized TLS configuration across the entire codebase. All providers and all credential drivers now support `ca_data` (inline PEM CA certificate) and `tls_skip_verify` config options via a shared TLS helper. When `tls_skip_verify=true`, `http://` URLs are permitted for dev/test environments. (#140)

### Improvements

- **Lazy transport initialization** — Refactored transport creation from eager package-level initialization to lazy initialization via `sync.Once` factory pattern. Transports are only created when a provider is actually mounted, eliminating unnecessary startup overhead and background goroutines. (#138)

### Bug Fixes

- **httpproxy data races, HTTP/2 regression, and validation gaps** — Extended mutex coverage to protect `providerURL`, `MaxBodySize`, `Timeout`, `Proxy.Transport`, `tlsSkipVerify`, and `caData` from concurrent access. Fixed `NewTransportWithTLS` silently breaking HTTP/2 by configuring HTTP/2 after TLS finalization. Reject `max_body_size=0` with bounds validation (100 MB cap). Made `DefaultTokenExtractor` case-insensitive for the Bearer scheme per RFC 7235. (#143)

- **Elastic API key expiration default** — Set default API key expiration to 1 hour when no explicit expiration is configured. (#134)

- **Flaky `TestOmitResponseFields` test** — Fixed race condition in the `omit_entire_response` test subcase. (#139)

- **Provider README inaccuracies** — Corrected GitLab `renew-secret` endpoint path and other documentation errors across provider READMEs. (#141)

- **CBP policy wildcard usage** — Corrected `*` vs `+` wildcard usage in capability-based policy examples across all provider READMEs. (#146)

### Infrastructure

- **Dependency updates** — Bumped `github.com/go-jose/go-jose/v4` from 4.1.3 to 4.1.4 (#112). Updated Go minor/patch dependencies (#125).
- **CI** — Bumped `codecov/codecov-action` from v5 to v6 (#124).

### Documentation

- **Provider READMEs** — Added full quickstart guides, configuration reference tables, and policy examples for all 11 new providers (OVH, Datadog, Cohere, Elastic, Dynatrace, Splunk, New Relic, Kubernetes, TFE, Cloudflare, Ansible Tower).
- **Self-hosted TLS examples** — Added custom CA and HTTP dev-mode configuration examples to GitLab, GitHub, Elastic, Splunk, ServiceNow, and Kubernetes READMEs. (#140)
- **CBP policy wildcard corrections** — Fixed wildcard usage across all existing provider READMEs. (#146)

## [v0.9.1] — 2026-04-06

### Bug Fixes

- **`--type` flag no longer required on `cred spec create`** — The CLI enforced `--type` as required even though the server can infer the credential type from the source driver. The flag is now optional, matching the server-side behavior documented since v0.7.0. (#111)

### Documentation

- **AWS Provider README** — Added Vault/OpenBao credential source section with `static_aws` and `dynamic_aws` mint method examples and configuration reference tables.
- **Quickstart paths** — Fixed docker-compose quickstart file path in all provider READMEs (`deploy/docker-compose.quickstart.yml` → `docker-compose.quickstart.yml`).

### Infrastructure

- **Vault init script** — Added `secret/data/*` read/list capabilities to the Vault policy, enabling KV v2 secret access for the `static_apikey` and `static_aws` mint methods.

## [v0.9.0] — 2026-04-06

### Breaking Changes

- **`kv2_static` mint method removed** — Replaced by `static_aws`. Existing credential specs using `mint_method=kv2_static` must be updated to `mint_method=static_aws`. The `kv2_mount` and `secret_path` config fields are unchanged.

- **`dynamic_database` mint method removed** — The Vault database engine mint method has been removed from the Vault driver. Credential specs using `mint_method=dynamic_database` will no longer work.

### New Features

- **`static_apikey` mint method** — Fetch static API keys from Vault/OpenBao KV v2 and infer the `api_key` credential type. Allows any provider that uses API keys (OpenAI, Anthropic, Mistral, Slack, PagerDuty, ServiceNow) to store secrets in Vault instead of directly in Warden.

- **`dynamic_gcp` mint method** — Generate GCP OAuth2 access tokens via the Vault GCP secret engine. Supports both `roleset` and `static-account` role types. No service account key needs to be stored in Warden.

- **`oauth2` mint method** — Fetch OAuth2 bearer tokens via a Vault/OpenBao OAuth2 secret engine plugin (compatible with openbao-plugin-secrets-oauthapp). Infers the `oauth_bearer_token` credential type. TTL is computed from the plugin's `expire_time` response field.

- **Vault as universal credential source** — The `api_key`, `gcp_access_token`, and `oauth_bearer_token` credential types now accept `hvault` as a valid source type, in addition to their native source types. This enables centralized secret management through Vault/OpenBao for all providers.

### Documentation

- **Provider READMEs** — Added Vault/OpenBao credential source examples and configuration reference tables to PagerDuty, ServiceNow, OpenAI, Anthropic, Mistral, Slack, and GCP provider READMEs.
- **Vault Provider README** — Updated mint methods table with all new methods (`static_aws`, `static_apikey`, `dynamic_gcp`, `oauth2`) and added configuration reference sections.

## [v0.8.0] — 2026-04-04

### Breaking Changes

- **`apikey` replaces per-provider source types** — The source types `anthropic`, `openai`, `mistral`, `slack`, and `pagerduty` have been removed. A single `apikey` driver type handles all static API key providers. Existing sources must be recreated with `--type=apikey` and explicit config fields. Source type constants `SourceTypeAnthropic`, `SourceTypeOpenAI`, `SourceTypeMistral`, `SourceTypeSlack`, and `SourceTypePagerDuty` are removed from the Go API.

- **`oauth2` replaces `pagerduty_oauth2`** — The `pagerduty_oauth2` source type has been removed. A single `oauth2` driver type handles all OAuth2 client credentials providers. `token_url` is now a required field (no provider-specific defaults). Source type constant `SourceTypePagerDutyOAuth` is removed from the Go API.

### New Features

- **Generic API Key Driver (`apikey`)** — Single config-driven credential source driver for any API key provider. Configurable via source config: `api_url`, `verify_endpoint`, `verify_method`, `auth_header_type` (`bearer`/`token`/`custom_header`), `auth_header_name`, `extra_headers` (comma-separated `key:value` pairs for static headers like `anthropic-version:2023-06-01`), `optional_metadata` (comma-separated spec fields to forward), and `display_name`.

- **Generic OAuth2 Driver (`oauth2`)** — Single config-driven credential source driver for any OAuth2 client credentials provider. Configurable via source config: `client_id`, `client_secret`, `token_url` (required), `default_scopes`, `verify_url`, `verify_method`, `auth_header_type`, `auth_header_name`, and `display_name`.

### Removed

- **`static_apikey_providers.go`** — Per-provider config definitions (`AnthropicProvider`, `OpenAIProvider`, `MistralProvider`, `SlackProvider`, `PagerDutyProvider`) and the `APIKeyProviderConfig` struct.
- **`OAuth2ProviderConfig`** — Per-provider OAuth2 config definitions (`PagerDutyOAuth2Provider`) and the `OAuth2ProviderConfig` struct.
- **`AuthHeaderFunc`** type — Replaced by declarative `auth_header_type`/`auth_header_name` config fields.

### Documentation

- **Provider READMEs** — Updated all credential source creation examples and config reference tables for the generic `apikey` and `oauth2` driver types (Anthropic, OpenAI, Mistral, Slack, PagerDuty).

## [v0.7.0] — 2026-04-03

### New Features

- **PagerDuty Provider** — New streaming gateway provider for the PagerDuty REST API v2. Proxies requests to incidents, services, users, schedules, and escalation policies with automatic credential injection. Supports two credential modes: static API tokens and OAuth2 client credentials.

- **Generic OAuth2 Client Credentials Driver** — New reusable credential driver that exchanges `client_id`/`client_secret` for bearer tokens via the standard OAuth2 client credentials grant (RFC 6749). Parameterized by an `OAuth2ProviderConfig` struct — adding a new OAuth2 provider requires only a config definition, no custom driver code. PagerDuty is the first provider to use it; future OAuth2 providers (Datadog, Twilio, etc.) can reuse it directly.

- **OAuth Bearer Token Credential Type** — New `oauth_bearer_token` credential type for OAuth2-minted bearer tokens. Tokens have a TTL from the provider's `expires_in` response and are minted on demand when leases expire. Primary field is `api_key` for compatibility with `BearerAPIKeyExtractor`.

- **HTTP Proxy Framework** — Extracted a generic `httpproxy` framework from the provider implementations. All streaming providers (Anthropic, GitHub, GitLab, Mistral, OpenAI, PagerDuty, Slack) now share a single `ProviderSpec`-based implementation, reducing per-provider code from ~500 lines to ~30 lines. (#114)

- **Credential Type Inference** — The `--type` flag on `warden cred spec create` is now optional. When omitted, the credential type is inferred from the source driver via `InferCredentialType`. All provider READMEs updated to omit the flag. (#111)

- **Slack Provider** — New streaming gateway provider for the Slack Web API with body parsing for policy evaluation on request fields (channel, text, user). (#97)

- **`?role=` Query Parameter** — Non-gateway backends now accept a `?role=` query parameter as an alternative to the `X-Warden-Role` header or URL path segment. (#108)

### Improvements

- **Unified Static API Key Driver** — Replaced four separate API key drivers (Anthropic, OpenAI, Mistral, Slack) with a single `StaticAPIKeyDriver` parameterized by `APIKeyProviderConfig`. (#111)

### Bug Fixes

- **SQL Server Removal** — Removed SQL Server physical storage backend. (#92)
- **CI Permissions** — Added explicit permissions block to CI workflow. (#99)

### Infrastructure

- **Test Coverage** — Increased test coverage across all packages. (#110)
- **Badges** — Added pkg.go.dev and Codecov badges. (#109)
- **Dependency Updates** — Bumped Go minor/patch dependencies. (#98)

### Documentation

- **Provider READMEs** — Removed `--type` from all `cred spec create` examples (now inferred). Added PagerDuty provider README with full quickstart for both static API token and OAuth2 client credentials modes.

## [v0.6.0] — 2026-03-27

### Breaking Changes

- **Transparent is Now the Only Authentication Mode** — The `token_type` field has been removed from auth method configs and roles. All authentication is now implicit: JWT backends always use `jwt_role`, cert backends always use `cert_role`. The `"warden"` token type alias and `warden_crypto_token` are no longer available. Existing stored roles are migrated automatically on load.

- **Explicit Login Blocked** — Calling `/auth/jwt/login` or `/auth/cert/login` directly now returns `400 Bad Request` for all roles. Clients authenticate implicitly by passing their JWT or certificate directly to the gateway endpoint.

- **`transparent_mode` Config Field Removed** — The `transparent_mode` boolean on provider configs has been removed. The `auto_auth_path` field (required on all providers) controls which auth backend is used for implicit authentication. Remove `"transparent_mode": true` from existing provider config payloads.

### New Features

- **AWS Transparent Mode with SigV4 Re-signing** — The AWS provider now supports transparent mode. AWS SDK clients authenticate via JWT or TLS certificate without Warden-specific tokens. The gateway intercepts SigV4-signed requests, verifies the client signature, then re-signs with real AWS credentials. Supports `aws-chunked` streaming uploads (S3 PutObject) by stripping chunk signatures and forwarding the decoded body. (#89)

- **RDS Provider (Access Backend)** — New provider type that vends credentials directly instead of proxying traffic. The RDS provider issues short-lived IAM authentication tokens for PostgreSQL and MySQL on RDS/Aurora. Introduces the access backend framework for credential-vending providers. (#88)

- **TLS in Dev Mode** — New `--dev-tls` and `--dev-tls-san` flags generate a self-signed TLS certificate at startup, enabling HTTPS in development without manual certificate management. (#86)

### Removed

- **`warden_crypto_token`** — The self-contained barrier-encrypted token type has been removed along with all crypto token code paths.

- **`token_type` API Field** — Removed from auth method config and role endpoints. The field is no longer accepted in write requests or returned in read responses.

- **`ValidTokenTypes` Backend Config** — Removed from the internal `logical.BackendConfig` struct. Auth backends no longer receive or validate a list of allowed token types.

### Infrastructure

- **SigV4 E2E Test Fix** — Fixed SigV4 forwarding tests that incorrectly treated HTTP 403 from upstream AWS (fake credentials rejected) as a Warden signature verification failure.

### Documentation

- **Provider READMEs** — Removed `token_type` and `transparent_mode` from all config examples and reference tables. Removed "Explicit Login with Certificates" sections. Updated quickstart instructions with PATH export steps. (#83, #84, #85)

## [v0.5.0] — 2026-03-20

### New Features

- **Anthropic AI Provider** — Native Anthropic provider with streaming gateway proxy, transparent mode, and policy evaluation on AI request fields (model, max_tokens, stream, temperature). Injects `x-api-key` and `anthropic-version: 2023-06-01` headers (differs from OpenAI/Mistral Bearer auth). Token extraction supports `X-Warden-Token`, `x-api-key`, and `Authorization: Bearer` for native Anthropic SDK, Claude Code, and Claude Desktop compatibility. Credential driver with SpecVerifier validates API keys at spec creation via `GET /v1/models`. (#81)

- **Warden Crypto Token** — New `warden_crypto_token` self-contained token type for stateless token validation. (#77)

- **`@file` Support for Write Command** — The `warden write` command now supports `@file` syntax to read values from files. (#72)

### Bug Fixes

- **X-Warden-Token Header** — Fixed token header handling and updated README logo. Fixed namespace list flag. (#73)

- **Remove OpenBao Internal Packages** — Removed dependency on OpenBao internal packages and added listener address logging. (#78)

### Documentation

- **Anthropic Provider README** — Full quickstart guide with JWT/cert auth setup, credential source/spec creation, policy examples (model restrictions for Claude models), Anthropic SDK, Claude Code, and Claude Desktop usage examples.

- **README Badges** — Added OpenBao Integrator, CI, release, Go Report Card, license, and Go version badges. (#74)

- **Cert Auth TLS Prerequisite** — Documented that certificate authentication requires TLS on the Warden listener. (#72)

### Infrastructure

- **Dependency Updates** — Bumped `dorny/paths-filter` from 3 to 4 (#75), updated Go minor/patch dependencies (#80), bumped `google.golang.org/grpc` to 1.79.3 (#79).

## [v0.4.1] — 2026-03-13

### Bug Fixes

- **AWS SigV4 Content-Length Signature Mismatch** — Fixed AWS gateway signature verification failing on all POST requests (EC2, DynamoDB, etc.). The AWS SDK v4 signer automatically includes `content-length` in canonical headers when `ContentLength > 0`, but most AWS clients (including the AWS CLI) do not sign `content-length`. The server now respects the client's `SignedHeaders` list and only includes `content-length` in the canonical request when the client actually signed it.

## [v0.4.0] — 2026-03-12

### New Features

- **TLS Certificate Authentication Method** — New `cert` auth backend supporting direct mTLS (client certificate from the TLS connection) and forwarded certificate modes (via X-Forwarded-Client-Cert / X-SSL-Client-Cert headers). Role-based constraints include allowed common names, DNS/Email/URI SANs (glob patterns), organizational units, and organizations. Principal identity can be extracted from CN, DNS SAN, Email SAN, URI SAN, serial number, or SPIFFE ID. Certificate revocation is supported via CRL, OCSP, or best-effort (OCSP with CRL fallback). Per-role or global CA certificate bundles for chain validation. Fingerprint-based token caching in transparent mode. Generic error messages prevent information leakage.

- **SPIFFE Support Across Auth Methods** — Both the JWT and cert auth methods now support SPIFFE workload identities. In cert auth, the `spiffe_id` principal claim extracts the SPIFFE URI from X.509 SVIDs, and `allowed_uri_sans` constraints use segment-aware pattern matching (`+` = one segment, `*` = one or more trailing segments, e.g. `spiffe://+/ns/*/sa/*`). In JWT auth, new `bound_uri_patterns` and `uri_claim` role fields validate SPIFFE JWT-SVIDs using the same pattern syntax.

- **Certificate Auth CLI Client** — The `warden login` command now supports certificate-based login via the `cert` method. Flags: `--cert` and `--key` (or env vars `WARDEN_CLIENT_CERT` / `WARDEN_CLIENT_KEY`). Custom mount path via `--mount` / `--path`.

- **`WARDEN_ROLE` Environment Variable** — The role used by all `warden` CLI commands can now be set via the `WARDEN_ROLE` environment variable (or the global `--role` / `-r` flag). The flag sets the env var internally, so any sub-command automatically picks it up without repeating it per invocation.

- **X-Warden-Role Header** — Clients can now specify their auth role via the `X-Warden-Role` HTTP header. Role resolution precedence (highest to lowest): URL-embedded role path → `X-Warden-Role` header → provider `default_role` → auth method `default_role`. The header is stripped before the request is proxied upstream.

- **Default Role on Auth Methods** — JWT and cert auth methods now support a `default_role` config field used as the final fallback in transparent mode role resolution.

- **Simplified Token Type API** — The `token_type` field on roles and auth method configs now accepts three user-facing aliases instead of internal names: `transparent` (replaces `jwt_role` / `cert_role`), `warden` (replaces `warden_token`), and `aws` (replaces `aws_access_keys`). The API reads back the alias, not the internal name. Internal names are still accepted for backwards compatibility. Default changes from required to `transparent`.

### Bug Fixes

- **Director LB Forwarding** — Fixed standby Director failing to set `X-Forwarded-For` when `RemoteAddr` is a bare IP (no port) after `middleware.RealIP` processing. The Director now falls back to `net.ParseIP` when `SplitHostPort` fails. (#68)

- **Transparent Mode IP Binding** — Fixed IP binding enforcement in transparent mode by injecting `ClientIP` into context during `performImplicitAuth` and returning `ErrOriginViolation` immediately instead of falling through to create a new token. (#68)

### Security

- **Explicit Login Blocked for Transparent Roles** — Calling the login endpoint directly on a role with `token_type=transparent` now returns `400 Bad Request`. Transparent roles authenticate inline during a gateway request; explicit login would hand a raw backend token to the caller, defeating the transparent mode isolation guarantee.

- **Removed X-Warden-Auth-Path Header** — The per-request auth path selection header has been removed. Auth backend selection is now config-only (`auto_auth_path` on the provider or namespace), preventing clients from downgrading to a weaker auth method.

- **Type-Aware Bound Claims Comparison** — JWT bound claims now use strict type-aware comparison, preventing implicit string coercion vulnerabilities.

- **CRL/OCSP Security Hardening** — CRL signature verification against the issuer certificate; HTTP redirects are blocked on CRL and OCSP fetches; OCSP nonces enabled by default.

### Infrastructure

- **TLS PeerCertificates Fallback** — When no forwarding header is present, the cert auth middleware now reads `r.TLS.PeerCertificates` directly, enabling cert auth in TLS passthrough scenarios (no load balancer TLS termination). (#67)

- **IP Binding E2E Tests** — Added 16 e2e subtests covering IP binding enforcement across optional and required policies, JWT and cert auth, JWT and cert auth modes. Simplified CI e2e test command to use `./e2e/...` instead of listing individual packages. (#68)

- **Docker Build Image** — Upgraded the build container from `golang:1.26.0-alpine` to `golang:1.26.1-alpine`.

- **CI Updates** — Bumped `docker/login-action` to v4 (#64) and `docker/setup-buildx-action` to v4 (#65).

- **Dependency Updates** — Updated `go-crypto` to 1.4.0, AWS SDK patches, and various `golang.org/x/*` packages. (#66)

## [v0.3.0] — 2026-03-05

### New Features

- **Runtime Conditions for CBP Policies** — Policies now support a `conditions` block that restricts access based on runtime context, even when capabilities match. Supported condition types: `source_ip` (CIDR ranges or bare IPs, IPv4/IPv6), `time_window` (time-of-day windows with timezone, including midnight-spanning ranges), and `day_of_week` (3-letter abbreviations). Condition types are AND-ed (all must be satisfied), values within each type are OR-ed (at least one must match). Conditions are validated at policy parse time, not per-request. Paths without conditions work as before. When multiple policies apply to the same path, OR semantics apply: if any policy has no conditions, access is unconditional.

### Documentation

- **Provider README updates** — All 8 provider READMEs (AWS, Azure, GCP, GitHub, GitLab, Vault, Mistral, OpenAI) now include runtime conditions examples showing how to protect destructive or costly operations on specific paths.

### Infrastructure

- **CI release gating** — Release workflow now requires unit and e2e tests to pass before publishing. (#56)

## [v0.2.1] — 2026-03-05

### Improvements

- **Configurable HA cluster tuning** — All HA cluster timeouts and intervals are now configurable via HCL: `goroutine_shutdown_timeout`, `lock_acquisition_timeout`, `leader_cleanup_interval`, `step_down_state_lock_timeout`, `leader_lookup_timeout`, `clock_skew_grace`, `cluster_listener_read_timeout`, `cluster_listener_write_timeout`, `forwarding_timeout`. Sensible defaults are provided via `DefaultClusterConfig()`.
- **Parallel goroutine shutdown** — Background goroutines (key upgrade checker, leader refresh, leader cleanup) now shut down in parallel during step-down with a configurable timeout, preventing sequential hangs.
- **Lock acquisition timeout** — HA lock acquisition can now be bounded with `lock_acquisition_timeout` to prevent indefinite blocking when the lock backend is unresponsive.
- **Leader lookup timeout** — Barrier reads in `Leader()` are now bounded by `leader_lookup_timeout` to prevent standby nodes from hanging on slow storage.
- **Step-down state lock timeout** — Step-down no longer blocks indefinitely waiting for the state lock; falls back to forced teardown after `step_down_state_lock_timeout`.
- **Leader advertisement failure aborts leadership** — If the active node fails to write its leader advertisement, it immediately steps down instead of running invisibly to standbys.
- **Forwarding metrics** — Added `ha.forward.{success,error,redirect,duration}` metrics for observability into standby-to-active request forwarding.
- **X-Forwarded-For chain preservation** — Standby forwarding now appends to existing `X-Forwarded-For` headers instead of overwriting them, preserving the full proxy chain.
- **Narrower connection error detection** — `isConnectionError` now only matches `dial`, `read`, and `write` operations, excluding DNS and TLS errors from connection-error handling.
- **Fresh leader lookup on forwarding errors** — Non-connection forwarding errors (e.g., TLS handshake failures) now trigger a fresh leader lookup before redirecting, avoiding stale addresses.
- **Idle connection cleanup on proxy invalidation** — Old transport connections are closed when the reverse proxy is recreated due to leader changes.
- **Configurable clock skew grace** — Cluster certificate `NotBefore` offset is now configurable via `clock_skew_grace` (default: 60s, was 30s).
- **Reduced leader cleanup interval** — Default leader advertisement cleanup interval reduced from 24h to 1h.

### Infrastructure

- **Sequential E2E tests** — E2E test packages now run sequentially (`-p 1`) to prevent HA chaos tests from destabilizing subsequent test suites.

## [v0.2.0] — 2026-03-04

### New Features

- **High Availability with Standby Nodes** — Active/standby HA using PostgreSQL advisory locks for leader election. Standby nodes forward requests to the leader via mTLS reverse proxy. Automatic failover when the leader becomes unavailable, with sealed-node protection to prevent forwarding to unhealthy nodes. Health and status endpoints (`sys/health`, `sys/leader`, `sys/seal-status`, `sys/init`, `sys/ready`) are served locally by standby nodes without forwarding. (#54)
- **OpenAI AI Provider** — Native OpenAI provider with transparent gateway mode. (#52)
- **Mistral AI Provider** — Native Mistral AI provider with transparent gateway mode. (#50)
- **Opt-in Request Body Parsing for Streaming Requests** — Streaming requests can now opt in to request body parsing for policy evaluation while preserving the original stream. (#49)
- **E2E Test Suite** — Comprehensive end-to-end tests running against a 3-node HA cluster covering cluster health, HA failover, request forwarding, provider integration, credential management, rotation, namespaces, seal/unseal, authentication, audit logging, and concurrency.

### Bug Fixes

- **SigV4 Host Header Preservation** — Fixed AWS SigV4 signature verification failure when requests are forwarded through standby nodes. The reverse proxy no longer rewrites the `Host` header, preserving the original value needed for signature verification. (#54)
- **Dependabot Unblocked** — Fixed broken OpenBao sub-module references that prevented Dependabot from running. (#35)

### Infrastructure

- **Go 1.26.0** — Upgraded from Go 1.25.1. (#48)
- **CI Updates** — Bumped `actions/checkout` to v6, `actions/setup-go` to v6, `goreleaser/goreleaser-action` to v7. (#36, #37, #38)
- **Dependency Updates** — Updated `github.com/cloudflare/circl`, `github.com/go-chi/chi`, and various Go module dependencies. (#41, #42, #44, #47)

## [v0.1.1] — 2025-12-22

### Bug Fix

- **fix: handle custom dev root tokens in LookupToken** — `LookupToken` failed with `"failed to detect token type"` when using `--dev-root-token` with a custom value that lacks a standard prefix. Added the same dev-mode fallback that `ResolveToken` already had. (#33)

## [v0.1.0] — 2025-12-21

Initial release. See the [v0.1.0 release notes](https://github.com/stephnangue/warden/releases/tag/v0.1.0) for the full feature list.

### Highlights

- Identity-aware egress gateway for cloud and SaaS services
- Providers: AWS, Azure, GCP, GitHub, GitLab, Vault/OpenBao
- Transparent and explicit gateway modes
- JWT authentication with JWKS validation
- Capability-based policy enforcement
- Request-level audit trail
- IP-bound sessions
- Two-stage credential rotation
- Seal/unseal with envelope encryption
- Namespace isolation
- Storage backends: in-memory, file, PostgreSQL
- Docker image published to `ghcr.io/stephnangue/warden`
- Pre-built binaries for Linux, macOS, and Windows

[v0.10.0]: https://github.com/stephnangue/warden/compare/v0.9.1...v0.10.0
[v0.9.1]: https://github.com/stephnangue/warden/compare/v0.9.0...v0.9.1
[v0.9.0]: https://github.com/stephnangue/warden/compare/v0.8.0...v0.9.0
[v0.8.0]: https://github.com/stephnangue/warden/compare/v0.7.0...v0.8.0
[v0.7.0]: https://github.com/stephnangue/warden/compare/v0.6.0...v0.7.0
[v0.6.0]: https://github.com/stephnangue/warden/compare/v0.5.0...v0.6.0
[v0.5.0]: https://github.com/stephnangue/warden/compare/v0.4.1...v0.5.0
[v0.4.1]: https://github.com/stephnangue/warden/compare/v0.4.0...v0.4.1
[v0.4.0]: https://github.com/stephnangue/warden/compare/v0.3.0...v0.4.0
[v0.3.0]: https://github.com/stephnangue/warden/compare/v0.2.1...v0.3.0
[v0.2.1]: https://github.com/stephnangue/warden/compare/v0.2.0...v0.2.1
[v0.2.0]: https://github.com/stephnangue/warden/compare/v0.1.1...v0.2.0
[v0.1.1]: https://github.com/stephnangue/warden/compare/v0.1.0...v0.1.1
[v0.1.0]: https://github.com/stephnangue/warden/releases/tag/v0.1.0
