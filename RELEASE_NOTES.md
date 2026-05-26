## Warden v0.14.0

**Warden is the secure gateway connecting AI agents to the enterprise systems they need to do real work.** Agents discover what they're allowed to access, Warden brokers every connection, and operators get one control plane for identity, policy, and audit — across every cloud, code-host, observability stack, database, and SaaS the agent reaches. No upstream credentials ever reach the agent: Warden authenticates the caller (JWT or TLS certificate), evaluates fine-grained policy at request time, and injects short-lived credentials before forwarding.

v0.14.0 lands per-call agent attribution in the audit log — both unverified (`X-Warden-On-Behalf-Of` header) and verified (RFC 8693 `act` claim) — so an MCP-style concentrator that authenticates to Warden once and forwards calls for many upstream agents is no longer a black box at audit time. The audit-config story moves from "auto-magic on first unseal" to "declared in HCL, registered before the listener accepts traffic." A new `X-Warden-Provider` header lets non-agent clients (legacy SDKs, hand-rolled curl) reach a provider mount without rewriting URLs. The CLI gains Vault-style single-dash long flags, a `-path` flag on every path-taking command, a top-level `warden status`, and a `:debug` Docker image variant published alongside `:nonroot`. Seven small breaking changes — read the **Upgrading** section before bumping.

### Breaking Changes

- **`auth enable`, `provider enable`, `audit enable` take TYPE as a positional, like Vault.** The `-type` flag is gone. Migration: `-type=jwt jwt-prod` → `-path=jwt-prod jwt`; `-type=aws` → `aws`. The mount path still defaults to TYPE; override with `-path=<mount>`. In `-json` mode the payload's `type` field, if present, must match the TYPE positional or the CLI rejects with a usage error.

- **JWT auth: `mode` field removed from `auth/{mount}/config`.** `mode=jwt|oidc` was redundant with the three mutually-exclusive key-source fields (`oidc_discovery_url`, `jwks_url`, `jwt_validation_pubkeys`) — the backend can derive everything it needs from which one is set. Exactly one of those three must now be provided. Existing scripts passing `mode=...` emit a framework warning but continue to succeed.

- **`X-Warden-Role` header now overrides any role embedded in the URL path.** Previously a role in the URL took priority over the header; now the header wins unconditionally in both routing modes, matching the precedence of the new `X-Warden-Provider`. The in-tree skills, the Helm chart, and the CLI never produce the URL-role + header-role combination, so the affected surface is likely zero — but any caller relying on URL-role winning over a stray `X-Warden-Role` must drop the header or align it with the URL.

- **`/v1/sys/health` and `/v1/sys/leader`: `is_self` is renamed to `is_leader`.** Symmetric across both endpoints. Update any external script that grepped for `"is_self":` against these endpoints.

- **`/v1/sys/health`: `server_time_utc` (int64 Unix seconds) is replaced with `server_time` (RFC3339 string).** Human-readable and sortable as text. The old integer field is gone, not aliased.

- **Listener HCL: `tls_enabled` is replaced by `tls_disable` (TLS on by default).** Drop `tls_enabled = true`; replace `tls_enabled = false` with `tls_disable = true`. Validation now rejects a listener that neither disables TLS nor supplies both `tls_cert_file` and `tls_key_file`. Dev mode sets `tls_disable = true` automatically; the shipped sample HCL, the e2e configs, and the Helm chart's listener template were all updated.

- **Audit auto-default device on first unseal is removed.** The Helm chart ships a working `audit "file"` block by default (see Upgrading); dev mode intentionally ships no audit; bare-binary operators add a one-line HCL block, or bootstrap via API (the broker now fail-opens at zero registered devices so the API path is reachable from a freshly-installed cluster).

### New Features

- **Audit log: per-call actor attribution for delegated chains.** A new `actors` array on `audit.Auth` carries `{subject, verified}` entries from two sources: unverified subjects via the `X-Warden-On-Behalf-Of` request header (regex-validated, gated on an authenticated principal so an unauthenticated caller cannot plant an actor), and verified subjects via the standard RFC 8693 §4.1 `act` claim on JWTs from IdPs that mint act-tokens for delegation. The header is added to every provider strip-list so it never leaks upstream. MCP-style concentrators that fan out per-agent calls under one Warden identity now produce an audit log a security team can actually correlate.

- **`X-Warden-Provider` header for mount routing.** Non-agent clients (legacy SDKs that take a single-string `base_url`, hand-rolled curl, scripted tools) can now reach a provider mount without rewriting the URL: send the request to `/v1/<literal-upstream-api-path>` with `X-Warden-Provider` naming the mount and `X-Warden-Role` naming the role, and the server synthesises the canonical `<mount>/role/<role>/gateway/<api>` shape before mount lookup. Multi-segment mount paths (`gitlab/prod`) are accepted; empty path segments and bare `..` are rejected as 400; unknown mounts fall through to the existing 404. Combined with a SigV4 Authorization header the call is refused with 400 (rather than silently invalidating the client signature and surfacing as 401). New `api.Client.SetProvider` / `WithProvider` helpers mirror the existing role/namespace pattern.

- **`warden status` subcommand, plus cluster-aware `/v1/sys/health`.** A new top-level CLI command that wraps `/v1/sys/health` and reports init/seal/standby/leader/active-since/version in one round-trip — exit code `0` on a healthy node (active or standby), `7` on a transport error, `10` when sealed-or-uninit, scriptable for operator playbooks. The endpoint grew `ha_enabled`, `is_leader`, `leader_address`, `active_time` (RFC3339, only set on the active leader), and `version` (server build) so external tooling no longer needs three round-trips to assemble a status view. Leader lookup is gated on `!sealed && ha_enabled`, so a sealed HA node no longer logs an error on every k8s probe.

- **JWT static public keys (`jwt_validation_pubkeys`) now work.** The field has lived in the config schema for several releases but the backend returned "not yet implemented" at runtime. PEM-encoded RSA and ECDSA keys now validate JWT signatures against a static keyset — no JWKS endpoint required, suitable for air-gapped clusters, CI/CD pipelines, and fixed-issuer workloads where neither OIDC discovery nor a reachable JWKS endpoint is available. `jwks_url` and `jwt_validation_pubkeys` are mutually exclusive within a single mount.

- **Audit devices declared in the HCL server config.** A new `audit "TYPE" "PATH" { description = "..." options = { ... } }` block registers devices *before the API listener accepts traffic* — a misconfigured sink (unwritable path, missing parent directory, permission denied) is a hard startup error, not a half-initialized cluster that takes requests and drops audit. Declarative (HCL) and imperative (API-enabled) devices coexist at different paths; an HCL block colliding with an API-enabled path refuses to start, and declarative devices cannot be modified or deleted via `sys/audit/{path}` (operators edit HCL and restart instead). The reconciler on every unseal preserves each entry's accessor and HMAC salt across restarts so audit-log HMACs stay stable. `GET /v1/sys/audit` responses now carry a `declarative` boolean so operators can tell the two origins apart.

- **`:debug` Docker image variant published alongside `:nonroot`.** Same multi-arch binary on `gcr.io/distroless/static-debian12:debug-nonroot` instead of the production distroless base — so operators can `kubectl exec -- sh` into a pod and inspect `/config`, `/app`, and the filesystem when something goes wrong. Swap `image.tag=v0.14.0-debug` for the day and back when done; UID, GID, entrypoint, exposed port, and the `/config` mount contract are identical to the production image.

- **CLI accepts Vault-style single-dash long flags.** Cobra/pflag is POSIX-strict, so `-format=json` would otherwise parse as `-f` taking value `ormat=json` and fail. A new normalizer rewrites single-dash long-flag tokens to double-dash before flag parsing; short flags, `--`, and genuine typos pass through unchanged so error paths still fire. All operator-facing docs (READMEs, CHANGELOG, tutorial scripts, provider docs, cobra help text) switched to the single-dash convention to match Vault muscle memory.

- **`-path` long flag on every path-taking CLI command.** `audit/auth/provider enable|disable|read` and the basic `read|write|delete|list` commands all accept the mount path as `-path=<mount>` as an alternative to the trailing positional, so `vault secrets enable -path=foo aws` ports verbatim. Existing positional usage is unchanged.

- **Server config: warn-and-ignore unknown HCL keys.** A typo or stale field in `warden.hcl` (think `cluster_name`, `ui`, `default_lease_ttl`) used to crash startup with an opaque `gohcl` error. The loader now walks the body against the schemas derived from `Config{}` and its nested blocks, deletes any unrecognized attribute or block, and emits one `[WARN] config: ignoring unknown attribute "X" at <file:line:col>` line on stderr per removal so the typo stays visible. Known fields still parse and validate exactly as before — this is a one-way relaxation, not a schema loosening.

### Bug Fixes

- **Audit broker is fail-open at zero registered devices.** Previously `auditManager.LogRequest/LogResponse` returned `(continue=false, nil)` when no devices were registered, causing the request handler to block every non-streaming request with HTTP 500 — including `sys/audit/{path}`, so a freshly-installed cluster with no audit had no way to bootstrap one via the API. The broker now short-circuits to `(true, nil)` when zero devices are registered. Once any device is registered (HCL or API) the broker becomes fail-closed again; running ≥2 devices is recommended to avoid wedge-lockout if one sink blocks.

- **`POST /v1/sys/audit/{path}` (disable) no longer refuses to remove the last audit device.** The previous "cannot disable the last audit device: fail-closed mode" gate is gone — with the broker now fail-opening at zero, removing the last device is a valid operator choice. Declarative HCL-owned devices remain protected with a clear error.

- **`warden operator init` honours `-o json` / `WARDEN_OUTPUT=json`.** The init banner used to render regardless of the global output flag, breaking IaC tooling that piped its output expecting the JSON envelope every other format-aware command produces. Init now returns `{unseal_keys, unseal_keys_base64, recovery_keys, recovery_keys_base64, root_token}` in JSON mode (with empty slices as `[]`, not `null`, so Shamir and auto-unseal share a stable schema). The human banner is preserved verbatim in table mode.

### Documentation

- **AWS access hygiene tutorial.** End-to-end demonstration of the *within-provider* dimension of discover-and-connect: a Goose agent audits IAM in a sandbox AWS account through four read-only lenses (inventory, recent usage, external exposure, effective access), publishes findings to Security Hub as ASFF, and posts a summary canvas to Slack — switching Warden roles between calls within a single AWS mount, with each role assuming a distinct narrowly-scoped IAM role via STS. Warden holds only the broker IAM user's static keys; the agent declares per-call intent via `AWS_ACCESS_KEY_ID`, and the audit log records each declared intent as `auth.role_name`. A hallucinated cross-role write — e.g. `BatchImportFindings` under the `iam-reader` intent — surfaces to the caller as a `permission denied` from AWS (the assumed role's narrow IAM policy refuses, not Warden's gateway policy), and the audit log captures the declared intent in `auth.role_name` so the deny pattern is identifiable after the fact as a hallucination signature.

- **Kubernetes deployment guide gains a "Debugging inside the Warden container itself" subsection** covering the new `:debug` image variant and the swap-and-revert pattern.

### Infrastructure

- **Helm-smoke CI guardrail.** `helm lint` and `kubeconform` validate manifest shape but never *run* it. Three classes of bug shipped past that gate recently (broken HCL inside a rendered ConfigMap in v0.13.1, image tag mismatches, read-only-filesystem path collisions). A new `helm-smoke` job boots a real `kind` cluster, builds and loads a smoke image, installs the chart, runs `warden operator init`, asserts the chart-provisioned declarative audit device registered, and dumps `kubectl get all` + events + the last 200 lines of `warden-0` logs on any failure. Reproducible locally with `bash deploy/helm/warden/ci/smoke.sh`.

### Upgrading

```bash
helm upgrade warden oci://ghcr.io/stephnangue/charts/warden \
  --version 0.3.0 \
  -n warden --reset-then-reuse-values
```

Chart `0.2.0` → `0.3.0`. Two template-side changes the operator should be aware of:

- The listener template no longer emits `tls_enabled = true` (TLS is now the binary's default). Existing values files apply as-is.
- A new `audit:` value subtree (enabled, type, name, description, filePath) renders a declarative `audit "file"` block in the ConfigMap, taking the place of the removed auto-default-on-first-unseal logic. Defaults to `enabled: true` writing to `/var/log/warden/audit.log` (the StatefulSet's pre-existing emptyDir mount). Set `audit.enabled=false` to ship zero audit declarations and bootstrap via API instead.

The binary changes covered by **Breaking Changes** are mostly transparent to a Helm install — the chart provides correct HCL out of the box — but scripted operator workflows that wrap `warden auth enable -type=...`, parse `is_self` / `server_time_utc` from `/v1/sys/health`, or pass `mode=jwt` on JWT auth config writes need updating.

### Resources

- New installs and detailed upgrade procedures: [docs/deployment/kubernetes.md](https://github.com/stephnangue/warden/blob/main/docs/deployment/kubernetes.md) — includes the new "Debugging inside the Warden container itself" subsection for the `:debug` image variant.
- Full provider list, auth-method reference, and per-provider guides: [README](https://github.com/stephnangue/warden#readme).

### License

[MPL-2.0](https://github.com/stephnangue/warden/blob/main/LICENSE)
