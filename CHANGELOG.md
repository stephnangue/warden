# Changelog

All notable changes to Warden are documented in this file.

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

[v0.2.1]: https://github.com/stephnangue/warden/compare/v0.2.0...v0.2.1
[v0.2.0]: https://github.com/stephnangue/warden/compare/v0.1.1...v0.2.0
[v0.1.1]: https://github.com/stephnangue/warden/compare/v0.1.0...v0.1.1
[v0.1.0]: https://github.com/stephnangue/warden/releases/tag/v0.1.0
