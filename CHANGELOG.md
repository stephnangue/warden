# Changelog

All notable changes to Warden are documented in this file.

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
