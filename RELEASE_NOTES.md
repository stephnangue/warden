## Warden v0.15.0

v0.15.0 is the MCP release. A new `mcp { }` policy block brings **body-authoritative governance** to MCP (JSON-RPC) traffic — gate by method, tool, resource, prompt, and tool-argument values, with the gateway strict-parsing the request body rather than trusting client-supplied headers — and three new providers carry it: `mcp_github` (transparent proxy to GitHub's hosted MCP server), `mcp_aws` (SigV4-signed gateway to AWS's hosted MCP servers and Bedrock AgentCore), and `mcp_gcp` (bearer-token gateway to a Google Cloud MCP server). The OAuth2 credential source gains an **authorization-code flow**, so a Warden role can broker calls as a *consenting user* — consent captured once through `warden cred spec connect`, refresh tokens rotated and written back automatically. `github` and `gitlab` now proxy **Git smart-HTTP** (`clone` / `fetch` / `push`) on the same mount as their REST API, and a new `kubernetes` auth method validates workload identities via **TokenReview**. Three breaking changes — read the **Upgrading** section before bumping.

### Breaking Changes

- **Transparent-auth role resolution: the provider role-extractor now outranks `default_role`.** The chain is `X-Warden-Role` header > role embedded in the path > the provider's role-extractor hook > the mount's `default_role`. Mounts that combine an extractor with `default_role` change behaviour — `github` Git smart-HTTP, AWS-with-SigV4, and Alicloud-with-ACS3/SigV4 now resolve to the extractor-derived role instead of `default_role`. Mounts without an extractor (or AWS/Alicloud requests that aren't SigV4-signed) are unchanged.

- **`github` provider: the `git_url` config field is removed.** It was declared but never read at runtime. Operators who had it set now get a clear "unknown field" error on config write instead of a silent no-op — drop it; the Git host is derived from `github_url` as before.

- **SDK signature changes for out-of-tree backends.** `StreamBodyParser.ShouldParseStreamBody` and `TransparentModeProvider.IsUnauthenticatedPath` now take the `*http.Request`, and `TransparentAuthRoleExtractor` returns `string` (was `(string, bool)`). In-tree backends are unaffected; only code implementing these interfaces out of tree needs updating.

### New Features

- **OAuth2 authorization-code flow — a Warden role can broker calls as a consenting user.** The `oauth2` source gains an `authorization_code` auth method alongside `client_credentials`, so a credential spec can hold a user's consent rather than a service identity. `warden cred spec connect <name>` runs the one-time browser consent over a loopback callback with PKCE and `state`, and the token exchange happens server-side — the client secret never reaches the operator's machine. Refresh tokens (and their expiry) are rotated and written back automatically under a per-spec lock that serializes concurrent mints. The audit log records which upstream identity acted, per call. `mcp_github` accepts these credentials, so one role can act as a GitHub App, a PAT, or a consenting GitHub user.

- **`mcp { }` policy block: body-authoritative governance of MCP (JSON-RPC) traffic.** A new `mcp { }` block inside a control-by-policy `path` rule gates requests by JSON-RPC `method`, by the `name` in `tools/call` / `resources/read` / `prompts/get`, and by tool-call argument values — each with allow/deny symmetry and case-insensitive trailing-`*` globs. The gateway strict-parses the JSON-RPC body and fails closed on any malformed 2.0 envelope, then evaluates against the parsed body rather than client headers. Opt-in per provider and method-aware (only JSON-RPC POSTs are evaluated, so Streamable HTTP's GET/DELETE pass through). Denials return an OAuth-shaped HTTP 403, and the audit log carries a structured `mcp_decision`.

- **Three new MCP providers.** `mcp_github` transparently proxies GitHub's hosted MCP server (reusing the GitHub credential, so one spec grants both REST and MCP reach). `mcp_aws` SigV4-signs traffic to AWS's hosted MCP servers and Bedrock AgentCore, inferring service and region from the endpoint. `mcp_gcp` mints a short-lived GCP access token per request for a Google Cloud MCP server. All three opt into `mcp { }` enforcement.

- **`github` and `gitlab` Git smart-HTTP.** Both providers now proxy `git clone` / `fetch` / `push` on the same mount that proxies their REST API. Clone URLs carry the Warden role as the Basic Auth username and the Warden JWT as the password, so Git's credential helpers cache cleanly per role. A new `git_max_body_size` config field caps Git request bodies separately from the REST `max_body_size`.

- **`kubernetes` auth method: validate workload tokens via TokenReview.** The first cloud-native member of the transparent-auth family validates a workload service-account token by calling `TokenReview` on the issuing kube-apiserver — no JWKS endpoint required on the spoke, awkward on hardened distros — matching the `auth/kubernetes` shape Vault and OpenBao operators know. The SA UID, namespace, and name land in the audit log for attribution.

- **Provider `tune` endpoint.** `warden provider tune <path> -description=...` updates a mount's description in place; previously this required an unmount and remount.

- **`X-Warden-Provider` requests may omit the `/v1/` prefix.** Header-routed calls (the documented `git clone` form via `http.extraheader`) no longer require the `/v1/` prefix on the path; the middleware prepends it when the header is present. The canonical `/v1/`-prefixed form is unchanged, and `sys/`-targeted requests with the header are rejected with 400.

### Bug Fixes

- **SigV4: client cancellation logs at debug, not error.** A client that disconnects mid-request on a SigV4 provider no longer produces an error-level log line.

### Documentation

- Operator READMEs for the `cert`, `jwt`, and `kubernetes` auth methods.
- `mcp_github` provider docs: authorization-code flow setup around a GitHub App (with a Claude Code `claude mcp add` worked example) and a body-authoritative `mcp { }` policy section.
- `mcp_aws` skill and operator README; `httpproxy` SDK hook reference; root README coverage of the MCP-server providers, on-behalf-of attribution, Kubernetes auth, and credential rotation.

### Upgrading

```bash
helm upgrade warden oci://ghcr.io/stephnangue/charts/warden \
  --version 0.3.1 \
  -n warden --reset-then-reuse-values
```

Chart `0.3.0` → `0.3.1` is an `appVersion` bump to track the v0.15.0 binary — there are no chart template or values changes, so existing values files apply as-is.

The binary breaking changes are mostly transparent to a Helm install, but be aware of three things before bumping:

- **Mounts that set `default_role` together with a role-extractor** (`github` Git smart-HTTP, AWS/Alicloud with SigV4) now resolve to the extractor-derived role instead of `default_role`. Review those mounts if you relied on `default_role` winning.
- **The `github` `git_url` config field is gone** — drop it from any provider config (the Git host is derived from `github_url`).
- **Out-of-tree providers** that implement `StreamBodyParser.ShouldParseStreamBody`, `TransparentModeProvider.IsUnauthenticatedPath`, or `TransparentAuthRoleExtractor` must update those signatures. In-tree providers and a stock Helm install need no changes.

### Resources

- New installs and detailed upgrade procedures: [docs/deployment/kubernetes.md](https://github.com/stephnangue/warden/blob/main/docs/deployment/kubernetes.md).
- MCP, OAuth2, and auth-method setup: [README](https://github.com/stephnangue/warden#readme) and the per-provider READMEs under [provider/](https://github.com/stephnangue/warden/tree/main/provider).

### License

[MPL-2.0](https://github.com/stephnangue/warden/blob/main/LICENSE)
