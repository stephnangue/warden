## Warden v0.16.0

v0.16.0 is the SPIFFE release. A new first-class **`spiffe` auth method** accepts a SPIFFE X.509-SVID (over mTLS or a trusted forwarding header) and a SPIFFE JWT-SVID (bearer) on the **same mount**, verifying each against the trust domain's bundle — which carries both the X.509 and JWT key sets — and issuing one token type. Roles bind on `trust_domain`, `allowed_spiffe_ids`, and `bound_audiences`; bundles are managed on the mount and can be **federated** from upstream endpoints with periodic refresh. The method leans on short-lived SVIDs and bundle rotation rather than CRL/OCSP. The control plane itself can now run on SPIFFE: the **API listener can serve its TLS certificate straight from the SPIFFE Workload API**, rotating automatically as the SVID renews. This release also **consolidates the MCP providers** — a single generic `mcp` provider replaces the typed `mcp_github` and `mcp_gcp` — and threads **non-secret subject metadata into the audit log** across the AWS, GCP, Azure, Kubernetes, and Vault sources, so a brokered call records *which* upstream identity acted. Two breaking changes — read the **Upgrading** section before bumping.

### Breaking Changes

- **The `mcp_github` and `mcp_gcp` provider types are removed in favour of a single generic `mcp` provider.** The new `mcp` provider fronts any bearer-authenticated MCP server (GitHub, Google Cloud, Slack, Cloudflare, …) and injects `Authorization: Bearer` for `oauth_bearer_token`, `api_key`, `github_token`, `gcp_access_token`, and `azure_bearer_token` — a superset of the typed providers it replaces. Re-mount as type `mcp` and set `mcp_url` (`https://api.githubcopilot.com/mcp` for GitHub; the operator's URL for Google Cloud). `mcp_aws` is unaffected — it SigV4-signs requests rather than injecting a bearer token.

- **`jwt` auth method: the `bound_uri_patterns` and `uri_claim` role fields are removed.** They provided segment-aware string matching against a JWT claim as a stand-in for real SPIFFE JWT-SVID validation. SPIFFE identities now belong to the new `spiffe` auth method, which verifies a JWT-SVID against a trust-domain bundle and enforces its audience. Stored roles carrying these keys decode cleanly and ignore them — a role that relied on URI-pattern matching becomes more permissive, so migrate it to the `spiffe` method.

### New Features

- **New `spiffe` auth method: first-class SPIFFE support for both SVID types on one mount.** Accepts a SPIFFE X.509-SVID (presented over mTLS or a trusted forwarding header) and a SPIFFE JWT-SVID (bearer) on the same mount, verifying each against the trust domain's bundle and issuing a single `spiffe_role` token type. When a request presents both, the explicitly-presented JWT-SVID wins over an ambient forwarded certificate. Roles bind on `trust_domain`, `allowed_spiffe_ids`, and `bound_audiences`; an audience is required for JWT-SVID logins, as SPIFFE mandates. Trust-domain bundles are managed on the mount and can be federated from upstream endpoints with periodic refresh. There is no X.509-SVID revocation surface — the method relies on short-lived SVIDs and bundle rotation, and an issued token's TTL is capped by the SVID's expiry.

- **The API listener can serve its TLS certificate from the SPIFFE Workload API.** Instead of a static certificate and key on disk, the listener can obtain an X.509-SVID from a SPIFFE Workload API endpoint and rotate it automatically as the SVID is renewed, keeping the control-plane TLS identity short-lived and self-renewing.

- **`cert` auth method consolidated to pure PKI.** The never-shipped experimental SPIFFE mode (`mode=spiffe`, trust-domain config, bundle federation, and the `spiffe_id` principal claim) is removed in favour of the dedicated `spiffe` method. The `cert` method keeps its X.509 chain-of-trust validation and URI-SAN matching (`uri_san` principal claim plus `allowed_uri_sans`), so a SPIFFE X.509-SVID can still be accepted as an ordinary client certificate bound on its URI SAN.

- **Audit-log subject metadata across the cloud and secrets sources.** The AWS, GCP, Azure, Kubernetes, and Vault drivers now populate the non-secret `Credential.Metadata` introduced in v0.15.0 when they mint — the assume-role identity on an AWS STS mint, and the token/access-token subject on the others — so an audit record shows which upstream identity a brokered call acted as, not merely that a call occurred.

### Bug Fixes

- **`httpproxy`: the gateway suffix is forwarded verbatim.** Gateway-suffix path extraction now preserves the upstream path exactly — including trailing slashes — so the SigV4-signed `mcp_aws` gateway's canonical request stays valid.

### Documentation

- Operator README for the new `spiffe` auth method, with SPIFFE content retargeted across the `cert`, `jwt`, and Vault-provider docs to point SPIFFE workloads at the dedicated method.
- `mcp_aws` README: a Claude Code CLI registration step (`claude mcp add`) for pointing Claude Code at an `mcp_aws` mount.
- Root README: a dedicated `spiffe` row in the authentication-methods table.

### Upgrading

```bash
helm upgrade warden oci://ghcr.io/stephnangue/charts/warden \
  --version 0.3.2 \
  -n warden --reset-then-reuse-values
```

Chart `0.3.1` → `0.3.2` is an `appVersion` bump to track the v0.16.0 binary — there are no chart template or values changes, so existing values files apply as-is.

Two operator-facing migrations before bumping:

- **Re-mount any `mcp_github` or `mcp_gcp` provider as type `mcp`** and set `mcp_url` (`https://api.githubcopilot.com/mcp` for GitHub; the operator's URL for Google Cloud). The generic provider reuses the same credential types, so existing credential specs apply unchanged. `mcp_aws` is unaffected.
- **Migrate any `jwt` role that used `bound_uri_patterns` or `uri_claim` to the `spiffe` method.** Those fields are gone; a role that relied on them now ignores them and becomes more permissive until migrated.

### Resources

- New installs and detailed upgrade procedures: [docs/deployment/kubernetes.md](https://github.com/stephnangue/warden/blob/main/docs/deployment/kubernetes.md).
- SPIFFE, MCP, and auth-method setup: [README](https://github.com/stephnangue/warden#readme) and the per-provider and per-method READMEs.

### License

[MPL-2.0](https://github.com/stephnangue/warden/blob/main/LICENSE)
