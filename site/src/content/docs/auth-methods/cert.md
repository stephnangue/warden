---
title: "Certificate"
---

The certificate auth method authenticates workload identities using **TLS client certificates**. The workload presents an X.509 certificate during the TLS handshake (direct mTLS) or via a forwarding header from a trusted proxy; Warden validates the certificate chain against a configured CA bundle, matches the role's constraints over CN / SANs / OU / Organization, resolves a principal from a chosen certificate field, and flows that principal through Warden's transparent-auth layer like any other auth method in the family.

Two properties set certificate auth apart from the bearer-token-based methods (`jwt`, `kubernetes`):

- **Replay-resistant on direct mTLS.** The TLS handshake requires proof-of-possession of the private key; a certificate that leaks through audit logs, a packet capture, or a compromised proxy cannot be re-used by another caller. By contrast, a leaked JWT or K8s SA token is a fully-usable bearer credential until it expires. This property holds end-to-end only when Warden terminates TLS directly — when fronted by a trusted proxy that forwards the certificate in a header, see the trust-boundary note in [How the Certificate Reaches Warden](#how-the-certificate-reaches-warden).
- **No per-call IdP dependency.** Once the workload has its certificate and key, it can authenticate to Warden indefinitely without contacting any external identity service. JWT auth needs to reach the OIDC issuer's JWKS endpoint (at config time, and on key rotation); Kubernetes auth calls TokenReview on the kube-apiserver on every cache-miss login. Cert auth is self-contained.

This is the auth method to reach for when:

- You operate **long-lived workloads** — persistent services, bare-metal or VM workloads outside an orchestrator's token-rotation lifecycle, or anything that runs for weeks to months under the same identity. The cert is rotated on the cadence of the issuing CA / mesh, not on the cadence of an IdP's token TTL.
- You operate in **air-gapped or constrained-network environments** where reaching an external IdP per login is not an option, but a CA bundle can ship with the deployment.
- Your workloads carry **service-mesh-issued certificates** (Istio, Linkerd, Consul Connect) and identity flows through the cert rather than a token.
- Your operators have already provisioned **mTLS at the network edge** and want Warden to consume that same certificate rather than layering a second credential on top.
- You need **revocation checking** built in — CRL or OCSP — so a compromised certificate can be cut off without rotating CAs.

If your workload's identity is a Kubernetes ServiceAccount token, prefer the `kubernetes` auth method. If it's a JWT from an OIDC provider, prefer the `jwt` method. If your workloads present **SPIFFE SVIDs** (X.509-SVID or JWT-SVID) and you want full trust-domain-bound SVID validation, use the dedicated `spiffe` auth method. The cert method is the right tool when a classic X.509 certificate **is** the identity — not when it's just transport encryption.

## Prerequisites

- A **Warden server** unsealed and reachable from the workload's network.
- A **PEM-encoded CA bundle** that issued (or transitively signed) the certificates your workloads present.
- A way to get the workload's certificate to Warden — either direct mTLS termination at the Warden listener, or a trusted reverse proxy that terminates TLS and re-presents the certificate via a forwarding header. See [How the Certificate Reaches Warden](#how-the-certificate-reaches-warden).
- A **role-mapping policy** in Warden that scopes what the resulting auth token can do (authenticating a certificate doesn't grant access on its own).

## Enabling mTLS on the Listener

Certificate auth requires TLS on the Warden listener so the client certificate can be presented during the handshake (mTLS). Two ways to satisfy it:

- **Dev mode.** Use `-dev-tls` to enable TLS with auto-generated certificates, or provide your own with `-dev-tls-cert-file`, `-dev-tls-key-file`, and `-dev-tls-ca-cert-file`. See [Serving TLS](/concepts/dev-server/#serving-tls) and [Requiring client certificates](/concepts/dev-server/#requiring-client-certificates-mtls).
- **Behind a load balancer.** Place Warden behind a proxy that terminates TLS and forwards the client certificate via the `X-Forwarded-Client-Cert` or `X-SSL-Client-Cert` header.

Both paths end at the same certificate extractor — see [How the Certificate Reaches Warden](#how-the-certificate-reaches-warden) for the trust-boundary details.

## Step 1: Configure Trusted CAs

Enable the auth method:

```bash
warden auth enable cert
```

This mounts at `auth/cert/` (the default when `-path` is omitted matches the type). If you need multiple cert mounts — e.g. one per trust domain or per issuing CA — use `-path` to name them:

```bash
warden auth enable -path=cert-prod cert
warden auth enable -path=cert-staging cert
```

The `-path` flag takes the mount name only; the CLI prefixes `auth/` automatically.

Then configure the CA bundle that signs your workload certificates:

```bash
warden write auth/cert/config \
  trusted_ca_pem=@/path/to/ca-bundle.pem \
  principal_claim="cn" \
  default_role="default"
```

`trusted_ca_pem` accepts a concatenated PEM bundle — multiple `-----BEGIN CERTIFICATE-----` blocks back-to-back are all loaded. The mount validates the bundle at write time and rejects PEM with no valid certificates.

When `principal_claim` is omitted, the mount defaults to `cn` (the certificate Subject's CommonName). For service-mesh certificates, `uri_san` or `dns_san` is often the right pick. See [Principal Claim Selection](#principal-claim-selection) for the full list.

## Step 2: Enable Revocation Checking (Optional)

By default the mount runs with `revocation_mode=none` — verified certificate chain plus role constraints, no live revocation check. For environments where compromised certificates need to be cut off without rotating the CA, enable CRL or OCSP:

```bash
warden write auth/cert/config \
  revocation_mode="best_effort" \
  crl_cache_ttl="1h" \
  ocsp_timeout="5s"
```

When revocation checking is enabled, Warden always tries **OCSP first, then CRL** — the mode controls only what happens when both probes return inconclusively. The four modes:

- `none` (default) — chain validation only, no revocation lookup.
- `ocsp`, `crl` — strict modes. Reject the login when OCSP and CRL both fail to return a definitive answer (definitive = "the responder said good" or "the responder said revoked"). The `ocsp` and `crl` names are advisory of operator intent rather than behaviorally distinct: both probes run in both modes.
- `best_effort` — same probing, but allow the login when both probes are inconclusive. Use this when revocation infrastructure is flaky and you'd rather accept the failure mode of "possibly accept a revoked cert" over "reject every login during an OCSP outage."

If either probe definitively says revoked, the login is rejected regardless of mode.

OCSP responses come from the responder URL in the certificate's AIA extension; CRLs come from the distribution-point URL. CRLs are downloaded once and cached per URL (default 1h, configurable via `crl_cache_ttl`); OCSP is queried per login (the cache layer above means most logins skip this entirely — only first-touch and post-TTL re-verifications hit OCSP). Both checks verify the response signature against the issuer from the verified chain, so forged CRLs and replayed OCSP responses are rejected.

## Step 3: Create a Role

A role decides which Warden policies are stamped on the issued token and constrains which certificates the role accepts. At least one certificate constraint is required — wide-open roles that accept any certificate signed by a trusted CA are refused at write time.

```bash
warden write auth/cert/role/inventory-agent \
  allowed_common_names="inventory-*" \
  allowed_organizations="ExampleCorp" \
  token_policies="inventory-read,inventory-write" \
  token_ttl="1h"
```

Available constraint fields (set at least one):

- `allowed_common_names` — glob patterns matched against `Subject.CommonName`. Standard shell globs (`?`, `*`, `[...]`); `inventory-*` matches `inventory-svc`, `inventory-cron`, etc.
- `allowed_dns_sans` — glob patterns matched against any of the certificate's DNS SANs (any-one match accepts).
- `allowed_email_sans` — glob patterns matched against email SANs.
- `allowed_uri_sans` — segment-aware patterns matched against URI SANs (see [URI SAN Patterns](#uri-san-patterns) for the syntax). Plain string matching only — it does not validate the certificate as a SPIFFE SVID.
- `allowed_organizational_units` — exact-match list against the Subject's Organizational Unit values.
- `allowed_organizations` — exact-match list against the Subject's Organization values.

Constraint fields combine with **AND** semantics: when set, every constraint must be satisfied. Within a single constraint with multiple values, **any-one match** accepts.

Per-role overrides:

- `certificate` — role-specific CA PEM that **replaces** the mount's `trusted_ca_pem` for this role. Use when one mount should serve roles backed by different issuing CAs. See [Role-Specific CAs](#role-specific-cas).
- `principal_claim` — overrides the mount's `principal_claim` for this role only.
- `token_ttl` — overrides the mount-level default.
- `cred_spec_name` — name of the credential spec to bind to this role. Downstream provider gateways use it to resolve and mint the upstream credential the workload's request will carry.
- `description` — human-readable purpose, surfaced via introspection so agents can pick the right role.

A role's `TokenType` is always pinned to `cert_role`; operators can't override it.

## Step 4: Wire Up Transparent Auth

The certificate auth method is **transparent-only**. There is no "log in once, get a Warden bearer token" handshake the workload performs explicitly — `POST /auth/<mount>/login` for a `cert_role` token is rejected at the request handler with `explicit login is not supported for roles with token_type=transparent`. The workload's certificate is re-presented (or re-forwarded) on every call, and Warden's transparent middleware does the validation in-line.

The shape:

1. The workload presents its certificate on every request to a Warden gateway URL — either via mTLS directly to Warden, or via mTLS to a trusted proxy that re-forwards the certificate to Warden in a header.
2. Warden resolves the auth mount via the provider's (or namespace's) `auto_auth_path` configuration.
3. Warden validates the certificate chain, runs the configured revocation check, and applies the role's constraints — or, if a prior call with the same (fingerprint, role) tuple is in cache, skips that work.
4. The role's policies decide whether the upstream call goes through.

So the workload-side setup is per-provider, not per-workload:

- On the provider you want the workload to reach, set `auto_auth_path` to the cert auth mount you configured (`auth/cert/`), and optionally a `default_role`.
- The workload presents its certificate on each Warden request (directly via mTLS or through a trusted proxy).

A typical workload-side call looks like:

```bash
curl --cert /path/to/client.crt --key /path/to/client.key \
     --cacert /path/to/warden-ca.pem \
     -H "X-Warden-Role: inventory-agent" \
     "${WARDEN_ADDR}/v1/<provider>/gateway/<upstream-path>"
```

The role can be set via the `X-Warden-Role` header (as above), embedded in the URL path (`/role/<r>/gateway/...`), or fall back to the provider's `default_role` or the auth method's `default_role`.

The first request with a given (certificate fingerprint, role) tuple triggers a fresh chain + revocation + constraint validation and caches the result. Subsequent requests with the same tuple hit Warden's in-memory cache (TTL = `min(role.token_ttl, cert-NotAfter-derived, mount.token_ttl)`) — no re-validation per call. The cache key uses the certificate's SHA-256 fingerprint, so a workload presenting a rotated certificate gets a fresh validation pass automatically.

> **Why no explicit login endpoint?** The `cert_role` token type is part of Warden's transparent-auth family (alongside `jwt_role` and `kubernetes_role`). Explicit logins returning a transparent token type are rejected by design. This keeps the workload's identity — the certificate, attested by the issuing CA — flowing through every call so each request is independently auditable, with no operator-distributed Warden tokens to rotate or revoke separately.

## Principal Claim Selection

`principal_claim` selects which field of the certificate becomes the principal identity recorded in audit logs and stamped on the issued token. The mount default is `cn`; roles may override.

| Value | Source | Use when |
|---|---|---|
| `cn` | `Subject.CommonName` | Default. Operator-issued certs with a meaningful CN per workload. |
| `dns_san` | First DNS SAN | Service-mesh certs where the SAN is the service name. Returns the first DNS SAN; if you have multiple and need stable picks, narrow via `allowed_dns_sans`. |
| `email_san` | First email SAN | Operator certs where the identity is a person, not a service. |
| `uri_san` | First URI SAN | Any URI-typed identity carried in the URI SAN. This is a plain string read — it does **not** validate the certificate as a SPIFFE SVID (use the `spiffe` auth method for that). |
| `serial` | `SerialNumber` (decimal string) | When the issuing CA assigns one cert per workload and the serial is the registry key. |

Pick the field whose value is **stable for the lifetime of the workload**. The principal flows into audit logs and policy decisions; you don't want it to change across cert rotations of the same workload identity.

## URI SAN Patterns

The `allowed_uri_sans` role field matches a certificate's URI SANs with **segment-aware** wildcards (rather than substring matches). It is a plain match against the URI value — it does **not** validate the certificate as a SPIFFE SVID; for trust-domain-bound SVID validation use the dedicated `spiffe` auth method. A URI SAN of the form `spiffe://trust-domain/path` is matched purely as a string here.

Pattern semantics (segment-aware, splitting on `/`):

- `+` matches exactly one segment, at any position.
- `*` as the **trailing** segment matches one or more remaining segments (a prefix wildcard).
- `scheme://*` (or bare `*` with no scheme) matches everything with the same scheme — a catch-all.
- `+*` is forbidden.
- All other segments require an exact match.

Examples:

- `spiffe://prod.example.org/ns/+/sa/+` matches `spiffe://prod.example.org/ns/default/sa/api` — any namespace, any service account.
- `spiffe://+/api/frontend/svc` matches `spiffe://prod.example.org/api/frontend/svc` and `spiffe://staging.example.org/api/frontend/svc` — any trust domain, exact `api/frontend/svc` path.
- `spiffe://+/+/+` matches any three-segment SPIFFE ID, regardless of trust domain or path.
- `spiffe://prod.example.org/*` matches any non-empty path under `prod.example.org`.

Patterns are validated at role-write time; malformed patterns (e.g. a `*` in a non-trailing segment, or `+*` combinations) are rejected up front.

## How the Certificate Reaches Warden

The auth method accepts the workload certificate from either direct mTLS or a trusted forwarding header. Both paths end at the same internal extractor, so the role / constraint logic is identical regardless of source.

**Direct mTLS** — the workload opens a TLS connection to Warden and presents its client certificate during the handshake. Warden's listener is configured to request and verify client certificates against the listener's CA pool, and the leaf certificate ends up on the request's TLS connection state. This is the simplest setup and the right pick when nothing sits between the workload and Warden. The TLS handshake proves the caller holds the private key, so a leaked certificate cannot be replayed by an unrelated caller.

**Trusted proxy forwarding** — the workload presents the certificate to a reverse proxy (Envoy, NGINX, HAProxy) that terminates TLS, then re-presents the certificate to Warden as a header (`X-SSL-Client-Cert` or `X-Forwarded-Client-Cert`). Warden trusts the header only from configured upstreams; arbitrary callers cannot inject one. This is the right pick when Warden is fronted by an ingress that already terminates mTLS for other reasons.

> **Trust-boundary note.** On the forwarded-header path, the proof-of-possession check happens at the proxy, not at Warden — by the time the cert reaches Warden it's just bytes in a header. The replay-resistance property therefore holds only across the segment of the network the proxy controls; anything that can inject headers between the proxy and Warden (a compromised co-located process, a misconfigured upstream-trust list, a hop through a non-mTLS internal load balancer) effectively bypasses the binding. Restrict the trusted-upstream list tightly and keep the proxy → Warden path on a network you control.

Two practical notes regardless of source:

- The forwarding-header path is re-applied on cluster-forwarded requests (standby → leader), so the certificate is available identically on whichever node ends up handling the request.
- The certificate is parsed once per request and stored in the request context; the auth handler and the introspect handler read from the same place.

## Role-Specific CAs

The mount-level `trusted_ca_pem` is the default trust anchor for every role. A role can override it via the `certificate` field, which **replaces** the mount-level pool for that role (not merges with it).

```bash
warden write auth/cert/role/external-partner \
  certificate=@/path/to/partner-ca.pem \
  allowed_common_names="*.partner.example" \
  token_policies="partner-read"
```

When a request comes in for this role, the cert is verified against `partner-ca.pem` only — the mount's CA bundle is not consulted. Use this when one mount needs to serve roles backed by different issuing CAs (e.g. internal workloads vs. external partner integrations) without standing up a second cert auth mount.

If `certificate` is omitted, the role falls back to the mount's `trusted_ca_pem`. If both are unset, the role cannot accept any certificate and login fails with the generic auth-failed error.

## Token Metadata

A role can copy verified certificate fields onto the issued token's metadata, where a CEL `condition` can match them via `token.metadata`. `metadata_mappings` is written as `cert-field = "destination-metadata-key"`, drawing from: `cn`, `serial`, `ou`, `org`, `dns_san`, `email_san`, and `uri_san`. Multi-valued fields (the SANs, OU, Org) are comma-joined.

```bash
warden write auth/cert/role/inventory-agent \
  allowed_common_names="inventory-agent" \
  metadata_mappings="ou=team,cn=cn"
```

A certificate with `OU=platform-core, CN=inventory-agent` yields metadata `team="platform-core"`, `cn="inventory-agent"`. A policy can then gate a path with `condition = "token.metadata.team.startsWith('platform')"`. Unknown field selectors are rejected at role write time.

## Discovering Assumable Roles

Agents that don't know which role to ask for can use Warden's namespace-wide introspection endpoint. The aggregator detects the credential format (certificate vs JWT vs Kubernetes SA JWT) and fans out only to auth mounts whose registered TokenType matches — so a certificate goes to cert mounts, a generic JWT goes to JWT mounts, a K8s SA token goes to kubernetes mounts. The workload doesn't need to know which mount serves it.

The endpoint reads the same certificate that login does (mTLS directly to Warden or via the trusted forwarding header), so the natural caller is the workload itself with `curl`:

```bash
curl --cert /path/to/client.crt --key /path/to/client.key \
     --cacert /path/to/warden-ca.pem \
     "${WARDEN_ADDR}/v1/sys/introspect/roles"
```

The response is `{roles: [{auth_path, name, description}, ...], warnings: [...]}`. Each role in the list has passed the chain check and the constraint check against the presented certificate, and `auth_path` tells the agent which mount the role lives on. Revocation is **not** checked at introspect time — it's advisory only, and the full revocation check runs at the actual call. Introspection is a discovery hint, not an authorization — the agent picks a role and uses it on subsequent gateway requests, where Warden's transparent-auth layer does the actual validation + cache write.

Per-mount introspection (`auth/<mount>/introspect/roles`) exists too — the aggregator calls it internally — but workloads should prefer the aggregator since it handles dispatch.

## Configuration Reference

### Mount configuration

| Field | Required | Description |
|---|---|---|
| `trusted_ca_pem` | Required unless every role sets its own `certificate` | PEM-encoded CA bundle that signs accepted client certificates. Multiple `-----BEGIN CERTIFICATE-----` blocks may be concatenated. |
| `principal_claim` | No (default `cn`) | Which certificate field becomes the principal identity. One of `cn`, `dns_san`, `email_san`, `uri_san`, `serial`. |
| `token_ttl` | No (default `1h`) | Default TTL for issued Warden auth tokens; per-role `token_ttl` overrides; capped further by the certificate's `NotAfter`. |
| `revocation_mode` | No (default `none`) | Revocation check mode. One of `none`, `ocsp`, `crl`, `best_effort`. |
| `crl_cache_ttl` | No (default `1h`) | How long a fetched CRL is cached per distribution-point URL. Example: `30m`, `2h`. |
| `ocsp_timeout` | No (default `5s`) | Per-request timeout for OCSP queries. Example: `3s`, `10s`. CRL downloads use a longer derived timeout because the payloads can be much larger. |
| `default_role` | No | Used by transparent-mode flows when the caller doesn't specify a role. |

### Role configuration

At least one of the `allowed_*` constraint fields must be set — wide-open roles are refused at write time.

| Field | Required | Description |
|---|---|---|
| `description` | No | Human-readable purpose, surfaced via introspection. |
| `allowed_common_names` | One of six | Glob patterns matched against `Subject.CommonName`. |
| `allowed_dns_sans` | One of six | Glob patterns matched against the certificate's DNS SANs (any-one match accepts). |
| `allowed_email_sans` | One of six | Glob patterns matched against email SANs. |
| `allowed_uri_sans` | One of six | Segment-aware URI patterns (see [URI SAN Patterns](#uri-san-patterns)). |
| `allowed_organizational_units` | One of six | Exact-match list against `Subject.OrganizationalUnit`. |
| `allowed_organizations` | One of six | Exact-match list against `Subject.Organization`. |
| `certificate` | No | Role-specific CA PEM that replaces the mount's `trusted_ca_pem` for this role only. |
| `principal_claim` | No | Per-role override of the mount's `principal_claim`. |
| `metadata_mappings` | No | Map of certificate field (`cn`, `serial`, `ou`, `org`, `dns_san`, `email_san`, `uri_san`) → token metadata key. Multi-valued fields are comma-joined. |
| `token_policies` | No | Warden policies attached to the issued token. |
| `token_ttl` | No (default `1h`) | TTL for issued tokens; overrides the mount-level `token_ttl`; further capped by the certificate's `NotAfter`. |
| `cred_spec_name` | No | Credential spec name to bind to this role; downstream provider gateways use it to mint the upstream credential. |

## Troubleshooting

**Gateway request returns "authentication failed" with no detail.** This is by design — all authentication failures collapse to the same generic error so the response can't be used to enumerate which check is failing. The Warden server logs carry the specific reason (chain not trusted, certificate expired, revoked, constraint mismatch, no principal extracted, etc.). Check the Warden server log at the timestamp of the failed call.

**Gateway request returns "explicit login is not supported for roles with token_type=transparent".** Something is hitting `auth/<mount>/login` directly instead of going through transparent auth on a gateway URL. The cert auth method is transparent-only; the explicit-login endpoint is reserved for internal use. Make sure your client is calling a provider gateway path (e.g. `/v1/<provider>/gateway/...`) with the certificate presented either via mTLS or the trusted forwarding header — not posting to `/auth/<mount>/login`.

**"no client certificate provided" / introspect returns empty roles.** The extractor found no certificate on the request. Direct mTLS: the client didn't send one (curl needs `--cert` and `--key`), or the listener isn't asking for one. Trusted proxy: the proxy didn't re-present the certificate in a header, the header name isn't one Warden recognizes, or the proxy isn't on Warden's trusted-upstream list and the header was discarded.

**Login fails for a certificate that should match.** Walk through each step on the server logs:

1. Did the chain verify? If not, your `trusted_ca_pem` (or the role's `certificate`) doesn't cover the issuing CA.
2. Did the revocation check pass? In strict modes (`ocsp` or `crl`), both OCSP and CRL must return at least one definitive answer; if both probes fail (unreachable responder + unreachable distribution point, or one returns inconclusive and the other has no URL embedded in the cert), the login is rejected. Switch to `best_effort` to allow on both-inconclusive, or fix the revocation infrastructure.
3. Did the constraints match? Roles AND across constraint kinds; the cert must satisfy every set constraint, not just one. Read the role back with `warden read auth/<mount>/role/<name>` and compare each `allowed_*` field to the actual cert.

**"trusted_ca_pem contains no valid certificates" at config write.** The CA bundle is empty, malformed, or contains non-CERTIFICATE PEM blocks only. Verify with `openssl crl2pkcs7 -nocrl -certfile bundle.pem | openssl pkcs7 -print_certs -noout` — every cert should print a `subject=` and `issuer=` line.

**`allowed_uri_sans` patterns reject what looks like a matching URI.** The patterns are segment-aware (split on `/`). Two easy ways to trip:
- `+` matches a single segment only — `spiffe://+/foo/bar` accepts one-segment trust domains, not nested paths.
- `*` is a *prefix* wildcard that only works as the trailing segment — `spiffe://example.com/*` matches one or more segments after `example.com/`, but you can't put `*` in the middle of a path.

Verify the role's patterns with `warden read auth/<mount>/role/<name>`, then walk through the segment match against the certificate's actual URI SAN by hand. Full pattern semantics are in the URI SAN Patterns section above.

**Token TTL is shorter than `token_ttl` requested.** Issued tokens are capped at `min(role.token_ttl, mount.token_ttl, time-until-cert-NotAfter)`. If the certificate is close to its `NotAfter`, the token's effective TTL collapses to whatever's left. The fix is to refresh the certificate, not to raise `token_ttl`.

**OCSP / CRL checks are slow or time out under load.** Each cache miss on revocation is a network round-trip. CRLs are cached per distribution-point URL (default 1h, raise `crl_cache_ttl` to reduce fetch frequency); OCSP isn't cached at this layer, but Warden's transparent-auth cache means most logins skip it entirely after first touch. If you're seeing consistent OCSP timeouts, raise `ocsp_timeout` (default 5s) or switch to `crl` for environments where CRLs are more reliable than the OCSP responder.

## See Also

- [Authentication](/concepts/authentication/) — the credential forms and how transparent auth resolves an identity per request.
- [Roles](/concepts/roles/) — how a validated credential maps to policies and token settings.
- [Agent Identity](/agent-identity/) — how a workload or its sidecar presents this credential to Warden.
- [Auth Methods](/auth-methods/) — the other auth methods Warden ships.
