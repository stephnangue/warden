# Certificate Auth Method

The certificate auth method authenticates workload identities using **TLS client certificates**. The workload presents an X.509 certificate during the TLS handshake (direct mTLS) or via a forwarding header from a trusted proxy; Warden validates the certificate, applies the matching role's constraints, and resolves a principal that flows through Warden's transparent-auth layer like any other auth method in the family. How the certificate is validated — and what the role constraints and principal are — depends on the mount's [trust mode](#trust-modes): classic PKI (`x509`) or SPIFFE X.509-SVID (`spiffe`).

Two properties set certificate auth apart from the bearer-token-based methods (`jwt`, `kubernetes`):

- **Replay-resistant on direct mTLS.** The TLS handshake requires proof-of-possession of the private key; a certificate that leaks through audit logs, a packet capture, or a compromised proxy cannot be re-used by another caller. By contrast, a leaked JWT or K8s SA token is a fully-usable bearer credential until it expires. This property holds end-to-end only when Warden terminates TLS directly — when fronted by a trusted proxy that forwards the certificate in a header, see the trust-boundary note in [How the Certificate Reaches Warden](#how-the-certificate-reaches-warden).
- **No per-call IdP dependency.** Once the workload has its certificate and key, it can authenticate to Warden indefinitely without contacting any external identity service. JWT auth needs to reach the OIDC issuer's JWKS endpoint (at config time, and on key rotation); Kubernetes auth calls TokenReview on the kube-apiserver on every cache-miss login. Cert auth is self-contained.

This is the auth method to reach for when:

- You operate **long-lived workloads** — persistent services, bare-metal or VM workloads outside an orchestrator's token-rotation lifecycle, or anything that runs for weeks to months under the same identity. The cert is rotated on the cadence of the issuing CA / mesh, not on the cadence of an IdP's token TTL.
- You operate in **air-gapped or constrained-network environments** where reaching an external IdP per login is not an option, but a CA bundle can ship with the deployment.
- Your workloads carry **SPIFFE X.509 SVIDs** (issued by SPIRE) — enable the mount's **[spiffe mode](#spiffe-mode)** to verify each SVID against its own trust domain's bundle (full X.509-SVID validation), then bind roles to SPIFFE IDs via segment-aware patterns (`spiffe://prod.example.org/ns/+/sa/+`).
- Your workloads carry **service-mesh-issued certificates** (Istio, Linkerd, Consul Connect) and identity flows through the cert rather than a token.
- Your operators have already provisioned **mTLS at the network edge** and want Warden to consume that same certificate rather than layering a second credential on top.
- You need **revocation checking** built in — CRL or OCSP — so a compromised certificate can be cut off without rotating CAs.

If your workload's identity is a Kubernetes ServiceAccount token, prefer the `kubernetes` auth method. If it's a JWT from an OIDC provider, prefer the `jwt` method. The cert method is the right tool when the certificate **is** the identity — not when it's just transport encryption.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Trust modes](#trust-modes)
- [Step 1: Configure Trusted CAs](#step-1-configure-trusted-cas)
- [Step 2: Enable Revocation Checking (Optional)](#step-2-enable-revocation-checking-optional)
- [Step 3: Create a Role](#step-3-create-a-role)
- [Step 4: Wire Up Transparent Auth](#step-4-wire-up-transparent-auth)
- [Principal Claim Selection](#principal-claim-selection)
- [SPIFFE URI Patterns](#spiffe-uri-patterns)
- [SPIFFE mode](#spiffe-mode)
- [How the Certificate Reaches Warden](#how-the-certificate-reaches-warden)
- [Role-Specific CAs](#role-specific-cas)
- [Discovering Assumable Roles](#discovering-assumable-roles)
- [Configuration Reference](#configuration-reference)
- [Troubleshooting](#troubleshooting)
- [Development / Testing](#development--testing)

## Prerequisites

- A **Warden server** unsealed and reachable from the workload's network.
- A **PEM-encoded CA bundle** that issued (or transitively signed) the certificates your workloads present.
- A way to get the workload's certificate to Warden — either direct mTLS termination at the Warden listener, or a trusted reverse proxy that terminates TLS and re-presents the certificate via a forwarding header. See [How the Certificate Reaches Warden](#how-the-certificate-reaches-warden).
- A **role-mapping policy** in Warden that scopes what the resulting auth token can do (authenticating a certificate doesn't grant access on its own).

## Trust modes

A cert mount runs in one of two modes, fixed at config time; the two don't mix within a mount, so run a separate mount per model.

- **`x509`** (default) — classic PKI. Warden checks the certificate chain against a configured CA bundle, matches role constraints over CN / SANs / OU / Organization, and resolves the principal from a chosen certificate field. **Steps 1–4 and the supporting sections below describe this mode** unless noted otherwise.
- **`spiffe`** — a spec-compliant SPIFFE X.509-SVID relying party. Each trust domain has its own registered bundle, roles bind to a trust domain (optionally restricting the SPIFFE ID path), and the principal is the verified SVID ID. See [SPIFFE mode](#spiffe-mode).

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

When `principal_claim` is omitted, the mount defaults to `cn` (the certificate Subject's CommonName). For service-mesh certificates, `uri_san` or `dns_san` is often the right pick. See [Principal Claim Selection](#principal-claim-selection) for the full list. (For SPIFFE SVIDs, use [spiffe mode](#spiffe-mode) instead — the principal is the verified SVID ID, not a `principal_claim`.)

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
- `allowed_uri_sans` — segment-aware patterns matched against URI SANs (see [SPIFFE URI Patterns](#spiffe-uri-patterns) for the syntax). Plain string matching only; for SPIFFE SVIDs use [spiffe mode](#spiffe-mode) instead.
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
| `uri_san` | First URI SAN | Any URI-typed identity, including a SPIFFE ID carried in the URI SAN. Note this is a plain string read — it does **not** validate the certificate as a SPIFFE SVID. |
| `serial` | `SerialNumber` (decimal string) | When the issuing CA assigns one cert per workload and the serial is the registry key. |

Pick the field whose value is **stable for the lifetime of the workload**. The principal flows into audit logs and policy decisions; you don't want it to change across cert rotations of the same workload identity.

## SPIFFE URI Patterns

SPIFFE IDs live in a certificate's URI SAN as `spiffe://trust-domain/path`. Two role fields match against that structure with the same **segment-aware** wildcards (rather than substring matches):

- `allowed_spiffe_ids` in [spiffe mode](#spiffe-mode) — applied **after** the certificate is verified as an SVID against its trust domain's bundle. This is the right field for SPIFFE workloads.
- `allowed_uri_sans` in x509 mode — a plain match against any URI SAN. It does **not** validate the certificate as an SVID, so if your workloads carry SVIDs, use spiffe mode instead of matching `spiffe://` URIs here.

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

## SPIFFE mode

With `mode=spiffe` the cert method becomes a spec-compliant **SPIFFE X.509-SVID relying party**. Instead of a single global CA, each SPIFFE trust domain is registered with its own bundle, and a login is accepted only if the presented certificate is a valid SVID for the trust domain its role binds to. A mount is either `x509` or `spiffe`; set the mode before creating roles or trust domains (it can't be changed while either exists), and run the two models as separate mounts.

### Step 1: Enable the mount in spiffe mode

```bash
warden auth enable -path=spiffe cert
warden write auth/spiffe/config mode=spiffe
```

In spiffe mode `trusted_ca_pem` and `principal_claim` are rejected — trust comes from per-trust-domain bundles, and the principal is always the verified SVID ID.

### Step 2: Register trust domains

Register each trust domain together with the X.509 authorities (the SPIRE bundle) that sign its SVIDs:

```bash
# from a PEM bundle of CA certificates
warden write auth/spiffe/trust-domain/prod.example.org bundle_pem=@prod-bundle.pem

# …or from a SPIFFE trust-bundle (JWKS) document
warden write auth/spiffe/trust-domain/prod.example.org bundle_json=@prod-bundle.json
```

Read back a summary (authority count and subjects — not the raw bundle), or list them:

```bash
warden read auth/spiffe/trust-domain/prod.example.org
warden list auth/spiffe/trust-domain
```

A trust bundle may hold several authorities (e.g. old + new roots during a CA rotation). Only the X.509 authorities of a JWKS bundle are consumed; JWT authorities are ignored.

### Step 3: Create a SPIFFE role

A spiffe role binds to exactly one `trust_domain` and may restrict the SPIFFE ID path with the same segment-aware patterns as [SPIFFE URI Patterns](#spiffe-uri-patterns):

```bash
warden write auth/spiffe/role/api \
  trust_domain="prod.example.org" \
  allowed_spiffe_ids="spiffe://prod.example.org/ns/+/sa/api" \
  token_policies="api-read" \
  token_ttl="1h"
```

`trust_domain` is required; the PKI constraints (`allowed_common_names`, `certificate`, `principal_claim`, …) are rejected on a spiffe role. The issued token's principal is the verified SVID ID, e.g. `spiffe://prod.example.org/ns/default/sa/api`.

### What is enforced

On each login Warden verifies, via the SPIFFE reference library, that the certificate:

- has exactly one URI SAN holding a syntactically valid SPIFFE ID;
- is a leaf SVID (`CA=false`, no certificate- or CRL-signing key usage);
- chains to the X.509 authorities of **its own trust domain's** bundle;
- whose trust domain equals the role's `trust_domain`; and
- whose SPIFFE ID matches `allowed_spiffe_ids`, when set.

A certificate whose trust domain isn't configured — or differs from the role's — is rejected, even if some *other* configured bundle would have accepted it. That cross-trust-domain isolation is the property plain CA-pool matching can't provide. The transparent-auth flow behaves exactly as in x509 mode, and revocation is available too — but SVIDs are typically short-lived and carry no CRL/OCSP endpoints, so leave `revocation_mode` at `none` (a strict mode would reject an SVID that has no revocation URL).

> **Chain note.** Only the leaf certificate is available on the forwarded-header path, so the registered bundle must contain the authority that directly signed the SVID (the usual SPIRE setup).

### Federation

Instead of a static bundle, a trust domain can pull its bundle from a remote **bundle endpoint** and refresh it automatically — the SPIFFE Federation model. Setting `bundle_endpoint_profile` makes a trust domain federated:

```bash
# https_web — the endpoint's TLS cert is validated via Web PKI (system roots,
# or web_pki_ca_pem for a private CA)
warden write auth/spiffe/trust-domain/partner.acme.io \
  bundle_endpoint_url="https://spire.acme.io/bundle" \
  bundle_endpoint_profile="https_web"

# https_spiffe — the endpoint is authenticated by its own SVID against a required
# bootstrap bundle and an expected endpoint SPIFFE ID
warden write auth/spiffe/trust-domain/partner.acme.io \
  bundle_endpoint_url="https://spire.acme.io:8443" \
  bundle_endpoint_profile="https_spiffe" \
  endpoint_spiffe_id="spiffe://partner.acme.io/spire/server" \
  bundle_pem=@bootstrap.pem
```

Fields:

- `bundle_endpoint_url` — the `https://` bundle endpoint (required for a federated domain).
- `bundle_endpoint_profile` — `https_web` or `https_spiffe`.
- `endpoint_spiffe_id` — the SVID the endpoint presents; **required** for `https_spiffe`, rejected for `https_web`. Must be in the same trust domain.
- `web_pki_ca_pem` — optional custom CA roots for an `https_web` endpoint's TLS cert (default: system roots).
- For `https_spiffe` a **bootstrap bundle** (`bundle_pem` or `bundle_json`) is required — it authenticates the first fetch and is the initial set of authorities. An `https_web` domain needs no bootstrap, but has no authorities (and fails closed at login) until its first successful fetch.

Refresh:

- Warden refreshes each federated bundle on a background loop, honoring the bundle's `spiffe_refresh_hint` (clamped to a sane range) and de-duplicating by sequence number; a failed fetch keeps the last-good bundle and surfaces `last_error` on read. A fetched bundle with no X.509 authorities is rejected (last-good kept).
- A config write doesn't fetch immediately; the loop primes a new federated domain on its next tick, or force a fetch now with `warden write auth/spiffe/trust-domain/<name>/refresh`.
- `warden read auth/spiffe/trust-domain/<name>` shows the endpoint, profile, `sequence`, `last_refresh`, and `last_error`.

> **HA note.** The refresh loop runs on the **active node only** (standbys forward auth requests). The fetched bundle is persisted, so on failover the new active node loads the last-good bundle and resumes refreshing.

### One mount, many trust domains

A single spiffe mount holds multiple trust domains — your own plus any federated peers. This is the federation-native shape, and it stays safe: a role binds exactly one `trust_domain`, an SVID validates only against its own domain's bundle, and adding a trust domain grants nothing until a role references it. Prefer **separate mounts** only for administrative isolation — distinct ACLs/audit, or different mount-level `token_ttl` / `revocation_mode` / `default_role`.

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
| `mode` | No (default `x509`) | Trust model for the mount: `x509` (classic PKI) or `spiffe` (SPIFFE X.509-SVID — see [SPIFFE mode](#spiffe-mode)). Cannot be changed while roles or trust domains exist. |
| `trusted_ca_pem` | x509 mode; required unless every role sets its own `certificate` | PEM-encoded CA bundle that signs accepted client certificates. Multiple `-----BEGIN CERTIFICATE-----` blocks may be concatenated. Rejected in spiffe mode. |
| `principal_claim` | No (default `cn`) | **x509 mode only.** Which certificate field becomes the principal identity. One of `cn`, `dns_san`, `email_san`, `uri_san`, `serial`. (In spiffe mode the principal is always the verified SVID ID.) |
| `token_ttl` | No (default `1h`) | Default TTL for issued Warden auth tokens; per-role `token_ttl` overrides; capped further by the certificate's `NotAfter`. |
| `revocation_mode` | No (default `none`) | Revocation check mode. One of `none`, `ocsp`, `crl`, `best_effort`. |
| `crl_cache_ttl` | No (default `1h`) | How long a fetched CRL is cached per distribution-point URL. Example: `30m`, `2h`. |
| `ocsp_timeout` | No (default `5s`) | Per-request timeout for OCSP queries. Example: `3s`, `10s`. CRL downloads use a longer derived timeout because the payloads can be much larger. |
| `default_role` | No | Used by transparent-mode flows when the caller doesn't specify a role. |

### Role configuration

In **x509 mode**, at least one of the `allowed_*` constraint fields must be set — wide-open roles are refused at write time. In **spiffe mode**, `trust_domain` is required and the x509-only fields below are rejected.

| Field | Required | Description |
|---|---|---|
| `description` | No | Human-readable purpose, surfaced via introspection. |
| `trust_domain` | spiffe mode (required) | SPIFFE trust domain the role authenticates (e.g. `prod.example.org`). The SVID must belong to this domain and chain to its registered bundle. Rejected in x509 mode. |
| `allowed_spiffe_ids` | No (spiffe mode) | Segment-aware SPIFFE ID patterns restricting the path within the trust domain (see [SPIFFE URI Patterns](#spiffe-uri-patterns)). |
| `allowed_common_names` | x509: one of six | Glob patterns matched against `Subject.CommonName`. |
| `allowed_dns_sans` | x509: one of six | Glob patterns matched against the certificate's DNS SANs (any-one match accepts). |
| `allowed_email_sans` | x509: one of six | Glob patterns matched against email SANs. |
| `allowed_uri_sans` | x509: one of six | Segment-aware URI patterns (see [SPIFFE URI Patterns](#spiffe-uri-patterns)). |
| `allowed_organizational_units` | x509: one of six | Exact-match list against `Subject.OrganizationalUnit`. |
| `allowed_organizations` | x509: one of six | Exact-match list against `Subject.Organization`. |
| `certificate` | No (x509 mode) | Role-specific CA PEM that replaces the mount's `trusted_ca_pem` for this role only. |
| `principal_claim` | No (x509 mode) | Per-role override of the mount's `principal_claim`. |
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

**SPIFFE URI patterns reject what looks like a matching SVID.** `allowed_spiffe_ids` (spiffe mode) and `allowed_uri_sans` (x509 mode) are segment-aware (split on `/`). Two easy ways to trip:
- `+` matches a single segment only — `spiffe://+/foo/bar` accepts one-segment trust domains, not nested paths.
- `*` is a *prefix* wildcard that only works as the trailing segment — `spiffe://example.com/*` matches one or more segments after `example.com/`, but you can't put `*` in the middle of a path.

Verify the role's patterns with `warden read auth/<mount>/role/<name>`, then walk through the segment match against the SVID's actual URI SAN by hand. Full pattern semantics are in the SPIFFE URI Patterns section above.

**Token TTL is shorter than `token_ttl` requested.** Issued tokens are capped at `min(role.token_ttl, mount.token_ttl, time-until-cert-NotAfter)`. If the certificate is close to its `NotAfter`, the token's effective TTL collapses to whatever's left. The fix is to refresh the certificate, not to raise `token_ttl`.

**`principal_claim=spiffe_id` is rejected, or a stored value now reads `uri_san`.** The `spiffe_id` principal claim was removed — it pulled a `spiffe://` URI from the certificate without validating it as an SVID. New writes are rejected; a value persisted by an older version is coerced to `uri_san` (the same string for a single-URI SVID) with a deprecation warning on load. For real SVID validation, use a [spiffe-mode](#spiffe-mode) mount.

**SPIFFE login fails with "authentication failed" on a spiffe-mode mount.** Check, in order: the role's `trust_domain` has a registered bundle (`warden read auth/<mount>/trust-domain/<td>`); the SVID's trust domain matches the role's `trust_domain`; the SVID chains to *that* domain's authorities (not some other configured domain's); the SVID is a leaf (not a CA cert) with exactly one `spiffe://` URI SAN; and its path matches `allowed_spiffe_ids` when set. A role bound to an unconfigured or deleted trust domain always fails closed.

**OCSP / CRL checks are slow or time out under load.** Each cache miss on revocation is a network round-trip. CRLs are cached per distribution-point URL (default 1h, raise `crl_cache_ttl` to reduce fetch frequency); OCSP isn't cached at this layer, but Warden's transparent-auth cache means most logins skip it entirely after first touch. If you're seeing consistent OCSP timeouts, raise `ocsp_timeout` (default 5s) or switch to `crl` for environments where CRLs are more reliable than the OCSP responder.

## Development / Testing

For local development, the easiest path is to generate a self-signed CA and a leaf cert with `openssl`, then point Warden at the CA:

```bash
# Generate a CA
openssl req -new -x509 -days 365 -keyout ca.key -out ca.crt -subj "/CN=dev-ca"

# Generate a leaf cert signed by that CA
openssl req -new -newkey rsa:2048 -nodes -keyout client.key -out client.csr -subj "/CN=dev-agent/O=ExampleCorp"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 365 -out client.crt

# Configure Warden
warden auth enable cert
warden write auth/cert/config \
  trusted_ca_pem=@ca.crt \
  principal_claim="cn" \
  default_role="dev"

warden write auth/cert/role/dev \
  allowed_common_names="dev-*" \
  allowed_organizations="ExampleCorp" \
  token_policies="default" \
  token_ttl="1h"
```

The certificate can then be presented as `--cert client.crt --key client.key` on any Warden gateway request that points its provider's `auto_auth_path` at `auth/cert/`.

For unit-test-level work, the cert auth method's test suite generates ephemeral CAs and leaves in-memory — no `openssl` needed.
