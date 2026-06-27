# SPIFFE Auth Method

The SPIFFE auth method authenticates workloads that present a **SPIFFE SVID** — the short-lived identity document a SPIFFE/SPIRE deployment issues to every workload. SPIFFE defines two SVID shapes, and this method accepts **both on the same mount**:

- an **X.509-SVID** — a TLS client certificate, presented over direct mTLS or re-forwarded by a trusted proxy, and
- a **JWT-SVID** — a bearer JWT carried in the `Authorization` header.

A SPIFFE *trust domain* is a single bundle that carries both the X.509 authorities and the JWT signing keys for that domain. Warden anchors trust per trust domain via these bundles — registered statically or fetched through **SPIFFE Federation** — verifies each presented SVID against the right bundle, and flows the verified SPIFFE ID through Warden's transparent-auth layer like any other auth method in the family. Every login issues the single `spiffe_role` token type.

This is the auth method to reach for when:

- Your workloads run in a **service mesh or SPIRE deployment** that already mints SPIFFE SVIDs, and you want Warden to consume that identity directly — whether the workload reaches Warden over mTLS (X.509-SVID) or with a bearer token (JWT-SVID).
- You federate identity **across trust domains** (multi-cluster, multi-cloud) and want Warden to trust a remote domain's workloads by fetching its bundle from a federation endpoint.
- You want **one mount** to serve both SVID types rather than splitting SPIFFE X.509 and SPIFFE JWT identity across the `cert` and `jwt` methods.

If your workload's identity is an ordinary OIDC JWT (not a SPIFFE JWT-SVID), use the `jwt` method. If it is a plain X.509 client certificate from a classic PKI (not issued under a SPIFFE trust domain), use the `cert` method. The `cert` method can still accept a SPIFFE X.509-SVID as an ordinary certificate bound on its URI SAN — but only the `spiffe` method verifies it against a trust-domain bundle and accepts the matching JWT-SVID on the same mount.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Step 1: Enable the Method and Register a Trust Domain](#step-1-enable-the-method-and-register-a-trust-domain)
- [Step 2: Create a Role](#step-2-create-a-role)
- [Step 3: Wire Up Transparent Auth](#step-3-wire-up-transparent-auth)
- [Credential Precedence: JWT-SVID Wins](#credential-precedence-jwt-svid-wins)
- [The Audience Requirement (JWT-SVID)](#the-audience-requirement-jwt-svid)
- [Restricting Allowed SPIFFE IDs](#restricting-allowed-spiffe-ids)
- [Federation](#federation)
- [Group-Based Policies (JWT-SVID)](#group-based-policies-jwt-svid)
- [On-Behalf-Of Chain (RFC 8693 `act` Claim)](#on-behalf-of-chain-rfc-8693-act-claim)
- [Discovering Assumable Roles](#discovering-assumable-roles)
- [Revocation and SVID Lifetime](#revocation-and-svid-lifetime)
- [Configuration Reference](#configuration-reference)
- [Troubleshooting](#troubleshooting)

## Prerequisites

- A **Warden server** unsealed and reachable from the workload's network.
- A **SPIFFE trust domain** whose bundle you can supply to Warden — either the PEM/JSON bundle bytes directly, or the URL of a SPIFFE Federation bundle endpoint Warden can fetch from.
- For X.509-SVID logins, a way to get the workload's certificate to Warden — direct mTLS termination at the Warden listener, or a trusted reverse proxy that terminates TLS and re-presents the certificate in a forwarding header.
- A **role-mapping policy** in Warden that scopes what the resulting auth token can do (issuing a token doesn't grant access on its own).

## Step 1: Enable the Method and Register a Trust Domain

Enable the auth method:

```bash
warden auth enable spiffe
```

This mounts at `auth/spiffe/`. Use `-path` to name additional mounts (e.g. one per environment); the CLI prefixes `auth/` automatically.

A `spiffe` mount carries no trust on its own — you register the trust domains it should honour. The simplest case is a **static bundle**: the X.509 authorities (and, for JWT-SVIDs, the JWT signing keys) of the domain, supplied directly.

```bash
# X.509 authorities as PEM (sufficient for X.509-SVIDs)
warden write auth/spiffe/trust-domain/prod.example.org \
  bundle_pem=@/path/to/prod-ca-bundle.pem
```

To accept **JWT-SVIDs** as well, supply a SPIFFE trust-bundle (JWKS) document, which carries both authority types:

```bash
warden write auth/spiffe/trust-domain/prod.example.org \
  bundle_json=@/path/to/prod-bundle.json
```

Read back a summary (authority counts and subjects, never the raw key bytes) and list the configured domains:

```bash
warden read auth/spiffe/trust-domain/prod.example.org
warden list auth/spiffe/trust-domain
```

A trust domain can be **federated** instead of static — Warden fetches and refreshes the bundle from an endpoint. See [Federation](#federation).

## Step 2: Create a Role

A role binds one trust domain to a set of Warden policies and decides what the issued token can do. The same role serves both SVID types: an X.509-SVID or a JWT-SVID whose verified SPIFFE ID is in the role's `trust_domain`.

```bash
warden write auth/spiffe/role/inventory-agent \
  trust_domain="prod.example.org" \
  bound_audiences="warden" \
  token_policies="inventory-read,inventory-write" \
  token_ttl="1h"
```

Fields:

- `trust_domain` (**required**) — the SPIFFE trust domain this role accepts. An SVID validates only against this domain's bundle; an SVID from any other domain is rejected.
- `allowed_spiffe_ids` — optional segment-aware SPIFFE-ID patterns the verified SVID must match. Omit to accept any SVID in the trust domain. See [Restricting Allowed SPIFFE IDs](#restricting-allowed-spiffe-ids).
- `bound_audiences` — audiences accepted for **JWT-SVID** logins. Required for JWT-SVIDs (an audience-less JWT-SVID login fails closed); ignored for X.509-SVIDs. See [The Audience Requirement](#the-audience-requirement-jwt-svid).
- `token_policies` — Warden policies stamped on the issued token.
- `token_ttl` — TTL for issued tokens (default `1h`). Always capped by the SVID's own expiry.
- `cred_spec_name` — credential spec to use for implicit-auth flows.
- `groups_claim` / `group_policy_prefix` — dynamic policy mapping from a JWT-SVID claim (JWT-SVID only). See [Group-Based Policies](#group-based-policies-jwt-svid).

A role's token type is always pinned to `spiffe_role`; operators can't override it. A role with no `bound_audiences` is accepted, but the write returns a warning: it can authenticate X.509-SVIDs but will reject every JWT-SVID login.

## Step 3: Wire Up Transparent Auth

The SPIFFE auth method is **transparent-only**. There is no "log in once, get a Warden bearer token" handshake the workload performs explicitly — `POST /auth/<mount>/login` for a `spiffe_role` token is rejected at the request handler with `explicit login is not supported for roles with token_type=transparent`. The workload re-presents its SVID on every call, and Warden's transparent middleware does the validation in-line (with a per-(SVID, role) cache so the verification isn't repeated on every request).

The shape:

1. The workload presents its SVID on every request to a Warden gateway URL — an **X.509-SVID** via mTLS (direct, or through a trusted proxy that re-forwards the certificate in a header), or a **JWT-SVID** as `Authorization: Bearer`.
2. Warden resolves the auth mount via the provider's (or namespace's) `auto_auth_path` configuration.
3. Warden verifies the SVID against the role's trust-domain bundle — or, if a prior call with the same (SVID, role) tuple is cached, skips that work.
4. The role's policies decide whether the upstream call goes through.

So the workload-side setup is per-provider, not per-workload: on the provider you want the workload to reach, set `auto_auth_path` to the SPIFFE mount (`auth/spiffe/`) and optionally a `default_role`.

A JWT-SVID call looks like:

```bash
curl -H "Authorization: Bearer $JWT_SVID" \
     -H "X-Warden-Role: inventory-agent" \
     "${WARDEN_ADDR}/v1/<provider>/gateway/<upstream-path>"
```

An X.509-SVID call presents the certificate over mTLS (directly to Warden, or to a trusted proxy that re-forwards it as `X-SSL-Client-Cert` / `X-Forwarded-Client-Cert` — Warden honours that header only from configured upstreams):

```bash
curl --cert workload.pem --key workload-key.pem \
     -H "X-Warden-Role: inventory-agent" \
     "${WARDEN_ADDR}/v1/<provider>/gateway/<upstream-path>"
```

The role can be set via the `X-Warden-Role` header (as above), embedded in the URL path (`/role/<r>/gateway/...`), or fall back to the provider's `default_role` or the auth method's `default_role`. The issued token's TTL is `min(role.token_ttl, config.token_ttl, time-until-SVID-expiry)`, so a token never outlives the SVID that minted it.

## Credential Precedence: JWT-SVID Wins

A single request can carry both credentials at once — common in a mesh, where a sidecar makes a forwarded X.509-SVID *ambient* on every call while the workload also sends a JWT-SVID bearer for a specific intent. When both are present, **the explicitly-presented JWT-SVID is used** and the ambient certificate is ignored. This keeps the JWT-SVID path live in a mesh and attributes the request to the identity the workload deliberately presented, rather than silently falling back to the sidecar's certificate. Present only an X.509-SVID (no bearer) to authenticate as the certificate identity.

## The Audience Requirement (JWT-SVID)

SPIFFE mandates that a JWT-SVID be minted for a specific **audience** and that the relying party validate it — without that check, a JWT-SVID issued for service A could be replayed against service B. Warden enforces this fail-closed:

- A JWT-SVID is validated against the role's `bound_audiences`. A token whose `aud` doesn't include one of them is rejected.
- A role with **no** `bound_audiences` rejects every JWT-SVID login (the role write warns about this). The same role still accepts X.509-SVIDs, which carry no audience.

Set `bound_audiences` to the identifier your workloads request their JWT-SVIDs for (often the Warden instance or the upstream service name):

```bash
warden write auth/spiffe/role/inventory-agent \
  trust_domain="prod.example.org" \
  bound_audiences="warden" \
  token_policies="inventory-read"
```

## Restricting Allowed SPIFFE IDs

By default a role accepts any SVID whose trust domain matches `trust_domain`. To narrow it to specific workloads, set `allowed_spiffe_ids` to one or more **segment-aware** patterns (split on `/`):

```bash
warden write auth/spiffe/role/frontend \
  trust_domain="prod.example.org" \
  bound_audiences="warden" \
  allowed_spiffe_ids="spiffe://prod.example.org/ns/web/sa/*,spiffe://prod.example.org/ns/edge/sa/+" \
  token_policies="frontend"
```

Pattern semantics:

- `+` matches exactly one segment, at any position.
- `*` as the **trailing** segment matches one or more remaining segments.
- All other segments require an exact match.

The patterns are matched against the SVID's verified SPIFFE ID, so a pattern can only ever narrow within the role's trust domain — it cannot widen acceptance to another domain.

## Federation

A trust domain can be **federated** rather than static: instead of pasting its bundle, you point Warden at the domain's SPIFFE Federation bundle endpoint, and Warden fetches the bundle and refreshes it periodically. This is how you trust workloads from another cluster or cloud whose authorities rotate on their own schedule.

SPIFFE defines two endpoint profiles, and Warden supports both:

**`https_web`** — the bundle endpoint is served over ordinary Web PKI TLS. Warden validates the endpoint's TLS certificate against the system roots (or custom roots you supply via `web_pki_ca_pem`).

```bash
warden write auth/spiffe/trust-domain/remote.example.org \
  bundle_endpoint_url="https://spiffe.remote.example.org/bundle" \
  bundle_endpoint_profile="https_web"
```

**`https_spiffe`** — the endpoint authenticates itself with its *own* SPIFFE X.509-SVID. This needs the endpoint's expected SPIFFE ID and a **bootstrap bundle** (carrying X.509 authorities) to authenticate that first fetch:

```bash
warden write auth/spiffe/trust-domain/remote.example.org \
  bundle_endpoint_url="https://spiffe.remote.example.org/bundle" \
  bundle_endpoint_profile="https_spiffe" \
  endpoint_spiffe_id="spiffe://remote.example.org/spire/server" \
  bundle_json=@/path/to/remote-bootstrap-bundle.json
```

Warden refreshes federated bundles in the background on the active node. To force an immediate fetch — after rotating the remote domain's authorities, say:

```bash
warden write -f auth/spiffe/trust-domain/remote.example.org/refresh
```

A refresh that can't reach the endpoint fails the call but keeps the last-good bundle in place, so a transient outage at the remote domain doesn't break logins for already-fetched authorities. Reading a federated trust domain surfaces its fetch status (sequence number, last refresh time, last error).

## Group-Based Policies (JWT-SVID)

If your JWT-SVIDs carry a claim listing the workload's groups, Warden can stamp one policy per group onto the issued token, in addition to the role's static `token_policies`. This applies to JWT-SVIDs only — X.509-SVIDs carry no claims.

```bash
warden write auth/spiffe/role/inventory-agent \
  trust_domain="prod.example.org" \
  bound_audiences="warden" \
  groups_claim="groups" \
  group_policy_prefix="spiffe-"
```

A JWT-SVID carrying `"groups": ["engineering", "billing"]` gets `spiffe-engineering` and `spiffe-billing` appended to its policy list. The default prefix is `group-`. Warden accepts the claim as a JSON array, a comma-separated string, or a single string.

## On-Behalf-Of Chain (RFC 8693 `act` Claim)

RFC 8693 §4.1 defines an `act` claim that attests a delegation chain — "this token represents X, acting on behalf of Y." When a JWT-SVID carries it, Warden extracts the chain (up to a fixed depth of 4), marks each actor as verified (the trust domain signed it), and persists it on the issued token so downstream audit entries carry the full chain. No configuration needed; extraction happens automatically when the claim is present.

## Discovering Assumable Roles

A workload that doesn't know which role to ask for can use Warden's namespace-wide introspection endpoint. The aggregator fans out to the auth mounts whose token type matches the presented credential — a `spiffe` mount is consulted for both X.509-SVIDs and JWT-SVIDs — and returns the roles the credential could assume.

```bash
# JWT-SVID
curl -H "Authorization: Bearer $JWT_SVID" \
  "${WARDEN_ADDR}/v1/sys/introspect/roles"
```

The response lists `{auth_path, name, description}` for each role whose trust-domain and SPIFFE-ID constraints the presented SVID satisfies. Introspection is a discovery hint, not an authorization — the workload picks a role and uses it on subsequent gateway requests, where the transparent-auth layer does the real validation. A credential that doesn't match the mount produces no error and no warning, so the aggregator can tolerate non-matching mounts.

Per-mount introspection (`auth/<mount>/introspect/roles`) exists too — the aggregator calls it internally — but workloads should prefer the aggregator since it handles dispatch.

## Revocation and SVID Lifetime

The SPIFFE method does **not** perform X.509 CRL or OCSP revocation checks. This is deliberate and matches the SPIFFE model: SVIDs are short-lived and continuously re-minted, and a compromised authority is handled by rotating the trust domain's bundle (which Warden picks up on its next federation refresh, or immediately on a manual refresh), not by revoking individual SVIDs. There is no revocation configuration surface on the mount.

Two properties keep the blast radius small without revocation:

- **Token TTL is capped by SVID expiry.** An issued Warden token never outlives the SVID that minted it, so a short-lived SVID yields a short-lived token automatically.
- **Bundle rotation is the kill switch.** Removing or rotating a trust domain's authorities stops Warden from validating any SVID signed by the old keys — update the bundle (static write or federation refresh) to cut off a compromised authority.

If you require per-certificate revocation semantics, use the `cert` method with its revocation modes against a classic PKI instead.

## Configuration Reference

### Mount configuration (`auth/spiffe/config`)

| Field | Required | Description |
|---|---|---|
| `token_ttl` | No (default `1h`) | Default TTL for issued tokens; the per-role `token_ttl` and the SVID expiry both further cap it. |
| `default_role` | No | Role used by transparent flows when the caller doesn't specify one. |

### Trust domain (`auth/spiffe/trust-domain/<name>`)

| Field | Required | Description |
|---|---|---|
| `bundle_pem` | For a static X.509-only domain | PEM-encoded X.509 authorities (CA certificates) for the trust domain. |
| `bundle_json` | For JWT-SVID support / `https_spiffe` bootstrap | SPIFFE trust-bundle (JWKS) document; both its X.509 and JWT authorities are used. |
| `bundle_endpoint_url` | For a federated domain | SPIFFE Federation bundle endpoint (`https://`). Setting this makes the domain federated. |
| `bundle_endpoint_profile` | With an endpoint URL | `https_web` (Web PKI) or `https_spiffe` (endpoint authenticated by its own SVID). |
| `endpoint_spiffe_id` | For `https_spiffe` | Expected SPIFFE ID of the bundle endpoint; must be in this trust domain. |
| `web_pki_ca_pem` | No (`https_web` only) | Custom PEM CA roots for the endpoint's TLS certificate (default: system roots). |

A trust domain is either **static** (a `bundle_pem`/`bundle_json` with no `bundle_endpoint_profile`) or **federated** (a `bundle_endpoint_url` plus a `bundle_endpoint_profile`). The three federation fields — `bundle_endpoint_url`, `endpoint_spiffe_id`, and `web_pki_ca_pem` — require a `bundle_endpoint_profile`; setting any of them on a static domain is rejected. Conversely, `endpoint_spiffe_id` is valid only for `https_spiffe`, and `web_pki_ca_pem` only for `https_web`.

### Role (`auth/spiffe/role/<name>`)

| Field | Required | Description |
|---|---|---|
| `trust_domain` | **Yes** | SPIFFE trust domain the role accepts. |
| `allowed_spiffe_ids` | No | Segment-aware SPIFFE-ID patterns the verified SVID must match. Empty accepts any SVID in the domain. |
| `bound_audiences` | For JWT-SVID logins | Accepted JWT-SVID audiences. Required for JWT-SVIDs; ignored for X.509-SVIDs. |
| `token_policies` | No | Warden policies attached to the issued token. |
| `token_ttl` | No (default `1h`) | TTL for issued tokens; always capped by SVID expiry. |
| `cred_spec_name` | No | Credential spec name for implicit-auth flows. |
| `groups_claim` | No | JWT-SVID claim carrying group names for dynamic policy mapping (JWT-SVID only). |
| `group_policy_prefix` | No (default `group-`) | Prefix prepended to each group name to form the policy name. |

## Troubleshooting

**Gateway request returns "authentication failed" with no detail.** This is by design — all authentication failures collapse to the same generic error so the response can't be used to enumerate which check is failing. The Warden server logs carry the specific reason (no matching trust domain, SVID outside the role's trust domain, SPIFFE-ID pattern mismatch, audience mismatch, expired SVID, no bundle loaded, etc.). Check the server log at the timestamp of the failed call.

**Every JWT-SVID login for a role fails, but X.509-SVID logins work.** The role has no `bound_audiences`. A JWT-SVID requires an audience to validate, so a role without one rejects all JWT-SVID logins (the role write warns about this). Set `bound_audiences` to the audience your workloads mint their JWT-SVIDs for.

**Logins fail right after enabling the method.** A `spiffe` mount serves no logins until at least one trust domain bundle is registered and loaded. Register the trust domain (`auth/spiffe/trust-domain/<name>`) and confirm `warden read` shows a non-zero authority count. If the mount can't load any bundle at startup it fails closed — every login is rejected until a valid bundle is present.

**A workload's SVID is rejected even though the certificate looks valid.** Check the trust domain. The role's `trust_domain` must exactly equal the SVID's trust domain, and the SVID must verify against *that* domain's bundle — an SVID from a different (even federated) domain won't satisfy a role bound elsewhere. If `allowed_spiffe_ids` is set, confirm the SVID's full SPIFFE ID matches one of the segment patterns.

**A federated trust domain stopped updating.** Read the trust domain and inspect `last_error` and `last_refresh`. A failed refresh keeps the last-good bundle, so logins keep working against the old authorities while refreshes fail silently in the background. Force a fetch with `auth/spiffe/trust-domain/<name>/refresh`; a `502` there reports the endpoint fetch error directly.

**`https_spiffe` federation won't configure.** The `https_spiffe` profile requires both `endpoint_spiffe_id` (a valid SPIFFE ID inside the trust domain being federated) and a bootstrap bundle (`bundle_json` or `bundle_pem`) that carries X.509 authorities to authenticate the endpoint's SVID on the first fetch. `https_web`, by contrast, rejects `endpoint_spiffe_id` and authenticates the endpoint with ordinary Web PKI.

## See Also

- [Authentication](../concepts/authentication.md) — the credential forms and how transparent auth resolves an identity per request.
- [Roles](../concepts/roles.md) — how a validated credential maps to policies and token settings.
- [Agent Identity](../agent-identity/README.md) — how a workload or its sidecar presents this credential to Warden.
- [Auth Methods](README.md) — the other auth methods Warden ships.
