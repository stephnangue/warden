---
title: "JWT"
---

The JWT auth method validates workload identities by **cryptographically verifying** the signature of a JSON Web Token against a configured key source. The hub holds (or fetches) the issuer's public keys directly; no upstream API call is made per login. Validated claims drive role binding (issuer, audience, subject, arbitrary bound claims), and the resolved principal flows through Warden's transparent-auth layer like any other auth method in the family.

This is the auth method to reach for when:

- Your workloads carry tokens issued by an **OIDC provider** (Auth0, Okta, Keycloak, Google, Azure AD, GitHub Actions OIDC, GitLab CI OIDC, Forgejo, Hydra, Dex, …) and you want their JWTs accepted directly.
- You have a fixed set of static issuer keys (PEM-encoded RSA or ECDSA) and no JWKS endpoint to publish them, and want to ship them with the Warden configuration.
- You need claim-driven role mapping — e.g. policies attached from the JWT's `groups` claim, or per-tenant routing via a custom `tenant` claim.

If your workload's identity is a Kubernetes ServiceAccount token, prefer the `kubernetes` auth method instead — it validates via TokenReview against the issuing cluster and avoids the JWKS distribution problem entirely. The JWT method works for K8s SA tokens too (the cluster's `/openid/v1/jwks` endpoint is a perfectly valid JWKS source), but only when that endpoint is reachable from Warden, which hardened distros often make awkward.

If your workloads present **SPIFFE identities** — an X.509-SVID or a JWT-SVID — use the dedicated `spiffe` auth method instead. It verifies the SVID against a trust-domain bundle and enforces the SPIFFE audience requirement, which generic JWT claim-binding here cannot do.

## Prerequisites

- A **Warden server** unsealed and reachable from the workload's network.
- One of:
  - An **OIDC issuer** with a discovery endpoint (the issuer URL — Warden appends `/.well-known/openid-configuration`).
  - A standalone **JWKS endpoint** (a URL serving the issuer's public keys as JSON Web Key Set).
  - A set of **PEM-encoded RSA or ECDSA public keys** (when no JWKS endpoint is reachable).
- A **role-mapping policy** in Warden that scopes what the resulting auth token can do (issuing a token doesn't grant access on its own).

## Step 1: Configure the Key Source

Enable the auth method:

```bash
warden auth enable jwt
```

This mounts at `auth/jwt/` (the default when `-path` is omitted matches the type). If you need multiple JWT mounts with different key sources — e.g. one per tenant or per IdP — use `-path` to name them:

```bash
warden auth enable -path=jwt-tenant-a jwt
warden auth enable -path=jwt-tenant-b jwt
```

The `-path` flag takes the mount name only; the CLI prefixes `auth/` automatically.

Then configure one — and only one — of the three key sources. The mount enforces this; mixed configurations are rejected.

**OIDC discovery** (most common — for any provider that publishes `/.well-known/openid-configuration`):

```bash
warden write auth/jwt/config \
  oidc_discovery_url="https://accounts.google.com" \
  default_role="default"
```

If the issuer's TLS chain isn't in the system roots, pass the CA bundle:

```bash
warden write auth/jwt/config \
  oidc_discovery_url="https://issuer.internal.example.com" \
  oidc_discovery_ca_pem=@/path/to/internal-ca.pem
```

**JWKS endpoint** (for issuers that publish a JWKS URL but no full OIDC discovery doc):

```bash
warden write auth/jwt/config \
  jwks_url="https://issuer.example.com/.well-known/jwks.json" \
  jwks_ca_pem=@/path/to/issuer-ca.pem
```

**Static PEM public keys** (for air-gapped clusters or fixed-issuer workloads where neither OIDC nor JWKS is reachable):

```bash
warden write auth/jwt/config \
  jwt_validation_pubkeys=@/path/to/issuer-pubkey.pem
```

Multiple PEM keys can be supplied as a comma-separated list — useful during key rotation when the issuer may sign with either of two keys.

**Quickstart (Ory Hydra).** The provider guides use the local [dev setup](/provider-backends/local-dev-setup/), whose bundled Hydra publishes a JWKS endpoint. Point the mount at it:

```bash
warden auth enable jwt
warden write auth/jwt/config jwks_url=http://localhost:4444/.well-known/jwks.json
```

## Step 2: Add Issuer / Audience / Claim Bindings

Bindings configured on the mount apply to every login through it (a role may override most of them with per-role bindings).

```bash
warden write auth/jwt/config \
  bound_issuer="https://accounts.google.com" \
  bound_audiences="my-warden-instance" \
  user_claim="email"
```

What each does:

- `bound_issuer` — the expected value of the JWT's `iss` claim. Required for almost every real-world deployment. Without it, any JWT signed by a key your discovery endpoint serves will pass.
- `bound_audiences` — accepted values of the JWT's `aud` claim. Tokens whose audience isn't in this list are rejected. Pin this when the issuer signs tokens for multiple audiences and only some should be allowed to talk to Warden.
- `bound_subject` — pin the expected `sub` claim. Rarely set at the mount level (more often per-role).
- `bound_claims` — a map of arbitrary claim → required value pairs. Tokens missing any required claim or carrying a mismatched value are rejected.
- `user_claim` — which claim Warden uses as the principal identity in audit logs and the issued token's `PrincipalID`. Defaults to `sub`. Override to `email`, `preferred_username`, or `name` as appropriate.

## Step 3: Create a Role

A role decides which Warden policies are stamped on the issued token and can tighten the claim bindings beyond what the mount already requires.

```bash
warden write auth/jwt/role/inventory-agent \
  bound_subject="agent@example.com" \
  token_policies="inventory-read,inventory-write" \
  token_ttl="1h"
```

Per-role overrides (when set, these win over the mount-level bindings):

- `bound_audiences` — narrower audience list than the mount's.
- `bound_subject` — different expected `sub` than the mount.
- `bound_claims` — additional claim → value pairs the role insists on.

Per-role-only fields:

- `max_age` — a freshness check: tokens whose `iat` (issued-at) claim is older than this duration are rejected. Useful when you want to force re-mint cycles to be no longer than, say, 5 minutes.
- `cred_spec_name` — the credential spec to use for implicit-auth flows.

A role's `TokenType` is always pinned to `jwt_role`; operators can't override it.

## Step 4: Wire Up Transparent Auth

The JWT auth method is **transparent-only**. There is no "log in once, get a Warden bearer token" handshake the workload performs explicitly — `POST /auth/<mount>/login` for a `jwt_role` token is rejected at the request handler with `explicit login is not supported for roles with token_type=transparent`. The workload's JWT flows through every call, and Warden's transparent middleware does the validation in-line.

The shape:

1. The workload includes its JWT in the `Authorization: Bearer` header on every request to a Warden gateway URL.
2. Warden resolves the auth mount via the provider's (or namespace's) `auto_auth_path` configuration.
3. Warden validates the JWT against the mount's keyset and bindings — or, if a prior call with the same (JWT, role) tuple is in cache, skips that work.
4. The role's policies decide whether the upstream call goes through.

So the workload-side setup is per-provider, not per-workload:

- On the provider you want the workload to reach, set `auto_auth_path` to the JWT auth mount you configured (`auth/jwt/`), and optionally a `default_role`.
- The workload passes its JWT as `Authorization: Bearer` on each Warden request.

A typical workload-side call looks like:

```bash
curl -H "Authorization: Bearer $JWT" \
     -H "X-Warden-Role: inventory-agent" \
     "${WARDEN_ADDR}/v1/<provider>/gateway/<upstream-path>"
```

The role can be set via the `X-Warden-Role` header (as above), embedded in the URL path (`/role/<r>/gateway/...`), or fall back to the provider's `default_role` or the auth method's `default_role`.

The first request with a given (JWT, role) tuple triggers a fresh signature + claim validation and caches the result. Subsequent requests with the same tuple hit Warden's in-memory cache (TTL = `min(role.token_ttl, jwt-exp-derived)`) — no signature re-verification per call.

> **Why no explicit login endpoint?** The `jwt_role` token type is part of Warden's transparent-auth family (alongside `cert_role` and `kubernetes_role`). Explicit logins returning a transparent token type are rejected by design. This keeps the workload's identity — the JWT, attested by the IdP — flowing through every call so each request is independently auditable, with no operator-distributed Warden tokens to rotate or revoke separately.

## Obtaining a JWT

The workload gets its JWT from your identity provider — the same IdP whose keys back the mount's [key source](#step-1-configure-the-key-source). How depends on the provider (OAuth2 client-credentials, an OIDC device flow, a CI runner's OIDC token, etc.).

For the local [dev setup](/provider-backends/local-dev-setup/), the bundled Ory Hydra issues one via the OAuth2 client-credentials grant:

```bash
export JWT=$(curl -s -X POST http://localhost:4444/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=my-agent&client_secret=agent-secret&scope=api:read api:write" \
  | jq -r '.access_token')
```

The workload then presents `$JWT` on every gateway request (as `Authorization: Bearer`, or via the provider-specific credential field documented in each provider guide).

## Group-Based Policies

If your IdP issues a `groups` claim (or any list-typed claim listing the user's groups), Warden can stamp one policy per group onto the issued token, in addition to the role's static `token_policies`.

```bash
warden write auth/jwt/config \
  groups_claim="groups" \
  group_policy_prefix="oidc-"
```

A JWT carrying `"groups": ["engineering", "billing-admin"]` gets `oidc-engineering` and `oidc-billing-admin` appended to its policy list.

The prefix is required to keep group-derived policies in a namespace operators can recognize and reason about (e.g. you'd write a policy named `oidc-engineering`, knowing it auto-attaches to anyone in that IdP group). Default prefix is `group-`.

Per-role overrides for `groups_claim` and `group_policy_prefix` let one mount serve multiple IdP claim conventions.

## Token Metadata

A role's `metadata_claims` copies verified JWT claims onto the issued token's metadata, where a CEL `condition` can match them via `token.metadata`. The mapping is `source-claim=destination-metadata-key`. The source is a literal claim name, or a JSON Pointer (leading `/`) for a nested claim; resolved values must be strings.

```bash
warden write auth/jwt/role/inventory-agent \
  metadata_claims="department=dept,/resource_access/warden/env=env"
```

A JWT with `"department": "eng"` and a nested `resource_access.warden.env` of `"prod"` produces a token whose metadata carries `dept="eng"` and `env="prod"`. A policy can then gate a path with `condition = "token.metadata.env == 'prod'"`. When a `condition` reads a metadata value to decide a request, that value is recorded in the audit entry under `auth.policy_results.condition.inputs` (keyed by the CEL path, e.g. `token.metadata.env`) — logged in clear by default, salt-able per key via the audit device's `salt_fields`.

> **Note:** metadata is matched at request time against the token's own values and is never compiled into the policy, so it stays correct for every token. Use it for authorization decisions that depend on identity attributes rather than path/capability alone.

## On-Behalf-Of Chain (RFC 8693 `act` Claim)

RFC 8693 §4.1 defines an `act` claim that attests a delegation chain — "this token represents X, who is acting on behalf of Y, who is acting on behalf of Z." When present, Warden extracts the chain (up to a fixed depth of 4 to guard against pathological tokens), marks each actor as verified (because the IdP signed it), and persists it on the issued token. Audit log entries for downstream requests carry the full chain.

No configuration needed — extraction happens automatically when the claim is present. Policies that want to inspect the chain can do so via the token's `actors` field.

## Discovering Assumable Roles

Agents that don't know which role to ask for can use Warden's namespace-wide introspection endpoint. The aggregator detects the token's shape (generic JWT vs Kubernetes SA JWT) and fans out only to auth mounts whose registered TokenType matches — so a generic JWT goes to JWT mounts, a K8s SA token goes to kubernetes mounts. The workload doesn't need to know which mount serves it.

The endpoint expects the workload's JWT in the `Authorization: Bearer` header (not the operator's Warden token), so the natural caller is the workload itself with `curl`:

```bash
curl -H "Authorization: Bearer $JWT" \
  "${WARDEN_ADDR}/v1/sys/introspect/roles"
```

The response is `{roles: [{auth_path, name, description}, ...], warnings: [...]}`. Each role in the list has passed the issuer + audience + subject + bound-claims checks against the presented token, and `auth_path` tells the agent which mount the role lives on. Introspection is a discovery hint, not an authorization — the agent picks a role and uses it on subsequent gateway requests, where Warden's transparent-auth layer does the actual validation + cache write.

Per-mount introspection (`auth/<mount>/introspect/roles`) exists too — the aggregator calls it internally — but workloads should prefer the aggregator since it handles dispatch.

## Configuration Reference

### Mount configuration

Exactly one of `oidc_discovery_url`, `jwks_url`, or `jwt_validation_pubkeys` must be set; mixed configurations are rejected at write time.

| Field | Required | Description |
|---|---|---|
| `oidc_discovery_url` | one of three | OIDC issuer URL. Warden appends `/.well-known/openid-configuration` and fetches the JWKS from the discovered endpoint. |
| `oidc_discovery_ca_pem` | No | PEM-encoded CA bundle for the discovery endpoint when its TLS chain isn't in the system roots. |
| `jwks_url` | one of three | Direct JWKS endpoint URL when the issuer doesn't publish full OIDC discovery. |
| `jwks_ca_pem` | No | PEM-encoded CA bundle for the JWKS endpoint. |
| `jwt_validation_pubkeys` | one of three | PEM-encoded RSA or ECDSA public keys (comma-separated for rotation overlap). For air-gapped clusters and fixed-issuer setups. |
| `bound_issuer` | No (but strongly recommended) | Expected value of the JWT's `iss` claim. Without this, any JWT signed by a key the configured source serves will pass. |
| `bound_audiences` | No | Accepted values of the JWT's `aud` claim. Roles may override with their own list. |
| `bound_subject` | No | Pinned `sub` claim. Roles may override. |
| `bound_claims` | No | Map of arbitrary claim → required value. Roles may add their own claims. |
| `user_claim` | No (default `sub`) | Which claim Warden uses as the principal identity. |
| `groups_claim` | No | JWT claim carrying a list of group names. When set, group-derived policies are appended to the issued token. |
| `group_policy_prefix` | No (default `group-`) | Prefix prepended to each group name to form the policy name. |
| `token_ttl` | No (default `1h`) | Default TTL for issued Warden auth tokens; per-role `token_ttl` overrides. |
| `default_role` | No | Used by transparent-mode flows when the caller doesn't specify a role. |

### Role configuration

| Field | Required | Description |
|---|---|---|
| `bound_audiences` | No | Per-role audience binding; overrides the mount's `bound_audiences` when set. |
| `bound_subject` | No | Per-role subject binding; overrides the mount's `bound_subject` when set. |
| `bound_claims` | No | Per-role claim requirements; merged with the mount's `bound_claims` (both must pass). |
| `user_claim` | No | Per-role override of the mount's `user_claim`. |
| `token_policies` | No | Warden policies attached to the issued token (in addition to any group-derived policies). |
| `token_ttl` | No (default `1h`) | TTL for issued tokens; overrides the mount-level `token_ttl`. |
| `groups_claim` | No | Per-role override of the mount's `groups_claim`. |
| `group_policy_prefix` | No | Per-role override of the mount's `group_policy_prefix`. |
| `metadata_claims` | No | Map of source claim (literal or JSON Pointer) → token metadata key. Copies verified claims into the token's metadata for CEL `condition` matching via `token.metadata`. Values must be strings. |
| `cred_spec_name` | No | Credential spec name for implicit-auth flows. |
| `max_age` | No | Maximum elapsed time since the JWT's `iat` claim. Example: `30m`. Empty disables the check. |

## Troubleshooting

**Gateway request returns "authentication failed" with no detail.** This is by design — all authentication failures collapse to the same generic error so the response can't be used to enumerate which check is failing. The Warden server logs carry the specific reason (signature mismatch, expired token, missing required claim, bound-audiences mismatch, `max_age` exceeded, etc.). Check the Warden server log at the timestamp of the failed call.

**Gateway request returns "explicit login is not supported for roles with token_type=transparent".** Something is hitting `auth/<mount>/login` directly instead of going through transparent auth on a gateway URL. The JWT auth method is transparent-only; the explicit-login endpoint is reserved for internal use. Make sure your client is calling a provider gateway path (e.g. `/v1/<provider>/gateway/...`) with the JWT in the `Authorization: Bearer` header — not posting to `/auth/<mount>/login`.

**"failed to fetch JWKS" / "OIDC discovery endpoint not reachable".** Warden hits the discovery URL (or JWKS URL) at config-write time to validate the configuration before persisting. Make sure the URL is reachable from the Warden server's network, and that the CA bundle (`oidc_discovery_ca_pem` / `jwks_ca_pem`) covers the endpoint's TLS chain if it's not a public CA. For air-gapped clusters, switch to `jwt_validation_pubkeys` with static PEM keys.

**Tokens from one IdP pass, tokens from another IdP fail with no clear reason.** Pin `bound_issuer` to the expected `iss` value. Without it, any JWT signed by a key your discovery / JWKS source returns will pass the signature check, which can produce surprising allows when the IdP signs for multiple consumers.

**Group-based policies aren't being applied.** Verify the JWT actually carries the `groups` claim. Warden accepts three shapes for it: a JSON array of strings (`["engineering", "billing"]`), a comma-separated string (`"engineering,billing"`), or a single string (treated as a one-element list). A JSON-encoded string that *looks* like an array (`"[engineering, billing]"`) is not parsed and won't work. If the claim is named something other than `groups`, set `groups_claim` accordingly on the mount or role. Verify the resulting policy names (e.g. `oidc-engineering`) actually exist in Warden.

**`max_age` rejects every login.** The JWT must carry an `iat` (issued-at) claim for the freshness check to work. Some IdPs omit `iat`; if yours does, you can't use `max_age` against tokens from it. Either configure the IdP to emit `iat` or drop `max_age` from the role.

## See Also

- [Authentication](/concepts/authentication/) — the credential forms and how transparent auth resolves an identity per request.
- [Roles](/concepts/roles/) — how a validated credential maps to policies and token settings.
- [Agent Identity](/agent-identity/) — how a workload or its sidecar presents this credential to Warden.
- [Auth Methods](/auth-methods/) — the other auth methods Warden ships.
