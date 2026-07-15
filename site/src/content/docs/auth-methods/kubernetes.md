---
title: "Kubernetes"
---

The Kubernetes auth method validates workload identities by calling **TokenReview** on the issuing kube-apiserver. The hub holds no public keys for any spoke cluster — every authentication becomes a single HTTP call to the cluster that minted the workload's ServiceAccount token, and the spoke answers "is this token valid, and which SA does it belong to."

The workload doesn't make an explicit login call; the auth method participates in Warden's transparent-auth flow, where the workload includes its SA JWT in the `Authorization: Bearer` header on every gateway request and Warden's middleware does the TokenReview in-line (with per-request caching).

This is the auth method to reach for when:

- You want to give in-cluster workloads (pods running with a ServiceAccount) identity-bound access to Warden without distributing JWKS endpoints, static public keys, or OIDC discovery configuration.
- Your Kubernetes distribution is hardened (Talos default, CIS-baseline, kube-apiserver behind a NetworkPolicy) and exposing `/openid/v1/jwks` to Warden would require extra plumbing you don't want to operate.
- You run a multi-spoke topology — one Warden hub, several Kubernetes clusters — and want one auth mount per spoke rather than one JWKS-bridging side-car per spoke.

Operators who have used Vault's or OpenBao's `auth/kubernetes` will find the shape familiar: the mount points at one kube-apiserver, roles bind to ServiceAccount names and namespaces, and TokenReview does the validation.

## Prerequisites

- A **Warden server** unsealed and reachable from the workload's network.
- A **Kubernetes cluster** whose kube-apiserver is reachable from the Warden server (HTTPS).
- The kube-apiserver's **CA certificate** in PEM form. For a cluster reachable from a pod, this is the file at `/var/run/secrets/kubernetes.io/serviceaccount/ca.crt`. For external reachability, your cloud provider's documentation will point at the right CA bundle.
- A **role-mapping policy** in Warden that scopes what the resulting auth token can do (issuing a token doesn't grant access on its own).

## Step 1: Grant `system:auth-delegator` on the Spoke

Warden's TokenReview calls need permission to ask the kube-apiserver about other tokens. That permission lives in the built-in `system:auth-delegator` ClusterRole. **Who** holds that permission decides which mode you use:

**Reviewer mode (recommended).** Create a dedicated ServiceAccount in the cluster, bind it to `system:auth-delegator`, and use its token as Warden's `token_reviewer_jwt`. Workloads only need permission to *get* their own tokens (already granted to every SA by default) — they don't need any cluster-level RBAC.

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: warden-token-reviewer
  namespace: warden-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: warden-token-reviewer
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: system:auth-delegator
subjects:
  - kind: ServiceAccount
    name: warden-token-reviewer
    namespace: warden-system
```

Mint a long-lived token for that SA (or read a projected token from a pod that runs as it) and supply it as `token_reviewer_jwt` when you configure the auth method below.

**Self-reviewing mode.** If every workload SA that will log in to Warden is itself bound to `system:auth-delegator`, you can skip the reviewer SA entirely. The workload's own token does double duty: it's both the token under review (`spec.token` in the TokenReview request) and the bearer that authorizes the TokenReview call. Simpler to set up, broader RBAC footprint. See [Self-Reviewing Mode](#self-reviewing-mode-no-token_reviewer_jwt) for when this trade is worth it.

## Step 2: Enable and Configure the Auth Method

Enable the auth method at any path. For multi-spoke setups, use a path that names the spoke so logs and roles stay readable. The `-path` flag takes the mount name only — the CLI prefixes `auth/` automatically.

```bash
warden auth enable -path=k8s-prod kubernetes
```

Configure it against the cluster:

```bash
warden write auth/k8s-prod/config \
  kubernetes_host="https://prod-cluster.example.com:6443" \
  kubernetes_ca_cert=@/path/to/prod-cluster-ca.pem \
  token_reviewer_jwt=@/path/to/warden-token-reviewer.jwt
```

A few notes on this command:

- `kubernetes_host` is the kube-apiserver base URL, no trailing path. Warden constructs the TokenReview path itself.
- `kubernetes_ca_cert` accepts raw PEM (the `@/path` form reads from a file). No base64 wrapping needed — that's an operator-friendly choice that distinguishes this auth method's config from credential drivers (which use base64 transport).
- `token_reviewer_jwt` is read sensitively: any subsequent read of the config returns it masked.

Optional fields that matter on Day 2:

- `issuer` — if set, Warden compares the incoming JWT's `iss` claim to this value before calling TokenReview. Cheap pre-filter that saves a network round-trip when a workload presents a token from the wrong cluster. The standard value for a Kubernetes 1.21+ cluster is the cluster's configured `--service-account-issuer` (often `https://kubernetes.default.svc.cluster.local`).
- `token_ttl` — default TTL for issued Warden auth tokens; per-role overrides win.
- `default_role` — used by transparent-mode flows when the caller doesn't specify a role.
- `tls_skip_verify` — disables TLS validation. Dev only.

## Step 3: Create a Role Bound to Your Workload

A role is the gate between a Kubernetes ServiceAccount and the Warden policies it can assume. Bind it to the SA that your workload runs as.

```bash
warden write auth/k8s-prod/role/inventory-agent \
  bound_service_account_names="inventory-agent" \
  bound_service_account_namespaces="agents" \
  token_policies="inventory-read,inventory-write" \
  token_ttl="1h"
```

Both `bound_service_account_names` and `bound_service_account_namespaces` accept lists. A `"*"` wildcard matches any value, but **at least one of the two fields must contain a concrete value** — Warden refuses a `*`/`*` binding that would let any pod in the cluster assume the role. This matches Vault's behavior and is intentional defense in depth.

You can pin an audience too:

```bash
warden write auth/k8s-prod/role/inventory-agent \
  bound_service_account_names="inventory-agent" \
  bound_service_account_namespaces="agents" \
  audience="warden.example.com" \
  token_policies="inventory-read,inventory-write"
```

When `audience` is set, Warden passes it through to TokenReview's `spec.audiences`. The kube-apiserver only confirms the token if the workload requested that audience when minting it (via `serviceAccountToken.audience` on a projected volume mount). This lets you keep workload SA tokens scoped to specific Warden mounts even when one SA could in principle reach multiple mounts.

For freshness-sensitive flows, `max_age` rejects tokens whose `iat` (issued-at) claim is older than the configured duration — useful when you want to force re-mint cycles to be no longer than, say, 5 minutes.

## Step 4: Wire Up Transparent Auth

The kubernetes auth method is **transparent-only**. There is no "log in once, get a Warden bearer token" handshake the workload performs explicitly — `POST /auth/<mount>/login` for a `kubernetes_role` token is rejected at the request handler with `explicit login is not supported for roles with token_type=transparent`. The workload's ServiceAccount JWT flows through every call, and Warden's transparent middleware does the auth in-line.

The shape:

1. The workload includes its SA JWT in the `Authorization: Bearer` header on every request to a Warden gateway URL.
2. Warden resolves the auth mount via the provider's (or namespace's) `auto_auth_path` configuration.
3. Warden calls TokenReview against the configured kube-apiserver — or, if a prior call with the same (JWT, role) tuple is in cache, skips that round-trip.
4. The role's policies decide whether the upstream call goes through.

So the workload-side setup is per-provider, not per-workload:

- On the provider you want the workload to reach, set `auto_auth_path` to the kubernetes auth mount you configured in Step 2 (`auth/k8s-prod/`), and optionally a `default_role`.
- Inside the pod, mount the projected SA token (the default for any pod) and pass it as `Authorization: Bearer` on each Warden request.

A typical pod-side call looks like:

```bash
JWT=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)

curl -H "Authorization: Bearer $JWT" \
     -H "X-Warden-Role: inventory-agent" \
     "${WARDEN_ADDR}/v1/<provider>/gateway/<upstream-path>"
```

The role can be set via the `X-Warden-Role` header (as above), embedded in the URL path (`/role/<r>/gateway/...`), or fall back to the provider's `default_role` or the auth method's `default_role`.

The first request with a given (JWT, role) tuple triggers a TokenReview round-trip and caches the result. Subsequent requests with the same tuple hit Warden's in-memory cache (TTL = `min(role.token_ttl, jwt-exp-derived)`) — no TokenReview per call.

> **Why no explicit login endpoint for kubernetes?** The `kubernetes_role` token type is part of Warden's transparent-auth family (alongside `jwt_role` and `cert_role`). Explicit logins returning a transparent token type are rejected by design. This keeps the workload's identity — the SA JWT, attested by the kube-apiserver — flowing through every call so each request is independently auditable, with no operator-distributed Warden tokens to rotate or revoke separately.

## Self-Reviewing Mode (No `token_reviewer_jwt`)

If `token_reviewer_jwt` is left unset, Warden uses the workload's own JWT both as the bearer authorizing the TokenReview call and as the token under review. There's no second SA to provision and rotate, but every workload SA that authenticates through this mount must itself be bound to `system:auth-delegator` on the cluster.

This trade-off looks like:

- **Reviewer mode** — narrow RBAC footprint (one cluster SA holds the broad permission); operator overhead of provisioning and rotating one reviewer token per spoke.
- **Self-reviewing mode** — zero operator state in Warden config beyond the host + CA; broader RBAC footprint because every workload SA holds `system:auth-delegator` (transitively able to validate any token in the cluster, including tokens for other SAs).

For most production setups, reviewer mode is the right default. Self-reviewing makes sense when you control all workload SAs and prefer to avoid the per-spoke reviewer-token rotation cycle, or when the cluster only hosts one workload (rare).

## Multi-Spoke Topologies

For a Warden hub serving several Kubernetes clusters, mount the auth method once per cluster with distinct names:

```bash
warden auth enable -path=k8s-prod kubernetes
warden auth enable -path=k8s-staging kubernetes
warden auth enable -path=k8s-eks-iowa kubernetes
```

Each mount carries its own `kubernetes_host`, CA bundle, and reviewer JWT. Providers used by workloads in `prod` set `auto_auth_path=auth/k8s-prod/`, providers used by workloads in `staging` set `auto_auth_path=auth/k8s-staging/`, and so on. Roles live per mount, so the same role name (e.g. `inventory-agent`) can exist in two mounts with different bindings without colliding.

When a workload presents its SA token, Warden's mount-driven dispatch sends the TokenReview only to the spoke that mount points at — never to the other clusters. The introspect aggregator (`sys/introspect/roles`) fans out to every kubernetes mount in the namespace, but each mount's introspect handler short-circuits when its configured `issuer` doesn't match the token's `iss` claim — so only the mount pointing at the right cluster actually makes a TokenReview round-trip. Pinning `issuer` per mount is the easy way to avoid N spoke clusters all auditing each introspect call.

## Audience Binding

A workload that mints its SA token with a specific audience (`projected.serviceAccountToken.audience` in the pod spec) tells the cluster "this token is for service X." When the role pins the same audience, Warden's TokenReview asks the kube-apiserver "is this token good for audience X?" and the apiserver rejects the review if the audience doesn't match.

The practical use:

- Different Warden mounts each get a distinct audience string (e.g. `warden.us-east.example.com` vs `warden.eu-west.example.com`). A pod that mints `warden.us-east...` tokens can only log into the matching mount; the token won't validate against the other mount even if the SA name happens to match.
- Token capture from one Warden integration can't be replayed against another integration in the same cluster, because the captured token's audience won't match the second integration's role binding.

Without `audience`, the kube-apiserver returns whatever audiences the token naturally carries, and Warden accepts any of them. Add `audience` when you want enforcement; leave it empty when binding by SA name + namespace is enough.

## Token Metadata

A role can copy verified TokenReview attributes onto the issued token's metadata, where a CEL `condition` can match them via `token.metadata`. `metadata_mappings` is written as `attribute = "destination-metadata-key"`, drawing from: `service_account_namespace`, `service_account_name`, `service_account_uid`, `username`, and `groups` (multi-valued, comma-joined).

```bash
warden write auth/kubernetes/role/inventory-agent \
  bound_service_account_names="inventory-agent" \
  bound_service_account_namespaces="prod" \
  metadata_mappings="service_account_namespace=ns,service_account_name=sa"
```

A workload whose SA is `system:serviceaccount:prod:inventory-agent` yields metadata `ns="prod"`, `sa="inventory-agent"`. A policy can then gate a path with `condition = "token.metadata.ns == 'prod'"`. Unknown attribute selectors are rejected at role write time.

## Discovering Assumable Roles

Agents that don't know which role to ask for can use Warden's namespace-wide introspection endpoint to discover the roles their token could assume. The workload doesn't need to know which auth mount serves it — the aggregator detects the token's shape, fans out to every auth mount in the namespace whose registered TokenType matches that shape, and merges the responses.

The endpoint expects the workload's JWT in the `Authorization: Bearer` header (not the operator's Warden token), so the natural caller is the workload itself with `curl`:

```bash
JWT=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)

curl -H "Authorization: Bearer $JWT" \
  "${WARDEN_ADDR}/v1/sys/introspect/roles"
```

The response is `{roles: [{auth_path, name, description}, ...], warnings: [...]}`. Each role in the list has passed the SA name + namespace + audience checks against the presented token, and `auth_path` tells the agent which mount the role lives on. Introspection is a discovery hint, not an authorization — the agent picks a role and uses it on subsequent gateway requests (via the `X-Warden-Role` header or the URL-path form), where Warden's transparent-auth layer does the actual TokenReview + cache write.

A Kubernetes SA token (recognized by its `sub: system:serviceaccount:*` claim) only fans out to kubernetes mounts — generic JWTs from other identity providers don't trigger wasted TokenReview round-trips against your kube-apiserver. Within the kubernetes mounts that get visited, each one does at most one TokenReview call per introspect request (regardless of how many roles the mount has), and a mount whose pinned `issuer` doesn't match the token's `iss` claim short-circuits before that call too.

## Configuration Reference

### Mount configuration

| Field | Required | Description |
|---|---|---|
| `kubernetes_host` | Yes | Base URL of the kube-apiserver, e.g. `https://10.0.0.1:6443`. |
| `kubernetes_ca_cert` | Yes (unless `tls_skip_verify`) | PEM-encoded CA bundle used to validate the kube-apiserver's TLS certificate. Accepts raw PEM directly; no base64 wrapping. |
| `token_reviewer_jwt` | No | Hub-side ServiceAccount token used to authorize TokenReview calls. When set, reviewer mode is used. When unset, self-reviewing mode kicks in. Treated as a secret — masked on read. |
| `tls_skip_verify` | No (default `false`) | Disables TLS certificate validation. Dev only. |
| `issuer` | No | Expected value of the JWT's `iss` claim. When set, mismatched tokens are rejected before the TokenReview round-trip. |
| `disable_iss_validation` | No (default `false`) | Skips the `iss` pre-filter even when `issuer` is configured. |
| `token_ttl` | No (default `1h`) | Default TTL for issued Warden auth tokens; per-role `token_ttl` overrides. |
| `default_role` | No | Used by transparent-mode flows when the caller doesn't specify a role. |

### Role configuration

| Field | Required | Description |
|---|---|---|
| `bound_service_account_names` | At least one of names/namespaces must be a concrete value | List of ServiceAccount names accepted by this role. `"*"` matches any. |
| `bound_service_account_namespaces` | At least one of names/namespaces must be a concrete value | List of namespaces accepted by this role. `"*"` matches any. |
| `audience` | No | Required token audience. When set, passed through to TokenReview's `spec.audiences`. |
| `token_policies` | No | Warden policies attached to the issued token. |
| `token_ttl` | No (default `1h`) | TTL for issued tokens; overrides the mount-level `token_ttl`. |
| `cred_spec_name` | No | Credential spec name for implicit-auth flows. |
| `max_age` | No | Maximum elapsed time since the JWT's `iat` claim. Example: `30m`. Empty disables the check. |
| `metadata_mappings` | No | Map of TokenReview attribute (`service_account_namespace`, `service_account_name`, `service_account_uid`, `username`, `groups`) → token metadata key. `groups` is comma-joined. |

A `*`/`*` binding (both names and namespaces only contain `"*"`) is refused at role-create time — at least one of the two must contain a concrete value.

## Troubleshooting

**Gateway request returns "authentication failed" with no detail.** This is by design — all authentication failures collapse to the same generic error so the response can't be used to enumerate which check is failing. The Warden server logs carry the specific reason (SA binding mismatch, TokenReview rejection, issuer mismatch, expired token, etc.). Check the Warden server log at the timestamp of the failed call.

**Gateway request returns "explicit login is not supported for roles with token_type=transparent".** Something is hitting `auth/<mount>/login` directly instead of going through transparent auth on a gateway URL. The kubernetes auth method is transparent-only; the explicit-login endpoint is reserved for internal use. Make sure your client is calling a provider gateway path (e.g. `/v1/<provider>/gateway/...`) with the SA JWT in the `Authorization: Bearer` header — not posting to `/auth/<mount>/login`.

**TokenReview calls are spamming the kube-apiserver audit log.** Pin the `issuer` field on the mount. Once set, tokens whose `iss` claim doesn't match are rejected before any TokenReview round-trip — usually clears up the noise immediately. If the spam comes from agents that present non-K8s JWTs, the introspect aggregator's exact-match filter already prevents fan-out to kubernetes mounts for those, so the noise must be from explicit logins; check the workload code path.

**"Forbidden: cannot create resource tokenreviews".** The bearer used to authorize the TokenReview call doesn't have `system:auth-delegator`. In reviewer mode, this points at the reviewer ServiceAccount; in self-reviewing mode, it points at the workload's SA. Grant the binding (see Step 1) or switch modes.

**"Unauthorized" from the kube-apiserver.** The bearer token expired or was malformed. For reviewer mode, rotate the reviewer JWT and update `token_reviewer_jwt` in the mount config. For self-reviewing mode, the workload's projected token rotates automatically (kubelet refreshes around 80% of its lifetime); if you're still seeing this, the kubelet may not be mounting a projected token — check the pod spec.

**Role binding rejects what looks like a matching SA.** TokenReview returns the SA identity as `system:serviceaccount:<namespace>:<name>`. Warden parses both halves out and matches the namespace half against `bound_service_account_namespaces` and the name half against `bound_service_account_names`. If your role pins `bound_service_account_namespaces=default` but the workload is in `kube-system`, the binding correctly rejects — even if the SA name is right.

**Cached auth entries expire faster than expected.** Warden's cached transparent-auth entry has a TTL equal to the minimum of the role's `token_ttl` and the workload JWT's remaining lifetime. Pods that have been running near the end of their projected-token cycle will get short-lived cache entries. The kubelet refreshes the projected token before expiry, so the next gateway request with the refreshed JWT seeds a new cache entry with the full TTL.

## See Also

- [Authentication](/concepts/authentication/) — the credential forms and how transparent auth resolves an identity per request.
- [Roles](/concepts/roles/) — how a validated credential maps to policies and token settings.
- [Agent Identity](/agent-identity/) — how a workload or its sidecar presents this credential to Warden.
- [Auth Methods](/auth-methods/) — the other auth methods Warden ships.
