---
title: "Kubernetes"
---

The Kubernetes auth method verifies workload identities by calling **TokenReview** on the issuing kube-apiserver. The hub holds no public keys for any spoke cluster: every check is a single HTTP call to the cluster that minted the workload's ServiceAccount token, and the spoke answers "is this token valid, and which service account does it belong to."

The workload makes no login call. It sends its ServiceAccount JWT as `Authorization: Bearer` on every gateway request, and Warden asks the mount to admit it there (see [Implicit authentication](/identity/authentication/#implicit-authentication)). The mount records what the TokenReview verified as **facts**, and takes the service account's username as the caller's **native identity**. It grants nothing: a [role](/identity/roles/) is granted per request by a [group](/identity/groups/) whose rules match those facts.

This is the auth method to reach for when:

- You want to give in-cluster workloads (pods running with a ServiceAccount) access to Warden without distributing JWKS endpoints, static public keys, or OIDC discovery configuration.
- Your Kubernetes distribution is hardened (Talos default, CIS-baseline, kube-apiserver behind a NetworkPolicy) and exposing `/openid/v1/jwks` to Warden would require extra plumbing you don't want to operate.
- You run a multi-spoke topology — one Warden hub, several Kubernetes clusters — and want one auth mount per spoke rather than one JWKS-bridging side-car per spoke.

Coming from v0.21.0? See [Upgrading from v0.21.0](/upgrade/from-v0-21/).

## Prerequisites

- A **Warden server** unsealed and reachable from the workload's network.
- A **Kubernetes cluster** whose kube-apiserver is reachable from the Warden server (HTTPS).
- The kube-apiserver's **CA certificate** in PEM form. For a cluster reachable from a pod, this is the file at `/var/run/secrets/kubernetes.io/serviceaccount/ca.crt`. For external reachability, your cloud provider's documentation will point at the right CA bundle.
- The **policies** the workload's role will carry. Admitting a credential grants nothing on its own.

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

Mint a long-lived token for that SA (the API server caps the duration at its `--service-account-max-token-expiration`), or read a projected token from a pod that runs as it:

```bash
kubectl create token warden-token-reviewer -n warden-system --duration=8760h > warden-token-reviewer.jwt
```

**Self-reviewing mode.** If every workload SA that authenticates through the mount is itself bound to `system:auth-delegator`, you can skip the reviewer SA entirely. The workload's own token does double duty: it's both the token under review (`spec.token` in the TokenReview request) and the bearer that authorizes the TokenReview call. Simpler to set up, broader RBAC footprint. See [Self-Reviewing Mode](#self-reviewing-mode-no-token_reviewer_jwt) for when this trade is worth it.

## Step 2: Enable and Configure the Mount

Enable the auth method at any path. For multi-spoke setups, use a path that names the spoke so logs and group rules stay readable. The `-path` flag takes the mount name only — the CLI prefixes `auth/` automatically.

```bash
warden auth enable -path=k8s-prod kubernetes
```

The configuration carries a PEM certificate, whose base64 can hold `=`, and `warden write` reads an argument with an `=` in it as `key=value` pairs. So build the JSON in a file with `jq` and pass it on stdin:

```bash
jq -n \
  --rawfile ca prod-cluster-ca.pem \
  --rawfile reviewer warden-token-reviewer.jwt \
  '{
    "kubernetes_host": "https://prod-cluster.example.com:6443",
    "kubernetes_ca_cert": $ca,
    "token_reviewer_jwt": ($reviewer | rtrimstr("\n")),
    "issuer": "https://kubernetes.default.svc.cluster.local",
    "bound_audiences": ["warden"],
    "entity_kind": "agent"
  }' > k8s-prod.json

warden write auth/k8s-prod/config < k8s-prod.json
warden read auth/k8s-prod/config
```

A few notes on this configuration:

- `kubernetes_host` is the kube-apiserver base URL, no trailing path. Warden builds the TokenReview path itself.
- `kubernetes_ca_cert` takes raw PEM, with no base64 wrapping. It is required unless `tls_skip_verify` is `true`.
- `token_reviewer_jwt` is a secret: a config read returns it masked. The `rtrimstr` drops the newline `kubectl` writes after the token, which would otherwise travel in the TokenReview's `Authorization` header.
- `issuer` pins the token's `iss` claim. Warden compares it before calling TokenReview, a cheap pre-filter that saves a network round-trip when a workload presents a token from the wrong cluster. The usual value is the cluster's `--service-account-issuer` (often `https://kubernetes.default.svc.cluster.local`).
- `bound_audiences` is sent to every TokenReview as `spec.audiences`. It is optional on this method, but without it the mount admits a default ServiceAccount token minted for the Kubernetes API, and every config read and write warns about it. See [Audience Binding](#audience-binding).
- `entity_kind` is `agent` by default.
- `max_age` (not set here) refuses a token whose `iat` is older than the duration, or that has no `iat`. Set it above the age your projected tokens reach: the kubelet replaces a token once it is 80% through its lifetime, so a one-hour token can be 48 minutes old.

A config write merges onto the stored configuration: keys you leave out are kept.

## Step 3: Create a Role and Grant It

A role names the policies a request runs under. It lives in the namespace, not on the mount:

```bash
warden role create inventory-agent -json '{
  "description": "Read and update the inventory",
  "policies": ["inventory-read", "inventory-write"],
  "provider_path": "vault/"
}'
```

`description` and `provider_path` are what the [discovery server](/concepts/discovery-and-skills/#discovering-roles) shows an agent: what the role is for, and the URL to call it at.

Nobody holds the role yet. A virtual group grants it to callers whose facts match its rules. This one grants `inventory-agent` to the `inventory-agent` ServiceAccount in the `agents` namespace of the prod cluster:

```bash
warden identity group create inventory-agents -json '{
  "type": "virtual",
  "description": "The inventory-agent service account on the prod cluster",
  "roles": ["inventory-agent"],
  "rules": [
    {
      "mount": ["auth/k8s-prod/"],
      "service_account_namespace": ["agents"],
      "service_account_name": ["inventory-agent"]
    }
  ]
}'
```

Every rule names the `mount` it trusts, so a token admitted through another cluster's mount never matches, even with the same namespace and name. Selectors in one rule must all match; a group with several rules matches when any one does. Values can be globs: `"service_account_name": ["inventory-*"]` matches every service account whose name starts with `inventory-`. The rule syntax is on [Groups](/identity/groups/#rules-and-selectors).

## Step 4: Point a Provider at the Mount

A provider's gateway asks the mount named by its `auto_auth_path` to admit the credential. Set it on the provider the workload calls:

```bash
warden write vault/config '{
  "auto_auth_path": "auth/k8s-prod/"
}'
```

Inside the pod, read the projected SA token and send it on each request. The role goes in the URL:

```bash
JWT=$(cat /var/run/secrets/warden/token)

curl -H "Authorization: Bearer $JWT" \
     "${WARDEN_ADDR}/v1/vault/role/inventory-agent/gateway/<upstream-path>"
```

A request can also name its role with the `X-Warden-Role` header, or fall back to the provider's `default_role`. A request that names no role is refused with `400` before its token is checked (see [How a request selects a role](/identity/roles/#how-a-request-selects-a-role)).

Warden keeps one cached admission per mount and token. The first request with a given token triggers a TokenReview; the requests after it reuse the result until the token expires or the mount's `token_ttl` (default `1h`) runs out, whichever is first. The role is still checked against the groups on every request, so a group or role change applies from the next one.

> **Why no login step for Kubernetes?** The workload's identity — the SA JWT, attested by the kube-apiserver — flows through every call, so each request is independently auditable, and there are no Warden tokens to distribute, rotate or revoke. A login against `auth/<mount>/login` runs the same checks and reports what they verified, but returns nothing to present on later requests.

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

Each mount carries its own `kubernetes_host`, CA bundle, reviewer JWT and `bound_audiences`. Providers used by workloads in `prod` set `auto_auth_path` to `auth/k8s-prod/`, providers used by workloads in `staging` to `auth/k8s-staging/`, and so on. Groups tell the clusters apart by `mount`: a rule on `auth/k8s-prod/` never matches a token admitted by `auth/k8s-staging/`, even for a service account of the same namespace and name. One group can trust several clusters by listing several mounts in a rule.

A workload's TokenReview goes only to the spoke its provider's mount points at. Discovery admits the presented token at each mount a role of the namespace is reached through, so with several spokes it can call more than one of them. Pin `issuer` on every mount: a token whose `iss` doesn't match is refused before any TokenReview, and the other spokes never see it.

## Audience Binding

A workload that mints its SA token with a specific audience (`serviceAccountToken.audience` on a projected volume) tells the cluster "this token is for service X." When the mount's `bound_audiences` lists X, Warden asks TokenReview "is this token good for audience X?", and the kube-apiserver refuses the review if it isn't. Warden also checks that the review reports one of the bound audiences back.

A pod that mints a token for Warden:

```yaml
spec:
  serviceAccountName: inventory-agent
  containers:
    - name: agent
      image: example/inventory-agent:1.4
      volumeMounts:
        - name: warden-token
          mountPath: /var/run/secrets/warden
          readOnly: true
  volumes:
    - name: warden-token
      projected:
        sources:
          - serviceAccountToken:
              path: token
              audience: warden
              expirationSeconds: 3600
```

The practical use:

- The default token every pod gets is minted for the Kubernetes API. With `bound_audiences` set, Warden refuses it, so a token stolen from a pod's default mount is useless against Warden.
- Different Warden mounts each get a distinct audience string (e.g. `warden.us-east.example.com` vs `warden.eu-west.example.com`). A token minted for one won't validate against the other, even if the SA name matches.

With `bound_audiences` empty, TokenReview checks the API server's own audience, so the default token is admitted, and config reads and writes warn: `bound_audiences is empty: TokenReview checks the API server's own audience, so a default service-account token for the Kubernetes API is admitted too`. The audiences the review validated are the `aud` fact either way.

## Facts and Native Identity

Every admission through a kubernetes mount carries these facts, which group rules select on:

| Fact | Value |
|---|---|
| `mount` | The mount's path in its namespace, e.g. `auth/k8s-prod/`. |
| `kind` | `agent` or `human`, from `entity_kind`. |
| `service_account_namespace` | The ServiceAccount's namespace, parsed from the reviewed username. |
| `service_account_name` | The ServiceAccount's name. |
| `service_account_uid` | The ServiceAccount's UID, as TokenReview reports it. |
| `username` | `system:serviceaccount:<namespace>:<name>`. |
| `groups` | The groups TokenReview reports, e.g. `system:serviceaccounts`, `system:serviceaccounts:agents`. |
| `aud` | The audiences TokenReview validated. |

A token whose reviewed username does not name a ServiceAccount is not admitted.

`facts` can publish one of these fields again under a second name. Only these fields can be sources; a mount maps at most 32, and `mount` and `kind` are reserved. Mapped facts also reach [CEL conditions](/concepts/cel-conditions/) as `agent.metadata.<name>` (a multi-valued fact joined with commas); map a field to its own name to expose it unchanged:

```bash
warden write auth/k8s-prod/config '{
  "facts": {
    "service_account_namespace": "k8s_namespace",
    "groups": "groups"
  }
}'
```

A policy can then gate a path with `condition = "agent.metadata.k8s_namespace == 'agents'"`. A write replaces the whole `facts` map; an empty map clears it.

The **native identity** is the `username` by default. `alias_name_source` can set it to `service_account_uid` instead, which is stricter: a ServiceAccount deleted and created again under the same name gets a new UID, so it is a new identity. No other value is allowed.

## Registering the Workload

The steps above grant roles to any token that matches the group's rules. To give the workload a record in the identity store, with a description, a sponsor and a state you can suspend, create an [entity](/identity/entities/) and have it claim the workload's native identity.

Once an entity claims it, virtual groups no longer apply to the workload: it holds only what static groups listing its entity grant, and only while the entity is governed. So create the entity without a claim, give it a [sponsor](/identity/sponsors/) and a static group, and claim last:

```bash
warden identity entity create inventory-agent -json '{
  "description": "Reads and updates the inventory"
}'

# ... propose a sponsor and list the entity in a static group, then:
warden identity alias add -json '{
  "mount": "auth/k8s-prod/",
  "name": "system:serviceaccount:agents:inventory-agent",
  "to": "inventory-agent"
}'
```

With `alias_name_source` set to `service_account_uid`, the `name` is the ServiceAccount's UID instead. [Entities](/identity/entities/#rolling-out) walks through the rollout.

## Discovering Roles

An agent that doesn't know which role to ask for asks the MCP discovery server's `list_roles`, which returns each role the groups grant it with its description, skill and URL — see [Discovery and Skills](/concepts/discovery-and-skills/#discovering-roles). Over plain HTTP, the workload presents its own JWT:

```bash
JWT=$(cat /var/run/secrets/warden/token)

curl -H "Authorization: Bearer $JWT" \
  "${WARDEN_ADDR}/v1/sys/introspect/roles"
```

The response is `{roles: [{name, description, skill, provider_path}, ...], warnings: [...]}`. Warden admits the token at each mount a role of the namespace is reached through (its provider's `auto_auth_path`) and lists the roles a group grants it there. A mount that could not decide (unconfigured, or its TokenReview failed) adds a warning; one that does not admit the token is silent. Discovery is a hint, not a grant: each gateway request is admitted and checked against the groups again.

## Configuration Reference

### Mount configuration (`auth/<mount>/config`)

| Field | Required | Description |
|---|---|---|
| `kubernetes_host` | Yes | Base URL of the kube-apiserver, e.g. `https://10.0.0.1:6443`. |
| `kubernetes_ca_cert` | Yes (unless `tls_skip_verify`) | PEM-encoded CA bundle used to validate the kube-apiserver's TLS certificate. Raw PEM; no base64 wrapping. |
| `token_reviewer_jwt` | No | ServiceAccount token that authorizes TokenReview calls (reviewer mode). When unset, the workload's own token is used (self-reviewing mode). Masked on read. |
| `tls_skip_verify` | No (default `false`) | Disables TLS certificate validation. Dev only. |
| `issuer` | No | Expected value of the JWT's `iss` claim. When set, a mismatched token is refused before the TokenReview round-trip. |
| `disable_iss_validation` | No (default `false`) | Skips the `iss` pre-filter even when `issuer` is set. |
| `bound_audiences` | No | Audiences a token must carry, any one of them, sent to TokenReview as `spec.audiences`. Empty checks the API server's own audience, with a warning. No entry may be empty. |
| `max_age` | No | Maximum age of a token at admission, from its `iat`, e.g. `15m`. A token older than that, or without an `iat`, is refused. Empty or `0` leaves it unset. |
| `token_ttl` | No (default `1h`) | How long an admission is reused before the token is reviewed again, capped by the token's `exp`. |
| `entity_kind` | No (default `agent`) | `agent` or `human`: the `kind` fact of every admission. |
| `facts` | No | Map of a built-in field (`service_account_namespace`, `service_account_name`, `service_account_uid`, `username`, `groups`, `aud`) to the extra fact name it is published as. At most 32. A write replaces the whole map. |
| `alias_name_source` | No (default `username`) | The fact the native identity is taken from: `username` or `service_account_uid`. Applies to tokens admitted after the change. |

A config write merges onto the stored configuration. A write that carries a key the mount no longer accepts is refused with `400`, naming the key and what replaced it.

## Troubleshooting

**Gateway request returns `401` with no detail.** This is by design — every admission failure collapses to the same response, so it can't be used to learn which check failed. The Warden server log carries the reason (`implicit authentication failed`, with the TokenReview rejection, issuer mismatch, audience mismatch, `max_age`, or a username that is not a ServiceAccount). Check it at the timestamp of the failed call.

**`400` "no role selected".** The request named no role and the provider has no `default_role`. Put the role in the URL (`/v1/<provider>/role/<role>/gateway/...`) or set `X-Warden-Role`.

**`403` `role "inventory-agent" is not assumable through auth/k8s-prod/: no group grants it to this caller`.** The token was admitted, but no group's rule matched its facts. TokenReview reports the identity as `system:serviceaccount:<namespace>:<name>`; Warden splits it into `service_account_namespace` and `service_account_name`, and a rule pinning namespace `default` correctly refuses a workload in `kube-system`. Check the rule's `mount` too: it is the path in the mount's namespace, with the trailing slash (`auth/k8s-prod/`). The audit entry's `role_denied_reason` and `groups` say which groups matched.

**The token is refused once `bound_audiences` is set.** The pod presents its default token, minted for the Kubernetes API. Mount a projected token with `audience` set to one of the bound audiences (see [Audience Binding](#audience-binding)) and send that one.

**TokenReview calls are spamming the kube-apiserver audit log.** Pin `issuer` on the mount. Once set, tokens whose `iss` claim doesn't match are refused before any TokenReview round-trip; with several spokes, this keeps discovery from reviewing every token at every cluster.

**"Forbidden: cannot create resource tokenreviews".** The bearer used to authorize the TokenReview call doesn't have `system:auth-delegator`. In reviewer mode, this points at the reviewer ServiceAccount; in self-reviewing mode, it points at the workload's SA. Grant the binding (see Step 1) or switch modes.

**"Unauthorized" from the kube-apiserver.** The bearer token expired or was malformed. For reviewer mode, mint a new reviewer JWT and write it as `token_reviewer_jwt` on the mount config. For self-reviewing mode, the workload's projected token rotates automatically (the kubelet refreshes it around 80% of its lifetime); if you still see this, the kubelet may not be mounting a projected token — check the pod spec.

**Cached admissions expire sooner than expected.** An admission lasts until the token's `exp` or the mount's `token_ttl`, whichever is first. A pod near the end of its projected-token cycle gets a short-lived entry. The kubelet refreshes the projected token before expiry, so the next request with the new JWT is reviewed again and cached for the full TTL.

## See Also

- [Authentication](/identity/authentication/) — how auth mounts admit credentials, and the facts they record.
- [Groups](/identity/groups/) and [Roles](/identity/roles/) — how an admitted workload is granted what it may do.
- [Entities](/identity/entities/) — registering a workload in the identity store.
- [Agent Identity](/agent-identity/) — how a workload or its sidecar presents this credential to Warden.
- [Auth Methods](/auth-methods/) — the other auth methods Warden ships.
