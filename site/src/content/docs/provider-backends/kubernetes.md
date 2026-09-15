---
title: "Kubernetes"
---

The Kubernetes provider enables proxied access to Kubernetes API servers through Warden. It forwards requests to the Kubernetes API (Pods, Deployments, Services, Namespaces, etc.) with automatic credential injection and policy evaluation. Credentials are injected via the `Authorization: Bearer` header using short-lived ServiceAccount tokens created via the Kubernetes TokenRequest API (`kubernetes` source type). Two credential modes are supported: keyless federation (`auth_method=oidc_federation`) and a stored source token (`auth_method=static`).

## How a request flows

Every request to this mount is served by a **freshly minted ServiceAccount token**, created
through the [TokenRequest API](https://kubernetes.io/docs/reference/kubernetes-api/authentication-resources/token-request-v1/)
and injected into the `Authorization` header as a bearer token. Both modes mint the same
way — `POST /api/v1/namespaces/{namespace}/serviceaccounts/{name}/token`. What differs is
**what authenticates that call**.

The recommended setup authenticates it with the caller's own identity, so Warden stores no
cluster credential at all.

<p align="center"><img alt="An agent presents the user's ID token and its own identity to Warden, which builds an assertion carrying user and agent claims, has an external KMS sign it, presents that assertion to the Kubernetes token endpoint to mint a ServiceAccount token, and injects the token to the Kubernetes API" src="/images/warden-prov-kubernetes-fed.png" width="860"></p>

1. The user authenticates and the agent holds their ID token.
2. The agent calls Warden presenting both credentials and asserting a role.
3. Warden builds the assertion the referenced spec calls for and sends it to a KMS-backed
   issuer unsigned, where one is configured.
4. The issuer returns it signed.
5. Warden calls the **TokenRequest endpoint** for the spec's target ServiceAccount,
   presenting the assertion as the bearer token.
6. The API server — configured to trust Warden's issuer — maps the assertion's claims to a
   user and groups, checks RBAC, and returns a ServiceAccount token.
7. Warden injects that token and forwards.

Unlike the STS-backed cloud providers there is **no token-exchange hop**: the assertion is
not traded for a cluster credential first, it *is* the credential for step 5. Nothing about
the cluster is stored in Warden, and the API server's audit log attributes the TokenRequest
to the identity behind the request rather than to one shared service account.

:::note[Steps 3–6 run only on a cache miss]
Warden caches the credential, so most requests skip from step 2 to step 7. The entry is
keyed by namespace, the agent's token id and the spec name — plus the user's token id when
the mount carries a user.
:::

### The simpler variant

<p align="center"><img alt="Warden reads a stored ServiceAccount token from its encrypted storage, presents it to the Kubernetes token endpoint to mint a ServiceAccount token for the target account, and injects that token to the Kubernetes API" src="/images/warden-prov-kubernetes-static-sts.png" width="860"></p>

**Static.** Warden holds a long-lived ServiceAccount token with permission to create tokens
for others, and presents *that* at step 5 instead of an assertion. Steps 6 and 7 are
identical. Simplest to stand up against a cluster whose authenticator you do not control —
but the credential lives in Warden, and every TokenRequest is audited as the same source
account no matter who asked.

## Credential modes

| Mode | What the API server authenticates | Where the credential lives |
|---|---|---|
| **Keyless federation** ✅ *recommended* | The caller's identity, per request | Nothing stored |
| **Static** ⚠️ | One shared source ServiceAccount | Warden's storage |

Both rows end with a short-lived, audience-scoped token for the *target* ServiceAccount —
that part is the TokenRequest API's doing, not the mode's. What the mode decides is whether
Warden holds a cluster credential, and whose identity the cluster sees asking.

:::note[Federation needs the cluster to trust Warden's issuer]
The API server must be started with `--api-audiences` including the audience the source
declares, and an authenticator configured for Warden's OIDC issuer. Where you cannot
reconfigure the control plane — most managed clusters without extra setup — use the static
mode.
:::

See the [Kubernetes credential driver](/credential-drivers/kubernetes/) for every source and
spec key.

## Prerequisites

- Docker and Docker Compose installed and running
- A **Kubernetes cluster** with a reachable HTTPS API server endpoint
- Permission to create tokens for the target ServiceAccounts (see [RBAC Requirements](#rbac-requirements)) — granted to the caller's federated identity under Option A, or to a source ServiceAccount under Option B
- For **Option A**, an API server whose authenticator trusts Warden's OIDC issuer
- For **Option B**, a **bearer token** for the source ServiceAccount

:::note[New to Warden?]
Follow [Local dev setup](/provider-backends/local-dev-setup/) to start a local dev environment (Ory Hydra + a Warden dev server) before Step 1.
:::

## Step 1: Configure JWT Auth and Create a Role

Enable the JWT auth method and point it at your identity provider's JWKS endpoint, then create a role that binds the credential spec and policy. Enabling the mount and configuring the key source is covered once in [JWT auth](/auth-methods/jwt/#step-1-configure-the-key-source) — for the local dev setup:

```bash
warden auth enable jwt -path=auth/jwt/
warden write auth/jwt/config \
  jwks_url="http://localhost:4444/.well-known/jwks.json" \
  default_role="k8s-user"

# Create a role
warden write auth/jwt/role/k8s-user \
  user_claim="sub" \
  token_policies="k8s-readonly" \
  token_ttl="1h"
```

## Step 2: Mount and Configure the Provider

```bash
# Enable the Kubernetes provider
warden provider enable kubernetes

# Configure the provider with your cluster's API server URL
warden write kubernetes/config \
  kubernetes_url="https://my-cluster.example.com:6443" \
  auto_auth_path="auth/jwt/"
```

See [Provider configuration](/provider-backends/configuration/) for the full list of common config fields (`proxy_domains`, `timeout`, `tls_skip_verify`, `ca_data`, and more).

For clusters with custom CA certificates:

```bash
# Get the CA certificate and base64-encode it
CA_DATA=$(cat /path/to/ca.crt | base64 -w0)

warden write kubernetes/config \
  kubernetes_url="https://my-cluster.example.com:6443" \
  ca_data="$CA_DATA" \
  auto_auth_path="auth/jwt/"
```

For development clusters with self-signed certificates:

```bash
warden write kubernetes/config \
  kubernetes_url="https://localhost:6443" \
  tls_skip_verify=true \
  auto_auth_path="auth/jwt/"
```

## Step 3: Create a Credential Source and Spec

### Option A: Keyless federation (recommended)

The flow in the first diagram. The source holds nothing; the caller's assertion authenticates
the TokenRequest call.

```bash
warden cred source create k8s-source -json '{
  "type": "kubernetes",
  "config": {
    "kubernetes_url": "https://my-cluster.example.com:6443",
    "auth_method": "oidc_federation",
    "audience": "https://kubernetes.example.com",
    "ca_data": "'"$CA_DATA"'"
  }
}'
```

`audience` must appear in the API server's `--api-audiences` list. A federation source has
no token of its own, so it has nothing to rotate — `token`, `source_service_account`,
`source_namespace` and `source_token_ttl` are all **rejected on write**, and no
`rotation-period` is needed.

```bash
warden cred spec create k8s-app-reader -json '{
  "source": "k8s-source",
  "config": {
    "subject_token_source": "warden_identity",
    "service_account": "app-reader",
    "namespace": "default",
    "ttl": "1h"
  }
}'
```

`subject_token_source` is what opts the spec into federation. Omit it against a keyless
source and **spec creation fails**, not the first request — Warden test-mints the credential
on write and reports `a source with auth_method=oidc_federation mints only from a caller
assertion`. The assertion's audience is inherited from the source's `audience` here; if the
source leaves it unset, the spec must carry `assertion_audience` instead, which spec creation
also enforces.

To project the caller's claims into the assertion, so the cluster can map them to a user
and groups:

```bash
warden cred spec create k8s-team-reader -json '{
  "source": "k8s-source",
  "config": {
    "subject_token_source": "warden_identity",
    "assertion_user_claims": "team",
    "assertion_metadata_claims": "env",
    "service_account": "app-reader",
    "namespace": "default",
    "ttl": "1h"
  }
}'
```

Nothing is projected unless it is listed: `{{user.*}}` claims need `assertion_user_claims`,
and agent claims other than `sub` need `assertion_metadata_claims`. Disclosure to the
cluster is opt-in and operator-chosen, never the whole metadata map.

:::note[The minted token outlives the assertion, by design]
The ServiceAccount token's lifetime is fixed by the API server when it is issued and does
not depend on the short-lived assertion that asked for it. That is expected: the assertion
authenticates one TokenRequest call, it does not bound the result.
:::

### Option B: Static source token

The second diagram. Use this when you cannot configure the cluster's authenticator to trust
Warden's issuer.

Create a credential source using a ServiceAccount token that has permission to create tokens:

```bash
# Create a short-lived token for bootstrapping (the driver will rotate it automatically)
SOURCE_TOKEN=$(kubectl create token warden-token-creator -n warden --duration=24h)

# Create the credential source with automatic token rotation
warden cred source create k8s-source \
  -type=kubernetes \
  -rotation-period=12h \
  -config=kubernetes_url=https://my-cluster.example.com:6443 \
  -config=token=$SOURCE_TOKEN \
  -config=ca_data=$CA_DATA \
  -config=source_service_account=warden-token-creator \
  -config=source_namespace=warden \
  -config=source_token_ttl=24h
```

For development clusters with self-signed certificates:

```bash
warden cred source create k8s-source-dev \
  -type=kubernetes \
  -rotation-period=12h \
  -config=kubernetes_url=https://localhost:6443 \
  -config=token=$SOURCE_TOKEN \
  -config=tls_skip_verify=true \
  -config=source_service_account=warden-token-creator \
  -config=source_namespace=warden \
  -config=source_token_ttl=24h
```

> **How rotation works:** `source_service_account` and `source_namespace` tell the driver
> which ServiceAccount the source token belongs to. Before the token expires, the driver
> mints a new token for itself via the TokenRequest API. Set `rotation-period` shorter than
> `source_token_ttl` to ensure rotation happens before expiry (e.g., rotate every 12h with
> a 24h token TTL).

<details>
<summary>Alternative: non-expiring Secret-based token (no rotation)</summary>

If you prefer not to use rotation, create a non-expiring Secret-based token instead:

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: warden-token-creator-token
  namespace: warden
  annotations:
    kubernetes.io/service-account.name: warden-token-creator
type: kubernetes.io/service-account-token
EOF

kubectl wait --for=jsonpath='{.data.token}' secret/warden-token-creator-token -n warden --timeout=30s
SOURCE_TOKEN=$(kubectl get secret warden-token-creator-token -n warden -o jsonpath='{.data.token}' | base64 -d)

warden cred source create k8s-source \
  -type=kubernetes \
  -rotation-period=0 \
  -config=kubernetes_url=https://my-cluster.example.com:6443 \
  -config=token=$SOURCE_TOKEN \
  -config=ca_data=$CA_DATA
```

</details>

Create credential specs targeting different ServiceAccounts. The access level of the
minted token is determined by the RBAC bindings on the target ServiceAccount — create
separate ServiceAccounts with different Roles for different access levels:

```yaml
# In Kubernetes: create ServiceAccounts with different permission levels
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: app-reader
  namespace: default
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-reader
  namespace: default
rules:
  - apiGroups: [""]
    resources: ["pods", "services"]
    verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: app-reader-binding
  namespace: default
subjects:
  - kind: ServiceAccount
    name: app-reader
    namespace: default
roleRef:
  kind: Role
  name: pod-reader
  apiGroup: rbac.authorization.k8s.io
```

```bash
# Read-only spec — tokens inherit the "pod-reader" Role
warden cred spec create k8s-app-reader \
  -source k8s-source \
  -config service_account=app-reader \
  -config namespace=default \
  -config ttl=1h
```

```bash
# Different spec for a different access level (e.g., an admin SA with broader permissions)
warden cred spec create k8s-app-admin \
  -source k8s-source \
  -config service_account=app-admin \
  -config namespace=default \
  -config ttl=30m
```

With custom audiences:

```bash
warden cred spec create k8s-api-consumer \
  -source k8s-source \
  -config service_account=api-consumer \
  -config namespace=production \
  -config audiences=https://my-app.example.com,https://api.example.com \
  -config ttl=30m
```

## Step 4: Create a Policy

Create a policy that grants access to specific Kubernetes API paths:

```bash
# Read-only access to pods and deployments in the default namespace
warden policy write k8s-readonly - <<EOF
path "kubernetes/gateway/api/v1/namespaces/default/pods*" {
  capabilities = ["read"]
}
path "kubernetes/gateway/apis/apps/v1/namespaces/default/deployments*" {
  capabilities = ["read"]
}
path "kubernetes/gateway/api/v1/namespaces" {
  capabilities = ["read"]
}
EOF
```

## Step 5: Get a JWT and Make Requests

Get a JWT from your identity provider — see [Obtaining a JWT](/auth-methods/jwt/#obtaining-a-jwt) (the local dev setup issues one from Hydra). Export it as `$JWT_TOKEN`.

Requests use role-based paths. Warden performs implicit JWT authentication and injects the Kubernetes ServiceAccount token automatically.

The URL pattern is: `/v1/kubernetes/role/{role}/gateway/{api-path}`

```bash
export K8S_ENDPOINT="${WARDEN_ADDR}/v1/kubernetes/role/k8s-user/gateway"
```

### List Pods

```bash
curl -s "${K8S_ENDPOINT}/api/v1/namespaces/default/pods" \
  -H "Authorization: Bearer $JWT_TOKEN" | jq .
```

### Get a Deployment

```bash
curl -s "${K8S_ENDPOINT}/apis/apps/v1/namespaces/default/deployments/my-app" \
  -H "Authorization: Bearer $JWT_TOKEN" | jq .
```

### List Namespaces

```bash
curl -s "${K8S_ENDPOINT}/api/v1/namespaces" \
  -H "Authorization: Bearer $JWT_TOKEN" | jq .
```

### Health Check

```bash
curl -s "${K8S_ENDPOINT}/healthz" \
  -H "Authorization: Bearer $JWT_TOKEN"
```

## RBAC Requirements

Whoever authenticates the TokenRequest call needs permission to create tokens for the target
ServiceAccounts. **Which subject that is depends on the mode**, and it is the one place the
two modes diverge operationally:

| Mode | Subject needing `serviceaccounts/token` `create` |
|---|---|
| Keyless federation | The user and groups the API server maps the caller's assertion to |
| Static | The source ServiceAccount (`warden-token-creator` below) |

Under federation there is no `warden-token-creator`: bind the ClusterRole below to the
subjects your authenticator produces instead — which is what lets the cluster grant
different callers different reach, and audit each one separately.

The ClusterRole itself is the same either way:

```yaml
# ClusterRole for token creation
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: warden-token-creator
rules:
  - apiGroups: [""]
    resources: ["serviceaccounts/token"]
    verbs: ["create"]
  - apiGroups: [""]
    resources: ["serviceaccounts"]
    verbs: ["get"]

---
# ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: warden-token-creator-binding
subjects:
  - kind: ServiceAccount
    name: warden-token-creator
    namespace: warden
roleRef:
  kind: ClusterRole
  name: warden-token-creator
  apiGroup: rbac.authorization.k8s.io
```

To restrict token creation to specific namespaces, use a `Role` and `RoleBinding` instead of `ClusterRole` and `ClusterRoleBinding`.

Under federation, replace the `subjects` block with the identity your authenticator maps the
assertion to — a `User` named by the assertion's subject claim, or a `Group` drawn from a
projected claim:

```yaml
subjects:
  - kind: Group
    name: platform-eng
    apiGroup: rbac.authorization.k8s.io
```

A group only exists to bind against if the spec projects the claim it comes from, via
`assertion_user_claims` or `assertion_metadata_claims`.

## Token Management

### Short-Lived Tokens

The Kubernetes provider creates short-lived ServiceAccount tokens via the [TokenRequest API](https://kubernetes.io/docs/reference/kubernetes-api/authentication-resources/token-request-v1/). Tokens are:

- **Time-bounded**: Configurable TTL from 10 minutes to 48 hours (default: 1 hour)
- **Audience-scoped**: Can be restricted to specific audiences for multi-tenant security
- **Non-revocable**: Tokens expire naturally and cannot be revoked through the API
- **Not persisted**: Tokens are not stored as Kubernetes Secrets; they exist only in memory

### Token Lifecycle

1. Client sends a request to a role-based gateway path with a JWT in the `Authorization: Bearer` header
2. Warden implicitly authenticates the JWT against the configured auth backend
3. Warden resolves the role to a credential spec and mints a ServiceAccount token via the TokenRequest API, authenticating that call with the caller's assertion (federation) or the stored source token (static)
4. Warden replaces the `Authorization` header with the minted Kubernetes token
5. Request is proxied to the Kubernetes API server
6. Token expires automatically after the configured TTL

### Source Token Rotation

Rotation applies to **`auth_method=static` only**. A federation source stores no token, so
there is nothing to rotate and the fields below are rejected on write.

When `source_service_account` and `source_namespace` are configured, the driver automatically rotates its own source token via the TokenRequest API:

1. **PrepareRotation**: Mints a new token for the source SA using the current (still valid) token
2. **CommitRotation**: Switches to the new token after verifying it works
3. **CleanupRotation**: No-op — old tokens expire naturally

Kubernetes has immediate consistency, so there is no activation delay.

Set `rotation-period` on the source to a value shorter than `source_token_ttl` to ensure rotation happens before the current token expires. For example, with `source_token_ttl=24h`, a `rotation-period=12h` provides comfortable overlap.

If rotation is not configured (no `source_service_account`/`source_namespace`), use a non-expiring Secret-based token as described in Step 3, or rotate manually:

```bash
SOURCE_TOKEN=$(kubectl create token warden-token-creator -n warden --duration=24h)
warden cred source create k8s-source \
  -type=kubernetes \
  -rotation-period=0 \
  -config=kubernetes_url=https://my-cluster.example.com:6443 \
  -config=token=$SOURCE_TOKEN
```

## Troubleshooting

### Authentication Failures

**Symptom:** `authentication failed (HTTP 401)` or `authentication failed (HTTP 403)` when creating the credential source.

With `auth_method=static`:

- Verify the source token is still valid: `kubectl auth can-i create serviceaccounts/token --as=system:serviceaccount:warden:warden-token-creator -A`
- If using a time-bound token, check it hasn't expired: `kubectl create token warden-token-creator -n warden --duration=24h` to generate a fresh one
- The driver verifies connectivity via the `/version` endpoint — ensure the token has at least basic API access

With `auth_method=oidc_federation`, a 401 at mint time points at the cluster rejecting the
assertion rather than at a stale credential:

- The audience the source declares must appear in the API server's `--api-audiences`
- The API server's authenticator must trust Warden's OIDC issuer and be able to fetch its
  JWKS
- A 403 rather than a 401 means the assertion authenticated but the identity it mapped to
  lacks `create` on `serviceaccounts/token` — check the binding, not the issuer

**Symptom:** `credential test failed ... mints only from a caller assertion: set
subject_token_source on the spec`, when creating a spec.

This is a Warden-side error, not a cluster one, and it surfaces on `cred spec create`
rather than on the first request: the source is keyless but the spec never opted into
federation. Add `subject_token_source: warden_identity`.

### RBAC Permission Errors

**Symptom:** `insufficient permissions to create token for service account "X" in namespace "Y"` when minting credentials.

- The source SA needs `create` on `serviceaccounts/token` and `get` on `serviceaccounts` (see [RBAC Requirements](#rbac-requirements))
- If using namespace-scoped Roles instead of ClusterRoles, ensure bindings exist in every namespace where target SAs reside

### Token TTL Rejected

**Symptom:** `invalid token request parameters` (HTTP 422) when minting credentials.

- The Kubernetes API server enforces TTL bounds. The default range is 10m–48h, but cluster admins can configure different limits via `--service-account-max-token-expiration`
- Ensure the `ttl` in your credential spec falls within your cluster's allowed range

### TLS Certificate Issues

**Symptom:** `API server unreachable` with TLS-related errors.

- Verify `ca_data` is properly base64-encoded: `echo "$CA_DATA" | base64 -d | openssl x509 -noout -text`
- For self-signed dev clusters, set `tls_skip_verify=true` on both the provider config and the credential source config
- Ensure `kubernetes_url` uses the `https://` scheme (required unless `tls_skip_verify=true` on the source)

### Clock Skew

**Symptom:** Minted tokens appear to expire immediately, or log warnings about expiration timestamps in the past.

- The driver compares the token's `expirationTimestamp` from the API server against the local clock. If clocks are out of sync, computed TTLs may be incorrect
- Ensure NTP is configured on both the Warden host and the Kubernetes API server nodes
- The driver falls back to the requested TTL when clock skew is detected, but the actual token validity depends on the API server's clock

### Rate Limiting

**Symptom:** `rate limited by Kubernetes API server` after retries.

- The driver retries on HTTP 429 with exponential backoff (up to 3 attempts)
- If rate limiting persists, reduce the frequency of credential minting by increasing spec TTLs or adjusting client request patterns
- Check API server audit logs or metrics for throttling configuration

## Custom CA Certificate

If your Kubernetes cluster uses a certificate signed by a private CA (common with self-managed clusters):

```bash
# Base64-encode the cluster CA certificate
CA_DATA=$(base64 < /path/to/cluster-ca.pem)

warden write kubernetes/config <<EOF
{
  "kubernetes_url": "https://k8s-api.internal.corp:6443",
  "ca_data": "${CA_DATA}",
  "auto_auth_path": "auth/jwt/"
}
EOF
```

## Development / Testing (no TLS)

For local development against a Kubernetes API server without TLS (e.g., kind, minikube):

```bash
warden write kubernetes/config <<EOF
{
  "kubernetes_url": "http://localhost:8080",
  "tls_skip_verify": true,
  "auto_auth_path": "auth/jwt/"
}
EOF
```
