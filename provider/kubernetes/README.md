# Kubernetes Provider

The Kubernetes provider enables proxied access to Kubernetes API servers through Warden. It forwards requests to the Kubernetes API (Pods, Deployments, Services, Namespaces, etc.) with automatic credential injection and policy evaluation. Credentials are injected via the `Authorization: Bearer` header using short-lived ServiceAccount tokens created via the Kubernetes TokenRequest API (`kubernetes` source type).

## Table of Contents

- [Prerequisites](#prerequisites)
- [Step 1: Configure JWT Auth and Create a Role](#step-1-configure-jwt-auth-and-create-a-role)
- [Step 2: Mount and Configure the Provider](#step-2-mount-and-configure-the-provider)
- [Step 3: Create a Credential Source and Spec](#step-3-create-a-credential-source-and-spec)
- [Step 4: Create a Policy](#step-4-create-a-policy)
- [Step 5: Get a JWT and Make Requests](#step-5-get-a-jwt-and-make-requests)
- [RBAC Requirements](#rbac-requirements)
- [Configuration Reference](#configuration-reference)
- [Token Management](#token-management)
- [Troubleshooting](#troubleshooting)

## Prerequisites

- Docker and Docker Compose installed and running
- A **Kubernetes cluster** with a reachable HTTPS API server endpoint
- A **ServiceAccount** with permissions to create tokens for other service accounts (see [RBAC Requirements](#rbac-requirements))
- A **bearer token** for the source ServiceAccount

> **New to Warden?** Follow these steps to get a local dev environment running:
>
> **1. Deploy the quickstart stack** -- this starts an identity provider ([Ory Hydra](https://www.ory.sh/hydra/)) needed to issue JWTs for authentication in Steps 1 and 5:
> ```bash
> curl -fsSL -o docker-compose.quickstart.yml \
>   https://raw.githubusercontent.com/stephnangue/warden/main/deploy/docker-compose.quickstart.yml
> docker compose -f docker-compose.quickstart.yml up -d
> ```
>
> **2. Start Warden in dev mode:**
> ```bash
> warden server -dev -dev-root-token-id=root
> ```

## Step 1: Configure JWT Auth and Create a Role

Enable JWT auth and create a role bound to a Warden policy:

```bash
# Enable JWT auth (if not already enabled)
warden auth enable -type=jwt -path=auth/jwt/

# Configure JWT auth with your OIDC provider
warden write auth/jwt/config \
  oidc_discovery_url="http://localhost:4444/.well-known/openid-configuration" \
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
warden provider enable -type=kubernetes

# Configure the provider with your cluster's API server URL
warden write kubernetes/config \
  kubernetes_url="https://my-cluster.example.com:6443" \
  auto_auth_path="auth/jwt/"
```

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

### Kubernetes Source (TokenRequest API)

Create a credential source using a ServiceAccount token that has permission to create tokens:

```bash
# Create a short-lived token for bootstrapping (the driver will rotate it automatically)
SOURCE_TOKEN=$(kubectl create token warden-token-creator -n warden --duration=24h)

# Create the credential source with automatic token rotation
warden cred source create k8s-source \
  --type=kubernetes \
  --rotation-period=12h \
  --config=kubernetes_url=https://my-cluster.example.com:6443 \
  --config=token=$SOURCE_TOKEN \
  --config=ca_data=$CA_DATA \
  --config=source_service_account=warden-token-creator \
  --config=source_namespace=warden \
  --config=source_token_ttl=24h
```

For development clusters with self-signed certificates:

```bash
warden cred source create k8s-source-dev \
  --type=kubernetes \
  --rotation-period=12h \
  --config=kubernetes_url=https://localhost:6443 \
  --config=token=$SOURCE_TOKEN \
  --config=tls_skip_verify=true \
  --config=source_service_account=warden-token-creator \
  --config=source_namespace=warden \
  --config=source_token_ttl=24h
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
  --type=kubernetes \
  --rotation-period=0 \
  --config=kubernetes_url=https://my-cluster.example.com:6443 \
  --config=token=$SOURCE_TOKEN \
  --config=ca_data=$CA_DATA
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
  --source k8s-source \
  --config service_account=app-reader \
  --config namespace=default \
  --config ttl=1h
```

```bash
# Different spec for a different access level (e.g., an admin SA with broader permissions)
warden cred spec create k8s-app-admin \
  --source k8s-source \
  --config service_account=app-admin \
  --config namespace=default \
  --config ttl=30m
```

With custom audiences:

```bash
warden cred spec create k8s-api-consumer \
  --source k8s-source \
  --config service_account=api-consumer \
  --config namespace=production \
  --config audiences=https://my-app.example.com,https://api.example.com \
  --config ttl=30m
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

Get a JWT from Hydra using one of the quickstart clients:

```bash
export JWT_TOKEN=$(curl -s -X POST http://localhost:4444/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=my-agent&client_secret=agent-secret&scope=api:read" \
  | jq -r '.access_token')
```

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

The source ServiceAccount used by the credential driver needs permissions to create tokens for other service accounts. Create the following RBAC resources:

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

## Configuration Reference

### Provider Configuration

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `kubernetes_url` | string | Yes | Kubernetes API server URL (e.g., `https://my-cluster.example.com:6443`) |
| `max_body_size` | int | No | Maximum request body size in bytes (default: 10MB, max: 100MB) |
| `timeout` | string | No | Request timeout duration (default: `30s`) |
| `auto_auth_path` | string | Yes | Auth mount path for implicit authentication (e.g., `auth/jwt/`) |
| `default_role` | string | No | Default role when not specified in URL path |
| `tls_skip_verify` | bool | No | Skip TLS certificate verification; also allows `http://` URLs (default: `false`) |
| `ca_data` | string | No | Base64-encoded PEM CA certificate for custom CAs |

### Credential Source Configuration

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `kubernetes_url` | string | Yes | Kubernetes API server URL |
| `token` | string | Yes | Bearer token for authenticating to the API server |
| `ca_data` | string | No | Base64-encoded PEM CA certificate |
| `tls_skip_verify` | string | No | Skip TLS verification; also allows `http://` URLs (`true`/`false`, default: `false`) |
| `source_service_account` | string | No | Name of the source SA (required for rotation) |
| `source_namespace` | string | No | Namespace of the source SA (required for rotation) |
| `source_token_ttl` | string | No | TTL for rotated source tokens (default: `24h`, min: `10m`, max: `48h`) |

### Credential Spec Configuration

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `service_account` | string | Yes | Target service account name |
| `namespace` | string | Yes | Namespace of the target service account |
| `audiences` | string | No | Comma-separated list of token audiences |
| `ttl` | string | No | Token TTL (e.g., `1h`, `30m`). Default: `1h`. Min: `10m`, Max: `48h` |

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
3. Warden resolves the role to a credential spec and mints a ServiceAccount token via the TokenRequest API
4. Warden replaces the `Authorization` header with the minted Kubernetes token
5. Request is proxied to the Kubernetes API server
6. Token expires automatically after the configured TTL

### Source Token Rotation

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
  --type=kubernetes \
  --rotation-period=0 \
  --config=kubernetes_url=https://my-cluster.example.com:6443 \
  --config=token=$SOURCE_TOKEN
```

## Troubleshooting

### Authentication Failures

**Symptom:** `authentication failed (HTTP 401)` or `authentication failed (HTTP 403)` when creating the credential source.

- Verify the source token is still valid: `kubectl auth can-i create serviceaccounts/token --as=system:serviceaccount:warden:warden-token-creator -A`
- If using a time-bound token, check it hasn't expired: `kubectl create token warden-token-creator -n warden --duration=24h` to generate a fresh one
- The driver verifies connectivity via the `/version` endpoint — ensure the token has at least basic API access

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
