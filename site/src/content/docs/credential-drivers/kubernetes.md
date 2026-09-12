---
title: "Kubernetes"
---

> Source `type`: `kubernetes`

:::tip[Prefer keyless]
This driver supports a **keyless mode** — use it instead of storing a secret inline. A stored secret is attack surface; keyless holds nothing. See [Keyless (OIDC federation)](#keyless-oidc-federation).
:::

The Kubernetes driver mints short-lived **ServiceAccount tokens** through the cluster's **TokenRequest API**. Each token is an audience-scoped bearer credential that a workload presents to the Kubernetes API server (or to any service that trusts the cluster's token issuer) as a specific service account.

The privileged secret — a bearer **token** with permission to create tokens for the target service accounts — lives in the **source** config alongside the API server URL and TLS settings. Each **spec** names the service account and namespace to mint for, plus optional audiences and TTL. An operator reaches for this driver to hand workloads narrowly-scoped, expiring identities without distributing long-lived service-account secrets.

## Keyless (OIDC federation)

Set `auth_method = "oidc_federation"` on the source to hold **no cluster credential**:
Warden mints an [identity assertion](/federation/oidc-issuer/) and presents it
**directly as the bearer token** to the API server. There is no exchange hop — the
cluster verifies Warden's issuer itself, so no intermediate token service is involved.

The assertion's `audience` must match one of the audiences the cluster's authenticator
accepts, or the API server rejects it. The spec sets `subject_token_source`
(`warden_identity` or `agent_identity`). See
[Keyless credential sources](/federation/keyless-credentials/).

## Credential issued

The credential `type` is `kubernetes_token`. It is **dynamic** — the token carries a TTL derived from the API server's returned expiration timestamp — but it is **not revocable**: ServiceAccount tokens expire naturally and cannot be invalidated through the API. See [the lifetime model](/concepts/credentials/#lifetime-and-revocation).

## Capabilities

- **Spec verification** — validates that the target service account exists in its namespace with a light API call at create/update time.
- **Source rotation** — available only when `source_service_account` and `source_namespace` are set. **Fast** — prepares and activates in one step (immediately-consistent upstream): the driver mints a fresh token for its own service account and swaps it in. Old tokens are left to expire naturally.

## Examples

### Keyless (recommended)

The source stores no cluster token; Warden presents an identity assertion directly to
the API server, so the `audience` must match one the cluster authenticator accepts.

```bash
warden cred source create k8s-keyless \
  -type=kubernetes \
  -config=auth_method=oidc_federation \
  -config=kubernetes_url=https://my-cluster.example.com:6443 \
  -config=audience=https://kubernetes.default.svc

warden cred spec create app-token \
  -source=k8s-keyless \
  -config=service_account=my-app \
  -config=namespace=default \
  -config=subject_token_source=warden_identity
```

### Inline secret (discouraged)

One source holds the token-creating bearer token; each spec mints for a specific service account.

```bash
warden cred source create prod-k8s \
  -type=kubernetes \
  -config=kubernetes_url=https://my-cluster.example.com:6443 \
  -config=token=eyJhbGciOiJSUzI1NiIs... \
  -config=ca_data=LS0tLS1CRUdJTi... \
  -config=source_service_account=warden-token-creator \
  -config=source_namespace=warden \
  -rotation-period=24h
```

**API-server audience** — a token the workload presents to the Kubernetes API as `my-app`:

```bash
warden cred spec create app-token \
  -source=prod-k8s \
  -config=service_account=my-app \
  -config=namespace=default \
  -config=audiences=https://kubernetes.default.svc \
  -config=ttl=1h
```

**Custom audience and longer TTL** — a token scoped for a service that trusts the cluster's issuer:

```bash
warden cred spec create vault-auth-token \
  -source=prod-k8s \
  -config=service_account=vault-auth \
  -config=namespace=platform \
  -config=audiences=https://vault.example.com \
  -config=ttl=4h
```

## Source config

Keys for `warden cred source create <name> -type=kubernetes -config=key=value ...`:

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `kubernetes_url` | Yes | — | Kubernetes API server URL. Must use `https` unless `tls_skip_verify` is set. |
| `token` | Yes* | — | Bearer token for authenticating to the API server (secret, masked on read). |
| `ca_data` | No | — | Base64-encoded PEM CA certificate for the cluster (secret, masked on read). |
| `tls_skip_verify` | No | `false` | Skip TLS certificate verification (dev/test clusters only). |
| `source_service_account` | No | — | Name of the source service account. Required for rotation. |
| `source_namespace` | No | — | Namespace of the source service account. Required for rotation. |
| `source_token_ttl` | No | `24h` | TTL for rotated source tokens. Min `10m`, max `48h`. |

\* Required only when the source is **not** keyless. A source that sets
`secret_spec` (chaining) or `auth_method=oidc_federation` must **omit** it — setting
both is rejected at write. See [Keyless](#keyless-oidc-federation).

## Specs and mint methods

The driver has a single mint path: it calls the TokenRequest API for the named service account. Keys operators set with `warden cred spec create ... -config=key=value`:

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `service_account` | Yes | — | Target service account name. |
| `namespace` | Yes | — | Namespace of the target service account. |
| `audiences` | No | — | Comma-separated token audiences. |
| `ttl` | No | `1h` | Requested token TTL, e.g. `1h`. The cluster may clamp this. |

## See Also

- [Credentials](/concepts/credentials/) — the source, spec, and credential model.
- [Kubernetes provider](/provider-backends/kubernetes/) — full operator setup guide.
- [Credential drivers](/credential-drivers/) — every driver.
