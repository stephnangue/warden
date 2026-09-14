---
title: "GCP"
---

The GCP provider enables proxied access to Google Cloud Platform APIs through Warden. It authenticates using service account keys, supports OAuth2 token minting and service account impersonation, and handles automated key rotation.

## How a request flows

This mount can carry **two principals** — the agent, and the user it is acting for — and
both can be described to Google in the same assertion.

The recommended setup stores **no GCP credentials at all**.

<p align="center"><img alt="An agent presents the user's ID token and its own identity to Warden, which builds an assertion carrying user claims and agent claims, has an external KMS sign it, exchanges it at GCP STS through Workload Identity Federation, and injects the returned access token as a bearer token to the GCP service API" src="/images/warden-prov-gcp-oidc-fed.png" width="860"></p>

1. The user authenticates and the agent holds their ID token.
2. The agent calls Warden presenting **both** credentials and asserting a role. Warden
   authenticates each against its own auth mount.
3. The asserted role selects the credential spec. Warden builds the assertion that spec
   calls for — agent claims, plus the user's under a nested `warden_user` claim when the
   spec opts in — and sends it to an **external KMS** unsigned.
4. The KMS returns it signed. No signing key lives in Warden.
5. Warden exchanges it at **GCP STS** through Workload Identity Federation.
6. STS verifies it against the trusted provider and returns an access token, optionally
   impersonating a service account.
7. Warden injects that token as `Authorization: Bearer <token>` and forwards.

Because the user's claims reach Google inside the assertion, a WIF attribute condition or
an IAM binding can be written against them.

:::note[Steps 3–6 run only on a cache miss]
Warden caches the minted credential, so most requests skip from step 2 to step 7. The
entry is keyed by namespace, the agent's token id, the spec name **and the user's token
id**, so one user's access token is never served to another, and it lives for the shorter
of the token's own lifetime and the session.
:::

The KMS leg is optional, and **recommended in production**: with a
[`signer` stanza](/configuration/signer/) configured, Warden holds no key material at all.
Omit the stanza and the issuer signs with a locally held key instead. The exchange at STS
is identical either way.

### When you must store a service account key

Where you cannot configure Workload Identity Federation, Warden holds a service account
key in encrypted storage and rotates it.

<p align="center"><img alt="Warden resolves the asserted role to a credential spec, reads that spec's service account key from encrypted storage, exchanges it at GCP STS for an access token, and injects it as a bearer token to the GCP service API" src="/images/warden-prov-gcp-static-sts.png" width="860"></p>

Steps 3 and 4 become a storage read instead of a signing call, and step 5 signs a JWT with
the stored key rather than presenting a federated assertion. The user is still
authenticated at step 2 and policy can still require them, but **the user no longer reaches
Google** — there is no assertion to carry them.

A service account key is the credential Google most warns about holding: it is long-lived,
and possession is authority. Federating removes it entirely, which is why it is the
recommended path here rather than merely the tidier one.

## Credential modes

| Mode | Supported | How |
|---|---|---|
| **Keyless federation** ✅ *recommended* | Yes | `auth_method=oidc_federation` via Workload Identity Federation; the only mode that carries the user through to Google |
| **Stored root → short-lived mint** | Yes | `auth_method=static`; a service account key in Warden storage, rotated on a schedule |
| **Static inline** | No | Every mode mints a fresh token |
| **Chaining** | Not as a consumer | A `gcp` source takes no `secret_spec`. It is a chaining **producer** via `mint_method=secret_read` — see [the driver page](/credential-drivers/gcp/) |
| **Delegated user token** | No | The upstream receives a minted token, not a forwarded user token |

See the [GCP credential driver](/credential-drivers/gcp/) for every source and spec key.

## Prerequisites

- Docker and Docker Compose installed and running
- A GCP **service account key** (JSON format) with appropriate IAM permissions

:::note[New to Warden?]
Follow [Local dev setup](/provider-backends/local-dev-setup/) to start a local dev environment (Ory Hydra + a Warden dev server) before Step 1.
:::

### Creating a Service Account Key

1. Go to the [GCP Console](https://console.cloud.google.com/) > **IAM & Admin > Service Accounts**.
2. Select or create a service account.
3. Go to the **Keys** tab and click **Add Key > Create new key > JSON**.
4. Download the JSON key file.

For key rotation support, the service account also needs:
- `iam.serviceAccountKeys.create`
- `iam.serviceAccountKeys.delete`

For impersonation, the source service account needs `iam.serviceAccounts.getAccessToken` on the target service account.

## Step 1: Configure JWT Auth and Create a Role

Enable the JWT auth method and point it at your identity provider's JWKS endpoint, then create a role that binds the credential spec and policy. Enabling the mount and configuring the key source is covered once in [JWT auth](/auth-methods/jwt/#step-1-configure-the-key-source) — for the local dev setup.

> **This step must come before configuring the provider.** Warden validates at configuration time that the auth backend referenced by `auto_auth_path` is already mounted.

```bash
warden auth enable jwt
warden write auth/jwt/config jwks_url=http://localhost:4444/.well-known/jwks.json

# Create a role that binds the credential spec and policy
warden write auth/jwt/role/gcp-user \
    token_policies="gcp-access" \
    user_claim=sub \
    cred_spec_name=gcp-cloud-platform
```

## Step 2: Mount and Configure the Provider

Enable the GCP provider at a path of your choice:

```bash
warden provider enable gcp
```

To mount at a custom path:

```bash
warden provider enable -path=gcp-prod gcp
```

Verify the provider is enabled:

```bash
warden provider list
```

Configure the provider with `auto_auth_path`. This allows clients to authenticate with their JWT directly — no explicit Warden login required:

```bash
warden write gcp/config <<EOF
{
  "auto_auth_path": "auth/jwt/",
  "timeout": "30s",
  "max_body_size": 10485760
}
EOF
```

See [Provider configuration](/provider-backends/configuration/) for the full list of common config fields (`proxy_domains`, `timeout`, `tls_skip_verify`, `ca_data`, and more).

Verify the configuration:

```bash
warden read gcp/config
```

## Step 3: Create a Credential Source and Spec

Start with the keyless source — it stores nothing. Every source and spec key is documented
on the [GCP credential driver page](/credential-drivers/gcp/).

### 3a. Keyless federation (recommended)

A federated source holds no key, so it takes **no `rotation_period`**. It names the
Workload Identity Federation provider Google should trust, as a **full resource name
beginning `//iam.googleapis.com/`** — a bare `projects/...` path is rejected.

```bash
warden cred source create gcp-src -json '{
  "type": "gcp",
  "config": {
    "auth_method": "oidc_federation",
    "workload_identity_provider": "//iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/warden-pool/providers/warden-oidc"
  }
}'
```

Configure that provider to trust Warden's issuer — see
[Keyless credentials](/federation/keyless-credentials/).

A spec on a keyless source **must** set `subject_token_source`, and
`assertion_user_claims` is what carries the user into the assertion:

```bash
warden cred spec create gcp-cloud-platform -json '{
  "source": "gcp-src",
  "min_ttl": 300,
  "max_ttl": 3600,
  "config": {
    "mint_method": "impersonated_access_token",
    "subject_token_source": "warden_identity",
    "target_service_account": "target@my-project.iam.gserviceaccount.com",
    "scopes": "https://www.googleapis.com/auth/cloud-platform"
  }
}'
```

Three mint methods work over federation — `impersonated_access_token`, `access_token` and
`secret_read`. Impersonation is the usual choice: the federated identity is granted only
`roles/iam.serviceAccountTokenCreator` on the target, and the target carries the actual
permissions.

`assertion_user_claims` is opt-in and **fails closed** on a claim the user's login does not
carry; omit it and the assertion describes the agent only.

### 3b. Stored service account key

The source holds the JSON key. Here `rotation_period` is meaningful — integer seconds in
JSON (`2592000` = 30 days).

```bash
warden cred source create gcp-sa -json "{
  \"type\": \"gcp\",
  \"rotation_period\": 2592000,
  \"config\": {
    \"auth_method\": \"static\",
    \"service_account_key\": $(jq -Rs . < /path/to/service-account-key.json)
  }
}"
```

`jq -Rs .` embeds the key file as a correctly escaped JSON string. Warden authenticates
with it before storing the source, so it must be a real key.

:::caution[The source type is `gcp`]
Not `gcp_access_token` — that is a *credential* type, not a source type, and a source
created with it is rejected: *"unknown source type"*. The available source types are listed
in the error if you get it wrong.
:::

Verify the source was created:

```bash
warden cred source read gcp-sa
```

### Spec mint methods

**`access_token`** — mint for the source service account directly:

```bash
warden cred spec create gcp-direct -json '{
  "source": "gcp-sa",
  "min_ttl": 300,
  "max_ttl": 3600,
  "config": {
    "mint_method": "access_token",
    "scopes": "https://www.googleapis.com/auth/cloud-platform"
  }
}'
```

**`impersonated_access_token`** — mint on behalf of another service account:

```bash
warden cred spec create gcp-impersonated -json '{
  "source": "gcp-sa",
  "min_ttl": 300,
  "max_ttl": 3600,
  "config": {
    "mint_method": "impersonated_access_token",
    "target_service_account": "target@my-project.iam.gserviceaccount.com",
    "scopes": "https://www.googleapis.com/auth/cloud-platform",
    "lifetime": "3600s"
  }
}'
```

### Option C: Vault/OpenBao GCP Secret Engine

Instead of storing a service account key in Warden, you can use the Vault GCP secret engine to dynamically mint access tokens. Vault manages the service account lifecycle.

**Prerequisites:** A Vault/OpenBao instance with:
- The GCP secret engine mounted and configured with a roleset or static account
- An AppRole configured for Warden access

```bash
# Create a Vault credential source
warden cred source create gcp-vault-src \
  -type=hvault \
  -config=vault_address=https://vault.example.com \
  -config=auth_method=approle \
  -config=role_id=your-role-id \
  -config=secret_id=your-secret-id \
  -config=approle_mount=approle \
  -config=role_name=warden-role \
  -rotation-period=24h

# Create a credential spec using the dynamic_gcp mint method (roleset)
warden cred spec create gcp-cloud-platform \
  -source gcp-vault-src \
  -config mint_method=dynamic_gcp \
  -config gcp_mount=gcp \
  -config role_name=my-roleset

# Or using a static account instead of a roleset
warden cred spec create gcp-static \
  -source gcp-vault-src \
  -config mint_method=dynamic_gcp \
  -config gcp_mount=gcp \
  -config role_name=my-static-account \
  -config role_type=static-account
```

Verify:

```bash
warden cred spec read gcp-cloud-platform
```

## Step 4: Create a Policy

Create a policy that grants access to the GCP provider gateway. Note that this policy is intentionally coarse-grained for simplicity, but it can be made much more fine-grained to restrict access to specific paths or capabilities as needed:

```bash
warden policy write gcp-access - <<EOF
path "gcp/role/+/gateway*" {
  capabilities = ["create", "read", "update", "delete", "patch"]
}
EOF
```

For tighter control, add runtime conditions to protect destructive operations on specific paths. For example, restrict Compute Engine instance deletion to trusted networks during business hours while leaving read access unconditional:

```bash
warden policy write gcp-prod-restricted - <<EOF
path "gcp/role/+/gateway/compute.googleapis.com/compute/v1/projects/+/zones/+/instances/*" {
  capabilities = ["delete"]
  condition = <<-CEL
    cidrContains("10.0.0.0/8", request.client_ip) &&
    now.getHours("UTC") >= 8 && now.getHours("UTC") < 18 &&
    now.getDayOfWeek("UTC") in [1, 2, 3, 4, 5]
  CEL
}

path "gcp/role/+/gateway*" {
  capabilities = ["create", "read", "update", "patch"]
}
EOF
```

The `condition` is a [CEL](https://cel.dev) expression (see [CEL conditions](/concepts/cel-conditions/)): `cidrContains` restricts by network and `now.getHours`/`now.getDayOfWeek` by time of day and weekday. It must evaluate to `true` for the rule to apply, and fails closed.

Verify:

```bash
warden policy read gcp-access
```

## Step 5: Get a JWT and Make Requests

Get a JWT from your identity provider — see [Obtaining a JWT](/auth-methods/jwt/#obtaining-a-jwt) (the local dev setup issues one from Hydra). Export it as `$JWT_TOKEN`.

Requests use role-based paths. Warden performs implicit JWT authentication and injects the OAuth2 Bearer token automatically.

The URL pattern is: `/v1/gcp/role/{role}/gateway/{googleapis-host}/{path}`

The first path segment after `gateway/` is the GCP API host, and the rest is the API path.

Export GCP_ENDPOINT as environment variable:
```bash
export GCP_ENDPOINT="${WARDEN_ADDR}/v1/gcp/role/gcp-user/gateway"
```

### Cloud Storage — List Buckets

```bash
curl "${GCP_ENDPOINT}/storage.googleapis.com/storage/v1/b?project=my-project" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### Cloud Storage — Get Object

```bash
curl "${GCP_ENDPOINT}/storage.googleapis.com/storage/v1/b/my-bucket/o/my-object" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### Compute Engine — List Instances

```bash
curl "${GCP_ENDPOINT}/compute.googleapis.com/compute/v1/projects/my-project/zones/us-central1-a/instances" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### Secret Manager — List Secrets

```bash
curl "${GCP_ENDPOINT}/secretmanager.googleapis.com/v1/projects/my-project/secrets" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### BigQuery — List Datasets

```bash
curl "${GCP_ENDPOINT}/bigquery.googleapis.com/bigquery/v2/projects/my-project/datasets" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### IAM — List Service Accounts

```bash
curl "${GCP_ENDPOINT}/iam.googleapis.com/v1/projects/my-project/serviceAccounts" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

## Cleanup

To stop Warden and the identity provider:

```bash
# Stop Warden (Ctrl+C in the terminal where it's running)

# Stop and remove the identity provider containers
docker compose -f docker-compose.quickstart.yml down -v
```

Since Warden dev mode uses in-memory storage, all configuration is lost when the server stops.

## Mint Methods

| Method | Description | Token Lifetime | Use Case |
|--------|-------------|----------------|----------|
| `access_token` | OAuth2 token from source SA key | ~1 hour (auto-refreshed) | Direct access with source SA permissions |
| `impersonated_access_token` | Token minted on behalf of another SA | Configurable via `lifetime` (default: 1h) | Least-privilege delegation without sharing target SA keys |
| `dynamic_gcp` | Token from Vault GCP secret engine | ~1 hour | Vault-managed service accounts — no SA key in Warden |

Both `access_token` and `impersonated_access_token` return tokens that expire naturally and cannot be revoked. `dynamic_gcp` delegates token minting to the Vault GCP engine.

### Returned Credential Data

```json
{
  "access_token": "ya29.xxx...",
  "project_id": "my-project",
  "scopes": "https://www.googleapis.com/auth/cloud-platform",
  "token_type": "Bearer",
  "target_service_account": "target@my-project.iam.gserviceaccount.com"
}
```

The `target_service_account` field is only present for impersonated tokens.

## Credential Rotation

The GCP provider supports the two-stage async rotation pattern for service account keys:

1. **Prepare**: Creates a new service account key via the IAM API.
2. **Activate**: After the activation delay, switches to the new key and invalidates all cached tokens.
3. **Cleanup**: Deletes the old service account key via the IAM API.

The default activation delay is **2 minutes** (configurable via `activation_delay` in the credential source config). This accounts for IAM propagation time across GCP.

When the source key rotates, all credential specs sharing that source automatically use the new key — no per-spec rotation is needed.

## TLS Certificate Authentication

Steps 4-5 above use JWT authentication. Alternatively, you can authenticate with a TLS client certificate. This is useful for workloads that already have X.509 certificates — Kubernetes pods with cert-manager, VMs with machine certificates, or SPIFFE X.509-SVIDs from a service mesh.

:::note[Prerequisite]
Certificate auth requires mTLS on the Warden listener so the client certificate can be presented during the handshake. See [Enabling mTLS on the listener](/auth-methods/cert/#enabling-mtls-on-the-listener).
:::

Steps 1-3 (provider setup) are identical. Replace Steps 4-5 with the following.

### Enable Cert Auth

```bash
warden auth enable cert
```

### Configure Trusted CA

Provide the PEM-encoded CA certificate that signs your client certificates:

```bash
warden write auth/cert/config \
    trusted_ca_pem=@/path/to/ca.pem \
    default_role=gcp-user
```

### Create a Cert Role

Create a role that binds allowed certificate identities to a credential spec and policy:

```bash
warden write auth/cert/role/gcp-user \
    allowed_common_names="agent-*" \
    token_policies="gcp-access" \
    cred_spec_name=gcp-cloud-platform
```

The `allowed_common_names` field supports glob patterns; you can also match on other certificate fields. See [Create a role](/auth-methods/cert/#step-3-create-a-role) for the full set of constraint fields.

### Configure Provider for Cert Auth

Update the provider config to use cert auth:

```bash
warden write gcp/config <<EOF
{
  "auto_auth_path": "auth/cert/",
  "timeout": "30s",
  "max_body_size": 10485760
}
EOF
```

### Make Requests with Certificates

```bash
# Role in URL path
curl --cert client.pem --key client-key.pem \
    --cacert warden-ca.pem \
    "https://warden.internal/v1/gcp/role/gcp-user/gateway/storage.googleapis.com/storage/v1/b?project=my-project"

# Default role (no role in URL)
curl --cert client.pem --key client-key.pem \
    --cacert warden-ca.pem \
    "https://warden.internal/v1/gcp/gateway/storage.googleapis.com/storage/v1/b?project=my-project"
```
