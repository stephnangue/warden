---
title: "Scaleway"
description: "Proxy Scaleway APIs through Warden: chain the management key from a vault per request, mint a short-lived API key with it, and inject that upstream."
---

The Scaleway provider enables proxied access to Scaleway APIs through Warden. It supports two authentication modes, auto-detected per request:

- **Standard API** — Injects `X-Auth-Token` header with the Scaleway secret key. Covers Instances, Kubernetes, Databases, IAM, Load Balancers, Registries, and all other Scaleway products.
- **S3 Object Storage** — Verifies the client's SigV4 signature, re-signs with real Scaleway credentials, and forwards to `s3.{region}.scw.cloud`. Compatible with any S3 client (AWS CLI, boto3, s3cmd, MinIO).

## How a request flows

Scaleway has no workload-identity federation, so minting short-lived API keys needs a
**management key** with IAM permissions. The question is whether that key sits in Warden's
storage or stays in the vault that owns it.

The recommended setup stores no Scaleway credential in Warden.

<p align="center"><img alt="An agent presents the user's ID token and its own identity to Warden, which builds an assertion carrying user and agent claims, has an external KMS sign it, reads the management key from an external vault at a path templated by the agent's team and environment, uses it to mint a short-lived API key at the Scaleway token endpoint, and injects that key to the Scaleway service API" src="/images/warden-prov-scaleway-cred-chain.png" width="860"></p>

1. The user authenticates and the agent holds their ID token.
2. The agent calls Warden presenting both credentials and asserting a role.
3. Warden builds the assertion that the referenced spec calls for and sends it to an
   **external KMS** unsigned.
4. The KMS returns it signed. No signing key lives in Warden.
5. Warden authenticates to the **external vault** with that assertion and reads
   `secret/scaleway/{{agent.team}}/{{agent.env}}`.
6. The vault returns the management key for that team and environment.
7. Warden presents it to **Scaleway IAM**…
8. …which mints a fresh, short-lived API key.
9. Warden injects that key as `X-Auth-Token` and forwards.

The minted key is revoked when its lease expires, so the credential reaching Scaleway is
short-lived even though the management key behind it is not — and that management key never
enters Warden's storage.

:::note[Steps 3–8 run only on a cache miss]
Warden caches the minted credential, so most requests skip from step 2 to step 9 — no
assertion, no vault read, no key minting. The entry is keyed by namespace, the agent's
token id, the spec name and the user's token id.
:::

### When you must store the management key

Where there is no vault to chain from, the key lives in the source and Warden can rotate it.

<p align="center"><img alt="Warden reads the Scaleway management key from its encrypted storage, uses it to mint a short-lived API key at the Scaleway token endpoint, and injects that key to the Scaleway service API" src="/images/warden-prov-scaleway-static-sts.png" width="860"></p>

Steps 3 to 6 collapse into a single storage read. The minting and injection are unchanged.

## Credential modes

| Mode | Supported | How |
|---|---|---|
| **Chaining** ✅ *recommended* | Yes | `secret_spec` on the source; the management key is read per request from a vault Warden reaches keylessly |
| **Stored root → short-lived mint** | Yes | `management_access_key` + `management_secret_key` on the source, rotated on a schedule |
| **Static inline** | Yes, discouraged | `mint_method=static_keys` serves a fixed pair — no minting, no expiry, revocation a no-op |
| **Keyless federation** | No | Scaleway exposes no workload-identity federation |
| **Delegated user token** | No | The upstream receives a key minted for an IAM application |

See the [Scaleway credential driver](/credential-drivers/scaleway/) for every source and
spec key.

## Prerequisites

- Docker and Docker Compose installed and running
- A **Scaleway account** with an API key (access key + secret key) — generate one at [Scaleway Console > IAM > API Keys](https://console.scaleway.com/iam/api-keys)

:::note[New to Warden?]
Follow [Local dev setup](/provider-backends/local-dev-setup/) to start a local dev environment (Ory Hydra + a Warden dev server) before Step 1.
:::

## Step 1: Configure JWT Auth and Create a Role

Enable the JWT auth method and point it at your identity provider's JWKS endpoint, then create a role that binds the credential spec and policy. Enabling the mount and configuring the key source is covered once in [JWT auth](/auth-methods/jwt/#step-1-configure-the-key-source) — for the local dev setup.

> **Set this up before configuring the provider.** The provider resolves
> `auto_auth_path` per request — writing the config only checks that it is
> non-empty, not that the mount exists — so a gateway call fails with `no auth
> mount registered ... for implicit auth` if the referenced auth mount isn't
> there yet.

```bash
warden auth enable jwt
warden write auth/jwt/config jwks_url=http://localhost:4444/.well-known/jwks.json

# Create a role that binds the credential spec and policy
warden write auth/jwt/role/scaleway-user \
    token_policies="scaleway-access" \
    user_claim=sub \
    cred_spec_name=scaleway-ops
```

## Step 2: Mount and Configure the Provider

Enable the Scaleway provider at a path of your choice:

```bash
warden provider enable scaleway
```

To mount at a custom path:

```bash
warden provider enable -path=scaleway-prod scaleway
```

Verify the provider is enabled:

```bash
warden provider list
```

Configure the provider with `auto_auth_path`. This allows clients to authenticate with their JWT directly — no explicit Warden login required:

```bash
warden write scaleway/config <<EOF
{
  "scaleway_url": "https://api.scaleway.com",
  "auto_auth_path": "auth/jwt/",
  "timeout": "30s",
  "max_body_size": 10485760
}
EOF
```

See [Provider configuration](/provider-backends/configuration/) for the full list of common config fields (`proxy_domains`, `timeout`, `tls_skip_verify`, `ca_data`, and more).

Verify the configuration:

```bash
warden read scaleway/config
```

## Step 3: Create a Credential Source and Spec

### Option A: Chained management key (recommended)

The flow in the diagram above. The **source** names a `secret_spec` and holds no key of its
own; Warden reads the management key per mint and uses it to create a short-lived API key.

```bash
# Producer: the management key, read from KV v2 through a keyless Vault source
warden cred spec create scaleway-mgmt-key -json '{
  "source": "vault-keyless",
  "min_ttl": 600,
  "max_ttl": 3600,
  "config": {
    "mint_method": "kv2_read",
    "subject_token_source": "warden_identity",
    "assertion_metadata_claims": "team,env",
    "kv2_mount": "secret",
    "secret_path": "scaleway/{{agent.team}}/{{agent.env}}"
  }
}'

# Consumer: a scaleway source holding no key of its own
warden cred source create scaleway-src -json '{
  "type": "scaleway",
  "config": {
    "scaleway_url": "https://api.scaleway.com",
    "secret_spec": "scaleway-mgmt-key"
  }
}'

warden cred spec create scaleway-ops -json '{
  "source": "scaleway-src",
  "min_ttl": 600,
  "max_ttl": 3600,
  "config": {
    "mint_method": "dynamic_keys",
    "application_id": "<your-iam-application-id>",
    "default_project_id": "<your-project-id>",
    "ttl": "1h",
    "description": "warden-managed"
  }
}'
```

`management_secret_key`, `management_access_key` and `activation_delay` must **all** be
omitted when `secret_spec` is set, and each is rejected by name if left behind. The secret
comes from the referenced spec, and rotation belongs to whoever owns that spec rather than
to this source. The referenced payload supplies the key under `management_secret_key` (or
`secret_key`).

Both principals are available to the path template. `{{agent.sub}}` needs nothing;
`{{agent.<claim>}}` needs the claim in `assertion_metadata_claims`; `{{user.<claim>}}`
needs it in `assertion_user_claims` **and** a user on the request. Templates resolve at
**mint, not at write**, so a path naming an unprojected claim is accepted by `spec create`
and fails on the first request.

### Option B: Management key stored on the source

Have Warden create short-lived API keys on demand via the Scaleway IAM API. Keys are automatically revoked when they expire. No long-lived secrets are stored in credential specs.

> **Note:** The Scaleway IAM API is currently `v1alpha1`. While it has been stable in practice (used by the CLI, Terraform, and all SDKs), Scaleway may introduce breaking changes without a deprecation period. If the API version changes, update the `iam_api_path` config on the credential source (e.g., `-config=iam_api_path=/iam/v2`). No code changes required.

**Prerequisites:**
- A **management API key** with IAM permissions to create and delete API keys
- A **Scaleway IAM application** that the dynamic keys will be attached to

```bash
warden cred source create scaleway-src -json '{
  "type": "scaleway",
  "rotation_period": 86400,
  "config": {
    "scaleway_url": "https://api.scaleway.com",
    "management_access_key": "SCWXXXXXXXXXXXXXXXXX",
    "management_secret_key": "<your-management-secret-key>"
  }
}'

warden cred spec create scaleway-ops -json '{
  "source": "scaleway-src",
  "min_ttl": 600,
  "max_ttl": 3600,
  "config": {
    "mint_method": "dynamic_keys",
    "application_id": "<your-iam-application-id>",
    "default_project_id": "<your-project-id>",
    "ttl": "1h",
    "description": "warden-managed"
  }
}'
```

`management_access_key` must start with `SCW` — the driver rejects a value that does not,
on the assumption the access key and secret key were swapped.

Each credential request creates a fresh API key via `POST /iam/v1alpha1/api-keys` with the configured TTL. When the lease expires, Warden revokes the key via `DELETE /iam/v1alpha1/api-keys/{access_key}`.

### Serving a fixed key pair

`mint_method=static_keys` serves an existing pair instead of minting one. It needs either
`access_key` and `secret_key` inline, or a `secret_spec` naming a spec that yields them:

```bash
warden cred spec create scaleway-static -json '{
  "source": "scaleway-src",
  "min_ttl": 600,
  "max_ttl": 3600,
  "config": {
    "mint_method": "static_keys",
    "secret_spec": "scaleway-api-pair"
  }
}'
```

Because the pair is served rather than minted, it carries no lease, does not expire, and
revocation is a no-op. Prefer `dynamic_keys` wherever the IAM permissions allow it.

:::caution[An `hvault` source cannot serve Scaleway keys directly]
`scaleway_keys` credentials require a `local` or `scaleway` source — pointing a spec at an
`hvault` source is rejected. To hold the keys in Vault/OpenBao, use the chaining route in
Option A: a `scaleway` source with `secret_spec`, and a `kv2_read` producer that does the
vault read.
:::

Verify:

```bash
warden cred spec read scaleway-ops
```

## Step 4: Create a Policy

Create a policy that grants access to the Scaleway provider gateway:

```bash
warden policy write scaleway-access - <<EOF
path "scaleway/role/+/gateway*" {
  capabilities = ["create", "read", "update", "delete", "patch"]
}
EOF
```

For fine-grained access control, restrict which Scaleway APIs and regions a role can use:

```bash
warden policy write scaleway-readonly - <<EOF
# Allow read-only access to instances in fr-par
path "scaleway/role/+/gateway/instance/v1/zones/fr-par-*" {
  capabilities = ["read"]
}

# Allow read-only access to Kubernetes clusters
path "scaleway/role/+/gateway/k8s/v1/regions/*" {
  capabilities = ["read"]
}

# Allow read-only access to IAM
path "scaleway/role/+/gateway/iam/*" {
  capabilities = ["read"]
}

# Allow read-only access to databases
path "scaleway/role/+/gateway/rdb/v1/regions/*" {
  capabilities = ["read"]
}
EOF
```

Verify:

```bash
warden policy read scaleway-access
```

## Step 5: Get a JWT and Make Requests

Get a JWT from your identity provider — see [Obtaining a JWT](/auth-methods/jwt/#obtaining-a-jwt) (the local dev setup issues one from Hydra). Export it as `$JWT_TOKEN`.

Requests use role-based paths. Warden performs implicit JWT authentication and injects the Scaleway credentials automatically.

The URL pattern is: `/v1/scaleway/role/{role}/gateway/{api-path}`

Export SCW_ENDPOINT as environment variable:
```bash
export SCW_ENDPOINT="${WARDEN_ADDR}/v1/scaleway/role/scaleway-user/gateway"
```

### List Instances

```bash
curl -s "${SCW_ENDPOINT}/instance/v1/zones/fr-par-1/servers" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### List Kubernetes Clusters

```bash
curl -s "${SCW_ENDPOINT}/k8s/v1/regions/fr-par/clusters" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### List Database Instances

```bash
curl -s "${SCW_ENDPOINT}/rdb/v1/regions/fr-par/instances" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### List API Keys (IAM)

```bash
curl -s "${SCW_ENDPOINT}/iam/v1alpha1/api-keys" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### List Load Balancers

```bash
curl -s "${SCW_ENDPOINT}/lb/v1/zones/fr-par-1/lbs" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### Create an Instance

```bash
curl -s -X POST "${SCW_ENDPOINT}/instance/v1/zones/fr-par-1/servers" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-instance",
    "commercial_type": "DEV1-S",
    "image": "ubuntu_jammy",
    "project": "your-project-id"
  }'
```

### Delete an Instance

```bash
curl -s -X DELETE "${SCW_ENDPOINT}/instance/v1/zones/fr-par-1/servers/{server-id}" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

## S3 Object Storage

The Scaleway provider auto-detects S3 requests by the presence of a SigV4 `Authorization` header. Any S3-compatible client works — AWS CLI, boto3, s3cmd, MinIO Client.

### S3 Transparent Auth with JWT

Configure your S3 client to point at Warden's gateway endpoint. Use your JWT as both the access key and secret key:

```bash
aws configure set aws_access_key_id "${JWT_TOKEN}"
aws configure set aws_secret_access_key "${JWT_TOKEN}"
aws configure set region fr-par
```

### S3 Transparent Auth with Certificates

For certificate-based authentication, use the role name as both the access key and secret key:

```bash
aws configure set aws_access_key_id "scaleway-user"
aws configure set aws_secret_access_key "scaleway-user"
aws configure set region fr-par
```

### S3 Operations

```bash
# List buckets
aws s3 ls \
  --endpoint-url "${WARDEN_ADDR}/v1/scaleway/role/scaleway-user/gateway"

# List objects in a bucket
aws s3 ls s3://my-bucket/ \
  --endpoint-url "${WARDEN_ADDR}/v1/scaleway/role/scaleway-user/gateway"

# Upload a file
aws s3 cp myfile.txt s3://my-bucket/myfile.txt \
  --endpoint-url "${WARDEN_ADDR}/v1/scaleway/role/scaleway-user/gateway"

# Download a file
aws s3 cp s3://my-bucket/myfile.txt ./downloaded.txt \
  --endpoint-url "${WARDEN_ADDR}/v1/scaleway/role/scaleway-user/gateway"
```

### Supported S3 Regions

| Region | Location | S3 Endpoint |
|--------|----------|-------------|
| `fr-par` | Paris, France | `s3.fr-par.scw.cloud` |
| `nl-ams` | Amsterdam, Netherlands | `s3.nl-ams.scw.cloud` |
| `pl-waw` | Warsaw, Poland | `s3.pl-waw.scw.cloud` |
| `it-mil` | Milan, Italy | `s3.it-mil.scw.cloud` |

The region is extracted from the SigV4 Authorization header and used to route to the correct Scaleway S3 endpoint.

## Terraform Provider Limitation

The native [Scaleway Terraform provider](https://registry.terraform.io/providers/scaleway/scaleway/latest) (`scaleway/scaleway`) validates that `secret_key` is a UUID, which is incompatible with Warden's JWT-based transparent authentication. It cannot be used to manage Scaleway resources through the Warden gateway.

**Workarounds for Terraform users:**

- **Standard API** — Use the [`Mastercard/restapi`](https://registry.terraform.io/providers/Mastercard/restapi) provider with the JWT in the `Authorization: Bearer` header. This covers all Scaleway API operations (instances, IAM, databases, etc.).
- **S3 Object Storage** — Use the [`hashicorp/aws`](https://registry.terraform.io/providers/hashicorp/aws) provider with `skip_region_validation = true` and the S3 endpoint set to the Warden gateway URL. The AWS provider performs real SigV4 signing, which Warden detects and re-signs with real Scaleway credentials.

See [`e2e_test/`](https://github.com/stephnangue/warden/tree/main/e2e) for a working example of this approach.

## Cleanup

To stop Warden and the identity provider:

```bash
# Stop Warden (Ctrl+C in the terminal where it's running)

# Stop and remove the identity provider containers
docker compose -f docker-compose.quickstart.yml down -v
```

Since Warden dev mode uses in-memory storage, all configuration is lost when the server stops.

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
    default_role=scaleway-user
```

### Create a Cert Role

Create a role that binds allowed certificate identities to a credential spec and policy:

```bash
warden write auth/cert/role/scaleway-user \
    allowed_common_names="agent-*" \
    token_policies="scaleway-access" \
    cred_spec_name=scaleway-ops
```

The `allowed_common_names` field supports glob patterns; you can also match on other certificate fields. See [Create a role](/auth-methods/cert/#step-3-create-a-role) for the full set of constraint fields.

### Configure Provider for Cert Auth

Update the provider config to use cert auth:

```bash
warden write scaleway/config <<EOF
{
  "scaleway_url": "https://api.scaleway.com",
  "auto_auth_path": "auth/cert/",
  "timeout": "30s",
  "max_body_size": 10485760
}
EOF
```

### Make Requests with Certificates

Standard API:

```bash
curl --cert client.pem --key client-key.pem \
    --cacert warden-ca.pem \
    -s "https://warden.internal/v1/scaleway/role/scaleway-user/gateway/instance/v1/zones/fr-par-1/servers" \
    -H "Content-Type: application/json"
```

S3 Object Storage:

```bash
aws s3 ls s3://my-bucket/ \
  --endpoint-url "https://warden.internal/v1/scaleway/role/scaleway-user/gateway"
```

## Token Management

### Static API Keys

| Aspect | Details |
|--------|---------|
| **Storage** | Access key and secret key are stored on the credential spec |
| **Rotation** | Manual — regenerate in Scaleway Console and update the spec |
| **Lifetime** | Static — no expiration or auto-refresh |
| **Revocation** | Scaleway API keys can be deleted via `DELETE /iam/v1alpha1/api-keys/{access_key}` |

**To rotate static API keys:**

1. Generate a new API key in [Scaleway Console > IAM > API Keys](https://console.scaleway.com/iam/api-keys)
2. Update the credential spec:
   ```bash
   warden cred spec update scaleway-ops \
     -config access_key=SCWNEWKEYXXXXXXXXXX \
     -config secret_key=new-uuid-secret-key
   ```
3. Delete the old API key in Scaleway Console

### Dynamic API Keys

| Aspect | Details |
|--------|---------|
| **Storage** | Management key on the source; no long-lived keys on specs |
| **Minting** | Fresh API key created via `POST /iam/v1alpha1/api-keys` on each credential request |
| **Lifetime** | Configurable via `ttl` (default: 1h); Scaleway enforces `expires_at` on the key |
| **Revocation** | Automatic — Warden calls `DELETE /iam/v1alpha1/api-keys/{access_key}` on lease expiry |
| **Rotation** | Not needed — keys are ephemeral |

**Automatic management key rotation:**

When both `management_secret_key` and `management_access_key` are configured on the source, Warden can automatically rotate the management key itself. Set a `rotation-period` on the source to enable it:

```bash
warden cred source create scaleway-dynamic-src \
  -type=scaleway \
  -rotation-period=24h \
  -config=scaleway_url=https://api.scaleway.com \
  -config=management_secret_key=your-management-secret-key \
  -config=management_access_key=SCWXXXXXXXXXXXXXXXXX
```

The rotation flow:
1. Warden creates a new management key via `POST /iam/v1alpha1/api-keys` for the same IAM application or user
2. Waits `activation_delay` (default: 30s) for propagation
3. Activates the new key in the driver
4. Deletes the old key via `DELETE /iam/v1alpha1/api-keys/{old_access_key}`

Both old and new keys remain valid during the overlap period, ensuring zero downtime.

**Manual management key rotation:**

If automatic rotation is not configured, rotate manually:

1. Generate a new management API key in [Scaleway Console > IAM > API Keys](https://console.scaleway.com/iam/api-keys)
2. Update the credential source:
   ```bash
   warden cred source update scaleway-dynamic-src \
     -config=management_secret_key=new-management-secret-key \
     -config=management_access_key=SCWNEWKEYXXXXXXXXXX
   ```
3. Delete the old management API key in Scaleway Console
