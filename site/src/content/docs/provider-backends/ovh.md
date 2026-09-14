---
title: "OVH"
description: "Proxy OVHcloud APIs through Warden: chain the OAuth2 service account from a vault per request, exchange it for a bearer token, and inject that upstream."
---

The OVH provider enables proxied access to OVHcloud APIs through Warden. It supports two authentication modes, auto-detected per request:

- **Standard API** — Injects `Authorization: Bearer` header with the API token. Covers account info, cloud projects, domains, IPs, and all other OVHcloud products.
- **S3 Object Storage** — Verifies the client's SigV4 signature, re-signs with real OVH S3 credentials, and forwards to `s3.{region}.io.cloud.ovh.net`. Compatible with any S3 client (AWS CLI, boto3, s3cmd, MinIO).

## How a request flows

OVH authenticates with an **OAuth2 service account** — a `client_id` and `client_secret`
pair. There is no workload-identity federation to replace it, so the question is whether
that pair sits in Warden's storage or stays in the vault that owns it.

The recommended setup stores no OVH credential in Warden.

<p align="center"><img alt="An agent presents the user's ID token and its own identity to Warden, which builds an assertion carrying user and agent claims, has an external KMS sign it, reads the OVH service account from an external vault at a path templated by the agent's team and environment, exchanges it at the OVH token endpoint for an access token, and injects the token to the OVH service API" src="/images/warden-prov-ovh-cred-chain.png" width="860"></p>

1. The user authenticates and the agent holds their ID token.
2. The agent calls Warden presenting both credentials and asserting a role.
3. Warden builds the assertion that the referenced spec calls for and sends it to an
   **external KMS** unsigned.
4. The KMS returns it signed. No signing key lives in Warden.
5. Warden authenticates to the **external vault** with that assertion and reads
   `secret/ovh/{{agent.team}}/{{agent.env}}`.
6. The vault returns the service account for that team and environment.
7. Warden exchanges it at the **OVH token endpoint**…
8. …receiving a short-lived access token.
9. Warden injects that token as `Authorization: Bearer <token>` and forwards.

Warden reaches the vault **keylessly**, so no vault token sits in its storage either, and
the read path is templated by the caller's claims — one spec serves every team and
environment while each reaches only its own credential.

:::note[Steps 3–8 run only on a cache miss]
Warden caches the minted credential, so most requests skip from step 2 to step 9 — no
assertion, no vault read, no token exchange. The entry is keyed by namespace, the agent's
token id, the spec name and the user's token id.
:::

### When you must store the service account

Where there is no vault to chain from, the pair lives in the source.

<p align="center"><img alt="Warden reads the OVH service account from its encrypted storage, exchanges it at the OVH token endpoint for an access token, and injects that token to the OVH service API" src="/images/warden-prov-ovh-static-sts.png" width="860"></p>

Steps 3 to 6 collapse into a single storage read. The exchange and injection are unchanged.

## Credential modes

| Mode | Supported | How |
|---|---|---|
| **Chaining** ✅ *recommended* | Yes | `secret_spec` on the source; the service account is read per request from a vault Warden reaches keylessly |
| **Stored root → short-lived mint** | Yes | `client_id` + `client_secret` on the source, exchanged for a bearer token per request |
| **Keyless federation** | No | OVH exposes no workload-identity federation for this exchange |
| **Static inline** | No | The bearer token is always minted; only the credential it is minted from varies |
| **Delegated user token** | No | The upstream receives a token minted for the service account |

See the [OVH credential driver](/credential-drivers/ovh/) for every source and spec key.

## Prerequisites

- Docker and Docker Compose installed and running
- An **OVHcloud account** with an OAuth2 service account (`client_id` + `client_secret`) — create one via [OVHcloud IAM](https://www.ovh.com/auth/) with `flow: "CLIENT_CREDENTIALS"`
- For S3 Object Storage: a Public Cloud project ID and user ID

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
warden write auth/jwt/role/ovh-user \
    token_policies="ovh-access" \
    user_claim=sub \
    cred_spec_name=ovh-ops
```

## Step 2: Mount and Configure the Provider

Enable the OVH provider at a path of your choice:

```bash
warden provider enable ovh
```

To mount at a custom path:

```bash
warden provider enable -path=ovh-prod ovh
```

Verify the provider is enabled:

```bash
warden provider list
```

Configure the provider with `auto_auth_path`. This allows clients to authenticate with their JWT directly — no explicit Warden login required:

```bash
warden write ovh/config <<EOF
{
  "ovh_url": "https://eu.api.ovh.com/1.0",
  "auto_auth_path": "auth/jwt/",
  "timeout": "30s",
  "max_body_size": 10485760
}
EOF
```

See [Provider configuration](/provider-backends/configuration/) for the full list of common config fields (`proxy_domains`, `timeout`, `tls_skip_verify`, `ca_data`, and more).

Verify the configuration:

```bash
warden read ovh/config
```

## Step 3: Create a Credential Source and Spec

**Prerequisites:** An OVH OAuth2 service account — create one via `POST /me/api/oauth2/client` with `flow: "CLIENT_CREDENTIALS"`. See the [e2e test README](https://github.com/stephnangue/warden/tree/main/e2e) for step-by-step instructions.

### Option A: Chained service account (recommended)

The flow in the diagram above. The **source** names a `secret_spec` and holds neither half
of the client credential.

```bash
# Producer: the service account, read from KV v2 through a keyless Vault source
warden cred spec create ovh-service-account -json '{
  "source": "vault-keyless",
  "min_ttl": 600,
  "max_ttl": 3600,
  "config": {
    "mint_method": "kv2_read",
    "subject_token_source": "warden_identity",
    "assertion_metadata_claims": "team,env",
    "kv2_mount": "secret",
    "secret_path": "ovh/{{agent.team}}/{{agent.env}}"
  }
}'

# Consumer: an ovh source holding no credential of its own
warden cred source create ovh-src -json '{
  "type": "ovh",
  "config": {
    "ovh_endpoint": "ovh-eu",
    "secret_spec": "ovh-service-account"
  }
}'

warden cred spec create ovh-api -json '{
  "source": "ovh-src",
  "min_ttl": 600,
  "max_ttl": 3600,
  "config": {
    "mint_method": "oauth2_token"
  }
}'
```

`client_id` **and** `client_secret` must both be omitted when `secret_spec` is set —
keeping either is rejected, because the pair authenticates together and a source that reads
as chained while storing half the credential is the thing chaining exists to prevent. The
referenced payload supplies both, under `client_id` and `client_secret`.

Both principals are available to the path template. `{{agent.sub}}` needs nothing;
`{{agent.<claim>}}` needs the claim in `assertion_metadata_claims`; `{{user.<claim>}}`
needs it in `assertion_user_claims` **and** a user on the request. Templates resolve at
**mint, not at write**, so a path naming an unprojected claim is accepted by `spec create`
and fails on the first request.

### Option B: Service account stored on the source

```bash
warden cred source create ovh-src -json '{
  "type": "ovh",
  "config": {
    "client_id": "<your-client-id>",
    "client_secret": "<your-client-secret>",
    "ovh_endpoint": "ovh-eu"
  }
}'

warden cred spec create ovh-api -json '{
  "source": "ovh-src",
  "min_ttl": 600,
  "max_ttl": 3600,
  "config": {
    "mint_method": "oauth2_token"
  }
}'
```

### Serving S3 credentials

`mint_method=access_keys` serves an **existing** S3 pair — Warden does not mint one. It
**requires** its own `secret_spec` naming a spec that yields the pair:

```bash
warden cred spec create ovh-s3 -json '{
  "source": "ovh-src",
  "min_ttl": 600,
  "max_ttl": 3600,
  "config": {
    "mint_method": "access_keys",
    "secret_spec": "ovh-s3-keys"
  }
}'
```

The referenced payload supplies `access_key` and `secret_key`. Because the pair is served
rather than minted, it carries no lease and revocation is a no-op.

:::caution[Removed in v0.20.0]
The `dynamic_s3` and `oauth2_token_and_s3` mint methods are gone, along with the source's
`api_url` key and the regional S3 API base URLs — see
[Upgrading from v0.19.0](/upgrade/from-v0-19/).

The source's `project_id` and `user_id` keys went with them. They are **not rejected**:
unknown source keys are accepted and ignored, so an older config carrying them writes
cleanly and simply has no effect. Remove them so the config says what it does.
:::

Verify:

```bash
warden cred spec read ovh-api
```

## Step 4: Create a Policy

Create a policy that grants access to the OVH provider gateway:

```bash
warden policy write ovh-access - <<EOF
path "ovh/role/+/gateway*" {
  capabilities = ["create", "read", "update", "delete", "patch"]
}
EOF
```

For fine-grained access control, restrict which OVH resources and actions a role can use:

```bash
warden policy write ovh-readonly - <<EOF
path "ovh/role/+/gateway/me" {
  capabilities = ["read"]
}

path "ovh/role/+/gateway/cloud/project" {
  capabilities = ["read"]
}

path "ovh/role/+/gateway/domain" {
  capabilities = ["read"]
}

path "ovh/role/+/gateway/ip" {
  capabilities = ["read"]
}
EOF
```

Verify:

```bash
warden policy read ovh-access
```

## Step 5: Get a JWT and Make Requests

Get a JWT from your identity provider — see [Obtaining a JWT](/auth-methods/jwt/#obtaining-a-jwt) (the local dev setup issues one from Hydra). Export it as `$JWT_TOKEN`.

Requests use role-based paths. Warden performs implicit JWT authentication and injects the OVH credentials automatically.

The URL pattern is: `/v1/ovh/role/{role}/gateway/{api-path}`

Export OVH_ENDPOINT as environment variable:
```bash
export OVH_ENDPOINT="${WARDEN_ADDR}/v1/ovh/role/ovh-user/gateway"
```

### Get Account Info

```bash
curl -s "${OVH_ENDPOINT}/me" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### List Cloud Projects

```bash
curl -s "${OVH_ENDPOINT}/cloud/project" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### List Domains

```bash
curl -s "${OVH_ENDPOINT}/domain" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### List IP Addresses

```bash
curl -s "${OVH_ENDPOINT}/ip" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### Get Cloud Project Details

```bash
curl -s "${OVH_ENDPOINT}/cloud/project/{projectId}" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### List Cloud Project Instances

```bash
curl -s "${OVH_ENDPOINT}/cloud/project/{projectId}/instance" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

## S3 Object Storage

The OVH provider auto-detects S3 requests by the presence of a SigV4 `Authorization` header. Any S3-compatible client works — AWS CLI, boto3, s3cmd, MinIO Client.

### S3 Transparent Auth with JWT

Configure your S3 client to point at Warden's gateway endpoint. Use your JWT as both the access key and secret key:

```bash
aws configure set aws_access_key_id "${JWT_TOKEN}"
aws configure set aws_secret_access_key "${JWT_TOKEN}"
aws configure set region gra
```

### S3 Transparent Auth with Certificates

For certificate-based authentication, use the role name as both the access key and secret key:

```bash
aws configure set aws_access_key_id "ovh-user"
aws configure set aws_secret_access_key "ovh-user"
aws configure set region gra
```

### S3 Operations

```bash
# List buckets
aws s3 ls \
  --endpoint-url "${WARDEN_ADDR}/v1/ovh/role/ovh-user/gateway"

# List objects in a bucket
aws s3 ls s3://my-bucket/ \
  --endpoint-url "${WARDEN_ADDR}/v1/ovh/role/ovh-user/gateway"

# Upload a file
aws s3 cp myfile.txt s3://my-bucket/myfile.txt \
  --endpoint-url "${WARDEN_ADDR}/v1/ovh/role/ovh-user/gateway"

# Download a file
aws s3 cp s3://my-bucket/myfile.txt ./downloaded.txt \
  --endpoint-url "${WARDEN_ADDR}/v1/ovh/role/ovh-user/gateway"
```

### Supported S3 Regions

| Region | Location | S3 Endpoint |
|--------|----------|-------------|
| `gra` | Gravelines, France | `s3.gra.io.cloud.ovh.net` |
| `bhs` | Beauharnois, Canada | `s3.bhs.io.cloud.ovh.net` |
| `sbg` | Strasbourg, France | `s3.sbg.io.cloud.ovh.net` |
| `de` | Frankfurt, Germany | `s3.de.io.cloud.ovh.net` |
| `uk` | London, United Kingdom | `s3.uk.io.cloud.ovh.net` |
| `waw` | Warsaw, Poland | `s3.waw.io.cloud.ovh.net` |

The region is extracted from the SigV4 Authorization header and used to route to the correct OVH S3 endpoint.

## Cleanup

To stop Warden and the identity provider:

```bash
# Stop Warden (Ctrl+C in the terminal where it's running)

# Stop and remove the identity provider containers
docker compose -f docker-compose.quickstart.yml down -v
```

Since Warden dev mode uses in-memory storage, all configuration is lost when the server stops.

## Regional Endpoints

OVHcloud operates three regional API endpoints. Each region has its own API base URL and OAuth2 token URL.

| Region | API Base URL | OAuth2 Token URL |
|--------|-------------|-----------------|
| Europe (default) | `https://eu.api.ovh.com/1.0` | `https://www.ovh.com/auth/oauth2/token` |
| Canada | `https://ca.api.ovh.com/1.0` | `https://ca.ovh.com/auth/oauth2/token` |
| United States | `https://api.us.ovhcloud.com/1.0` | `https://us.ovhcloud.com/auth/oauth2/token` |

To use a non-EU region, update the provider config:

```bash
# Example: configure for the US region
warden write ovh/config <<EOF
{
  "ovh_url": "https://api.us.ovhcloud.com/1.0",
  "auto_auth_path": "auth/jwt/",
  "timeout": "30s"
}
EOF
```

S3 Object Storage regions are independent of the API region and are auto-detected from the SigV4 header.

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
    default_role=ovh-user
```

### Create a Cert Role

Create a role that binds allowed certificate identities to a credential spec and policy:

```bash
warden write auth/cert/role/ovh-user \
    allowed_common_names="agent-*" \
    token_policies="ovh-access" \
    cred_spec_name=ovh-ops
```

The `allowed_common_names` field supports glob patterns; you can also match on other certificate fields. See [Create a role](/auth-methods/cert/#step-3-create-a-role) for the full set of constraint fields.

### Configure Provider for Cert Auth

Update the provider config to use cert auth:

```bash
warden write ovh/config <<EOF
{
  "ovh_url": "https://eu.api.ovh.com/1.0",
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
    -s "https://warden.internal/v1/ovh/role/ovh-user/gateway/me" \
    -H "Content-Type: application/json"
```

S3 Object Storage:

```bash
aws s3 ls s3://my-bucket/ \
  --endpoint-url "https://warden.internal/v1/ovh/role/ovh-user/gateway"
```

## Token Management

| Aspect | Details |
|--------|---------|
| **Storage** | OAuth2 `client_id` + `client_secret` stored on the credential source (long-lived) |
| **API tokens** | Auto-minted via `client_credentials` grant, ~1h TTL, refreshed automatically |
| **S3 credentials** | Created on demand via OVH API, ~1h TTL (tied to OAuth2 token lifetime), revoked and re-created on expiry |
| **Rotation** | Rotate the OAuth2 service account secret in OVHcloud IAM, then update the source |

**To rotate the OAuth2 service account:**

1. Create a new service account or regenerate the secret in OVHcloud IAM
2. Update the credential source:
   ```bash
   warden cred source update ovh-src \
     -config client_id=new-client-id \
     -config client_secret=new-client-secret
   ```
3. Revoke the old service account in OVHcloud IAM
