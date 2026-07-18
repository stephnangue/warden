---
title: "Honeycomb"
---

The Honeycomb provider enables proxied access to the Honeycomb API through Warden. It forwards requests to Honeycomb endpoints (`/1/events/{dataset}`, `/1/queries/{dataset}`, `/2/teams/{team}/api-keys`, etc.) with automatic credential injection and policy evaluation. Honeycomb uses two authentication modes: the `X-Honeycomb-Team` header for ingest and configuration keys, and `Authorization: Bearer <key_id>:<key_secret>` for management keys. Credentials can be static tokens from an `apikey` source or dynamically minted API keys from the `honeycomb` source driver.

## Prerequisites

- Docker and Docker Compose installed and running
- A Honeycomb account with a management key (key ID + key secret) for dynamic key minting, **or** a static ingest/configuration key
- Team slug from your Honeycomb organization (visible in your Honeycomb URL)

:::note[New to Warden?]
Follow [Local dev setup](/provider-backends/local-dev-setup/) to start a local dev environment (Ory Hydra + a Warden dev server) before Step 1.
:::

## Step 1: Configure JWT Auth and Create a Role

Enable the JWT auth method and point it at your identity provider's JWKS endpoint, then create a role that binds the credential spec and policy. Enabling the mount and configuring the key source is covered once in [JWT auth](/auth-methods/jwt/#step-1-configure-the-key-source) — for the local dev setup.

> **This step must come before configuring the provider.** Warden validates at configuration time that the auth backend referenced by `auto_auth_path` is already mounted.

```bash
warden auth enable jwt
warden write auth/jwt/config jwks_url=http://localhost:4444/.well-known/jwks.json

# Create a role that binds the credential spec and policy
warden write auth/jwt/role/honeycomb-user \
    token_policies="honeycomb-access" \
    user_claim=sub \
    cred_spec_name=honeycomb-ops
```

## Step 2: Mount and Configure the Provider

Enable the Honeycomb provider at a path of your choice:

```bash
warden provider enable honeycomb
```

To mount at a custom path (e.g., for the EU region):

```bash
warden provider enable -path=honeycomb-eu honeycomb
```

Verify the provider is enabled:

```bash
warden provider list
```

Configure the provider:

```bash
warden write honeycomb/config <<EOF
{
  "honeycomb_url": "https://api.honeycomb.io",
  "auto_auth_path": "auth/jwt/",
  "timeout": "30s",
  "max_body_size": 10485760
}
EOF
```

See [Provider configuration](/provider-backends/configuration/) for the full list of common config fields (`proxy_domains`, `timeout`, `tls_skip_verify`, `ca_data`, and more).

For EU region:

```bash
warden write honeycomb-eu/config <<EOF
{
  "honeycomb_url": "https://api.eu1.honeycomb.io",
  "auto_auth_path": "auth/jwt/",
  "timeout": "30s"
}
EOF
```

Verify the configuration:

```bash
warden read honeycomb/config
```

## Step 3: Create a Credential Source and Spec

### Option A: Static API Key

Use this when you already have a Honeycomb ingest or configuration key and want Warden to proxy requests with it.

```bash
warden cred source create honeycomb-src \
  -type=apikey \
  -rotation-period=0 \
  -config=api_url=https://api.honeycomb.io \
  -config=display_name=Honeycomb
```

Create a credential spec with your API key:

```bash
warden cred spec create honeycomb-ops \
  -source honeycomb-src \
  -config api_key=your-honeycomb-api-key
```

### Option B: Dynamic API Keys (Honeycomb Source Driver)

Use this to have Warden dynamically create and revoke Honeycomb API keys using a management key. This is the recommended approach for production as it provides automatic key rotation and revocation.

**Prerequisites:**
- A Honeycomb management key (Settings > Team Settings > API Keys > Manage Management Keys)
- The team slug from your Honeycomb account
- An environment ID (visible in the URL when you select an environment)

Create a credential source backed by the Honeycomb API:

```bash
warden cred source create honeycomb-src \
  -type=honeycomb \
  -rotation-period=24h \
  -config=management_key_id=hcxmk_01abc123 \
  -config=management_key_secret=your-management-key-secret \
  -config=team_slug=my-team \
  -config=honeycomb_url=https://api.honeycomb.io
```

Create a credential spec that mints ingest keys:

```bash
warden cred spec create honeycomb-ops \
  -source honeycomb-src \
  -config environment_id=your-environment-id \
  -config key_type=ingest \
  -config key_name_prefix=warden- \
  -config key_ttl=24h
```

For configuration keys with specific permissions:

```bash
warden cred spec create honeycomb-config \
  -source honeycomb-src \
  -config environment_id=your-environment-id \
  -config key_type=configuration \
  -config key_name_prefix=warden- \
  -config key_ttl=24h \
  -config 'permissions={"send_events":true,"create_datasets":true,"run_queries":true}'
```

### Option C: Vault/OpenBao as Credential Source

Instead of storing the API key directly in Warden, you can store it in a Vault/OpenBao KV v2 secret engine and have Warden fetch it at runtime.

**Prerequisites:** A Vault/OpenBao instance with:
- A KV v2 mount containing your Honeycomb API key (e.g., at `secret/honeycomb/ops` with an `api_key` field)
- An AppRole configured for Warden access

```bash
# Create a Vault credential source
warden cred source create honeycomb-vault-src \
  -type=hvault \
  -config=vault_address=https://vault.example.com \
  -config=auth_method=approle \
  -config=role_id=your-role-id \
  -config=secret_id=your-secret-id \
  -config=approle_mount=approle \
  -config=role_name=warden-role \
  -rotation-period=24h
```

Create a credential spec using the `static_apikey` mint method:

```bash
warden cred spec create honeycomb-ops \
  -source honeycomb-vault-src \
  -config mint_method=static_apikey \
  -config kv2_mount=secret \
  -config secret_path=honeycomb/ops
```

The KV v2 secret at `secret/honeycomb/ops` must contain an `api_key` field with your Honeycomb ingest or configuration key.

Verify:

```bash
warden cred spec read honeycomb-ops
```

## Step 4: Create a Policy

Create a policy that grants access to the Honeycomb provider gateway:

```bash
warden policy write honeycomb-access - <<EOF
path "honeycomb/role/+/gateway*" {
  capabilities = ["create", "read", "update", "delete", "patch"]
}
EOF
```

For read-only access (querying only):

```bash
warden policy write honeycomb-readonly - <<EOF
path "honeycomb/role/+/gateway/1/queries*" {
  capabilities = ["create", "read"]
}

path "honeycomb/role/+/gateway/1/boards*" {
  capabilities = ["read"]
}

path "honeycomb/role/+/gateway/1/slos*" {
  capabilities = ["read"]
}

path "honeycomb/role/+/gateway/1/auth" {
  capabilities = ["read"]
}
EOF
```

Verify:

```bash
warden policy read honeycomb-access
```

## Step 5: Get a JWT and Make Requests

Get a JWT from your identity provider — see [Obtaining a JWT](/auth-methods/jwt/#obtaining-a-jwt) (the local dev setup issues one from Hydra). Export it as `$JWT_TOKEN`.

Requests use role-based paths. Warden performs implicit JWT authentication and injects the Honeycomb credential automatically.

The URL pattern is: `/v1/honeycomb/role/{role}/gateway/{api-path}`

Export the base endpoint:

```bash
export HC_ENDPOINT="${WARDEN_ADDR}/v1/honeycomb/role/honeycomb-user/gateway"
```

### Verify Authentication

```bash
curl -s "${HC_ENDPOINT}/1/auth" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### Send an Event

```bash
curl -s -X POST "${HC_ENDPOINT}/1/events/my-dataset" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"message": "hello from warden", "duration_ms": 42}'
```

### Send a Batch of Events

```bash
curl -s -X POST "${HC_ENDPOINT}/1/batch/my-dataset" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '[{"data": {"message": "event 1"}}, {"data": {"message": "event 2"}}]'
```

### Query Data

```bash
curl -s -X POST "${HC_ENDPOINT}/1/queries/my-dataset" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "calculations": [{"op": "COUNT"}],
    "time_range": 3600
  }'
```

### List Boards

```bash
curl -s "${HC_ENDPOINT}/1/boards" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### List SLOs

```bash
curl -s "${HC_ENDPOINT}/1/slos" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### List Markers

```bash
curl -s "${HC_ENDPOINT}/1/markers/my-dataset" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### List Triggers

```bash
curl -s "${HC_ENDPOINT}/1/triggers" \
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

## TLS Certificate Authentication

Steps 1-4 above use JWT authentication. Alternatively, you can authenticate with a TLS client certificate. This is useful for workloads that already have X.509 certificates — Kubernetes pods with cert-manager, VMs with machine certificates, or SPIFFE X.509-SVIDs from a service mesh.

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
    default_role=honeycomb-user
```

### Create a Cert Role

```bash
warden write auth/cert/role/honeycomb-user \
    allowed_common_names="agent-*" \
    token_policies="honeycomb-access" \
    cred_spec_name=honeycomb-ops
```

The `allowed_common_names` field supports glob patterns; you can also match on other certificate fields. See [Create a role](/auth-methods/cert/#step-3-create-a-role) for the full set of constraint fields.

### Configure Provider for Cert Auth

```bash
warden write honeycomb/config <<EOF
{
  "honeycomb_url": "https://api.honeycomb.io",
  "auto_auth_path": "auth/cert/",
  "timeout": "30s",
  "max_body_size": 10485760
}
EOF
```

### Make Requests with Certificates

```bash
curl --cert client.pem --key client-key.pem \
    --cacert warden-ca.pem \
    -s "https://warden.internal/v1/honeycomb/role/honeycomb-user/gateway/1/auth"
```

## Token Management

### Static API Key

| Aspect | Details |
|--------|---------|
| **Storage** | Key is stored on the credential spec |
| **Rotation** | Manual -- generate a new key in Honeycomb and update the spec |
| **Lifetime** | Does not expire unless deleted in Honeycomb |

### Dynamic API Keys (Honeycomb Source Driver)

| Aspect | Details |
|--------|---------|
| **Storage** | Key secret is captured at creation and managed by Warden |
| **Rotation** | Automatic -- Warden creates a new key and deletes the old one on the configured rotation period |
| **Lifetime** | Controlled by `key_ttl` in the spec config; keys are revoked (deleted) when the lease expires |
| **Revocation** | On lease expiry or manual revocation, Warden calls `DELETE /2/teams/{team}/api-keys/{id}` |

**To rotate static credentials:**

1. Generate a new API key in Honeycomb (Settings > Team Settings > API Keys)
2. Update the credential spec:
   ```bash
   warden cred spec update honeycomb-ops \
     -config api_key=your-new-api-key
   ```
3. Delete the old key in Honeycomb

**To rotate the management key (source driver):**

1. Create a new management key in Honeycomb
2. Update the credential source:
   ```bash
   warden cred source update honeycomb-src \
     -config management_key_id=new-key-id \
     -config management_key_secret=new-key-secret
   ```
3. Delete the old management key in Honeycomb
