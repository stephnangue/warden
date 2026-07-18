---
title: "Vault"
---

The Vault provider enables proxied access to HashiCorp Vault (or OpenBao) through Warden. It intercepts client requests, injects a short-lived Vault token minted from a credential spec, and forwards the request to the target Vault instance. This allows Warden to broker Vault access without distributing long-lived credentials to clients.

## Prerequisites

- HashiCorp Vault running and unsealed
- Vault CLI (for initial AppRole setup)
- OpenSSL (for generating certificates)

:::note[New to Warden?]
Follow [Local dev setup](/provider-backends/local-dev-setup/) to start a local dev environment (Ory Hydra + a Warden dev server) before Step 1.
:::

## Step 1: Create an AppRole in Vault

Create a dedicated AppRole for Warden with policies that grant access to the secrets engines it needs.

### Create a Vault Policy

```bash
vault policy write warden-source - <<EOF
# KV v2 read access
path "secret/data/*" {
  capabilities = ["read"]
}

# Database credential generation
path "database/creds/*" {
  capabilities = ["read"]
}

# AWS credential generation
path "aws/creds/*" {
  capabilities = ["read", "create", "update"]
}

# Token creation via roles
path "auth/token/create/*" {
  capabilities = ["create", "update"]
}

# Lease revocation
path "sys/leases/revoke" {
  capabilities = ["update"]
}

# Token revocation via accessor
path "auth/token/revoke-accessor" {
  capabilities = ["update"]
}

path "auth/warden_approle/role/warden-source" {
  capabilities = ["read"]
}

# Self-manage secret_id for rotation
path "auth/warden_approle/role/warden-source/secret-id" {
  capabilities = ["create", "update"]
}
path "auth/warden_approle/role/warden-source/secret-id-accessor/destroy" {
  capabilities = ["update"]
}
EOF
```

### Enable AppRole and Create the Role

```bash
# Enable AppRole auth at a custom mount
vault auth enable -path=warden_approle approle

# Create the role
vault write auth/warden_approle/role/warden-source \
  token_policies="warden-source" \
  token_ttl=1h \
  token_max_ttl=4h \
  secret_id_num_uses=0 \
  secret_id_ttl=0
```

### Create Token Roles

Warden mints child Vault tokens via [token roles](https://developer.hashicorp.com/vault/docs/auth/token#token-roles). Create the roles referenced by the credential specs in Step 4:

```bash
# Read-only token role (used by the vault-reader cred spec)
vault write auth/token/roles/reader \
  allowed_policies="warden-source" \
  orphan=true \
  token_period=1h \
  renewable=true

# Elevated token role (used by the vault-admin cred spec)
vault write auth/token/roles/admin \
  allowed_policies="warden-source" \
  orphan=true \
  token_period=4h \
  renewable=true
```

### Generate Credentials

```bash
# Get the role_id (static, does not change)
vault read auth/warden_approle/role/warden-source/role-id

# Generate a secret_id (Warden will rotate this automatically)
vault write -f auth/warden_approle/role/warden-source/secret-id
```

Save the `role_id`, `secret_id`, and `secret_id_accessor` from the output.

## Step 2: Configure Cert Auth and Create a Role

Set up a TLS certificate auth method and create a role that binds the credential spec and policy. This uses the same CA that signed the client certificate generated in the Prerequisites.

> Warden validates at configuration time that the auth backend referenced by `auto_auth_path` is already mounted.

```bash
# Enable cert auth
warden auth enable cert

# Configure with the CA that signs client certificates
warden write auth/cert/config \
    trusted_ca_pem=@$CERT_DIR/ca.pem \
    default_role=vault-user

# Create a role that binds the credential spec and policy
warden write auth/cert/role/vault-user \
    allowed_common_names="agent-*" \
    token_policies="vault-access" \
    cred_spec_name=vault-reader
```

The `allowed_common_names` field supports glob patterns. The client certificate generated in the Prerequisites has CN `agent-quickstart`, which matches `agent-*`. You can also match on other certificate fields; see [Create a role](/auth-methods/cert/#step-3-create-a-role) for the full set of constraint fields.

## Step 3: Mount and Configure the Provider

Enable the Vault provider at a path of your choice:

```bash
warden provider enable vault
```

To mount at a custom path:

```bash
warden provider enable -path=vault-prod vault
```

Verify the provider is enabled:

```bash
warden provider list
```

Configure the provider with the Vault server address and the cert auth mount from Step 2:

```bash
warden write vault/config <<EOF
{
  "vault_address": "http://127.0.0.1:8200",
  "auto_auth_path": "auth/cert/",
  "timeout": "30s",
  "max_body_size": 10485760
}
EOF
```

See [Provider configuration](/provider-backends/configuration/) for the full list of common config fields (`proxy_domains`, `timeout`, `tls_skip_verify`, `ca_data`, and more).

Verify:

```bash
warden read vault/config
```

## Step 4: Create a Credential Source and Specs

The credential source tells Warden how to authenticate to Vault using the AppRole created in Step 1.

```bash
warden cred source create vault-prod \
  -type hvault \
  -rotation-period 24h \
  -config vault_address=http://127.0.0.1:8200 \
  -config auth_method=approle \
  -config role_id=<role-id> \
  -config secret_id=<secret-id> \
  -config secret_id_accessor=<accessor> \
  -config approle_mount=warden_approle \
  -config role_name=warden-source
```

For Vault Enterprise/HCP Vault with namespaces or OpenBao, add `vault_namespace` to scope all Warden API calls (AppRole auth, credential minting) to that namespace:

```bash
warden cred source create vault-prod \
  -type hvault \
  -rotation-period 24h \
  -config vault_address=https://vault.example.com:8200 \
  -config auth_method=approle \
  -config role_id=<role-id> \
  -config secret_id=<secret-id> \
  -config secret_id_accessor=<accessor> \
  -config approle_mount=warden_approle \
  -config role_name=warden-source \
  -config vault_namespace=admin/team-a
```

The `-rotation-period` controls how often Warden rotates the AppRole `secret_id`. During rotation, Warden generates a new `secret_id`, verifies it works, persists the new config, then destroys the old one. Both credentials remain valid during the transition — there is no downtime.

Set to `0` to disable rotation (not recommended for production).

Verify:

```bash
warden cred source read vault-prod
```

The Vault provider gateway requires a credential spec of type `vault_token`. Warden mints child Vault tokens via token roles and injects them into proxied requests.

```bash
# Read-only Vault token
warden cred spec create vault-reader \
  -source vault-prod \
  -config mint_method=vault_token \
  -config token_role=reader \
  -min-ttl 600s \
  -max-ttl 2h

# Admin Vault token with custom TTL
warden cred spec create vault-admin \
  -source vault-prod \
  -config mint_method=vault_token \
  -config token_role=admin \
  -config ttl=4h \
  -min-ttl 1h \
  -max-ttl 8h
```

## Step 5: Create a Policy

Create a policy that grants access to the Vault provider gateway. Note that this policy is intentionally coarse-grained for simplicity, but it can be made much more fine-grained to restrict access to specific paths or capabilities as needed:

```bash
warden policy write vault-access - <<EOF
path "vault/gateway*" {
  capabilities = ["read", "create", "update", "delete", "patch"]
}
EOF
```

For use cases where the role will be provided in the path, also grant access to role-based paths:

```bash
warden policy write vault-access - <<EOF
path "vault/gateway*" {
  capabilities = ["read", "create", "update", "delete", "patch"]
}
path "vault/role/+/gateway*" {
  capabilities = ["read", "create", "update", "delete", "patch"]
}
EOF
```

For tighter control, add runtime conditions to protect sensitive Vault paths. For example, restrict secret deletion to trusted networks during business hours while leaving read access unconditional:

```bash
warden policy write vault-prod-restricted - <<EOF
path "vault/gateway/secret/data/*" {
  capabilities = ["delete"]
  condition = <<-CEL
    cidrContains("10.0.0.0/8", request.client_ip) &&
    now.getHours("UTC") >= 8 && now.getHours("UTC") < 18 &&
    now.getDayOfWeek("UTC") in [1, 2, 3, 4, 5]
  CEL
}

path "vault/gateway*" {
  capabilities = ["read", "create", "update", "patch"]
}
EOF
```

The `condition` is a [CEL](https://cel.dev) expression (see [CEL conditions](/concepts/cel-conditions/)): `cidrContains` restricts by network and `now.getHours`/`now.getDayOfWeek` by time of day and weekday. It must evaluate to `true` for the rule to apply, and fails closed.

Verify:

```bash
warden policy read vault-access
```

## Step 6: Make Requests with Client Certificates

No login step is required. The client certificate is presented during the TLS handshake and Warden performs implicit authentication on every call — no session token to manage.

The URL pattern includes the role name: `/v1/vault/role/{role}/gateway/{vault-api-path}`

### Using curl

```bash
VAULT_ENDPOINT="https://127.0.0.1:8400/v1/vault/role/vault-user/gateway"

# Read a secret
curl --cert $CERT_DIR/client.pem --key $CERT_DIR/client.key --cacert $CERT_DIR/ca.pem \
    "${VAULT_ENDPOINT}/secret/data/myapp"

# List secrets
curl --cert $CERT_DIR/client.pem --key $CERT_DIR/client.key --cacert $CERT_DIR/ca.pem \
    "${VAULT_ENDPOINT}/secret/metadata/?list=true"
```

### Using the Vault CLI

Set the gateway as the Vault address and configure the client certificate:

```bash
export VAULT_ADDR=https://127.0.0.1:8400/v1/vault/role/vault-user/gateway
export VAULT_CACERT=$PWD/$CERT_DIR/ca.pem
export VAULT_CLIENT_CERT=$PWD/$CERT_DIR/client.pem
export VAULT_CLIENT_KEY=$PWD/$CERT_DIR/client.key

# Read a KV secret
vault kv get secret/myapp

# List secrets
vault kv list secret/

# Issue a PKI certificate
vault write pki/issue/my-role common_name=example.com

# Read database credentials
vault read database/creds/my-role
```

Auth with certificates is the simplest and most secure approach — there is no bearer token to leak. It is ideal for workloads that already have X.509 identities: Kubernetes pods with cert-manager, VMs with machine certificates, or SPIFFE X.509-SVIDs from a service mesh.

---

Warden injects the real Vault token (minted from the credential spec) into each proxied request. The client never sees or handles the Vault token directly.

### Vault Namespaces

The gateway preserves `X-Vault-Namespace` headers from client requests. This allows clients to target specific Vault namespaces through the proxy:

```bash
# Read a secret in the admin/team-a namespace
vault kv get -namespace=admin/team-a secret/myapp

# Or set it as an environment variable
export VAULT_NAMESPACE=admin/team-a
vault kv get secret/myapp
```

Note that the `vault_namespace` on the **credential source** (Step 4) and the `X-Vault-Namespace` on **client requests** serve different purposes:
- **Source `vault_namespace`**: Scopes Warden's own Vault API calls (AppRole auth, credential minting)
- **Client `X-Vault-Namespace`**: Scopes the proxied request to a namespace in the target Vault instance

These can differ — for example, Warden may authenticate in the `admin` namespace while clients target `admin/team-a`.

### Path Rewriting

The gateway automatically prepends `/v1` to API paths when not already present:

```
/vault/gateway/secret/data/my-secret    → /v1/secret/data/my-secret
/vault/gateway/v1/secret/data/my-secret → /v1/secret/data/my-secret
/vault/gateway/sys/health               → /v1/sys/health
```

## Cleanup

To stop Warden:

```bash
# Stop Warden (Ctrl+C in the terminal where it's running)

# Remove generated certificates
rm -rf $CERT_DIR/
```

Since Warden dev mode uses in-memory storage, all configuration is lost when the server stops.

## Mint Methods

| Mint Method | Credential Type | Description |
|-------------|-----------------|-------------|
| `static_aws` | `aws_access_keys` | Fetch static AWS credentials from Vault KV v2 |
| `static_apikey` | `api_key` | Fetch static API keys from Vault KV v2 |
| `dynamic_aws` | `aws_access_keys` | Generate temporary AWS credentials via Vault AWS engine |
| `dynamic_gcp` | `gcp_access_token` | Generate GCP access tokens via Vault GCP engine |
| `vault_token` | `vault_token` | Create a child Vault token via token roles |
| `oauth2` | `oauth_bearer_token` | Fetch OAuth2 tokens via Vault OAuth2 plugin (openbao-plugin-secrets-oauthapp) |

## JWT Authentication

Steps 2 and 6 above use TLS certificate authentication. Alternatively, you can authenticate with a JWT. This is useful for workloads that obtain tokens from an identity provider (OIDC/OAuth2) — CI/CD pipelines, cloud functions, or services with federated identity.

> **Prerequisite:** JWT authentication requires an identity provider that issues JWTs. The quickstart uses [Ory Hydra](https://www.ory.sh/hydra/) via Docker Compose:
> ```bash
> curl -fsSL -o docker-compose.quickstart.yml \
>   https://raw.githubusercontent.com/stephnangue/warden/main/deploy/docker-compose.quickstart.yml
> docker compose -f docker-compose.quickstart.yml up -d
> ```

Steps 1, 3-5 (provider setup) are identical. Replace Steps 2 and 6 with the following.

### Enable JWT Auth

Enable the JWT auth method and point it at your identity provider's JWKS endpoint, then create a role that binds the credential spec and policy. Enabling the mount and configuring the key source is covered once in [JWT auth](/auth-methods/jwt/#step-1-configure-the-key-source) — for the local dev setup:

```bash
warden auth enable jwt
warden write auth/jwt/config jwks_url=http://localhost:4444/.well-known/jwks.json

# Create a role that binds the credential spec and policy
warden write auth/jwt/role/vault-user \
    token_policies="vault-access" \
    user_claim=sub \
    cred_spec_name=vault-reader \
    token_ttl=1h
```

### JWT auth method

Configure the provider to use JWT auth:

```bash
warden write vault/config <<EOF
{
  "vault_address": "http://127.0.0.1:8200",
  "auto_auth_path": "auth/jwt/",
  "timeout": "30s"
}
EOF
```

Get a JWT from your identity provider — see [Obtaining a JWT](/auth-methods/jwt/#obtaining-a-jwt) (the local dev setup issues one from Hydra). Export it as `$JWT`.

```bash
VAULT_ENDPOINT="${WARDEN_ADDR}/v1/vault/role/vault-user/gateway"

# Read a secret
curl "${VAULT_ENDPOINT}/secret/data/myapp" \
  -H "Authorization: Bearer ${JWT}"

# List secrets
curl "${VAULT_ENDPOINT}/secret/metadata/?list=true" \
  -H "Authorization: Bearer ${JWT}"
```

Or set environment variables for the Vault CLI:

```bash
export VAULT_ADDR=${WARDEN_ADDR}/v1/vault/role/vault-user/gateway
export VAULT_TOKEN=$JWT

vault kv get secret/myapp
vault kv list secret/
```

### Cleanup (JWT)

To stop the identity provider containers:

```bash
docker compose -f docker-compose.quickstart.yml down -v
```

## Troubleshooting

### "Vault provider not configured" error

The `vault_address` has not been set. Configure the provider:

```bash
warden write vault/config vault_address=https://vault.example.com:8200
```

### "Unauthorized" on gateway requests

1. Verify the credential spec is correctly bound to the cert auth role.
2. Check that the Vault AppRole policy grants access to the paths being requested.
3. Ensure the client certificate CN matches the `allowed_common_names` pattern on the role.
4. Verify the client certificate is signed by the CA configured in `trusted_ca_pem`.

### Request returns 403

1. Verify `auto_auth_path` is set in the provider config.
2. Ensure the cert auth role exists and is bound to a `vault_token` credential spec.
3. Check the Warden policy grants access to `vault/role/+/gateway*`.

### TLS certificate errors

Verify the client certificate, server certificate, and CA are consistent:

```bash
# Verify server cert is signed by the CA
openssl verify -CAfile $CERT_DIR/ca.pem $CERT_DIR/server.pem

# Verify client cert is signed by the CA
openssl verify -CAfile $CERT_DIR/ca.pem $CERT_DIR/client.pem

# Test the TLS connection
openssl s_client -connect 127.0.0.1:8400 -CAfile $CERT_DIR/ca.pem \
    -cert $CERT_DIR/client.pem -key $CERT_DIR/client.key
```

For development with self-signed Vault certificates:

```bash
warden write vault/config vault_address=https://vault.local:8200 tls_skip_verify=true
```

Do not use `tls_skip_verify` in production. Instead, ensure the Vault TLS certificate is signed by a trusted CA.

### Debug Logging

Enable trace-level logging to see request proxying details:

```hcl
log_level = "trace"
```
