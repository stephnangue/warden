---
title: "Azure"
description: "Proxy Azure APIs through Warden: federate the agent and the user it acts for into a short-lived Entra ID access token, injected per request."
---

The Azure provider proxies Azure API traffic through Warden. The agent presents its own
identity, Warden obtains a short-lived Microsoft Entra ID access token for the role it
asserted, injects it as a bearer, and forwards. The agent never holds a client secret.

## How a request flows

This mount can carry **two principals** — the agent, and the user it is acting for — and
both can be described to Entra ID in the same assertion.

The recommended setup stores **no Azure credentials at all**.

<p align="center"><img alt="An agent presents the user's ID token and its own identity to Warden, which builds an assertion carrying user claims and agent claims, has an external KMS sign it, presents it to Azure STS as a client assertion, and injects the returned access token as a bearer token to the Azure service API" src="/images/warden-prov-azure-oidc-fed.png" width="860"></p>

1. The user authenticates and the agent holds their ID token.
2. The agent calls Warden presenting **both** credentials and asserting a role. Warden
   authenticates each against its own auth mount.
3. The asserted role selects the credential spec. Warden builds the assertion that spec
   calls for — agent claims, plus the user's under a nested `warden_user` claim when the
   spec opts in — and sends it to an **external KMS** unsigned.
4. The KMS returns it signed. No signing key lives in Warden.
5. Warden presents it to **Entra ID** as a federated client assertion, in place of a
   client secret.
6. Entra ID verifies it against the trusted issuer and returns an access token.
7. Warden injects that token as `Authorization: Bearer <token>` and forwards.

Because the user's claims reach Entra ID inside the assertion, a federated-credential
policy can condition on them.

:::note[Steps 3–6 run only on a cache miss]
Warden caches the minted credential, so most requests skip from step 2 to step 7. The
entry is keyed by namespace, the agent's token id, the spec name **and the user's token
id**, so one user's access token is never served to another, and it lives for the shorter
of the token's own lifetime and the session.
:::

The KMS leg is optional, and **recommended in production**: with a
[`signer` stanza](/configuration/signer/) configured, Warden holds no key material at all.
Omit the stanza and the issuer signs with a locally held key instead. The exchange at
Entra ID is identical either way.

### When you must store a service principal

Where you cannot configure a federated credential on the app registration, Warden holds
the client secret in encrypted storage and rotates it through Microsoft Graph.

<p align="center"><img alt="Warden resolves the asserted role to a credential spec, reads that spec's service principal credentials from encrypted storage, exchanges them at Azure STS for an access token, and injects it as a bearer token to the Azure service API" src="/images/warden-prov-azure-static-sts.png" width="860"></p>

Steps 3 and 4 become a storage read instead of a signing call, and step 5 presents the
client secret rather than an assertion. The user is still authenticated at step 2 and
policy can still require them, but **the user no longer reaches Entra ID** — there is no
assertion to carry them.

## Credential modes

| Mode | Supported | How |
|---|---|---|
| **Keyless federation** ✅ *recommended* | Yes | `auth_method=oidc_federation`; the only mode that carries the user through to Entra ID |
| **Stored root → short-lived mint** | Yes | `auth_method=static`; a client secret in Warden storage, rotated via Microsoft Graph |
| **Static inline** | No | Every mode mints a fresh token |
| **Chaining** | No | An `azure` source takes no `secret_spec` |
| **Delegated user token** | No | The upstream receives a token minted for the app, not a forwarded user token |

See the [Azure credential driver](/credential-drivers/azure/) for every source and spec key.

## Prerequisites

- Docker and Docker Compose installed and running
- A Microsoft Entra ID **App Registration** (service principal) with a client secret

:::note[New to Warden?]
Follow [Local dev setup](/provider-backends/local-dev-setup/) to start a local dev environment (Ory Hydra + a Warden dev server) before Step 1.
:::

### Creating a Microsoft Entra ID App Registration

1. Go to **Azure Portal** > **Microsoft Entra ID** > **App registrations** > **New registration**.
2. Name the application (e.g., `warden-source`) and set the account type (typically "Single tenant").
3. Click **Register** and note the following values:
   - **Application (client) ID** — used as `client_id`
   - **Directory (tenant) ID** — used as `tenant_id`
4. Go to **Certificates & secrets** > **New client secret**, set a description and expiry, then copy the **Value** — used as `client_secret`.

### Azure Roles & Permissions

Assign Azure RBAC roles to your service principal depending on which Azure services you need to access:

| Azure Service | Required Role | Scope |
|---------------|---------------|-------|
| Azure Resource Manager | `Reader` / `Contributor` | Subscription or Resource Group |
| Azure Key Vault | `Key Vault Secrets User` | Key Vault resource |
| Azure Storage | `Storage Blob Data Reader` | Storage Account |

To assign a role:

```bash
az role assignment create \
  --assignee <client_id> \
  --role "Reader" \
  --scope "/subscriptions/<subscription_id>"
```

### Microsoft Graph API Permissions (Optional — Required for Rotation)

If you want Warden to automatically rotate service principal credentials, the source service principal needs Microsoft Graph API permissions:

1. Go to **App registrations** > your app > **API permissions** > **Add a permission**.
2. Select **Microsoft Graph** > **Application permissions**.
3. Add `Application.ReadWrite.OwnedBy` (sufficient for rotating the app's own credentials). Use `Application.ReadWrite.All` only if Warden manages credentials for other applications.
4. Click **Grant admin consent** for your tenant.

> **Note:** Without Graph API permissions, credential rotation will be unavailable but all other features (token minting, proxying, Key Vault secret fetching) will work normally.

### Network Access

Warden needs network access to the following Azure endpoints:
- `login.microsoftonline.com` (Microsoft Entra ID authentication)
- `management.azure.com` (Azure Resource Manager)
- `graph.microsoft.com` (Microsoft Graph, required for rotation)
- Any additional Azure service endpoints you plan to proxy

## Step 1: Configure JWT Auth and Create a Role

Enable the JWT auth method and point it at your identity provider's JWKS endpoint, then create a role that binds the credential spec and policy. Enabling the mount and configuring the key source is covered once in [JWT auth](/auth-methods/jwt/#step-1-configure-the-key-source) — for the local dev setup.

> **This step must come before configuring the provider.** Warden validates at configuration time that the auth backend referenced by `auto_auth_path` is already mounted.

```bash
warden auth enable jwt
warden write auth/jwt/config jwks_url=http://localhost:4444/.well-known/jwks.json

# Create a role that binds the credential spec and policy
warden write auth/jwt/role/azure-user \
    token_policies="azure-access" \
    user_claim=sub \
    cred_spec_name=azure-ops
```

## Step 2: Mount and Configure the Provider

Enable the Azure provider at a path of your choice:

```bash
warden provider enable azure
```

To mount at a custom path:

```bash
warden provider enable -path=azure-prod azure
```

Verify the provider is enabled:

```bash
warden provider list
```

Configure the provider with `auto_auth_path`. This allows clients to authenticate with their JWT directly — no explicit Warden login required:

```bash
warden write azure/config <<EOF
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
warden read azure/config
```

## Step 3: Create a Credential Source and Spec

Start with the keyless source — it stores nothing. Every source and spec key is documented
on the [Azure credential driver page](/credential-drivers/azure/).

### 3a. Keyless federation (recommended)

A federated source still names the app registration (`tenant_id`, `client_id`), because
that is the identity Entra ID is being asked to issue for. What it does **not** hold is the
secret: `client_secret` and `secret_id` are rejected outright, and there is no
`rotation_period` because there is nothing to rotate.

`audience` defaults to `api://AzureADTokenExchange`, which is what Entra ID expects for a
federated credential.

```bash
warden cred source create azure-src -json '{
  "type": "azure",
  "config": {
    "auth_method": "oidc_federation",
    "tenant_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "client_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "subscription_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "audience": "api://AzureADTokenExchange"
  }
}'
```

On the Azure side, add a **federated credential** to that app registration pointing at
Warden's issuer — see [Keyless credentials](/federation/keyless-credentials/).

A spec on a keyless source **must** set `subject_token_source`, and
`assertion_user_claims` is what carries the user into the assertion:

```bash
warden cred spec create azure-ops -json '{
  "source": "azure-src",
  "min_ttl": 600,
  "max_ttl": 3600,
  "config": {
    "mint_method": "bearer_token",
    "subject_token_source": "warden_identity",
    "tenant_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "client_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "resource_uri": "https://management.azure.com/",
    "assertion_user_claims": "sub,email"
  }
}'
```

Three things about a federated spec are easy to get wrong:

- **`client_id` is still required.** It names the **workload** service principal the token
  is minted for, which need not be the one on the source.
- **`tenant_id` is required too.** On a static spec it is optional and defaults to the
  source's; on a federated one it must be explicit.
- **`client_secret` and `secret_id` must be omitted** — there is no stored secret to name,
  and leaving one behind is rejected rather than ignored.

Only `bearer_token` works over federation. **`key_vault_secret` is rejected on a federated
spec** (*"not supported over federation"*) — fetching a Key Vault secret needs the static
path below.

`assertion_user_claims` is opt-in and **fails closed** on a claim the user's login does not
carry; omit it and the assertion describes the agent only.

### 3b. Stored service principal

The source holds the app registration's client secret. `secret_id` is what lets Warden
rotate it through Microsoft Graph, and `rotation_period` is integer seconds in JSON
(`2592000` = 30 days).

```bash
warden cred source create azure-static -json '{
  "type": "azure",
  "rotation_period": 2592000,
  "config": {
    "auth_method": "static",
    "tenant_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "client_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "client_secret": "<your-client-secret>",
    "secret_id": "<secret-id-for-rotation>",
    "subscription_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
  }
}'
```

`tenant_id`, `client_id`, `client_secret` and `secret_id` are all required together here,
and `audience` is rejected — it seeds only a federation assertion, so on a static source it
would be silently ignored. Warden authenticates against Entra ID before storing the source,
so this needs real credentials rather than the placeholders above.

Verify the source:

```bash
warden cred source read azure-static
```

A static spec names the workload service principal and its secret.

**`bearer_token`** — mints an Entra ID access token for `resource_uri`:

```bash
warden cred spec create azure-ops -json '{
  "source": "azure-static",
  "min_ttl": 600,
  "max_ttl": 3600,
  "config": {
    "mint_method": "bearer_token",
    "client_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "client_secret": "<workload-sp-client-secret>",
    "resource_uri": "https://management.azure.com/"
  }
}'
```

**`key_vault_secret`** — fetches a secret straight from Azure Key Vault. Its credential
type cannot be inferred from the mint method, so pass `type` explicitly:

```bash
warden cred spec create azure-kv -json '{
  "source": "azure-static",
  "type": "azure_bearer_token",
  "min_ttl": 600,
  "max_ttl": 3600,
  "config": {
    "mint_method": "key_vault_secret",
    "client_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "client_secret": "<workload-sp-client-secret>",
    "vault_name": "my-key-vault",
    "secret_name": "my-secret"
  }
}'
```

Verify:

```bash
warden cred spec read azure-ops
```

## Step 4: Create a Policy

Create a policy that grants access to the Azure provider gateway. Note that this policy is intentionally coarse-grained for simplicity, but it can be made much more fine-grained to restrict access to specific paths or capabilities as needed:

```bash
warden policy write azure-access - <<EOF
path "azure/role/+/gateway*" {
  capabilities = ["create", "read", "update", "delete", "patch"]
}
EOF
```

For tighter control, add runtime conditions to protect destructive operations on specific paths. For example, restrict resource group deletion to trusted networks during business hours while leaving read access unconditional:

```bash
warden policy write azure-prod-restricted - <<EOF
path "azure/role/+/gateway/management.azure.com/subscriptions/+/resourcegroups/*" {
  capabilities = ["delete"]
  condition = <<-CEL
    cidrContains("10.0.0.0/8", request.client_ip) &&
    now.getHours("UTC") >= 8 && now.getHours("UTC") < 18 &&
    now.getDayOfWeek("UTC") in [1, 2, 3, 4, 5]
  CEL
}

path "azure/role/+/gateway*" {
  capabilities = ["create", "read", "update", "patch"]
}
EOF
```

The `condition` is a [CEL](https://cel.dev) expression (see [CEL conditions](/concepts/cel-conditions/)): `cidrContains` restricts by network and `now.getHours`/`now.getDayOfWeek` by time of day and weekday. It must evaluate to `true` for the rule to apply, and fails closed.

Verify:

```bash
warden policy read azure-access
```

## Step 5: Get a JWT and Make Requests

Get a JWT from your identity provider — see [Obtaining a JWT](/auth-methods/jwt/#obtaining-a-jwt) (the local dev setup issues one from Hydra). Export it as `$JWT_TOKEN`.

Requests use role-based paths. Warden performs implicit JWT authentication and injects the Azure Bearer token automatically.

The URL pattern is: `/v1/azure/role/{role}/gateway/{azure-host}/{path}`

The first path segment after `gateway/` is the Azure API host, and the rest is the API path.

Export AZURE_ENDPOINT as environment variable:
```bash
export AZURE_ENDPOINT="${WARDEN_ADDR}/v1/azure/role/azure-user/gateway"
```

### List Azure Subscriptions

```bash
curl "${AZURE_ENDPOINT}/management.azure.com/subscriptions?api-version=2022-12-01" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### Get a Key Vault Secret

```bash
curl "${AZURE_ENDPOINT}/myvault.vault.azure.net/secrets/my-secret?api-version=7.6" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### List Storage Blobs

```bash
curl "${AZURE_ENDPOINT}/mystorage.blob.core.windows.net/mycontainer?restype=container&comp=list" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### Query Microsoft Graph

```bash
curl "${AZURE_ENDPOINT}/graph.microsoft.com/v1.0/users" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### List Resource Groups

```bash
curl "${AZURE_ENDPOINT}/management.azure.com/subscriptions/<subscription-id>/resourcegroups?api-version=2025-04-01" \
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

## Supported Azure Services

The provider proxies requests to any Azure service reachable over HTTPS. The target host is extracted from the gateway path. Common services include:

| Service | Hostname | Description |
|---------|----------|-------------|
| Azure Resource Manager | `management.azure.com` | Manage Azure resources (VMs, networks, etc.) |
| Microsoft Graph | `graph.microsoft.com` | Users, groups, applications, directory data |
| Azure Key Vault | `*.vault.azure.net` | Secrets, keys, and certificates |
| Azure Blob Storage | `*.blob.core.windows.net` | Object/blob storage |
| Azure Queue Storage | `*.queue.core.windows.net` | Message queuing |
| Azure Table Storage | `*.table.core.windows.net` | NoSQL key-value storage |
| Azure File Storage | `*.file.core.windows.net` | Managed file shares |
| Azure Data Lake Storage | `*.dfs.core.windows.net` | Big data analytics storage |

## Credential Rotation

Warden supports automatic rotation of Azure service principal credentials via the Microsoft Graph API. Rotation follows a three-phase process:

1. **Prepare** — A new `client_secret` is created on the service principal via `addPassword`
2. **Activate** — The new credentials are activated and the token cache is cleared
3. **Cleanup** — The old `client_secret` is removed via `removePassword`

### Requirements for Rotation

- The source service principal must have **`Application.ReadWrite.All`** permission on Microsoft Graph
- Admin consent must be granted for the permission

### Rotation Scope

| Rotation Type | Description |
|---------------|-------------|
| Source rotation | Rotates the source service principal's own credentials |
| Spec rotation | Rotates workload service principal credentials |

> **Note:** Microsoft Entra ID Bearer tokens are not directly revocable — they expire naturally (typically after 1 hour). Rotation applies to the underlying service principal secrets.

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
    default_role=azure-user
```

### Create a Cert Role

Create a role that binds allowed certificate identities to a credential spec and policy:

```bash
warden write auth/cert/role/azure-user \
    allowed_common_names="agent-*" \
    token_policies="azure-access" \
    cred_spec_name=azure-ops 
```

The `allowed_common_names` field supports glob patterns; you can also match on other certificate fields. See [Create a role](/auth-methods/cert/#step-3-create-a-role) for the full set of constraint fields.

### Configure Provider for Cert Auth

Update the provider config to use cert auth:

```bash
warden write azure/config <<EOF
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
    "https://warden.internal/v1/azure/role/azure-user/gateway/management.azure.com/subscriptions?api-version=2022-12-01"

# Default role (no role in URL)
curl --cert client.pem --key client-key.pem \
    --cacert warden-ca.pem \
    "https://warden.internal/v1/azure/gateway/management.azure.com/subscriptions?api-version=2022-12-01"
```

## Troubleshooting

### "credential not found" or "invalid credential type" errors

1. Verify the credential spec exists and is configured correctly
2. Ensure the credential type is `azure_bearer_token`
3. Check that the `client_id` and `client_secret` are valid

### Token acquisition failures

1. Verify the service principal credentials are not expired
2. Check that the `tenant_id` is correct (must be a valid UUID)
3. Ensure network connectivity to `login.microsoftonline.com`
4. Verify the `resource_uri` is correct for the target service:
   - Resource Manager: `https://management.azure.com/`
   - Key Vault: `https://vault.azure.net/`
   - Storage: `https://storage.azure.com/`
   - Graph: `https://graph.microsoft.com/`

### Key Vault secret retrieval failures

1. Ensure the service principal has the `Key Vault Secrets User` role on the vault
2. Verify the `vault_name` and `secret_name` are correct
3. Check that the Key Vault firewall allows access from the Warden server

### Rotation not available

1. Confirm the source SP has `Application.ReadWrite.All` permission
2. Verify admin consent has been granted
3. Check Warden logs for Graph API errors
