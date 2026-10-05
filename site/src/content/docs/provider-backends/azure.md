---
title: "Azure"
description: "Proxy Azure APIs through Warden: federate the agent into a short-lived Entra ID access token, injected per request — no client secret stored."
---

The Azure provider proxies Azure API traffic through Warden. The agent presents its own
identity, Warden obtains a short-lived Microsoft Entra ID access token for the role it
asserted, injects it as a bearer, and forwards. The agent never holds a client secret.

## How a request flows

The recommended setup stores **no Azure credentials at all**. The mount can carry **two
principals** — the agent, and the user it is acting for — but only the agent is described
to Entra ID.

<p align="center"><img alt="An agent presents its identity to Warden, which builds an assertion, has an external KMS sign it, presents it to Azure STS as a client assertion, and injects the returned access token as a bearer token to the Azure service API" src="/images/warden-prov-azure-oidc-fed.png" width="860"></p>

1. The user authenticates and the agent holds their ID token.
2. The agent calls Warden presenting **both** credentials and asserting a role. Warden
   authenticates each against its own auth mount.
3. The asserted role selects the credential spec. Warden builds the assertion that spec
   calls for — under the `minimal` profile new Azure specs use, the registered claims
   only, naming the agent — and sends it to an **external KMS** unsigned.
4. The KMS returns it signed. No signing key lives in Warden.
5. Warden presents it to **Entra ID** as a federated client assertion, in place of a
   client secret.
6. Entra ID verifies it against the trusted issuer and returns an access token.
7. Warden injects that token as `Authorization: Bearer <token>` and forwards.

An Entra ID federated identity credential matches the assertion's issuer, subject and
audience **exactly** and reads no other claim. So the assertion carries the agent's
composite subject and nothing Entra cannot use, and the user — though authenticated at
step 2, and available to [policy](/concepts/cel-conditions/#agent-acting-for-a-user) — is
never disclosed to Entra ID. See
[Assertion claims](/federation/assertion-claims/#when-a-user-is-disclosed).

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
policy can still require them.

## Credential modes

| Mode | Supported | How |
|---|---|---|
| **Keyless federation** ✅ *recommended* | Yes | `auth_method=oidc_federation`. **Nothing stored.** |
| **Stored root → short-lived mint** | Yes | `auth_method=static`; a client secret in Warden storage, rotated via Microsoft Graph |
| **Static inline** | No | Every mode mints a fresh token |
| **Chaining** | Not as a consumer | An `azure` source takes no `secret_spec`. It is a chaining **producer**: `mint_method=secret_read` serves a Key Vault secret to other specs |
| **Delegated user token** | No | The upstream receives a token minted for the app, not a forwarded user token |

See the [Azure credential driver](/credential-drivers/azure/) for every source and spec key.

## Prerequisites

- Docker and Docker Compose installed and running
- A Microsoft Entra ID **App Registration** (service principal). Keyless, it needs a
  federated credential trusting Warden's issuer and no client secret; with a stored
  secret, it needs a client secret

:::note[New to Warden?]
Follow [Local dev setup](/provider-backends/local-dev-setup/) to start a local dev environment (Ory Hydra + a Warden dev server) before Step 1.
:::

### Creating a Microsoft Entra ID App Registration

1. Go to **Azure Portal** > **Microsoft Entra ID** > **App registrations** > **New registration**.
2. Name the application (e.g., `warden-source`) and set the account type (typically "Single tenant").
3. Click **Register** and note the following values:
   - **Application (client) ID** — used as `client_id`
   - **Directory (tenant) ID** — used as `tenant_id`
4. Keyless: go to **Certificates & secrets** > **Federated credentials** and add one for
   Warden's issuer (see [3a](#3a-keyless-federation-recommended)). With a stored secret
   instead: **Certificates & secrets** > **New client secret**, set a description and
   expiry, then copy the **Value** — used as `client_secret`.

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

> **Note:** Graph permissions matter only with a stored secret. Without them, credential rotation will be unavailable but all other features (token minting, proxying, Key Vault secret fetching) will work normally.

### Network Access

Warden needs network access to the following Azure endpoints:
- `login.microsoftonline.com` (Microsoft Entra ID authentication)
- `management.azure.com` (Azure Resource Manager)
- `graph.microsoft.com` (Microsoft Graph, required for rotation)
- Any additional Azure service endpoints you plan to proxy

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

Configure the provider with `auto_auth_path`. This allows clients to authenticate with their JWT directly — no explicit Warden login required. `auto_auth_path` must be in the same write as the settings it goes with: a write that leaves the mount without one is refused, and a refused write changes nothing.

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

A federated source holds **no secret**: `client_secret` and `secret_id` are rejected
outright, and there is no `rotation_period` because there is nothing to rotate. The app
registration it acts as is named on each spec.

`audience` defaults to `api://AzureADTokenExchange`, which is what Entra ID expects for a
federated credential.

```bash
warden cred source create azure-src -json '{
  "type": "azure",
  "config": {
    "auth_method": "oidc_federation",
    "audience": "api://AzureADTokenExchange"
  }
}'
```

A spec on a keyless source **must** set `subject_token_source`:

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
    "resource_uri": "https://management.azure.com/"
  }
}'
```

The spec is stored with
[`assertion_profile=minimal`](/federation/assertion-claims/#the-minimal-profile): the
assertion carries the registered claims only, and its `sub` is the agent's composite
`wid:<namespaceID>:<mountAccessor>:<principalID>`. On the Azure side, add a
**federated credential** to the spec's app registration with Warden's issuer URL, that
exact subject, and the audience — see [Keyless credentials](/federation/keyless-credentials/).
Read the subject from the audit log, or from the `subject` recorded on the credential.

Three things about a federated spec are easy to get wrong:

- **`client_id` is still required.** It names the **workload** app registration the token
  is minted for, and must be a UUID.
- **`tenant_id` is required too.** On a static spec it is optional and defaults to the
  source's; on a federated one it must be explicit.
- **`client_secret` and `secret_id` must be omitted** — there is no stored secret to name,
  and leaving one behind is rejected rather than ignored.

Both mint methods work over federation. **`secret_read`** reads a Key Vault secret as the
app registration the spec names — for an agent, or as the producer at the far end of a
[credential chain](/federation/credential-chaining/):

```bash
warden cred spec create azure-kv -json '{
  "source": "azure-src",
  "config": {
    "mint_method": "secret_read",
    "subject_token_source": "warden_identity",
    "tenant_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "client_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "vault_name": "my-key-vault",
    "secret_name": "my-secret"
  }
}'
```

:::caution[`key_vault_secret` is removed]
`mint_method=key_vault_secret` fails every mint, and a write naming it is refused. Move
such specs to `secret_read` (type `key_value`, inferred). Writes also refuse
`azure_db_iam_token`, the retired `scopes` key (use `resource_uri`), and a `client_id` or
`tenant_id` that is not a UUID. See
[Upgrading from v0.20.0](/upgrade/from-v0-20/#6-azure-key_vault_secret-specs-fail-every-mint).
:::

### 3b. Stored service principal

With a stored secret, the source holds the app registration's client secret. `secret_id`
is what lets Warden rotate it through Microsoft Graph, and `rotation_period` is integer
seconds in JSON (`2592000` = 30 days).

```bash
warden cred source create azure-static -json '{
  "type": "azure",
  "rotation_period": 2592000,
  "config": {
    "auth_method": "static",
    "tenant_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "client_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "client_secret": "<your-client-secret>",
    "secret_id": "<secret-id-for-rotation>"
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

**`bearer_token`** — a static spec names the workload service principal, its secret, and
the secret's id:

```bash
warden cred spec create azure-ops -json '{
  "source": "azure-static",
  "min_ttl": 600,
  "max_ttl": 3600,
  "config": {
    "mint_method": "bearer_token",
    "client_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "client_secret": "<workload-sp-client-secret>",
    "secret_id": "<workload-secret-id>",
    "resource_uri": "https://management.azure.com/"
  }
}'
```

**`secret_read`** — on a static source, the source's own service principal reads the
secret, so the spec names no app registration:

```bash
warden cred spec create azure-kv -json '{
  "source": "azure-static",
  "config": {
    "mint_method": "secret_read",
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
2. Ensure the credential type is `azure_bearer_token` for a token, or `key_value` for a
   `secret_read`
3. Keyless: check that the federated credential's subject matches the agent's composite
   subject exactly. With a stored secret: check that the `client_id` and `client_secret`
   are valid

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

1. Ensure the reading principal — the spec's app registration when federated, the
   source's service principal otherwise — has the `Key Vault Secrets User` role on the vault
2. Verify the `vault_name` and `secret_name` are correct
3. Check that the Key Vault firewall allows access from the Warden server
4. A disabled secret, one not yet valid or past its expiry, or one over 25 KB is refused

### Rotation not available

1. Confirm the source SP has `Application.ReadWrite.All` permission
2. Verify admin consent has been granted
3. Check Warden logs for Graph API errors
