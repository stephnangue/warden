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
step 2, and available to [policy](/identity/cel-conditions/#agent-acting-for-a-user) — is
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
| **Certificate** | Yes | `auth_method=certificate`; a certificate registered on the app, its key stored in Warden or held in a KMS. Not rotated |
| **Stored root → short-lived mint** | Yes | `auth_method=static`; a client secret in Warden storage, rotated via Microsoft Graph |
| **Static inline** | No | Every mode mints a fresh token |
| **Chaining** | Producer; consumer for a certificate key | `mint_method=secret_read` serves a Key Vault secret to other specs. A `certificate` source's `secret_spec` names only a `transit_signer` that signs with its KMS-held key |
| **Delegated user token** | By exchange | `mint_method=on_behalf_of` exchanges the user's Entra token for a token delegated by that user; the user's token itself is never forwarded. For Microsoft Graph, use the [Microsoft Graph provider](/provider-backends/msgraph/) |

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

## Step 1: Configure JWT Auth

Enable the JWT auth method and point it at your identity provider's JWKS endpoint. Enabling the mount and configuring the key source is covered once in [JWT auth](/auth-methods/jwt/#step-1-configure-the-key-source) — for the local dev setup:

> **Set this up before configuring the provider.** The provider resolves
> `auto_auth_path` per request — writing the config only checks that it is
> non-empty, not that the mount exists — so a gateway call fails with `no auth
> mount registered ... for implicit auth` if the referenced auth mount isn't
> there yet.

```bash
warden auth enable jwt
warden write auth/jwt/config '{
  "jwks_url": "http://localhost:4444/.well-known/jwks.json",
  "bound_issuer": "http://localhost:4444",
  "bound_audiences": ["warden"]
}'
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

### Allowed hosts

The first path segment after `gateway/` names the Azure host the request goes to, and the
request leaves carrying an Entra token. So Warden checks the host before it reads any
credential:

- it must be a plain lowercase hostname, with no IP address, port, userinfo or path
  characters, or the answer is `400`;
- it must match the mount's `allowed_host_suffixes`, or the answer is `403`.

The default allows the public cloud's Microsoft-run endpoints:

| Entry | Service |
|---|---|
| `.management.azure.com` | Resource Manager |
| `.graph.microsoft.com` | Microsoft Graph |
| `.vault.azure.net` | Key Vault |
| `.blob.core.windows.net`, `.queue.core.windows.net`, `.table.core.windows.net`, `.file.core.windows.net`, `.dfs.core.windows.net` | Storage |
| `.openai.azure.com` | Azure OpenAI |
| `.cognitiveservices.azure.com` | Azure AI services |
| `.services.ai.azure.com` | Azure AI Foundry |

Each entry is named where the service starts, not by a broad suffix: `azure.com` and
`core.windows.net` also hold hosts customers control, such as a VM's
`<label>.<region>.cloudapp.azure.com` and static websites under `web.core.windows.net`.

Sovereign clouds, Azure Monitor, Azure DevOps and custom domains are not in the default.
To reach them, list every host the mount needs, the defaults you keep included:

```bash
warden write azure/config '{
  "auto_auth_path": "auth/jwt/",
  "allowed_host_suffixes": [
    ".management.azure.com",
    ".vault.azure.net",
    ".monitor.azure.com",
    ".dev.azure.com"
  ]
}'
```

An entry `.example.com` allows `example.com` and every host under it. An entry without
the leading dot is refused, and so are `*` and a bare top-level domain. An empty list
restores the default, and a mount that never set one follows the default as it changes.

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
Entra matches the subject exactly, with no wildcard, so each agent needs its own federated
credential, and an app holds at most 20. To build an agent's subject, read
`auth.namespace_id`, `auth.mount_accessor` and `auth.principal_id` from the audit entry of
one of its requests; in the root namespace, the namespace ID is `root`. The `subject` in a
`bearer_token` credential's metadata is the app's client ID, not the agent.

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

### 3c. Certificate

Where the tenant blocks client secrets and Entra cannot reach Warden's issuer, the source
can authenticate with a certificate registered on the app, its key stored in Warden or
held in a KMS. Certificates are not rotated. See
[Certificate authentication](/credential-drivers/azure/#certificate-authentication).

## Step 4: Create a Role and Grant It

A [role](/identity/roles/) binds the credential spec and policy, and `provider_path` names the provider mount it is used with. Create it after the provider has its `auto_auth_path`; until then, agents cannot find the role through discovery. The policy comes in the next step, so the write warns that it does not exist yet:

```bash
warden role create azure-user -json '{
  "policies": ["azure-access"],
  "cred_spec_name": "azure-ops",
  "provider_path": "azure/"
}'
```

Nobody holds the role yet. A virtual [group](/identity/groups/) grants it to the callers the JWT mount admits:

```bash
warden identity group create azure-user-agents -json '{
  "type": "virtual",
  "roles": ["azure-user"],
  "rules": [
    { "mount": ["auth/jwt/"] }
  ]
}'
```

:::caution[In production, register the agent]
The group above grants the role to every agent the mount admits: fine for trying the provider, not for production. In production, register each agent: create an [entity](/identity/entities/) for it, have its team [sponsor](/identity/sponsors/) it, and grant the role through a [static group](/identity/groups/) that lists the entity. Mark the role `governed_only` so no virtual group can grant it. Claim the agent's native identity last ([Rolling out](/identity/entities/#rolling-out)); [Governing an agent](/tutorials/identity/govern-an-agent/) walks through it.
:::

This rule matches every token the mount accepts. Add selectors on the token's facts, such as `sub`, to grant the role to fewer callers.

## Step 5: Create a Policy

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

The `condition` is a [CEL](https://cel.dev) expression (see [CEL conditions](/identity/cel-conditions/)): `cidrContains` restricts by network and `now.getHours`/`now.getDayOfWeek` by time of day and weekday. It must evaluate to `true` for the rule to apply, and fails closed.

Verify:

```bash
warden policy read azure-access
```

## Step 6: Get a JWT and Make Requests

Get a JWT from your identity provider — see [Obtaining a JWT](/auth-methods/jwt/#obtaining-a-jwt), with `audience=warden` (the local dev setup issues one from Hydra). Export it as `$JWT_TOKEN`.

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

Graph JSON batching (`$batch`) is refused with `400` on a Graph host of any cloud, before
a token is attached. A batch body carries up to twenty requests, each with its own method
and path, which a path policy never sees. Send the requests one by one. Resource
Manager's own `/batch` is not affected. To call Graph as the signed-in user, with paging
links and errors in Graph's shape, use the
[Microsoft Graph provider](/provider-backends/msgraph/).

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

The provider proxies requests over HTTPS to any Azure host in the mount's [`allowed_host_suffixes`](#allowed-hosts). The target host is extracted from the gateway path. The default allows these, among others:

| Service | Hostname | Description |
|---------|----------|-------------|
| Azure Resource Manager | `management.azure.com` | Manage Azure resources (VMs, networks, etc.) |
| Microsoft Graph | `graph.microsoft.com` | Users, groups and applications. `$batch` is refused |
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

The steps above use JWT authentication. Alternatively, you can authenticate with a TLS client certificate. This is useful for workloads that already have X.509 certificates — Kubernetes pods with cert-manager, VMs with machine certificates, or SPIFFE X.509-SVIDs from a service mesh.

:::note[Prerequisite]
Certificate auth requires mTLS on the Warden listener so the client certificate can be presented during the handshake. See [Enabling mTLS on the listener](/auth-methods/cert/#enabling-mtls-on-the-listener).
:::

The role, credential spec and policy are identical. Replace the JWT mount (Step 1), its group (Step 4) and the requests (Step 6) with the following.

### Enable Cert Auth

```bash
warden auth enable cert
```

### Configure Trusted CA

Provide the PEM-encoded CA certificate that signs your client certificates:

```bash
warden write auth/cert/config trusted_ca_pem=@/path/to/ca.pem
```

### Grant the Role to Certificates

A virtual group grants `azure-user` to the certificates the mount admits whose common name matches:

```bash
warden identity group create azure-user-agents -json '{
  "type": "virtual",
  "roles": ["azure-user"],
  "rules": [
    { "mount": ["auth/cert/"], "cn": ["agent-*"] }
  ]
}'
```

The `cn` selector supports glob patterns; you can also match on other certificate fields. See [Grant the role with a group](/auth-methods/cert/#step-4-grant-the-role-with-a-group) for the full set of fields.

### Configure Provider for Cert Auth

Update the provider config to use cert auth. `default_role` names the role a request takes when its URL names none:

```bash
warden write azure/config <<EOF
{
  "auto_auth_path": "auth/cert/",
  "default_role": "azure-user",
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

### `403` "target host ... is not allowed on this mount"

The host after `gateway/` is not in the mount's `allowed_host_suffixes`. Add it, with the
defaults you still need — see [Allowed hosts](#allowed-hosts). A `400` instead means the
host is not a plain hostname: an IP address, a port or an encoded character.

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
