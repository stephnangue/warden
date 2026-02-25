# Azure Provider

The Azure provider enables proxied access to Azure APIs through Warden. It manages Azure AD credentials, supports Bearer token minting and Key Vault secret fetching, and handles automated credential rotation via the Microsoft Graph API.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Step 1: Mount the Azure Provider](#step-1-mount-the-azure-provider)
- [Step 2: Configure the Provider](#step-2-configure-the-provider)
- [Step 3: Create a Credential Source](#step-3-create-a-credential-source)
- [Step 4: Create a Credential Spec](#step-4-create-a-credential-spec)
- [Step 5: Create a Policy](#step-5-create-a-policy)
- [Step 6: Configure JWT Auth and Create a Role](#step-6-configure-jwt-auth-and-create-a-role)
- [Step 7: Get a JWT](#step-7-get-a-jwt)
- [Step 8: Make Requests Through the Gateway](#step-8-make-requests-through-the-gateway)
- [Supported Azure Services](#supported-azure-services)
- [Credential Rotation](#credential-rotation)
- [Configuration Reference](#configuration-reference)
- [Troubleshooting](#troubleshooting)

## Prerequisites

- Docker and Docker Compose installed and running
- An Azure AD **App Registration** (service principal) with a client secret

> **New to Warden?** Follow these steps to get a local dev environment running:
>
> **1. Deploy the quickstart stack** — this starts an identity provider ([Ory Hydra](https://www.ory.sh/hydra/)) needed to issue JWTs for authentication in Steps 6–7:
> ```bash
> curl -fsSL -o docker-compose.quickstart.yml \
>   https://raw.githubusercontent.com/stephnangue/warden/main/docker-compose.quickstart.yml
> docker compose -f docker-compose.quickstart.yml up -d
> ```
>
> **2. Download the latest Warden binary:**
> ```bash
> # macOS (Apple Silicon)
> curl -L https://github.com/stephnangue/warden/releases/latest/download/warden_$(curl -s https://api.github.com/repos/stephnangue/warden/releases/latest | grep tag_name | cut -d '"' -f4 | tr -d v)_darwin_arm64.tar.gz | tar xz
>
> # macOS (Intel)
> curl -L https://github.com/stephnangue/warden/releases/latest/download/warden_$(curl -s https://api.github.com/repos/stephnangue/warden/releases/latest | grep tag_name | cut -d '"' -f4 | tr -d v)_darwin_amd64.tar.gz | tar xz
>
> # Linux (x86_64)
> curl -L https://github.com/stephnangue/warden/releases/latest/download/warden_$(curl -s https://api.github.com/repos/stephnangue/warden/releases/latest | grep tag_name | cut -d '"' -f4 | tr -d v)_linux_amd64.tar.gz | tar xz
>
> # Linux (ARM64)
> curl -L https://github.com/stephnangue/warden/releases/latest/download/warden_$(curl -s https://api.github.com/repos/stephnangue/warden/releases/latest | grep tag_name | cut -d '"' -f4 | tr -d v)_linux_arm64.tar.gz | tar xz
> ```
>
> **3. Start the Warden server** in dev mode:
> ```bash
> ./warden server --dev
> ```
>
> **4. In another terminal window**, export the environment variables for the CLI:
> ```bash
> export WARDEN_ADDR="http://127.0.0.1:8400"
> export WARDEN_TOKEN="<your-token>"
> ```

### Creating an Azure AD App Registration

1. Go to **Azure Portal** > **Azure Active Directory** > **App registrations** > **New registration**.
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
3. Add `Application.ReadWrite.All`.
4. Click **Grant admin consent** for your tenant.

> **Note:** Without Graph API permissions, credential rotation will be unavailable but all other features (token minting, proxying, Key Vault secret fetching) will work normally.

### Network Access

Warden needs network access to the following Azure endpoints:
- `login.microsoftonline.com` (Azure AD authentication)
- `management.azure.com` (Azure Resource Manager)
- `graph.microsoft.com` (Microsoft Graph, required for rotation)
- Any additional Azure service endpoints you plan to proxy

## Step 1: Mount the Azure Provider

Enable the Azure provider at a path of your choice:

```bash
warden provider enable --type=azure
```

To mount at a custom path:

```bash
warden provider enable --type=azure azure-prod
```

Verify the provider is enabled:

```bash
warden provider list
```

## Step 2: Configure the Provider

Configure the provider with transparent mode enabled. This allows clients to authenticate with their JWT directly — no explicit Warden login required:

```bash
warden write azure/config <<EOF
{
  "transparent_mode": true,
  "auto_auth_path": "auth/jwt/",
  "timeout": "30s",
  "max_body_size": 10485760
}
EOF
```

Verify the configuration:

```bash
warden read azure/config
```

## Step 3: Create a Credential Source

The credential source holds the Azure AD service principal credentials used to authenticate with Azure.

```bash
warden cred source create azure-src \
  --type=azure \
  --rotation-period=720h \
  --config=tenant_id=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx \
  --config=client_id=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx \
  --config=client_secret=your-client-secret \
  --config=subscription_id=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

Verify the source was created:

```bash
warden cred source read azure-src
```

## Step 4: Create a Credential Spec

Create a credential spec that references the credential source. The spec defines how Warden mints Azure credentials and gets associated with tokens at login time.

### Option A: Bearer Token (Recommended)

Mints an Azure AD Bearer token using the client credentials flow:

```bash
warden cred spec create azure-ops \
  --type azure_bearer_token \
  --source azure-src \
  --config auth_method=bearer_token \
  --config client_id=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx \
  --config client_secret=workload-sp-client-secret \
  --config resource_uri=https://management.azure.com/
```

### Option B: Key Vault Secret

Fetches a secret directly from Azure Key Vault:

```bash
warden cred spec create azure-kv \
  --type azure_bearer_token \
  --source azure-src \
  --config auth_method=key_vault_secret \
  --config client_id=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx \
  --config client_secret=workload-sp-client-secret \
  --config vault_name=my-key-vault \
  --config secret_name=my-secret
```

Verify:

```bash
warden cred spec read azure-ops
```

## Step 5: Create a Policy

Create a policy that grants access to the Azure provider gateway. Note that this policy is intentionally coarse-grained for simplicity, but it can be made much more fine-grained to restrict access to specific paths or capabilities as needed:

```bash
warden policy write azure-access - <<EOF
path "azure/role/+/gateway*" {
  capabilities = ["create", "read", "update", "delete", "patch"]
}
EOF
```

Verify:

```bash
warden policy read azure-access
```

## Step 6: Configure JWT Auth and Create a Role

Set up a JWT auth method and create a role that binds the credential spec and policy. With transparent mode, clients authenticate directly with their JWT — no separate login step is needed.

```bash
# Enable JWT auth if not already enabled
warden auth enable --type=jwt

# Configure JWT with Hydra's JWKS endpoint (from docker-compose.quickstart.yml)
warden write auth/jwt/config mode=jwt jwks_url=http://localhost:4444/.well-known/jwks.json

# Create a role that binds the credential spec and policy
warden write auth/jwt/role/azure-user \
    token_type=jwt_role \
    token_policies="azure-access" \
    user_claim=sub \
    cred_spec_name=azure-ops \
    token_ttl=1h
```

## Step 7: Get a JWT

Get a JWT from Hydra using one of the quickstart clients:

```bash
export JWT_TOKEN=$(curl -s -X POST http://localhost:4444/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=my-agent&client_secret=agent-secret&scope=api:read api:write" \
  | jq -r '.access_token')
```

## Step 8: Make Requests Through the Gateway

With transparent mode, requests use role-based paths. Warden performs implicit JWT authentication and injects the Azure Bearer token automatically.

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
curl "${AZURE_ENDPOINT}/myvault.vault.azure.net/secrets/my-secret?api-version=7.4" \
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
curl "${AZURE_ENDPOINT}/management.azure.com/subscriptions/<subscription-id>/resourcegroups?api-version=2021-04-01" \
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

> **Note:** Azure AD Bearer tokens are not directly revocable — they expire naturally (typically after 1 hour). Rotation applies to the underlying service principal secrets.

## Configuration Reference

### Provider Config

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_body_size` | int | 10485760 (10 MB) | Maximum request body size in bytes (max 100 MB) |
| `timeout` | duration | `30s` | Request timeout (e.g., `30s`, `5m`) |
| `transparent_mode` | bool | `false` | Enable implicit JWT authentication |
| `auto_auth_path` | string | — | JWT auth mount path (required when `transparent_mode` is true) |
| `default_role` | string | — | Fallback role when not specified in URL |

### Credential Source Config

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `tenant_id` | string | Yes | Azure AD Tenant ID (UUID format) |
| `client_id` | string | Yes | Service Principal Application (Client) ID |
| `client_secret` | string | Yes | Service Principal client secret |
| `subscription_id` | string | No | Azure Subscription ID |

### Credential Spec Config (Bearer Token)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mint_method` | string | No | Must be `bearer_token` (default) |
| `client_id` | string | Yes | Workload SP Application ID |
| `client_secret` | string | Yes | Workload SP client secret |
| `tenant_id` | string | No | Override tenant ID (defaults to source tenant) |
| `resource_uri` | string | No | Token scope (default: `https://management.azure.com/`) |

### Credential Spec Config (Key Vault Secret)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mint_method` | string | Yes | Must be `key_vault_secret` |
| `client_id` | string | Yes | SP with access to the Key Vault |
| `client_secret` | string | Yes | SP client secret |
| `vault_name` | string | Yes | Name of the Azure Key Vault |
| `secret_name` | string | Yes | Name of the secret to retrieve |
| `secret_version` | string | No | Specific version (defaults to latest) |
| `tenant_id` | string | No | Override tenant ID |

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
