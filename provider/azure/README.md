# Azure Provider for Warden

The Azure provider enables secure proxying of Azure API requests with automatic Bearer token injection. It acts as a gateway between your applications and Azure services, managing Azure AD credentials and injecting authentication tokens into outgoing requests.

## Prerequisites

### 1. Azure AD App Registration (Service Principal)

You need at least one Azure AD App Registration to serve as the **source credential** (the identity Warden uses to acquire tokens).

1. Go to **Azure Portal** > **Azure Active Directory** > **App registrations** > **New registration**
2. Name the application (e.g., `warden-source`)
3. Set the supported account type (typically "Single tenant")
4. Click **Register**
5. Note down the following values:
   - **Application (client) ID** — used as `client_id`
   - **Directory (tenant) ID** — used as `tenant_id`

6. Create a client secret:
   - Go to **Certificates & secrets** > **New client secret**
   - Set a description and expiry
   - Click **Add** and copy the **Value** — used as `client_secret`

### 2. Azure Roles & Permissions

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

### 3. Microsoft Graph API Permissions (Optional — Required for Rotation)

If you want Warden to automatically rotate service principal credentials, the source service principal needs Microsoft Graph API permissions:

1. Go to **App registrations** > your app > **API permissions** > **Add a permission**
2. Select **Microsoft Graph** > **Application permissions**
3. Add `Application.ReadWrite.All`
4. Click **Grant admin consent** for your tenant

> **Note:** Without Graph API permissions, credential rotation will be unavailable but all other features (token minting, proxying, Key Vault secret fetching) will work normally.

### 4. Workload Service Principals (Optional)

For issuing tokens scoped to specific workloads, create additional App Registrations (one per workload). Each workload SP needs:

- Its own `client_id` and `client_secret`
- Appropriate Azure RBAC roles for the resources it accesses

### 5. Warden Server

- A running Warden server instance
- Network access from Warden to the following Azure endpoints:
  - `login.microsoftonline.com` (Azure AD authentication)
  - `management.azure.com` (Azure Resource Manager)
  - `graph.microsoft.com` (Microsoft Graph, required for rotation)
  - Any additional Azure service endpoints you plan to proxy

## Configuration

### Provider Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `allowed_hosts` | list(string) | See below | Azure hostnames allowed for proxying (supports wildcard prefixes) |
| `max_body_size` | int | `10485760` (10MB) | Maximum request body size in bytes (0–100MB) |
| `timeout` | duration | `"30s"` | Request timeout (e.g., `"30s"`, `"5m"`) |
| `transparent_mode` | bool | `false` | Enable implicit JWT-based authentication |
| `auto_auth_path` | string | `""` | JWT auth mount path (required when `transparent_mode` is enabled) |
| `default_role` | string | `""` | Default role for transparent mode |

### Default Allowed Hosts

```
management.azure.com
graph.microsoft.com
*.vault.azure.net
*.blob.core.windows.net
*.queue.core.windows.net
*.table.core.windows.net
*.file.core.windows.net
*.dfs.core.windows.net
```

> Wildcard entries (e.g., `*.vault.azure.net`) match any subdomain such as `myvault.vault.azure.net`.

### Example Provider Configuration

```hcl
provider "azure" {
  path = "azure"
  config = {
    allowed_hosts    = [".vault.azure.net", "management.azure.com"]
    max_body_size    = 10485760
    timeout          = "30s"
    transparent_mode = false
  }
}
```

## Setting Up Credentials

### Step 1: Register a Credential Source

Create a credential source using the Azure driver. This tells Warden how to authenticate with Azure AD.

```bash
curl -X POST http://localhost:8200/v1/sys/credentials/sources \
  -H "X-Warden-Token: <your-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "azure-source",
    "type": "azure",
    "config": {
      "tenant_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
      "client_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
      "client_secret": "your-client-secret",
      "subscription_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    }
  }'
```

| Field | Required | Description |
|-------|----------|-------------|
| `tenant_id` | Yes | Azure AD Tenant ID (UUID format) |
| `client_id` | Yes | Service Principal Application (Client) ID |
| `client_secret` | Yes | Service Principal client secret |
| `subscription_id` | No | Azure Subscription ID |

### Step 2: Create a Credential Spec

A credential spec defines how Warden mints credentials for a particular workload.

#### Option A: Bearer Token (default)

Mints an Azure AD Bearer token using the client credentials flow.

```bash
curl -X POST http://localhost:8200/v1/sys/credentials/specs \
  -H "X-Warden-Token: <your-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-azure-token",
    "source": "azure-source",
    "cred_type": "azure_bearer_token",
    "config": {
      "mint_method": "bearer_token",
      "client_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
      "client_secret": "workload-sp-client-secret",
      "resource_uri": "https://management.azure.com/"
    }
  }'
```

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `mint_method` | No | `bearer_token` | Set to `bearer_token` |
| `client_id` | Yes | — | Workload SP Application ID |
| `client_secret` | Yes | — | Workload SP client secret |
| `tenant_id` | No | Source tenant | Override tenant ID |
| `resource_uri` | No | `https://management.azure.com/` | Token scope (e.g., `https://vault.azure.net/`) |

#### Option B: Key Vault Secret

Fetches a secret directly from Azure Key Vault.

```bash
curl -X POST http://localhost:8200/v1/sys/credentials/specs \
  -H "X-Warden-Token: <your-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-kv-secret",
    "source": "azure-source",
    "cred_type": "azure_bearer_token",
    "config": {
      "mint_method": "key_vault_secret",
      "client_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
      "client_secret": "workload-sp-client-secret",
      "vault_name": "my-key-vault",
      "secret_name": "my-secret"
    }
  }'
```

| Field | Required | Description |
|-------|----------|-------------|
| `mint_method` | Yes | Set to `key_vault_secret` |
| `client_id` | Yes | SP with access to the Key Vault |
| `client_secret` | Yes | SP client secret |
| `vault_name` | Yes | Name of the Azure Key Vault |
| `secret_name` | Yes | Name of the secret to retrieve |
| `secret_version` | No | Specific version (defaults to latest) |
| `tenant_id` | No | Override tenant ID |

## Using the Gateway

### Request Flow

1. Client sends a request to the Warden gateway endpoint with an authentication token
2. Warden validates the token and retrieves the associated Azure credential
3. Warden verifies the target Azure host is in the allowed list
4. Warden injects the Bearer token into the `Authorization` header
5. Warden strips sensitive and hop-by-hop headers
6. Request is forwarded to the Azure service over HTTPS
7. Response is returned to the client

### Gateway URL Format

```
https://<warden-host>/v1/azure/gateway/<azure-host>/<path>
```

### Examples

**List Azure Subscriptions (Resource Manager):**

```bash
curl https://localhost:8200/v1/azure/gateway/management.azure.com/subscriptions?api-version=2022-12-01 \
  -H "X-Warden-Token: <your-token>"
```

**Get a Key Vault Secret:**

```bash
curl https://localhost:8200/v1/azure/gateway/myvault.vault.azure.net/secrets/my-secret?api-version=7.4 \
  -H "X-Warden-Token: <your-token>"
```

**List Storage Blobs:**

```bash
curl https://localhost:8200/v1/azure/gateway/mystorage.blob.core.windows.net/mycontainer?restype=container&comp=list \
  -H "X-Warden-Token: <your-token>"
```

**Query Microsoft Graph:**

```bash
curl https://localhost:8200/v1/azure/gateway/graph.microsoft.com/v1.0/users \
  -H "X-Warden-Token: <your-token>"
```

### Authentication

The gateway accepts authentication tokens via two headers (in priority order):

1. **`X-Warden-Token`** header (recommended)
2. **`Authorization: Bearer`** header

### Transparent Mode

When `transparent_mode` is enabled, the gateway uses implicit JWT-based authentication. Requests are routed through role-based paths:

```
https://<warden-host>/v1/azure/role/<role-name>/gateway/<azure-host>/<path>
```

This mode requires `auto_auth_path` to be configured and pointing to a valid JWT auth mount.

## Supported Azure Services

The provider proxies requests to any Azure service whose hostname is in the allowed hosts list. Default supported services include:

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

Additional hosts can be added via the `allowed_hosts` configuration.

## Credential Rotation

Warden supports automatic rotation of Azure service principal credentials via the Microsoft Graph API. Rotation follows a three-phase process:

1. **Prepare** — A new `client_secret` is created on the service principal via `addPassword`
2. **Commit** — The new credentials are activated and the token cache is cleared
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

## Troubleshooting

### "host not allowed" errors

The target Azure hostname is not in the `allowed_hosts` list. Either:
- Add the hostname to `allowed_hosts` via the config API
- Use a wildcard entry (e.g., `.vault.azure.net` matches `myvault.vault.azure.net`)

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

### Debug Logging

Enable trace-level logging to see detailed request processing:

```hcl
log_level = "trace"
```

This will show:
- Incoming request details
- Token extraction and injection
- Host validation
- Target URL construction
- Proxy forwarding operations
