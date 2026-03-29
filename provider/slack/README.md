# Slack Provider

The Slack provider enables proxied access to the Slack Web API through Warden. It streams requests to Slack API methods (chat.postMessage, conversations.list, etc.) with automatic bot token injection and policy evaluation on request fields like channel, text, and user.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Step 1: Configure JWT Auth and Create a Role](#step-1-configure-jwt-auth-and-create-a-role)
- [Step 2: Mount and Configure the Provider](#step-2-mount-and-configure-the-provider)
- [Step 3: Create a Credential Source and Spec](#step-3-create-a-credential-source-and-spec)
- [Step 4: Create a Policy](#step-4-create-a-policy)
- [Step 5: Get a JWT and Make Requests](#step-5-get-a-jwt-and-make-requests)
- [Policy Evaluation on Slack Requests](#policy-evaluation-on-slack-requests)
- [Configuration Reference](#configuration-reference)
- [Token Management](#token-management)

## Prerequisites

- Docker and Docker Compose installed and running
- A **Slack Bot Token** (`xoxb-...`) from a [Slack App](https://api.slack.com/apps) with the required OAuth scopes (e.g., `chat:write`, `channels:read`)

> **New to Warden?** Follow these steps to get a local dev environment running:
>
> **1. Deploy the quickstart stack** — this starts an identity provider ([Ory Hydra](https://www.ory.sh/hydra/)) needed to issue JWTs for authentication in Steps 1 and 5:
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
> **3. Add the binary to your PATH:**
> ```bash
> export PATH="$PWD:$PATH"
> ```
>
> **4. Start the Warden server** in dev mode:
> ```bash
> warden server --dev --dev-root-token=root
> ```
>
> **5. In another terminal window**, export the environment variables for the CLI:
> ```bash
> export PATH="$PWD:$PATH"
> export WARDEN_ADDR="http://127.0.0.1:8400"
> export WARDEN_TOKEN="root"
> ```

## Step 1: Configure JWT Auth and Create a Role

Set up a JWT auth method and create a role that binds the credential spec and policy. Clients authenticate directly with their JWT — no separate login step is needed.

> **This step must come before configuring the provider.** Warden validates at configuration time that the auth backend referenced by `auto_auth_path` is already mounted.

```bash
# Enable JWT auth if not already enabled
warden auth enable --type=jwt

# Configure JWT with Hydra's JWKS endpoint (from docker-compose.quickstart.yml)
warden write auth/jwt/config mode=jwt jwks_url=http://localhost:4444/.well-known/jwks.json

# Create a role that binds the credential spec and policy
warden write auth/jwt/role/slack-user \
    token_policies="slack-access" \
    user_claim=sub \
    cred_spec_name=slack-ops
```

## Step 2: Mount and Configure the Provider

Enable the Slack provider at a path of your choice:

```bash
warden provider enable --type=slack
```

To mount at a custom path:

```bash
warden provider enable --type=slack slack-prod
```

Verify the provider is enabled:

```bash
warden provider list
```

Configure the provider with `auto_auth_path`. This allows clients to authenticate with their JWT directly — no explicit Warden login required:

```bash
warden write slack/config <<EOF
{
  "slack_url": "https://slack.com/api",
  "auto_auth_path": "auth/jwt/",
  "timeout": "30s",
  "max_body_size": 10485760
}
EOF
```

Verify the configuration:

```bash
warden read slack/config
```

## Step 3: Create a Credential Source and Spec

The credential source holds only connection info (`api_url`). The bot token is stored on the credential spec below, allowing multiple specs with different tokens to share one source.

```bash
warden cred source create slack-src \
  --type=slack \
  --rotation-period=0 \
  --config=api_url=https://slack.com/api
```

Verify the source was created:

```bash
warden cred source read slack-src
```

Create a credential spec that references the credential source. The spec carries the bot token and gets associated with tokens at login time.

```bash
warden cred spec create slack-ops \
  --type api_key \
  --source slack-src \
  --config api_key=xoxb-your-bot-token
```

The bot token is validated at creation time via a `POST /auth.test` call to the Slack API (SpecVerifier). If the token is invalid, spec creation will fail.

Verify:

```bash
warden cred spec read slack-ops
```

## Step 4: Create a Policy

Create a policy that grants access to the Slack provider gateway:

```bash
warden policy write slack-access - <<EOF
path "slack/role/+/gateway*" {
  capabilities = ["create", "read", "update", "delete", "patch"]
}
EOF
```

For fine-grained access control, restrict which Slack methods and channels a role can use:

```bash
warden policy write slack-restricted - <<EOF
path "slack/role/+/gateway/chat.postMessage" {
  capabilities = ["create"]
  allowed_parameters = {
    "channel" = ["#alerts", "#ops"]
    "text"    = []
    "*"       = []
  }
}

path "slack/role/+/gateway/conversations.list" {
  capabilities = ["create"]
}

path "slack/role/+/gateway/conversations.history" {
  capabilities = ["create"]
  allowed_parameters = {
    "channel" = []
    "limit"   = []
  }
}
EOF
```

You can combine parameter restrictions with runtime conditions. For example, restrict posting to specific channels from trusted networks during business hours:

```bash
warden policy write slack-prod-restricted - <<EOF
path "slack/role/+/gateway/chat.postMessage" {
  capabilities = ["create"]
  allowed_parameters = {
    "channel" = ["#alerts", "#incidents"]
    "text"    = []
    "*"       = []
  }
  denied_parameters = {
    "as_user" = ["true"]
  }
  conditions {
    source_ip   = ["10.0.0.0/8"]
    time_window = ["08:00-18:00 UTC"]
    day_of_week = ["Mon", "Tue", "Wed", "Thu", "Fri"]
  }
}

path "slack/role/+/gateway/auth.test" {
  capabilities = ["create"]
}
EOF
```

Condition types are AND-ed (all must be satisfied), values within each type are OR-ed (at least one must match). Supported types: `source_ip` (CIDR or bare IP), `time_window` (`HH:MM-HH:MM TZ`, supports midnight-spanning), `day_of_week` (3-letter abbreviations).

Verify:

```bash
warden policy read slack-access
```

## Step 5: Get a JWT and Make Requests

Get a JWT from Hydra using one of the quickstart clients:

```bash
export JWT_TOKEN=$(curl -s -X POST http://localhost:4444/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=my-agent&client_secret=agent-secret&scope=api:read api:write" \
  | jq -r '.access_token')
```

Requests use role-based paths. Warden performs implicit JWT authentication and injects the Slack bot token automatically.

The URL pattern is: `/v1/slack/role/{role}/gateway/{slack-method}`

Export SLACK_ENDPOINT as environment variable:
```bash
export SLACK_ENDPOINT="${WARDEN_ADDR}/v1/slack/role/slack-user/gateway"
```

### Post a Message

```bash
curl -X POST "${SLACK_ENDPOINT}/chat.postMessage" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "channel": "#general",
    "text": "Hello from Warden!"
  }'
```

### List Conversations

```bash
curl -X POST "${SLACK_ENDPOINT}/conversations.list" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "limit": 100
  }'
```

### Get Conversation History

```bash
curl -X POST "${SLACK_ENDPOINT}/conversations.history" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "channel": "C01ABC123",
    "limit": 50
  }'
```

### Test Authentication

```bash
curl -X POST "${SLACK_ENDPOINT}/auth.test" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"
```

### Add a Reaction

```bash
curl -X POST "${SLACK_ENDPOINT}/reactions.add" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "channel": "C01ABC123",
    "name": "thumbsup",
    "timestamp": "1234567890.123456"
  }'
```

### Get User Info

```bash
curl -X POST "${SLACK_ENDPOINT}/users.info" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "user": "U01ABC123"
  }'
```

## Cleanup

To stop Warden and the identity provider:

```bash
# Stop Warden (Ctrl+C in the terminal where it's running)

# Stop and remove the identity provider containers
docker compose -f docker-compose.quickstart.yml down -v
```

Since Warden dev mode uses in-memory storage, all configuration is lost when the server stops.

## Policy Evaluation on Slack Requests

The Slack provider has request body parsing enabled (`ParseStreamBody: true`), which means Warden can evaluate policies against fields in the Slack request body. This enables fine-grained access control that goes beyond what Slack's native permission model offers.

**Slack's native model:** One bot token = one set of OAuth scopes. If a bot has `chat:write`, it can post to any channel it's in.

**Warden's CBP layer adds:** One bot token, many Warden roles with different policies. Each role can be restricted to specific methods, channels, fields, source IPs, and time windows.

Evaluable fields include:

| Field | Type | Description |
|-------|------|-------------|
| `channel` | string | Channel ID or name (e.g., `#general`, `C01ABC123`) |
| `text` | string | Message text content |
| `user` | string | User ID |
| `as_user` | boolean | Whether to post as the authenticated user |
| `thread_ts` | string | Thread timestamp for replies |
| `name` | string | Reaction name (for `reactions.add`) |
| `timestamp` | string | Message timestamp |
| `limit` | integer | Pagination limit |

This allows operators to enforce policies such as:
- Restrict which channels a service can post to
- Prevent impersonation (`as_user` denied)
- Limit read-only services to `conversations.list` and `conversations.history`
- Require specific fields to be present (`required_parameters`)

## TLS Certificate Authentication

Steps 4-5 above use JWT authentication. Alternatively, you can authenticate with a TLS client certificate. This is useful for workloads that already have X.509 certificates — Kubernetes pods with cert-manager, VMs with machine certificates, or SPIFFE X.509-SVIDs from a service mesh.

> **Prerequisite:** Certificate authentication requires TLS to be enabled on the Warden listener so that client certificates can be presented during the TLS handshake (mTLS). In dev mode, use `--dev-tls` to enable TLS with auto-generated certificates, or provide your own with `--dev-tls-cert-file`, `--dev-tls-key-file`, and `--dev-tls-ca-cert-file`. Alternatively, place Warden behind a load balancer that terminates TLS and forwards the client certificate via the `X-Forwarded-Client-Cert` or `X-SSL-Client-Cert` header.

Steps 1-3 (provider setup) are identical. Replace Steps 4-5 with the following.

### Enable Cert Auth

```bash
warden auth enable --type=cert
```

### Configure Trusted CA

Provide the PEM-encoded CA certificate that signs your client certificates:

```bash
warden write auth/cert/config \
    trusted_ca_pem=@/path/to/ca.pem \
    default_role=slack-user
```

### Create a Cert Role

Create a role that binds allowed certificate identities to a credential spec and policy:

```bash
warden write auth/cert/role/slack-user \
    allowed_common_names="agent-*" \
    token_policies="slack-access" \
    cred_spec_name=slack-ops
```

The `allowed_common_names` field supports glob patterns. You can also match on other certificate fields: `allowed_dns_sans`, `allowed_email_sans`, `allowed_uri_sans`, or `allowed_organizational_units`.

### Configure Provider for Cert Auth

Update the provider config to use cert auth:

```bash
warden write slack/config <<EOF
{
  "slack_url": "https://slack.com/api",
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
    -X POST "https://warden.internal/v1/slack/role/slack-user/gateway/chat.postMessage" \
    -H "Content-Type: application/json" \
    -d '{
      "channel": "#general",
      "text": "Hello from Warden with mTLS!"
    }'
```

## Configuration Reference

### Provider Config

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `slack_url` | string | `https://slack.com/api` | Slack API base URL (must be HTTPS) |
| `max_body_size` | int | 10485760 (10 MB) | Maximum request body size in bytes (max 100 MB) |
| `timeout` | duration | `30s` | Request timeout |
| `auto_auth_path` | string | — | Auth mount path for implicit authentication (e.g., `auth/jwt/`, `auth/cert/`) |
| `default_role` | string | — | Fallback role when not specified in URL |

### Credential Source Config

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `api_url` | string | `https://slack.com/api` | Slack API base URL (must be HTTPS) |

### Credential Spec Config

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `api_key` | string | Yes | Slack bot token (sensitive — masked in output) |

## Token Management

| Aspect | Details |
|--------|---------|
| **Storage** | Bot token is stored on the credential spec (not the source) |
| **Validation** | Token is verified at spec creation via `POST /auth.test` |
| **Rotation** | Manual — Slack bot tokens are tied to app installations |
| **Lifetime** | Static — no expiration or auto-refresh |

**To rotate a bot token:**

1. Regenerate the token in the [Slack App settings](https://api.slack.com/apps) or reinstall the app to the workspace
2. Update the credential spec:
   ```bash
   warden cred spec update slack-ops \
     --config api_key=xoxb-new-bot-token
   ```
3. Revoke the old token from the Slack App settings if needed
