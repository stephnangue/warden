---
title: "Slack"
---

The Slack provider enables proxied access to the Slack Web API through Warden. It streams requests to Slack API methods (chat.postMessage, conversations.list, etc.) with automatic bot token injection and policy evaluation on request fields like channel, text, and user.

## How a request flows

This mount injects `Authorization: Bearer <token>` from an **`api_key`** credential. The question is where that
bot token (`xoxb-…`) lives.

The recommended setup keeps it in the vault that manages it, read per request.

<p align="center"><img alt="An agent presents the user's ID token and its own identity to Warden, which builds an assertion carrying user and agent claims, has an external KMS sign it, reads the Slack bot token (`xoxb-…`) from an external vault at a path templated by the agent's team and environment, and injects it to the Slack API" src="/images/warden-prov-slack-vault-apikey.png" width="860"></p>

1. The user authenticates and the agent holds their ID token.
2. The agent calls Warden presenting both credentials and asserting a role.
3. Warden builds the assertion the referenced spec calls for and sends it to a KMS-backed
   issuer unsigned, where one is configured.
4. The issuer returns it signed.
5. Warden authenticates to the **external vault** and reads
   `secret/slack/{{agent.team}}/{{agent.env}}`.
6. The vault returns the bot token (`xoxb-…`) for that team and environment.
7. Warden injects it and forwards.

The credential is served **verbatim** — nothing is minted. What chaining buys is custody:
it stays in the store that manages it, and the read path decides who reaches which one.

:::note[Steps 3–6 run only on a cache miss]
Warden caches the credential, so most requests skip from step 2 to step 7. The entry is
keyed by namespace, the agent's token id and the spec name — plus the user's token id when
the mount carries a user.
:::

### The simpler variant

<p align="center"><img alt="Warden reads a static Slack bot token (`xoxb-…`) from its encrypted storage and injects it to the Slack API for every caller" src="/images/warden-prov-slack-inline-apikey.png" width="860"></p>

**Inline.** The credential sits in Warden's storage. Shortest to set up, weakest custody:
one long-lived credential for every caller.

## Credential modes

| Mode | What Slack sees | Where the credential lives |
|---|---|---|
| **Chained** ✅ *recommended* | One long-lived credential, scoped by path | The vault; nothing in Warden |
| **Inline** ⚠️ | One long-lived credential, shared | Warden's storage |

Slack exposes no workload-identity federation and mints nothing per request, so the
credential is long-lived in both rows; what changes is whether Warden holds it.

See the [apikey credential driver](/credential-drivers/apikey/) for every source and spec
key.

## Prerequisites

- Docker and Docker Compose installed and running
- A **Slack Bot Token** (`xoxb-...`) from a [Slack App](https://api.slack.com/apps) with the required OAuth scopes (e.g., `chat:write`, `channels:read`)

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
warden write auth/jwt/role/slack-user \
    token_policies="slack-access" \
    user_claim=sub \
    cred_spec_name=slack-ops
```

## Step 2: Mount and Configure the Provider

Enable the Slack provider at a path of your choice:

```bash
warden provider enable slack
```

To mount at a custom path:

```bash
warden provider enable -path=slack-prod slack
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

See [Provider configuration](/provider-backends/configuration/) for the full list of common config fields (`proxy_domains`, `timeout`, `tls_skip_verify`, `ca_data`, and more).

Verify the configuration:

```bash
warden read slack/config
```

## Step 3: Create a Credential Source and Spec

### Option A: Chained (recommended)

The flow in the first diagram. The vault holds the credential; Warden reads it per request
and injects it.

```bash
# The store Warden reads from, reached keylessly — no vault token in Warden
warden cred source create vault-keyless -json '{
  "type": "hvault",
  "config": {
    "vault_address": "https://vault.example.com",
    "auth_method": "oidc_federation",
    "jwt_role": "warden-agents",
    "jwt_mount": "jwt",
    "audience": "https://vault.example.com"
  }
}'

warden cred spec create slack-ops -json '{
  "source": "vault-keyless",
  "min_ttl": 600,
  "max_ttl": 3600,
  "config": {
    "mint_method": "static_apikey",
    "subject_token_source": "warden_identity",
    "assertion_metadata_claims": "team,env",
    "kv2_mount": "secret",
    "secret_path": "slack/{{agent.team}}/{{agent.env}}"
  }
}'
```

The KV secret must carry the credential under **`api_key`**.

Both principals are available to the path template: `{{agent.sub}}` is free,
`{{agent.<claim>}}` needs `assertion_metadata_claims`, and `{{user.<claim>}}` needs
`assertion_user_claims` plus a user on the request. Swap `{{agent.team}}` for
`{{user.sub}}` to give each person their own credential. Templates resolve at **mint,
not at write**, so a path naming an unprojected claim is accepted by `spec create` and
fails on the first request.

### Option B: Inline

⚠️ 
```bash
warden cred source create slack-src -json '{
  "type": "apikey",
  "config": {
    "api_url": "https://slack.com/api",
    "verify_endpoint": "/auth.test",
    "verify_method": "POST",
    "display_name": "Slack"
  }
}'

printf '{"source":"slack-src","min_ttl":3600,"max_ttl":86400,"config":{"api_key":"%s"}}' \
  "$(cat /path/to/slack-token)" | warden cred spec create slack-ops -json -
```

One long-lived credential for every caller. Prefer Option A.

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
  condition = "!has(request.data.channel) || request.data.channel in ['#alerts', '#ops']"
}

path "slack/role/+/gateway/conversations.list" {
  capabilities = ["create"]
}

path "slack/role/+/gateway/conversations.history" {
  capabilities = ["create"]
  condition = "request.data.all(k, k in ['channel', 'limit'])"
}
EOF
```

You can combine parameter restrictions with runtime conditions. For example, restrict posting to specific channels from trusted networks during business hours:

```bash
warden policy write slack-prod-restricted - <<EOF
path "slack/role/+/gateway/chat.postMessage" {
  capabilities = ["create"]
  condition = <<-CEL
    (!has(request.data.channel) || request.data.channel in ["#alerts", "#incidents"]) &&
    (!has(request.data.as_user) || request.data.as_user != true) &&
    cidrContains("10.0.0.0/8", request.client_ip) &&
    now.getHours("UTC") >= 8 && now.getHours("UTC") < 18 &&
    now.getDayOfWeek("UTC") in [1, 2, 3, 4, 5]
  CEL
}

path "slack/role/+/gateway/auth.test" {
  capabilities = ["create"]
}
EOF
```

The `condition` is a [CEL](https://cel.dev) expression (see [CEL conditions](/concepts/cel-conditions/)): `cidrContains` restricts by network and `now.getHours`/`now.getDayOfWeek` by time of day and weekday. It must evaluate to `true` for the rule to apply, and fails closed.

Verify:

```bash
warden policy read slack-access
```

## Step 5: Get a JWT and Make Requests

Get a JWT from your identity provider — see [Obtaining a JWT](/auth-methods/jwt/#obtaining-a-jwt) (the local dev setup issues one from Hydra). Export it as `$JWT_TOKEN`.

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
- Require specific fields to be present (`has(request.data.x)` in a `condition`)

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

The `allowed_common_names` field supports glob patterns; you can also match on other certificate fields. See [Create a role](/auth-methods/cert/#step-3-create-a-role) for the full set of constraint fields.

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

## Token Management

| Aspect | Details |
|--------|---------|
| **Storage** | Bot token is stored on the credential spec (not the source) |
| **Validation** | Spec creation calls `POST /auth.test`, but that only proves the endpoint is reachable: Slack answers an invalid token with HTTP 200 and `ok:false`, and the driver checks the status code only, so a bad token still stores |
| **Rotation** | Manual — Slack bot tokens are tied to app installations |
| **Lifetime** | Static — no expiration or auto-refresh |

**To rotate a bot token:**

1. Regenerate the token in the [Slack App settings](https://api.slack.com/apps) or reinstall the app to the workspace
2. Update the credential spec:
   ```bash
   warden cred spec update slack-ops \
     -config api_key=xoxb-new-bot-token
   ```
3. Revoke the old token from the Slack App settings if needed
