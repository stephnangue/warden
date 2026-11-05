---
title: "Microsoft Graph"
description: "Proxy Microsoft Graph through Warden: the agent calls Graph as the signed-in user, through Entra on-behalf-of, or as the app, and never holds a Graph token."
---

The Microsoft Graph provider fronts every Graph workload: Microsoft 365 mail, calendar,
Teams, SharePoint and OneDrive, Entra ID users and groups, Intune, Planner, To Do and
Security.
The agent calls a Warden URL. Warden obtains a Graph token for the role the agent asserted,
injects it as `Authorization: Bearer <token>`, and forwards the request to Graph. The agent
never holds a Graph token.

A role acts in one of two ways:

- **As the user.** Warden exchanges the user's own Entra access token for a delegated
  Graph token through Entra **on-behalf-of**. Graph sees exactly that user's permissions:
  `/me/messages` is the user's mailbox, and a site the user cannot open stays closed.
- **As the app.** Warden mints an app-only token with the client-credentials grant. Graph
  sees the app's application permissions.

## How a request flows

The recommended setup stores **no Azure secret**. Each request carries two principals:
the user, whose token Warden exchanges, and the agent, which authorizes the request.

<p align="center"><img alt="A user gives an agent their Entra access token. The agent calls Warden's Microsoft Graph provider with that token and its own identity. Warden sends an unsigned assertion to an external KMS and gets it back signed, presents the user's access token and the signed assertion to Entra ID, receives a delegated access token, and calls Microsoft Graph with it." src="/images/warden-prov-msgraph-fic.png" width="860"></p>

1. The user signs in, and the agent holds the user's Entra access token for Warden's app.
2. The agent calls Warden with the user's token in `Authorization` and its own identity
   out of band: a client certificate, or `X-Warden-Agent-Token`. Warden authenticates the
   agent on `auto_auth_path` and the user on `user_auth_path`. The agent's role selects the
   credential spec.
3. Warden builds an assertion naming the agent and sends it unsigned to an **external
   KMS**.
4. The KMS returns it signed. No signing key lives in Warden.
5. Warden presents the user's access token and the signed assertion to **Entra ID** in an
   on-behalf-of request. The user's token is the grant's `assertion`. The signed assertion
   is the client assertion Entra's federated identity credential trusts: it proves the
   request comes from Warden's app, in place of a client secret.
6. Entra ID returns an access token for Graph, delegated by that user.
7. Warden injects the token and forwards the request to **Microsoft Graph**.

The KMS leg is the OIDC issuer's [`signer` stanza](/configuration/signer/), and is
**recommended in production**. Without it, the issuer signs with a key it holds itself,
and the exchange at Entra ID is the same.

:::note[Steps 3–6 run only on a cache miss]
Warden caches the delegated token per user token, so most requests skip from step 2 to
step 7. One user's token is never served to another, and a delegated token never outlives
the user's own: when the user's token entry expires, the next request exchanges again.
Entra also returns a refresh token. Warden discards it, so it never reaches the
credential, a log or the audit trail.
:::

### Other ways to authenticate the app

The user's token is always the on-behalf-of assertion. What proves the request comes from
the app depends on the credential source:

- **A federated identity credential** (above): an `oidc_federation` source. Nothing is
  stored.
- **A certificate** registered on the app: an `auth_method=certificate` source. The
  certificate's key is either stored in Warden or held in a KMS that signs through a
  `transit_signer` spec. Use it when Entra cannot reach Warden's issuer, or an app would
  need more than 20 federated credentials. See
  [Certificate authentication](/credential-drivers/azure/#certificate-authentication).
- **A client secret**: a `static` source. Warden stores the secret.

## Credential modes

| Mode | What Graph sees | Where the credential lives |
|---|---|---|
| **Delegated, keyless** ✅ *recommended* | The user, through the app | Nothing stored; the app authenticates with a Warden assertion |
| **Delegated, certificate** | The user, through the app | The certificate's key, in Warden or in a KMS |
| **Delegated, client secret** ⚠️ | The user, through the app | The app's client secret, in Warden's storage |
| **App-only** | The app | Nothing stored when keyless |
| **OAuth bearer token** | Whoever connected it | An `oauth2` or `token_exchange` spec, such as a shared mailbox connected once |

The provider accepts `azure_bearer_token` and `oauth_bearer_token` credentials. See the
[Azure credential driver](/credential-drivers/azure/) for every source and spec key.

## Prerequisites

- Docker and Docker Compose installed and running.
- A Microsoft Entra ID tenant where you can register an app and grant admin consent.
- Warden's [OIDC issuer](/federation/oidc-issuer/) enabled, at an HTTPS URL Entra ID can
  reach. Entra fetches its discovery document and keys. If it cannot, use a certificate
  source instead.

:::note[New to Warden?]
Follow [Local dev setup](/provider-backends/local-dev-setup/) to start a local dev
environment (Ory Hydra + a Warden dev server) before Step 1. Hydra issues the agent's
token; the user's token comes from Entra ID.
:::

### Registering the app in Entra ID

The steps below are guidance for the Entra admin center; check Microsoft's documentation
for your tenant's settings.

1. **App registrations** > **New registration**. Note the **Application (client) ID** and
   the **Directory (tenant) ID**.
2. **Expose an API**: set an Application ID URI and add a scope, such as
   `access_as_user`. The client that signs the user in asks for this scope, so the user's
   token is issued for this app. On-behalf-of needs that: the user's token must name the
   app as its audience.
3. **API permissions** > **Microsoft Graph** > **Delegated permissions**: add what the
   agent needs (`User.Read`, `Mail.Read`, `Calendars.ReadWrite`, …), then **Grant admin
   consent**. Without consent, every exchange is refused with `403`.
4. **Certificates & secrets** > **Federated credentials** > **Other issuer**: one
   credential per agent, with Warden's issuer URL, the agent's subject and the audience
   `api://AzureADTokenExchange`. Step 4 shows how to find the subject.

## Step 1: Configure Auth for the Agent and the User

The agent and the user each have their own auth mount.

**The agent** authenticates with a JWT. Enabling the mount and configuring the key source
is covered once in [JWT auth](/auth-methods/jwt/#step-1-configure-the-key-source). For the
local dev setup:

```bash
warden auth enable jwt
warden write auth/jwt/config '{
  "jwks_url": "http://localhost:4444/.well-known/jwks.json",
  "bound_issuer": "http://localhost:4444",
  "bound_audiences": ["warden"]
}'
```

**The user** authenticates with their Entra access token, on a `human` JWT mount that
trusts your tenant:

```bash
warden auth enable -path=entra-users jwt
warden write auth/entra-users/config '{
  "oidc_discovery_url": "https://login.microsoftonline.com/<tenant-id>/v2.0",
  "bound_issuer": "https://login.microsoftonline.com/<tenant-id>/v2.0",
  "bound_audiences": ["<app-client-id>"],
  "entity_kind": "human"
}'
```

`bound_audiences` is the audience Entra puts in the user's token. For a v2.0 access token
it is the app's client ID; for a v1.0 token, its Application ID URI, with the issuer
`https://sts.windows.net/<tenant-id>/`. The token's version follows the app's
`requestedAccessTokenVersion` setting.

> **Set this up before configuring the provider.** The provider resolves
> `auto_auth_path` per request — writing the config only checks that it is
> non-empty, not that the mount exists — so a gateway call fails with `no auth
> mount registered ... for implicit auth` if the referenced auth mount isn't
> there yet.

## Step 2: Mount and Configure the Provider

Enable the provider:

```bash
warden provider enable msgraph
```

Configure it with both auth mounts. `auto_auth_path` admits the agent and `user_auth_path`
admits the user:

```bash
warden write msgraph/config <<EOF
{
  "auto_auth_path": "auth/jwt/",
  "user_auth_path": "auth/entra-users/",
  "timeout": "60s",
  "max_body_size": 10485760
}
EOF
```

`graph_url` defaults to `https://graph.microsoft.com`. It may name only a Graph host of the
public or a sovereign cloud (`graph.microsoft.us`, `dod-graph.microsoft.us`,
`microsoftgraph.chinacloudapi.cn`), as a bare `https` origin with no port, because every
user's delegated token is sent there. Warden checks it at mount time, on every config
write, and on every request.

Paging links are rewritten to point at Warden (see [Paging](#paging)). Warden builds those
links from the external address clients use, so publish it. The setting is
deployment-wide, written in the root namespace:

```bash
warden protected-resource configure -resource-url=https://warden.example.com
```

This also publishes the metadata a client reads when Warden asks for a user. See
[protected-resource](/cli/protected-resource/) and the common fields in
[Provider configuration](/provider-backends/configuration/).

Verify the configuration:

```bash
warden read msgraph/config
```

## Step 3: Create a Role and Grant It

A [role](/identity/roles/) binds the credential spec and policy, and `provider_path` names
the provider mount it is used with. The spec and policy come in the next steps, so the
write warns that they do not exist yet:

```bash
warden role create m365-agent -json '{
  "policies": ["msgraph-access"],
  "cred_spec_name": "graph-obo",
  "provider_path": "msgraph/"
}'
```

Nobody holds the role yet. A virtual [group](/identity/groups/) grants it to the agents
the JWT mount admits:

```bash
warden identity group create m365-agent-agents -json '{
  "type": "virtual",
  "roles": ["m365-agent"],
  "rules": [
    { "mount": ["auth/jwt/"] }
  ]
}'
```

:::caution[In production, register the agent]
The group above grants the role to every agent the mount admits: fine for trying the provider, not for production. In production, register each agent: create an [entity](/identity/entities/) for it, have its team [sponsor](/identity/sponsors/) it, and grant the role through a [static group](/identity/groups/) that lists the entity. Mark the role `governed_only` so no virtual group can grant it. Claim the agent's native identity last ([Rolling out](/identity/entities/#rolling-out)); [Governing an agent](/tutorials/identity/govern-an-agent/) walks through it.
:::

This rule matches every token the mount accepts. Add selectors on the token's facts, such
as `sub`, to grant the role to fewer agents. The user is granted nothing: the user leg
carries identity only.

## Step 4: Create a Credential Source and Spec

### Option A: Keyless on-behalf-of (recommended)

The source holds no secret:

```bash
warden cred source create azure-keyless -json '{
  "type": "azure",
  "config": {
    "auth_method": "oidc_federation"
  }
}'
```

The spec takes the user's token as the subject and Warden's assertion of the agent as the
actor:

```bash
warden cred spec create graph-obo -json '{
  "source": "azure-keyless",
  "config": {
    "mint_method": "on_behalf_of",
    "subject_token_source": "user_identity",
    "actor_token_source": "warden_identity",
    "tenant_id": "<tenant-id>",
    "client_id": "<app-client-id>",
    "resource_uri": "https://graph.microsoft.com/"
  }
}'
```

- `client_id` is the app the user's token was issued for, and the app whose federated
  credential checks the assertion.
- `resource_uri` defaults to Microsoft Graph. Warden asks for its `.default` scope, so the
  token carries the delegated permissions the app was consented for.
- The assertion uses the `minimal` profile: registered claims only. Its `sub` is the
  agent's composite subject, `wid:<namespaceID>:<mountAccessor>:<principalID>`, and its
  audience is `api://AzureADTokenExchange`.

Entra matches the subject exactly, with no wildcard, so each agent needs its own
federated credential on the app. To find an agent's subject, read `auth.namespace_id`,
`auth.mount_accessor` and `auth.principal_id` from the audit entry of one of its requests.
In the root namespace, the namespace ID is `root`. Once a mint succeeds, the audit entry's
credential metadata records the same subject as `actor`, and the user's `oid` as
`subject`.

### Option B: Certificate or client secret

Over a `certificate` or `static` source, the source's own credential authenticates the
app. The spec names no actor, and its `client_id` and `tenant_id` must be the source's:

```bash
warden cred spec create graph-obo -json '{
  "source": "azure-cert",
  "config": {
    "mint_method": "on_behalf_of",
    "subject_token_source": "user_identity",
    "tenant_id": "<tenant-id>",
    "client_id": "<app-client-id>"
  }
}'
```

How to create a certificate source, with a local key or a KMS-held one, is on
[the driver page](/credential-drivers/azure/#certificate-authentication).

### Option C: App-only

To act as the app, bind the role to a client-credentials spec instead. The app needs
Graph **application** permissions, with admin consent:

```bash
warden cred spec create graph-app -json '{
  "source": "azure-keyless",
  "config": {
    "mint_method": "bearer_token",
    "subject_token_source": "warden_identity",
    "tenant_id": "<tenant-id>",
    "client_id": "<app-client-id>",
    "resource_uri": "https://graph.microsoft.com/"
  }
}'
```

An app-only role needs no user. On a mount without `user_auth_path`, the agent's JWT rides
`Authorization`.

## Step 5: Create a Policy

A coarse policy that admits every Graph call under the role:

```bash
warden policy write msgraph-access - <<EOF
path "msgraph/role/+/gateway*" {
  capabilities = ["create", "read", "update", "delete", "patch"]
  condition    = "user.present == true"
}
EOF
```

The `user.present` condition refuses a request without a user with a `401` challenge, so
the client signs the user in and retries. See
[CEL conditions](/identity/cel-conditions/#agent-acting-for-a-user).

Request bodies and query parameters are parsed, so policy can read them. Read-only access
to the user's own data, with a page size cap and a projection, and no `beta` or other
users:

```bash
warden policy write msgraph-own-mail - <<'EOF'
path "msgraph/role/+/gateway/v1.0/me" {
  capabilities = ["read"]
  condition    = "user.present == true"
}

path "msgraph/role/+/gateway/v1.0/me/messages" {
  capabilities = ["read"]
  condition    = <<-CEL
    user.present &&
    '$select' in request.data && size(request.data['$select']) > 0 &&
    (!('$top' in request.data) || int(request.data['$top']) <= 25)
  CEL
}

path "msgraph/role/+/gateway/beta/*" {
  capabilities = ["deny"]
}

path "msgraph/role/+/gateway/v1.0/users/*" {
  capabilities = ["deny"]
}
EOF
```

Mail sent to internal recipients only:

```bash
warden policy write msgraph-internal-mail - <<'EOF'
path "msgraph/role/+/gateway/v1.0/me/sendMail" {
  capabilities = ["create"]
  condition    = <<-CEL
    user.present &&
    has(request.data.message) &&
    request.data.message.toRecipients.all(r, r.emailAddress.address.endsWith('@contoso.com')) &&
    (!has(request.data.message.ccRecipients) ||
      request.data.message.ccRecipients.all(r, r.emailAddress.address.endsWith('@contoso.com'))) &&
    (!has(request.data.message.bccRecipients) ||
      request.data.message.bccRecipients.all(r, r.emailAddress.address.endsWith('@contoso.com')))
  CEL
}
EOF
```

Guard each optional list with `has()`, as above. Iterating an `orValue([])` result has no
size bound, and `warden policy write` refuses it.

## Step 6: Make Requests

The agent gets its JWT as in [Obtaining a JWT](/auth-methods/jwt/#obtaining-a-jwt), with
`audience=warden`, and exports it as `$AGENT_JWT`. The user's Entra access token for the
app, which the agent's client obtained when the user signed in, is `$USER_TOKEN`.

The URL pattern is `/v1/msgraph/role/{role}/gateway/{version}/{resource}`:

```bash
export GRAPH="${WARDEN_ADDR}/v1/msgraph/role/m365-agent/gateway"
```

### The signed-in user

```bash
curl "${GRAPH}/v1.0/me" \
  -H "Authorization: Bearer ${USER_TOKEN}" \
  -H "X-Warden-Agent-Token: ${AGENT_JWT}"
```

### Latest mail, projected

```bash
curl "${GRAPH}/v1.0/me/messages?\$top=10&\$select=subject,from,receivedDateTime" \
  -H "Authorization: Bearer ${USER_TOKEN}" \
  -H "X-Warden-Agent-Token: ${AGENT_JWT}"
```

### Create a calendar event

```bash
curl -X POST "${GRAPH}/v1.0/me/events" \
  -H "Authorization: Bearer ${USER_TOKEN}" \
  -H "X-Warden-Agent-Token: ${AGENT_JWT}" \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "Sync",
    "start": { "dateTime": "2026-11-20T10:00:00", "timeZone": "UTC" },
    "end": { "dateTime": "2026-11-20T10:30:00", "timeZone": "UTC" }
  }'
```

### Files in a SharePoint site

```bash
curl "${GRAPH}/v1.0/sites/<site-id>/drive/root/children" \
  -H "Authorization: Bearer ${USER_TOKEN}" \
  -H "X-Warden-Agent-Token: ${AGENT_JWT}"
```

### From a Graph SDK

Point the SDK at the gateway instead of Graph:

- Set the base URL to `$WARDEN_ADDR/v1/msgraph/role/<role>/gateway/v1.0`. Agents read the
  gateway URL from the role's `url` in [discovery](/concepts/discovery-and-skills/).
- Give the client a token provider that returns the user's token.
- Send the agent's identity on every request: a client certificate on the SDK's HTTP
  client, or `X-Warden-Agent-Token` as a default header.
- Some SDKs attach the token only to Microsoft hosts. Add Warden's host to the SDK's
  allowed or custom hosts.
- Turn off batching helpers: `$batch` is refused.

## Paging

Graph pages long listings and delta queries with absolute links back to Graph. An SDK
follows them as given, which would skip Warden. So Warden rewrites the top-level
`@odata.nextLink` and `@odata.deltaLink`, plain or qualified (`members@odata.nextLink`),
onto the gateway URL the client used. Clients follow them unchanged.

- Only successful JSON responses to `GET` are rewritten, and nothing else in the body
  changes.
- It needs the protected-resource `resource_url` from Step 2. Without it, links are left
  as Graph wrote them.
- A body over `max_body_size`, or one that is encoded or not JSON, is forwarded whole.
- `rewrite_links` (default `true`) turns rewriting off.

When a link still points at Graph, replace its origin with the gateway URL and keep the
rest, including `$skiptoken`.

## Errors and challenges

A failure Warden raises itself is answered in Graph's error shape, so a Graph SDK reads it
as it reads Graph's own:

```json
{
  "error": {
    "code": "Authorization_RequestDenied",
    "message": "Warden: ...",
    "innerError": { "request-id": "...", "date": "2026-11-05T10:00:00" }
  }
}
```

The status is Warden's. When Entra refuses to act for the user until the user does
something, Warden answers `401` with the challenge MSAL and the Graph SDKs expect:

| Case | Answer |
|---|---|
| No user token on the request | `401`, `WWW-Authenticate: Bearer` pointing at the mount's protected resource metadata |
| The user's token is expired or for the wrong audience | `401`, `error="invalid_token"` |
| Conditional Access or MFA demands more claims | `401`, Microsoft's format: `realm`, `authorization_uri`, `error="insufficient_claims"` and the claims request in base64. Re-acquire the user's token with those claims (MSAL: `WithClaims`) and retry. |
| The user must sign in interactively | `401`, `error="invalid_token"` with `error_description="interaction_required"` |
| Admin consent is missing | `403`, *admin consent is missing*. The operator must grant it. |
| Entra refused the app's credential | `403`, naming the federated credential, certificate or secret to fix |

`authorization_uri` names the Entra authority the request went to, so a sovereign cloud
works. No Entra free text reaches a header, a log or the audit trail.

## Batching is refused

A Graph `$batch` body carries up to twenty requests, each with its own method and path,
while policy sees only the outer `POST`. So Warden refuses `$batch` with `400`
(`batchNotSupported`) whatever policy says, in any spelling. Send the requests one by
one. The [Azure provider](/provider-backends/azure/) refuses `$batch` on Graph hosts too.

## Uploads and downloads

`PUT` uploads and `/content` or `/$value` downloads skip body parsing, so policy cannot
read their bodies, and Warden does not default their `Accept` to JSON. Graph answers a
download with a redirect to a pre-authenticated URL; follow it directly, without an
`Authorization` header. A large upload uses `createUploadSession`; send its chunks to the
returned `uploadUrl` directly. A body sent through Warden is capped by `max_body_size`.

## TLS Certificate Authentication

The agent can authenticate with a TLS client certificate instead of a JWT. The user's
token still rides `Authorization`.

:::note[Prerequisite]
Certificate auth requires mTLS on the Warden listener so the client certificate can be presented during the handshake. See [Enabling mTLS on the listener](/auth-methods/cert/#enabling-mtls-on-the-listener).
:::

The role, credential spec and policy are identical. Replace the agent's JWT mount
(Step 1), its group (Step 3) and the requests (Step 6) with the following.

```bash
warden auth enable cert
warden write auth/cert/config trusted_ca_pem=@/path/to/ca.pem
```

A virtual group grants `m365-agent` to the certificates the mount admits whose common
name matches:

```bash
warden identity group create m365-agent-agents -json '{
  "type": "virtual",
  "roles": ["m365-agent"],
  "rules": [
    { "mount": ["auth/cert/"], "cn": ["agent-*"] }
  ]
}'
```

The `cn` selector supports glob patterns; you can also match on other certificate fields.
See [Grant the role with a group](/auth-methods/cert/#step-4-grant-the-role-with-a-group).

Point the provider's agent leg at the cert mount:

```bash
warden write msgraph/config <<EOF
{
  "auto_auth_path": "auth/cert/",
  "user_auth_path": "auth/entra-users/",
  "timeout": "60s"
}
EOF
```

```bash
curl --cert client.pem --key client-key.pem \
    --cacert warden-ca.pem \
    "https://warden.internal/v1/msgraph/role/m365-agent/gateway/v1.0/me" \
    -H "Authorization: Bearer ${USER_TOKEN}"
```

## Configuration reference

| Field | Default | Description |
|---|---|---|
| `graph_url` | `https://graph.microsoft.com` | The Graph endpoint: a Graph host of the public or a sovereign cloud, `https`, bare origin, no port. |
| `rewrite_links` | `true` | Rewrite Graph's paging links onto the gateway. Needs the protected-resource `resource_url`. |
| `auto_auth_path` | — | The auth mount that admits the agent. |
| `user_auth_path` | — | The auth mount that admits the user's Entra access token, for on-behalf-of. |
| `default_role` | — | The role used when the request names none. |
| `timeout` | `60s` | How long a single Graph call may take. |
| `max_body_size` | `10485760` (10 MB) | Maximum request body size (max 100 MB). |

## Troubleshooting

**Every request answers `401 invalid_token`.** The user's token is not for the app the
spec names. Check that the client asks for the app's scope, and that the user mount's
`bound_issuer` and `bound_audiences` match the token's version.

**`403` naming the federated credential.** Entra refused Warden's assertion. Check the
federated credential's issuer, subject and audience. A new one can take minutes to take
effect.

**`403` with *admin consent is missing*.** Grant admin consent to the app for the
delegated permissions, then retry.

**`429` from Graph.** Wait for `Retry-After` seconds. A throttled token endpoint answers
`503`.

**Intune calls fail.** Many `deviceManagement` APIs exist only under `beta`, and the user
also needs an Intune role.
