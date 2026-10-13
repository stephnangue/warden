---
name: msgraph
description: "Call Microsoft Graph through Warden — mail, calendar, Teams, SharePoint/OneDrive, Entra directory, Intune — as the signed-in user, without holding a Graph token."
category: provider-guide
provider: msgraph
requires: []
upstream: Microsoft Graph (graph.microsoft.com)
---

# Microsoft Graph through Warden

## What it does

Warden proxies Microsoft Graph requests. The agent calls a Warden URL;
Warden authenticates the agent, exchanges **the user's Entra access token**
for a Graph token on that user's behalf (or uses an app-only token, if the
role is bound to one), injects it as `Authorization: Bearer <token>`, and
forwards to Graph. The agent **never holds a Graph token**, and Graph sees
exactly the user's own permissions.

## Configure the CLI/SDK

`<gateway-url>` is the `url` of the role you chose, as returned by the
`list_roles` discovery tool. Prepend `$WARDEN_ADDR`. To act under a
*different* role, use that role's `url`.

Each call carries two identities:

- **the user** — their Entra access token for Warden's app, as
  `Authorization: Bearer <user-token>`;
- **the agent** — an mTLS client certificate, or `X-Warden-Agent-Token: <jwt>`.

```bash
URL pattern : $WARDEN_ADDR<gateway-url><version>/<resource>
Example     : $WARDEN_ADDR/v1/msgraph/role/m365-agent/gateway/v1.0/me
```

Graph SDKs: set the base URL to `$WARDEN_ADDR<gateway-url>v1.0` and give the
client a static token provider that returns the user's token. Turn off SDK
batching helpers (see Quirks).

## Examples

(Examples use `<gateway-url>` = `/v1/msgraph/role/m365-agent/gateway/`.)

Latest mail, projected:
```bash
curl --cert agent.pem --key agent.key -H "Authorization: Bearer $USER_TOKEN" \
  "$WARDEN_ADDR/v1/msgraph/role/m365-agent/gateway/v1.0/me/messages?\$top=10&\$select=subject,from,receivedDateTime"
```

Create a calendar event:
```bash
curl --cert agent.pem --key agent.key -H "Authorization: Bearer $USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"subject":"Sync","start":{"dateTime":"2026-10-20T10:00:00","timeZone":"UTC"},"end":{"dateTime":"2026-10-20T10:30:00","timeZone":"UTC"}}' \
  "$WARDEN_ADDR/v1/msgraph/role/m365-agent/gateway/v1.0/me/events"
```

Teams chats, and a SharePoint site's files:
```bash
curl ... "$WARDEN_ADDR/v1/msgraph/role/m365-agent/gateway/v1.0/me/chats?\$top=20"
curl ... "$WARDEN_ADDR/v1/msgraph/role/m365-agent/gateway/v1.0/sites/contoso.sharepoint.com:/sites/eng"
curl ... "$WARDEN_ADDR/v1/msgraph/role/m365-agent/gateway/v1.0/sites/<site-id>/drive/root/children"
```

Directory search (advanced query) and Intune devices:
```bash
curl ... -H "ConsistencyLevel: eventual" \
  "$WARDEN_ADDR/v1/msgraph/role/m365-agent/gateway/v1.0/users?\$search=%22displayName:ann%22&\$count=true"
curl ... "$WARDEN_ADDR/v1/msgraph/role/m365-agent/gateway/v1.0/deviceManagement/managedDevices?\$top=50"
```

## Quirks

- **`$batch` is refused** (400 `batchNotSupported`). Send requests one by one.
- **401 with `WWW-Authenticate: … error="insufficient_claims", claims="…"`**
  (from Warden or from Graph): Conditional Access wants more. Re-acquire the
  user's token with those claims (MSAL: `WithClaims`) and retry.
  **401 `invalid_token`**: the user's token expired or is for the wrong
  audience — get a fresh one for Warden's app. **403 "admin consent is
  missing"**: ask the operator; retrying will not help.
- **Paging:** follow `@odata.nextLink` as given; if it still points at
  `graph.microsoft.com`, replace that origin with `$WARDEN_ADDR<gateway-url>`
  and keep the rest (including `$skiptoken`) unchanged.
- **Downloads and uploads:** `…/content` answers `302` to a pre-authenticated
  URL — follow it **directly, without** an Authorization header. Large uploads
  use `createUploadSession`; PUT the chunks to its `uploadUrl` directly, also
  without Authorization. Bodies sent through Warden are capped by the mount's
  `max_body_size`.
- **Throttling:** on `429`, wait for `Retry-After` seconds.
- **Policy may restrict paths and body fields** (e.g. only `/me/*`, or
  `sendMail` to internal recipients). A refusal before Graph is reached comes
  from Warden, in Graph's error shape, with a `Warden:` message prefix.
- **Intune:** many `deviceManagement` APIs exist only under `beta`, and need
  the user to hold an Intune role on top of the delegated scopes.
- **SharePoint REST (`/_api`) is not Graph:** it needs a different role and
  token audience.
