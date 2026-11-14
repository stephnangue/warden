---
name: gws
description: "Call Google Workspace through Warden — Gmail, Drive, Calendar, Docs, Sheets, Chat, People, Admin SDK — as the signed-in user, without holding a Google token."
category: provider-guide
provider: gws
requires: []
upstream: Google Workspace APIs (*.googleapis.com)
---

# Google Workspace through Warden

## What it does

Warden proxies Google Workspace API requests. The agent calls a Warden URL
naming the Google API host; Warden authenticates the agent and the user, mints a
Google token acting as **that user** (domain-wide delegation), injects it as
`Authorization: Bearer <token>`, and forwards to Google. The agent **never holds
a Google token**, and Google applies the user's own data and permissions.

## Configure the CLI/SDK

`<gateway-url>` is the role's `url` from `list_roles`; prepend `$WARDEN_ADDR`.
The role is the URL's `role/<role>/` segment: use another role's `url` to act
under that role. The Google API host is the first segment after the gateway,
then Google's own path:

```
URL pattern : $WARDEN_ADDR<gateway-url><host>/<api-path>
Example     : $WARDEN_ADDR/v1/gws/role/ws-agent/gateway/gmail.googleapis.com/gmail/v1/users/me/messages
```

Each call carries two identities: **the user** as `Authorization: Bearer <user-token>`,
and **the agent** as an mTLS client certificate or `X-Warden-Agent-Token: <jwt>`.

Google client libraries: set the client's root URL to
`$WARDEN_ADDR<gateway-url><host>/` (for Drive and Calendar, `www.googleapis.com/`),
give it a static token that is the user's, and turn batching off.

## Examples

(`GW="$WARDEN_ADDR/v1/gws/role/ws-agent/gateway"`, no trailing slash.)

```bash
curl -H "Authorization: Bearer $USER_TOKEN" -H "X-Warden-Agent-Token: $AGENT_JWT" \
  "$GW/gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=10"

curl -H "Authorization: Bearer $USER_TOKEN" -H "X-Warden-Agent-Token: $AGENT_JWT" \
  "$GW/www.googleapis.com/drive/v3/files?pageSize=20&fields=files(id,name)"

curl -H "Authorization: Bearer $USER_TOKEN" -H "X-Warden-Agent-Token: $AGENT_JWT" \
  -o report.pdf "$GW/www.googleapis.com/drive/v3/files/$FILE_ID?alt=media"

curl -X POST -H "Authorization: Bearer $USER_TOKEN" -H "X-Warden-Agent-Token: $AGENT_JWT" \
  -H "Content-Type: application/json" \
  -d '{"summary":"Sync","start":{"dateTime":"2026-11-20T10:00:00Z"},"end":{"dateTime":"2026-11-20T10:30:00Z"}}' \
  "$GW/www.googleapis.com/calendar/v3/calendars/primary/events"
```

## Quirks

- **`users/me` is the user Warden acts for.** Use it rather than an address.
- **Paging** uses `nextPageToken`/`pageToken`; there are no links to follow.
- **Batch requests are refused** (400): send requests one at a time.
- **Bodies are JSON**, labelled by one `Content-Type: application/json`, outside
  `/upload/` paths: any other body is refused (415), XML ones (CalDAV, CardDAV)
  included, and so is a body on GET or DELETE (400 `bodyNotAllowed`).
- **Resumable uploads**: the session URL in `Location` points back at Warden;
  send every chunk there, each no larger than the mount's `max_body_size`. A
  501 `uploadNotRoutable` means Warden has no external address: upload in one
  request (`uploadType=multipart`) instead. Upload bodies are not parsed for policy.
- **Do not send your own credentials**: `access_token`, `key`, `userProject` or
  a `$` parameter other than `$alt`, `$fields`, `$prettyPrint` in the query is
  refused, and method-override and API-key headers are dropped.
- **401** means the user must sign in (follow `WWW-Authenticate`); **403
  `userNotAllowed`** means the user is outside the domains this role may act
  for — retrying will not help; **403 `hostNotAllowed`** means this mount does
  not reach that API.
- **Admin SDK** calls act with the user's own admin privileges, if any.
