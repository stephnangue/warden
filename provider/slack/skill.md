---
name: slack
description: "Call the Slack Web API through Warden — post messages, read channels, manage reactions — without holding a bot token."
category: provider-guide
provider: slack
requires: [foundation, discovery]
upstream: Slack Web API (slack.com/api)
---

# Slack through Warden

## What it does

Warden proxies Slack Web API requests. The agent calls a Warden URL;
Warden authenticates the caller (JWT/cert), looks up the Slack bot
token bound to the chosen role, injects it as
`Authorization: Bearer <xoxb-…>`, and forwards to Slack. The agent
**never holds a bot token**.

## Configure the CLI/SDK

`<mount-url>` and `<role>` below come from the discovery flow:
- `<mount-url>` is the chosen provider's `mount_url` from
  `warden provider list` (e.g. `/v1/slack/`, `/v1/team-ops/slack-prod/`).
  Warden has already baked the namespace + mount path in.
- `<role>` is the role you picked from `warden role list` to perform this
  task — it goes in the URL path.

```bash
URL pattern : $WARDEN_ADDR<mount-url>role/<role>/gateway/<slack-method>
Auth header : Authorization: Bearer $WARDEN_TOKEN
```

For `curl` or any HTTP client: rewrite the Slack host to
`$WARDEN_ADDR<mount-url>role/<role>/gateway` and add the bearer token.

## Examples

(All examples assume `mount_url = /v1/slack/` and role `slack-user`;
substitute yours. All Slack Web API calls are **POST**, even reads.)

Post a message to a channel:
```bash
curl -X POST -H "Authorization: Bearer $WARDEN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"channel":"#general","text":"Hello from Warden!"}' \
  $WARDEN_ADDR/v1/slack/role/slack-user/gateway/chat.postMessage
```

List conversations the bot can see:
```bash
curl -X POST -H "Authorization: Bearer $WARDEN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"limit":100}' \
  $WARDEN_ADDR/v1/slack/role/slack-user/gateway/conversations.list
```

Read recent messages from a channel:
```bash
curl -X POST -H "Authorization: Bearer $WARDEN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"channel":"C01ABC123","limit":50}' \
  $WARDEN_ADDR/v1/slack/role/slack-user/gateway/conversations.history
```

Test that the injected bot token is valid:
```bash
curl -X POST -H "Authorization: Bearer $WARDEN_TOKEN" \
  $WARDEN_ADDR/v1/slack/role/slack-user/gateway/auth.test
```

### Publishing a channel canvas

A canvas is the right format for long, formatted text published to a
channel (a `.md` file upload renders as a download blob with no
formatting; a canvas renders Markdown natively). A channel can hold
at most one canvas, so replace any prior one. Four calls in order:

1. **Check for an existing canvas** — `conversations.info` reads
   `.channel.properties.canvas.file_id`:
   ```bash
   EXISTING=$(curl -sSf -X POST -H "Authorization: Bearer $WARDEN_TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"channel":"C01ABC123"}' \
        $WARDEN_ADDR/v1/slack/role/slack-user/gateway/conversations.info \
     | jq -r '.channel.properties.canvas.file_id // empty')
   ```

2. **Delete the prior canvas** (if any) — `canvases.delete`:
   ```bash
   if [ -n "$EXISTING" ]; then
     jq -n --arg id "$EXISTING" '{canvas_id:$id}' \
       | curl -sSf -X POST -H "Authorization: Bearer $WARDEN_TOKEN" \
              -H "Content-Type: application/json" --data @- \
              $WARDEN_ADDR/v1/slack/role/slack-user/gateway/canvases.delete
   fi
   ```

3. **Create the new canvas** — `conversations.canvases.create`. Pipe
   the report body via `jq --rawfile` so the markdown never
   re-enters the agent's context:
   ```bash
   jq -n --arg ch "C01ABC123" \
         --arg title "Report — $(date -u +%Y-%m-%d)" \
         --rawfile md report.md \
         '{channel_id:$ch, title:$title,
           document_content:{type:"markdown", markdown:$md}}' \
     | curl -sSf -X POST -H "Authorization: Bearer $WARDEN_TOKEN" \
            -H "Content-Type: application/json" --data @- \
            $WARDEN_ADDR/v1/slack/role/slack-user/gateway/conversations.canvases.create
   ```

4. **Notify the channel** — `chat.postMessage`. The canvas is pinned
   in the channel header but a short message draws attention:
   ```bash
   jq -n --arg ch "C01ABC123" '{channel:$ch, text:"Report updated."}' \
     | curl -sSf -X POST -H "Authorization: Bearer $WARDEN_TOKEN" \
            -H "Content-Type: application/json" --data @- \
            $WARDEN_ADDR/v1/slack/role/slack-user/gateway/chat.postMessage
   ```

The Slack app's bot needs the `canvases:write`, `channels:read`, and
`chat:write` scopes for this sequence. **Do not invent shortcut method
names** like `canvas.set` or `canvas.update` — they don't exist on the
Slack Web API. The four above are the real ones.

### Using SDK clients

For the `@slack/web-api` (Node) or `slack_sdk` (Python) clients:
point the `slackApiUrl` / `base_url` at
`$WARDEN_ADDR<mount-url>role/<role>/gateway` and supply your JWT as the
auth token instead of an `xoxb-` token.

## Quirks

- **Everything is POST** — Slack's Web API does not use REST verbs.
  Even read-style methods like `conversations.list` and `users.info`
  are `POST`. Send `Content-Type: application/json` (or
  `application/x-www-form-urlencoded` if you prefer Slack's legacy form).
- **HTTP 200 ≠ success.** Slack returns 200 even on errors and signals
  failure in the JSON body's `ok` field. Always check `ok`; on `false`,
  read `error` (e.g. `not_in_channel`, `channel_not_found`,
  `missing_scope`).
- **Channel can be name or ID.** `#general` works for some methods,
  but channel IDs (`C01ABC123`) are more reliable across `chat.*`,
  `conversations.*`, and `reactions.*`.
- **Policies can restrict request body fields.** Warden parses the
  Slack request body, so an operator's policy may allow only certain
  `channel`, `text`, or `as_user` values. If a request is rejected
  before reaching Slack, the error comes from Warden, not Slack.
- **Bot tokens are static.** Slack bot tokens (`xoxb-…`) do not
  auto-rotate; the operator rotates them out-of-band via the Slack
  App settings. Your agent does not need to handle token refresh.
- **Rate limits propagate from Slack.** Warden does not retry; back
  off when you see `429` with a `Retry-After` header, or `ok:false`
  with `error:"ratelimited"`.
