---
name: openai
description: "Call the OpenAI API through Warden — chat, embeddings, moderation — without holding an OpenAI API key."
category: provider-guide
provider: openai
requires: []
upstream: OpenAI REST API (api.openai.com)
---

# OpenAI through Warden

## What it does

Warden proxies OpenAI REST API requests. The agent calls a Warden
URL; Warden authenticates the caller (JWT/cert), looks up the OpenAI
API key bound to the chosen role, injects `Authorization: Bearer <key>`
plus optional `OpenAI-Organization` and `OpenAI-Project` headers,
and forwards. The agent **never holds an API key**.

## Configure the CLI/SDK

`<gateway-url>` is the `url` of the role you chose, as returned by the
`list_roles` discovery tool. Prepend `$WARDEN_ADDR` (the address you already
used to discover your roles). Each role has its own `url`: to act under a
*different* role, use that role's `url`.

Present your identity on every call: `Authorization: Bearer <jwt>`, or an mTLS
client certificate. A `401` means the JWT expired (typical TTL 5–60 min) —
refresh and retry.

```bash
URL pattern : $WARDEN_ADDR<gateway-url><openai-api-path>
Auth header : Authorization: Bearer <jwt>
```

The same shape as upstream OpenAI requests, just with the host swapped
out and a JWT instead of an API key.

### OpenAI SDK (Python)

```python
from openai import OpenAI
client = OpenAI(
    base_url=f"{WARDEN_ADDR}<gateway-url>",  # e.g. .../v1/openai/role/llm-app/gateway/
    api_key="<jwt>",                         # JWT, not an OpenAI key
)
```

### OpenAI SDK (Node)

```js
import OpenAI from "openai";
const client = new OpenAI({
  baseURL: `${process.env.WARDEN_ADDR}<gateway-url>`,  // e.g. .../v1/openai/role/llm-app/gateway/
  apiKey: "<jwt>",
});
```

## Examples

(Examples use a concrete `<gateway-url>` of `/v1/openai/role/llm-app/gateway/`;
substitute your role's `url`.)

Chat completion via `curl`:
```bash
curl -H "Authorization: Bearer <jwt>" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hi"}]}' \
  $WARDEN_ADDR/v1/openai/role/llm-app/gateway/chat/completions
```

Embeddings:
```bash
curl -H "Authorization: Bearer <jwt>" \
  -H "Content-Type: application/json" \
  -d '{"model":"text-embedding-3-small","input":"some text"}' \
  $WARDEN_ADDR/v1/openai/role/embeddings/gateway/embeddings
```

List models:
```bash
curl -H "Authorization: Bearer <jwt>" \
  $WARDEN_ADDR/v1/openai/role/llm-app/gateway/models
```

## Quirks

- **No `/v1` auto-prepend** (unlike Vault) — write the OpenAI path
  exactly as upstream documents it: `chat/completions`,
  `embeddings`, `models`, etc.
- **Request body parsing is enabled.** Operators may attach policies
  that inspect the JSON body (model name, max tokens, etc.) and
  reject requests that exceed configured limits — for example, a
  policy can restrict your role to a specific model list. Failures
  surface as `403 forbidden` with the policy reason.
- **Default 120s timeout.** Long generations close to the limit may
  fail at the proxy level; chunk requests with smaller `max_tokens`.
- **`OpenAI-Organization` / `OpenAI-Project` headers** are injected
  only when the operator configured them on the credential. Any you
  send are stripped, so you cannot override them per request.
- **Keyless roles send neither header.** A role backed by workload
  identity federation injects a short-lived token bound to one service
  account, whose organization and project are fixed by that binding.
- **Streaming responses (SSE)** pass through unchanged — usable from
  the OpenAI SDK's `stream=true` mode.
- **Warden's own failures use OpenAI's error shape.** A request Warden
  refuses itself (authentication, policy, credential) comes back as
  `{"error": {...}}` with a `code` starting `warden_` and a message
  starting `Warden: `. `warden_credential_refused` and
  `warden_permission_denied` will not succeed on retry: the role or
  its credential needs changing. Errors without the prefix are
  OpenAI's own.

