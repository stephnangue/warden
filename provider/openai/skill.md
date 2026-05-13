---
name: openai
description: "Call the OpenAI API through Warden — chat, embeddings, moderation — without holding an OpenAI API key."
category: provider-guide
provider: openai
requires: [foundation, discovery]
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

`<mount-url>` and `<role>` below come from the discovery flow:
- `<mount-url>` is the chosen provider's `mount_url` from
  `warden provider list` (e.g. `/v1/openai/`, `/v1/team-data/openai-prod/`).
  Warden has already baked the namespace + mount path in — append
  `role/<role>/gateway/<openai-api-path>` for transparent mode.
- `<role>` is the role you picked from `warden role list` to perform this
  task — it goes in the URL path.

```bash
URL pattern : $WARDEN_ADDR<mount-url>role/<role>/gateway/<openai-api-path>
Auth header : Authorization: Bearer $WARDEN_TOKEN
```

The same shape as upstream OpenAI requests, just with the host swapped
out and a JWT instead of an API key.

### OpenAI SDK (Python)

```python
from openai import OpenAI
client = OpenAI(
    base_url=f"{WARDEN_ADDR}{MOUNT_URL}role/llm-app/gateway",
    api_key=WARDEN_TOKEN,                  # JWT, not an OpenAI key
)
```

### OpenAI SDK (Node)

```js
import OpenAI from "openai";
const client = new OpenAI({
  baseURL: `${process.env.WARDEN_ADDR}${MOUNT_URL}role/llm-app/gateway`,
  apiKey: process.env.WARDEN_TOKEN,
});
```

## Examples

(All examples assume `mount_url = /v1/openai/`; substitute yours.)

Chat completion via `curl`:
```bash
curl -H "Authorization: Bearer $WARDEN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hi"}]}' \
  $WARDEN_ADDR/v1/openai/role/llm-app/gateway/chat/completions
```

Embeddings:
```bash
curl -H "Authorization: Bearer $WARDEN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"model":"text-embedding-3-small","input":"some text"}' \
  $WARDEN_ADDR/v1/openai/role/embeddings/gateway/embeddings
```

List models:
```bash
curl -H "Authorization: Bearer $WARDEN_TOKEN" \
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
  only when the operator configured them on the credential. You can
  also override per-request.
- **Streaming responses (SSE)** pass through unchanged — usable from
  the OpenAI SDK's `stream=true` mode.

