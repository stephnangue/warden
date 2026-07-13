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

`<gateway-url>` comes from the role you chose: the `list_roles` discovery tool
returns each role with a `description`, and for a non-MCP provider the operator
embeds the role's **gateway URL** in it — a relative path
`/v1/<namespace>/<mount>/role/<role>/gateway/`, with the namespace, mount, and role already baked in. Prepend `$WARDEN_ADDR` (the address you already
used to discover your roles).

The `role/<role>/` segment in `<gateway-url>` is the role this call runs under.
To act under a *different* role, use the `<gateway-url>` of that role from
`list_roles` — each role provides its own role-bearing URL in its description.

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
substitute the one from your role's `list_roles` description.)

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
  only when the operator configured them on the credential. You can
  also override per-request.
- **Streaming responses (SSE)** pass through unchanged — usable from
  the OpenAI SDK's `stream=true` mode.

