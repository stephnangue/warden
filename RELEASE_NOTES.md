## Warden v0.18.0

v0.18.0 is the on-behalf-of release. A new **`token_exchange` credential source** lets a Warden role broker an upstream call *as the agent acting for the end user* rather than as a static service identity: it exchanges a caller-presented token at an STS/IdP endpoint following [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693), with support for the `id_jag` cross-app-access flow, [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707) resource indicators, and `private_key_jwt` client authentication. The exchange is **verified-origin** — the subject and actor tokens are drawn from the agent's own verified inbound Warden JWT (or explicitly-supplied headers), and the caller-supplied exchange headers are stripped before the request reaches the upstream. Alongside it, an always-on **MCP discovery server** at `sys/mcp` lets an agent discover its roles and skills over MCP itself, and **MCP `tools/list` responses are pruned to the callable set** so discovery matches enforcement. One breaking change — MCP `mcp { }` authorization is now deny-by-default; read **Upgrading** before bumping.

### Breaking Changes

- **MCP `mcp { }` authorization is now deny-by-default.** An `mcp { }` block previously allowed anything it did not explicitly deny; it now **denies** anything it does not explicitly allow — an empty or absent `allowed_methods` / `allowed_tools` / `allowed_resources` / `allowed_prompts` denies every method/tool/resource/prompt in that family. This silently tightens deployed policies: `mcp { denied_tools = ["delete_*"] }` (or a block carrying only a `condition`) goes from "all tools except `delete_*`" to "**deny every tool**". The session-lifecycle methods `initialize`, `ping`, and `notifications/*` are exempt — they pass without being allow-listed (a `denied_methods` entry can still block them). Audit every `mcp { }` block before upgrading; see **Upgrading**.

### New Features

- **New `token_exchange` credential source — RFC 8693 on-behalf-of token exchange.** A source of type `token_exchange` mints an upstream access token by exchanging a caller-presented token at a `token_url`. `subject_token_source` / `actor_token_source` choose where the subject and actor tokens come from — `auth_token` reuses the agent's verified inbound Warden JWT (`verified` origin), `header` reads `X-Warden-Subject-Token` / `X-Warden-Actor-Token` (unverified), `none` omits it (the two sources can't both be `auth_token`). Selectable grants (`grant`): `rfc8693`, `jwt_bearer` ([RFC 7523](https://www.rfc-editor.org/rfc/rfc7523)), and `id_jag` (two-leg ID-JAG, needs `resource_token_url`). Client auth is `client_secret_basic`, `client_secret_post`, or `private_key_jwt`. Requested `audience`, `scope`, and RFC 8707 `resources` live on the spec; a header-sourced subject token is verified against a configured issuer/JWKS. The source issues an `oauth_bearer_token` credential, so any bearer-token provider (including the generic `mcp` provider) can carry it, and the caller-supplied exchange headers are stripped before forwarding upstream.

- **MCP discovery server at `sys/mcp`.** An always-on MCP endpoint exposes two tools: `list_roles` returns the roles the caller can assume (each naming the skill that drives it), and `get_skill` (argument `skill`) returns that skill as markdown. Namespace is selected with the `X-Warden-Namespace` header. This replaces the retired CLI-loop discovery skills.

- **MCP list responses are filtered to the callable set.** When a `tools/list`, `resources/list`, or `prompts/list` request is allowed, Warden prunes the response to only the items the caller could actually use — an item survives iff the corresponding `tools/call` / `resources/read` / `prompts/get` would pass policy (per-call `condition`s are deferred to call time). A batched request containing a list method is denied, and a list response that can't be buffered within `max_body_size` fails closed rather than streaming unfiltered.

### Upgrading

The MCP deny-by-default flip changes how existing `mcp { }` blocks behave. Audit every block and restore intended openness explicitly:

- Open everything, then subtract: `mcp { allowed_methods = ["*"], allowed_tools = ["*"], allowed_resources = ["*"], allowed_prompts = ["*"], denied_tools = ["delete_*"] }`
- A block that carried only a `condition` (or only `denied_*` lists) now denies its whole family — add the matching `allowed_* = ["*"]` to keep it open.
- You no longer need to allow-list the MCP handshake: `initialize`, `ping`, and `notifications/*` pass without being listed (block them explicitly via `denied_methods` if you must).

The change is enforced at request time, not policy-write time, so review blocks before upgrading rather than relying on a parse error to catch them.
