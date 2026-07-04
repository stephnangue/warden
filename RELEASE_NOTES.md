## Warden v0.17.0

v0.17.0 is the CEL release. Capability-Based Policy gains one expressive predicate layer: a path rule can carry a **`condition`** (evaluated once per request) and an `mcp { }` block a **per-call `condition`** (evaluated once per tool call) — a [CEL](https://cel.dev) expression over a fixed `request.*` / `token.*` / `now` / `call.*` namespace, with helpers for CIDR matching (`cidrContains`), optional arguments (`call.args.?x.orValue(d)`), and timezone-aware time (`now.getHours(tz)`, `now.getDayOfWeek(tz)`). Evaluation is **fail-closed** and **cost-bounded**, conditions are compiled once and identity-independent, and every decision is **explainable in the audit log** (the expression and the exact input values it read). CEL replaces — and this release **removes** — the three structured mechanisms it subsumes: the `conditions {}` block, MCP `allowed_params`/`denied_params`, and CBP request-body `*_parameters`. Alongside it, **login-derived token metadata** lands across all four auth methods (feeding `token.metadata.*` in conditions), a new generic **`rest` provider** proxies arbitrary JSON/REST upstreams, and the documentation is substantially restructured and expanded (including a 20-example CEL cookbook). Three breaking changes — read **Upgrading** before bumping.

### Breaking Changes

- **The structured `conditions {}` block is removed — express it as a CEL `condition`.** Its four predicates map directly: `source_ip` → `cidrContains("10.0.0.0/8", request.client_ip)`, `time_window` → `now.getHours(tz)` / `now.getMinutes(tz)`, `day_of_week` → `now.getDayOfWeek("UTC")` (0 = Sunday), `token_metadata` → `token.metadata.<key>`. The parser rejects the block with a directed error.

- **MCP `allowed_params` / `denied_params` are removed — express them as a per-call `condition` over `call.args`.** e.g. `condition = "call.args.amount <= 1500 && call.args.currency in ['USD','EUR']"`. Semantics change deliberately: a condition is fail-closed (absent argument → deny), whereas the old lists let an absent argument pass — use `call.args.?x.orValue(d)` where "absent is OK".

- **CBP request-body `required_parameters` / `allowed_parameters` / `denied_parameters` are removed — express them as a `condition` over `request.data`.** `has(request.data.owner)` requires a field, `request.data.tier in ['gold','silver']` constrains a value, `!has(request.data.internal)` forbids one. Pagination (`pagination_limit`) and list-response filtering are unchanged. The parser rejects the removed keys.

### New Features

- **CEL policy conditions.** Path-level and per-call `mcp { }` conditions over `request.*` (incl. the new `request.namespace`), `token.*`, `now`, and `call.*`; helpers `cidrContains`, optional types, and the timezone-aware `now.get*` built-ins. Fail-closed and cost-bounded (type-checked and cost-limited at write time; a runtime cost limit backstops size-dependent expressions). A path-level condition that references `call.*` is a compile-time error. See the [CEL condition cookbook](https://github.com/stephnangue/warden/blob/main/docs/concepts/cel-conditions.md).

- **Login-derived token metadata across `jwt`, `cert`, `kubernetes`, and `spiffe`.** Per-role `metadata_claims` (claims, incl. nested via JSON Pointer) or `metadata_mappings` (certificate fields, TokenReview attributes, SPIFFE-ID components) map verified identity attributes onto the token; `token.metadata.<key>` is then usable in conditions and attributed in audit.

- **Explainable audit for CEL decisions.** `auth.policy_results.condition` records the expression, decision, a sanitized error category, and the referenced `inputs` — logged in clear by default and HMAC-salt-able per key via `salt_fields`.

- **Generic `rest` provider.** A REST/HTTP reverse-proxy backend for JSON/REST APIs without a dedicated provider, with a Warden-injected credential.

### Upgrading

Rewrite any policy that used the removed structured mechanisms as a CEL `condition`:

- `conditions { source_ip = ["10.0.0.0/8"] }` → `condition = "cidrContains('10.0.0.0/8', request.client_ip)"`
- `conditions { token_metadata = { env = ["prod"] } }` → `condition = "token.metadata.env == 'prod'"`
- MCP `allowed_params { amount = ["<=1500"] }` → `mcp { condition = "call.args.amount <= 1500" }` (add `call.args.?amount.orValue(0) <= 1500` if an absent argument should still pass)
- CBP `required_parameters = ["owner"]` → `condition = "has(request.data.owner)"`

The parser rejects each removed construct at policy-write time with an error naming its CEL equivalent, so a stale policy fails fast on `warden policy write` rather than changing behaviour silently.
