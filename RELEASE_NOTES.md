## Warden v0.21.0

v0.21.0 is the **first-experience** release. Trying Warden used to mean standing up an identity provider, finding an upstream key to hand it, and wiring a Compose stack before the first request — the better part of an hour before anything was governed. Now it is one command. **`warden server -dev-playground`** starts Warden with its own identity provider and a bank to protect, and a nine-scenario tour walks your own agent — Claude Code, Codex, Cursor, Gemini CLI, opencode, VS Code, or any MCP client — through what Warden does: the agent holds no secret, policy picks its tools and then its arguments, it acts for a person, a prompt-injected memo cannot move the money, every call is audited, it finds its own roles, and the tour ends on your own GitHub. Start at [Getting started](https://wardengateway.com/getting-started/).

Discovery grows up alongside it. A role now says what it is in structured fields — the **`skill`** to read and the **`provider_path`** it fronts — and `list_roles` hands the agent the URL to call and a `skill://` URI, read with **`read_skill`** or through the **MCP Skills extension**. What an agent can read is bound to who it is.

Keyless keeps widening: **Anthropic** and **OpenAI** federate, **Cloudflare** gets a keyless source, **Azure Key Vault** joins the chaining producers, and the default assertion becomes an **RFC 8693 delegation token** that names the user on top and the agent in `act`. A new **`keyless_enforcement_level`** warns — or refuses — when a write would leave a secret stored in Warden. And when Warden itself refuses a request, it now answers **in the upstream's own error shape**, so an AWS SDK, an OpenAI client or an Anthropic client reads the failure as it reads any other.

**Nine breaking changes — read Upgrading before you bump.**

### Breaking Changes

- **The `default` assertion profile is an RFC 8693 delegation token.** With a user disclosed, the top level is the user and the agent moves into `act`. `warden_sub`, `warden_auth_mount`, `warden_user` and the agent-level `warden_namespace` are gone; the agent's composite `sub` is unchanged, so agent-only trusts keep matching.
- **`get_skill` is removed** for `read_skill(uri)`, and the `(skill: …, url: …)` description convention gives way to the role fields `skill` and `provider_path`. Backfill `provider_path`, or a role is listed with no URL.
- **Skill reads on the discovery server are identity-bound.**
- **Skill names drop the underscore**: every stored skill with one is renamed at unseal — `mcp_aws` becomes `mcp-aws`, `ansible_tower` becomes `ansible-tower`.
- **MCP refusals are JSON-RPC errors** (`-32090`); the former `error` / `error_description` move under `error.data`.
- **Azure `key_vault_secret` specs fail every mint** — move them to `secret_read`.
- **GitHub's singular `repository` is refused**, and a stored `permissions` value is now enforced.
- **New AWS federated specs default to the `aws` profile** (session tags, needs `sts:TagSession`); new Azure federated specs default to `minimal`.
- **AWS and Alibaba Cloud config writes merge** — a key left out keeps its value.

### Security

- **Azure Key Vault URL injection closed**, and rotation no longer deletes live secrets.
- **MCP policy is enforced on every POST** to an MCP mount, whatever its `Content-Type`.

### New Features

**The playground**

- **`warden server -dev-playground`**, its identity provider, a bank with MCP and REST faces, and GitHub's MCP server waiting for your PAT.
- **`warden dev jwt | scenarios | audit`**, and the tour written out for seven agents — on the page, or with `warden dev scenarios -client`.

**Discovery and skills**

- **Structured role fields**, `list_roles` with a resolved provider, skill URI and URL, the **MCP Skills extension**, and `read_skill` returning the skill's markdown in its structured output.

**Keyless credentials**

- **Anthropic and OpenAI workload identity federation**, a **keyless Cloudflare source**, and **Azure Key Vault** as a chaining producer.
- **`assertion_profile`** — `default`, `minimal` or `aws` — and a per-spec **`assertion_ttl`**.
- **`keyless_enforcement_level`**, `stored_secrets` on every source and spec, and **`warden cred source|spec keyless-plan`** to describe the keyless replacement for one.
- **Public `token_exchange` clients**, and **GitHub App tokens scoped** by `repositories` and `permissions`.

**The gateway**

- **Native error shapes** for AWS, OpenAI and Anthropic, and a **`504`** — not an empty `200` — when a mount's timeout beats the upstream.
- **Policy reads request bodies on `rest` mounts**, up to the mount's `max_body_size`.
- **Anthropic** workspaces, version and beta headers governed from mount config, and user-profile attribution.
- **The audit log records the user's namespace, role and act chain.**

### Fixed

- **A mint the upstream refuses answers `403`**, not `500`.
- **A config write takes effect only once it is saved**; a refused write changes nothing.
- **Rotation activations no longer revert operator edits or orphan keys**, and source drivers are rebuilt after a node steps down.
- **Each credential client owns its connection pool**, so deleting one source no longer drops another's connections.

### Upgrading

Nine changes need action. Work through [Upgrading from v0.20.0](https://wardengateway.com/upgrade/from-v0-20/) before rolling out the binary.

- **Find every verifier bound to the old `default` claims** — a Vault JWT role, a GCP attribute condition, a CEL rule reading `warden_sub`, `warden_user` or `warden_auth_mount` — and rewrite it.
- **Backfill `provider_path`** on roles that relied on the description convention, and move agents from `get_skill` to `read_skill`.
- **Move Azure `key_vault_secret` specs to `secret_read`**, and GitHub specs from `repository` to `repositories`.
- **Behind a load balancer, list it in `trusted_proxies`**; and add internal hosts to `NO_PROXY`, which sources with a custom CA now honour.

A `local`-source `github_token` spec stored with `repositories` or `permissions` before this release keeps minting the unscoped token it holds; a static token cannot be narrowed. New writes are refused.
