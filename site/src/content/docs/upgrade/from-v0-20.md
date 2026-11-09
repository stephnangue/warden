---
title: "Upgrading from v0.20.0"
description: "Breaking changes to migrate when moving off v0.20.0 — the delegation-shaped default assertion, role fields and read_skill, skill names, MCP refusals, Azure Key Vault specs, GitHub token scope, and two config-write changes."
---

Nine changes since **v0.20.0** need action on upgrade. None of them destroys state the
way v0.20.0's policy rename could, but two fail **closed at mint** — Azure
`key_vault_secret` specs and GitHub specs that still say `repository` — and one changes
the claims an upstream verifier sees, so read **Before you upgrade** first.

## Before you upgrade

**1. Find every verifier bound to the old `default` assertion claims.** Wherever Warden
federates — a Vault or OpenBao JWT role, a GCP workload identity provider, an Azure
federated credential, an AWS trust policy, a CEL rule on a downstream Warden — note which
claims it reads. Anything that reads `warden_sub`, `warden_auth_mount`, `warden_user`, or
an agent-level `warden_namespace` must change (§1). A trust that binds only the agent's
composite `sub` keeps matching unchanged.

**2. List the roles agents discover.** Every role an agent finds through the discovery
server needs `provider_path` after the upgrade, or it is listed without a URL (§2):

```bash
warden role list -o json
```

**3. List Azure `key_vault_secret` specs and GitHub specs that set `repository`.** Both
stop minting at the upgrade (§6, §7). Moving them first avoids an outage:

```bash
warden cred spec list -o json
```

**4. Behind a load balancer, add it to `trusted_proxies`.** Forwarding headers —
`X-Forwarded-For`, `X-Real-IP` and `X-Request-Id` — are now honoured only from a trusted
proxy. Without the entry, every client IP resolves to the balancer, which IP-bound tokens
and `request.client_ip` conditions then see. See
[Listener](/configuration/listener/).

**5. Add internal hosts to `NO_PROXY`.** Sources with `ca_data` or `tls_skip_verify`, and
the Kubernetes auth method with a CA certificate, now honour `HTTPS_PROXY`, `HTTP_PROXY`
and `NO_PROXY`. A proxy set in Warden's environment will start carrying their traffic.

## 1. The `default` assertion profile is an RFC 8693 delegation token

The assertion Warden mints for keyless federation and chaining has a new default shape.
It depends on whether the spec **discloses a user** — lists `assertion_user_claims`, on a
source whose verifier can bind more than `iss`, `sub` and `aud`.

**No user disclosed** — the top level is the agent, as before:

| Claim | Before | After |
|---|---|---|
| `sub` | composite `wid:…` | unchanged, byte for byte |
| `warden_role` | the agent's role | unchanged |
| `warden_metadata` | opt-in | unchanged |
| `warden_namespace` | the agent's namespace | **removed** — the composite `sub` carries it |
| `warden_sub`, `warden_auth_mount` | present | **removed** |

**User disclosed** — the token names the user, and the agent acting for them:

| Claim | Meaning |
|---|---|
| `sub` | the **user's** id, as their IdP asserted it |
| `warden_namespace` | the namespace path — bind it **together with** `sub` |
| `warden_role` | the auth role the user's token was validated under |
| `warden_metadata` | the user's projected claims |
| `act` | the **agent**: its composite `sub`, `iss` (Warden), `warden_role`, `warden_metadata` |

`warden_user` is gone: the user is the top level now.

A verifier that bound the agent's composite `sub` alone keeps matching when no user is
disclosed. One that read the user from `warden_user`, or the agent from the top-level
`sub` of a delegation spec, must move — read the user from `sub` plus
`warden_namespace`, and the agent from `act.sub`. See
[Assertion claims](/federation/assertion-claims/).

## 2. `get_skill` is removed; roles carry `skill` and `provider_path`

The discovery server's `get_skill` tool is gone. Agents read a skill with
`read_skill(uri)`, passing the `skill://<name>/SKILL.md` URI that `list_roles` returns
for each role.

What a role is for moves out of its description and into two fields, on the jwt, cert,
kubernetes and spiffe auth methods:

- **`provider_path`** — the mount the role is used with, such as `vault/`. The discovery
  server derives the role's URL from it.
- **`skill`** — the skill that teaches an agent to use the role. It defaults to the skill
  of the provider at `provider_path`, so most roles never set it.

The convention of writing `(skill: …, url: …)` into the description is retired; a
description is plain prose again. **Backfill `provider_path`** on every role agents
discover — until you do, `list_roles` shows it with no URL and no skill:

```bash
warden write auth/jwt/role/read-secret provider_path=vault/
```

The write updates only the fields it names.

## 3. Skill reads on the discovery server are identity-bound

`read_skill`, and the MCP Skills extension's `skills/list`, `skills/get` and `skill://`
resources, return only the skills reachable from the roles the calling identity can
assume — each role's skill, the shared skills, and what those declare in `requires`. An
agent that read an unrelated skill before now gets *not found*. The `sys/skills` API and
`warden skill` are unchanged.

## 4. Skill names follow the Agent Skills rule

A skill name is lowercase letters, digits and single hyphens, with no leading or trailing
hyphen, at most 64 characters — no underscore. At the first unseal after the upgrade,
every stored skill whose name carries an underscore is renamed, hyphens for underscores,
and `requires` entries that name it follow. That includes two built-in skills:

| Before | After |
|---|---|
| `mcp_aws` | `mcp-aws` |
| `ansible_tower` | `ansible-tower` |

A rename that would collide with an existing skill, or still break the rule, is left in
place and logged for you to resolve. Provider **type** names do not change — the
`mcp_aws` provider is still `mcp_aws`. Update scripts and agents that name a skill with
an underscore; for new skills, `<provider>-<purpose>`, such as `aws-s3-read-only`, is the
convention.

## 5. MCP refusals are JSON-RPC errors

When Warden refuses an MCP call, it now answers with a JSON-RPC error — code `-32090`,
echoing the call's `id` — so the client's session survives and the next call goes
through. The status stays `403`, and the `WWW-Authenticate` challenge is unchanged.

```diff
- {"error": "insufficient_permissions", "error_description": "…"}
+ {"jsonrpc": "2.0", "id": 7, "error": {"code": -32090, "message": "…",
+   "data": {"error": "insufficient_permissions", "error_description": "…"}}}
```

Anything that parsed the old top-level fields reads them from `error.data`. See
[MCP](/provider-backends/mcp/).

## 6. Azure `key_vault_secret` specs fail every mint

`mint_method=key_vault_secret` is replaced by **`secret_read`**, which reads a Key Vault
secret — and can be federated, so the chain is keyless. A stored `key_vault_secret` spec
fails at mint; recreate it with `secret_read`. Writes now also refuse
`azure_db_iam_token`, `scopes`, and a `client_id` or `tenant_id` that is not a UUID. See
[Azure](/credential-drivers/azure/).

## 7. GitHub's singular `repository` is refused

App installation tokens are scoped by **`repositories`** — a list of bare repository
names, at most 500 — and **`permissions`**, as `name:level` pairs. The singular
`repository` key is refused on write, and a stored spec that carries it **fails at mint**.
An update merges into the stored config, so clear the old key in the same write:

```bash
warden cred spec update ci-reader -json '{
  "config": {
    "repository": "",
    "repositories": "api,web",
    "permissions": "contents:read,issues:read"
  }
}'
```

A stored `permissions` value used to be ignored, so the token covered the whole
installation; it is now enforced, and a spec may mint a narrower token than before.
Narrowing reaches a caller holding a cached token when that token expires, within the
hour. A `local`-source `github_token` spec cannot be narrowed — a static token is what it
is — and keeps minting. See [GitHub](/credential-drivers/github/).

## 8. New AWS and Azure federated specs choose their assertion profile

A **new** AWS federated spec is written with `assertion_profile=aws`, which carries the
role and projected metadata as session tags; the role's trust policy needs
`sts:TagSession`. A **new** Azure federated spec is written with `minimal`, the
registered claims Entra matches exactly. Existing specs keep `default`. To create a spec
in the old shape, set `assertion_profile=default` on it. See
[Assertion claims](/federation/assertion-claims/).

## 9. AWS and Alibaba Cloud config writes merge

A config write to an `aws` or `alicloud` mount now keeps every key it does not name.
Scripts that relied on a partial write to reset a key must name it — for example
`tls_skip_verify=false`, `ca_data=""` or `timeout=30s`.

## Behavior changes that need no migration

- **A mint the upstream refuses answers `403`**, not `500`; an unreachable upstream
  answers `503`.
- **A provider or auth-method config write takes effect only once saved.** A refused
  write changes nothing. Vault, Azure and GCP config must carry `auto_auth_path` in the
  same write as the settings it goes with.
- **Every write that leaves a secret stored in Warden now warns.**
  `keyless_enforcement_level`, in the server configuration, defaults to `warn`; set
  `enforce` to refuse such writes, or `off` to silence them. It is read at startup, so a
  change takes a restart — and under `enforce`, any edit to an object that still stores a
  secret is refused until the secret is gone, though deleting it always works. See
  [Keyless credentials](/federation/keyless-credentials/).
- **Warden's own failures arrive in the upstream's error shape** on AWS, OpenAI and
  Anthropic mounts, with the same status as before, and a mount timeout answers `504`
  rather than an empty `200`.
- **`application/jsonl` bodies are no longer parsed** for policy.
- **Dev mode in the container image listens on `0.0.0.0:8400`.** Publish it as
  `-p 127.0.0.1:8400:8400`, or keep it on the container's loopback with
  `-dev-listen-address=127.0.0.1:8400`.
