---
title: "Upgrading from v0.19.0"
description: "Breaking changes to migrate when moving off v0.19.0 — the agent CEL namespace, first-class MCP policies, dual-token extraction, and three driver changes."
---

Eight changes since **v0.19.0** need action on upgrade — more, and sharper, than the last
release. Two of them can take a working deployment down if you roll the binary out first
and migrate afterwards, so read **Before you upgrade** before doing anything else.

## Before you upgrade

**1. Export every policy that uses a `token.*` condition.** The `token` CEL namespace is
gone (see §1). A stored policy is re-parsed every time it is read, and a parse failure is
returned as an error rather than skipped — so after the upgrade a policy carrying
`token.*` **cannot be read back**, and you cannot recover its text from Warden to migrate
it. Export first:

```bash
for name in $(warden policy list); do
  warden policy read "$name" > "policy-backup-$name.hcl"
done
```

**2. Snapshot your audit device config.** The `salt_fields` selectors move with the
rename (§1). A stale selector does not error — it silently stops matching, and the value
it was protecting **begins logging in clear**.

```bash
warden audit list > audit-backup.txt
```

**3. Drain OVH leased credential pairs.** Credentials minted by the removed OVH mint
methods keep their lease ids and will not be cleaned up after the upgrade (§8).

## 1. The `token` CEL namespace is now `agent`

The `token` namespace is **removed outright** — there is no deprecated alias. Policy
conditions describe two principals now, so the namespace is named for the one it means:
`agent` (the workload) and `user` (the human it may be acting for).

Six fields carry over unchanged under the new name; three take a `token_` prefix, because
`agent.type` would have read as the *agent's* type rather than its token's:

| Before | After |
|---|---|
| `token.principal` | `agent.principal` |
| `token.role` | `agent.role` |
| `token.namespace` | `agent.namespace` |
| `token.policies` | `agent.policies` |
| `token.metadata.<key>` | `agent.metadata.<key>` |
| `token.actors` | `agent.actors` |
| `token.type` | `agent.token_type` |
| `token.ttl_seconds` | `agent.token_ttl_seconds` |
| `token.expires_at` | `agent.token_expires_at` |

```diff
- condition = "token.role == 'deployer' && token.metadata.env == 'prod'"
+ condition = "agent.role == 'deployer' && agent.metadata.env == 'prod'"
```

A condition that still references `token` fails to compile with a directed error naming
the replacement, both when you write the policy and when Warden loads it:

```
undeclared reference to 'token' (the `token` namespace was renamed to `agent`: ...)
```

**Audit `salt_fields` selectors move too.** This is the quiet one. A selector that named
`token.metadata.env` does not error after the upgrade — it simply matches nothing, and the
field it was salting is written to the audit log unprotected. Rewrite every selector:

```diff
- salt_fields = ["token.metadata.env", "token.type"]
+ salt_fields = ["agent.metadata.env", "agent.token_type"]
```

:::caution[There is no alias]
Early design drafts proposed keeping `token` as a deprecated alias for one release. That
is **not** what shipped. Plan for a hard cut.
:::

## 2. Dual-token extraction; `user_token_header` retired

Warden now extracts two credentials from a request — the agent's and, on mounts
configured for it, the end user's. Three consequences:

- **`X-Warden-User-Token` and the `user_token_header` config key are retired.** A
  persisted `user_token_header` loads with an *"ignoring retired user_token_header config
  key"* warning and is ignored; it is not rejected on write. Remove it from your mount
  configs at your convenience — but note the header itself is no longer read, so anything
  depending on it stops working at upgrade.

- **The agent can now arrive out of band on a user-auth mount.** On a mount with
  `user_auth_path` set, `Authorization` carries the **user**, and the agent presents
  either a client certificate or the new **`X-Warden-Agent-Token`** header. If you have
  agents sending their own token in `Authorization` under an ambient client cert on such
  a mount, that request now resolves to the *certificate* identity — move those agents to
  `X-Warden-Agent-Token`.

- **`user_auth_path` is read from the mount only.** It is no longer picked up from
  namespace metadata, so a deployment that set it once at the namespace level loses the
  user leg on every mount. Re-set it per mount (a config write is a partial update — the
  keys you omit keep their current values):

  ```bash
  warden write github/config <<EOF
  {
    "user_auth_path": "auth/user-oidc/"
  }
  EOF
  ```

Sending both `X-Warden-Token` and `Authorization` to a protected-resource mount is now a
`400`.

## 3. MCP rules are a first-class policy type

MCP authorization has moved out of capability policies into its own policy type, stored
separately at `sys/policies/mcp/<name>`. **An `mcp { }` block inside a capability policy's
`path` stanza is now rejected at parse**, with an error pointing at the new location.

Effective access is the intersection: a request must pass the capability policy **and**
every MCP policy in scope. MCP policies are purely restrictive — they cannot grant access
a capability policy withholds.

The grammar changed with the move, from `allowed_*`/`denied_*` keys to family blocks:

```diff
- # capability policy — no longer parses
- path "mcp/gateway/github/*" {
-   capabilities = ["create", "update"]
-   mcp {
-     allowed_methods = ["tools/list", "tools/call"]
-     allowed_tools   = ["get_repository"]
-     denied_tools    = ["delete_*"]
-   }
- }
```

Split it into two documents. The capability policy keeps the path and its capabilities:

```hcl
path "mcp/gateway/github/*" {
  capabilities = ["create", "update"]
}
```

…and the MCP contract becomes its own policy, written with `-type mcp`:

```bash
warden policy write -type mcp github-tools - <<'EOF'
path "mcp/gateway/github/*" {
  methods { allowed = ["tools/list", "tools/call"] }
  tools {
    allowed = ["get_repository"]
    denied  = ["delete_*"]
  }
}
EOF
```

Every policy subcommand takes the flag, defaulting to `cbp`:

```bash
warden policy read   -type mcp github-tools
warden policy list   -type mcp
warden policy delete -type mcp github-tools
```

Policy names are unique across both types, so an MCP policy cannot share a name with a
capability policy.

**Argument constraints are now CEL.** The `allowed_params` / `denied_params` keys are
removed and rejected at write. Express the same restriction as a `condition` over
`call.args`:

```diff
- allowed_params = { env = ["staging", "dev"] }
+ condition = "call.args.?env.orValue('') != 'prod'"
```

## 4. MCP traffic is deny-by-default

An MCP-shaped request on a path with **no MCP policy in scope is now denied** (rule
`no_mcp_policy`). Previously it passed unrestricted. Any mount you intend to leave open
needs an explicit wildcard MCP policy:

```bash
warden policy write -type mcp mcp-open - <<'EOF'
path "mcp/gateway/*" {
  methods   { allowed = ["*"] }
  tools     { allowed = ["*"] }
  resources { allowed = ["*"] }
  prompts   { allowed = ["*"] }
}
EOF
```

The session-lifecycle methods `initialize`, `ping`, `notifications/*`, and `server/discover`
are **exempt** — they pass without being allow-listed, so the client handshake and the
2026-07-28 revision's discovery RPC work without a policy. An explicit `denied` entry
still blocks them.

## 5. MCP mount `timeout` now defaults to 60 seconds

On the `mcp` and `mcp_aws` providers, the mount `timeout` default drops from **10 minutes
to 60 seconds**, and its meaning tightens: it now caps a *single* call rather than the
whole session. This applies to **newly created mounts** — existing mounts keep their
stored value.

Streaming subscriptions are no longer governed by `timeout`. `subscriptions/listen` and
the legacy SSE GET answer to the new **`listen_timeout`**, which defaults to the previous
10 minutes — so a long-lived SSE session keeps working without action.

Long-running *single* tool calls are the case that breaks. Set both explicitly on any new
mount that needs them:

```bash
warden write mcp/config <<EOF
{
  "timeout": "5m",
  "listen_timeout": "15m"
}
EOF
```

## 6. `apikey` sources rename `optional_metadata` to `credential_fields`

The `apikey` source key `optional_metadata` is renamed to `credential_fields`. The old
name is **rejected on write** with an error naming the new one; there is no alias.

```diff
- warden cred source update my-datadog -config=optional_metadata=application_key
+ warden cred source update my-datadog -config=credential_fields=application_key
```

The mechanism also works now, where before the declared fields were dropped before
reaching the provider. Adjunct fields declared by the source are carried into the
credential data, which makes Datadog's `application_key` and Atlassian's `email` reachable
for the first time — so a spec that looked correct under the old name may behave
differently (correctly) once renamed.

## 7. IBM `iam_with_cos` is removed

The IBM `iam_with_cos` mint method is gone. It bundled two unrelated credentials into one
spec; split it into a bearer spec and an `access_keys` spec that sources the COS HMAC pair
by chaining:

```bash
warden cred spec create ibm-bearer \
  -source=my-ibm \
  -config=mint_method=iam_token

warden cred spec create ibm-cos \
  -source=my-ibm \
  -config=mint_method=access_keys \
  -config=secret_spec=cos-hmac-in-vault
```

## 8. OVH `dynamic_s3` and `oauth2_token_and_s3` are removed

Both OVH mint methods are gone, along with the source's `api_url` key and the regional S3
API base URLs. Replace them with `access_keys`, which serves a pair held elsewhere:

```bash
warden cred spec create ovh-s3 \
  -source=my-ovh \
  -config=mint_method=access_keys \
  -config=secret_spec=ovh-keys-in-vault
```

`access_keys` serves an existing pair rather than minting one, so revocation is a no-op
and no leases are issued. **Drain any credentials minted by the removed methods before
upgrading** — they keep their lease ids and will not be deleted afterwards.

---

## Behavior changes that need no migration

These are not breaking, but they change what you will observe in production.

- **A policy denial that a user could remedy now answers `401`, not `403`.** When a path
  condition references `user.*` and denies because no user was presented, Warden returns
  `401` with a `WWW-Authenticate: Bearer` challenge carrying a `resource_metadata`
  parameter, so a client knows where to authenticate. A retry that presents a user and
  still fails gets a terminal `403` — the exchange cannot loop.

- **`cas_required` is enforced.** The policy-store `cas_required` setting was previously
  never applied on the write path. It now is, and a check-and-set refusal answers `4xx`
  instead of `500`. A deployment that set it and relied on writes succeeding anyway will
  start seeing conflicts.

- **Denied requests are audited once.** A denial previously produced two `type: "response"`
  entries per request id.

- **Responses longer than 10 seconds survive.** A hardcoded 10s write timeout severed
  every response that took longer, which no LLM provider mount could ever satisfy. The
  listener now exposes `http_read_timeout` (5s), `http_write_timeout` (10s), and
  `http_idle_timeout` (1m), and streaming and gateway traffic sheds the deadlines
  entirely.

See [CEL Conditions](/concepts/cel-conditions/) for the rewritten condition cookbook,
[MCP](/concepts/mcp/) for the policy type, and [Delegation](/concepts/delegation/) for the
user principal.
