---
title: "Upgrading from v0.21.0"
description: "Breaking changes to migrate when moving off v0.21.0 — auth roles replaced by namespace roles and groups, mount audiences, token types, reserved names, discovery under policy, MCP skills, host allowlists, one spelling for names and paths, credential sources, audit, nested namespaces and mixed-version clusters."
---

Twelve changes since **v0.21.0** need action on upgrade. The largest is the first: auth
roles are gone. After the upgrade, every path that held them answers `410 Gone`, so you
cannot read them back to convert them — **export them on v0.21.0**. Three more refuse
callers from the first request: agent jwt and spiffe mounts without `bound_audiences`,
providers that still name `user_auth_role`, and every token a v0.21.0 auth mount issued.
Read **Before you upgrade** first.

## Before you upgrade (on v0.21.0)

Run these against your v0.21.0 cluster, with the v0.21.0 CLI and a root token. The
commands use `jq`.

**1. Export every auth role and every auth mount config.** Each auth role becomes a
namespace role and a group (§1). After the upgrade `warden list auth/<mount>/role` and
`warden read auth/<mount>/role/<name>` answer `410`, and the CLI exits `11`.

```bash
mkdir -p v021-export
for mount in $(warden auth list -o json | jq -r '.[].path'); do
  name="${mount%/}"; name="${name//\//-}"
  warden read -o json "auth/${mount}config" > "v021-export/mount-${name}.json"
  for role in $(warden list -o json "auth/${mount}role" 2>/dev/null | jq -r '.keys[]?'); do
    warden read -o json "auth/${mount}role/${role}" > "v021-export/role-${name}-${role}.json"
  done
done
```

Run it once per namespace, with `-n <namespace>` on every command. Keep the mount
configs too: they hold `default_role`, `groups_claim` and the bindings a role relied on.

**2. List the agent jwt and spiffe mounts that set no `bound_audiences`.** After the
upgrade, an agent jwt mount without one admits no JWT, and an agent spiffe mount admits
no JWT-SVID (§2):

```bash
for mount in $(warden auth list -o json | jq -r '.[] | select(.type == "jwt" or .type == "spiffe") | .path'); do
  echo "$mount $(warden read -o json "auth/${mount}config" | jq -c '.bound_audiences // []')"
done
```

An empty list needs a value. Take it from the `bound_audiences` of the roles you exported
from that mount, and note any role `max_age` too: both are mount settings now.

**3. List the providers that set `user_auth_role`.** Such a provider refuses every user
credential after the upgrade (§1):

```bash
for mount in $(warden provider list -o json | jq -r '.[].path'); do
  role=$(warden read -o json "${mount}config" 2>/dev/null | jq -r '.user_auth_role // empty')
  [ -n "$role" ] && echo "$mount user_auth_role=$role"
done
```

**4. List the gcp and azure mounts that call hosts outside the defaults.** After the
upgrade they forward only to `allowed_host_suffixes` (§7). The audit log shows which
hosts they reach:

```bash
jq -r 'select(.request.mount_type == "azure" or .request.mount_type == "gcp")
       | .response.upstream_url // empty' /var/log/warden/audit.log \
  | awk -F/ '{print $3}' | sort -u
```

Anything outside `*.googleapis.com` on gcp, or outside the public Azure endpoints listed
in §7 on azure, needs adding.

**5. Find policy names written with uppercase letters.** Warden already stored them in
lowercase, so `warden policy list` shows none; what breaks is the script, pipeline or
role that names `Admin` (§8). Search them, and the roles you exported:

```bash
jq -r '.token_policies[]? | select(test("[A-Z]"))' v021-export/role-*.json | sort -u
```

**6. Save each audit device's `salt_fields` and `omit_fields`.** A path that matches no
audit field is now refused at enable and dropped at load (§10):

```bash
for dev in $(warden audit list -o json | jq -r '.[].path'); do
  warden audit read -o json "$dev"
done > v021-export/audit-devices.json
```

**7. Find what reads a token type by name.** SIEM queries on `auth.token_type`, and CEL
conditions on `agent.token_type` or `user.token_type`, see new names (§3):

```bash
for name in $(warden policy list -o text); do
  warden policy read -o table "$name" | grep -q token_type && echo "cbp: $name"
done
for name in $(warden policy list -type mcp -o text); do
  warden policy read -type mcp -o table "$name" | grep -q token_type && echo "mcp: $name"
done
```

**8. List the `hvault` credential sources.** Each needs `auth_method` before its next
edit, and an `http://` `vault_address` needs `tls_skip_verify` (§9):

```bash
for src in $(warden cred source list -o json | jq -r '.[] | select(.type == "hvault") | .name'); do
  warden cred source read -o json "$src" \
    | jq -c '{name, auth_method: .config.auth_method, vault_address: .config.vault_address}'
done
```

**9. Take a storage snapshot.** The upgrade rewrites no data in place, but it is the only
way back if you need one. On PostgreSQL:

```bash
pg_dump "$WARDEN_PG_CONNECTION_URL" --table=warden_kv_store \
  --format=custom --file=warden-v0.21.0.dump
```

A restore needs the same unseal keys or seal. See [Storage](/configuration/storage/).

**10. Write the conversion as a script, and rehearse it.** Between the moment a v0.22.0
node answers agent requests and the moment your groups exist, an agent no group grants a
role to is refused. Keep that window short: write every command of §1 and §2 as one
script, run it against a throwaway v0.22.0 dev server first
(`docker run --rm -p 127.0.0.1:8400:8400 ghcr.io/stephnangue/warden:v0.22.0 -dev -dev-root-token=root`),
read its warnings, then run it on the cluster as soon as every node is upgraded (§12).

## 1. Auth roles are removed; roles are granted per request by groups

A login now **admits** a credential: the auth mount verifies it, records what it verified
as **facts**, and picks one value as the caller's **native identity**. It takes no `role`.
The role is chosen on each request and granted by a **group**:

- a **role** lives in the namespace, at `sys/roles/<name>`. It names the policies, the
  credential spec, and how discovery describes it. See [Roles](/identity/roles/).
- a **virtual group**, at `sys/identity/group/<name>`, grants roles to the callers whose
  facts match one of its rules. Every rule names the auth mounts it trusts. See
  [Groups](/identity/groups/).

What goes away:

- Every operation under `auth/<mount>/role/` answers `410 Gone`. The CLI exits `11`.
- An auth mount config write carrying `default_role`, `groups_claim`,
  `group_policy_prefix`, `metadata_claims`, `metadata_mappings` or `token_type` is
  refused. A stored one is ignored, with a warning on read; the next config write removes
  it.
- The provider key `user_auth_role` is removed. A provider that still stores it refuses
  every user credential.
- A request that selects no role gets `400`; one with no credential gets `401`.

How agents select a role does not change: the `role/<role>/` segment of a gateway URL,
or `X-Warden-Role`. Keep each role's name when you convert it, and agent URLs keep
working. A role that started `warden-` needs another name (§4).

### Worked example: a GitHub Actions role on a jwt mount

On v0.21.0, `auth/jwt/` admitted GitHub Actions tokens, and its role `deploy-api` let the
`main` branch of `acme/api` deploy. The export from step 1 reads, trimmed to the fields
the conversion uses:

```json
{
  "description": "Deploys acme/api from main",
  "bound_audiences": ["https://warden.example.com"],
  "bound_claims": {
    "repository": "acme/api",
    "ref": "refs/heads/main"
  },
  "metadata_claims": {
    "environment": "env"
  },
  "max_age": "5m",
  "token_ttl": "15m",
  "token_policies": ["deploy-api"],
  "cred_spec_name": "deploy-api-aws",
  "provider_path": "aws/"
}
```

It becomes three writes, made once every node runs v0.22.0.

**The mount names its facts, its audience and its credential age.** A jwt mount publishes
`sub`, `iss` and `aud` on its own; every other claim a group matches, or a policy reads,
must be named in `facts`, a map of claim (or JSON Pointer, such as `/resource_access/env`)
to fact name. A config write keeps the keys it does not name, but **`facts` is replaced
whole**, so list the claims of every role on the mount in one write:

```bash
warden write auth/jwt/config '{
  "bound_audiences": ["https://warden.example.com"],
  "max_age": "5m",
  "token_ttl": "15m",
  "facts": {
    "repository": "repo",
    "ref": "ref",
    "environment": "env"
  }
}'
```

`max_age` and `token_ttl` now hold for every credential the mount admits. If its roles
set different values, use the shortest.

**The role carries the policies, the spec and the discovery fields:**

```bash
warden role create deploy-api -json '{
  "description": "Deploys acme/api from main",
  "policies": ["deploy-api"],
  "cred_spec_name": "deploy-api-aws",
  "provider_path": "aws/"
}'
```

**A virtual group grants it to the callers the role used to bind**, with one rule per
mount and one selector per claim:

```bash
warden identity group create acme-api-main -json '{
  "type": "virtual",
  "description": "GitHub Actions runs of acme/api on main",
  "roles": ["deploy-api"],
  "rules": [
    {
      "mount": ["auth/jwt/"],
      "repo": ["acme/api"],
      "ref": ["refs/heads/main"]
    }
  ]
}'
```

A caller must match one value of every selector in a rule, and any one rule of the group.
`*` and `?` are globs; `*` stops at `/` and `**` does not. A policy condition that read
`agent.metadata.env` keeps working: a mapped fact is what `agent.metadata` holds.

Check the result with `warden role read deploy-api` and
`warden identity group read acme-api-main`. The agent's next call to
`/v1/aws/role/deploy-api/gateway/…` is granted the role. `warden identity usage` shows how
much of the namespace's group and selector caps you have used.

### Field by field

| v0.21.0 auth role or mount key | v0.22.0 |
|---|---|
| `token_policies` | role `policies` |
| `cred_spec_name`, `description`, `skill`, `provider_path` | the role, same names |
| `bound_claims` | a mount `facts` entry per claim, and a selector per claim in the group rule |
| `bound_subject` | a `sub` selector in the rule |
| `bound_audiences` (role) | the mount's `bound_audiences`, or an `aud` selector in the rule to narrow it |
| `max_age`, `token_ttl` (role) | the mount's `max_age` and `token_ttl` |
| `metadata_claims`, `metadata_mappings` | mount `facts`; CEL reads them as `agent.metadata.<name>` |
| `groups_claim` with group-named policies | a fact for the groups claim, and a virtual group per IdP group whose rule matches it, granting a role that carries those policies |
| `default_role` (auth mount) | `default_role` on the provider, naming a namespace role |
| `token_type` | none: the auth method decides it (§3) |

A role bound on **several mounts** — `deploy` on `auth/jwt/` and on `auth/kubernetes/` —
becomes one role and one group with one rule per mount. If the two auth roles carried
different policies, give them different names.

### The other auth methods

The same three writes apply. Their built-in facts cover what roles used to bind:

| Method | v0.21.0 role binding | Selector in the rule |
|---|---|---|
| kubernetes | `bound_service_account_names` | `service_account_name` |
| kubernetes | `bound_service_account_namespaces` | `service_account_namespace` |
| cert | `allowed_common_names`, `allowed_dns_sans`, `allowed_email_sans`, `allowed_uri_sans` | `cn`, `dns_san`, `email_san`, `uri_san` |
| cert | `allowed_organizations`, `allowed_organizational_units` | `org`, `ou` |
| spiffe | `allowed_spiffe_ids` | `spiffe_id` (also `trust_domain`, `path`) |

A `"*"` that matched any value becomes no selector at all. Check each pattern against the
glob rules above: a SPIFFE ID or URI pattern that crossed `/` with `*` needs `**`.

```bash
warden identity group create ci-deployers -json '{
  "type": "virtual",
  "roles": ["deploy"],
  "rules": [
    {
      "mount": ["auth/kubernetes/"],
      "service_account_namespace": ["ci"],
      "service_account_name": ["deployer"]
    }
  ]
}'
```

Per-method facts are listed in [Authentication](/identity/authentication/).

### Providers that named `user_auth_role`

The user's token audience is now bound by the **user mount's `bound_audiences`**, else by
the provider's protected-resource identifier, else refused. Move the audience the old
role bound onto the user mount, and mark a mount that admits only people as human:

```bash
warden write auth/entra-users/config '{
  "entity_kind": "human",
  "bound_audiences": ["api://warden-graph"]
}'
```

Then make any config write to the provider; it never stores the removed key, so this
clears it. Rewriting its `user_auth_path` is enough:

```bash
warden write msgraph/config user_auth_path=auth/entra-users/
```

## 2. Agent jwt and spiffe mounts require `bound_audiences`; `max_age` is a mount setting

A mount that admits agents (`entity_kind` `agent`, the default) must bind an audience:

- **jwt** — a stored config without `bound_audiences` admits no JWT, and a config write
  that leaves it out is refused.
- **spiffe** — a stored config without one admits no JWT-SVID; X.509-SVIDs, which carry no
  audience, are still admitted. Any config write to an agent spiffe mount must carry it.

Credential age is bounded by the mount's `max_age` on jwt, kubernetes and spiffe
(JWT-SVIDs only), no longer by a role. Set both on each mount from step 2's list:

```bash
warden write auth/spiffe/config '{
  "bound_audiences": ["https://warden.example.com"],
  "max_age": "10m"
}'
```

A mount with `entity_kind` `human` is refused on the agent leg of a request; it admits
people only.

## 3. Token types are named by what they carry

| v0.21.0 | v0.22.0 |
|---|---|
| `jwt_role` | `identity_token` (IDs `wdi_`) |
| `cert_role` | `identity_token` |
| `kubernetes_role` | `identity_token` |
| `spiffe_role` | `identity_token` |
| `transparent` (display name) | `identity_token` |
| `warden_token` (values `cws.`, IDs `wtkn_`) | `service_token` (values `wds.`, IDs `wds_`) |

The names change in audit (`auth.token_type`) and in CEL (`agent.token_type`,
`user.token_type`). Update the queries and conditions step 7 found:

```diff
- condition = "agent.token_type == 'jwt_role'"
+ condition = "agent.token_type == 'identity_token'"
```

The type no longer says which auth method admitted a caller. To tell them apart, use the
group: `'ci-deployers' in agent.groups`.

**Tokens:**

- **Any token a v0.21.0 auth mount issued is refused.** Agents log in again; an agent
  that presents its JWT or certificate on every call is admitted again on its next one.
- **A `cws.` token no auth mount issued** — the root token from `warden operator init`, for
  one — resolves until it expires or is revoked. Every new service token is `wds.`, so
  rotate the old ones on your usual schedule.

A login's audit result no longer carries `role_name` or `credential_spec`: the role is
recorded on each request, under `auth.role_granted_by` and `auth.groups`. The Go client
packages `api/auth/jwt` and `api/auth/cert` are removed. See [Tokens](/identity/tokens/).

## 4. Reserved names

- **Policies:** `default` and every name starting `default-` are reserved, in both policy
  types. Two of them now ship built in (§5).
- **Roles:** names starting `warden-`, in any case, are reserved for the
  [built-in operator roles](/identity/built-in-roles/).

A policy an earlier release stored under a reserved name can still be read and deleted,
but no request is given it. Rename it, and update the roles that list it:

```bash
warden policy list -o text | grep -E '^default(-|$)'
warden policy read -o table default-ops > ops.hcl
warden policy write ops ops.hcl
warden policy delete default-ops
```

Give any auth role starting `warden-` another name when you convert it in §1, and update
the agents that put it in their URLs.

## 5. Discovery runs through the request path

`/v1/sys/mcp` and `sys/introspect/roles` are now authorized by policy and audited. Two
built-in policies in every namespace grant them: `default-cbp` and `default-mcp`. They
can be edited, never deleted; emptying one withdraws its grants.

- Every `sys/mcp` call needs a credential, except the session lifecycle, `tools/list`,
  `resources/templates/list`, `logging/setLevel` and `subscriptions/listen`. With none
  admitted the answer is HTTP `401`, or `503` when none was admitted and a mount could
  not decide — where v0.21.0 answered `200` with warnings.
- A batch of more than 50 messages is refused.
- Discovery streams end after one minute; clients reconnect.
- `/v1/<namespace>/sys/mcp` works by path, beside the `X-Warden-Namespace` header.

Present the agent's credential on every discovery call. If you edit the built-ins, keep
them granting the discovery paths:

```bash
warden policy read default-cbp
warden policy read -type mcp default-mcp
```

## 6. The MCP `resources` family covers `skills/get` and `resources/directory/read`

Both are now gated by URI, as `resources/read` is, and `skills/list` and listings are
pruned to what the caller could fetch. A contract that allows every method but grants no
resources now refuses them. Add a `resources` grant:

```hcl
path "mcp/gateway/*" {
  methods   { allowed = ["*"] }
  tools     { allowed = ["*"] }
  resources { allowed = ["skill://*"] }
}
```

Grant a skill by its folder, `skill://<name>/*`, rather than its `SKILL.md` alone. An
`Mcp-Name` header that disagrees with the body is a `header_mismatch` on every method that
names something. See [MCP](/concepts/mcp/).

## 7. gcp and azure forward only to `allowed_host_suffixes`; azure refuses Graph `$batch`

A request to a host outside the mount's list gets `403` before a token is attached. The
defaults:

- **gcp:** `.googleapis.com`.
- **azure:** `.management.azure.com`, `.graph.microsoft.com`, `.vault.azure.net`,
  `.blob.core.windows.net`, `.queue.core.windows.net`, `.table.core.windows.net`,
  `.file.core.windows.net`, `.dfs.core.windows.net`, `.openai.azure.com`,
  `.cognitiveservices.azure.com` and `.services.ai.azure.com`.

Each entry takes a leading dot, and `.example.com` allows `example.com` and every host
under it. **A list you set replaces the default**, so name every host the mount uses —
sovereign clouds, Azure Monitor, Azure DevOps, custom domains:

```bash
warden write azure/config '{
  "allowed_host_suffixes": [
    ".management.azure.com",
    ".graph.microsoft.com",
    ".vault.azure.net",
    ".dev.azure.com"
  ]
}'
```

An empty list restores the default. A Graph `$batch` through the azure provider gets
`400`: send the calls one by one, or move them to the msgraph provider. See
[Azure](/provider-backends/azure/) and [GCP](/provider-backends/gcp/).

## 8. Policy names and request paths have one spelling

- **Write policy names in lowercase.** A name that is not canonical, such as `Admin`,
  gets `400` on the policy endpoints, with the spelling to use:
  `policy name "Admin" is not canonical: use "admin"`. Fix the scripts step 5 found.
- **Send paths unencoded.** A percent-encoded `.`, `..` or empty path segment gets `400`.
  A dot inside a segment (`.github`, `repo.git`) is ordinary, and an encoded slash inside
  a segment is still allowed.
- **The upstream receives exactly the path the request was authorized on.** A client
  that double-encoded a slash (`%252F`) so the upstream would see `%2F` now sends `%2F`
  itself.
- **`X-Warden-Role` must be a valid role name**, or the request gets `400`.

## 9. Credential sources are held to their own config

- **`hvault` sources** build their client from their own config alone. An edit must set
  `auth_method`, and an `http://` `vault_address` needs `tls_skip_verify`. A source stored
  without `auth_method` keeps minting, with a warning, until you edit it. Set it on each
  source from step 8 — the keyless form holds no Vault credential:

  ```bash
  warden cred source update vault-prod -json '{
    "config": {
      "auth_method": "oidc_federation",
      "jwt_mount": "jwt",
      "jwt_role": "warden",
      "audience": "https://vault.example.com"
    }
  }'
  ```

  See [Vault](/credential-drivers/vault/).
- **A user principal beginning `wid:` is refused** with `403`: that prefix is reserved for
  agents.
- **Providers strip** Kubernetes `Impersonate-*`, Elastic `es-security-runas-user` and
  Warden's routing headers before forwarding.
- **A spec or source edit reaches live sessions on their next request**, not when the
  session ends.
- **An edit that would break a `secret_spec` reference is refused**, naming the spec that
  uses it.

## 10. Audit has a floor

- Request headers and bodies are no longer fields of an audit entry. A policy condition
  still records the values it read.
- `salt_fields` **extends** the default salting instead of replacing it: issued
  credentials are always salted. `omit_fields` has nothing left to drop from the
  default — the headers and bodies a custom list used to expose are no longer fields.
- A device with no HMAC key omits its salt paths instead of writing them in clear.
- `response.upstream_url` keeps the scheme, host, path and query keys; every query value
  reads `[redacted]`.
- A salt or omit path that matches no field is refused at enable. A stored device loads
  without it, with a warning.

Remove unknown paths from the configs step 6 saved, and re-enable those devices. Omitting
the old header and body paths is accepted and does nothing. See
[Audit](/configuration/audit/).

## 11. Nested namespaces written through an ancestor were misplaced

Before this release, a namespace created, updated or deleted by its full path from an
ancestor — `warden namespace create acme/dev` from root — had its record stored in the
ancestor's place instead of its parent's. A reload could then fail, or bring a deleted
namespace back. One created from its parent (`warden -n acme namespace create dev`) is
not affected.

**No repair ships.** Recreate the namespaces written that way, with their mounts, policies,
roles and groups. `warden namespace list -R` lists them all. From this release a nested
path works from any ancestor; a path with an empty, `.` or `..` segment gets `400`, and
one whose parent does not exist gets `400` instead of `500`.

## 12. Mixed-version clusters and cache capacity

- **Upgrade every node before writing roles, groups or entities**, and before the mount
  writes of §1 and §2. A v0.21.0 node knows nothing of them, and cannot decode a `PS256`
  signing capability a v0.22.0 node minted.
- **The token cache counts what tokens really cost.** At the default 100 MiB it holds
  about 113,000 service tokens, against about 409,000 at the old flat cost that
  undercounted them. Raise it on busy nodes, in the server configuration:

  ```hcl
  token_cache_megabytes      = 256
  credential_cache_megabytes = 128
  ```

  Both are read at startup. See [Configuration](/configuration/).

## Behavior changes that need no migration

- **Observe, then deny.** Every namespace starts in `observe`: no agent is refused for
  being unknown, and each request records in `auth.identity_status` why `deny` would
  refuse it. When you are ready, claim agents' native identities with entities in the
  identity store, give each a sponsor so it is governed, then switch to `deny`. See
  [Entities](/identity/entities/) and [Sponsors](/identity/sponsors/).
- **People sign in** with the new `oidc` auth method and `warden login`, and are granted
  roles by groups over their IdP's claims. See [Human operators](/identity/human-operators/).
- **Built-in operator roles** — `warden-admin`, `warden-provider-admin`,
  `warden-security-admin`, `warden-viewer` — exist in root, and in a namespace whose
  parent turns on `enable_builtin_roles`. No one holds them until a group grants them.
- **The seeded `troubleshooting` skill is not refreshed**, and neither is a provider skill
  seeded before the upgrade, such as `aws`, which now covers Bedrock Runtime. Take the
  v0.22.0 text from a throwaway dev server and update yours; the file holds the body
  without its frontmatter, which is what `-raw` prints:

  ```bash
  docker run --rm -d --name warden-ref -p 127.0.0.1:8410:8400 \
    ghcr.io/stephnangue/warden:v0.22.0 -dev -dev-root-token=root
  ref() { WARDEN_ADDR=http://127.0.0.1:8410 WARDEN_TOKEN=root warden "$@"; }
  ref provider enable aws
  ref skill read troubleshooting -raw > troubleshooting.md
  ref skill read aws -raw > aws.md
  docker stop warden-ref

  warden skill update troubleshooting -body-file troubleshooting.md
  warden skill update aws -body-file aws.md
  ```

  Skill updates need a root-namespace token. See [skill](/cli/skill/).
- **On an access path whose provider has `auto_auth_path`, operators send
  `X-Warden-Token`**, not `Authorization: Bearer`, which now carries the agent's own
  credential.
- **A mount `timeout` of zero is refused** on write; a stored one keeps the default, with
  a warning. The mount's `timeout`, not a fixed 20 or 120 seconds, now bounds the wait for
  response headers.
- **The `pkcs11` seal is removed.** No release ever supported it. A `seal "pkcs11"`
  stanza fails at startup with an error pointing to the alternative: the
  [transit seal](/configuration/seal/transit/) over an HSM-backed key.
- **Seal stanza keys reach the seal.** A transit seal configured in HCL alone works for
  the first time; `region`, `endpoint`, `key_name` and the key ids of the other seals are
  no longer lost; Azure's `resource` is a string. Environment variables still win over
  the stanza, so a workaround through them keeps working — but check that the stanza's
  values match the key.
- **`sys/step-down` requires root or sudo**, is audited, and is refused in namespaces.
- **The root token is recognised after a restart**, so revoking or replacing it takes
  effect.
- **`max_ttl` caps every credential**, and oauth2 and token_exchange take
  `default_token_ttl` when a response has no `expires_in`.
- **Every stored secret is masked** on a spec or source read, list and keyless plan.
