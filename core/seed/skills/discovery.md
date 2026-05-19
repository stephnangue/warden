---
name: discovery
description: "The agent loop: authenticate, introspect roles, list providers, match the task, pick a role, learn how to call the chosen provider."
category: agent-flow
requires: [foundation]
---

# Discovering what you can do

Before sending any request to an upstream service, an agent on Warden
runs five steps. Each one returns structured JSON; chain them
deterministically.

## Step 1 — confirm the session

Four env vars define the agent's session. **All four are pre-populated
by the runtime that started the agent** — the agent doesn't fetch
them; just confirm they're set:

| Env var | Purpose |
|---|---|
| `WARDEN_TOKEN` | JWT bearer — the CLI auto-detects the JWT prefix and sends `Authorization: Bearer <jwt>` |
| `WARDEN_CLIENT_CERT` / `WARDEN_CLIENT_KEY` | (alternative to JWT) PEM paths for mTLS |
| `WARDEN_ADDR` | the Warden server URL |
| `WARDEN_NAMESPACE` | the namespace to scope every call to |

If `WARDEN_NAMESPACE` is missing, every call lands in the root
namespace, which usually has none of the providers you need —
surface this rather than silently calling the wrong scope.

If you need a per-call override (unusual for agents), pass
`--namespace <ns>` / `-n <ns>`.

## Step 2 — discover assumable roles

```bash
warden role list -o json -F name,description
```

Returns one record per role your identity can assume in the current
namespace:

```json
[
  {"name": "data-reader",      "description": "Read-only access to data warehouses"},
  {"name": "deploy-bot",       "description": "Deploy via TFE; full access to staging"},
  {"name": "vault-secrets-ro", "description": "Read app-config secrets from Vault"}
]
```

Each `description` is operator-set free text — that's how operators
communicate intent. Don't memorize role names: read descriptions,
match to your task.

## Step 3 — list providers in this namespace

```bash
warden provider list -o json -F type,description,mount_url
```

Returns one record per mounted provider:

```json
[
  {"type": "aws",    "description": "Production AWS account 1234",     "mount_url": "/v1/team-data/aws/"},
  {"type": "openai", "description": "OpenAI API for embeddings + chat", "mount_url": "/v1/team-data/openai/"},
  {"type": "rds",    "description": "RDS PostgreSQL — analytics",      "mount_url": "/v1/team-data/rds-pg/"},
  {"type": "vault",  "description": "Internal Vault — secrets/, pki/", "mount_url": "/v1/team-data/vault/"}
]
```

`mount_url` is the relative URL path with the namespace and mount path
already baked in — append `$WARDEN_ADDR` plus the per-provider suffix
(e.g. `gateway`, `role/<role>/gateway`, `access/<grant>`) from the
provider's skill to build the full upstream URL.

**Do not re-prefix the namespace.** `mount_url` already starts with
`/v1/<namespace>/<mount>/`; the full URL is `$WARDEN_ADDR<mount_url>...`.
Concatenating `$WARDEN_NAMESPACE` separately produces a double-
namespaced path that doesn't route (e.g.
`/v1/tutorial/tutorial/vault/...` → `no route found`).

Listing providers requires capabilities granted by your role's
policy — by convention this is included in the namespace's default
role. If your `roles` list is empty or the list call returns
`forbidden`, that's an operator-setup problem; surface it instead of
hard-coding a provider URL.

## Step 4 — match task → provider, pick a role

Read both descriptions side-by-side. The fit is usually obvious:

> *"Read S3 bucket `analytics-events`"* →
> provider `aws/` (description: AWS) +
> role `data-reader` (description: read-only data warehouses).

Multiple providers can match (multi-tenant, regional split, prod vs
staging). When unsure:
- Prefer the **most-scoped** option (e.g., a role described as
  "read-only X" over "admin").
- If two providers look equivalent, surface the ambiguity to the user
  rather than guess.

## Step 5 — call the provider

```bash
warden skill read <type> --raw
```

Returns the provider's self-contained recipe in markdown: endpoint URL,
env vars / auth headers, role-selection mechanic, copy-paste examples.
Follow it.

Provider skills are seeded into the registry the first time a provider
of that type is mounted; if `warden skill read aws` returns 404, the
operator hasn't enabled an AWS provider in this cluster — surface to
the user instead of fabricating an endpoint.

## If a call fails

Don't loop blindly. The CLI returns structured error envelopes whose
`code` field maps deterministically to a recovery action — read the
`troubleshooting` skill before retrying:

```bash
warden skill read troubleshooting --raw
```

In short: `auth_required` → refresh the token; `forbidden` → re-run
`warden role list` and pick a more-scoped role (usually the *right*
role for the task you didn't read carefully enough the first time —
descriptions are operator-set free text, read them); `not_found` →
re-list providers (the namespace's mounts may have changed);
`network`/`server` → bounded backoff. Surface the rest to the user
rather than retrying.

