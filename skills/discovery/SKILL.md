---
name: discovery
description: "The agent loop: authenticate, introspect roles, list providers, match the task, pick a role, learn how to call the chosen provider."
category: agent-flow
requires: [warden-shared]
---

# Discovering what you can do

Before sending any request to an upstream service, an agent on Warden
runs four steps. Each one returns structured JSON; chain them
deterministically.

## Step 1 — confirm the session

Four env vars define the agent's session. **All four are pre-populated
by the runtime that started the agent** — the agent doesn't fetch
them; just confirm they're set:

| Env var | Purpose |
|---|---|
| `WARDEN_TOKEN` | JWT bearer — sent automatically as both `X-Warden-Token` and `Authorization: Bearer <jwt>` |
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
warden roles -o json
```

Returns one record per role your identity can assume in the current
namespace:

```json
[
  {"name": "data-reader",      "description": "Read-only access to data warehouses",     "auth_path": "jwt/"},
  {"name": "deploy-bot",       "description": "Deploy via TFE; full access to staging", "auth_path": "jwt/"},
  {"name": "vault-secrets-ro", "description": "Read app-config secrets from Vault",      "auth_path": "jwt/"}
]
```

Each `description` is operator-set free text — that's how operators
communicate intent. Don't memorize role names: read descriptions,
match to your task.

## Step 3 — list providers in this namespace

```bash
warden list sys/providers -o json
```

Returns one record per mounted provider:

```json
{
  "aws/":     {"type": "aws",     "description": "Production AWS account 1234"},
  "openai/":  {"type": "openai",  "description": "OpenAI API for embeddings + chat"},
  "rds-pg/":  {"type": "rds",     "description": "RDS PostgreSQL — analytics"},
  "vault/":   {"type": "vault",   "description": "Internal Vault — secrets/, pki/"}
}
```

Listing and reading providers requires capabilities granted by your
role's policy — by convention this is included in the namespace's
default role. If your `roles` list is empty or the list call returns
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

Read `skills/providers/<type>/SKILL.md` for the chosen provider —
that's the self-contained recipe: endpoint URL, env vars / auth
headers, role-selection mechanic, copy-paste examples. Follow it.


