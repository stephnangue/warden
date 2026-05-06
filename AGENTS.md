# Warden — agent guide

This file orients an autonomous agent (LLM, AI assistant, automation
script) that needs to *call services through Warden*. Operators looking
to set up Warden, mount providers, or onboard credentials should read
the per-provider tutorials in `provider/<name>/README.md`; this tree is
for the *consumer* side.

## Where to start

1. **`skills/warden-shared/SKILL.md`** — global flags, env vars, exit
   codes, output framework. Read this first.
2. **`skills/discovery/SKILL.md`** — how to introspect which roles you
   can assume and which providers are available, then match the task at
   hand to a provider + role.
3. **`skills/providers/<name>/SKILL.md`** — once you know which provider
   you want, this tells you how to point your CLI/SDK at it.
4. **`skills/troubleshooting/SKILL.md`** — when something fails:
   classified errors, what to retry, what means "ask the operator".

## The agent loop

```
[ authenticate + set namespace ]
       │
       ▼
[ warden roles ]                      ← what identities can I assume?
       │
       ▼
[ warden list sys/providers ]         ← what is available in this namespace?
       │
       ▼
[ match task → pick provider+role ]   ← read descriptions; choose the fit
       │
       ▼
[ read skills/providers/<type>/SKILL.md ]
       │                              ← the per-provider recipe
       ▼
[ call CLI or SDK with chosen role ]
```

Each step is a one-liner; `skills/discovery/` walks through the
variants.

## Provider skills available today

| Provider | Skill | Pattern |
|---|---|---|
| AWS | `skills/providers/aws/SKILL.md` | SigV4 gateway |
| Vault / OpenBao | `skills/providers/vault/SKILL.md` | HTTP gateway |
| GitHub | `skills/providers/github/SKILL.md` | HTTP gateway |
| OpenAI | `skills/providers/openai/SKILL.md` | HTTP gateway |
| Scaleway | `skills/providers/scaleway/SKILL.md` | Dual REST + S3 |
| RDS | `skills/providers/rds/SKILL.md` | DB credential mint |

Other providers (`azure`, `gcp`, `cloudflare`, `datadog`, `sentry`,
`grafana`, `kubernetes`, `slack`, `tfe`, …) follow the same patterns
but don't yet have dedicated skills. Until they do, the closest
existing skill plus the provider's `README.md` is your best reference.

## Adding a skill for a new provider

When a new provider lands under `provider/<name>/`, ship a matching
`skills/providers/<name>/SKILL.md` with the same shape as the existing
ones:

```yaml
---
name: provider-<name>
description: "<one line: what does this provider expose>"
category: provider-guide
upstream: "<service name>"
---
```

Body sections, in order:
1. **What it does** — one paragraph.
2. **Configure the CLI/SDK** — env vars, endpoint URL, auth headers,
   how to select a role. The actionable part.
3. **Examples** — three to five copy-paste commands or SDK snippets.
4. **Quirks** — provider-specific gotchas, unsupported operations,
   DNS requirements.

Aim for 50–80 lines. Skills are runbooks, not tutorials.
