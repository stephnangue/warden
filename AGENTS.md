# Warden — agent guide

This file orients an autonomous agent (LLM, AI assistant, automation
script) that needs to *call services through Warden*. Operators looking
to set up Warden, mount providers, or onboard credentials should read
the per-provider tutorials in `provider/<name>/README.md`; this tree is
for the *consumer* side.

## Where to start

Skills are served by the cluster at `/v1/sys/skills`, not from this
filesystem. Read them in order via the CLI:

1. **`warden skill read foundation --raw`** — global flags, env vars,
   exit codes, output framework. Read this first.
2. **`warden skill read discovery --raw`** — how to introspect which
   roles you can assume and which providers are available, then match
   the task at hand to a provider + role.
3. **`warden skill read <provider-type> --raw`** — once you know which
   provider type you want (`aws`, `vault`, `openai`, …), this tells you
   how to point your CLI/SDK at it.
4. **`warden skill read troubleshooting --raw`** — when something fails:
   classified errors, what to retry, what means "ask the operator".

To browse what's in the catalog:

```bash
warden skill list -F name,description
```

## The agent loop

```
[ authenticate + set namespace ]      ← runtime sets env vars
       │
       ▼
[ warden role list ]                  ← what identities can I assume?
       │
       ▼
[ warden provider list ]              ← what is available in this namespace?
       │
       ▼
[ match task → pick provider+role ]   ← read descriptions; choose the fit
       │
       ▼
[ warden skill read <type> --raw ]    ← the per-provider recipe
       │
       ▼
[ call CLI or SDK with chosen role ]
```

The `discovery` skill walks through each step in full.

## Provider skills available today

Skills for the six providers below are seeded into the registry the
first time the corresponding provider type is mounted in the cluster:

| Provider | Skill name | Pattern |
|---|---|---|
| AWS | `aws` | SigV4 gateway |
| Vault / OpenBao | `vault` | HTTP gateway |
| GitHub | `github` | HTTP gateway |
| OpenAI | `openai` | HTTP gateway |
| Scaleway | `scaleway` | Dual REST + S3 |
| RDS | `rds` | DB credential mint |

Other providers (`azure`, `gcp`, `cloudflare`, `datadog`, `sentry`,
`grafana`, `kubernetes`, `slack`, `tfe`, …) follow the same patterns
but don't yet ship skills. Until they do, the closest existing skill
plus the provider's `README.md` is your best reference.

## Adding a skill for a new provider

When a new provider lands under `provider/<name>/`, ship a matching
`provider/<name>/skill.md` with the same shape as the existing ones,
and add `<name>.Skill()` to the `providerSkills` map in
`cmd/server/server.go`. The skill is seeded into the registry on the
first mount of that provider type.

```yaml
---
name: <name>
description: "<one line: what does this provider expose>"
category: provider-guide
provider: <name>
requires: [foundation, discovery]
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
