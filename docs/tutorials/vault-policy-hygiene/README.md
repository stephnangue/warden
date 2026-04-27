# OpenBao Policy Hygiene Audit with Goose, via Warden

This tutorial stands up an AI agent that audits every ACL policy on an
OpenBao cluster for **hygiene** — concrete, actionable findings a security
team can triage and fix in one command. The agent is built with
[Goose](https://goose-docs.ai/), authenticates with a per-job OIDC JWT issued
by a local Forgejo instance, and reaches three upstream services — OpenBao
for inspection, the Anthropic API for inference, and (optionally) Slack to
deliver the final report — exclusively through Warden. The agent holds zero
credentials: no OpenBao token, no Anthropic key, no Slack bot token.

This is the first in a series of tutorials. One planned follow-up covers an
audit-log-driven **least-privilege proposer** (an AWS IAM Access Analyzer-style
agent that narrows policies based on what tokens actually used) — it reuses
the identical Warden + Goose plumbing built here.

Versions pinned in this tutorial: OpenBao **2.5.3**, Forgejo **15.x**,
Forgejo Runner **12.8.0**, Goose **1.32.0**. Forgejo 15+ and Runner 12.5+
are required for the per-job OIDC token feature this tutorial relies on.
The JWKS path discovery in section 3 will handle Forgejo version drift
within the 15.x line automatically.

---

## 1. What you'll build

![Architecture: a Forgejo-hosted AI agent in the centre of the Warden boundary calls outward with a Forgejo-signed JWT on three legs; Warden's Vault gateway swaps the JWT for an OpenBao token, the Anthropic gateway swaps it for the real Claude API key, and the Slack gateway swaps it for a Slack bot token to deliver the final report.](../images/policy-hygiene-architecture.png)

The **same Forgejo-signed JWT** — minted per Actions job by curling
`$ACTIONS_ID_TOKEN_REQUEST_URL`, auto-expired when the job ends — is used on
all three legs. It rides in the Vault CLI's `X-Vault-Token` header on the
OpenBao leg, the Anthropic SDK's `x-api-key` header on the inference leg,
and an `Authorization: Bearer` header on the Slack delivery leg. The role
the agent wants to assume is **named directly in the URL** —
`…/vault/role/policy-scanner/…`, `…/anthropic/role/anthropic-ops/…`, or
`…/slack/role/slack-ops/…`. Warden validates the JWT against Forgejo's
JWKS, then checks that the JWT's claims satisfy the `bound_claims`
configured on that role; if yes, it checks the access policy, substitutes
the real upstream credential (an OpenBao token, the Anthropic API key, or
the Slack bot token), and forwards. The agent never sees any of those
credentials, and there is no separate "dev JWT" story to maintain.

The reader's iteration loop is: edit the recipe, push to Forgejo, watch the
workflow, download the report. Production is a URL swap; section 9 covers it.

## 2. Prerequisites

- Docker + Docker Compose, ~2 GB RAM free (Forgejo ~250 MB, runner ~80 MB,
  OpenBao ~60 MB). Warden runs on the host.
- `git` client.
- A Go toolchain for `go install` of Warden, or a prebuilt `warden` binary.
- An API key for an Anthropic-compatible LLM endpoint. The tutorial uses
  **DeepSeek's** Anthropic-compat endpoint (`https://api.deepseek.com/anthropic`)
  by default — cheaper and a useful demo of how Warden's `anthropic`
  provider works against any Anthropic-API-compatible upstream. To use
  Anthropic itself, swap the URL in section 5c. **The key goes into
  Warden's credential store, not into any CI variable.** You paste it once
  during section 5 and never again.
- (Optional, for Slack delivery) A Slack workspace, a [bot user OAuth token](https://api.slack.com/authentication/token-types#bot)
  (`xoxb-...`) with the `canvases:write`, `channels:read`, and `chat:write`
  scopes (the report is published as a channel canvas, not a file upload),
  and a channel ID (e.g. `C0123456789`) the bot is a member of. Same rule:
  the token goes into Warden, never into a CI variable. Skip this if you
  only want the Forgejo-Actions artefact and don't care about Slack
  delivery.

The `bao` and `goose` CLIs are installed inside the Actions job's container
— you do not run them on the host.

## 3. Bring up the stack with Docker Compose

The four files we'll use (`docker-compose.yml`, `bao-init.sh`,
`bao-seed.sh`, `forgejo-init.sh`) are alongside this README. Either `cd`
into this folder to run them in place, or copy them to a fresh working
directory.

`docker-compose.yml` runs OpenBao, Forgejo, the Forgejo runner, and two
one-shot init services that bootstrap state so you don't have to:

```yaml
services:
  openbao:
    image: openbao/openbao:2.5.3
    ports: ["8200:8200"]
    environment:
      BAO_DEV_ROOT_TOKEN_ID: dev-bao-root
      BAO_DEV_LISTEN_ADDRESS: 0.0.0.0:8200

  bao-init:
    image: openbao/openbao:2.5.3
    depends_on: [openbao]
    environment:
      BAO_ADDR: http://openbao:8200
      BAO_TOKEN: dev-bao-root
    volumes:
      - ./bao-init.sh:/init.sh:ro
      - ./bao-out:/out
    entrypoint: ["sh", "-c"]
    command:
      - >-
        until bao status >/dev/null 2>&1; do sleep 1; done;
        sh /init.sh
    restart: "no"

  bao-seed:
    image: openbao/openbao:2.5.3
    depends_on: [openbao]
    environment:
      BAO_ADDR: http://openbao:8200
      BAO_TOKEN: dev-bao-root
    volumes:
      - ./bao-seed.sh:/seed.sh:ro
    entrypoint: ["sh", "-c"]
    command:
      - >-
        until bao status >/dev/null 2>&1; do sleep 1; done;
        sh /seed.sh
    restart: "no"

  forgejo:
    image: codeberg.org/forgejo/forgejo:15
    hostname: forgejo.local
    ports: ["3000:3000", "2222:22"]
    environment:
      FORGEJO__server__ROOT_URL: http://forgejo.local:3000/
      FORGEJO__actions__ENABLED: "true"
      FORGEJO__security__INSTALL_LOCK: "true"
    volumes:
      - forgejo-data:/data

  forgejo-init:
    image: codeberg.org/forgejo/forgejo:15
    depends_on: [forgejo]
    user: "1000:1000"
    volumes:
      - forgejo-data:/data
      - ./forgejo-init.sh:/init.sh:ro
    entrypoint: ["sh", "-c"]
    command:
      - >-
        until forgejo --config /data/gitea/conf/app.ini admin user list >/dev/null 2>&1; do sleep 1; done;
        sh /init.sh
    restart: "no"

  runner:
    image: code.forgejo.org/forgejo/runner:12.8.0
    depends_on: [forgejo]
    user: "0:0"
    command: ["/bin/forgejo-runner", "daemon", "--config", "/data/config.yaml"]
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - ./runner-config:/data
    extra_hosts:
      - "forgejo.local:host-gateway"

volumes:
  forgejo-data:
```

`bao-init.sh` provisions the AppRole, ACL, and token role Warden uses to
auth against OpenBao, and writes `ROLE_ID`/`SECRET_ID` to
`bao-out/creds.env` for section 5b to source:

```sh
#!/bin/sh
set -eu

bao auth list -format=json 2>/dev/null | grep -q '"approle/"' \
  || bao auth enable approle

bao policy write policy-reader-acl - <<'EOF'
path "sys/policies/acl/*"   { capabilities = ["read", "list"] }
path "sys/mounts"           { capabilities = ["read"] }
path "sys/auth"             { capabilities = ["read"] }
path "identity/entity/id"   { capabilities = ["list"] }
path "identity/entity/id/*" { capabilities = ["read"] }
EOF

bao write auth/token/roles/policy-reader \
  allowed_policies=policy-reader-acl \
  orphan=true period=10m

bao policy write warden-vault-source - <<'EOF'
path "auth/token/create/policy-reader"          { capabilities = ["update"] }
path "auth/approle/role/warden-policy-scanner"  { capabilities = ["read"] }
EOF

bao write auth/approle/role/warden-policy-scanner \
  token_policies=warden-vault-source \
  token_ttl=1h token_max_ttl=24h

ROLE_ID=$(bao read -field=role_id auth/approle/role/warden-policy-scanner/role-id)
SECRET_ID=$(bao write -force -field=secret_id auth/approle/role/warden-policy-scanner/secret-id)

mkdir -p /out
cat > /out/creds.env <<EOF
ROLE_ID=$ROLE_ID
SECRET_ID=$SECRET_ID
EOF
```

`forgejo-init.sh` creates the `siteowner` admin user (idempotent):

```sh
#!/bin/sh
set -eu

FORGEJO="forgejo --config /data/gitea/conf/app.ini"

if $FORGEJO admin user list 2>/dev/null | awk '{print $2}' | grep -qx siteowner; then
  exit 0
fi

$FORGEJO admin user create \
  --admin --username siteowner --password warden-tutorial \
  --email siteowner@local --must-change-password=false
```

Make sure all three scripts are executable: `chmod +x bao-init.sh bao-seed.sh forgejo-init.sh`.

Then:

1. Map `forgejo.local` to localhost so both your browser and Warden's JWT
   validator resolve it (the JWT's `iss` claim must match `bound_issuer`):
   ```bash
   echo "127.0.0.1 forgejo.local" | sudo tee -a /etc/hosts
   ```
2. Start the long-running services and run the three one-shot init services:
   ```bash
   docker compose up -d openbao forgejo
   docker compose up bao-init bao-seed forgejo-init   # all exit on success
   ```
   Confirm Forgejo's healthcheck:
   ```bash
   curl -sf http://forgejo.local:3000/api/healthz
   ```
   `bao-init` writes `bao-out/creds.env` (used in section 5b);
   `bao-seed` writes the five test policies + the `anchor-user` entity that
   the audit will inspect (see "Seed OpenBao" below for what each policy
   demonstrates); `forgejo-init` provisions the `siteowner` admin.
3. Sign in at `http://forgejo.local:3000/` as `siteowner` / `warden-tutorial`,
   create a new repo `siteowner/policy-hygiene`, then clone it locally:
   ```bash
   git clone http://forgejo.local:3000/siteowner/policy-hygiene.git
   ```
4. Register the runner. In the Forgejo admin UI go to **Site Administration →
   Actions → Runners → New runner** to obtain a registration token, then:
   ```bash
   docker compose run --rm runner forgejo-runner register \
     --no-interactive \
     --instance http://forgejo.local:3000 \
     --token <REGISTRATION_TOKEN> \
     --name local-runner \
     --labels "docker:docker://node:20-bookworm-slim"
   ```
   Create a runner config so spawned job containers can resolve
   `forgejo.local` (the JWT's `iss` claim hostname):
   ```bash
   cat > runner-config/config.yaml <<'EOF'
   container:
     options: "--add-host=forgejo.local:host-gateway --add-host=host.docker.internal:host-gateway"
   EOF
   docker compose up -d runner
   ```
5. Discover Forgejo's **Actions** OIDC config — Warden will use these URLs in
   section 5. Forgejo has two OIDC contexts: user-login (under
   `/.well-known/...`) and per-job Actions (under `/api/actions/...`). The
   per-job JWTs this tutorial uses come from the second one:
   ```bash
   curl -sf http://forgejo.local:3000/api/actions/.well-known/openid-configuration | \
     jq '{issuer, jwks_uri}'
   ```
   On Forgejo 15.x you'll typically see
   `http://forgejo.local:3000/api/actions` and
   `http://forgejo.local:3000/api/actions/.well-known/keys`. Use whatever the
   discovery endpoint returns — do not hardcode.

### Seed OpenBao with deliberately varied policies

The `bao-seed` service from step 2 runs [`bao-seed.sh`](bao-seed.sh) inside
an OpenBao container, so you do not need the `bao` CLI on the host. The
script writes five policies — each shaped to trigger exactly one hygiene
check, plus one clean baseline — and binds `clean` to a named entity so the
agent can verify at-least-one-binding logic.

```hcl
# clean — read-only path on a real mount, no smells
path "secret/data/team-a/*" { capabilities = ["read"] }
```

```hcl
# root-ish — sudo + wildcard at top level
path "*" { capabilities = ["sudo", "read", "list"] }
```

```hcl
# dead-mount — references mounts that don't exist (kv-legacy, aws-prod)
path "kv-legacy/*"          { capabilities = ["read"] }
path "aws-prod/creds/admin" { capabilities = ["read"] }
```

```hcl
# duplicates — same path declared twice with different capabilities
path "secret/data/app/*" { capabilities = ["read"] }
path "secret/data/app/*" { capabilities = ["read", "delete"] }
```

```hcl
# orphan — valid path, but not attached to any live entity
path "secret/data/legacy-batch-job/*" { capabilities = ["read"] }
```

`orphan` is intentionally **not** attached to any entity — that is the
finding the hygiene agent should surface.

## 4. Start Warden in dev mode

In a new shell:

```bash
warden server --dev --dev-root-token=dev-warden-root
```

The dev listener is hard-coded to `127.0.0.1:8400`.

In a third shell — the **admin shell**, used only to run the bootstrap
commands in section 5 — set:

```bash
export WARDEN_ADDR=http://127.0.0.1:8400
export WARDEN_TOKEN=dev-warden-root
```

The root token is used only to configure providers, the JWT auth method, and
the access policy. After section 5 it is no longer needed.

Confirm Warden can reach Forgejo's JWKS — this is the URL Warden calls on
every JWT validation:

```bash
JWKS_URI=$(curl -sf http://forgejo.local:3000/.well-known/openid-configuration \
            | jq -r .jwks_uri)
curl -sf "$JWKS_URI" | jq '.keys | length'   # should print >= 1
```

### Audit log: already running

Warden auto-creates a default file audit device on first start — no
`audit enable` command needed. It writes to `warden-audit.log` in the
directory you launched `warden server` from, mounted at the `file/` accessor.
Section 8 will tail it to confirm every agent request flows through Warden
with attributable identity.

The log is line-delimited JSON, one entry per request and one per response.
Sensitive headers (the JWT itself, upstream tokens) are HMAC-redacted before
they hit disk.

## 5. Wire Warden: JWT auth, three providers, three policies

All three providers (Vault, Anthropic, and the optional Slack) expose the
same `role/<name>/gateway/...` URL shape, so callers see a uniform
interface — but the implementations are separate. Anthropic and Slack are
built on Warden's shared HTTP-proxy framework, while Vault has its own
gateway. **The JWT auth method is shared across all three** — one
identity, up to three egress paths (Slack is skipped if you don't pass
`--slack-token` to `warden-init.sh`).

This whole section is automated by [`warden-init.sh`](warden-init.sh) (next
to this README). From the directory where `bao-out/creds.env` lives, in the
admin shell with `WARDEN_ADDR` and `WARDEN_TOKEN` exported:

```bash
./warden-init.sh --anthropic-key=sk-ant-... [--slack-token=xoxb-...]
```

`--slack-token` is optional; without it, the Slack provider/role/policy are
skipped and the agent's Slack-canvas step at the end of the run will fail
loudly (the report is still recoverable from Forgejo's `actions/upload-artifact`).

The subsections below describe what the script does so you can read or
adapt it. Skim to understand, run the script to apply.

### 5a. JWT auth pointed at Forgejo

Enable the JWT auth method and configure it against Forgejo's Actions OIDC
endpoints (the ones discovered in section 3, step 5 — `/api/actions/...`,
not the user-login OIDC). `default_audience=http://warden.local` is an
arbitrary identifier that both Warden and the Forgejo workflow will agree
on; Warden uses it to reject tokens minted for the wrong system.

### 5b. Vault provider → OpenBao

`bao-init` (from section 3) already provisioned the AppRole, ACL policy,
and token role Warden needs, and wrote `ROLE_ID`/`SECRET_ID` to
`bao-out/creds.env`. `warden-init.sh` sources that file and creates an
`hvault` credential source authenticated by AppRole login (the only auth
method `hvault` accepts — static tokens are not supported by design). The
cred spec mints OpenBao tokens via the `policy-reader` token role;
`rotation_period=24h` rotates the AppRole's `secret_id` automatically.

The JWT role `policy-scanner` is bound to the Forgejo repo's main branch
via `bound_claims` and attaches the `vault-readonly` policy described in 5d.

### 5c. Anthropic-compatible LLM provider → DeepSeek (default) or Anthropic

The `anthropic` provider in Warden speaks the Anthropic Messages API but the
upstream URL is configurable. The tutorial points it at
`https://api.deepseek.com/anthropic` (DeepSeek's Anthropic-compatible
endpoint) by default — change `anthropic_url` in `warden-init.sh` to
`https://api.anthropic.com` if you want Claude itself.

The credential source holds the LLM API key (DeepSeek `sk-…` or Anthropic
`sk-ant-…`) — it's **only entered here**, passed once via
`--anthropic-key=sk-...`. Warden's Anthropic provider strips any incoming
`x-api-key` and `anthropic-version` headers from agent requests and
substitutes its own stored values, so what the agent sends in those headers
is irrelevant. SSE streaming passes through unbuffered.

The JWT role `anthropic-ops` shares the same `bound_claims` as
`policy-scanner` (same identity, two roles) and attaches the `anthropic-ops`
policy described in 5d.

### 5d. Two access policies, one per role — fine-grained

The whole point of this tutorial is policy hygiene, so the agent's own access
policies practice what they preach: **only the exact paths and capabilities
the recipe needs, nothing more.** A wildcard like
`vault/role/policy-scanner/gateway/*` with full CRUD would let the agent
*modify or delete* OpenBao policies — exactly the `least_privilege_smell` the
recipe is meant to flag.

**One policy per role, not one bundled across both.** A combined policy
attached to both JWT roles would let a Vault-side token also call Anthropic
(and vice versa) — extra authority neither role needs, since each role's
`cred_spec_name` only mints credentials for one upstream. Splitting by
capability keeps each token's reach equal to what it can actually use.

The agent's full call inventory:

| Recipe step | Upstream HTTP | CBP capability needed |
|---|---|---|
| `bao policy list` | `GET /v1/sys/policies/acl?list=true` | `read` on `…/v1/sys/policies/acl` |
| `bao policy read <name>` | `GET /v1/sys/policies/acl/<name>` | `read` on `…/v1/sys/policies/acl/*` |
| `bao secrets list` | `GET /v1/sys/mounts` | `read` on `…/v1/sys/mounts` |
| `bao auth list` | `GET /v1/sys/auth` | `read` on `…/v1/sys/auth` |
| `bao list identity/entity/id` | `GET /v1/identity/entity/id?list=true` | `read` on `…/v1/identity/entity/id` |
| `bao read identity/entity/id/<id>` | `GET /v1/identity/entity/id/<id>` | `read` on `…/v1/identity/entity/id/*` |
| Goose Anthropic SDK | `POST /v1/messages` | `create` on `…/v1/messages` |
| Pre-flight check (Anthropic) | `GET /v1/models` | `read` on `…/v1/models` |
| Slack canvas — check existing | `GET /api/conversations.info` | `read` on `…/conversations.info` |
| Slack canvas — delete prior | `POST /api/canvases.delete` | `create` on `…/canvases.delete` |
| Slack canvas — create | `POST /api/conversations.canvases.create` | `create` on `…/conversations.canvases.create` |
| Slack chat notification | `POST /api/chat.postMessage` | `create` on `…/chat.postMessage` |
| Pre-flight check (Slack) | `POST /api/auth.test` | `create` on `…/auth.test` |

Note: bao CLI list operations send `GET ?list=true`. Warden classifies every
gateway GET as a READ at the policy layer (only `?warden-list=true` maps to
LIST), so the capability needed is `read` — the upstream OpenBao still
receives `?list=true` downstream and returns the listing.

Note the doubled `/v1/`: Warden's CBP policy operates on logical paths
(without the leading `/v1/` of the Warden URL), but the proxied OpenBao /
Anthropic path *itself* starts with `v1/`. So policy stanzas read
`vault/role/policy-scanner/gateway/v1/sys/policies/acl`, not
`vault/role/policy-scanner/gateway/sys/policies/acl`.

The policies that `warden-init.sh` writes (the third, `slack-ops`, is only
written when `--slack-token` is passed):

```hcl
# vault-readonly — attached to the policy-scanner JWT role only
path "vault/role/policy-scanner/gateway/v1/sys/policies/acl"     { capabilities = ["read"] }
path "vault/role/policy-scanner/gateway/v1/sys/policies/acl/*"   { capabilities = ["read"] }
path "vault/role/policy-scanner/gateway/v1/sys/mounts"           { capabilities = ["read"] }
path "vault/role/policy-scanner/gateway/v1/sys/auth"             { capabilities = ["read"] }
path "vault/role/policy-scanner/gateway/v1/identity/entity/id"   { capabilities = ["read"] }
path "vault/role/policy-scanner/gateway/v1/identity/entity/id/*" { capabilities = ["read"] }
```

```hcl
# anthropic-ops — attached to the anthropic-ops JWT role only
path "anthropic/role/anthropic-ops/gateway/v1/messages" { capabilities = ["create"] }
path "anthropic/role/anthropic-ops/gateway/v1/models"   { capabilities = ["read"] }
```

```hcl
# slack-ops — attached to the slack-ops JWT role only (optional)
path "slack/role/slack-ops/gateway/conversations.info"            { capabilities = ["read"] }
path "slack/role/slack-ops/gateway/conversations.canvases.create" { capabilities = ["create"] }
path "slack/role/slack-ops/gateway/canvases.delete"               { capabilities = ["create"] }
path "slack/role/slack-ops/gateway/chat.postMessage"              { capabilities = ["create"] }
path "slack/role/slack-ops/gateway/auth.test"                     { capabilities = ["create"] }
```

### 5e. Slack provider → slack.com/api (optional)

If you passed `--slack-token=xoxb-...` to `warden-init.sh`, a third egress
leg is wired up: same JWT, same `bound_claims`, a third role
(`slack-ops`) with the `slack-ops` policy above. The bot token lives only in
Warden — agents send the same `$WARDEN_JWT` and Warden swaps it for
`Authorization: Bearer xoxb-...` at the gateway.

The agent **builds `hygiene-report.md` incrementally** (one shell-tool
`cat >>` per policy) and publishes it at the end as the channel's Slack
**Canvas**, which renders Markdown natively (a plain `.md` file upload
appears as a download blob with no formatting). Slack permits at most
one canvas per channel, so the recipe replaces any prior run's canvas:

1. `GET /conversations.info?channel=$SLACK_CHANNEL` — read
   `.channel.properties.canvas.file_id` to find any existing canvas.
2. `POST /canvases.delete` — if one exists, delete it.
3. `POST /conversations.canvases.create` with
   `{channel_id, document_content:{type:"markdown", markdown:<file>}}` —
   create the new channel canvas. The file body is piped through
   `jq --rawfile` so the model never reads it back into context.
4. `POST /chat.postMessage` — short notification so members see it in
   chat (the canvas itself is also pinned in the channel header).

Every call goes through Warden (`Authorization: Bearer $WARDEN_JWT`).
Building incrementally (rather than holding the full Markdown in the
model's context) keeps each LLM turn small. With DeepSeek-chat (Flash
non-thinking) this is reliable; if you swap in a model + provider that
fights long contexts, consider streaming `chat.postMessage` per finding
instead.

The Slack app backing `--slack-token` needs the `canvases:write`,
`channels:read`, and `chat:write` scopes (in addition to `auth:read`
for the pre-flight). `canvases:write` is the new one — older bots
typically don't have it.

This is the demonstration of the Warden value prop in full: **one JWT
identity, three upstream services, three independently-scoped policies, no
long-lived credentials anywhere on the agent's side.**

These policies are what enforcement looks like end-to-end: even if the LLM
hallucinates a `bao policy delete` or a curl to `/v1/admin-api-keys`, Warden
returns 403. Each token's authority is bounded by exactly what its role's
recipe step requires — not by what its credentials happen to allow, and not
by what the *other* role on the same JWT identity is doing.

If you discover Warden 403s on a path you legitimately need (e.g. you extend
the recipe to read group bindings), tail Warden's audit log to see the
exact path being denied, then add the minimal stanza. The CBP capabilities
are: `create`, `read`, `update`, `delete`, `list`, `patch`.

The `auth/jwt/role/*` definitions in 5b and 5c each attach their own policy
(`vault-readonly` for `policy-scanner`, `anthropic-ops` for `anthropic-ops`)
via `token_policies`, so each JWT that satisfies the `bound_claims` gets
exactly the access its role needs — no more, no less.

## 6. The Goose recipe

The recipe is staged at [`policy-hygiene.yaml`](policy-hygiene.yaml) in this
folder — copy it into your cloned `siteowner/policy-hygiene` repo:

```bash
cp <path-to>/docs/tutorials/vault-policy-hygiene/policy-hygiene.yaml siteowner/policy-hygiene/
```

It uses the recipe schema documented in
[Goose's `recipe-reference`](https://goose-docs.ai/docs/guides/recipes/recipe-reference).
Reproduced inline below for reading.

```yaml
version: "1.0.0"
title: "OpenBao policy hygiene audit"
description: "Audit every ACL policy on an OpenBao cluster via Warden for dead-mount references, orphan bindings, duplicates, and least-privilege smells."

parameters:
  - key: warden_role
    input_type: string
    requirement: optional
    default: policy-scanner
    description: "Warden Vault-provider role whose spec mints a read-only OpenBao token"
  - key: warden_addr
    input_type: string
    requirement: optional
    default: "http://127.0.0.1:8400"
    description: "Warden HTTP listener"

instructions: |
  You are a security auditor performing a HYGIENE REVIEW of every ACL policy on
  this OpenBao cluster. The `bao` CLI in your shell is already pointed at Warden —
  **do not log in, do not set a token, and do not modify `VAULT_ADDR` or
  `VAULT_TOKEN`**. They are pre-set to the Warden gateway URL and a per-job
  JWT respectively. Just call `bao` directly; the existing env routes through
  Warden.

  Collect the ground truth first. **Always pipe verbose JSON through `jq`
  to extract only the fields you need** — raw `bao …list -format=json`
  outputs are big and accumulate in context across turns, eating into the
  Anthropic input-token rate limit. Use these exact extractions:
    - `bao policy list`                                              → policy names
    - `bao secrets list -format=json | jq -r 'keys[]'`               → secret-mount paths only
    - `bao auth list    -format=json | jq -r 'keys[]'`               → auth-mount paths only
    - `bao list -format=json identity/entity/id | jq -r '.[]'`       → entity IDs only
    - For each entity, extract just name + policies:
        bao read -format=json identity/entity/id/<id> \
          | jq -c '{name: .data.name, policies: .data.policies}'
      Build a map { policy_name -> [entity_names_binding_it] } from those.

  Policy bodies (`bao policy read <name>`) DO need to be read in full —
  that is what you analyse for the four findings.

  Then, for each policy (`bao policy read NAME`), emit findings in exactly
  these four categories. Do not invent others. Cite the HCL line excerpt.

    1. dead_mount_reference
       A `path "<prefix>/*"` whose prefix does NOT match any mount from
       `bao secrets list` or `bao auth list`. Remediation: remove the stanza
       or restore the mount.

    2. orphan_binding
       The policy is attached to zero live entities (not found in the map built
       above) AND is not a built-in (`default`, `root`). Remediation: delete or
       document its purpose.

    3. duplicate_or_contradictory_path
       Same `path "X"` declared twice in one policy, especially with differing
       capabilities. Remediation: merge into a single stanza.

    4. least_privilege_smell
       Any of:
         - `capabilities` list contains "sudo"
         - `path "*"` or `path "sys/*"` at top level
         - `create`/`update`/`delete`/`patch` on a glob path without
           `allowed_parameters` narrowing
       Remediation: narrow path, drop sudo, add allowed_parameters.

  Do NOT score policies 0–100 — that's subjective. Instead, for each policy
  report the finding list, and derive a deterministic severity:
    - critical: any least_privilege_smell with "sudo" OR path "*"
    - warning:  any other finding
    - ok:       no findings

prompt: |
  Run the full hygiene audit against Warden role {{ warden_role }} at
  {{ warden_addr }}, then publish the report as the Slack channel canvas
  on `$SLACK_CHANNEL`. **Build the Markdown file incrementally** with
  shell tool calls — do NOT compose the full report as a single final
  assistant message.

  Sequence: (1) gather ground-truth via the jq-extracted commands from
  instructions; (2) start the file with `printf '# OpenBao policy
  hygiene\n\n' > hygiene-report.md`; (3) for each policy, read + analyse
  + APPEND a section to the file in one shell call (heredoc) — drop prior
  findings from your context, the file is the source of truth; (4) append
  a summary section; (5) publish as the channel canvas: GET
  `conversations.info` to find any existing canvas, POST
  `canvases.delete` if one exists, POST `conversations.canvases.create`
  with the file piped via `jq --rawfile` (so the markdown body never
  enters your context), then POST `chat.postMessage` to notify the
  channel — every call uses `Authorization: Bearer $WARDEN_JWT` against
  `$SLACK_HOST`. (6) Final assistant message: one short line.

  Do NOT skip the canvas publish even if findings are zero.

extensions:
  - type: builtin
    name: developer
    description: "Shell + file tools so the agent can run the bao CLI"

settings:
  goose_provider: anthropic
  goose_model: deepseek-chat   # = Flash non-thinking; swap to claude-sonnet-4-6 for native Anthropic
```

A few notes on the recipe:

- `parameters` are Jinja-rendered into `instructions` and `prompt` at run
  time using `{{ key }}` syntax.
- `extensions: builtin developer` is the single extension Goose needs — its
  `shell` tool runs `bao` directly. No custom MCP shim is required because
  Warden is a transparent HTTP proxy: pointing `VAULT_ADDR` at the Warden
  gateway URL is enough.
- `settings.goose_provider: anthropic` plus the `ANTHROPIC_HOST` env var set
  by the workflow tells Goose's Anthropic SDK where to send requests.

## 7. The Forgejo Actions workflow

The workflow is staged at
[`.forgejo/workflows/hygiene.yaml`](.forgejo/workflows/hygiene.yaml) in this
folder — copy the whole `.forgejo/` directory into your cloned repo:

```bash
cp -r <path-to>/docs/tutorials/vault-policy-hygiene/.forgejo siteowner/policy-hygiene/
```

Reproduced inline below for reading. The workflow
explicitly fetches an OIDC JWT — Forgejo's `enable-openid-connect: true`
(GitHub Actions's equivalent: `permissions: id-token: write`) unlocks
`$ACTIONS_ID_TOKEN_REQUEST_URL` plus `$ACTIONS_ID_TOKEN_REQUEST_TOKEN` —
copies it into both `VAULT_TOKEN` and `ANTHROPIC_API_KEY`, and runs Goose.

```yaml
name: policy-hygiene
on:
  push:
    branches: [main]
  workflow_dispatch:

enable-openid-connect: true   # Forgejo's equivalent of GitHub's `permissions: id-token: write`

jobs:
  hygiene:
    runs-on: docker
    container:
      image: node:20-bookworm-slim
    env:
      WARDEN_ADDR:    http://host.docker.internal:8400
      VAULT_ADDR:     http://host.docker.internal:8400/v1/vault/role/policy-scanner/gateway
      ANTHROPIC_HOST: http://host.docker.internal:8400/v1/anthropic/role/anthropic-ops/gateway
      SLACK_HOST:     http://host.docker.internal:8400/v1/slack/role/slack-ops/gateway
      SLACK_CHANNEL:  C0123456789   # ← replace with your channel ID
    steps:
      - name: Install git (so actions/checkout uses git clone, not REST)
        run: apt-get update && apt-get install -y --no-install-recommends git ca-certificates

      - uses: actions/checkout@v4

      - name: Install bao + goose CLIs
        run: |
          set -euo pipefail
          apt-get install -y --no-install-recommends curl jq bash bzip2 libgomp1 libxcb1 libdbus-1-3
          case "$(uname -m)" in
            aarch64|arm64) BAO_ARCH=arm64 ;;
            x86_64|amd64)  BAO_ARCH=x86_64 ;;
          esac
          curl --retry 3 --retry-delay 5 -fsSL \
            "https://github.com/openbao/openbao/releases/download/v2.5.3/bao_2.5.3_Linux_${BAO_ARCH}.tar.gz" \
            | tar xz -C /usr/local/bin
          # Pin goose to v1.32.0 — the upstream `latest` release tag is
          # currently unmarked (v2 release candidates exist but none is
          # "latest"), so /releases/latest/download/... returns 404.
          curl --retry 3 --retry-delay 5 -fsSL \
            https://github.com/aaif-goose/goose/releases/download/v1.32.0/download_cli.sh \
            | CONFIGURE=false bash
          mv /root/.local/bin/goose /usr/local/bin/

      - name: Mint Warden JWT from Forgejo OIDC
        shell: bash
        run: |
          set -euo pipefail
          RESPONSE=$(curl -sSL \
            -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
            "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=http://warden.local")
          WARDEN_JWT=$(echo "$RESPONSE" | jq -r .value)
          if [ -z "$WARDEN_JWT" ] || [ "$WARDEN_JWT" = "null" ]; then
            echo "Failed to mint JWT. OIDC response was:"
            echo "$RESPONSE"
            exit 1
          fi
          if [[ "$WARDEN_JWT" != eyJ* ]]; then
            echo "JWT doesn't look like a JWT (got ${WARDEN_JWT:0:20}...)"
            exit 1
          fi
          # Print claims (public — signed but not encrypted) so bound_claims mismatches are visible
          PAYLOAD=$(echo "$WARDEN_JWT" | cut -d. -f2)
          while [ $(( ${#PAYLOAD} % 4 )) -ne 0 ]; do PAYLOAD="${PAYLOAD}="; done
          echo "JWT claims:"
          echo "$PAYLOAD" | tr '_-' '/+' | base64 -d 2>/dev/null | jq .
          echo "::add-mask::$WARDEN_JWT"
          echo "WARDEN_JWT=$WARDEN_JWT" >> $GITHUB_ENV

      - name: Pre-flight all three Warden legs
        run: |
          export VAULT_TOKEN="$WARDEN_JWT"
          bao policy list > /dev/null \
            || { echo "Warden->OpenBao leg broken"; exit 1; }
          # /v1/models isn't exposed on every Anthropic-compatible upstream
          # (DeepSeek's compat layer omits it). Only treat 401/403 as a
          # failure — any other status proves Warden auth + policy worked.
          status=$(curl -s -o /dev/null -w "%{http_code}" \
                       -H "x-api-key: $WARDEN_JWT" -H "anthropic-version: 2023-06-01" \
                       "$ANTHROPIC_HOST/v1/models")
          case "$status" in 401|403) echo "Warden->Anthropic leg broken (status $status)"; exit 1 ;; esac
          curl -sf -X POST -H "Authorization: Bearer $WARDEN_JWT" \
               "$SLACK_HOST/auth.test" > /dev/null \
            || { echo "Warden->Slack leg broken"; exit 1; }

      - name: Run Goose hygiene audit
        env:
          GOOSE_STREAM_TIMEOUT: "300"   # default 30s is too short for the structured output
        run: |
          export VAULT_TOKEN="$WARDEN_JWT"
          export ANTHROPIC_API_KEY="$WARDEN_JWT"
          goose run --debug --recipe policy-hygiene.yaml \
              --params warden_role=policy-scanner \
              --params warden_addr=$WARDEN_ADDR

      - uses: actions/upload-artifact@v3
        if: always()
        with:
          name: hygiene-report
          path: hygiene-report.md     # built incrementally by the agent; recoverable even if Slack delivery fails
```

A few notes on the workflow:

- `enable-openid-connect: true` is the key on Forgejo (GitHub Actions uses
  `permissions: id-token: write` instead) — without it,
  `$ACTIONS_ID_TOKEN_REQUEST_URL` is unset and the JWT fetch returns 404.
- `audience=http://warden.local` in the request URL must equal
  `default_audience` from Warden's `auth/jwt/config` in 5a.
- `echo "::add-mask::$WARDEN_JWT"` redacts the JWT from subsequent log
  output. Even though it expires with the job, it's a bearer credential for
  Warden while live — treat it like one.
- `host.docker.internal` lets the job container reach Warden on the host. On
  Docker Desktop this works out of the box; on Linux the `host-gateway`
  mapping in the runner service from section 3 provides the same.
- The pre-flight step catches configuration drift (wrong `bound_claims`,
  expired audience, missing JWKS reachability) before burning Anthropic
  quota on a failed Goose run.
- The JWT's lifetime equals the step's duration. There is no rotation logic
  on the agent side.

## 8. Run it: push, watch, inspect

```bash
cd policy-hygiene/                      # the repo cloned from local Forgejo
cp /path/to/policy-hygiene.yaml .
mkdir -p .forgejo/workflows
cp /path/to/hygiene.yaml .forgejo/workflows/
git add .
git commit -m "hygiene audit recipe"
git push origin main
```

Open `http://forgejo.local:3000/siteowner/policy-hygiene/actions` and watch the
`policy-hygiene` workflow. When it finishes, the report is in two places:
the channel canvas on Slack (if Slack delivery was wired up in 5e), and the
`hygiene-report.md` artifact on the workflow run. Pull it via API:

```bash
curl -H "Authorization: token <PAT>" \
     "http://forgejo.local:3000/api/v1/repos/siteowner/policy-hygiene/actions/artifacts/<id>/zip" \
     -o hygiene-report.zip
unzip hygiene-report.zip
cat hygiene-report.md
```

Expected output across the seven analysed policies (the five seed policies
in `bao-seed.sh` plus `policy-reader-acl` and `warden-vault-source` from
`bao-init.sh` — built-ins `default` and `root` are skipped):

- `clean` — severity `ok`, bound to `anchor-user`, no findings.
- `root-ish` — severity `critical`, finding `least_privilege_smell` citing
  the `sudo` line plus `path "*"` at top level.
- `dead-mount` — severity `warning`, finding `dead_mount_reference` citing
  `kv-legacy/*` and `aws-prod/creds/admin`, remediation "remove stanza or
  restore the mount".
- `duplicates` — severity `warning`, finding
  `duplicate_or_contradictory_path` on `secret/data/app/*`.
- `orphan` — severity `warning`, zero bound entities, finding
  `orphan_binding`.
- `policy-reader-acl` — severity `warning`, `orphan_binding` (it's bound
  to a token role, not an entity, which is invisible to the audit's entity
  scan).
- `warden-vault-source` — severity `warning`, `orphan_binding` (bound to
  the AppRole, same caveat).

Every finding is concrete, verifiable, and maps to a specific remediation.
The agent does not write 0–100 risk scores or design opinions — those would
be subjective; these findings are not.

The dev loop is: edit `policy-hygiene.yaml`, commit, push, wait ~60–90 s
(dominated by `apk add` and the LLM call), download report, repeat.

### Inspect the Warden audit trail

The hygiene report is the agent's view; the audit log is **Warden's** view of
what the agent did. Every request to either gateway is logged with the
caller's resolved identity, the policy that authorized it, the upstream URL,
and the response status. Tail it during the run, or query it after:

```bash
# How many requests did the agent make through each gateway?
jq -r 'select(.type == "request") | .request.mount_point' warden-audit.log \
  | sort | uniq -c
#       6 anthropic/        (LLM turns + 1 pre-flight)
#      12 vault/            (5 policies + secrets/auth list + entity reads + pre-flight)

# What did the JWT actually grant?
jq -r 'select(.type == "request") | [.auth.principal_id, .auth.role_name, .request.path] | @tsv' \
  warden-audit.log | sort -u | head
```

A single representative entry — what Warden sees when the agent reads one
policy through the Vault gateway:

```json
{
  "type": "request",
  "timestamp": "2026-04-25T14:32:11.412Z",
  "request": {
    "id": "01H…",
    "operation": "read",
    "path": "vault/role/policy-scanner/gateway/v1/sys/policies/acl/orphan",
    "mount_point": "vault/",
    "mount_type": "vault",
    "mount_class": "provider",
    "method": "GET",
    "client_ip": "172.17.0.4",
    "transparent": true
  },
  "auth": {
    "principal_id": "repo:siteowner/policy-hygiene:ref:refs/heads/main",
    "role_name": "policy-scanner",
    "policies": ["vault-readonly"],
    "policy_results": {
      "granting_policies": ["vault-readonly"]
    }
  }
}
```

Three things to verify here:

1. **`auth.principal_id`** is derived from Forgejo's JWT claims (`repository`,
   `ref`) — proof that the identity comes from the OIDC token, not a stored
   token in the agent's environment.
2. **`auth.policy_results.granting_policies`** names `vault-readonly` — proof
   that the fine-grained access stanzas from section 5d are what authorized
   the call. If the agent had tried `bao policy delete orphan`, this entry
   would carry `error: "permission denied"` and a `403` response status,
   because no stanza in `vault-readonly` grants `delete` on
   `/v1/sys/policies/acl/*`.
3. **`request.transparent: true`** marks calls that came in via the
   `role/*/gateway/*` path — i.e., that Warden authenticated the client via
   JWT in a header rather than a Warden session token. This is how you spot
   agentic traffic in a busy log.

## 9. Moving to production

Because dev already uses a standard OIDC JWT issuer, production works with
**any** OIDC-capable forge or CI — Forgejo at scale, GitHub Actions, GitLab,
Jenkins with the OIDC plugin, CircleCI, Buildkite. Warden does not care
which. The change set is small and localized to three places.

### 9a. Repoint Warden at the production issuer

Discover URLs from the issuer's `/.well-known/openid-configuration`, then:

```bash
warden write auth/jwt/config \
     mode=jwt \
     jwks_url=<issuer>/<jwks path> \
     bound_issuer=<issuer URL> \
     default_audience=https://warden.example.com
```

### 9b. Update `bound_claims` to the production repo

The claim names differ slightly across issuers. Three concrete examples:

- **Forgejo**:
  `{"repository":"acme/policy-hygiene","ref":"refs/heads/main","ref_type":"branch"}`
- **GitHub Actions**:
  `{"repository":"acme/policy-hygiene","ref":"refs/heads/main","workflow_ref":"acme/policy-hygiene/.github/workflows/hygiene.yaml@refs/heads/main"}`
- **GitLab**:
  `{"project_path":"acme/policy-hygiene","ref":"main","ref_type":"branch"}`

### 9c. Update the workflow file

Change the `audience` to match the new `default_audience`, and `WARDEN_ADDR`
to the production Warden URL. The OIDC-enablement syntax differs by host:
Forgejo uses `enable-openid-connect: true`, GitHub Actions uses
`permissions: id-token: write`, and GitLab auto-injects via `id_tokens:` —
identical mechanism, three slightly different one-liners. The rest of the
workflow (the curl to `$ACTIONS_ID_TOKEN_REQUEST_URL`, the Goose run, the
artifact upload) is unchanged across all three.

That's it. The recipe is unchanged, the Goose code path is unchanged, and
the OpenBao/Anthropic provider configuration in Warden is unchanged.
Production inherits the full audit trail: every request in Warden's log
carries the CI's full run provenance — repo, branch, workflow ref, job id,
actor.

Three operational adjustments worth making explicit in production:

- The dev AppRole is already minimally scoped (only `update` on
  `auth/token/create/policy-reader`). For production, also bind it to a CIDR
  via `bound_cidr_list`, wrap secret_id issuance with `-wrap-ttl=60s`, and
  shorten the policy-reader token role's `period` to the agent's actual job
  duration.
- Rotate the LLM API key (DeepSeek or Anthropic) by updating the spec in
  Warden. The CI job is unaffected — it still authenticates with its JWT.
- Replace the default file audit device with a socket or syslog one to ship
  to a SIEM (Splunk, Elastic, Datadog): `warden audit disable file && warden
  audit enable --type=socket --address=siem:9514` (or `--type=syslog`). The
  JSON shape is the same as in section 8.

## 10. Cleanup

When you're done experimenting, tear the dev stack down:

```bash
# From the directory where you ran docker compose
docker compose down -v          # stop containers + drop named volumes (forgejo-data)
rm -rf bao-out runner-config    # local artefacts: AppRole creds + runner registration
```

Stop Warden (`Ctrl-C` in its shell — `--dev` mode is in-memory, so nothing to
clean up on disk besides the audit log), and optionally remove the host
mapping:

```bash
sudo sed -i '' '/forgejo.local/d' /etc/hosts   # macOS
# sudo sed -i '/forgejo.local/d' /etc/hosts    # Linux
```

To rerun from a clean slate, just `docker compose up -d openbao forgejo &&
docker compose up bao-init forgejo-init` again — the init scripts are
idempotent.

## 11. What's next

This tutorial's agent does **static** hygiene analysis — it inspects policy
HCL and live cluster state (mounts, entities). It cannot tell you which
capabilities a policy *grants but nobody has used in six months*.

The next tutorial picks that up: a Goose agent that reads OpenBao's audit
log through Warden, computes the effective set of (path, capability) pairs
each token actually exercised, diffs it against the granted set, and
proposes a narrowed HCL policy — same shape as AWS IAM Access Analyzer's
"generate policy from CloudTrail" feature. It reuses the Warden + Forgejo
Actions + Anthropic-through-Warden plumbing built here; the only new piece
is `audit/` read access on the Warden access policy and a log-window
parameter in the recipe.

Forward link: [vault-policy-least-privilege.md](vault-policy-least-privilege.md)
(coming soon — sibling tutorial, not part of this PR).
