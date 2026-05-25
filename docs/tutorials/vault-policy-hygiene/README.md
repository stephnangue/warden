# OpenBao Policy Hygiene Audit with Goose, via Warden

This tutorial stands up an AI agent that audits every ACL policy on an
OpenBao cluster for **hygiene** — concrete, actionable findings a security
team can triage and fix in one command. The agent is built with
[Goose](https://goose-docs.ai/), authenticates with a per-job OIDC JWT issued
by a local Forgejo instance, and reaches three upstream services — OpenBao
for inspection, the Anthropic API for inference, and (optionally) Slack to
deliver the final report — exclusively through Warden. The agent holds zero
credentials: no OpenBao token, no Anthropic key, no Slack bot token.

What makes this tutorial worth reading is **how the agent finds its way
around Warden**. The recipe contains no provider URLs, no role names, and
no channel IDs. The agent reads two seeded skills (`foundation`,
`discovery`), introspects its identity, lists the providers in the
namespace, picks the right role + provider by reading operator-set
descriptions, then fetches each provider's `skill.md` recipe for the
exact call shape. This is the **discover-and-connect** pattern documented
in [docs/agent-flow.md](../../agent-flow.md), demonstrated end-to-end
against three real upstreams.

This is the first in a series. A planned follow-up covers an audit-log-driven
**least-privilege proposer** — it reuses the identical Warden + Goose
plumbing (and the same `tutorial/` namespace) built here.

Versions pinned in this tutorial: OpenBao **2.5.3**, Forgejo **15.x**,
Forgejo Runner **12.8.0**, Goose **1.32.0**, Warden **0.13.2**. Forgejo
15+ and Runner 12.5+ are required for the per-job OIDC token feature
this tutorial relies on. The JWKS path discovery in section 3 will
handle Forgejo version drift within the 15.x line automatically.

---

## 1. What you'll build

![Architecture: a Forgejo-hosted AI agent in the centre of the Warden boundary calls outward with a Forgejo-signed JWT on three legs; Warden's Vault gateway swaps the JWT for an OpenBao token, the Anthropic gateway swaps it for the real Claude API key, and the Slack gateway swaps it for a Slack bot token to deliver the final report. The agent learns which role and provider to use for each leg by reading Warden's introspection endpoints and per-provider skill catalog at runtime — none of those URLs are baked into the recipe.](../images/policy-hygiene-architecture.png)

The **same Forgejo-signed JWT** — minted per Actions job by curling
`$ACTIONS_ID_TOKEN_REQUEST_URL`, auto-expired when the job ends — is the
identity vehicle on every leg. The runtime sets three env vars before
spawning the agent: `WARDEN_ADDR`, `WARDEN_NAMESPACE=tutorial`,
`WARDEN_TOKEN=<jwt>`. **Nothing else is pre-configured for the agent.**

At runtime the agent:

1. Reads the `foundation` and `discovery` skills from `/v1/sys/skills/...`.
2. Calls `warden role list` — Warden's `sys/introspect/roles` introspects
   the JWT and returns every role the identity may assume in the
   `tutorial/` namespace, with operator-set descriptions.
3. Calls `warden provider list` — returns every provider mounted in the
   namespace, each with its `mount_url` and description.
4. Picks a (role, provider) pair for each leg by reading descriptions —
   not by name and not by hardcoded URL. The operator-set descriptions
   embed the upstream binding (mount_url, Slack channel) so the agent
   doesn't need any out-of-band knowledge.
5. Calls `warden skill read <type>` for each chosen provider — gets the
   exact CLI/SDK recipe for that provider (env vars to set, URL shape).
6. Executes the audit and publishes the report, following the recipes.

Warden validates the JWT against Forgejo's JWKS on every call, applies
the policy attached to the resolved role, swaps the JWT for the real
upstream credential (OpenBao token, Anthropic key, Slack bot token), and
forwards. The agent never sees any of those credentials, and there is no
separate "dev JWT" story to maintain.

The reader's iteration loop is: edit the recipe, push to Forgejo, watch
the workflow, download the report. Production is a URL swap; section 10
covers it.

## 2. Prerequisites

- Docker + Docker Compose, ~2 GB RAM free (Forgejo ~250 MB, runner ~80 MB,
  OpenBao ~60 MB). Warden runs on the host.
- `git` client.
- A Go toolchain for `go install` of Warden, or a prebuilt `warden` binary.
- An API key for an Anthropic-compatible LLM endpoint. The tutorial uses
  **DeepSeek's** Anthropic-compat endpoint (`https://api.deepseek.com/anthropic`)
  by default — cheaper and a useful demo of how Warden's `anthropic`
  provider works against any Anthropic-API-compatible upstream. To use
  Anthropic itself, swap the URL in section 5e. **The key goes into
  Warden's credential store, not into any CI variable.** You paste it once
  during section 5 and never again.
- (Optional, for Slack delivery) A Slack workspace, a [bot user OAuth token](https://api.slack.com/authentication/token-types#bot)
  (`xoxb-...`) with the `canvases:write`, `channels:read`, and `chat:write`
  scopes (the report is published as a channel canvas, not a file upload),
  and a channel ID (e.g. `C0123456789`) the bot is a member of. Same rule:
  the token goes into Warden, never into a CI variable. The channel ID
  and name are passed to `warden-init.sh` and embedded into the
  `slack-ops` role description — the agent reads them from there, not
  from a `SLACK_CHANNEL` env var. Skip this if you only want the
  Forgejo-Actions artefact and don't care about Slack delivery.

The `bao`, `goose`, and `warden` CLIs are installed inside the Actions
job's container — you do not run them on the host.

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
`bao-out/creds.env` for section 5d to source:

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
   `bao-init` writes `bao-out/creds.env` (used in section 5d);
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

The root token is used only to configure the namespace, providers, the
JWT auth method, and the access policies. After section 5 it is no
longer needed.

Confirm Warden can reach Forgejo's JWKS — this is the URL Warden calls on
every JWT validation:

```bash
JWKS_URI=$(curl -sf http://forgejo.local:3000/.well-known/openid-configuration \
            | jq -r .jwks_uri)
curl -sf "$JWKS_URI" | jq '.keys | length'   # should print >= 1
```

### Audit log

The `warden server --dev` instance ships with zero audit devices — the
broker fail-opens at zero, so the cluster runs unaudited until one is
enabled. The §5 wiring script (`warden-init.sh`) calls
`warden audit enable --type=file --file-path=./warden-audit.log audit-default`
as its first step, which writes the log to `warden-audit.log` in the
directory you launched `warden server` from. Section 9 tails it to
confirm every agent request flows through Warden with attributable
identity.

The log is line-delimited JSON, one entry per request and one per response.
Sensitive headers (the JWT itself, upstream tokens) are HMAC-redacted before
they hit disk.

## 5. Wire Warden: namespace, JWT auth, three providers, descriptions

The entire section is automated by [`warden-init.sh`](warden-init.sh)
(next to this README). From the directory where `bao-out/creds.env`
lives, in the admin shell with `WARDEN_ADDR` and `WARDEN_TOKEN` exported:

```bash
./warden-init.sh \
    --anthropic-key=sk-... \
    [--slack-token=xoxb-...] \
    [--slack-channel-id=C0123456789 --slack-channel-name='#sec-hygiene']
```

`--slack-token` is optional; without it, the Slack provider/role/policy
are skipped. When passed, both `--slack-channel-id` and
`--slack-channel-name` are required: they're embedded into the
`slack-ops` role's `description` so the agent extracts the channel from
discovery rather than an env var.

The subsections below describe what the script does so you can read or
adapt it. Skim to understand, run the script to apply.

### 5a. Create the tutorial namespace

```bash
warden namespace create tutorial --metadata=auto_auth_path=auth/jwt/
```

The discovery flow relies on two namespace-scoped mechanisms:

1. **`auto_auth_path` custom_metadata** — tells Warden which auth mount
   to use for *implicit* JWT authentication on `sys/*` paths. When the
   agent calls `/v1/sys/introspect/roles` with just a bearer JWT (no
   Warden session token, no role segment in the URL), the request
   handler reads `ns.CustomMetadata["auto_auth_path"]` and routes the
   JWT through that mount. Without this metadata, every `sys/*` call
   returns 401 because there's no identity to apply policy against.
2. **`default_role` on the JWT auth method** (configured in 5b) — the
   role-resolution fallback once implicit auth picks the mount.

Root namespace can't carry `custom_metadata`, so the tutorial *must*
create a dedicated namespace. We use `tutorial/` rather than
`policy-hygiene/` so the next tutorial in this series reuses the same
namespace.

All subsequent operator setup happens within this namespace. The
script exports `WARDEN_NAMESPACE=tutorial` and every `warden write`
/ `warden auth enable` / `warden provider enable` lands there.

### 5b. JWT auth pointed at Forgejo

Enable the JWT auth method and configure it against Forgejo's Actions
OIDC endpoints (the ones discovered in section 3, step 5 —
`/api/actions/...`, not the user-login OIDC).

```bash
warden auth enable --type=jwt
warden write auth/jwt/config \
    jwks_url=http://forgejo.local:3000/api/actions/.well-known/keys \
    bound_issuer=http://forgejo.local:3000/api/actions \
    default_audience=http://warden.local \
    default_role=discovery-baseline
```

`default_role=discovery-baseline` is the key field: it names the role
Warden falls back to when no other role is in scope (i.e. `/v1/sys/*`
calls without a header). Role-resolution precedence top-to-bottom is:
`X-Warden-Role` header → URL-embedded role → `?role=` query param →
provider `default_role` → **auth method `default_role`**. Discovery
calls hit the bottom of that ladder.

### 5c. discovery-baseline role + policy

```bash
warden write auth/jwt/role/discovery-baseline \
    description="Baseline namespace identity for any authenticated agent. Grants read on sys/introspect/roles, sys/providers, and sys/skills/*. No upstream credentials are minted by this role." \
    bound_audiences=http://warden.local \
    bound_claims='{"repository":"siteowner/policy-hygiene"}' \
    user_claim=sub \
    token_policies=discovery-baseline
```

```hcl
# discovery-baseline — minimal policy for the sys/* paths the agent's
# discovery loop touches. `warden provider list` and `warden skill list`
# send GET ?warden-list=true, which Warden classifies as LIST (not READ),
# so both capabilities are needed on the listing endpoints.
path "sys/introspect/roles" { capabilities = ["read"] }
path "sys/providers"        { capabilities = ["read", "list"] }
path "sys/providers/*"      { capabilities = ["read"] }
path "sys/skills"           { capabilities = ["read", "list"] }
path "sys/skills/*"         { capabilities = ["read"] }
```

The role has no `cred_spec_name` — it does not mint upstream credentials.
It exists only so the auth layer can resolve a policy when the agent
has no role in the URL. The agent's task-specific roles
(`policy-scanner`, `slack-ops`) keep their own narrow gateway stanzas
in 5g; they don't need to carry discovery paths.

### 5d. Vault provider + policy-scanner role

`bao-init` (from section 3) already provisioned the AppRole, ACL policy,
and token role Warden needs, and wrote `ROLE_ID`/`SECRET_ID` to
`bao-out/creds.env`. `warden-init.sh` sources that file and creates an
`hvault` credential source authenticated by AppRole login (the only auth
method `hvault` accepts — static tokens are not supported by design). The
cred spec mints OpenBao tokens via the `policy-reader` token role;
`rotation_period=24h` rotates the AppRole's `secret_id` automatically.

```bash
warden provider enable --type=vault \
    --description="Internal OpenBao cluster — ACL policies, mounts, identity (read-mostly)" \
    --path=vault
```

The mount path can be supplied either positionally or via `--path` —
both forms work and Vault-style single-dash long flags (`-path=vault`)
are accepted too.

```bash
warden write auth/jwt/role/policy-scanner \
    description="Read-only ACL policy hygiene auditing against OpenBao at /v1/tutorial/vault/. Reads policies, mounts, and entity bindings; no writes." \
    bound_claims='{"repository":"siteowner/policy-hygiene","ref":"refs/heads/main","ref_type":"branch"}' \
    cred_spec_name=policy-scanner \
    token_policies=vault-readonly
```

The role's `description` is dense on purpose: it embeds the upstream
binding (`/v1/tutorial/vault/`) and the task scope ("policy hygiene
auditing"). When the agent runs `warden role list`, this string is what
it pattern-matches against the audit task — no role-name memorisation
required.

### 5e. Anthropic provider + anthropic-ops role

The `anthropic` provider in Warden speaks the Anthropic Messages API but
the upstream URL is configurable. The tutorial points it at
`https://api.deepseek.com/anthropic` (DeepSeek's Anthropic-compatible
endpoint) by default — change `anthropic_url` in `warden-init.sh` to
`https://api.anthropic.com` if you want Claude itself.

```bash
warden provider enable --type=anthropic \
    --description="Anthropic-compatible LLM endpoint (default: DeepSeek). Internal — used by Goose runtime, not chosen by agents." \
    anthropic
```

Note the description: it tells any agent that reads it that this leg is
**not part of the discovery flow**. The LLM upstream is wired by the
runtime (Goose's `ANTHROPIC_HOST`), not chosen by the agent at task
time, because Goose's own SDK is initialised before the recipe runs.
This matches the runtime contract documented in
[docs/agent-flow.md §1](../../agent-flow.md): the runtime injects the
identity vehicle and the LLM upstream, the agent discovers everything
else.

### 5f. Slack provider + slack-ops role (optional)

If you passed `--slack-token=xoxb-...`, a third egress leg is wired up.
The bot token lives only in Warden — agents send `$WARDEN_JWT` and
Warden swaps it for `Authorization: Bearer xoxb-...` at the gateway.

```bash
warden write auth/jwt/role/slack-ops \
    description="Post hygiene reports as Slack canvas in channel #sec-hygiene (C0123456789) via the Slack provider at /v1/tutorial/slack/." \
    bound_claims='{"repository":"siteowner/policy-hygiene","ref":"refs/heads/main","ref_type":"branch"}' \
    cred_spec_name=slack-ops \
    token_policies=slack-ops
```

The channel ID and name are embedded in the description by
`warden-init.sh` from the `--slack-channel-id` and `--slack-channel-name`
flags. The agent extracts both from the role description — there is no
`SLACK_CHANNEL` env var on the runtime side.

The recipe and call shape (canvas check/delete/create, chat
notification) are documented in the `slack` provider skill, which the
agent fetches via `warden skill read slack --raw`.

### 5g. Decoy roles — prove the agent matches by description

To show that role selection is description-driven (not name-driven or
provider-typed), `warden-init.sh` also creates two **decoy roles** that
share the same JWT identity but describe wrong-for-this-task bindings:

| Decoy role | Description | Why it's wrong |
|---|---|---|
| `kv-secrets-reader` | "Read application secrets from KV-v2 at /v1/tutorial/vault/ (e.g. secret/data/app/*). Not for policy or identity reads." | Same provider as `policy-scanner`, but scoped to KV secrets — not policy-hygiene work. |
| `slack-alert-poster` | "Post short alert notifications to #oncall-pings (C9876543210) via the Slack provider at /v1/tutorial/slack/. One-line messages only — not for hygiene reports." | Same provider as `slack-ops`, but described for short alerts and a different channel. |

Both decoys carry the same `bound_claims` as the real roles and only the
`discovery-baseline` policy — so the JWT *could* assume them, but they
wouldn't be authorised to do anything useful even if the agent did pick
them. Section 9 will tail the audit log and confirm `auth.role_name` is
`policy-scanner` and `slack-ops`, never a decoy.

### 5h. Access policies (gateway stanzas) — one per task role

The whole point of this tutorial is policy hygiene, so the agent's own
access policies practice what they preach: **only the exact paths and
capabilities the recipe needs, nothing more.** A wildcard like
`vault/role/policy-scanner/gateway/*` with full CRUD would let the agent
*modify or delete* OpenBao policies — exactly the `least_privilege_smell`
the recipe is meant to flag.

The policies that `warden-init.sh` writes (the third, `slack-ops`, is
only written when `--slack-token` is passed):

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
# slack-ops — attached to the slack-ops JWT role only (optional).
# Slack's Web API is all POST (no REST verbs), so every method maps to
# `create` at Warden's policy layer — including read-style ones.
path "slack/role/slack-ops/gateway/conversations.info"            { capabilities = ["create"] }
path "slack/role/slack-ops/gateway/conversations.canvases.create" { capabilities = ["create"] }
path "slack/role/slack-ops/gateway/canvases.delete"               { capabilities = ["create"] }
path "slack/role/slack-ops/gateway/chat.postMessage"              { capabilities = ["create"] }
path "slack/role/slack-ops/gateway/auth.test"                     { capabilities = ["create"] }
```

These are what enforcement looks like end-to-end: even if the LLM
hallucinates a `bao policy delete` or a curl to `/v1/admin-api-keys`,
Warden returns 403. Each token's authority is bounded by exactly what
its role's recipe step requires — not by what its credentials happen to
allow, and not by what the *other* role on the same JWT identity is
doing.

If you discover Warden 403s on a path you legitimately need (e.g. you
extend the recipe to read group bindings), tail Warden's audit log to
see the exact path being denied, then add the minimal stanza. The CBP
capabilities are: `create`, `read`, `update`, `delete`, `list`, `patch`.

## 6. How the agent discovers Warden

Once section 5 is done, the agent has everything it needs to find its
own way around — through five live introspection calls. This section is
the prose walkthrough; the canonical reference is
[docs/agent-flow.md](../../agent-flow.md).

### Step 1 — Confirm the runtime contract

The runtime injects three env vars before spawning the agent:

```
WARDEN_ADDR=http://host.docker.internal:8400
WARDEN_NAMESPACE=tutorial
WARDEN_TOKEN=<the Forgejo OIDC JWT for this job>
```

That's it. No provider URL, no role name, no Slack channel.

### Step 2 — `warden role list`

```bash
warden role list -o json -F name,description
```

Hits `GET /v1/sys/introspect/roles`. Returns every role the JWT can
assume in the `tutorial/` namespace. With the operator setup from
section 5, the response is:

```json
[
  {"name": "discovery-baseline",  "description": "Baseline namespace identity for any authenticated agent..."},
  {"name": "policy-scanner",      "description": "Read-only ACL policy hygiene auditing against OpenBao at /v1/tutorial/vault/..."},
  {"name": "anthropic-ops",       "description": "LLM inference for the hygiene auditor agent..."},
  {"name": "slack-ops",           "description": "Post hygiene reports as Slack canvas in channel #sec-hygiene (C0123456789) via the Slack provider at /v1/tutorial/slack/."},
  {"name": "kv-secrets-reader",   "description": "Read application secrets from KV-v2... Not for policy or identity reads."},
  {"name": "slack-alert-poster",  "description": "Post short alert notifications to #oncall-pings... not for hygiene reports."}
]
```

Each description is operator-set free text. The agent reads them and
filters by task vocabulary. For "policy hygiene audit", `policy-scanner`
matches; `kv-secrets-reader` is rejected because it explicitly says "not
for policy or identity reads". For "publish hygiene report to Slack",
`slack-ops` matches; `slack-alert-poster` is rejected because it says
"one-line messages only — not for hygiene reports".

### Step 3 — `warden provider list`

```bash
warden provider list -o json -F type,description,mount_url
```

Hits `GET /v1/sys/providers?warden-list=true`. Returns every provider
mount in the namespace:

```json
[
  {"type": "vault",     "description": "Internal OpenBao cluster...",         "mount_url": "/v1/tutorial/vault/"},
  {"type": "anthropic", "description": "Anthropic-compatible LLM endpoint...","mount_url": "/v1/tutorial/anthropic/"},
  {"type": "slack",     "description": "Slack workspace for security-team...","mount_url": "/v1/tutorial/slack/"}
]
```

Note that role descriptions already named the mount URL — `mount_url`
here is the same string the descriptions embed. Either source works;
the agent has both available for cross-checks.

### Step 4 — `warden skill read <type>` for each chosen provider

```bash
warden skill read vault --raw
warden skill read slack --raw
```

Hits `GET /v1/sys/skills/<name>`. Returns the per-provider recipe in
markdown — exact env vars to set, exact URL shape to use, exact CLI/SDK
quirks. Example for `vault`:

```
URL pattern : $WARDEN_ADDR<mount-url>role/<role>/gateway/<vault-api-path>
Auth header : Authorization: Bearer $WARDEN_TOKEN  # OR X-Vault-Token: $WARDEN_TOKEN
```

The agent substitutes `<mount-url>` (from step 3) and `<role>` (from
step 2), exports `VAULT_ADDR` + `VAULT_TOKEN`, and runs `bao` unchanged.

### Step 5 — Execute

The audit is the same `bao policy list` / `bao policy read` loop as
before; the Slack canvas publish is the same four-call sequence. What's
new is that **the agent never wrote down any of those URLs in its
recipe** — every concrete string came from a live introspection call.

This makes the recipe portable: rename the role from `policy-scanner`
to `bao-auditor`, move the namespace from `tutorial/` to `prod-audit/`,
swap DeepSeek for real Anthropic — the recipe does not change.

## 7. The Goose recipe

The recipe is staged at [`policy-hygiene.yaml`](policy-hygiene.yaml) in
this folder — copy it into your cloned `siteowner/policy-hygiene` repo:

```bash
cp <path-to>/docs/tutorials/vault-policy-hygiene/policy-hygiene.yaml siteowner/policy-hygiene/
```

It uses the recipe schema documented in
[Goose's `recipe-reference`](https://goose-docs.ai/docs/guides/recipes/recipe-reference).

The whole recipe is **task semantics** — what an audit is, what the four
finding categories are, how severity is derived, what the deliverable
looks like. The only line that mentions Warden is the one-sentence
bootstrap at the top of `instructions:` that points the agent at the
`foundation` and `discovery` skills. The agent learns everything else —
how to authenticate, which role to pick, how to call Vault and Slack —
from those skills and the per-provider skills it fetches at runtime.

Notable consequences:

- **The recipe has no `parameters:` block.** Nothing is parameterised
  because nothing is recipe-author-tunable: role names, provider URLs,
  and channel IDs all come from discovery.
- **The recipe has no `$VAULT_ADDR`, `$SLACK_HOST`, or `$SLACK_CHANNEL`
  references.** The agent exports those itself after step 4, following
  the per-provider skill recipes.
- **The four-category audit rubric is preserved verbatim** — that's the
  *task*, and it's identical whether the agent runs against
  `tutorial/vault` or `prod-audit/vault`.

The `developer` extension is the single Goose extension needed — its
`shell` + `text-editor` tools run `warden`, `bao`, and `curl`. No
custom MCP shim is required because Warden is a transparent HTTP proxy:
once the agent has set `VAULT_ADDR` per the vault skill, `bao` calls
flow through Warden unchanged.

## 8. The Forgejo Actions workflow

The workflow is staged at
[`.forgejo/workflows/hygiene.yaml`](.forgejo/workflows/hygiene.yaml) in
this folder — copy the whole `.forgejo/` directory into your cloned repo:

```bash
cp -r <path-to>/docs/tutorials/vault-policy-hygiene/.forgejo siteowner/policy-hygiene/
```

The workflow's env block is short — the runtime contract from
[docs/agent-flow.md §1](../../agent-flow.md) plus the one LLM-leg
override:

```yaml
env:
  WARDEN_ADDR:      http://host.docker.internal:8400
  WARDEN_NAMESPACE: tutorial
  ANTHROPIC_HOST:   http://host.docker.internal:8400/v1/tutorial/anthropic/role/anthropic-ops/gateway
```

`VAULT_ADDR`, `VAULT_TOKEN`, `SLACK_HOST`, and `SLACK_CHANNEL` are
**not set** — the agent discovers and exports them.

The workflow does four things:

1. Install `bao`, `goose`, and `warden` CLIs.
2. Mint a per-job OIDC JWT from Forgejo and export it as `WARDEN_JWT`.
3. **Pre-flight discovery** — make a bare-JWT call to `warden role
   list`, `warden provider list`, and `warden skill read discovery
   --raw`. If any of these fails, the agent's first discovery call
   would too — surface here, before burning LLM tokens.
4. Run Goose with the recipe; export the JWT into `WARDEN_TOKEN` (for
   `warden`) and `ANTHROPIC_API_KEY` (for Goose's Anthropic SDK).

A few notes:

- `enable-openid-connect: true` is the key on Forgejo (GitHub Actions
  uses `permissions: id-token: write` instead) — without it,
  `$ACTIONS_ID_TOKEN_REQUEST_URL` is unset and the JWT fetch returns 404.
- `audience=http://warden.local` in the request URL must equal
  `default_audience` from Warden's `auth/jwt/config` in 5b.
- `echo "::add-mask::$WARDEN_JWT"` redacts the JWT from subsequent log
  output. Even though it expires with the job, it's a bearer credential
  for Warden while live — treat it like one.
- `host.docker.internal` lets the job container reach Warden on the
  host. On Docker Desktop this works out of the box; on Linux the
  `host-gateway` mapping in the runner service from section 3 provides
  the same.

## 9. Run it: push, watch, inspect

```bash
cd policy-hygiene/                      # the repo cloned from local Forgejo
cp /path/to/policy-hygiene.yaml .
mkdir -p .forgejo/workflows
cp /path/to/hygiene.yaml .forgejo/workflows/
git add .
git commit -m "hygiene audit recipe"
git push origin main
```

Open `http://forgejo.local:3000/siteowner/policy-hygiene/actions` and
watch the `policy-hygiene` workflow. The pre-flight step prints the JSON
the agent will see — role list, provider list, discovery skill — so you
can verify discovery works before the LLM run begins. When it finishes,
the report is in two places: the channel canvas on Slack (if Slack
delivery was wired up in 5f), and the `hygiene-report.md` artifact on
the workflow run.

Expected output across the seven analysed policies (the five seed
policies in `bao-seed.sh` plus `policy-reader-acl` and
`warden-vault-source` from `bao-init.sh` — built-ins `default` and
`root` are skipped):

- `clean` — severity `ok`, bound to `anchor-user`, no findings.
- `root-ish` — severity `critical`, finding `least_privilege_smell`
  citing the `sudo` line plus `path "*"` at top level.
- `dead-mount` — severity `warning`, finding `dead_mount_reference`
  citing `kv-legacy/*` and `aws-prod/creds/admin`.
- `duplicates` — severity `warning`, finding
  `duplicate_or_contradictory_path` on `secret/data/app/*`.
- `orphan` — severity `warning`, zero bound entities, finding
  `orphan_binding`.
- `policy-reader-acl` — severity `warning`, `orphan_binding`.
- `warden-vault-source` — severity `warning`, `orphan_binding`.

### Inspect the Warden audit trail

Every request to Warden — discovery calls *and* gateway calls — is
logged with the caller's resolved identity, the policy that authorized
it, the upstream URL, and the response status. Tail it after the run:

```bash
# What roles did Warden resolve, and on which paths?
jq -r 'select(.type=="request") |
       [.auth.role_name // "-", .request.path] | @tsv' \
  warden-audit.log | sort -u
```

Expect three clusters:

1. **Discovery calls** — `sys/introspect/roles`, `sys/providers`,
   `sys/skills/foundation`, `sys/skills/discovery`, `sys/skills/vault`,
   `sys/skills/slack` — all with `auth.role_name = discovery-baseline`.
   This is the `default_role` fallback firing: the URL had no role
   segment, so Warden resolved the JWT against the auth method's
   default.
2. **Vault gateway calls** — `vault/role/policy-scanner/gateway/v1/...`
   with `auth.role_name = policy-scanner`. The agent chose this role
   from the role list and used it explicitly in the URL.
3. **Slack gateway calls** — `slack/role/slack-ops/gateway/...` with
   `auth.role_name = slack-ops`.

The decoy roles **must not appear** in `auth.role_name`:

```bash
jq -r 'select(.type=="request") | .auth.role_name // empty' \
  warden-audit.log | sort -u
# discovery-baseline
# policy-scanner
# slack-ops
```

If `kv-secrets-reader` or `slack-alert-poster` shows up here, the agent
matched by provider type instead of by description — the recipe needs
tightening or the descriptions need to be more discriminating.

## 10. Moving to production

Production works with any OIDC-capable forge or CI — GitHub Actions,
GitLab, Jenkins with the OIDC plugin, CircleCI, Buildkite. The change
set is small:

1. **Repoint Warden at the production issuer.** Discover URLs from the
   issuer's `/.well-known/openid-configuration`, then update
   `auth/jwt/config` in the production namespace.
2. **Update `bound_claims` on each role** to the production repo. Claim
   names differ slightly across issuers (Forgejo uses `repository`,
   GitHub Actions uses `repository` + `workflow_ref`, GitLab uses
   `project_path`).
3. **Update the workflow's `audience`** to match the new `default_audience`,
   and `WARDEN_ADDR`/`WARDEN_NAMESPACE` to the production values.
4. **Re-run `warden-init.sh` against the production namespace** with the
   production Slack channel + token, and the production Anthropic key.

That's it. The recipe is unchanged, the Goose code path is unchanged,
and even the per-provider skills are unchanged — the entire delta lives
in operator-side configuration. Production inherits the full audit
trail: every request in Warden's log carries the CI's full run
provenance — repo, branch, workflow ref, job id, actor.

Three operational adjustments worth making explicit in production:

- The dev AppRole is already minimally scoped (only `update` on
  `auth/token/create/policy-reader`). For production, also bind it to a
  CIDR via `bound_cidr_list`, wrap secret_id issuance with
  `-wrap-ttl=60s`, and shorten the policy-reader token role's `period`
  to the agent's actual job duration.
- Rotate the LLM API key (DeepSeek or Anthropic) by updating the spec
  in Warden. The CI job is unaffected — it still authenticates with its
  JWT.
- Replace the default file audit device with a socket or syslog one to
  ship to a SIEM (Splunk, Elastic, Datadog).

## 11. Cleanup

When you're done experimenting, tear the dev stack down:

```bash
# From the directory where you ran docker compose
docker compose down -v          # stop containers + drop named volumes (forgejo-data)
rm -rf bao-out runner-config    # local artefacts: AppRole creds + runner registration
```

Stop Warden (`Ctrl-C` in its shell — `--dev` mode is in-memory, so
nothing to clean up on disk besides the audit log), and optionally
remove the host mapping:

```bash
sudo sed -i '' '/forgejo.local/d' /etc/hosts   # macOS
# sudo sed -i '/forgejo.local/d' /etc/hosts    # Linux
```

To rerun from a clean slate, just `docker compose up -d openbao forgejo &&
docker compose up bao-init forgejo-init` again — the init scripts are
idempotent, and `warden-init.sh` is too (it reuses the `tutorial/`
namespace if it already exists).

## 12. What's next

This tutorial's agent does **static** hygiene analysis — it inspects
policy HCL and live cluster state (mounts, entities). It cannot tell
you which capabilities a policy *grants but nobody has used in six
months*.

The next tutorial picks that up: a Goose agent that reads OpenBao's
audit log through Warden, computes the effective set of (path,
capability) pairs each token actually exercised, diffs it against the
granted set, and proposes a narrowed HCL policy — same shape as AWS IAM
Access Analyzer's "generate policy from CloudTrail" feature. It reuses
the same `tutorial/` namespace, the same Forgejo + Goose plumbing, and
the same discovery pattern — only the recipe and one new gateway stanza
on `vault-readonly` change.

Forward link: [vault-policy-least-privilege.md](vault-policy-least-privilege.md)
(coming soon — sibling tutorial, not part of this PR).

For a sibling tutorial that exercises the *within-provider* axis of
discover-and-connect — same Forgejo + Goose + Warden plumbing, but
the agent switches roles between calls within a single AWS provider
mount — see [aws-access-hygiene](../aws-access-hygiene/README.md).
