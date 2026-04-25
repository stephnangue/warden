# OpenBao Policy Hygiene Audit with Goose, via Warden

This tutorial stands up an AI agent that audits every ACL policy on an
OpenBao cluster for **hygiene** — concrete, actionable findings a security team
can triage and fix in one command. The agent is built with [Goose](https://goose-docs.ai/),
authenticates with a per-job OIDC JWT issued by a local Forgejo instance, and
reaches OpenBao **and** the Anthropic API exclusively through Warden. The agent
holds zero credentials: no OpenBao token, no Anthropic API key.

This is the first of two tutorials. A follow-up will cover an audit-log-driven
**least-privilege proposer** (an AWS IAM Access Analyzer-style agent that
narrows policies based on what tokens actually used). That sequel reuses the
identical Warden + Goose plumbing built here.

Versions pinned in this tutorial: OpenBao **2.5.3**, Forgejo **7.x**,
Forgejo Runner **6.x**. Adjust to your needs, but the JWKS path discovery in
section 3 will handle Forgejo version drift automatically.

---

## 1. What you'll build

![Architecture: a Forgejo-hosted AI agent in the centre of the Warden boundary calls outward with a Forgejo-signed JWT on both legs; Warden's Anthropic gateway swaps the JWT for the real Claude API key, and Warden's Vault gateway swaps the JWT for an OpenBao token.](images/policy-hygiene-architecture.png)

The **same Forgejo-signed JWT** — minted per Actions job by curling
`$ACTIONS_ID_TOKEN_REQUEST_URL`, auto-expired when the job ends — is used on
both legs. It rides in the Vault CLI's `X-Vault-Token` header on one side and
the Anthropic SDK's `x-api-key` header on the other. The role the agent wants
to assume is **named directly in the URL** — `…/vault/role/policy-scanner/…`
or `…/anthropic/role/anthropic-ops/…`. Warden validates the JWT against
Forgejo's JWKS, then checks that the JWT's claims satisfy the
`bound_claims` configured on that role; if yes, it checks the access policy,
substitutes the real upstream credential, and forwards. The agent never sees
a real OpenBao token or Anthropic key, and there is no separate "dev JWT"
story to maintain.

The reader's iteration loop is: edit the recipe, push to Forgejo, watch the
workflow, download the report. Production is a URL swap; section 9 covers it.

## 2. Prerequisites

- Docker + Docker Compose, ~2 GB RAM free (Forgejo ~250 MB, runner ~80 MB,
  OpenBao ~60 MB). Warden runs on the host.
- `git` client.
- A Go toolchain for `go install` of Warden, or a prebuilt `warden` binary.
- An Anthropic API key. **It goes into Warden's credential store, not into
  any CI variable.** You paste it once during section 5 and never again.

The `bao` and `goose` CLIs are installed inside the Actions job's container
— you do not run them on the host.

## 3. Bring up the stack with Docker Compose

Save this as `docker-compose.yml` in a fresh working directory:

```yaml
services:
  openbao:
    image: openbao/openbao:2.5.3
    ports: ["8200:8200"]
    environment:
      BAO_DEV_ROOT_TOKEN_ID: dev-bao-root
      BAO_DEV_LISTEN_ADDRESS: 0.0.0.0:8200

  forgejo:
    image: codeberg.org/forgejo/forgejo:7
    hostname: forgejo.local
    ports: ["3000:3000", "2222:22"]
    environment:
      FORGEJO__server__ROOT_URL: http://forgejo.local:3000/
      FORGEJO__actions__ENABLED: "true"
    volumes:
      - forgejo-data:/var/lib/gitea

  runner:
    image: code.forgejo.org/forgejo/runner:6
    depends_on: [forgejo]
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - ./runner-config:/data
    extra_hosts:
      - "forgejo.local:host-gateway"

volumes:
  forgejo-data:
```

Then:

1. Map `forgejo.local` to localhost so both your browser and Warden's JWT
   validator resolve it (the JWT's `iss` claim must match `bound_issuer`):
   ```bash
   echo "127.0.0.1 forgejo.local" | sudo tee -a /etc/hosts
   ```
2. Start OpenBao and Forgejo:
   ```bash
   docker compose up -d openbao forgejo
   ```
   Wait ~30 s and confirm Forgejo's healthcheck:
   ```bash
   curl -sf http://forgejo.local:3000/api/healthz
   ```
3. Open `http://forgejo.local:3000/` in a browser, complete the install
   wizard, and create the admin user `admin`.
4. Create a new repo `admin/policy-hygiene`, then clone it locally:
   ```bash
   git clone http://forgejo.local:3000/admin/policy-hygiene.git
   ```
5. Register the runner. In the Forgejo admin UI go to **Site Administration →
   Actions → Runners → New runner** to obtain a registration token, then:
   ```bash
   docker compose run --rm runner forgejo-runner register \
     --no-interactive \
     --instance http://forgejo.local:3000 \
     --token <REGISTRATION_TOKEN> \
     --name local-runner \
     --labels "docker:docker://alpine:3.20"
   docker compose up -d runner
   ```
6. Discover Forgejo's OIDC config — Warden will use these URLs in section 5:
   ```bash
   curl -sf http://forgejo.local:3000/.well-known/openid-configuration | \
     jq '{issuer, jwks_uri}'
   ```
   Note the values; on Forgejo 7 you'll typically see
   `http://forgejo.local:3000` and
   `http://forgejo.local:3000/api/v1/actions/oidc/jwks`. Use whatever the
   discovery endpoint returns — do not hardcode.

### Seed OpenBao with deliberately varied policies

Each policy is shaped to trigger exactly one hygiene check, plus one clean
baseline. With a host shell pointed at the dev OpenBao (you'll need the `bao`
CLI on the host for this one-time setup; download it from the
[OpenBao 2.5.3 release](https://github.com/openbao/openbao/releases/tag/v2.5.3)):

```bash
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=dev-bao-root

# kv-v2 + userpass so the "good" policies have something real to reference
bao secrets enable -path=secret kv-v2
bao auth enable userpass

cat > /tmp/clean.hcl <<'EOF'
path "secret/data/team-a/*" {
  capabilities = ["read"]
}
EOF
bao policy write clean /tmp/clean.hcl

cat > /tmp/root-ish.hcl <<'EOF'
path "*" {
  capabilities = ["sudo", "read", "list"]
}
EOF
bao policy write root-ish /tmp/root-ish.hcl

cat > /tmp/dead-mount.hcl <<'EOF'
path "kv-legacy/*" {
  capabilities = ["read"]
}
path "aws-prod/creds/admin" {
  capabilities = ["read"]
}
EOF
bao policy write dead-mount /tmp/dead-mount.hcl

cat > /tmp/duplicates.hcl <<'EOF'
path "secret/data/app/*" {
  capabilities = ["read"]
}
path "secret/data/app/*" {
  capabilities = ["read", "delete"]
}
EOF
bao policy write duplicates /tmp/duplicates.hcl

cat > /tmp/orphan.hcl <<'EOF'
path "secret/data/legacy-batch-job/*" {
  capabilities = ["read"]
}
EOF
bao policy write orphan /tmp/orphan.hcl

# Anchor case: attach `clean` to one identity entity so it has a live binding
ENTITY_ID=$(bao write -format=json identity/entity name="anchor-user" \
                policies="clean" | jq -r .data.id)
echo "anchor entity: $ENTITY_ID"
```

`orphan` is intentionally **not** attached to any entity — that is the
finding the hygiene agent should surface.

## 4. Start Warden in dev mode

In a new shell:

```bash
warden server --dev --dev-root-token=dev-warden-root
```

The `--dev*` flags are defined at [cmd/server/server.go:172-178](../../cmd/server/server.go#L172-L178)
and the dev listener is hard-coded to `127.0.0.1:8400` per
[config/config.go:555](../../config/config.go#L555).

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

### Enable the audit log

Section 8 will tail this to confirm every agent request flows through Warden
with attributable identity. From the admin shell:

```bash
warden audit enable --type=file --file-path=/tmp/warden-audit.log
```

The log is line-delimited JSON, one entry per request and one per response,
with the format defined at [audit/types.go:12-26](../../audit/types.go#L12-L26).
Sensitive headers (the JWT itself, upstream tokens) are HMAC-redacted via
[audit/hmac.go](../../audit/hmac.go) before they hit disk.

## 5. Wire Warden: JWT auth, two providers, one policy

Both providers expose the same `role/<name>/gateway/...` URL shape, so callers
see a uniform interface — but the implementations are separate. Anthropic is
built on the shared [provider/httpproxy](../../provider/httpproxy/) framework,
while Vault registers its own gateway paths in
[provider/vault/provider.go](../../provider/vault/provider.go) and handles
them in [provider/vault/path_gateway.go](../../provider/vault/path_gateway.go).
**The JWT auth method is shared across both** — one identity, two egress paths.

### 5a. Enable JWT auth pointed at Forgejo

Use the URLs you discovered in section 3:

```bash
warden auth enable --type=jwt
warden write auth/jwt/config \
     mode=jwt \
     jwks_url=http://forgejo.local:3000/api/v1/actions/oidc/jwks \
     bound_issuer=http://forgejo.local:3000 \
     default_audience=http://warden.local
```

Adjust `jwks_url` and `bound_issuer` if the discovery endpoint returned
different values. `default_audience` is an arbitrary identifier that both
Warden and the Forgejo workflow will agree on; Warden uses it to reject
tokens minted for the wrong system.

### 5b. Vault provider → OpenBao

Following the canonical setup in [provider/vault/README.md](../../provider/vault/README.md):

```bash
# 1. Enable the provider
warden provider enable --type=vault vault
warden write vault/config \
     vault_address=http://host.docker.internal:8200 \
     auto_auth_path=auth/jwt/

# 2. Credential source — for dev, the OpenBao root token
warden cred source create openbao-root --type=vault \
     --config=vault_address=http://host.docker.internal:8200 \
     --config=auth_method=token \
     --config=token=dev-bao-root

# 3. Credential spec — mints OpenBao tokens with the read-only role
warden cred spec create policy-scanner --source openbao-root \
     --config mint_method=vault_token \
     --config token_role=policy-reader \
     --config ttl=10m

# 4. JWT role bound to the Forgejo repo's main branch
warden write auth/jwt/role/policy-scanner \
     bound_claims='{"repository":"admin/policy-hygiene","ref":"refs/heads/main","ref_type":"branch"}' \
     cred_spec_name=policy-scanner \
     token_policies=agent-policy
```

For step 3 to work, OpenBao needs a `policy-reader` token role that can
`read`/`list` on `sys/policies/acl/*`, `sys/mounts`, `sys/auth`, and
`identity/entity`. Create it on the host:

```bash
bao policy write policy-reader-acl - <<'EOF'
path "sys/policies/acl/*"  { capabilities = ["read", "list"] }
path "sys/mounts"          { capabilities = ["read"] }
path "sys/auth"            { capabilities = ["read"] }
path "identity/entity/id"  { capabilities = ["list"] }
path "identity/entity/id/*"{ capabilities = ["read"] }
EOF
bao write auth/token/roles/policy-reader \
     allowed_policies=policy-reader-acl \
     orphan=true period=10m
```

### 5c. Anthropic provider → api.anthropic.com

Following [provider/anthropic/README.md](../../provider/anthropic/README.md):

```bash
warden provider enable --type=anthropic anthropic
warden write anthropic/config \
     anthropic_url=https://api.anthropic.com \
     auto_auth_path=auth/jwt/ \
     timeout=120s

warden cred source create anthropic-src --type=apikey \
     --config=api_url=https://api.anthropic.com \
     --config=verify_endpoint=/v1/models \
     --config=auth_header_type=custom_header \
     --config=auth_header_name=x-api-key

warden cred spec create anthropic-ops --source anthropic-src \
     --config api_key=<your-anthropic-key>

warden write auth/jwt/role/anthropic-ops \
     bound_claims='{"repository":"admin/policy-hygiene","ref":"refs/heads/main","ref_type":"branch"}' \
     cred_spec_name=anthropic-ops \
     token_policies=agent-policy
```

This is the only place the Anthropic key is ever entered. Warden's Anthropic
provider strips any incoming `x-api-key` and `anthropic-version` headers
([provider/anthropic/provider.go:44-45](../../provider/anthropic/provider.go#L44-L45))
and injects its own stored values, so what the agent sends in those headers
is irrelevant — Warden replaces it. SSE streaming passes through unbuffered
([provider/httpproxy/gateway.go](../../provider/httpproxy/gateway.go)).

### 5d. One access policy covering both gateways — fine-grained

The whole point of this tutorial is policy hygiene, so the agent's own access
policy practices what it preaches: **only the exact paths and capabilities
the recipe needs, nothing more.** A wildcard like
`vault/role/policy-scanner/gateway/*` with full CRUD would let the agent
*modify or delete* OpenBao policies — exactly the `least_privilege_smell` the
recipe is meant to flag.

The agent's full call inventory:

| Recipe step | Upstream HTTP | CBP capability needed |
|---|---|---|
| `bao policy list` | `LIST /v1/sys/policies/acl` | `list` on `…/v1/sys/policies/acl` |
| `bao policy read <name>` | `GET /v1/sys/policies/acl/<name>` | `read` on `…/v1/sys/policies/acl/*` |
| `bao secrets list` | `GET /v1/sys/mounts` | `read` on `…/v1/sys/mounts` |
| `bao auth list` | `GET /v1/sys/auth` | `read` on `…/v1/sys/auth` |
| `bao list identity/entity/id` | `LIST /v1/identity/entity/id` | `list` on `…/v1/identity/entity/id` |
| `bao read identity/entity/id/<id>` | `GET /v1/identity/entity/id/<id>` | `read` on `…/v1/identity/entity/id/*` |
| Goose Anthropic SDK | `POST /v1/messages` | `create` on `…/v1/messages` |
| Pre-flight check | `GET /v1/models` | `read` on `…/v1/models` |

Note the doubled `/v1/`: Warden's CBP policy operates on logical paths
(without the leading `/v1/` of the Warden URL), but the proxied OpenBao /
Anthropic path *itself* starts with `v1/`. So policy stanzas read
`vault/role/policy-scanner/gateway/v1/sys/policies/acl`, not
`vault/role/policy-scanner/gateway/sys/policies/acl`.

```bash
cat > /tmp/agent-policy.hcl <<'EOF'
# ── OpenBao read-only policy introspection ─────────────────────────────
path "vault/role/policy-scanner/gateway/v1/sys/policies/acl" {
  capabilities = ["list"]
}
path "vault/role/policy-scanner/gateway/v1/sys/policies/acl/*" {
  capabilities = ["read"]
}

# ── Mount + auth method enumeration (for dead-mount detection) ─────────
path "vault/role/policy-scanner/gateway/v1/sys/mounts" {
  capabilities = ["read"]
}
path "vault/role/policy-scanner/gateway/v1/sys/auth" {
  capabilities = ["read"]
}

# ── Identity entity introspection (for orphan-binding detection) ───────
path "vault/role/policy-scanner/gateway/v1/identity/entity/id" {
  capabilities = ["list"]
}
path "vault/role/policy-scanner/gateway/v1/identity/entity/id/*" {
  capabilities = ["read"]
}

# ── Anthropic: only Messages + Models, nothing else ────────────────────
path "anthropic/role/anthropic-ops/gateway/v1/messages" {
  capabilities = ["create"]
}
path "anthropic/role/anthropic-ops/gateway/v1/models" {
  capabilities = ["read"]
}
EOF
warden policy write agent-policy /tmp/agent-policy.hcl
```

This policy is what enforcement looks like end-to-end: even if the LLM
hallucinates a `bao policy delete` or a curl to `/v1/admin-api-keys`, Warden
returns 403. The agent's authority is bounded by what the recipe requires,
not by what its credentials happen to allow.

If you discover Warden 403s on a path you legitimately need (e.g. you extend
the recipe to read group bindings), tail Warden's audit log to see the
exact path being denied, then add the minimal stanza. The CBP capabilities
are: `create`, `read`, `update`, `delete`, `list`, `patch`
([core/policy.go:22-29](../../core/policy.go#L22-L29)).

Both `auth/jwt/role/*` definitions in 5b and 5c attached `agent-policy` via
`token_policies`, so any JWT that satisfies the `bound_claims` gets exactly
this access — no more, no less.

## 6. The Goose recipe

Save this as `policy-hygiene.yaml` in the `admin/policy-hygiene` repo. It
uses the recipe schema documented in [Goose's `recipe-reference`](https://goose-docs.ai/docs/guides/recipes/recipe-reference).

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
  do not log in, do not set a token.

  Collect the ground truth first (make these calls once, cache the output):
    - `bao policy list`                  → all policy names
    - `bao secrets list -format=json`    → mounted secret engines
    - `bao auth list -format=json`       → mounted auth methods
    - `bao list -format=json identity/entity/id`  → live identity entity IDs
    - For each entity: `bao read -format=json identity/entity/id/<id>`
        to build a map { policy_name -> [entities_binding_it] }

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
  {{ warden_addr }}. Start by gathering the ground-truth lists, then iterate
  through every policy. Return the structured report defined in the response
  schema.

extensions:
  - type: builtin
    name: developer
    description: "Shell + file tools so the agent can run the bao CLI"

settings:
  goose_provider: anthropic
  goose_model: claude-sonnet-4-6
  temperature: 0.2
  max_turns: 40

response:
  json_schema:
    type: object
    required: [policies, summary, ground_truth]
    properties:
      ground_truth:
        type: object
        required: [secret_mounts, auth_mounts, live_entities]
        properties:
          secret_mounts: { type: array, items: { type: string } }
          auth_mounts:   { type: array, items: { type: string } }
          live_entities: { type: integer }
      summary:
        type: object
        required: [total, critical, warning, ok]
        properties:
          total:    { type: integer }
          critical: { type: integer }
          warning:  { type: integer }
          ok:       { type: integer }
      policies:
        type: array
        items:
          type: object
          required: [name, severity, bound_entities, findings]
          properties:
            name:           { type: string }
            severity:       { type: string, enum: [ok, warning, critical] }
            bound_entities: { type: integer }
            findings:
              type: array
              items:
                type: object
                required: [category, line_excerpt, remediation]
                properties:
                  category:
                    type: string
                    enum: [dead_mount_reference, orphan_binding, duplicate_or_contradictory_path, least_privilege_smell]
                  line_excerpt: { type: string }
                  remediation:  { type: string }
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
- `response.json_schema` forces structured output so the result is pipeable
  through `jq`.

## 7. The Forgejo Actions workflow

Save this as `.forgejo/workflows/hygiene.yaml` in the same repo. The workflow
explicitly fetches an OIDC JWT (the GitHub/Forgejo Actions model:
`permissions: id-token: write` unlocks `$ACTIONS_ID_TOKEN_REQUEST_URL` plus
`$ACTIONS_ID_TOKEN_REQUEST_TOKEN`), copies it into both `VAULT_TOKEN` and
`ANTHROPIC_API_KEY`, and runs Goose.

```yaml
name: policy-hygiene
on:
  push:
    branches: [main]
  workflow_dispatch:

permissions:
  id-token: write       # required to request OIDC JWTs inside a step

jobs:
  hygiene:
    runs-on: docker
    container:
      image: alpine:3.20
    env:
      WARDEN_ADDR:    http://host.docker.internal:8400
      VAULT_ADDR:     http://host.docker.internal:8400/v1/vault/role/policy-scanner/gateway
      ANTHROPIC_HOST: http://host.docker.internal:8400/v1/anthropic/role/anthropic-ops/gateway
    steps:
      - uses: actions/checkout@v4

      - name: Install bao + goose CLIs
        run: |
          apk add --no-cache curl jq bash ca-certificates
          curl -fsSL https://github.com/openbao/openbao/releases/download/v2.5.3/bao_2.5.3_Linux_x86_64.tar.gz \
            | tar xz -C /usr/local/bin
          curl -fsSL https://github.com/aaif-goose/goose/releases/latest/download/download_cli.sh | bash

      - name: Mint Warden JWT from Forgejo OIDC
        run: |
          WARDEN_JWT=$(curl -sSL \
            -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
            "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=http://warden.local" \
            | jq -r .value)
          echo "::add-mask::$WARDEN_JWT"
          echo "WARDEN_JWT=$WARDEN_JWT" >> $GITHUB_ENV

      - name: Pre-flight both Warden legs
        run: |
          export VAULT_TOKEN="$WARDEN_JWT"
          bao policy list > /dev/null \
            || { echo "Warden->OpenBao leg broken"; exit 1; }
          curl -sf -H "x-api-key: $WARDEN_JWT" -H "anthropic-version: 2023-06-01" \
               "$ANTHROPIC_HOST/v1/models" > /dev/null \
            || { echo "Warden->Anthropic leg broken"; exit 1; }

      - name: Run Goose hygiene audit
        run: |
          export VAULT_TOKEN="$WARDEN_JWT"
          export ANTHROPIC_API_KEY="$WARDEN_JWT"
          goose run --recipe policy-hygiene.yaml \
              --params warden_role=policy-scanner warden_addr=$WARDEN_ADDR \
              > hygiene-report.json

      - uses: actions/upload-artifact@v3
        if: always()
        with:
          name: hygiene-report
          path: hygiene-report.json
```

A few notes on the workflow:

- `permissions: id-token: write` is the key — without it,
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

Open `http://forgejo.local:3000/admin/policy-hygiene/actions` and watch the
`policy-hygiene` workflow. When it finishes, download the `hygiene-report`
artifact from the run page, or via API:

```bash
curl -H "Authorization: token <PAT>" \
     "http://forgejo.local:3000/api/v1/repos/admin/policy-hygiene/actions/artifacts/<id>/zip" \
     -o hygiene-report.zip
unzip hygiene-report.zip
jq '.summary, .policies[] | select(.severity != "ok")' hygiene-report.json
```

Expected (trimmed) output across the five seed policies:

- `clean` — severity `ok`, `bound_entities: 1`, no findings.
- `root-ish` — severity `critical`, finding `least_privilege_smell` citing
  the `sudo` line.
- `dead-mount` — severity `warning`, finding `dead_mount_reference` citing
  `kv-legacy/*`, remediation "remove stanza or mount kv-legacy".
- `duplicates` — severity `warning`, finding
  `duplicate_or_contradictory_path`.
- `orphan` — severity `warning`, `bound_entities: 0`, finding
  `orphan_binding`.

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
jq -r 'select(.type == "request") | .request.mount_point' /tmp/warden-audit.log \
  | sort | uniq -c
#       6 anthropic/        (LLM turns + 1 pre-flight)
#      12 vault/            (5 policies + secrets/auth list + entity reads + pre-flight)

# What did the JWT actually grant?
jq -r 'select(.type == "request") | [.auth.principal_id, .auth.role_name, .request.path] | @tsv' \
  /tmp/warden-audit.log | sort -u | head
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
    "principal_id": "repository:admin/policy-hygiene:ref:refs/heads/main",
    "role_name": "policy-scanner",
    "policies": ["agent-policy"],
    "policy_results": {
      "granting_policies": ["agent-policy"]
    }
  }
}
```

Three things to verify here:

1. **`auth.principal_id`** is derived from Forgejo's JWT claims (`repository`,
   `ref`) — proof that the identity comes from the OIDC token, not a stored
   token in the agent's environment.
2. **`auth.policy_results.granting_policies`** names `agent-policy` — proof
   that the fine-grained access stanzas from section 5d are what authorized
   the call. If the agent had tried `bao policy delete orphan`, this entry
   would carry `error: "permission denied"` and a `403` response status,
   because no stanza in `agent-policy` grants `delete` on
   `/v1/sys/policies/acl/*`.
3. **`request.transparent: true`** ([audit/types.go:54](../../audit/types.go#L54))
   marks calls that came in via the `role/*/gateway/*` path — i.e., that
   Warden authenticated the client via JWT in a header rather than a Warden
   session token. This is how you spot agentic traffic in a busy log.

The audit field reference: request shape at [audit/types.go:30-54](../../audit/types.go#L30-L54),
response shape at [audit/types.go:58-72](../../audit/types.go#L58-L72), auth
shape at [audit/types.go:87-97](../../audit/types.go#L87-L97).

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
to the production Warden URL. If you're moving to GitLab, the workflow
syntax also shifts from GitHub-Actions-style (`permissions: id-token: write`
plus a curl to `$ACTIONS_ID_TOKEN_REQUEST_URL`) to GitLab's `id_tokens:`
auto-injection — slight syntax difference, identical mechanism. On Forgejo
or GitHub Actions, the workflow file is unchanged.

That's it. The recipe is unchanged, the Goose code path is unchanged, and
the OpenBao/Anthropic provider configuration in Warden is unchanged.
Production inherits the full audit trail: every request in Warden's log
carries the CI's full run provenance — repo, branch, workflow ref, job id,
actor.

Three operational adjustments worth making explicit in production:

- Rotate the upstream `openbao-root` source to an AppRole scoped to
  `read`/`list` on `sys/policies/acl/*` only. Dev uses the root token for
  expedience; production must not.
- Rotate the Anthropic key by updating the spec in Warden. The CI job is
  unaffected — it still authenticates with its JWT.
- Ship the audit log enabled in section 4 to a SIEM (Splunk, Elastic,
  Datadog) instead of a local file: `warden audit enable --type=socket
  --address=siem:9514` or `--type=syslog`. The JSON shape is the same as in
  section 8.

## 10. What's next

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
