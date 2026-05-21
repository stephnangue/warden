# AWS Access Hygiene Audit with Goose, the AWS CLI, and Warden

> **Status:** scaffolding only. This PR ships the Forgejo + runner stack and the directory layout. AWS provider wiring, the Goose recipe, the CI workflow, and the conceptual narrative arrive in follow-up PRs.

This tutorial stands up an AI agent that audits a sandbox AWS account's IAM
through **four read-only lenses** — inventory, recent usage, external
exposure, effective access — and publishes findings to Security Hub and a
human-readable canvas to Slack. The agent is built with
[Goose](https://goose-docs.ai/), authenticates with a per-job OIDC JWT
issued by a local Forgejo instance, and reaches AWS and Slack exclusively
through Warden. The agent holds zero credentials: no IAM access keys, no
Slack bot token.

What makes this tutorial worth reading is **how the agent switches AWS
roles between calls**. The companion tutorial [vault-policy-hygiene](../vault-policy-hygiene/README.md)
demonstrates discover-and-connect across providers (one Vault role for
the audit, one Slack role for delivery). This one demonstrates it *within*
the AWS provider: the agent reads the descriptions of several AWS roles
exposed by Warden, picks a different one per call based on the operation
at hand, and a write-scoped role is reachable only through deliberate
selection that the audit log records as a phase transition.

Versions pinned in this tutorial: Forgejo **15.x**, Forgejo Runner
**12.8.0**, Goose **1.32.0**, Warden **0.13.2**. Forgejo 15+ and Runner
12.5+ are required for the per-job OIDC token feature this tutorial relies
on. The JWKS path discovery in section 3 will handle Forgejo version drift
within the 15.x line automatically.

---

## 1. What you'll build

A Forgejo Actions workflow pushes a Goose recipe; the runner spawns a
Goose agent inside a container. The runtime sets three env vars before
spawning the agent: `WARDEN_ADDR`, `WARDEN_NAMESPACE=tutorial-aws`,
`WARDEN_TOKEN=<jwt>`. **Nothing else is pre-configured for the agent.**

At runtime the agent:

1. Reads the `foundation` and `discovery` skills from `/v1/sys/skills/...`.
2. Calls `warden role list` — introspects the JWT and returns every role
   the identity may assume in the `tutorial-aws/` namespace, with
   operator-set descriptions.
3. Calls `warden provider list` — returns every provider mounted in the
   namespace.
4. Reads role descriptions and picks one per sub-task: distinct roles for
   IAM inventory, CloudTrail usage, Access Analyzer external-exposure,
   IAM policy simulator, and Security Hub finding publication. A
   different role for the Slack canvas. The recipe encodes the *shape*
   of the audit (the lenses, the deliverable); the roles that carry each
   lens are discovered live, never named.
5. Calls `warden skill read <type>` for each chosen provider — gets the
   exact CLI recipe (env vars to set, URL shape).
6. Executes the audit. Between AWS calls, the agent swaps
   `AWS_ACCESS_KEY_ID` to switch roles — the audit log records this as a
   sequence of distinct `auth.role_name` values, all under the same JWT.

Warden validates the JWT on every call, applies the policy attached to
the resolved role, mints short-lived AWS credentials via `sts:AssumeRole`
into a narrowly-scoped IAM role chosen by the spec, resigns the request,
and forwards. The agent never sees any real AWS access keys or the Slack
bot token.

The reader's iteration loop is: edit the recipe, push to Forgejo, watch
the workflow, inspect Security Hub and Slack. Production is a URL swap.

## 2. Prerequisites

PR 1 only stands up the Forgejo + runner stack. The full tutorial adds
prerequisites for AWS and Slack in follow-up PRs; this section will be
expanded then.

- Docker + Docker Compose, ~1 GB RAM free (Forgejo ~250 MB, runner ~80 MB).
- `git` client.
- `curl` and `jq` for the OIDC discovery step in §3 step 5.

A Go toolchain (for `go install` of Warden) and an AWS sandbox account
are required for the follow-up PRs but not for this scaffold.

## 3. Bring up the stack with Docker Compose

The three files we'll use (`docker-compose.yml`, `forgejo-init.sh`,
and — in a follow-up PR — `aws-init.sh` / `warden-init.sh`) are
alongside this README. Either `cd` into this folder to run them in
place, or copy them to a fresh working directory.

`docker-compose.yml` runs Forgejo, the Forgejo runner, and a one-shot
init service that bootstraps the `siteowner` admin user:

```yaml
services:
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

Make sure the script is executable: `chmod +x forgejo-init.sh`.

Then:

1. Map `forgejo.local` to localhost so both your browser and Warden's JWT
   validator resolve it (the JWT's `iss` claim must match `bound_issuer`):
   ```bash
   echo "127.0.0.1 forgejo.local" | sudo tee -a /etc/hosts
   ```
2. Start Forgejo and run the init service:
   ```bash
   docker compose up -d forgejo
   docker compose up forgejo-init   # exits on success
   ```
   Confirm Forgejo's healthcheck:
   ```bash
   curl -sf http://forgejo.local:3000/api/healthz
   ```
   `forgejo-init` provisions the `siteowner` admin.
3. Sign in at `http://forgejo.local:3000/` as `siteowner` / `warden-tutorial`,
   create a new repo `siteowner/aws-access-hygiene`, then clone it locally:
   ```bash
   git clone http://forgejo.local:3000/siteowner/aws-access-hygiene.git
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
   `forgejo.local`:
   ```bash
   cat > runner-config/config.yaml <<'EOF'
   container:
     options: "--add-host=forgejo.local:host-gateway --add-host=host.docker.internal:host-gateway"
   EOF
   docker compose up -d runner
   ```
5. Discover Forgejo's **Actions** OIDC config — Warden will use these URLs
   in the follow-up PR's section 5. Forgejo has two OIDC contexts:
   user-login (under `/.well-known/...`) and per-job Actions (under
   `/api/actions/...`). The per-job JWTs this tutorial uses come from the
   second one:
   ```bash
   curl -sf http://forgejo.local:3000/api/actions/.well-known/openid-configuration | \
     jq '{issuer, jwks_uri}'
   ```
   On Forgejo 15.x you'll typically see
   `http://forgejo.local:3000/api/actions` and
   `http://forgejo.local:3000/api/actions/.well-known/keys`. Use whatever
   the discovery endpoint returns — do not hardcode.

---

> The remaining sections — Warden dev-mode startup (§4), namespace and
> provider wiring (§5), the within-provider role-switching narrative (§6),
> Goose's discovery loop (§7), the recipe (§8), the Forgejo Actions
> workflow (§9), the audit-log walkthrough (§10), and production / cleanup
> / next steps (§11–13) — arrive in follow-up PRs.
