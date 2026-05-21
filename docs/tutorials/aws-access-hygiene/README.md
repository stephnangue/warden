# AWS Access Hygiene Audit with Goose, the AWS CLI, and Warden

> **Status:** operator setup is complete (Forgejo + runner stack and the AWS / Warden / Slack wiring); the Goose recipe, the CI workflow, the conceptual narrative, and the audit-log walkthrough arrive in follow-up PRs.

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

- Docker + Docker Compose, ~1 GB RAM free (Forgejo ~250 MB, runner ~80 MB).
  Warden runs on the host.
- `git` client.
- `curl` and `jq` (the latter is also used by `aws-init.sh` to build
  IAM trust policies).
- A Go toolchain for `go install` of Warden, or a prebuilt `warden`
  binary on PATH.
- An AWS sandbox account and the **AWS CLI v2** authenticated as a
  principal that can create IAM users, IAM roles, and access keys. The
  audit also calls Security Hub, so **Security Hub must be enabled in
  the chosen region** (default `us-east-1`). The credentials you use to
  run `aws-init.sh` are only used to bootstrap the broker; they never
  enter Warden or the agent's environment.
- (Optional, for Slack delivery) A Slack workspace, a [bot user OAuth token](https://api.slack.com/authentication/token-types#bot)
  (`xoxb-...`) with the `canvases:write`, `channels:read`, and
  `chat:write` scopes, and a channel ID the bot is a member of. The
  token goes into Warden, never into a CI variable. The channel ID and
  name are passed to `warden-init.sh` and embedded into the
  `hygiene-poster` role description — the agent reads them from there,
  not from any env var. Skip this to fall back to Security Hub-only
  delivery.

The `aws`, `goose`, and `warden` CLIs are installed inside the Actions
job's container in PR 3; you do not run them on the host beyond the
operator setup steps below.

## 3. Bring up the stack with Docker Compose

The files we'll use (`docker-compose.yml`, `forgejo-init.sh`,
`aws-init.sh`, `warden-init.sh`) are alongside this README. Either `cd`
into this folder to run them in place, or copy them to a fresh working
directory.

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

## 4. Start Warden in dev mode

In a new shell:

```bash
warden server --dev --dev-root-token=dev-warden-root
```

Dev mode persists everything to an ephemeral in-memory store and writes
an audit log to `warden-audit.log` in the current directory — convenient
for the demo and disposable. For the admin shell that runs the wiring
script in §5, export:

```bash
export WARDEN_ADDR=http://127.0.0.1:8400
export WARDEN_TOKEN=dev-warden-root
```

The agent will use a different token (the Forgejo Actions OIDC JWT)
when it runs in §9; these admin variables are only for `warden-init.sh`.

## 5. Wire Warden: namespace, JWT auth, AWS + Slack providers, roles, policies

The wiring runs in two scripts, both alongside this README:

- `aws-init.sh` — provisions the **AWS-side primitives** Warden's
  AssumeRole specs depend on: one broker IAM user and five
  narrowly-scoped IAM roles in your sandbox account. Outputs broker
  access keys and role ARNs to `aws-out/creds.env`.
- `warden-init.sh` — wires **Warden**: namespace, JWT auth, AWS
  provider, one credential source (the broker keys), five AssumeRole
  credential specs (one per active Warden role), the five active
  Warden roles, three decoy roles, the Slack provider (optional), and
  all access policies. Reads `aws-out/creds.env` for ARNs and keys.

The decoupling is deliberate. Warden never holds the AWS-side
permission policies; those live entirely at AWS on the assumed IAM
roles. Warden holds only the broker user's static keys and the
configuration that says "for role X, assume IAM role Y." Per-lens
least-privilege is therefore enforced **at AWS** via the AssumeRole
chain — Warden's contribution is per-call audit attribution and the
credential-routing chain itself.

### 5a. Provision the AWS-side prereqs

Make `aws-init.sh` executable and run it against your sandbox account:

```bash
chmod +x aws-init.sh
./aws-init.sh                                  # uses caller's account, us-east-1
./aws-init.sh --account-id=123456789012 \
              --region=eu-west-1               # or specify explicitly
```

What the script does, idempotently:

1. Creates a broker IAM user `warden-aws-tutorial-broker` with **no**
   operational permissions. Its only attached policy allows
   `sts:AssumeRole` on exactly the five role ARNs the script also
   creates — no wildcards, no other actions.
2. Creates five IAM roles, each with:
   - A trust policy admitting only the broker IAM user as a principal:
     ```json
     {
       "Version": "2012-10-17",
       "Statement": [{
         "Effect": "Allow",
         "Principal": { "AWS": "arn:aws:iam::<account>:user/warden-aws-tutorial-broker" },
         "Action": "sts:AssumeRole"
       }]
     }
     ```
   - A narrow inline permissions policy matching its purpose. Example
     for `tutorial-iam-reader-role`:
     ```json
     {
       "Version": "2012-10-17",
       "Statement": [{
         "Effect": "Allow",
         "Action": ["iam:Get*", "iam:List*"],
         "Resource": "*"
       }]
     }
     ```
   The other four roles get equivalently narrow policies for
   `cloudtrail:LookupEvents` + `cloudtrail:Describe*`,
   `access-analyzer:Get*` + `access-analyzer:List*`,
   `iam:SimulatePrincipalPolicy`, and
   `securityhub:BatchImportFindings` only.
3. Mints a broker access key pair and writes everything to
   `aws-out/creds.env` for `warden-init.sh` to source.

If the broker user already exists but `aws-out/creds.env` is missing
(AWS won't let you re-read a secret access key after creation),
re-run with `--rotate-key` to drop the orphan key and mint a fresh
one.

### 5b. Run the Warden wiring

With Warden running (§4) and `aws-out/creds.env` populated:

```bash
chmod +x warden-init.sh
./warden-init.sh                                                      # AWS only
./warden-init.sh --slack-token=xoxb-... \
                 --slack-channel-id=C0XXXXXXX \
                 --slack-channel-name='#access-audits'                # + Slack
```

What it provisions, in order:

1. **Namespace** `tutorial-aws/` with `custom_metadata.auto_auth_path=auth/jwt/`
   — so the agent's bare-JWT discovery calls to `/v1/sys/*` get
   implicit authentication.
2. **JWT auth** pointed at Forgejo's Actions OIDC (the JWKS URL
   discovered in §3 step 5), with `default_role=discovery-baseline`
   as the fallback when the URL carries no role segment.
3. **discovery-baseline role + policy** — read-only access on the four
   `sys/*` paths the agent's discovery loop hits, scoped to the
   tutorial repo by `bound_claims`.
4. **AWS provider** enabled at `aws/`, configured with the
   *mandatory* `auto_auth_path=auth/jwt/`:
   ```bash
   warden write aws/config auto_auth_path=auth/jwt/
   ```
   `proxy_domains` is left unset. Unlike Vault's provider where it
   gates request forwarding, the AWS provider's `proxy_domains` is
   consulted only by the S3 processors for virtual-hosted bucket URL
   rewriting — and this tutorial uses no S3 calls.
5. **One AWS credential source** `demo-aws-source` (type `aws`,
   `mint_method` implicit) backed by the broker's access keys plus the
   chosen region. Stored once in Warden; never enters the agent's
   environment.
6. **Five AWS credential specs**, each of type `aws_access_keys`
   (inferred), with `mint_method=sts_assume_role` and a distinct
   target IAM role ARN. At runtime, when the agent calls Warden under
   `iam-reader`, Warden uses the broker keys to `sts:AssumeRole` on
   `tutorial-iam-reader-role`, gets 1-hour temporary credentials,
   resigns the request, and forwards. Each call therefore lands at
   AWS as a *narrow, temporary, lens-specific* identity:
   ```bash
   warden cred spec create iam-reader-spec --source demo-aws-source \
       --config mint_method=sts_assume_role \
       --config role_arn="$WARDEN_AWS_ROLE_IAM_READER_ARN" \
       --config session_name=warden-iam-reader \
       --config ttl=1h
   # ...repeated for cloudtrail-reader-spec, access-analyzer-reader-spec,
   # policy-simulator-spec, securityhub-writer-spec.
   ```
7. **Five active AWS Warden roles**, each bound to one spec. Role
   descriptions are dense and operator-set — the agent reads them
   verbatim from `warden role list` and matches each one to a lens by
   what data it can access, what region's resources it covers (for
   regional services), and what it is *not* for. The call-shape
   contract (env vars, URL pattern) is *not* in the role description
   — it lives in the AWS provider's skill (`warden skill read aws`):
   - **`iam-reader`** — read-only IAM inventory (global service)
   - **`cloudtrail-reader`** — CloudTrail `LookupEvents` in the
     chosen region
   - **`access-analyzer-reader`** — Access Analyzer
     `ListAnalyzers`/`ListFindings` in the chosen region
   - **`policy-simulator-runner`** — IAM `SimulatePrincipalPolicy`
     (global service, dry-run effective access)
   - **`securityhub-writer`** — `securityhub:BatchImportFindings`
     in the chosen region; ingest only
8. **Three AWS decoy roles** — `iam-admin`, `securityhub-admin`,
   `account-root-bridge`. Same JWT identity as the active roles,
   descriptions that explicitly warn they are destructive or
   break-glass, and **no `cred_spec_name`**. Invoking one fails at
   credential minting before any AWS call leaves Warden. Decoys exist
   for the agent to read and *reject* by description — they prove that
   the picker is description-driven, not provider-typed.
9. **One AWS access policy** `aws-gateway-access`, attached to all
   five active AWS roles. It is uniform across roles because Warden's
   AWS gateway cannot distinguish SigV4 service or action at the
   policy layer (the AWS provider does not set `ParseStreamBody`).
   The capability list mirrors what the AWS API actually uses — `read`
   for GETs, `create` for POSTs, `list` for paginated `?list=true`
   GETs:
   ```hcl
   path "aws/gateway"   { capabilities = ["read", "create", "list"] }
   path "aws/gateway/*" { capabilities = ["read", "create", "list"] }
   ```
   Per-lens least-privilege is enforced *at AWS*, not by this policy.
10. **Slack provider** (only when `--slack-token` is given) plus its
    source, spec, the active `hygiene-poster` role (channel embedded
    in the description), and a `slack-hygiene-poster` policy granting
    `create` on the Slack Web API methods the agent will call. A
    `alert-poster` decoy role is added without a spec.

### 5c. Sanity-check the wiring

In the admin shell, read the Warden config back:

```bash
export WARDEN_NAMESPACE=tutorial-aws
warden role list -F name,description
warden provider list -F type,description,mount_url
warden policy read aws-gateway-access
warden cred source read demo-aws-source
warden cred spec read iam-reader-spec
```

You should see ten roles (`discovery-baseline` + 5 active AWS + 3 decoy
AWS + `hygiene-poster` if Slack is on + `alert-poster` decoy if Slack
is on), two provider mounts (`aws` and `slack` if enabled), and the
two-line gateway policy above. Decoy roles show empty `cred_spec_name`
fields — that is intentional; they fail at credential minting if the
agent picks them.

AWS-side trust smoke test — confirm the broker user can actually
assume each of the five IAM roles before any agent runs. This uses
the broker keys directly, bypassing Warden, to isolate the
IAM-trust-policy half of the chain:

```bash
. aws-out/creds.env

for arn in "$WARDEN_AWS_ROLE_IAM_READER_ARN" \
           "$WARDEN_AWS_ROLE_CLOUDTRAIL_READER_ARN" \
           "$WARDEN_AWS_ROLE_ACCESS_ANALYZER_ARN" \
           "$WARDEN_AWS_ROLE_POLICY_SIMULATOR_ARN" \
           "$WARDEN_AWS_ROLE_SECURITYHUB_WRITER_ARN"; do
  AWS_ACCESS_KEY_ID="$WARDEN_AWS_BROKER_ACCESS_KEY_ID" \
  AWS_SECRET_ACCESS_KEY="$WARDEN_AWS_BROKER_SECRET_ACCESS_KEY" \
  aws sts assume-role \
    --role-arn "$arn" \
    --role-session-name "smoke-$(basename "$arn")" \
    --query 'AssumedRoleUser.Arn' --output text
done
```

Each line should print an `arn:aws:sts::<account>:assumed-role/...`
identity matching the corresponding role. If a role's trust policy or
the broker's `sts:AssumeRole` policy is wrong, the call fails — fix
`aws-init.sh` or re-run with `--rotate-key`.

The end-to-end Warden → AWS test (which requires a Forgejo-signed JWT)
runs as part of PR 3's first agent invocation.

---

> The remaining sections — the within-provider role-switching narrative
> (§6), Goose's discovery loop (§7), the recipe (§8), the Forgejo Actions
> workflow (§9), the audit-log walkthrough (§10), and production /
> cleanup / next steps (§11–13) — arrive in follow-up PRs.
