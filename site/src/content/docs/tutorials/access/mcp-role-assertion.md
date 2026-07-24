---
title: "Asserting a Role Per MCP Call with Warden"
sidebar:
  label: "MCP role assertion"
---

**Goal:** give one agent a single identity, then watch it borrow a **different role for each
task** — and get refused the moment it reaches for authority its identity was never granted.
You'll front **GitHub's hosted MCP server** with Warden, define four roles, and let Claude
drive them. Three roles the agent can assume; a fourth it cannot. The agent creates a repo,
files and closes an issue, and reads a file — each under its own role — then tries to create
a repo it has no role for, and Warden refuses it at the gateway.

An agent authenticates to Warden with a JWT from **Ory Hydra**. It holds nothing else: no
GitHub token (Warden injects that per request), and no standing GitHub access. Every call
**names a role**, Warden resolves that role fresh, and only the roles the agent's identity is
admitted to ever resolve.

| | One broad token (ambient authority) | Per-call role assertion (this tutorial) |
|---|---|---|
| What the agent holds | a token whose scopes can do everything | one identity JWT; each call names a role |
| Creating a repo | can create/delete **any** repo | only the repo the named role's policy allows |
| The `warden-forbidden` repo | just another API call away | **no role the agent can assume permits it** — refused at Warden |
| The GitHub token | sits on the agent | injected by Warden per role, never on the agent |

---

## The problem

Point an MCP client at a hosted server the usual way and it holds one long-lived token for
the whole session. Reaching the system becomes doing anything in it: *"can reach GitHub"*
silently becomes *"can delete any repository."* Authority sits on the connection, waiting to
be reused — by the next task, by a hallucinated tool call, by a prompt-injection payload.
There is nothing per-request deciding *which* task is allowed to do *what*.

## The solution

Give the agent one identity and put **roles** between it and GitHub. A role is a named,
reusable definition — set by an operator — that Warden resolves **on every request** into
three things: *who may assume it* (the identity binding), *what it may do* (its policy), and
*what credential Warden mints* upstream. The agent asks Warden *"what may I do?"*
([`list_roles`](/concepts/mcp/#warden-as-an-mcp-server-discovery-interface)), gets back only
the roles its identity is admitted to, and **asserts one role per call** by pointing at that
role's gateway. Authority rides on the call, never on the connection — so there is no ambient
grant to reuse, and a task can only ever touch its own slice. See [Roles](/concepts/roles/)
and [Runtime authorization](/use-cases/runtime-authorization/) for the full picture.

### The four roles

All four front the same `github-mcp` mount; each projects a different slice of it. Three bind
to the agent's identity; the fourth binds to a different one.

| Role | What its policy grants | Scoped to repo | Agent can assume? |
|------|------------------------|----------------|-------------------|
| `repo-lifecycle` | create the repo, write & delete its files | `warden-role-assertion` | ✅ |
| `issue-triage` | open & close issues | `warden-role-assertion` | ✅ |
| `repo-reader` | read files | `warden-role-assertion` | ✅ |
| `forbidden-repo-lifecycle` | create the repo, write & delete its files | `warden-forbidden` | ❌ — bound to another identity |

The fourth role is real and fully functional — it just belongs to a **different principal**
(think: a human admin). The agent holds the wrong identity for it, so Warden never admits the
agent to it: it is invisible in `list_roles` and rejected at the gateway. That is the whole
lesson — the wall is the identity binding, checked on every request.

### Prerequisites

- **Docker** and **Docker Compose**
- **[Claude Code](https://docs.claude.com/en/docs/claude-code)**
- A **GitHub Personal Access Token** (classic, scope `repo`) — Warden verifies it when you
  create the credential, so it must be valid. You'll paste it into a single Warden command in
  Step 4. **Don't put it in an environment variable** — keeping it out of your shell is the
  whole point: no agent you launch from this shell (Claude included) ever sees it.
- The **Warden CLI + server** binary. This installs the latest release for your platform:
  ```bash
  curl -sL https://wardengateway.com/install | bash
  warden --version      # confirm it's on your PATH
  ```

### Get the files

The Docker Compose stack (Ory Hydra) for this tutorial lives in the
[**warden-tuto**](https://github.com/stephnangue/warden-tuto) repository. Clone it and work
from the tutorial folder:

```bash
git clone https://github.com/stephnangue/warden-tuto.git
cd warden-tuto/access-mcp-role-assertion
```

### Step 1 — start the identity provider (Hydra)

```bash
docker compose up -d

# wait ~10s for Hydra to initialize and create the OAuth2 client, then confirm:
docker compose logs hydra-client-init | grep my-agent   # ->  [OK] my-agent
```

This runs Ory Hydra with an in-memory database and one pre-created client, `my-agent` /
`agent-secret`, that mints JWTs via the OAuth2 `client_credentials` grant. For that grant the
JWT's `sub` claim is the client id — `my-agent` — which is exactly the identity our roles
bind against.

### Step 2 — start Warden (dev mode)

In a **separate terminal**, run the Warden server in the foreground (dev mode: in-memory,
auto-unsealed, root token `root`):

```bash
warden server --dev --dev-root-token=root
```

Back in your first terminal, point the CLI at it:

```bash
export WARDEN_ADDR=http://127.0.0.1:8400
export WARDEN_TOKEN=root
warden status          # sealed: false
```

### Step 3 — trust Hydra's JWTs

Enable the [JWT auth method](/auth-methods/jwt/) and point it at Hydra via OIDC discovery.
Warden runs on your host, so it reaches Hydra at `localhost:4444` for both discovery and key
fetching:

```bash
warden auth enable jwt
warden write auth/jwt/config \
  oidc_discovery_url=http://localhost:4444 \
  bound_issuer=http://localhost:4444
```

### Step 4 — front GitHub's MCP server

This has four small pieces; run them one at a time.

**1. Mount the generic [`mcp` provider](/provider-backends/mcp/)** at a path that identifies
GitHub:

```bash
warden provider enable -path=github-mcp -description="GitHub Copilot MCP" mcp
```

**2. Point the mount at GitHub's MCP endpoint** and the JWT auth method:

```bash
warden write github-mcp/config \
  mcp_url=https://api.githubcopilot.com/mcp \
  auto_auth_path=auth/jwt/ \
  timeout=10m \
  max_body_size=10485760
```

**3. Create the credential source** — the connection info for GitHub:

```bash
warden cred source create github-src -type=github -rotation-period=0 \
  -config=github_url=https://api.github.com
```

**4. Store your PAT as a credential spec.** Warden injects it upstream per request, so the
agent never holds it. Paste your token directly in place of `ghp_your_token_here` — **don't**
put it in an environment variable, or an agent you run from this shell (Claude included)
would inherit it:

```bash
warden cred spec create github-ops -source github-src \
  -config auth_method=pat -config token=ghp_your_token_here
```

See [GitHub MCP](/provider-backends/mcp-github/) for App-based and OAuth credential options.

### Step 5 — define the four roles

Each role is a **policy** (what it may do, scoped to one repo) plus a **role binding** (who
may assume it, which credential it mints). Run the blocks below one at a time.

**1. `repo-lifecycle` — create `warden-role-assertion` and write & delete its files.**
GitHub's MCP server has no repo-*deletion* tool, so a repo's "lifecycle" here is creating it
and then owning its **contents**: `create_repository` makes the repo, `create_or_update_file`
writes files, and `delete_file` removes them. The condition scopes all of them to one repo,
keyed with `has()`: *if* an argument is present it must equal the repo. The tools name the
repo under **different keys** — `create_repository` takes `name` (the repo doesn't exist
yet), the file tools take `owner` + `repo` — so each key is pinned on its own line. A call
that carries neither key — `tools/list`, and the lifecycle handshake — passes untouched, so
the tool listing works with no special-case for the method:

```bash
warden policy write pol-repo-lifecycle - <<'EOF'
path "github-mcp/role/+/gateway*" {
  capabilities = ["create", "read", "delete"]
  mcp {
    allowed_methods = ["tools/list", "tools/call"]
    allowed_tools   = ["create_repository", "create_or_update_file", "delete_file"]
    condition = <<-CEL
      (!has(call.args.name) || call.args.name == "warden-role-assertion") &&
      (!has(call.args.repo) || call.args.repo == "warden-role-assertion")
    CEL
  }
}
EOF

warden write auth/jwt/role/repo-lifecycle \
  bound_subject=my-agent \
  token_policies=pol-repo-lifecycle \
  user_claim=sub \
  cred_spec_name=github-ops \
  description="create the warden-role-assertion repo and write & delete its files (skill: mcp)" \
  token_ttl=1h
```

**2. `issue-triage` — open & close issues on `warden-role-assertion`.** GitHub's MCP server
exposes a single `issue_write` tool for both — `method: "create"` opens an issue,
`method: "update"` with `state: "closed"` closes it — and it carries `repo`, so one `has()`
clause scopes it; a `tools/list`, which has no `repo`, passes untouched:

```bash
warden policy write pol-issue-triage - <<'EOF'
path "github-mcp/role/+/gateway*" {
  capabilities = ["create", "read", "delete"]
  mcp {
    allowed_methods = ["tools/list", "tools/call"]
    allowed_tools   = ["issue_write"]
    condition = <<-CEL
      !has(call.args.repo) || call.args.repo == "warden-role-assertion"
    CEL
  }
}
EOF

warden write auth/jwt/role/issue-triage \
  bound_subject=my-agent \
  token_policies=pol-issue-triage \
  user_claim=sub \
  cred_spec_name=github-ops \
  description="open & close issues on warden-role-assertion (skill: mcp)" \
  token_ttl=1h
```

**3. `repo-reader` — read files in `warden-role-assertion`:**

```bash
warden policy write pol-repo-reader - <<'EOF'
path "github-mcp/role/+/gateway*" {
  capabilities = ["create", "read", "delete"]
  mcp {
    allowed_methods = ["tools/list", "tools/call"]
    allowed_tools   = ["get_file_contents"]
    condition = <<-CEL
      !has(call.args.repo) || call.args.repo == "warden-role-assertion"
    CEL
  }
}
EOF

warden write auth/jwt/role/repo-reader \
  bound_subject=my-agent \
  token_policies=pol-repo-reader \
  user_claim=sub \
  cred_spec_name=github-ops \
  description="read files in warden-role-assertion (skill: mcp)" \
  token_ttl=1h
```

**4. `forbidden-repo-lifecycle` — create & delete `warden-forbidden`, bound to a different
identity.** The policy is fully functional; the only difference that matters is
`bound_subject=admin-agent` — an identity the agent does **not** hold:

```bash
warden policy write pol-forbidden - <<'EOF'
path "github-mcp/role/+/gateway*" {
  capabilities = ["create", "read", "delete"]
  mcp {
    allowed_methods = ["tools/list", "tools/call"]
    allowed_tools   = ["create_repository", "create_or_update_file", "delete_file"]
    condition = <<-CEL
      (!has(call.args.name) || call.args.name == "warden-forbidden") &&
      (!has(call.args.repo) || call.args.repo == "warden-forbidden")
    CEL
  }
}
EOF

warden write auth/jwt/role/forbidden-repo-lifecycle \
  bound_subject=admin-agent \
  token_policies=pol-forbidden \
  user_claim=sub \
  cred_spec_name=github-ops \
  description="create the warden-forbidden repo and write & delete its files (skill: mcp)" \
  token_ttl=1h
```

Finally, turn on an audit log so you can watch every decision — which role carried each call,
and why each was allowed or denied:

```bash
warden audit enable file -file-path=/tmp/warden-audit.log
```

### Step 6 — connect Claude

**1. Get a JWT from Hydra.** This is the agent's *own* identity credential — unlike the
GitHub PAT, it's meant for Claude to present, so exporting it is fine:

```bash
export JWT=$(curl -s -X POST http://localhost:4444/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=my-agent&client_secret=agent-secret&scope=api:read api:write" \
  | jq -r '.access_token')
```

**2. Attach Warden's own discovery MCP server.** Warden answers MCP for its *own*
capabilities at `/v1/sys/mcp` — this is how the agent finds out which roles it can assume:

```bash
claude mcp add --transport http warden \
  "http://127.0.0.1:8400/v1/sys/mcp" \
  --header "Authorization: Bearer $JWT"
```

**3. Attach one GitHub gateway per role.** Each role is asserted by the `role/<role>/`
segment of its URL, so each is a separate MCP server. Attach all four — including the
forbidden one, so you can see it refused:

```bash
claude mcp add --transport http gh-repo-lifecycle \
  "http://127.0.0.1:8400/v1/github-mcp/role/repo-lifecycle/gateway/" \
  --header "Authorization: Bearer $JWT"
```

```bash
claude mcp add --transport http gh-issue-triage \
  "http://127.0.0.1:8400/v1/github-mcp/role/issue-triage/gateway/" \
  --header "Authorization: Bearer $JWT"
```

```bash
claude mcp add --transport http gh-repo-reader \
  "http://127.0.0.1:8400/v1/github-mcp/role/repo-reader/gateway/" \
  --header "Authorization: Bearer $JWT"
```

```bash
claude mcp add --transport http gh-forbidden \
  "http://127.0.0.1:8400/v1/github-mcp/role/forbidden-repo-lifecycle/gateway/" \
  --header "Authorization: Bearer $JWT"
```

**4. Confirm what connected:**

```bash
claude mcp list
```

```
warden: ✓ Connected
gh-repo-lifecycle: ✓ Connected
gh-issue-triage: ✓ Connected
gh-repo-reader: ✓ Connected
gh-forbidden: ✗ Failed to connect
```

The first proof, before Claude does anything: **`gh-forbidden` never connects.** Even the MCP
handshake on that role fails, because the agent's identity (`sub=my-agent`) doesn't satisfy
the role's `bound_subject=admin-agent`. The agent can't open a door it was never admitted to —
there is no ambient authority to fall back on.

### Step 7 — discover: what roles can I assume?

Open a `claude` session and ask, in plain language:

> **use the warden mcp server to list the roles I can assume**

Claude calls Warden's `list_roles` tool and reports exactly three: `repo-lifecycle`,
`issue-triage`, and `repo-reader`, each with the description you set. `forbidden-repo-lifecycle`
is **not on the list** — Warden only returns roles the presented identity is admitted to, so
the forbidden role doesn't exist as far as this agent is concerned. The menu the agent plans
against is already scoped to its identity.

### Step 8 — one role per task

Ask for these in turn. Each maps to exactly one role, and Warden records which.

**Create the repo** — this uses `repo-lifecycle`:

> **create a new GitHub repository named `warden-role-assertion`, initialized with a README**

The *initialized with a README* part matters: it tells `create_repository` to auto-init the
repo with a `README.md`, so the read task later has a file to fetch. Without it the repo is
empty and `get_file_contents` returns a `404`. (The `repo-lifecycle` condition only checks
the repo `name`, so the extra argument passes freely.)

**Write, then delete a file** — still `repo-lifecycle`:

> **add a file `NOTES.md` with the text "scratch" to `warden-role-assertion`, then delete it**

That exercises `create_or_update_file` and `delete_file` — the "delete" half of this role's
lifecycle — both scoped by the condition to `warden-role-assertion`.

**Open, then close an issue** — this uses `issue-triage`:

> **open an issue titled "hello" on `warden-role-assertion`, then close it**

Both go through the single `issue_write` tool (`method: "create"`, then `method: "update"`
with `state: "closed"`).

**Read a file** — this uses `repo-reader`:

> **read the README of `warden-role-assertion`**

Each request succeeds under its own role, with its own Warden-minted credential, and nothing
wider. The same agent, holding the same JWT, acted with three different authorities — one per
call — without ever re-authenticating.

### Step 9 — the forbidden repo

Now ask for the one thing no assumable role permits:

> **create a new GitHub repository named `warden-forbidden`**

It fails, and it fails at **two** independent walls — neither of which is the prompt:

1. The role built for this, `forbidden-repo-lifecycle`, is unreachable: its gateway never
   connected (Step 6), because the agent isn't admitted to it.
2. The role the agent *does* hold for creating repos, `repo-lifecycle`, refuses:
   its policy's condition allows `create_repository` **only** when
   `name == "warden-role-assertion"`. A call with `name="warden-forbidden"` is denied at the
   gateway before it reaches GitHub.

Claude has no path to `warden-forbidden` and tells you so. The agent could be confused,
hallucinating, or actively manipulated — the answer is the same, because the boundary lives at
the gateway, not in the model.

### Step 10 — see it in the audit log

Every decision was recorded, stamped with the **role** that carried it. Watch the calls you
just made:

```bash
tail -f /tmp/warden-audit.log | jq 'select(.type=="request") | {
  role:     .auth.role_name,
  allowed:  .auth.policy_results.allowed,
  tool:     .auth.policy_results.mcp_decision.name,
  decision: .auth.policy_results.mcp_decision.decision,
  rule:     .auth.policy_results.mcp_decision.rule_type
}'
```

The tasks each show a different role and `allowed: true`:

```json
{ "role": "repo-lifecycle", "allowed": true, "tool": "create_repository", "decision": "allow", "rule": "allowed_tools" }
{ "role": "repo-lifecycle", "allowed": true, "tool": "delete_file",       "decision": "allow", "rule": "allowed_tools" }
{ "role": "issue-triage",   "allowed": true, "tool": "issue_write",       "decision": "allow", "rule": "allowed_tools" }
{ "role": "repo-reader",    "allowed": true, "tool": "get_file_contents", "decision": "allow", "rule": "allowed_tools" }
```

The forbidden attempt shows the condition denying it under the only role that could reach for
it:

```json
{ "role": "repo-lifecycle", "allowed": false, "tool": "create_repository", "decision": "deny", "rule": "condition" }
```

The trail reads as a per-task ledger: which role created the repo, which filed the issue,
which read the file — each under its own scoped credential, each attributable to exactly one
task. The injected GitHub token never appears in the clear — the audit layer salts it to
`hmac-sha256:…`.

## Troubleshooting

- **`gh-forbidden` shows `✗`** — that's the expected result, not a setup error. The agent's
  `sub` (`my-agent`) doesn't match the role's `bound_subject` (`admin-agent`), so Warden
  refuses to admit it to that role at all.
- **A gateway shows `✗` that should connect** — the JWT expired (1h TTL) or wasn't pasted
  literally. Mint a fresh one (Step 6), then `claude mcp remove <name>` and re-add. Quick
  connectivity check for one role:
  ```bash
  curl -s -o /dev/null -w "%{http_code}\n" -X POST \
    "http://127.0.0.1:8400/v1/github-mcp/role/repo-lifecycle/gateway/" \
    -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" \
    -H "Accept: application/json, text/event-stream" \
    -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
  ```
- **`credential spec "github-ops" not found`** — Step 4's `cred spec create` failed (usually
  an invalid PAT — Warden verifies it on creation). Re-run that command with a valid token.
- **`404` from GitHub on a tool call** — trailing-slash mismatch. The gateway URL must end
  `…/gateway/`; the suffix after `gateway` is forwarded verbatim to GitHub's `…/mcp/`.
- **A task ran under the wrong role, or a role's tools look stale** — Claude fetches an MCP
  server's tool list once when a session starts and caches it for the session. After changing
  a policy or role, exit Claude (`/exit`) and start a fresh session so it re-fetches.

## Cleanup

```bash
claude mcp remove warden
claude mcp remove gh-repo-lifecycle
claude mcp remove gh-issue-triage
claude mcp remove gh-repo-reader
claude mcp remove gh-forbidden
# delete the warden-role-assertion repo you created (on GitHub, or via the gh CLI)
# stop the `warden server --dev` process (Ctrl-C in its terminal)
docker compose down -v
rm -f /tmp/warden-audit.log
unset WARDEN_ADDR WARDEN_TOKEN JWT
```
