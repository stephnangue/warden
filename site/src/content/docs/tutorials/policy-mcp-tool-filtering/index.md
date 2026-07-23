---
title: "Filtering MCP Tools with Warden Policy"
---

**Goal:** put an MCP server behind Warden and let a **policy** decide which of its tools an agent can
see and call — then watch the effect live in Claude. You'll ask Claude the same question twice, *"list
all the available tools on github mcp server"*, and change nothing but the policy: first Claude sees
GitHub's full tool set (including destructive writes), then only read-only tools, with writes refused
at the gateway.

We front **GitHub's hosted MCP server** with Warden. An agent authenticates to Warden with a JWT from
**Ory Hydra**; Warden injects a GitHub token per request (the agent never holds it) and enforces the
tool-filtering policy on every call.

| | Without the filter | With the filter |
|---|---|---|
| Tools Claude sees | every GitHub tool, incl. `delete_*`, `create_*`, `push_*` | only `get_*`, `list_*`, `search_*` |
| A `delete_repository` call | forwarded to GitHub | **refused at Warden**, never reaches GitHub |
| The GitHub token | injected by Warden, never on the agent | injected by Warden, never on the agent |

---

## The problem

Point an MCP client at a hosted server the usual way and it holds a long-lived token and can call
**every** tool that token's scopes allow — including destructive ones. A hallucinated or
prompt-injected `delete_repository` is just another tool call; nothing between the model and GitHub
decides whether it's allowed. You want a single place to say *"this agent may read, not write,"* that
holds regardless of what the model decides to do.

## The solution

Route the MCP server through Warden and attach a policy that decides which tools the agent may use.
Warden strict-parses every JSON-RPC call, **prunes `tools/list`** so the client only sees permitted
tools, and refuses any disallowed `tools/call` before it leaves the gateway. See
[MCP concepts](/concepts/mcp/) for the full grammar and [Policies](/concepts/policies/) for how a
policy attaches to a path.

### Prerequisites

- **Docker** and **Docker Compose**
- **[Claude Code](https://docs.claude.com/en/docs/claude-code)**
- A **GitHub Personal Access Token** (classic, scopes `repo` + `read:org`) — Warden verifies it when
  you create the credential, so it must be valid. You'll paste it into a single Warden command in
  Step 4. **Don't put it in an environment variable** — keeping it out of your shell environment is
  the whole point: no agent you launch from this shell (Claude included) ever sees it.
- The **Warden CLI + server** binary. This installs the latest release for your platform:
  ```bash
  curl -sL https://wardengateway.com/install | bash
  warden --version      # confirm it's on your PATH
  ```

### Get the files

The Docker Compose stack (Ory Hydra) for this tutorial lives in the
[**warden-tuto**](https://github.com/stephnangue/warden-tuto) repository. Clone it and work from the
tutorial folder:

```bash
git clone https://github.com/stephnangue/warden-tuto.git
cd warden-tuto/policy-mcp-tool-filtering
```

### Step 1 — start the identity provider (Hydra)

```bash
docker compose up -d

# wait ~10s for Hydra to initialize and create the OAuth2 client, then confirm:
docker compose logs hydra-client-init | grep my-agent   # ->  [OK] my-agent
```

This runs Ory Hydra with an in-memory database and one pre-created client, `my-agent` /
`agent-secret`, that mints JWTs via the OAuth2 `client_credentials` grant.

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

Enable the [JWT auth method](/auth-methods/jwt/) and point it at Hydra via OIDC discovery. Warden runs
on your host, so it reaches Hydra at `localhost:4444` for both discovery and key fetching:

```bash
warden auth enable jwt
warden write auth/jwt/config \
  oidc_discovery_url=http://localhost:4444 \
  bound_issuer=http://localhost:4444
```

### Step 4 — front GitHub's MCP server

This has four small pieces; run them one at a time.

**1. Mount the generic [`mcp` provider](/provider-backends/mcp/)** at a path that identifies GitHub:

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

**4. Store your PAT as a credential spec.** Warden injects it upstream per request, so the agent never
holds it. Paste your token directly in place of `ghp_your_token_here` — **don't** put it in an
environment variable, or an agent you run from this shell (Claude included) would inherit it:

```bash
warden cred spec create github-ops -source github-src \
  -config auth_method=pat -config token=ghp_your_token_here
```

See [GitHub MCP](/provider-backends/mcp-github/) for App-based and OAuth credential options.

### Step 5 — start with NO filter (the "before")

Three small pieces; run them one at a time.

**1. Write a permissive policy** — every method, every tool:

```bash
warden policy write mcp-tools - <<'EOF'
path "github-mcp/role/+/gateway*" {
  capabilities = ["create", "read", "delete"]
  mcp {
    allowed_methods = ["*"]
    allowed_tools   = ["*"]
  }
}
EOF
```

**2. Create the role** that carries that policy and the GitHub credential:

```bash
warden write auth/jwt/role/mcp-user \
  token_policies=mcp-tools \
  user_claim=sub \
  cred_spec_name=github-ops \
  token_ttl=1h
```

**3. Turn on an audit log** so you can watch the decisions:

```bash
warden audit enable file -file-path=/tmp/warden-audit.log
```

### Step 6 — connect Claude and look at the tools

**1. Get a JWT from Hydra.** This is the agent's *own* identity credential — unlike the GitHub PAT,
it's meant for Claude to present, so exporting it is fine:

```bash
export JWT=$(curl -s -X POST http://localhost:4444/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=my-agent&client_secret=agent-secret&scope=api:read api:write" \
  | jq -r '.access_token')
```

**2. Register the mount with Claude Code.** The shell expands `$JWT` into the header, so the resolved
token is what gets stored:

```bash
claude mcp add --transport http github \
  "http://127.0.0.1:8400/v1/github-mcp/role/mcp-user/gateway/" \
  --header "Authorization: Bearer $JWT"
```

**3. Confirm it connected:**

```bash
claude mcp list      # github: ✓ Connected
```

Now open a `claude` session and ask, in plain language:

> **list all the available tools on github mcp server**

Claude enumerates the **full** GitHub tool set — including write tools like `delete_repository`,
`create_or_update_file`, and `push_files`. Ask a read too ("list 3 of my repositories") and it works.

:::caution
Don't ask Claude to run a destructive write here. The point is only that those tools are exposed and
callable — nothing at the gateway would stop a hallucinated or injected `delete_*`. That's what we fix
next.
:::

### Step 7 — apply the filter

Rewrite the **same** policy as an allow-list, plus an explicit deny-list for good measure. No need to
touch Claude — Warden re-evaluates the policy on the very next request:

```bash
warden policy write mcp-tools - <<'EOF'
path "github-mcp/role/+/gateway*" {
  capabilities = ["create", "read", "delete"]
  mcp {
    allowed_methods = ["tools/list", "tools/call"]
    allowed_tools   = ["get_*", "list_*", "search_*"]
    denied_tools    = ["delete_*", "create_*", "update_*", "push_*", "merge_*"]
  }
}
EOF
```

The block is **deny-by-default**: a tool must match `allowed_tools` and must *not* match `denied_tools`
(a deny always wins). Patterns are case-insensitive and use a trailing `*`. The MCP handshake methods
(`initialize`, `ping`, `notifications/*`) are always exempt.

### Step 8 — ask the same question again (the "after")

Staying in the **same** `claude` session — no reconnect, no restart — ask exactly what you asked
before:

> **list all the available tools on github mcp server**

Claude re-queries the server, and this time it lists **only** the `get_*` / `list_*` / `search_*` read
tools. The write tools are gone — Warden pruned them from `tools/list` under the new policy. The
identical prompt, a different answer, and the only thing that changed was the policy.

A read still works ("list 3 of my repositories"). Now ask for a write:

> **delete my repository `demo`**

Claude will *propose* `delete_repository`, but Warden refuses it at the gateway and returns:

```json
{ "error": "insufficient_permissions", "error_description": "Tool 'delete_repository' not allowed." }
```

Nothing reaches GitHub — the model can propose a write, but the policy won't let it run.

### Step 9 — see it in the audit log

Every decision was recorded. Watch the two calls you just made:

```bash
tail -f /tmp/warden-audit.log | jq 'select(.type=="request") | {
  allowed:  .auth.policy_results.allowed,
  tool:     .auth.policy_results.mcp_decision.name,
  decision: .auth.policy_results.mcp_decision.decision,
  rule:     .auth.policy_results.mcp_decision.rule_type,
  matched:  .auth.policy_results.mcp_decision.matched_rule
}'
```

The blocked write shows:

```json
{ "allowed": false, "tool": "delete_repository", "decision": "deny",
  "rule": "denied_tools", "matched": "delete_*" }
```

The injected GitHub token never appears in the clear — the audit layer salts it to `hmac-sha256:…`.

## Troubleshooting

- **`claude mcp list` shows `github ✗`** — the JWT expired (1h TTL) or wasn't pasted literally. Mint a
  fresh one (Step 6) and `claude mcp remove github` then re-add. Quick connectivity check:
  ```bash
  curl -s -o /dev/null -w "%{http_code}\n" -X POST \
    "http://127.0.0.1:8400/v1/github-mcp/role/mcp-user/gateway/" \
    -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" \
    -H "Accept: application/json, text/event-stream" \
    -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
  ```
- **`credential spec "github-ops" not found`** — Step 4's `cred spec create` failed (usually an
  invalid PAT — Warden verifies it on creation). Re-run that command with a valid token.
- **`404` from GitHub on a tool call** — trailing-slash mismatch. The gateway URL must end
  `…/gateway/`; the suffix after `gateway` is forwarded verbatim to GitHub's `…/mcp/`.
- **The tool list didn't change after Step 7** — you're looking at a cached answer; ask the question
  again so Claude re-queries the server (it re-runs `tools/list`).

## Cleanup

```bash
claude mcp remove github
# stop the `warden server --dev` process (Ctrl-C in its terminal)
docker compose down -v
rm -f /tmp/warden-audit.log
unset WARDEN_ADDR WARDEN_TOKEN JWT
```
