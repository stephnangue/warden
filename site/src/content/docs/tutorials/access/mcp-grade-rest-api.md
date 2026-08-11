---
title: "Using a REST API as Efficiently as an MCP Server with Warden"
sidebar:
  label: "MCP-grade REST API access"
---

**Goal:** give one agent a single identity and let it drive the **plain GitHub REST API** — with
**no GitHub MCP server** fronting it — yet work exactly like an MCP client: it discovers a short
menu of **roles**, pulls a **tool-sized recipe** for the one it needs, and calls only the endpoints
that role is allowed to touch. You'll front `api.github.com` with Warden's `github` provider,
define four roles the agent can assume plus one it cannot, and let Claude run the whole thing with
`gh api`.

The agent still speaks MCP for **discovery** — that's Warden's own always-on interface at
`/v1/sys/mcp`, how it lists roles and fetches skills. What's gone is any GitHub-specific MCP
server: the upstream is the ordinary REST API. An MCP server is pleasant for an agent for two
reasons — it exposes a **small, task-shaped set of tools** (not a 900-endpoint spec), and each tool
is **already scoped** to what you're allowed to do. A raw REST API gives you neither: one broad
token reaches everything, and the agent has to swallow the entire OpenAPI surface to know how to
call anything. Warden puts both properties back, over plain HTTP.

| | Raw REST API | MCP-grade via Warden (this tutorial) |
|---|---|---|
| What the agent must **know** | the entire GitHub OpenAPI spec | a **tool-sized, role-scoped skill** — a handful of endpoints |
| What it may **call** | every endpoint one PAT can reach | only the endpoints the **named role's policy** allows |
| Where the **credential** lives | a PAT sitting on the agent | injected by Warden **per request**, never on the agent |
| Switching task | same token, same blast radius | **assert a different role** — authority rides the call |

---

## The problem

Point an agent at a REST API the usual way and it holds one long-lived token for the whole
session, and it needs the full API spec in context to use it. Both are liabilities. The token is
ambient authority — *"can reach GitHub"* silently becomes *"can delete any repository"*, reusable
by the next task, a hallucinated call, or a prompt-injection payload. The spec is dead weight —
thousands of endpoints the agent will never use, crowding the context window, none of them a hint
about which calls are actually *permitted*. A GitHub MCP server dodges both problems by
construction. A plain REST API doesn't — unless something sits in front of it.

## The solution

Put **roles** between the agent and GitHub. A role is a named, reusable definition — set by an
operator — that Warden resolves **on every request** into three things: *who may assume it* (the
identity binding), *what it may do* (its [policy](/concepts/policies/)), and *what credential
Warden mints* upstream. The agent asks Warden *"what may I do?"*
([`list_roles`](/concepts/mcp/#warden-as-an-mcp-server-discovery-interface)), gets back only the
roles its identity is admitted to, reads the one that fits, and fetches a
**[skill](/concepts/discovery-and-skills/)** — a small markdown recipe scoped to that role's
endpoints. Then it calls the API with `gh api`, asserting the role in the URL. Authority rides on
the call, never on the connection; the recipe is a few endpoints, never the whole spec. See
[Roles](/concepts/roles/) and [Runtime authorization](/use-cases/runtime-authorization/) for the
full picture.

This is the discovery loop from the [MCP role-assertion tutorial](/tutorials/access/mcp-role-assertion/) —
the same `list_roles` → `get_skill` → act sequence — but the upstream is a plain REST API, and
the agent acts with `gh api` instead of MCP tool calls.

### The four roles

All five roles front the same `github` mount; each projects a different slice of the GitHub REST
API. Four bind to the agent's identity; the fifth binds to a different one. The agent **creates
the repo itself** under the first role, then every other role operates on it.

| Role | What its policy grants (REST endpoints) | Agent can assume? |
|------|-----------------------------------------|-------------------|
| `repo-creator` | `POST /user/repos` — create **only** a repo named `warden-gh-api` | ✅ |
| `repo-reader` | `GET` repo metadata, README, contents, languages | ✅ |
| `issue-manager` | list / open / edit / comment on issues | ✅ |
| `label-curator` | list / create / rename / delete labels | ✅ |
| `collaborator-admin` | add repo collaborators — **bound to another identity** | ❌ |

`repo-creator` shows the two ways a policy reaches fine-grained scope. The three repo-scoped roles
pin the repo in the **URL path** (`…/repos/+/warden-gh-api/…`). But `POST /user/repos` has no repo
in its path — the repo doesn't exist yet — so `repo-creator` pins the name in the **request body**
with a CEL condition: `request.data.name == "warden-gh-api"`. The agent can create that one repo
and no other.

The fifth role is real and fully functional — it just belongs to a **different principal** (think:
a human admin). The agent holds the wrong identity for it, so Warden never admits it: the role is
invisible in `list_roles` and refused at the gateway. That is the whole lesson — the wall is the
identity binding, checked on every request.

### Prerequisites

- **Docker** and **Docker Compose**
- **[Claude Code](https://docs.claude.com/en/docs/claude-code)**
- **[GitHub CLI](https://cli.github.com/)** (`gh`) — the agent drives the API with `gh api`.
- A **GitHub Personal Access Token** (classic, scope `repo`) — Warden verifies it when you create
  the credential, so it must be valid. You'll paste it into a single Warden command in Step 4.
  **Don't put it in an environment variable** — keeping it out of your shell is the whole point: no
  agent you launch from this shell (Claude included) ever sees it.
- The **Warden CLI + server** binary. This installs the latest release for your platform:
  ```bash
  curl -sL https://wardengateway.com/install | bash
  warden --version      # confirm it's on your PATH
  ```

### Get the files

The Docker Compose stack (Ory Hydra) for this tutorial lives in the
[**warden-tuto**](https://github.com/stephnangue/warden-tuto) repository — one pre-created agent
client that mints JWTs, the same identity setup as the
[MCP role-assertion tutorial](/tutorials/access/mcp-role-assertion/). Clone it and work from this
tutorial's folder:

```bash
git clone https://github.com/stephnangue/warden-tuto.git
cd warden-tuto/access-mcp-grade-rest-api
```

Everything else below runs from the Warden CLI, so no other files are needed.

### Step 1 — start the identity provider (Hydra)

```bash
docker compose up -d

# wait ~10s for Hydra to initialize and create the OAuth2 client, then confirm:
docker compose logs hydra-client-init | grep my-agent   # ->  [OK] my-agent
```

This runs Ory Hydra with an in-memory database and one pre-created client, `my-agent` /
`agent-secret`, that mints JWTs via the OAuth2 `client_credentials` grant. For that grant the JWT's
`sub` claim is the client id — `my-agent` — which is exactly the identity our roles bind against.

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

Enable the [JWT auth method](/auth-methods/jwt/) and point it at Hydra via OIDC discovery. Warden
runs on your host, so it reaches Hydra at `localhost:4444`:

```bash
warden auth enable jwt
warden write auth/jwt/config \
  oidc_discovery_url=http://localhost:4444 \
  bound_issuer=http://localhost:4444
```

### Step 4 — front the GitHub REST API

Four small pieces; run them one at a time.

**1. Mount the [`github` provider](/provider-backends/github/)** at a path that identifies it:

```bash
warden provider enable -path=github -description="GitHub REST API" github
```

**2. Point the mount at GitHub** and the JWT auth method:

```bash
warden write github/config \
  github_url=https://api.github.com \
  auto_auth_path=auth/jwt/
```

**3. Create the credential source** — the connection info for GitHub:

```bash
warden cred source create github-src -type=github -rotation-period=0 \
  -config=github_url=https://api.github.com
```

**4. Store your PAT as a credential spec.** Warden injects it upstream per request, so the agent
never holds it. Paste your token directly in place of `ghp_your_token_here` — **don't** put it in
an environment variable, or an agent you run from this shell (Claude included) would inherit it:

```bash
warden cred spec create github-ops -source github-src \
  -config mint_method=pat -config token=ghp_your_token_here
```

### Step 5 — define the roles

Each role is a **policy** (which endpoints it may call, by HTTP method) plus a **role binding**
(who may assume it, which credential it mints). For a REST provider a policy is pure `path` +
`capabilities`: a capability *is* the HTTP method — `GET` needs `read`, `POST` needs `create`,
`PATCH` needs `patch`, `PUT` needs `update`, `DELETE` needs `delete`. The path Warden authorizes
is the internal gateway path, `github/role/<role>/gateway/<api-path>`, so a policy scopes GitHub
endpoints by writing patterns against it. Everything is default-deny; only what a rule grants gets
through. Run the blocks below one at a time.

**1. `repo-creator` — create exactly one repo, name pinned in the body.** `POST /user/repos`
carries no repo in its path, so the name is pinned with a CEL `condition` on the request body
(`request.data` is the body for a REST provider). A call for any other name is denied:

```bash
warden policy write pol-repo-creator - <<'EOF'
path "github/role/repo-creator/gateway/user/repos" {
  capabilities = ["create"]
  condition    = "request.data.name == 'warden-gh-api'"
}
EOF

warden write auth/jwt/role/repo-creator \
  bound_subject=my-agent \
  token_policies=pol-repo-creator \
  user_claim=sub \
  cred_spec_name=github-ops \
  description="create the warden-gh-api repository (skill: gh-repo-creator, url: /v1/github/role/repo-creator/gateway/)" \
  token_ttl=1h
```

**2. `repo-reader` — read one repo.** The owner segment is a `+` wildcard so the command copies
cleanly; the repo name is pinned literally:

```bash
warden policy write pol-repo-reader - <<'EOF'
path "github/role/repo-reader/gateway/repos/+/warden-gh-api"            { capabilities = ["read"] }
path "github/role/repo-reader/gateway/repos/+/warden-gh-api/readme"     { capabilities = ["read"] }
path "github/role/repo-reader/gateway/repos/+/warden-gh-api/contents/*" { capabilities = ["read"] }
path "github/role/repo-reader/gateway/repos/+/warden-gh-api/languages"  { capabilities = ["read"] }
EOF

warden write auth/jwt/role/repo-reader \
  bound_subject=my-agent \
  token_policies=pol-repo-reader \
  user_claim=sub \
  cred_spec_name=github-ops \
  description="read the warden-gh-api repo, its README, files and languages (skill: gh-repo-reader, url: /v1/github/role/repo-reader/gateway/)" \
  token_ttl=1h
```

**3. `issue-manager` — list, open, edit, and comment on issues.** `GET` needs `read`, `POST`
needs `create`, and closing an issue is a `PATCH`, so it needs `patch`:

```bash
warden policy write pol-issue-manager - <<'EOF'
path "github/role/issue-manager/gateway/repos/+/warden-gh-api/issues"            { capabilities = ["read", "create"] }
path "github/role/issue-manager/gateway/repos/+/warden-gh-api/issues/+"          { capabilities = ["read", "patch"] }
path "github/role/issue-manager/gateway/repos/+/warden-gh-api/issues/+/comments" { capabilities = ["read", "create"] }
EOF

warden write auth/jwt/role/issue-manager \
  bound_subject=my-agent \
  token_policies=pol-issue-manager \
  user_claim=sub \
  cred_spec_name=github-ops \
  description="list, open, edit and comment on issues in warden-gh-api (skill: gh-issue-manager, url: /v1/github/role/issue-manager/gateway/)" \
  token_ttl=1h
```

**4. `label-curator` — manage labels.** Renaming is a `PATCH`, deleting a `DELETE`:

```bash
warden policy write pol-label-curator - <<'EOF'
path "github/role/label-curator/gateway/repos/+/warden-gh-api/labels"   { capabilities = ["read", "create"] }
path "github/role/label-curator/gateway/repos/+/warden-gh-api/labels/+" { capabilities = ["read", "patch", "delete"] }
EOF

warden write auth/jwt/role/label-curator \
  bound_subject=my-agent \
  token_policies=pol-label-curator \
  user_claim=sub \
  cred_spec_name=github-ops \
  description="list, create, rename and delete labels on warden-gh-api (skill: gh-label-curator, url: /v1/github/role/label-curator/gateway/)" \
  token_ttl=1h
```

**5. `collaborator-admin` — add collaborators, bound to a different identity.** The policy is
fully functional; the only difference that matters is `bound_subject=admin-agent`, an identity the
agent does **not** hold. It carries no skill, because the agent will never see it:

```bash
warden policy write pol-collaborator-admin - <<'EOF'
path "github/role/collaborator-admin/gateway/repos/+/warden-gh-api/collaborators"   { capabilities = ["read"] }
path "github/role/collaborator-admin/gateway/repos/+/warden-gh-api/collaborators/+" { capabilities = ["read", "update"] }
EOF

warden write auth/jwt/role/collaborator-admin \
  bound_subject=admin-agent \
  token_policies=pol-collaborator-admin \
  user_claim=sub \
  cred_spec_name=github-ops \
  description="add collaborators to warden-gh-api" \
  token_ttl=1h
```

Finally, turn on an audit log so you can watch every decision — which role carried each call, and
why each was allowed or denied:

```bash
warden audit enable file -file-path=/tmp/warden-audit.log
```

### Step 6 — author the skills: a base recipe plus per-role endpoints

This is the "as efficient as MCP" half — and it factors cleanly. The `gh api` mechanics are the
same for every role, so put them in **one base skill** that each role skill **`requires`**. A role
skill then shrinks to a few lines: the endpoints it exposes. It does **not** hardcode a gateway URL —
the agent already has that from the role's `list_roles` description (the `url:` field), so the skill
lists only REST path suffixes. When the agent fetches a role skill it sees `requires: [gh-via-warden]`
and pulls the base once for the mechanics — the way an MCP client shares one transport across many
tools. Skills are authored from a file, so each block writes the body then registers it.

**1. The base skill — `gh-via-warden`** (the shared `gh api` recipe, no endpoints of its own):

````bash
cat > gh-via-warden.md <<'EOF'
# Calling GitHub through a Warden gateway with gh api

`gh`'s high-level subcommands (`gh repo`, `gh issue`, `gh pr`) build their own request paths and
can't be pointed at a Warden gateway. `gh api` can: it takes a full URL and calls any REST
endpoint. GraphQL (`gh api graphql`) is not proxied.

## Recipe

- **Base URL comes from the role's description.** `list_roles` gives each role a `url:` field (its
  gateway, e.g. `/v1/github/role/<role>/gateway/`). Don't guess it — read it there. Set it once and
  reuse it: `GW="$WARDEN_ADDR<url-from-description>"` (drop the trailing slash). Every call is then
  `gh api "$GW/<rest-path>"`, where `<rest-path>` is one of the paths the role skill lists.
- **Auth**: pass `-H "Authorization: Bearer <jwt>"`. Warden reads the bearer value as your
  identity and injects the real GitHub token upstream — you never hold it.
- **Placeholder token**: `gh` refuses to run with no token configured. Set any value:
  `export GH_TOKEN=unused`. It is never sent; the bearer header is the real credential.
- **Reads**: `gh api "$GW/<rest-path>" -H "Authorization: Bearer $JWT"`. `--paginate` and `--jq`
  work through the proxy.
- **Writes**: add `--method POST` / `PATCH` / `PUT` / `DELETE`; fields via `-f key=val` (string)
  or `-F key=val` (typed), or a whole JSON body with `--input file.json`.
- **Switch role**: reset `$GW` to the other role's `url:` (or add `-H "X-Warden-Role: <role>"`).

The role skill that required this one lists the exact `<rest-path>`s you may call; anything outside
that list is denied at the gateway.
EOF

warden skill create -name=gh-via-warden -category=shared \
  -description="How to call any Warden-fronted GitHub REST endpoint with gh api" \
  -body-file=gh-via-warden.md
````

**2. The role skills.** Here they are deliberately **tiny** — a title line and the list of
rest-paths the role may call, nothing else. That list is the one thing the skill uniquely adds: the
model already knows GitHub's REST API and (from `gh-via-warden`) how to call it, so the skill's job
is to state the *authorized surface*, not re-teach the API. `$GW` is the role's gateway, set from its
`list_roles` description per the base skill. Author them one at a time.

`gh-repo-creator`:

```bash
cat > gh-repo-creator.md <<'EOF'
# repo-creator — see gh-via-warden for gh api mechanics; $GW from this role's description
- POST  user/repos   (body name must be "warden-gh-api", policy-enforced; -F auto_init=true seeds a README)
EOF

warden skill create -name=gh-repo-creator -category=custom -requires=gh-via-warden \
  -description="create the warden-gh-api repository via gh api" -body-file=gh-repo-creator.md
```

`gh-repo-reader`:

```bash
cat > gh-repo-reader.md <<'EOF'
# repo-reader (read-only) — see gh-via-warden for mechanics; $GW from this role's description
# {owner} = the full_name returned when the repo was created
- GET  repos/{owner}/warden-gh-api
- GET  repos/{owner}/warden-gh-api/readme
- GET  repos/{owner}/warden-gh-api/contents/{path}
- GET  repos/{owner}/warden-gh-api/languages
EOF

warden skill create -name=gh-repo-reader -category=custom -requires=gh-via-warden \
  -description="read the warden-gh-api repo via gh api" -body-file=gh-repo-reader.md
```

`gh-issue-manager`:

```bash
cat > gh-issue-manager.md <<'EOF'
# issue-manager — see gh-via-warden for mechanics; $GW from this role's description
- GET, POST   repos/{owner}/warden-gh-api/issues            (open: -f title= -f body=)
- GET, PATCH  repos/{owner}/warden-gh-api/issues/{n}        (close: -f state=closed)
- POST        repos/{owner}/warden-gh-api/issues/{n}/comments
EOF

warden skill create -name=gh-issue-manager -category=custom -requires=gh-via-warden \
  -description="triage issues on warden-gh-api via gh api" -body-file=gh-issue-manager.md
```

`gh-label-curator`:

```bash
cat > gh-label-curator.md <<'EOF'
# label-curator — see gh-via-warden for mechanics; $GW from this role's description
- GET, POST      repos/{owner}/warden-gh-api/labels         (create: -f name= -f color=<6-hex>)
- PATCH, DELETE  repos/{owner}/warden-gh-api/labels/{name}  (rename: -f new_name=)
EOF

warden skill create -name=gh-label-curator -category=custom -requires=gh-via-warden \
  -description="manage labels on warden-gh-api via gh api" -body-file=gh-label-curator.md
```

:::tip
Notice how little each role skill holds: not the API, not the call syntax — just the **paths this
role may call**. The model already knows GitHub's REST API; the skill exists to hand it the
*authorized surface*, and the base recipe (shared once) supplies the `gh api` mechanics. GitHub's
OpenAPI description is megabytes; this is a few lines per role — a lean, task-shaped menu like a
GitHub MCP server's tool list, over the ordinary REST API.
:::

### Step 7 — connect Claude

Unlike the [MCP role-assertion tutorial](/tutorials/access/mcp-role-assertion/), there are **no
per-role gateways to attach as MCP servers.** The agent needs only Warden's discovery server —
still MCP, but Warden's own — plus a shell that can run `gh api`.

**1. Get a JWT from Hydra.** This is the agent's *own* identity credential — meant for Claude to
present, so exporting it is fine:

```bash
export JWT=$(curl -s -X POST http://localhost:4444/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=my-agent&client_secret=agent-secret&scope=api:read api:write" \
  | jq -r '.access_token')
```

**2. Give the shell the two values `gh api` needs** — the gateway address and a placeholder
GitHub token (the real credential is the bearer header Warden reads; the placeholder just satisfies
`gh`):

```bash
export WARDEN_ADDR=http://127.0.0.1:8400
export GH_TOKEN="unused-real-credential-is-the-authorization-header"
```

**3. Attach Warden's discovery MCP server** — this is how the agent finds out which roles it can
assume and fetches their skills:

```bash
claude mcp add --transport http warden \
  "http://127.0.0.1:8400/v1/sys/mcp" \
  --header "Authorization: Bearer $JWT"
```

**4. Confirm it connected:**

```bash
claude mcp list        # warden: ✓ Connected
```

### Step 8 — discover: what roles can I assume?

Open a `claude` session and ask, in plain language:

> **use the warden mcp server to list the roles I can assume**

Claude calls Warden's `list_roles` tool and reports exactly four: `repo-creator`, `repo-reader`,
`issue-manager`, and `label-curator` — each with the
description you set. `collaborator-admin` is **not on the list**: Warden only returns roles the
presented identity is admitted to. The menu the agent plans against is already scoped to its
identity — just like an MCP `tools/list`.

### Step 9 — one role per task

Ask for these in turn. For each, Claude reads the matching role's description — taking the gateway
URL from its `url:` field — calls `get_skill` for the role's recipe (and the `gh-via-warden` base
skill it requires), builds the `gh api` command against that gateway, and runs it. Each task maps to
exactly one role.

**Create the repo** — `repo-creator`:

> **create the `warden-gh-api` repository, initialized with a README**

Claude runs `gh api --method POST …/user/repos -f name=warden-gh-api -F auto_init=true`. The
`auto_init` gives the repo an initial commit and a `README.md`, so the read task below has a file to
fetch. Note the response's `full_name` — that's the `OWNER/warden-gh-api` the next commands need.

**Read the repo** — `repo-reader`:

> **read the README and language breakdown of `warden-gh-api`**

**Triage an issue** — `issue-manager`:

> **open an issue titled "flaky test" on `warden-gh-api`, comment on it, then close it**

**Curate a label** — `label-curator`:

> **create a `needs-triage` label on `warden-gh-api`, then rename it to `triage`**

Each request succeeds under its own role, with its own Warden-minted credential, and nothing wider.
The same agent, holding the same JWT, acted with four different authorities — one per call — and for
each it loaded only a handful of endpoints, never GitHub's full spec.

### Step 10 — the two walls

Now try the things no assumable role permits. They fail at two independent walls — neither of them
the prompt.

**A forbidden endpoint inside a role the agent *does* hold.** Ask Claude to reuse the read-only role
for a write:

> **using the repo-reader role, open an issue titled "sneaky" on `warden-gh-api`**

Claude points `gh api --method POST` at the `repo-reader` gateway. Warden refuses: `pol-repo-reader`
grants no `create`, and the issues path isn't in its allow-list at all — **default-deny at the
gateway**, before the call reaches GitHub. The same task succeeded a moment ago under
`issue-manager`; the only thing that changed is which role carried it.

**A role the agent isn't admitted to.** Ask for the collaborator change:

> **add `octocat` as a collaborator on `warden-gh-api`**

There is no path to it. `collaborator-admin` never appeared in `list_roles`, and if Claude aims a
request at that role's gateway anyway, Warden rejects it: the agent's identity (`sub=my-agent`)
doesn't satisfy the role's `bound_subject=admin-agent`, so no token is ever minted for it. Claude
has no assumable role that grants collaborator writes and tells you so. The agent could be confused,
hallucinating, or actively manipulated — the answer is the same, because the boundary lives at the
gateway, not in the model.

### Step 11 — see it in the audit log

Every decision was recorded, stamped with the **role** that carried it. Watch the calls you just
made:

```bash
tail -f /tmp/warden-audit.log | jq 'select(.type=="request") | {
  role:      .auth.role_name,
  method:    .request.method,
  path:      .request.path,
  allowed:   .auth.policy_results.allowed,
  condition: .auth.policy_results.condition.decision
}'
```

The tasks each show a different role and `allowed: true`; `repo-creator` also shows its body
condition passing:

```json
{ "role": "repo-creator",     "method": "POST",  "path": "github/role/repo-creator/gateway/user/repos", "allowed": true, "condition": "allow" }
{ "role": "repo-reader",      "method": "GET",   "path": "github/role/repo-reader/gateway/repos/OWNER/warden-gh-api/readme", "allowed": true }
{ "role": "issue-manager",    "method": "POST",  "path": "github/role/issue-manager/gateway/repos/OWNER/warden-gh-api/issues", "allowed": true }
{ "role": "label-curator",    "method": "PATCH", "path": "github/role/label-curator/gateway/repos/OWNER/warden-gh-api/labels/needs-triage", "allowed": true }
```

The forbidden write under `repo-reader` shows the gateway denying it:

```json
{ "role": "repo-reader", "method": "POST", "path": "github/role/repo-reader/gateway/repos/OWNER/warden-gh-api/issues", "allowed": false }
```

The trail reads as a per-task ledger: which role created the repo, which filed the issue, which
curated the label — each under its own scoped credential, each attributable to exactly one task. The
injected GitHub token never appears in the clear — the audit layer salts it to `hmac-sha256:…`.

## Troubleshooting

- **`gh` prints "gh: To use GitHub CLI... authenticate"** — set the placeholder token:
  `export GH_TOKEN=unused`. Its value is never used; the real credential is the `Authorization:
  Bearer $JWT` header Warden reads.
- **`403` / "permission denied" on a call that should work** — the JWT expired (1h TTL) or the URL
  named the wrong role. Mint a fresh JWT (Step 7) and re-check the `role/<role>/` segment. Quick
  connectivity check for one role:
  ```bash
  gh api "$WARDEN_ADDR/v1/github/role/repo-reader/gateway/repos/OWNER/warden-gh-api" \
    -H "Authorization: Bearer $JWT" --jq '.full_name'
  ```
- **`404` from GitHub** — usually the `OWNER` segment. Use the `full_name` returned when the repo
  was created (your GitHub login), not a placeholder.
- **`credential spec "github-ops" not found`** — Step 4's `cred spec create` failed (usually an
  invalid PAT — Warden verifies it on creation). Re-run that command with a valid token.
- **A task ran under the wrong role, or a skill looks stale** — Claude caches an MCP server's tool
  list (including `list_roles`/`get_skill`) once per session. After changing a role, policy, or
  skill, exit Claude (`/exit`) and start a fresh session so it re-fetches.
- **The forbidden collaborator call "just works"** — check `collaborator-admin` was written with
  `bound_subject=admin-agent`, not `my-agent`. That one field is the wall.

## Cleanup

```bash
claude mcp remove warden
warden skill delete gh-via-warden
warden skill delete gh-repo-creator
warden skill delete gh-repo-reader
warden skill delete gh-issue-manager
warden skill delete gh-label-curator
# delete the warden-gh-api repo the agent created (on GitHub, or: gh repo delete OWNER/warden-gh-api)
# stop the `warden server --dev` process (Ctrl-C in its terminal)
docker compose down -v
rm -f /tmp/warden-audit.log gh-*.md
unset WARDEN_ADDR WARDEN_TOKEN JWT GH_TOKEN
```
