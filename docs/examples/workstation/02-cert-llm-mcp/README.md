# 02 — Certificate → Warden → LLM + MCP

**Goal:** get GitHub's MCP token off the laptop too — and put every tool call under the same
central policy and audit. We add a real MCP server — **GitHub** — behind the *same* client
certificate from [01](../01-cert-llm/): one identity, a new role in the URL path, and Warden
injects the GitHub token per request, checks it against policy, and records it. Claude Code
never holds the token.

![Architecture: Using X509 certificate as identity to make inference calls and MPC tool calls](./image/cert-llm-mcp.png)

| Credential | Before this rung | After this rung |
|------------|------------------|-----------------|
| GitHub MCP token | in `~/.claude.json` | **only inside Warden** ✅ |
| Anthropic API key | (removed in 01) | only inside Warden ✅ |
| Client private key | — | on disk (`./certs/client.key`) — removed in [03](../03-spiffe-llm-mcp/) |

> This rung builds on **01** and reuses the identical cert stack. Finish 01 first (its Steps
> 1–2 bring up the stack and enable cert auth); everything below is the GitHub/token delta.

---

## The problem — today, without Warden

The usual way to give Claude Code a hosted MCP server is to paste a long-lived token into its
config:

```bash
claude mcp add --transport http github https://api.githubcopilot.com/mcp/ \
  --header "Authorization: Bearer ghp_XXXXXXXXXXXXXXXXXXXX"

grep -A3 '"github"' ~/.claude.json
#   "headers": { "Authorization": "Bearer ghp_XXXXXXXXXXXXXXXXXXXX" }
```

That one line creates three problems:

- **The credential lives on the workstation.** A long-lived token sits in plaintext in a
  home-directory file, readable by every process that runs as you — a dependency's postinstall, a
  script, another tool, a synced backup. Lose the laptop and it walks out the door.
- **No central policy.** The token grants whatever its scopes allow; nothing constrains which
  repos or operations the agent may use, and you can't scope it down per task without minting
  another token by hand.
- **No central audit.** Calls go straight to GitHub under that token — there's no single record of
  which identity used it, for what, and when.

We'll move the token into Warden and let the certificate you already have authorize access to it:
the secret leaves the laptop, every call is policy-checked, and every call is audited under the
caller's identity.

---

## The fix — with ghostunnel + Warden

### Prerequisites

You need Docker, Claude Code, and a **GitHub PAT** (classic, `repo` + `read:org`) for Warden to
inject. Download the **Warden CLI** onto your `PATH` (swap `darwin_arm64` for `darwin_amd64` or
`linux_*`):

```bash
VER=0.16.0
curl -fsSL "https://github.com/stephnangue/warden/releases/download/v${VER}/warden_${VER}_darwin_arm64.tar.gz" \
  | tar -xz warden && chmod +x warden
export PATH="$PWD:$PATH"
```

Work from this directory:

```bash
cd docs/examples/workstation/02-cert-llm-mcp
export GH_PAT=ghp_...
```

### Step 1 — bring up the cert stack (same as 01)

```bash
docker compose up -d

# Point the CLI at Warden through ghostunnel's plaintext port
export WARDEN_ADDR=http://127.0.0.1:9000
export WARDEN_TOKEN=root
warden status

# Enable cert auth if you haven't (identity = cert CN). Idempotent to re-run.
warden auth enable cert 2>/dev/null || true
warden write auth/cert/config trusted_ca_pem=@certs/ca.crt principal_claim=cn
```

### Step 2 — route GitHub's MCP server through Warden

Mount the generic `mcp` provider, store the PAT as a `github` credential, and bind a **second**
cert-auth role (same cert, new role) to that credential.

```bash
# Provider — GitHub's hosted MCP endpoint REQUIRES the trailing slash on its URL
warden provider enable -path=github-mcp -description="GitHub Copilot MCP" mcp

warden write github-mcp/config <<'EOF'
{ "mcp_url": "https://api.githubcopilot.com/mcp", "auto_auth_path": "auth/cert/", "timeout": "10m", "max_body_size": 10485760 }
EOF

# Credential — GitHub PAT, injected upstream as a bearer token (stays inside Warden)
warden cred source create github-src -type=github -rotation-period=0 \
  -config=github_url=https://api.github.com

warden cred spec create github-ops -source github-src \
  -config auth_method=pat -config token=$GH_PAT

# Policy + cert-auth role — same client cert (allowed_common_names="mcp-agent")
warden policy write mcp-github-access - <<'EOF'
path "github-mcp/role/+/gateway*" { capabilities = ["create", "read", "delete"] }
EOF

warden write auth/cert/role/github-user \
  allowed_common_names="mcp-agent" \
  token_policies="mcp-github-access" token_ttl="1h" \
  cred_spec_name="github-ops"
```

> **Want the interactive OAuth consent flow instead of a PAT?** Warden supports GitHub-App
> user-to-server OAuth (`auth_method=authorization_code` + `warden cred spec connect`, which runs
> a loopback listener and opens your browser for one-time consent — the host CLI handles this
> fine). It's the better fit for real use (per-user consent, refresh tokens), but needs a GitHub
> App and a callback URL; a PAT keeps this tutorial's setup short and demonstrates the same point
> — the token lives only in Warden.

### Step 3 — smoke-test through the tunnel

No auth header — the cert is the identity. GitHub's MCP endpoint needs the **trailing slash**
on `gateway/`:

```bash
curl -sS http://127.0.0.1:9000/v1/github-mcp/role/github-user/gateway/ \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

A JSON-RPC tool list proves the chain: cert → role `github-user` → injected GitHub token →
upstream.

### Step 4 — register GitHub with Claude Code

```bash
claude mcp add --transport http github "http://127.0.0.1:9000/v1/github-mcp/role/github-user/gateway/"
claude mcp list      # github: ✓ Connected
```

Notice there's **no `--header`** — the token used to live there; now the ghostunnel cert is the
identity and Warden injects the token. In a `claude` session, run `/mcp`, then try a read-only
call (e.g. "list 3 of my repositories").

### Bring the LLM along too

This rung is "LLM **+** MCP". If you want inference routed through Warden as well, add 01's
Anthropic provider/role here (it's the same cert stack) and set `ANTHROPIC_BASE_URL` — see
[01, Steps 3 & 5](../01-cert-llm/#step-3--route-the-anthropic-api-through-warden).

---

## Verify it worked

1. Step 3's curl returns a JSON-RPC tool list, not `401`/`403`.
2. `claude mcp list` shows `github ✓ Connected` with **no token in the config** —
   `grep github ~/.claude.json` shows only the gateway URL.
3. A read-only GitHub tool call from Claude returns data; `docker compose logs warden` shows a
   cert login + `github-ops` credential issue.
4. **Nothing on disk:** `grep -ri 'ghp_\|Bearer ' ~/.claude.json` finds no token — the config
   holds only the gateway URL, and the call was authorized by the cert and recorded in Warden's
   audit log.

## Scorecard

The **GitHub token is gone from the laptop** ✅ — injected per request inside Warden, with
central revocation (delete the role) and one audit trail. Combined with 01, **no API key and no
MCP token** remain. What's *still* on disk is the mTLS **client private key**
(`./certs/client.key`). Removing that is the whole point of [**03 — SPIFFE → LLM + MCP**](../03-spiffe-llm-mcp/).

## Troubleshooting

- **GitHub `HTTP 404`** — trailing-slash mismatch. The gateway URL must end `…/gateway/`. The
  suffix after `gateway` is forwarded verbatim to the upstream.
- **`403` + `WWW-Authenticate`** — the cert CN didn't match `allowed_common_names`, or the
  `mcp-github-access` policy is missing.
- **`401` from GitHub** — the PAT is wrong or lacks scope; re-create `github-ops` with a valid
  `$GH_PAT` (`repo` + `read:org`).
- **`warden` hangs / connection refused** — confirm the stack is up (`docker compose ps`) and
  `WARDEN_ADDR=http://127.0.0.1:9000` is set in this shell.

## Cleanup

```bash
claude mcp remove github
unset GH_PAT WARDEN_ADDR WARDEN_TOKEN
docker compose down -v
rm -rf certs
```

> To add Slack and AWS MCP servers behind the same cert, see the *Add more upstreams* appendix
> referenced from the [series README](../README.md). Each follows the same shape: mount the
> provider → create the credential → add a cert-auth role for the same CN.
