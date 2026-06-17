# 01 — Certificate → Warden → LLM

**Goal:** get your Anthropic API key off the laptop — and put every model call under central
policy and audit. Claude Code's own inference is routed through Warden, which authenticates the
workstation by its **mTLS client certificate**, checks the request against policy, injects the
real Console key server-side, and records the call. A local **ghostunnel** holds the cert and
originates the mTLS leg.

![Architecture: Using X509 certificate as identity to make inference calls](./image/cert-llm.png)

| Credential | Before this rung | After this rung |
|------------|------------------|-----------------|
| Anthropic API key | in your shell / `~/.claude/settings.json` | **only inside Warden** ✅ |
| Client private key | — | on disk (`./certs/client.key`) — removed in [03](../03-spiffe-llm-mcp/) |

---

## The problem — today, without Warden

To let Claude Code talk to a model, you put a long-lived key where the agent can read it:

```bash
echo "$ANTHROPIC_API_KEY"
# sk-ant-api03-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX...

grep -r ANTHROPIC_API_KEY ~/.claude/ 2>/dev/null
# settings.json:    "ANTHROPIC_API_KEY": "sk-ant-..."
```

That creates three problems:

- **The credential lives on the workstation.** The key is plaintext on disk and in your
  environment, readable by every process that runs as you — a postinstall script, a rogue
  dependency, a `printenv` in a screen-share, a synced dotfile backup. It's long-lived, and if
  it leaks there's no central kill switch: you rotate it everywhere by hand.
- **No central policy.** The raw key is all-or-nothing — nothing caps which model or how many
  tokens a request may use, or restricts it by time or source.
- **No central audit.** Every call hits the provider under the same key, with no per-identity
  record of who issued which request.

We fix all three by moving the key into Warden: it leaves the laptop, each request is
policy-checked, and each is audited under the caller's identity.

---

## The fix — with ghostunnel + Warden

### Prerequisites

```bash
docker compose version     # v2
claude --version
```

Download the **Warden CLI** onto your `PATH` (Apple Silicon shown — swap `darwin_arm64` for
`darwin_amd64` or `linux_*`):

```bash
VER=0.16.0
curl -fsSL "https://github.com/stephnangue/warden/releases/download/v${VER}/warden_${VER}_darwin_arm64.tar.gz" \
  | tar -xz warden && chmod +x warden
export PATH="$PWD:$PATH"
```

Then put your Anthropic Console key in a file (never on the command line). Work from this
directory:

```bash
cd docs/examples/workstation/01-cert-llm
mkdir -p secrets
printf '%s' 'sk-ant-...' > secrets/anthropic-key.txt && chmod 600 secrets/anthropic-key.txt
```

### Step 1 — start the stack

`docker compose up` runs three things: `cert-init` (generates a CA + server + client cert into
`./certs`), **Warden** (dev mode, mTLS listener serving the server cert), and **ghostunnel**
(client tunnel holding the client cert, published on `127.0.0.1:9000`).

```bash
docker compose up -d
docker compose logs cert-init        # "generated CA + server + client certs in ./certs"
```

Point the Warden CLI at the gateway **through ghostunnel** (plain HTTP in, mTLS out — nothing to
verify on the host). The root token is fixed to `root` by the compose `--dev-root-token=root`:

```bash
export WARDEN_ADDR=http://127.0.0.1:9000     # → ghostunnel → Warden's mTLS listener
export WARDEN_TOKEN=root
warden status
```

The client identity is the certificate's Common Name — inspect it:

```bash
openssl x509 -in certs/client.crt -noout -subject
# subject=CN=mcp-agent, O=Warden Demo
```

### Step 2 — enable certificate auth (trust the CA, identity = cert CN)

```bash
warden auth enable cert

warden write auth/cert/config trusted_ca_pem=@certs/ca.crt principal_claim=cn
```

No `default_role` — the role is selected per request by the URL path. One certificate can map
to many roles; here we create one for inference.

### Step 3 — route the Anthropic API through Warden

Mount the `anthropic` provider, store the Console key as a credential, and bind a cert-auth
role to it. The key is validated via `GET /v1/models` at create time, so a bad key fails fast.

```bash
# Provider: where Warden forwards inference calls
warden provider enable -path=anthropic -description="Anthropic API (inference)" anthropic

warden write anthropic/config <<'EOF'
{ "anthropic_url": "https://api.anthropic.com", "auto_auth_path": "auth/cert/", "timeout": "120s", "max_body_size": 10485760 }
EOF

# Credential: the static Console key, injected upstream as the x-api-key header
warden cred source create anthropic-src -type=apikey -rotation-period=0 \
  -config=api_url=https://api.anthropic.com \
  -config=verify_endpoint=/v1/models \
  -config=auth_header_type=custom_header \
  -config=auth_header_name=x-api-key \
  -config=extra_headers=anthropic-version:2023-06-01 \
  -config=display_name=Anthropic

warden cred spec create anthropic-ops -source anthropic-src \
  -config api_key=@secrets/anthropic-key.txt

# Policy + cert-auth role bound to the credential
warden policy write anthropic-access - <<'EOF'
path "anthropic/role/+/gateway*" { capabilities = ["create", "read", "update", "delete", "patch"] }
EOF

warden write auth/cert/role/anthropic-user \
  allowed_common_names="mcp-agent" \
  token_policies="anthropic-access" token_ttl="1h" \
  cred_spec_name="anthropic-ops"
```

### Step 4 — smoke-test through the tunnel

No auth header — the ghostunnel cert is the identity. The path selects the role.

```bash
curl -sS http://127.0.0.1:9000/v1/anthropic/role/anthropic-user/gateway/v1/models | head
```

A JSON list of models (not `401`/`403`) proves the chain: ghostunnel cert → cert auth → role
`anthropic-user` → injected `x-api-key` → Anthropic.

### Step 5 — route Claude Code's inference through Warden

Point Claude Code's model calls at the gateway. `ANTHROPIC_API_KEY` becomes a placeholder
Warden strips and replaces with the real Console key.

```bash
export ANTHROPIC_BASE_URL="http://127.0.0.1:9000/v1/anthropic/role/anthropic-user/gateway"
export ANTHROPIC_API_KEY="placeholder"
claude
```

Every prompt is now routed through Warden: the Console key lives only in Warden, and you can cap
`model`/`max_tokens` centrally in the `anthropic-access` policy. (To persist it, put
`ANTHROPIC_BASE_URL` under `env` in `~/.claude/settings.json`.)

---

## Verify it worked

1. `warden status` (through ghostunnel) connects.
2. Step 4's curl returns a model list, not `401`/`403`.
3. With `ANTHROPIC_BASE_URL` set, a `claude` prompt gets a response; `docker compose logs
   warden` shows a cert login + `anthropic-ops` credential issue, and the upstream call carries
   the injected `x-api-key` (your placeholder is stripped).
4. Your key never left Warden: `printf '%s' "$ANTHROPIC_API_KEY"` on the workstation is just
   `placeholder`, and `grep -r sk-ant ~/.claude/` finds nothing. The real key lives only in
   Warden, every request was policy-checked, and each is in Warden's audit log under the cert
   identity.

## Scorecard

The **Anthropic API key is gone from the laptop** ✅ — it lives only in Warden, with central
revocation and body-level policy. What's still on disk is the mTLS **client private key**
(`./certs/client.key`): cert auth traded an API key for a private key. That's exactly what
[**03 — SPIFFE → LLM + MCP**](../03-spiffe-llm-mcp/) removes. First, [**02**](../02-cert-llm-mcp/) adds an
MCP server so we also stop storing MCP tokens.

## Troubleshooting

- **`x509: certificate is valid for … not 127.0.0.1`** — the server cert lost its IP SAN.
  `docker compose down -v && rm -rf certs && docker compose up -d` to regenerate.
- **`403` + `WWW-Authenticate`** — the cert's CN didn't match the role's `allowed_common_names`,
  or the policy is missing. Re-check Step 2/Step 3.
- **`warden status` connection refused** — the stack isn't up yet (`docker compose ps`), or
  `WARDEN_ADDR` isn't set to `http://127.0.0.1:9000` in this shell.
- **`cred spec create` fails** — the Console key in `secrets/anthropic-key.txt` is wrong; it's
  validated via `GET /v1/models` at create time.
- **Claude shows `403` on a model** — the `anthropic-access` policy (or a tighter
  `allowed_parameters`) is blocking that `model`/param.

## Cleanup

```bash
unset ANTHROPIC_BASE_URL ANTHROPIC_API_KEY WARDEN_ADDR WARDEN_TOKEN
docker compose down -v
rm -rf certs secrets        # certs/ is a bind mount; down -v won't remove it
```

> Dev mode uses in-memory storage — everything resets on `down`. No Warden source is modified;
> this is purely compose + config + run.
