---
title: "GitHub"
description: "Proxy the GitHub API and Git over HTTPS through Warden: mint short-lived App installation tokens, or serve each user their own PAT from a vault."
---

The GitHub provider enables proxied access to both the GitHub REST API and Git smart-HTTP (clone, fetch, push) through Warden. It supports both **GitHub App** and **Personal Access Token (PAT)** authentication, and works with GitHub.com and GitHub Enterprise Server.

## How a request flows

Two decisions shape this mount, and they are independent:

- **Whose identity the call runs as.** A **GitHub App** acts as the app — permissions belong
  to the installation, not to a person. A **PAT** acts as the person who owns it, so branch
  protection, `CODEOWNERS` and audit attribution all land on them.
- **Where the credential lives.** In Warden's encrypted storage, or in a vault Warden reads
  per request.

That gives four combinations. The vertical axis is what GitHub sees; the horizontal is what
Warden stores.

|  | Credential in Warden | Credential chained from a vault |
|---|---|---|
| **App** → short-lived installation token | [stored App credential](#option-b-app-credential-stored-in-warden) | [chained App credential](#option-a-chained-app-credential-recommended) ✅ |
| **PAT** → the person's own token | [inline PAT](#option-d-inline-pat) ⚠️ | [per-user PAT from a vault](#option-c-per-user-pat-from-a-vault) ✅ |

### Chained App credential

The App's private key stays in the vault; Warden reads it per request and exchanges it for
a short-lived installation token.

<p align="center"><img alt="An agent presents the user's ID token and its own identity to Warden, which builds an assertion carrying user and agent claims, has an external KMS sign it, reads the GitHub App credential from an external vault at a path templated by the agent's team and environment, exchanges it at the GitHub token endpoint for an app token, and injects that token to the GitHub API or Git host" src="/images/warden-prov-github-cred-chain.png" width="860"></p>

1. The user authenticates and the agent holds their ID token.
2. The agent calls Warden presenting both credentials and asserting a role.
3. Warden builds the assertion the referenced spec calls for and sends it to an **external
   KMS** unsigned.
4. The KMS returns it signed. No signing key lives in Warden.
5. Warden authenticates to the **external vault** and reads
   `secret/github/{{agent.team}}/{{agent.env}}`.
6. The vault returns the App credential for that team and environment.
7. Warden presents it to the **GitHub token endpoint**…
8. …receiving a short-lived installation token.
9. Warden injects that token and forwards.

The App private key is the crown jewel — anything holding it can mint installation tokens
— so keeping it in the vault is the point of this arrangement.

### Per-user PAT from a vault

Same machinery, different scoping. The path is templated by the **user**, so each person's
own PAT is what reaches GitHub.

<p align="center"><img alt="Warden authenticates to an external vault with a KMS-signed assertion carrying user and agent claims, reads the personal access token from a path templated by the user's subject and the agent's environment, and injects that token to the GitHub API or Git host" src="/images/warden-prov-github-vault-pat.png" width="860"></p>

The read is `secret/github/{{user.sub}}/{{agent.env}}`, so one spec serves everyone and each
caller reaches only their own token — enforced by the path, not by policy alone. There is no
token endpoint step: a PAT is served as it is, not exchanged.

This is the mode to reach for when the agent acts **for a person** and you need GitHub to
see that person.

### The stored variants

<p align="center"><img alt="Warden reads the GitHub App credential from its encrypted storage, exchanges it at the GitHub token endpoint for an app token, and injects that token to the GitHub API or Git host" src="/images/warden-prov-github-static-sts.png" width="860"></p>

With the App credential in Warden's storage, steps 3 to 6 collapse into a storage read; the
exchange and injection are unchanged.

<p align="center"><img alt="Warden reads a personal access token from its encrypted storage and injects it to the GitHub API or Git host for every caller" src="/images/warden-prov-github-inline-pat.png" width="860"></p>

An inline PAT is the shortest path and the weakest: one person's long-lived token, shared by
every caller of the spec, with no expiry and revocation a manual step at GitHub. It still
keeps the token off agent hosts, but prefer any row above it.

:::note[Steps 3–8 run only on a cache miss]
Warden caches the minted credential, so most requests skip straight to the injection. The
entry is keyed by namespace, the agent's token id, the spec name and the user's token id —
so a per-user PAT is never served to another user.
:::

See the [GitHub credential driver](/credential-drivers/github/) for every source and spec
key, and [MCP GitHub](/provider-backends/mcp-github/) for the same credentials behind
GitHub's MCP server.

## Prerequisites

- Docker and Docker Compose installed and running
- One of the following:
  - **GitHub App** with a private key and installation ID, OR
  - **Personal Access Token** (classic or fine-grained)

:::note[New to Warden?]
Follow [Local dev setup](/provider-backends/local-dev-setup/) to start a local dev environment (Ory Hydra + a Warden dev server) before Step 1.
:::

## Step 1: Configure JWT Auth and Create a Role

Enable the JWT auth method and point it at your identity provider's JWKS endpoint, then create a role that binds the credential spec and policy. Enabling the mount and configuring the key source is covered once in [JWT auth](/auth-methods/jwt/#step-1-configure-the-key-source) — for the local dev setup.

> **Set this up before configuring the provider.** The provider resolves
> `auto_auth_path` per request — writing the config only checks that it is
> non-empty, not that the mount exists — so a gateway call fails with `no auth
> mount registered ... for implicit auth` if the referenced auth mount isn't
> there yet.

```bash
warden auth enable jwt
warden write auth/jwt/config jwks_url=http://localhost:4444/.well-known/jwks.json

# Create a role that binds the credential spec and policy
warden write auth/jwt/role/github-user \
    token_policies="github-access" \
    user_claim=sub \
    cred_spec_name=github-ops
```

## Step 2: Mount and Configure the Provider

Enable the GitHub provider at a path of your choice:

```bash
warden provider enable github
```

To mount at a custom path:

```bash
warden provider enable -path=github-prod github
```

Verify the provider is enabled:

```bash
warden provider list
```

Configure the provider with `auto_auth_path`. This allows clients to authenticate with their JWT directly — no explicit Warden login required:

```bash
warden write github/config <<EOF
{
  "github_url": "https://api.github.com",
  "auto_auth_path": "auth/jwt/",
  "timeout": "30s",
  "max_body_size": 10485760
}
EOF
```

See [Provider configuration](/provider-backends/configuration/) for the full list of common config fields (`proxy_domains`, `timeout`, `tls_skip_verify`, `ca_data`, and more).

Verify the configuration:

```bash
warden read github/config
```

## Step 3: Create a Credential Source and Spec

The credential source holds only connection info; the credential itself lives on the spec,
or in a vault the spec chains from.

```bash
warden cred source create github-src -json '{
  "type": "github",
  "config": {
    "github_url": "https://api.github.com"
  }
}'
```

Four options, best first. A–B act as the **App**; C–D act as a **person**.

### Option A: Chained App credential (recommended)

1. Go to **Settings > Developer settings > GitHub Apps** and create a new app.
2. Note the **App ID**, generate an RSA **private key**, install the app and note the
   **Installation ID**.
3. Put the private key in your vault rather than in Warden.

```bash
# Producer: the App key, read from KV v2 through a keyless Vault source
warden cred spec create github-app-key -json '{
  "source": "vault-keyless",
  "min_ttl": 600,
  "max_ttl": 3600,
  "config": {
    "mint_method": "kv2_read",
    "subject_token_source": "warden_identity",
    "assertion_metadata_claims": "team,env",
    "kv2_mount": "secret",
    "secret_path": "github/{{agent.team}}/{{agent.env}}"
  }
}'

# Consumer: the App spec, with the key sourced rather than stored
warden cred spec create github-ops -json '{
  "source": "github-src",
  "min_ttl": 600,
  "max_ttl": 3600,
  "config": {
    "mint_method": "app",
    "app_id": "<your-app-id>",
    "installation_id": "<your-installation-id>",
    "secret_spec": "github-app-key",
    "secret_field": "private_key"
  }
}'
```

`private_key` is absent from the consumer entirely. `secret_field` names which field of the
fetched payload holds the key; store it under `private_key` and you can omit it. A
`secret_field` that resolves to an empty or absent field **fails loudly** rather than
quietly substituting a different key.

`mint_method=app` requires both `app_id` and `installation_id` — omitting either is rejected
naming it.

### Option B: App credential stored in Warden

```bash
cat > github-app-spec.json <<EOF
{
  "source": "github-src",
  "min_ttl": 600,
  "max_ttl": 3600,
  "config": {
    "mint_method": "app",
    "app_id": "<your-app-id>",
    "installation_id": "<your-installation-id>",
    "private_key": $(jq -Rs . < /path/to/private-key.pem)
  }
}
EOF

warden cred spec create github-ops -json @github-app-spec.json
rm github-app-spec.json
```

`jq -Rs .` embeds the PEM as a correctly escaped JSON string so the newlines survive, and
the payload goes through a file so the key never lands in shell history.

### Option C: Per-user PAT from a vault

Each person's own PAT, resolved by the templated path. Use this when GitHub should see the
individual rather than an app.

```bash
warden cred spec create github-user-pat -json '{
  "source": "vault-keyless",
  "min_ttl": 600,
  "max_ttl": 3600,
  "config": {
    "mint_method": "kv2_read",
    "subject_token_source": "warden_identity",
    "assertion_metadata_claims": "env",
    "assertion_user_claims": "sub",
    "kv2_mount": "secret",
    "secret_path": "github/{{user.sub}}/{{agent.env}}"
  }
}'

warden cred spec create github-ops -json '{
  "source": "github-src",
  "min_ttl": 600,
  "max_ttl": 3600,
  "config": {
    "mint_method": "pat",
    "secret_spec": "github-user-pat"
  }
}'
```

The referenced payload supplies the token under `token`. Because `{{user.sub}}` is in the
path, the mount **must** carry a user (`user_auth_path`) — with no user on the request there
is nothing to resolve and the mint fails closed, which is the behaviour you want.

Which claims resolve depends on what the producer projects: `{{agent.sub}}` is free,
`{{agent.<claim>}}` needs `assertion_metadata_claims`, and `{{user.<claim>}}` needs
`assertion_user_claims`. Templates resolve at **mint, not at write**, so a path naming an
unprojected claim is accepted by `spec create` and fails on the first request.

### Option D: Inline PAT

⚠️ One person's long-lived token, shared by every caller. Prefer any option above.

```bash
printf '{"source":"github-src","min_ttl":3600,"max_ttl":86400,"config":{"mint_method":"pat","token":"%s"}}' \
  "$(cat /path/to/pat)" | warden cred spec create github-ops -json -
```

Warden verifies the PAT against GitHub before storing the spec and rejects an invalid one
with a `401`, so this needs a real token.

Verify:

```bash
warden cred spec read github-ops
```

## Step 4: Create a Policy

Create a policy that grants access to the GitHub provider gateway. Note that this policy is intentionally coarse-grained for simplicity, but it can be made much more fine-grained to restrict access to specific paths or capabilities as needed:

```bash
warden policy write github-access - <<EOF
# Role taken from the URL path (/v1/github/role/<role>/gateway/...).
# Used when callers pin the role per request via the URL.
path "github/role/+/gateway*" {
  capabilities = ["create", "read", "update", "delete", "patch"]
}

# Role taken from the Basic Auth username (git clone), the X-Warden-Role
# header, or the mount's default_role. URL has no /role/<role>/ segment.
# Both REST and Git smart-HTTP can land on either rule — the distinction
# is the URL shape, not the protocol.
path "github/gateway/*" {
  capabilities = ["create", "read", "update", "delete", "patch"]
}
EOF
```

For tighter control, add runtime conditions to protect destructive operations on specific paths. For example, restrict repository deletion to trusted networks during business hours while leaving read and create access unconditional:

```bash
warden policy write github-prod-restricted - <<EOF
path "github/role/+/gateway/repos/+/*" {
  capabilities = ["delete"]
  condition = <<-CEL
    cidrContains("10.0.0.0/8", request.client_ip) &&
    now.getHours("UTC") >= 8 && now.getHours("UTC") < 18 &&
    now.getDayOfWeek("UTC") in [1, 2, 3, 4, 5]
  CEL
}

path "github/role/+/gateway*" {
  capabilities = ["create", "read", "update", "patch"]
}
EOF
```

The `condition` is a [CEL](https://cel.dev) expression (see [CEL conditions](/concepts/cel-conditions/)): `cidrContains` restricts by network and `now.getHours`/`now.getDayOfWeek` by time of day and weekday. It must evaluate to `true` for the rule to apply, and fails closed.

Verify:

```bash
warden policy read github-access
```

## Step 5: Get a JWT and Make Requests

Get a JWT from your identity provider — see [Obtaining a JWT](/auth-methods/jwt/#obtaining-a-jwt) (the local dev setup issues one from Hydra). Export it as `$JWT_TOKEN`.

Requests use role-based paths. Warden performs implicit JWT authentication and injects the GitHub token automatically.

The URL pattern is: `/v1/github/role/{role}/gateway/{github-api-path}`

Export GITHUB_ENDPOINT as environment variable:
```bash
export GITHUB_ENDPOINT="${WARDEN_ADDR}/v1/github/role/github-user/gateway"
```

> **Note:** The available GitHub API endpoints depend on your auth method. GitHub App installation tokens and Personal Access Tokens have different scopes — see the examples below.

### GitHub App Examples

GitHub App installation tokens are scoped to the repositories where the app is installed. Use `/installation/` and `/repos/` endpoints.

#### List Repositories the App Is Installed On

```bash
curl "${GITHUB_ENDPOINT}/installation/repositories" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

#### Get a Specific Repository

```bash
curl "${GITHUB_ENDPOINT}/repos/owner/repo-name" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

#### List Pull Requests

```bash
curl "${GITHUB_ENDPOINT}/repos/owner/repo-name/pulls?state=open" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

#### Create an Issue

```bash
curl -X POST "${GITHUB_ENDPOINT}/repos/owner/repo-name/issues" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Bug report",
    "body": "Description of the issue"
  }'
```

#### List Organization Members

```bash
curl "${GITHUB_ENDPOINT}/orgs/my-org/members" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### Personal Access Token (PAT) Examples

PATs are scoped to the authenticated user. Use `/user/` endpoints in addition to `/repos/`.

#### List Repositories for the Authenticated User

```bash
curl "${GITHUB_ENDPOINT}/user/repos" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

#### Get the Authenticated User's Profile

```bash
curl "${GITHUB_ENDPOINT}/user" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

#### Get a Specific Repository

```bash
curl "${GITHUB_ENDPOINT}/repos/owner/repo-name" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

#### List Pull Requests

```bash
curl "${GITHUB_ENDPOINT}/repos/owner/repo-name/pulls?state=open" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

## Git over HTTPS

The same `github/` mount also proxies Git smart-HTTP (`git clone`, `fetch`, `push`) to the Git host (`github.com` by default; the corresponding host for GHE). REST paths continue to proxy to `api.github.com` unchanged — the provider dispatches per-request based on the path shape, so no separate mount or configuration is needed.

### Clone, fetch, push (path-routed form)

The clone URL carries the Warden role as the HTTP Basic Auth **username** and the Warden JWT as the **password**:

```bash
git clone "https://<role>:${JWT_TOKEN}@${WARDEN_HOST}/v1/github/gateway/<owner>/<repo>.git"
cd <repo>
git pull
git push
```

The Git credential helpers on macOS (`osxkeychain`), Linux (`libsecret`), and Windows (`git-credential-manager`) key cached credentials on **URL + username**, so two roles cloning the same repo land in distinct cache entries — switching roles does not invalidate the other's cache. Subsequent `pull`/`push` against the cloned remote re-use the same role automatically.

To avoid putting the JWT in shell history or `.git/config`, use a credential helper that prompts on demand:

```bash
git config --global credential.helper "store"
# or, better, a short-lived in-memory cache:
git config --global credential.helper "cache --timeout=900"
```

### Header-routed form (`X-Warden-Provider`)

Operators who want a clone URL that looks like a real Git URL (no Warden-specific path prefix) can use header routing instead. Set `X-Warden-Provider: github` via Git's `http.extraheader` config:

```bash
git -c http.extraheader="X-Warden-Provider: github" \
    clone "https://<role>:${JWT_TOKEN}@${WARDEN_HOST}/<owner>/<repo>.git"
```

`http.extraheader` persists into `.git/config` at clone time, so follow-up `pull`/`push` against the cloned remote carry the header automatically. Warden synthesises the canonical `github/gateway/<owner>/<repo>.git/...` path before mount lookup, so the dispatch and credential flows behave identically to the path-routed form.

### Cert-auth clients

Cert-auth clients (mTLS or `X-SSL-Client-Cert` from a TLS-terminating proxy) still need to populate Git's password slot because the Git protocol requires it. Any placeholder works — the github provider's token extractor skips the Basic Auth password when `X-SSL-Client-Cert` is set, so the placeholder is never sent to the JWT validator:

```bash
git clone "https://<role>:cert@${WARDEN_HOST}/v1/github/gateway/<owner>/<repo>.git"
```

Mixing a malformed cert with a valid JWT in the Basic Auth password is intentionally not a fallback path: if cert auth fails the request fails with a clear cert-auth error rather than silently switching schemes.

### Role precedence

Role resolution follows core ordering, with the Basic Auth username consulted after path/header roles but before `default_role`:

1. `X-Warden-Role` header
2. Path-embedded role (`/v1/github/role/<role>/gateway/...`)
3. **Basic Auth username** (Git smart-HTTP only)
4. `default_role` from the mount config

So `git clone https://<role>:$JWT@<host>/...` resolves to the username even when a mount-level `default_role` is configured; the default is used only when none of the higher-precedence sources contribute. REST callers are unaffected — the Basic Auth username is consulted only on Git smart-HTTP paths.

### Sizing `git_max_body_size` and `timeout`

- **`git_max_body_size`** caps Git request bodies in bytes. Default 2 GiB; valid range 1 MiB to 10 GiB. The existing `max_body_size` field controls REST POST bodies separately (default 10 MiB, 100 MiB ceiling) — do not raise `max_body_size` to accommodate Git pushes, that is what `git_max_body_size` is for.
- **Do not crank `git_max_body_size` to the 10 GiB ceiling reflexively.** The ceiling is a sanity cap, not a recommended value. Bodies stream through Warden chunk-by-chunk so memory is fine, but each accepted request pins one goroutine, one outbound socket, and 2× the body's bandwidth (ingress + egress to the Git host) for the duration of the transfer. Size to your actual largest expected push, not the maximum theoretical push.
- **Tune `timeout` for the longest expected push.** The mount-level `timeout` controls how long Warden will wait for the full request/response cycle. The default suits REST API calls, not multi-minute Git pushes. Rough heuristic: `timeout ≥ (git_max_body_size / smallest expected client bandwidth) × 2`, rounded up generously. Example: a 2 GiB cap with clients on a 100 Mbps link needs at least 320 s — set `timeout = 600s`. Too-tight `timeout` shows up as half-uploaded pushes that fail at the same byte count, which is a confusing failure mode.

### GHE: deriving the Git host

For GitHub Enterprise Server, the Git host is derived from the REST URL: `https://ghe.example.com/api/v3` → `https://ghe.example.com`. Setting `github_url` alone is sufficient for both REST and Git.

## Cleanup

To stop Warden and the identity provider:

```bash
# Stop Warden (Ctrl+C in the terminal where it's running)

# Stop and remove the identity provider containers
docker compose -f docker-compose.quickstart.yml down -v
```

Since Warden dev mode uses in-memory storage, all configuration is lost when the server stops.

## Authentication Methods

| Method | Auth Header | Token Lifetime | Rotation |
|--------|-------------|----------------|----------|
| **App** | Installation token (auto-minted) | 1 hour (auto-refreshed) | Not needed — tokens are ephemeral |
| **PAT** | Static personal access token | No expiration | Not supported — manage PAT lifecycle on GitHub |

**GitHub App** is recommended because:
- Tokens are short-lived (1 hour) and automatically refreshed
- Fine-grained permissions scoped to the app installation
- No long-lived secrets stored after initial setup
- Audit trail tied to the app identity

## TLS Certificate Authentication

Steps 4-5 above use JWT authentication. Alternatively, you can authenticate with a TLS client certificate. This is useful for workloads that already have X.509 certificates — Kubernetes pods with cert-manager, VMs with machine certificates, or SPIFFE X.509-SVIDs from a service mesh.

:::note[Prerequisite]
Certificate auth requires mTLS on the Warden listener so the client certificate can be presented during the handshake. See [Enabling mTLS on the listener](/auth-methods/cert/#enabling-mtls-on-the-listener).
:::

Steps 1-3 (provider setup) are identical. Replace Steps 4-5 with the following.

### Enable Cert Auth

```bash
warden auth enable cert
```

### Configure Trusted CA

Provide the PEM-encoded CA certificate that signs your client certificates:

```bash
warden write auth/cert/config \
    trusted_ca_pem=@/path/to/ca.pem \
    default_role=github-user
```

### Create a Cert Role

Create a role that binds allowed certificate identities to a credential spec and policy:

```bash
warden write auth/cert/role/github-user \
    allowed_common_names="agent-*" \
    token_policies="github-access" \
    cred_spec_name=github-ops
```

The `allowed_common_names` field supports glob patterns; you can also match on other certificate fields. See [Create a role](/auth-methods/cert/#step-3-create-a-role) for the full set of constraint fields.

### Configure Provider for Cert Auth

Update the provider config to use cert auth:

```bash
warden write github/config <<EOF
{
  "github_url": "https://api.github.com",
  "auto_auth_path": "auth/cert/",
  "timeout": "30s",
  "max_body_size": 10485760
}
EOF
```

### Make Requests with Certificates

```bash
# Role in URL path
curl --cert client.pem --key client-key.pem \
    --cacert warden-ca.pem \
    https://warden.internal/v1/github/role/github-user/gateway/repos/owner/repo-name

# Default role (no role in URL)
curl --cert client.pem --key client-key.pem \
    --cacert warden-ca.pem \
    https://warden.internal/v1/github/gateway/repos/owner/repo-name
```

## GitHub Enterprise Server

To use with GitHub Enterprise Server, set `github_url` to your instance's API endpoint:

```bash
warden write github/config <<EOF
{
  "github_url": "https://github.example.com/api/v3"
}
EOF
```

All gateway requests will be proxied to the configured Enterprise Server instance.

### Custom CA Certificate

If your GitHub Enterprise instance uses a certificate signed by a private CA:

```bash
CA_DATA=$(base64 < /path/to/corporate-ca.pem)

warden write github/config <<EOF
{
  "github_url": "https://github.internal.corp/api/v3",
  "ca_data": "${CA_DATA}",
  "auto_auth_path": "auth/jwt/"
}
EOF
```

### Development / Testing (no TLS)

For local development against a GitHub Enterprise instance without TLS:

```bash
warden write github/config <<EOF
{
  "github_url": "http://localhost:3000/api/v3",
  "tls_skip_verify": true,
  "auto_auth_path": "auth/jwt/"
}
EOF
```
