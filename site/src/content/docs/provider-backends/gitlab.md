---
title: "GitLab"
---

The GitLab provider enables proxied access to the GitLab REST API through Warden. It supports **Personal Access Token (PAT)** and **OAuth2** authentication, can mint scoped project and group access tokens on demand, and works with both GitLab.com and self-hosted instances.

## Prerequisites

- Docker and Docker Compose installed and running
- One of the following:
  - **OAuth2 application** credentials (`application_id` and `application_secret`), OR
  - **Personal Access Token** with `api` scope (and `admin` scope if rotation is needed)

:::note[New to Warden?]
Follow [Local dev setup](/provider-backends/local-dev-setup/) to start a local dev environment (Ory Hydra + a Warden dev server) before Step 1.
:::

## Step 1: Configure JWT Auth and Create a Role

Enable the JWT auth method and point it at your identity provider's JWKS endpoint, then create a role that binds the credential spec and policy. Enabling the mount and configuring the key source is covered once in [JWT auth](/auth-methods/jwt/#step-1-configure-the-key-source) — for the local dev setup.

> **This step must come before configuring the provider.** Warden validates at configuration time that the auth backend referenced by `auto_auth_path` is already mounted.

```bash
warden auth enable jwt
warden write auth/jwt/config jwks_url=http://localhost:4444/.well-known/jwks.json

# Create a role that binds the credential spec and policy
warden write auth/jwt/role/gitlab-user \
    token_policies="gitlab-access" \
    user_claim=sub \
    cred_spec_name=gitlab-project-token
```

## Step 2: Mount and Configure the Provider

Enable the GitLab provider at a path of your choice:

```bash
warden provider enable gitlab
```

To mount at a custom path:

```bash
warden provider enable -path=gitlab-prod gitlab
```

Verify the provider is enabled:

```bash
warden provider list
```

Configure the provider with `auto_auth_path`. This allows clients to authenticate with their JWT directly — no explicit Warden login required:

```bash
warden write gitlab/config <<EOF
{
  "gitlab_address": "https://gitlab.com",
  "auto_auth_path": "auth/jwt/",
  "timeout": "30s",
  "max_body_size": 10485760
}
EOF
```

See [Provider configuration](/provider-backends/configuration/) for the full list of common config fields (`proxy_domains`, `timeout`, `tls_skip_verify`, `ca_data`, and more).

Verify the configuration:

```bash
warden read gitlab/config
```

## Step 3: Create a Credential Source and Spec

The credential source holds the connection info and auth credentials for GitLab.

### Option A: OAuth2 Application (Recommended)

1. In GitLab, go to **Admin Area > Applications** (or **User Settings > Applications**).
2. Create an OAuth2 application and note the `Application ID` and `Secret`.

```bash
warden cred source create gitlab-oauth \
  -type=gitlab \
  -rotation-period=720h \
  -config=gitlab_address=https://gitlab.com \
  -config=auth_method=oauth2 \
  -config=application_id=<your-application-id> \
  -config=application_secret=<your-application-secret>
```

### Option B: Personal Access Token

1. In GitLab, go to **User Settings > Access Tokens**.
2. Create a token with the required scopes (`api` at minimum, `admin` for rotation support).

```bash
warden cred source create gitlab-pat \
  -type=gitlab \
  -rotation-period=720h \
  -config=gitlab_address=https://gitlab.com \
  -config=auth_method=pat \
  -config=personal_access_token=glpat-xxxxxxxxxxxxxxxxxxxx
```

Verify the source was created:

```bash
warden cred source read gitlab-pat
```

Create a credential spec that references the credential source. The spec defines what type of token to mint (project access token, group access token, etc.).

### Project Access Token

```bash
warden cred spec create gitlab-project-token \
  -source=gitlab-pat \
  -min-ttl=1h \
  -max-ttl=24h \
  -config=mint_method=project_access_token \
  -config=project_id=123 \
  -config=token_name=warden-minted \
  -config=scopes=api,read_api \
  -config=access_level=30
```

### Group Access Token

```bash
warden cred spec create gitlab-group-token \
  -source=gitlab-pat \
  -min-ttl=1h \
  -max-ttl=24h \
  -config=mint_method=group_access_token \
  -config=group_id=79644309 \
  -config=token_name=warden-minted \
  -config=scopes=api \
  -config=access_level=30
```

Verify:

```bash
warden cred spec read gitlab-project-token
```

## Step 4: Create a Policy

Create a policy that grants access to the GitLab provider gateway. Note that this policy is intentionally coarse-grained for simplicity, but it can be made much more fine-grained to restrict access to specific paths or capabilities as needed:

```bash
warden policy write gitlab-access - <<EOF
path "gitlab/role/+/gateway*" {
  capabilities = ["create", "read", "update", "delete", "patch"]
}
EOF
```

For tighter control, add runtime conditions to protect destructive operations on specific paths. For example, restrict project deletion to trusted networks during business hours while leaving read and create access unconditional:

```bash
warden policy write gitlab-prod-restricted - <<EOF
path "gitlab/role/+/gateway/api/v4/projects/*" {
  capabilities = ["delete"]
  condition = <<-CEL
    cidrContains("10.0.0.0/8", request.client_ip) &&
    now.getHours("UTC") >= 8 && now.getHours("UTC") < 18 &&
    now.getDayOfWeek("UTC") in [1, 2, 3, 4, 5]
  CEL
}

path "gitlab/role/+/gateway*" {
  capabilities = ["create", "read", "update", "patch"]
}
EOF
```

The `condition` is a [CEL](https://cel.dev) expression (see [CEL conditions](/concepts/cel-conditions/)): `cidrContains` restricts by network and `now.getHours`/`now.getDayOfWeek` by time of day and weekday. It must evaluate to `true` for the rule to apply, and fails closed.

Verify:

```bash
warden policy read gitlab-access
```

## Step 5: Get a JWT and Make Requests

Get a JWT from your identity provider — see [Obtaining a JWT](/auth-methods/jwt/#obtaining-a-jwt) (the local dev setup issues one from Hydra). Export it as `$JWT_TOKEN`.

Requests use role-based paths. Warden performs implicit JWT authentication and injects the GitLab token automatically. Note that GitLab API paths start with `/api/v4/`.

The URL pattern is: `/v1/gitlab/role/{role}/gateway/{gitlab-api-path}`

Export GITLAB_ENDPOINT as environment variable:
```bash
export GITLAB_ENDPOINT="${WARDEN_ADDR}/v1/gitlab/role/gitlab-user/gateway"
```

### List Projects

```bash
curl "${GITLAB_ENDPOINT}/api/v4/projects" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### Get a Specific Project

```bash
curl "${GITLAB_ENDPOINT}/api/v4/projects/123" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### List Merge Requests

```bash
curl "${GITLAB_ENDPOINT}/api/v4/projects/123/merge_requests?state=opened" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### List Pipelines

```bash
curl "${GITLAB_ENDPOINT}/api/v4/projects/123/pipelines" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### List Group Projects

```bash
curl "${GITLAB_ENDPOINT}/api/v4/groups/my-group/projects" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

### Create an Issue

```bash
curl -X POST "${GITLAB_ENDPOINT}/api/v4/projects/123/issues" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Bug report",
    "description": "Description of the issue"
  }'
```

### List Repository Branches

```bash
curl "${GITLAB_ENDPOINT}/api/v4/projects/123/repository/branches" \
  -H "Authorization: Bearer ${JWT_TOKEN}"
```

## Git over HTTPS

The same mount also proxies Git smart-HTTP (`clone`, `fetch`, `push`) to the configured `gitlab_address` — no separate config field needed, since GitLab serves both REST (`/api/v4/...`) and Git (`/<group>/<repo>.git/...`) off the same host root. The provider dispatches per-request: paths ending in `.git/info/refs`, `.git/git-upload-pack`, or `.git/git-receive-pack` route to GitLab with HTTP Basic Auth carrying `oauth2:<access-token>` as the credential; everything else continues to route as REST with the existing `Authorization: Bearer` flow.

### Clone, fetch, push (path-routed form)

The clone URL carries the Warden role as the Basic Auth username and the Warden JWT as the password. Git's credential helpers cache on URL + username, so each role gets a distinct cache entry — switching roles does not invalidate the other's cache. Subsequent `pull`/`push` against the cloned remote re-use the same role automatically.

```bash
git clone "https://<role>:${JWT_TOKEN}@${WARDEN_HOST}/v1/gitlab/gateway/<group>/<repo>.git"
```

Note the path shape: `/v1/gitlab/gateway/<group>/<repo>.git`. Unlike REST (which goes under `/v1/gitlab/gateway/api/v4/...`), Git smart-HTTP paths sit directly under `gateway/` — no `/api/v4` prefix, since Git and REST are separate protocols on the same mount.

To keep the JWT out of shell history and `.git/config`:

```bash
git config --global credential.helper "store"
# or, better, a short-lived in-memory cache:
git config --global credential.helper "cache --timeout=900"
```

### Header-routed form (`X-Warden-Provider` + `X-Warden-Namespace`)

Operators who want a clone URL that looks like a real Git URL (no Warden-specific path prefix) can use header routing instead. Set `X-Warden-Provider` via Git's `http.extraheader` config, carrying the mount path from `warden provider list`:

```bash
git -c http.extraheader="X-Warden-Provider: gitlab" \
    clone "https://<role>:${JWT_TOKEN}@${WARDEN_HOST}/<group>/<repo>.git"
```

For mounts in a non-root namespace, add `X-Warden-Namespace` as a second `http.extraheader` carrying the namespace path (the same value used in `WARDEN_NAMESPACE`):

```bash
git -c http.extraheader="X-Warden-Provider: gitlab" \
    -c http.extraheader="X-Warden-Namespace: team-a/data" \
    clone "https://<role>:${JWT_TOKEN}@${WARDEN_HOST}/<group>/<repo>.git"
```

Both headers persist into `.git/config` at clone time, so follow-up `pull`/`push` against the cloned remote carry them automatically. Warden synthesises the canonical `gitlab/gateway/<group>/<repo>.git/...` path under the resolved namespace before mount lookup, so the dispatch and credential flows behave identically to the path-routed form.

### Cert-auth clients

Cert-auth clients (mTLS or `X-SSL-Client-Cert` from a TLS-terminating proxy) still need to populate Git's password slot because the Git protocol requires it. Any placeholder works — the gitlab provider's token extractor skips the Basic Auth password when `X-SSL-Client-Cert` is set, so the placeholder is never sent to the JWT validator:

```bash
git clone "https://<role>:cert@${WARDEN_HOST}/v1/gitlab/gateway/<group>/<repo>.git"
```

Mixing a malformed cert with a valid JWT in the Basic Auth password is intentionally not a fallback path: if cert auth fails the request fails with a clear cert-auth error rather than silently switching schemes.

### Role precedence

Role resolution follows core ordering, with the Basic Auth username consulted after path/header roles but before `default_role`:

1. `X-Warden-Role` header
2. Path-embedded role (`/v1/gitlab/role/<role>/gateway/...`)
3. **Basic Auth username** (Git smart-HTTP only)
4. `default_role` from the mount config

So `git clone https://<role>:$JWT@<host>/...` resolves to the username even when a mount-level `default_role` is configured; the default is used only when none of the higher-precedence sources contribute. REST callers are unaffected — the Basic Auth username is consulted only on Git smart-HTTP paths.

### Sizing `git_max_body_size` and `timeout`

- **`git_max_body_size`** caps Git request bodies in bytes. Default 2 GiB; valid range 1 MiB to 10 GiB. The existing `max_body_size` field controls REST POST bodies separately (default 10 MiB, 100 MiB ceiling) — do not raise `max_body_size` to accommodate Git pushes, that is what `git_max_body_size` is for.
- **Do not crank `git_max_body_size` to the 10 GiB ceiling reflexively.** The ceiling is a sanity cap, not a recommended value. Bodies stream through Warden chunk-by-chunk so memory is fine, but each accepted request pins one goroutine, one outbound socket, and 2× the body's bandwidth (ingress + egress to the Git host) for the duration of the transfer. Size to your actual largest expected push, not the maximum theoretical push.
- **Tune `timeout` for the longest expected push.** The mount-level `timeout` controls how long Warden will wait for the full request/response cycle. The default suits REST API calls, not multi-minute Git pushes. Rough heuristic: `timeout ≥ (git_max_body_size / smallest expected client bandwidth) × 2`, rounded up generously. Example: a 2 GiB cap with clients on a 100 Mbps link needs at least 320 s — set `timeout = 600s`. Too-tight `timeout` shows up as half-uploaded pushes that fail at the same byte count, which is a confusing failure mode.

## Cleanup

To stop Warden and the identity provider:

```bash
# Stop Warden (Ctrl+C in the terminal where it's running)

# Stop and remove the identity provider containers
docker compose -f docker-compose.quickstart.yml down -v
```

Since Warden dev mode uses in-memory storage, all configuration is lost when the server stops.

## Minting Project and Group Access Tokens

Warden mints short-lived, scoped access tokens for GitLab projects and groups through credential specs (configured in Step 4).

### Access Levels

| Value | Role |
|-------|------|
| 10 | Guest |
| 15 | Planner |
| 20 | Reporter |
| 30 | Developer |
| 40 | Maintainer |

### Available Scopes

`api`, `read_api`, `read_user`, `read_repository`, `write_repository`, `read_registry`, `write_registry`, `sudo`, `admin_mode`, `create_runner`, `manage_runner`, `ai_features`, `k8s_proxy`

## Authentication Methods

| Method | Header Used | Token Caching | Rotation |
|--------|-------------|---------------|----------|
| **PAT** | `PRIVATE-TOKEN` | N/A | Supported via GitLab rotate API |
| **OAuth2** | `Authorization: Bearer` | Cached with 30s expiry buffer | Supported via application secret rotate API |

**OAuth2** is recommended because the application identity is organization-owned and not tied to a personal account. **PAT** is simpler to set up but creates a dependency on a single user account.

## Credential Rotation

GitLab credentials support the two-stage async rotation pattern:

- **PAT mode:** Rotates via `POST /api/v4/personal_access_tokens/{id}/rotate`. GitLab immediately revokes the old token and issues a new one.
- **OAuth2 mode:** Rotates via `POST /api/v4/applications/{id}/renew-secret`. GitLab immediately invalidates the old secret.

The default activation delay is **1 minute** (configurable via `activation_delay` in the credential source config). No cleanup is needed since GitLab automatically invalidates old credentials during rotation.

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
    default_role=gitlab-user
```

### Create a Cert Role

Create a role that binds allowed certificate identities to a credential spec and policy:

```bash
warden write auth/cert/role/gitlab-user \
    allowed_common_names="agent-*" \
    token_policies="gitlab-access" \
    cred_spec_name=gitlab-project-token
```

The `allowed_common_names` field supports glob patterns; you can also match on other certificate fields. See [Create a role](/auth-methods/cert/#step-3-create-a-role) for the full set of constraint fields.

### Configure Provider for Cert Auth

Update the provider config to use cert auth:

```bash
warden write gitlab/config <<EOF
{
  "gitlab_address": "https://gitlab.com",
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
    https://warden.internal/v1/gitlab/role/gitlab-user/gateway/api/v4/projects

# Default role (no role in URL)
curl --cert client.pem --key client-key.pem \
    --cacert warden-ca.pem \
    https://warden.internal/v1/gitlab/gateway/api/v4/projects
```

## Self-Hosted GitLab

To use with a self-hosted GitLab instance, set `gitlab_address` in both the provider config and credential source config:

```bash
warden write gitlab/config <<EOF
{
  "gitlab_address": "https://gitlab.example.com",
  "auto_auth_path": "auth/jwt/"
}
EOF
```

All gateway requests will be proxied to the configured GitLab instance.

### Custom CA Certificate

If your GitLab instance uses a certificate signed by a private CA:

```bash
# Base64-encode the CA certificate
CA_DATA=$(base64 < /path/to/corporate-ca.pem)

warden write gitlab/config <<EOF
{
  "gitlab_address": "https://gitlab.internal.corp",
  "ca_data": "${CA_DATA}",
  "auto_auth_path": "auth/jwt/"
}
EOF
```

### Development / Testing (no TLS)

For local development against a GitLab instance without TLS:

```bash
warden write gitlab/config <<EOF
{
  "gitlab_address": "http://localhost:8080",
  "tls_skip_verify": true,
  "auto_auth_path": "auth/jwt/"
}
EOF
```
