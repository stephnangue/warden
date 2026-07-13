---
name: gitlab
description: "Call the GitLab REST API or clone/push Git repos through Warden — without holding a GitLab access token. Covers REST (read projects, manage issues, trigger pipelines) and Git smart-HTTP (clone, fetch, push)."
category: provider-guide
provider: gitlab
requires: []
upstream: GitLab REST API (gitlab.com/api/v4 or self-hosted /api/v4) and Git smart-HTTP (same host)
---

# GitLab through Warden

## What it does

Warden proxies GitLab REST API requests. The agent calls a Warden
URL; Warden authenticates the caller (JWT/cert), looks up the GitLab
access token bound to the chosen role, injects it as
`Authorization: Bearer <token>`, and forwards to GitLab. The agent
**never holds an access token**.

## Configure the CLI/SDK

`<gateway-url>` comes from the role you chose: the `list_roles` discovery tool
returns each role with a `description`, and for a non-MCP provider the operator
embeds the role's **gateway URL** in it — a relative path
`/v1/<namespace>/<mount>/role/<role>/gateway/`, with the namespace, mount, and role already baked in. Prepend `$WARDEN_ADDR` (the address you already
used to discover your roles).

The `role/<role>/` segment in `<gateway-url>` is the role this call runs under.
To act under a *different* role, use the `<gateway-url>` of that role from
`list_roles` — each role provides its own role-bearing URL in its description.

Present your identity on every call: `Authorization: Bearer <jwt>`, or an mTLS
client certificate. A `401` means the JWT expired (typical TTL 5–60 min) —
refresh and retry.

```bash
URL pattern : $WARDEN_ADDR<gateway-url>api/v4/<gitlab-api-path>
Auth header : Authorization: Bearer <jwt>
```

Unlike GitHub (which proxies REST off the host root), GitLab's REST
API lives under `/api/v4/`, so the gateway path includes `api/v4/`
**after** the `gateway/` segment.

For `curl` or any HTTP client: rewrite the GitLab host (including
`/api/v4`) to `$WARDEN_ADDR<gateway-url>api/v4` and
add the bearer token.

## Examples

(Examples use a concrete `<gateway-url>` of `/v1/gitlab/role/repo-reader/gateway/`;
substitute the one from your role's `list_roles` description.)

List projects you're a member of:
```bash
curl -H "Authorization: Bearer <jwt>" \
  $WARDEN_ADDR/v1/gitlab/role/repo-reader/gateway/api/v4/projects?membership=true
```

Read a specific project's issues:
```bash
curl -H "Authorization: Bearer <jwt>" \
  "$WARDEN_ADDR/v1/gitlab/role/repo-reader/gateway/api/v4/projects/<id>/issues"
```

Open an issue (operator must grant a write-capable role):
```bash
curl -X POST -H "Authorization: Bearer <jwt>" \
  -H "Content-Type: application/json" \
  -d '{"title":"Bug","description":"..."}' \
  "$WARDEN_ADDR/v1/gitlab/role/issue-writer/gateway/api/v4/projects/<id>/issues"
```

For the python-gitlab client: configure `gitlab.Gitlab(url=...)` with
`$WARDEN_ADDR<gateway-url>` (no `/api/v4` suffix — the
client appends it) and use `oauth_token=<jwt>` for auth.

## Quirks

- **The injected header is `Authorization: Bearer <token>`** —
  Warden swaps your `Authorization: Bearer <jwt>` (incoming)
  for the credential token (outgoing). GitLab accepts the same Bearer
  shape for OAuth2 tokens, personal access tokens, and project/group
  access tokens.
- **`PRIVATE-TOKEN` header on incoming requests works too** — if your
  client prefers GitLab's native auth header, send the JWT there
  instead of `Authorization`. Warden strips it before proxying.
- **Self-hosted instances** point Warden at the instance URL (e.g.
  `https://gitlab.example.com`); ask the operator which host the mount
  fronts. The same `gitlab_address` covers both REST and Git.
- **Rate limits propagate from GitLab**. Warden does not retry; back
  off when you see `429 Too Many Requests`.

## Git

The same mount also proxies Git smart-HTTP (`git clone`, `fetch`, `push`)
to the configured `gitlab_address`. REST and Git share the mount; the
provider dispatches per-request based on path shape — `.git/info/refs`,
`.git/git-upload-pack`, and `.git/git-receive-pack` route to GitLab
with HTTP Basic Auth instead of the REST `Authorization: Bearer`.

(Examples use a concrete `<gateway-url>` of `/v1/gitlab/role/repo-reader/gateway/`;
substitute the one from your role's `list_roles` description.)

### Clone

The clone URL carries the Warden role as the Basic Auth username and
the Warden JWT as the password. Substitute `<role>` and the mount path:

Git embeds Basic Auth between scheme and host in the clone URL, so
split `$WARDEN_ADDR` — `${WARDEN_ADDR%%://*}` is the scheme,
`${WARDEN_ADDR#*://}` is the host (and port if present):

```bash
git clone "${WARDEN_ADDR%%://*}://<role>:<jwt>@${WARDEN_ADDR#*://}/v1/gitlab/gateway/<group>/<repo>.git"
```

Note: Git smart-HTTP paths use `<group>/<repo>.git` directly off the
mount's `gateway/` segment — no `/api/v4/` here, since Git is a
separate protocol from REST.

Git's credential helpers cache on URL+username, so each role gets a
distinct cache entry — switching roles does not invalidate the other's
cache. Subsequent `pull`/`push` against the cloned remote re-use the
same role automatically.

To keep the JWT out of shell history and `.git/config`:
```bash
git config --global credential.helper "cache --timeout=900"
```

### Header-routed alternative

If you prefer a clone URL that looks like a real Git URL, pass the
mount and namespace as headers via `http.extraheader` instead. Both come
straight out of `<gateway-url>` (`/v1/<namespace>/<mount>/role/<role>/gateway/`):
`X-Warden-Provider` is the `<mount>` segment and `X-Warden-Namespace` is
the `<namespace>` segment.

```bash
git -c http.extraheader="X-Warden-Provider: <mount>" \
    -c http.extraheader="X-Warden-Namespace: <namespace>" \
    clone "${WARDEN_ADDR%%://*}://<role>:<jwt>@${WARDEN_ADDR#*://}/<group>/<repo>.git"
```

`http.extraheader` persists into `.git/config` at clone time, so both
headers carry through to follow-up operations automatically.

### Quirks

- **Basic Auth username is `oauth2`** on the upstream call — Warden
  formats the credential as `Basic base64(oauth2:<access-token>)`,
  which is GitLab's published convention for OAuth2 tokens and also
  accepted for personal/project/group access tokens. The username slot
  on your **clone URL** is still the Warden role; Warden re-encodes it
  on the upstream side.
- **Role precedence**: `X-Warden-Role` header > path-embedded
  `/role/<r>/` > Basic Auth username (Git smart-HTTP only) >
  `default_role`. Per-clone role selection via the username works even
  when a mount-level `default_role` is set.
- **Cert-auth clients** still need a non-empty Basic Auth password
  (Git protocol requirement). Any placeholder works; the placeholder is
  never sent to the JWT validator when `X-SSL-Client-Cert` is present.
- **Body size**: large pushes need `git_max_body_size` raised on the
  mount (default 2 GiB, max 10 GiB), and the mount `timeout` raised to
  match. See the provider README for sizing guidance.
- **Not in scope**: LFS, partial clone, submodules with embedded
  credentials.
