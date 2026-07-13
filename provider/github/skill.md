---
name: github
description: "Call the GitHub REST API or clone/push Git repos through Warden — without holding a GitHub PAT. Covers REST (read repos, manage issues, push releases) and Git smart-HTTP (clone, fetch, push)."
category: provider-guide
provider: github
requires: []
upstream: GitHub REST API (api.github.com or GHE) and Git smart-HTTP (github.com or GHE)
---

# GitHub through Warden

## What it does

Warden proxies GitHub REST API requests. The agent calls a Warden
URL; Warden authenticates the caller (JWT/cert), looks up the GitHub
PAT bound to the chosen role, injects it as `Authorization: token <pat>`
plus a default `X-GitHub-Api-Version` header, and forwards to GitHub.
The agent **never holds a PAT**.

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
URL pattern : $WARDEN_ADDR<gateway-url><github-api-path>
Auth header : Authorization: Bearer <jwt>
```

For `curl` or any HTTP client: rewrite the GitHub host to
`$WARDEN_ADDR<gateway-url>` and add the bearer token.

## Examples

(Examples use a concrete `<gateway-url>` of `/v1/github/role/repo-reader/gateway/`;
substitute the one from your role's `list_roles` description.)

List your authenticated user's repos:
```bash
curl -H "Authorization: Bearer <jwt>" \
  $WARDEN_ADDR/v1/github/role/repo-reader/gateway/user/repos
```

Read a specific repo's issues:
```bash
curl -H "Authorization: Bearer <jwt>" \
  $WARDEN_ADDR/v1/github/role/repo-reader/gateway/repos/myorg/myrepo/issues
```

Open an issue (operator must grant a write-capable role):
```bash
curl -X POST -H "Authorization: Bearer <jwt>" \
  -H "Accept: application/vnd.github+json" \
  -d '{"title":"Bug","body":"..."}' \
  $WARDEN_ADDR/v1/github/role/issue-writer/gateway/repos/myorg/myrepo/issues
```

For the Octokit JS / PyGithub clients: configure the `baseUrl` /
`base_url` to `$WARDEN_ADDR<gateway-url>`
and supply your JWT as the auth token.

## Quirks

- **The injected header is `Authorization: token <pat>` (not `Bearer`)** —
  Warden uses GitHub's classic token form, which works for both PATs
  and fine-grained tokens.
- **`X-GitHub-Api-Version: 2022-11-28` is auto-injected** unless your
  request supplies its own. Override by setting the header in your
  call.
- **GHE (GitHub Enterprise Server) deployments** point Warden at the
  GHE host instead of `api.github.com`; ask the operator which host the
  mount fronts.
- **Rate limits propagate from GitHub**. Warden does not retry; back
  off when you see `403 rate limit exceeded` headers.

## Git

The same mount also proxies Git smart-HTTP (`git clone`, `fetch`, `push`)
to the Git host (`github.com` by default; for GHE the host of `github_url`
with `/api/v3` stripped). REST and Git share the mount; the provider
dispatches per-request based on path shape — `.git/info/refs`,
`.git/git-upload-pack`, and `.git/git-receive-pack` route to the Git
host with HTTP Basic Auth instead of the REST `Authorization: token`.

(Examples use a concrete `<gateway-url>` of `/v1/github/role/repo-reader/gateway/`;
substitute the one from your role's `list_roles` description.)

### Clone

The clone URL carries the Warden role as the Basic Auth username and
the Warden JWT as the password. Substitute `<role>` and the mount path:

Git embeds Basic Auth between scheme and host in the clone URL, so
split `$WARDEN_ADDR` — `${WARDEN_ADDR%%://*}` is the scheme,
`${WARDEN_ADDR#*://}` is the host (and port if present):

```bash
git clone "${WARDEN_ADDR%%://*}://<role>:<jwt>@${WARDEN_ADDR#*://}/v1/github/gateway/<owner>/<repo>.git"
```

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
    clone "${WARDEN_ADDR%%://*}://<role>:<jwt>@${WARDEN_ADDR#*://}/<owner>/<repo>.git"
```

`http.extraheader` persists into `.git/config` at clone time, so both
headers carry through to follow-up operations automatically.

### Quirks

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

