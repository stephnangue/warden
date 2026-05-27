---
name: github
description: "Call the GitHub REST API or clone/push Git repos through Warden — without holding a GitHub PAT. Covers REST (read repos, manage issues, push releases) and Git smart-HTTP (clone, fetch, push)."
category: provider-guide
provider: github
requires: [foundation, discovery]
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

`<mount-url>` and `<role>` below come from the discovery flow:
- `<mount-url>` is the chosen provider's `mount_url` from
  `warden provider list` (e.g. `/v1/github/`, `/v1/team-data/github-enterprise/`).
  Warden has already baked the namespace + mount path in.
- `<role>` is the role you picked from `warden role list` to perform this
  task — it goes in the URL path.

```bash
URL pattern : $WARDEN_ADDR<mount-url>role/<role>/gateway/<github-api-path>
Auth header : Authorization: Bearer $WARDEN_TOKEN
```

For `curl` or any HTTP client: rewrite the GitHub host to
`$WARDEN_ADDR<mount-url>role/<role>/gateway` and add the bearer token.

## Examples

(All examples assume `mount_url = /v1/github/` and role `repo-reader`;
substitute yours.)

List your authenticated user's repos:
```bash
curl -H "Authorization: Bearer $WARDEN_TOKEN" \
  $WARDEN_ADDR/v1/github/role/repo-reader/gateway/user/repos
```

Read a specific repo's issues:
```bash
curl -H "Authorization: Bearer $WARDEN_TOKEN" \
  $WARDEN_ADDR/v1/github/role/repo-reader/gateway/repos/myorg/myrepo/issues
```

Open an issue (operator must grant a write-capable role):
```bash
curl -X POST -H "Authorization: Bearer $WARDEN_TOKEN" \
  -H "Accept: application/vnd.github+json" \
  -d '{"title":"Bug","body":"..."}' \
  $WARDEN_ADDR/v1/github/role/issue-writer/gateway/repos/myorg/myrepo/issues
```

For the Octokit JS / PyGithub clients: configure the `baseUrl` /
`base_url` to `$WARDEN_ADDR<mount-url>role/<role>/gateway`
and supply your JWT as the auth token.

## Quirks

- **The injected header is `Authorization: token <pat>` (not `Bearer`)** —
  Warden uses GitHub's classic token form, which works for both PATs
  and fine-grained tokens.
- **`X-GitHub-Api-Version: 2022-11-28` is auto-injected** unless your
  request supplies its own. Override by setting the header in your
  call.
- **GHE (GitHub Enterprise Server) deployments** point Warden at the
  GHE host instead of `api.github.com`; check
  `warden read github/config` to confirm which.
- **Rate limits propagate from GitHub**. Warden does not retry; back
  off when you see `403 rate limit exceeded` headers.

## Git

The same mount also proxies Git smart-HTTP (`git clone`, `fetch`, `push`)
to the Git host (`github.com` by default; for GHE the host of `github_url`
with `/api/v3` stripped). REST and Git share the mount; the provider
dispatches per-request based on path shape — `.git/info/refs`,
`.git/git-upload-pack`, and `.git/git-receive-pack` route to the Git
host with HTTP Basic Auth instead of the REST `Authorization: token`.

### Clone

The clone URL carries the Warden role as the Basic Auth username and
the Warden JWT as the password. Substitute `<role>` and the mount URL:

```bash
git clone "https://<role>:${WARDEN_TOKEN}@$WARDEN_HOST/v1/github/gateway/<owner>/<repo>.git"
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

If you prefer a clone URL that looks like a real Git URL, set
`X-Warden-Provider: github` via `http.extraheader` instead:

```bash
git -c http.extraheader="X-Warden-Provider: github" \
    clone "https://<role>:${WARDEN_TOKEN}@$WARDEN_HOST/<owner>/<repo>.git"
```

`http.extraheader` persists into `.git/config` at clone time, so the
header carries through to follow-up operations automatically.

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

