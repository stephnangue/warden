---
name: github
description: "Call the GitHub REST API through Warden — read repos, manage issues, push releases — without holding a GitHub PAT."
category: provider-guide
provider: github
upstream: GitHub REST API (api.github.com or GHE)
---

# GitHub through Warden

## What it does

Warden proxies GitHub REST API requests. The agent calls a Warden
URL; Warden authenticates the caller (JWT/cert), looks up the GitHub
PAT bound to the chosen role, injects it as `Authorization: token <pat>`
plus a default `X-GitHub-Api-Version` header, and forwards to GitHub.
The agent **never holds a PAT**.

## Configure the CLI/SDK

`<mount>` and `<role>` below come from the discovery flow:
- `<mount>` is the chosen provider's path from `warden provider list`
  (e.g. `github/`, `github-enterprise/`).
- `<role>` is the role you picked from `warden role list` to perform this
  task — it goes in the URL path.

```bash
URL pattern : $WARDEN_ADDR/v1/<mount>/role/<role>/gateway/<github-api-path>
Auth header : Authorization: Bearer <JWT>
```

For `curl` or any HTTP client: rewrite the GitHub host to
`<warden>/v1/<mount>/role/<role>/gateway` and add the bearer JWT.

## Examples

(All examples assume mount `github/` and role `repo-reader`;
substitute yours.)

List your authenticated user's repos:
```bash
curl -H "Authorization: Bearer $JWT" \
  $WARDEN_ADDR/v1/github/role/repo-reader/gateway/user/repos
```

Read a specific repo's issues:
```bash
curl -H "Authorization: Bearer $JWT" \
  $WARDEN_ADDR/v1/github/role/repo-reader/gateway/repos/myorg/myrepo/issues
```

Open an issue (operator must grant a write-capable role):
```bash
curl -X POST -H "Authorization: Bearer $JWT" \
  -H "Accept: application/vnd.github+json" \
  -d '{"title":"Bug","body":"..."}' \
  $WARDEN_ADDR/v1/github/role/issue-writer/gateway/repos/myorg/myrepo/issues
```

For the Octokit JS / PyGithub clients: configure the `baseUrl` /
`base_url` to `$WARDEN_ADDR/v1/<mount>/role/<role>/gateway`
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

