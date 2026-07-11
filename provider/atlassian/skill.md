---
name: atlassian
description: "Call Jira, Confluence, or Bitbucket REST APIs through Warden — search and create issues, read and write pages, list repos — without holding an API token, PAT, or app password."
category: provider-guide
provider: atlassian
requires: []
upstream: Atlassian Jira / Confluence / Bitbucket REST APIs
---

# Atlassian through Warden

## What it does

Warden proxies Atlassian REST API requests. The agent calls a Warden
URL; Warden authenticates the caller (JWT/cert), looks up the
Atlassian credential bound to the chosen role, injects the right
auth header (Basic when the credential carries `email` + `api_key`,
Bearer when it carries `api_key` alone), and forwards to Atlassian.
The agent **never holds an API token, PAT, or app password**.

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
URL pattern : $WARDEN_ADDR<gateway-url><api-path>
Auth header : Authorization: Bearer <jwt>
```

**One `atlassian` mount = one product.** A single Atlassian provider
type fronts every Atlassian REST API; the operator picks which —
Jira, Confluence, or Bitbucket — at mount time and signals the
choice via the mount's **description**. Read the role's `list_roles`
description (e.g. "Engineering Jira Cloud",
"Docs Confluence space", "Platform Bitbucket"), match it to the
product, then use the path shapes for that product below:

| Product | Path shape after `/gateway/` |
|---|---|
| Jira Cloud v3 | `myself`, `issue`, `search/jql`, `project` |
| Jira Data Center | same as Jira Cloud, but accepts wiki/plain markup in bodies |
| Confluence Cloud v2 | `spaces`, `pages`, `blogposts` |
| Bitbucket Cloud | `user`, `repositories/{workspace}` |

If the description is ambiguous, surface that to the user rather
than guessing — calling a Confluence path against a Jira mount
returns `404` from the upstream, not a helpful error.

Atlassian's API path is part of the upstream URL — Warden does not
strip or prepend it. Write the path verbatim after `/gateway/`.

## Examples

(Examples use a concrete `<gateway-url>` of
`/v1/jira/role/atlassian-ops/gateway/` for Jira,
`/v1/confluence/role/atlassian-ops/gateway/` for Confluence,
`/v1/bitbucket/role/atlassian-ops/gateway/` for Bitbucket; substitute the one
from your role's `list_roles` description.)

Current user (verifies the injected credential is valid):
```bash
curl -H "Authorization: Bearer <jwt>" \
  $WARDEN_ADDR/v1/jira/role/atlassian-ops/gateway/myself
```

Search issues with JQL (use POST to skip URL-encoding):
```bash
curl -X POST -H "Authorization: Bearer <jwt>" \
  -H "Content-Type: application/json" \
  -d '{"jql":"project = ENG AND status = Open","fields":["summary","status"]}' \
  $WARDEN_ADDR/v1/jira/role/atlassian-ops/gateway/search/jql
```

Create a Jira issue (note the ADF `description` — see Quirks):
```bash
curl -X POST -H "Authorization: Bearer <jwt>" \
  -H "Content-Type: application/json" \
  -d '{
    "fields": {
      "project": {"key": "ENG"},
      "summary": "Investigate flaky test",
      "issuetype": {"name": "Task"},
      "description": {
        "type": "doc", "version": 1,
        "content": [{"type":"paragraph","content":[{"type":"text","text":"Repro on CI run 1842."}]}]
      }
    }
  }' \
  $WARDEN_ADDR/v1/jira/role/atlassian-ops/gateway/issue
```

List Confluence spaces:
```bash
curl -H "Authorization: Bearer <jwt>" \
  $WARDEN_ADDR/v1/confluence/role/atlassian-ops/gateway/spaces
```

Create a Confluence page (requires numeric `spaceId` — see Quirks):
```bash
curl -X POST -H "Authorization: Bearer <jwt>" \
  -H "Content-Type: application/json" \
  -d '{
    "spaceId": "123456",
    "status": "current",
    "title": "Postmortem 2026-05-20",
    "body": {"representation": "storage", "value": "<p>Summary…</p>"}
  }' \
  $WARDEN_ADDR/v1/confluence/role/atlassian-ops/gateway/pages
```

List Bitbucket repositories in a workspace:
```bash
curl -H "Authorization: Bearer <jwt>" \
  $WARDEN_ADDR/v1/bitbucket/role/atlassian-ops/gateway/repositories/my-workspace
```

## Quirks

- **Jira v3 `description` must be ADF, not a plain string.** Plain
  text on `POST /issue` returns `400`. Send the Atlassian Document
  Format structure (`{"type":"doc","version":1,"content":[…]}`) as
  in the example above, or target a Jira Data Center mount
  (`/rest/api/2`) where wiki/plain markup is accepted.
- **Confluence v2 wants numeric `spaceId`, not `spaceKey`.** Either
  pass `?space-key=ENG` on `GET /pages`, or look the space up first
  via `GET /spaces?keys=ENG` and read `results[0].id`. Sending an
  alphanumeric key as `spaceId` returns `400`.
- **Jira `/search` is deprecated in Cloud.** Prefer
  `POST /rest/api/3/search/jql` (shown above) over the old
  `GET /rest/api/3/search` — same JQL, the new shape puts the query
  in a JSON body and removes the per-page result cap.
- **Pagination differs per product.** Jira uses `startAt` /
  `maxResults`; Confluence v2 uses `limit` / `cursor` (and returns
  a `next` link); Bitbucket uses `page` / `pagelen`. Do not assume
  one applies across products.
- **Bitbucket paths take `{workspace}/{repo_slug}`, not
  `owner/repo`.** The workspace slug is what appears in the
  bitbucket.org URL, and is independent of the user that owns the
  repo.
- **Rate limits return `429` with a `Retry-After` header** across
  all three products. Honor the header — don't immediate-retry, or
  you'll get throttled harder.
- **Policies can restrict request body fields.** Warden parses the
  request body, so an operator's policy may allow only specific
  Jira fields, Confluence properties, or Bitbucket attributes. If a
  request is rejected before reaching Atlassian, the error comes
  from Warden, not the upstream API.
