---
name: troubleshooting
description: "Common agent failures: classified errors, what to retry, what means 'ask the operator'."
category: shared
requires: [warden-shared]
---

# Troubleshooting

Every Warden CLI call exits with one of nine codes (see
`warden-shared`). Branch on `code` from the JSON envelope; don't grep
the human message.

## `auth_required` (exit 4)

Symptoms: `WARDEN_TOKEN` not set, expired JWT, missing client cert.

Action:
- Refresh the JWT (typical TTL is 5–60 minutes; agents that hold a
  JWT for hours WILL hit this).
- Confirm `WARDEN_CLIENT_CERT` / `WARDEN_CLIENT_KEY` resolve to
  readable files.
- For SigV4-signed providers (AWS, Scaleway S3): a stale JWT also
  produces `SignatureDoesNotMatch` upstream because the SDK signed
  with a now-rejected token. Same fix: refresh.

Retry: yes, after refresh.

## `forbidden` (exit 5)

Symptoms: identity is valid but the policy bound to the chosen role
doesn't allow the operation.

Action:
- Re-run `warden roles -o json` and pick a role whose description
  matches the operation.
- If no role fits, the operator hasn't granted you the capability —
  surface to the user, don't try to escalate.

Retry: only after picking a different role.

## `not_found` (exit 6)

Symptoms: path doesn't exist (typo in mount name), or namespace is
wrong, or resource has been deleted.

Action:
- Run `warden list sys/providers -o json` to see real mount names.
- Check `WARDEN_NAMESPACE` is the one you mean (`-n` overrides per-call).
- For typed resources: re-list (`warden cred source list`,
  `warden auth list`, `warden namespace list`) before retrying.

Retry: no, unless you've confirmed the path exists.

## `invalid_input` (exit 3)

Symptoms: payload validation rejected something locally — wrong field
name, wrong type, missing required field.

Action:
- Re-read the error envelope's `message`. Validators emit one line per
  problem and include "did you mean" hints for typos.
- `warden schema <mount>/<path> -o json` to see the canonical
  parameter list (look at `parameters[].name`, `.type`, `.required`,
  `.sensitive`).
- Fix the payload and retry.

Retry: yes, with corrected payload.

## `network` (exit 7)

Symptoms: connection refused, TLS handshake failed, DNS resolution
failed, request timeout.

Action:
- Check `WARDEN_ADDR`.
- For S3-style operations against AWS/Scaleway: virtual-hosted DNS
  (e.g., `<bucket>.<warden-host>`) requires wildcard DNS. See
  `provider/aws/README.md` § DNS Configuration. Without it the SDK's
  signed Host doesn't resolve to Warden.
- Backoff + retry.

Retry: yes, with exponential backoff.

## `server` (exit 8)

Symptoms: 5xx from Warden or from the upstream service Warden
proxied to. The error envelope often contains the upstream's text
verbatim — read it, don't assume it's Warden's fault.

Action:
- Distinguish "Warden returned 500" (file a Warden bug) from
  "upstream returned 500" (not Warden's responsibility).
- Backoff + retry on transient upstream errors.

Retry: bounded, with backoff.

## `conflict` (exit 9)

Symptoms: `name already exists` on a create.

Action:
- The resource exists. Read it and either update with the right
  values or pick a different name.

Retry: no — this is a deterministic state, not a transient issue.

## When the discovery flow itself fails

| Symptom | Likely cause | Action |
|---|---|---|
| `warden roles` returns `[]` | identity isn't bound to any role on this namespace | ask operator to bind your identity |
| `warden roles` returns `forbidden` | introspection endpoint not reachable | check `WARDEN_TOKEN`, JWT issuer, namespace |
| `warden list sys/providers` returns `forbidden` | namespace's default role doesn't grant `read sys/providers/*` | ask operator to add the policy |
| Provider exists in `list sys/providers` but `path-help` says "no help" | provider has no documented help | use `warden schema <mount>/<path>` and the provider's `README.md` |

## Sensitive-field handling

If a parameter shows `sensitive: true` in `warden schema`:
- Never log the request body or print to stdout outside `-o json`.
- Read responses already mask server-side, but **treat any field
  that was sensitive on the way in as secret on the way out** —
  someone may have leaked it into your context.

