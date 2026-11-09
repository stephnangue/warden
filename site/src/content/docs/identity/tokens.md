---
title: "Tokens"
---

A **token** is Warden's record of an authenticated caller. Every authorized
request runs against one, whether or not the caller ever sees a token value.
[Authentication](/identity/authentication/) produces it; the role a request
runs under is not part of it. A token says *who* the caller is, and
[groups](/identity/groups/) grant a [role](/identity/roles/) to it on each
request.

Warden has three token types:

| Type | Value | ID | Issued by | Stored | Default lifetime |
|------|-------|----|-----------|--------|------------------|
| `identity_token` | none, never handed out | `wdi_…` | a `jwt`, `kubernetes`, `cert` or `spiffe` mount, on implicit authentication | in memory only | the mount's `token_ttl` (1 hour), capped by the credential's expiry |
| `service_token` | `wds.…` | `wds_…` | Warden; the root token is one | encrypted storage | 1 hour; the root token never expires |
| `ticket_token` | `wdt.…` | `wdt_…` | an `oidc` mount, at `warden login` | nowhere | the mount's `session_ttl` (1 hour, at most 8) |

For what changed from the previous model, see
[Upgrading from v0.21.0](/upgrade/from-v0-21/).

## Identity tokens

An identity token is the cached result of an auth mount admitting a credential
the caller already holds: a JWT, a Kubernetes service account token, a client
certificate or an SVID. It holds the admission (the verified facts, the native
identity and the kind) and no policies of its own.

There is **one identity token per auth mount and credential**. Its ID is
`wdi_` followed by a hash of the mount's accessor and the credential, so the
same JWT presented again maps to the same token, and the same JWT presented to
two mounts maps to two. A busy agent sends thousands of requests with one
credential and is admitted once.

No value is ever handed out. The caller presents its own credential on every
request, and Warden finds the token from it. An identity token's ID sent back
as `X-Warden-Token` is refused a role.

Identity tokens live **in memory only**. They are never written to storage, and
after a restart or a seal they do not exist until the next request admits the
credential again. This keeps high-volume, per-request workload identities out
of durable storage.

## Service tokens

A service token is a bearer token Warden issues and keeps. Its value is `wds.`
followed by 64 random characters; its ID is `wds_` followed by a hash of the
value. Unlike the other two types, a service token carries its own
[policies](/identity/policies/) rather than taking a role per request.

Service tokens are **written through** to Warden's encrypted storage, so they
survive restarts and unseals, and each has an **accessor**: a random reference
that names the token without being usable to authenticate.

### The root token

The **root token** is a service token carrying the built-in `root` policy, the
root namespace and **no expiry**. It is the bootstrap identity: the credential
that enables auth methods, writes groups, roles and policies, and configures the
server before any other identity exists.

- It is printed once in the [dev server](/concepts/dev-server/) banner, or
  returned by `warden operator init` on a production server.
- On a dev server, `-dev-root-token` sets its value, which is convenient for
  fixtures and scripts.
- Only one root token is valid at a time.

Because the root policy allows everything, treat the root token as a
break-glass credential. Set up an [oidc](/auth-methods/oidc/) mount and the
[built-in operator roles](/identity/built-in-roles/), then sign in with
`warden login` for day-to-day work.

## Tickets

A ticket is the session a person gets from an `oidc` mount. After the browser
sign-in, the mount seals what it verified into the ticket value itself: the
native identity, the kind (`human`), the facts the mount publishes from the ID
token, the namespace, the issuing mount, the issue and expiry times, and when
the person last authenticated at the identity provider. The value is `wdt.`
followed by that payload, encrypted under Warden's key.

A ticket is **self-contained**. Warden stores nothing when it issues one, and
any node of a cluster can read it. It carries **no role and no policies**: each
request names a role, and the groups that match the ticket's facts must grant
it. A ticket has no accessor and no IP binding.

```bash
warden login
warden login -role=operator
warden role use auditor
```

`warden login` keeps the ticket in `~/.warden/sessions`, one per Warden address
and namespace, and later commands send it with the chosen role.
`warden print token` prints it for other tools, which send it as an
`Authorization` bearer and name the role with `X-Warden-Role`.

A ticket is accepted on `X-Warden-Token` or as an `Authorization` bearer, and
nowhere else: not on `X-Warden-Agent-Token`, not in a provider-specific
channel, and never as the user of a provider with a user leg.

Its claims are fixed when it is issued. A change to the person's groups at the
identity provider reaches Warden at the next sign-in; `warden login -force`
signs in again before the ticket expires. See
[Human operators](/identity/human-operators/).

## Checks on every request

A token is accepted only if it passes every check, on every request:

- **Not expired.** The current time is before its expiry.
- **Namespace.** The token is valid in the namespace it was issued in and its
  descendants, never in a sibling or an ancestor (see
  [Namespaces](/concepts/namespaces/)).
- **Origin.** A token that recorded the client IP it was created from is
  checked against the request's address, as the server's `ip_binding_policy`
  says (see [Configuration](/configuration/)). A ticket has no IP binding.
- **Issuing mount.** A ticket's `oidc` mount must still exist in the ticket's
  namespace.

## Expiry and revocation

No token is renewable. When one expires, the caller gets a new one the way it
got the first.

| Type | Ends when |
|------|-----------|
| `identity_token` | it expires, or its auth mount is disabled; the next request with the same, still valid credential is admitted again |
| `service_token` | it expires, or its namespace is deleted |
| `ticket_token` | it expires, its `oidc` mount is disabled, or its namespace is deleted |

**A ticket cannot be revoked before it expires.** The one way to end tickets
early is to disable the `oidc` mount that issued them: every ticket it issued is
refused from the next request, and a mount enabled again at the same path is a
new mount whose tickets are new. Keep `session_ttl` short for that reason.
`warden logout` only forgets the local copy; the ticket itself stays valid
until it expires.

Revoking a token is rarely what you need, because tokens carry no permissions
for an agent or a person. To stop a caller now:

- **Change what it is granted.** Remove the group rule or the role. Group and
  role edits apply from the next request, including for cached identity tokens
  and tickets.
- **Stop admitting its credential.** Tighten the auth mount (`bound_claims`,
  `max_age`, a narrower trust anchor) or revoke the credential at its issuer.
- **Act on its entity.** If an [entity](/identity/entities/) in the identity
  store claims the caller's native identity, suspending or retiring that entity
  can refuse its requests.

## In audit and in policy

Each [audit](/concepts/audit/) entry describes the token the request ran
under. The token value is never logged.

| Audit field | Meaning |
|-------------|---------|
| `auth.token_type` | `identity_token`, `service_token` or `ticket_token` |
| `auth.token_id` | the token's ID: `wdi_…`, `wds_…` or `wdt_…` |
| `auth.token_accessor` | the accessor; absent for a ticket |
| `auth.mount_accessor` | the auth mount that admitted the credential; absent for the root token |
| `auth.alias_name` | the native identity the credential presented |
| `auth.entity_kind` | `agent` or `human` |
| `auth.auth_time` | for a ticket, when the person last signed in at the identity provider |
| `auth.user.token_id` | on a request with a user leg, the user's identity token |

The role granted for the request is recorded beside it, in `auth.role_name`,
`auth.role_granted_by` and `auth.groups`, or in `auth.role_denied_reason` when
no role was granted.

In [CEL conditions](/identity/cel-conditions/), `agent.token_type` holds the
same strings: `identity_token`, `service_token` or `ticket_token`.
`user.token_type` is `identity_token` whenever a user is present. A token type
says how the caller authenticated, not which auth method admitted it; select on
the mount with groups, or on mapped facts with `agent.metadata.<name>`.

```hcl
path "prod/payments/*" {
  capabilities = ["update"]
  condition    = "agent.token_type == 'identity_token' && agent.metadata.env == 'prod'"
}
```

## See also

- [Authentication](/identity/authentication/): how a credential is admitted.
- [Groups](/identity/groups/) and [Roles](/identity/roles/): how a token is
  granted a role per request.
- [Human operators](/identity/human-operators/): tickets in practice.
- [Built-in roles](/identity/built-in-roles/): operator roles for tickets.
- [Policies](/identity/policies/) and [Namespaces](/concepts/namespaces/).
