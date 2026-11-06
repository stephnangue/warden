---
title: "Authentication"
---

Every request to Warden carries a credential. Authentication is how Warden
turns that credential into a verified identity: who the caller is, what kind of
caller it is, and the facts its credential proved. It does not decide what the
caller may do. That is the job of a [role](/identity/roles/), which
[groups](/identity/groups/) grant per request from the facts authentication
recorded. An auth mount only vouches for a credential; it grants nothing.

For what changed from the previous model, see
[Upgrading from v0.21.0](/upgrade/from-v0-21/).

## Credentials Warden accepts

| Credential | How it is sent | Who checks it |
|------------|----------------|---------------|
| **Bearer JWT** (OIDC, CI, any issuer with keys) | `Authorization: Bearer <jwt>` | a [`jwt`](/auth-methods/jwt/) mount |
| **Kubernetes service account token** | `Authorization: Bearer <jwt>` | a [`kubernetes`](/auth-methods/kubernetes/) mount, through the cluster's TokenReview |
| **SPIFFE JWT-SVID** | `Authorization: Bearer <jwt>` | a [`spiffe`](/auth-methods/spiffe/) mount |
| **mTLS client certificate** or **X.509-SVID** | the TLS handshake, or `X-Forwarded-Client-Cert` from a trusted proxy | a [`cert`](/auth-methods/cert/) or `spiffe` mount |
| **Service token** (`wds.…`) | `X-Warden-Token` | Warden's token store; no mount |
| **Ticket** (`wdt.…`) | `X-Warden-Token`, or `Authorization: Bearer` | Warden itself; issued by an [`oidc`](/auth-methods/oidc/) mount |

The first four are credentials the caller already holds. Warden verifies them
on the request itself, so an agent built for the upstream API points its
client at Warden and keeps presenting the token or certificate it has. The last
two are Warden's own [tokens](/identity/tokens/): the root token and other
service tokens, and the ticket a person gets from `warden login`.

> **mTLS is a property of the connection.** A client certificate authenticates
> because it is presented in the TLS handshake, by any client. A sidecar such as
> [ghostunnel](https://github.com/ghostunnel/ghostunnel) can hold the
> certificate for the workload, and [Robin](https://github.com/stephnangue/robin)
> can attach a bearer JWT the same way. mTLS needs a listener configured to
> request client certificates; it does nothing on the plain-HTTP
> [dev server](/concepts/dev-server/) listener. See
> [Agent Identity](/agent-identity/) for every way to present an identity.

## Implicit authentication

Warden authenticates every request where it lands. There is no login step for
an agent: when a request reaches a provider's gateway or access path, or any
other path of a namespace that sets an `auto_auth_path`, Warden hands the
credential to the auth mount that path names and asks it to **admit** it.

Which mount is asked comes from configuration, never from the request:

- **A provider's gateway and access paths** use the provider's
  `auto_auth_path`.
- **Other paths** use the namespace's `auto_auth_path`, kept in the
  namespace's custom metadata.

`X-Warden-Token` opts out. A request that carries it is authenticated by the
service token or ticket on that header, and the mount is not asked.

A request must also say which role it wants, because the credential carries
none. On a gateway path the role is the `role/<role>/` segment of the URL, the
`X-Warden-Role` header, or the provider's `default_role`. Elsewhere it is the
`?role=` query parameter or `X-Warden-Role`. A request that selects no role is
refused with `400` before its credential is checked; one with no credential at
all gets `401`.

## What "admit" means

An auth mount admits a credential when the credential passes every check the
mount is configured with: signature, issuer, audience, expiry, age, trust
anchor. Admitting it produces an **admission**: a record of what the mount
verified.

An admission holds:

- the **facts** the credential proved, under the names the mount publishes;
- the **native identity** (an *alias* in Warden's commands and fields): the one value that names
  this caller at this mount, such as a JWT's `sub` or a SPIFFE ID;
- the **principal**, recorded in audit and offered to policy as
  `agent.principal`;
- the **kind**: `agent` or `human`, from the mount's `entity_kind`.

Warden keeps **one cached admission per mount and credential**. The first
request with a given JWT or certificate is checked by the mount; the requests
that follow reuse the result until the credential expires or the mount's
`token_ttl` (default one hour) runs out, whichever is first. Concurrent first
requests share a single check. The admission lives in memory only; after a
restart the next request is admitted again.

The admission is then matched against the namespace's groups, which grant the
requested role or refuse it. Group and role edits apply from the next request,
and so do edits to a mount's `facts` and `entity_kind`, even for cached
admissions. If an [entity](/identity/entities/) in the identity store claims the
native identity, the request is attributed to that entity.

An explicit login against an agent mount runs the same checks and reports what
they verified, but hands out nothing to present on later requests. Agents
authenticate by presenting their own credential every time. The
[discovery server](/concepts/discovery-and-skills/) works the same way: it
admits the credential without a role and lists the roles it would be granted.

## Mount configuration

Each auth method has its own keys for *how* to verify: an OIDC discovery URL,
a CA bundle, a Kubernetes host. These five keys are shared and say *what* the
mount admits:

| Key | Methods | What it does |
|-----|---------|--------------|
| `entity_kind` | all | `agent` (default) or `human`. An `oidc` mount is always `human`. |
| `bound_audiences` | `jwt`, `spiffe`, `kubernetes` | Audiences a token must carry, any one of them. **Required** on an agent `jwt` or `spiffe` mount; on `kubernetes` it is sent to the TokenReview. |
| `max_age` | `jwt`, `kubernetes`, `spiffe` | Maximum age of a credential at admission, from its `iat`, e.g. `10m`. A credential older than that, or without an `iat`, is refused. On `spiffe` it applies to JWT-SVIDs only. |
| `facts` | all | Allowlist of extra facts: a map of source to fact name. |
| `alias_name_source` | all but `spiffe` | The fact whose first value is the caller's native identity. |

`bound_audiences` is required on agent mounts because without it, a token the
same issuer minted for any other relying party would be admitted. A config
write that leaves an agent `jwt` or `spiffe` mount without one is refused.

### `facts`

A mount publishes its built-in facts (below) and nothing else. Every other
claim stays invisible to groups and policy until `facts` names it. The map goes
from a **source** to the **fact name** it is published as:

- On `jwt` and `oidc`, a source is a claim name (`tenant`), or a JSON Pointer
  into nested claims (`/scp/0`, `/realm_access/roles`).
- On `cert`, `kubernetes` and `spiffe`, a source is one of the built-in fields,
  published again under a second name.

Fact names use lowercase letters, digits and `_ . : / -`. A mount maps at most
32 facts, and `mount` and `kind` are reserved. A write replaces the whole map;
an empty map clears it.

### `alias_name_source`

The native identity is what an entity claims and what groups and audit name the
caller by, so it should be stable and unique at the mount:

| Method | Allowed sources | Default |
|--------|-----------------|---------|
| `jwt`, `oidc` | any fact the mount publishes, built-in or mapped | `sub` |
| `cert` | `cn`, `dns_san`, `email_san`, `uri_san`, `serial` | `cn` |
| `kubernetes` | `username` or `service_account_uid` | `username` |
| `spiffe` | fixed to `spiffe_id`; a write setting it is refused | `spiffe_id` |

A change applies to credentials admitted after it. On `cert`, prefer `uri_san`
when the mount trusts more than one CA: two CAs can issue the same common name.

## Built-in facts

Every admission answers two facts whatever the method: `mount`, the admitting
mount's path in its namespace (e.g. `auth/jwt/`), and `kind`, `agent` or
`human`. Each method adds its own:

| Method | Built-in facts |
|--------|----------------|
| `jwt` | `sub`, `iss`, `aud` |
| `oidc` | `sub`, `iss`, `aud` (from the ID token) |
| `kubernetes` | `service_account_namespace`, `service_account_name`, `service_account_uid`, `username`, `groups`, `aud` |
| `cert` | `cn`, `serial`, `ou`, `org`, `dns_san`, `email_san`, `uri_san`, `ca` |
| `spiffe` | `spiffe_id`, `trust_domain`, `path`, `svid`, `aud` |

A few values worth knowing: the certificate `serial` is decimal, `ca` holds the
SHA-256 fingerprint (lowercase hex) of each trust anchor the certificate was
verified to, `svid` is `x509` or `jwt`, and Kubernetes `aud` holds the audiences
the TokenReview validated. An empty value is not a fact: a certificate without
a common name has no `cn`.

[Group](/identity/groups/) rules select on these facts. Mapped facts also reach
[CEL conditions](/concepts/cel-conditions/) as `agent.metadata.<name>`, a
multi-valued fact joined with commas.

## One mount, end to end

A `jwt` mount that admits agents from an OIDC issuer, publishes two extra facts
and takes the native identity from the client ID:

```bash
warden auth enable jwt

warden write auth/jwt/config '{
  "oidc_discovery_url": "https://idp.example.com",
  "bound_issuer": "https://idp.example.com",
  "bound_audiences": ["warden"],
  "max_age": "15m",
  "entity_kind": "agent",
  "facts": {
    "client_id": "client",
    "/scp/0": "first_scope"
  },
  "alias_name_source": "client"
}'

warden read auth/jwt/config
```

A JWT from that issuer, carrying `aud: warden` and issued less than fifteen
minutes ago, is now admitted with the facts `sub`, `iss`, `aud`, `client` and
`first_scope`, and the native identity is its `client_id`. It is granted
nothing until a [group](/identity/groups/) with a rule on `mount: auth/jwt/`
grants it a [role](/identity/roles/), and a provider or the namespace names
`auth/jwt/` as its `auto_auth_path`.

## The agent leg and the user leg

Most requests carry one identity: the agent's. A provider whose config sets
`user_auth_path` takes a second one: the user the agent acts for (see
[Delegation](/concepts/delegation/)). Each leg has its own channel:

| Leg | Where it arrives |
|-----|------------------|
| **Agent** | a client certificate, or `X-Warden-Agent-Token: <jwt>` |
| **User** | `Authorization: Bearer <jwt>` |

On a provider without `user_auth_path`, the agent's JWT rides `Authorization`
as usual and there is no user leg.

The two legs are not equal:

- **The agent authorizes.** It is admitted through the `auto_auth_path` mount,
  matched against groups and granted a role. That mount must admit agents: a
  credential admitted through a `human` mount is refused on the agent leg.
- **The user is identity only.** It is admitted through the `user_auth_path`
  mount, which should be a `human` mount; the provider's config read warns
  otherwise. The user is granted no role, no groups and no policies. Its mapped
  facts reach conditions as `user.metadata.<name>`.

The user's token must be meant for this resource, by one of two routes,
checked in this order:

1. the user mount sets `bound_audiences`, and checked the token against it; or
2. protected-resource metadata is on, and the token's `aud` names this
   provider's resource identifier.

With neither, every user credential is refused, and the provider's config read
says so.

A few more rules hold on a provider with a user leg:

- `X-Warden-Token` together with `Authorization` is refused with `400`: the
  first is an operator credential and carries no user.
- The user credential must differ from the agent's.
- A ticket is never accepted as the user.
- A missing user credential is not an error. The request runs with the agent
  alone, and a condition that needs a user answers `401` with a
  `WWW-Authenticate` challenge, so the client can sign the user in and retry.

The user leg is resolved on gateway requests only.

## People

People do not hold workload credentials, so they sign in through an `oidc`
mount with `warden login`. The browser opens at the identity provider; once the
person signs in, the mount issues a **ticket**: a sealed record of who they are
and the facts their ID token proved. It carries no role. Each command picks one,
which the person's groups must grant. See
[Human operators](/identity/human-operators/) and [Tokens](/identity/tokens/).

## CLI and client behaviour

The CLI reads `WARDEN_`-prefixed environment variables:

| Variable | Purpose |
|----------|---------|
| `WARDEN_ADDR` | Server address, e.g. `http://127.0.0.1:8400`. |
| `WARDEN_TOKEN` | A service token or ticket, sent on `X-Warden-Token`. A value starting with `eyJ` (a JWT) is sent as `Authorization: Bearer` instead. |
| `WARDEN_CLIENT_CERT` / `WARDEN_CLIENT_KEY` | Client certificate and key for mTLS. Set both. |
| `WARDEN_CACERT` / `WARDEN_CAPATH` | CA certificates that verify the server. |
| `WARDEN_TLS_SERVER_NAME` / `WARDEN_SKIP_VERIFY` | TLS verification tuning; skipping is for dev only. |
| `WARDEN_NAMESPACE` | Sets `X-Warden-Namespace`. |
| `WARDEN_ROLE` | Sets `X-Warden-Role`, the role the request asks for. |

With neither `WARDEN_TOKEN` nor a client certificate set, the CLI uses the
session `warden login` saved for the address and namespace, and the role chosen
with `warden role use`.

## Troubleshooting

- **`400`, no role selected.** Put the role in the URL, set `X-Warden-Role` (or
  `WARDEN_ROLE`), or pass `?role=` off the gateway.
- **`401`, no credential.** Send a bearer JWT, configure a client certificate,
  or set `WARDEN_TOKEN`.
- **`401` with a valid-looking JWT.** Check `bound_issuer`, `bound_audiences`
  and `max_age` on the mount the path's `auto_auth_path` names, and that the
  mount is not a `human` mount.
- **A role is refused.** The credential was admitted, but no group grants that
  role for these facts. The audit entry's `role_denied_reason` and `groups` say
  why.
- **A JWT sent as a Warden token.** A raw JWT on `X-Warden-Token` is not a
  Warden token and fails. The CLI moves `eyJ…` values to `Authorization`; do the
  same when you build requests yourself.

## See also

- [Tokens](/identity/tokens/): identity tokens, service tokens and tickets.
- [Groups](/identity/groups/) and [Roles](/identity/roles/): how an admitted
  caller is granted what it may do.
- [Entities](/identity/entities/): records that claim native identities.
- [Auth Methods](/auth-methods/): per-method setup.
- [Policies](/concepts/policies/) and [Namespaces](/concepts/namespaces/).
