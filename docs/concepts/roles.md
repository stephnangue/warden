# Roles

A **role** is the rule that turns a validated credential into an authorized
identity. It is configured on an [auth method](authentication.md#auth-methods)
and answers two questions:

- **Who matches?** — the binding constraints a presented credential must satisfy
  (which audiences, subjects, certificate names, service accounts, or SPIFFE IDs
  are accepted).
- **What do they get?** — the [policies](policies.md) and token settings granted
  to a caller who matches.

Roles are the bridge between authentication and authorization: authentication
proves a credential is genuine, the role decides what that credential is allowed
to become. Every issued [token](tokens.md) is stamped with the role it matched.

## Roles Are Per-Request

The credential proves *who* you are; the **role** decides *what you may do*. A
single credential carries no fixed authority of its own — it takes on the
policies of whichever role it presents. This has a few consequences worth
internalizing, because they shape how clients are expected to talk to Warden.

**The role is supplied on every request.** For transparent callers there is no
login and no session in which a role is fixed once; the role travels with each
individual request (via the `X-Warden-Role` header, the request path, or a query
parameter — see [Selecting a Role](#selecting-a-role)). The role is not a
property of the connection, it is a property of the request.

**Authorization happens per request, at runtime.** Because the role rides on the
request, Warden authorizes each request independently against the role it names.
There is no ambient, pre-granted authority sitting on the connection waiting to
be reused — every call is evaluated on its own terms. Internally Warden derives a
transparent token's identifier by hashing *credential + mount + role* together,
so a request that names a different role resolves to a different token with
different policies.

**Clients can change role mid-session.** The same workload, holding the same
credential, can present one role on one request and a different role on the
next. This is especially useful for **AI agents**: an agent can operate under a
least-privilege role for routine work and name a higher-privilege role only for
the specific request that genuinely needs it, narrowing the blast radius of any
single step without re-authenticating.

**One provider endpoint, many access levels.** Because authority comes from the
role rather than the route, the *same* provider endpoint can be reached at
different access levels simply by presenting different roles — a read-only role
and a read-write role can target the identical upstream, with Warden applying the
matching policies (and minting the matching credentials) for each.

## Where Roles Live

Each auth method holds its own set of roles, addressed relative to the method's
mount path:

```
auth/<method>/role/<name>
```

Create and inspect them with the standard read/write commands:

```bash
# Create or update a role
warden write auth/jwt/role/developer \
  bound_audiences=api.example.com \
  token_policies=dev \
  token_ttl=8h

# Read, list, and delete
warden read   auth/jwt/role/developer
warden list   auth/jwt/role
warden delete auth/jwt/role/developer
```

To discover which roles the **caller's own identity** can assume — without
knowing their names in advance — use the introspection command, which fans out
across every auth mount of the caller's credential type in the current
namespace:

```bash
warden role list
warden role list -auth-path auth/jwt/   # restrict to one mount
warden role list -o ndjson | jq -r .name
```

## Common Fields

Every role, regardless of auth method, shares the same grant fields:

| Field | Meaning |
|-------|---------|
| `token_policies` | The [policies](policies.md) attached to tokens issued for this role. |
| `token_ttl` | Lifetime of issued tokens. Stored as a duration string (e.g. `1h`, `8h`); defaults to **1h** when unset. |
| `cred_spec_name` | Name of a [credential spec](credentials.md) the issued token is scoped to — what Warden mints for callers of this role. |
| `description` | Human-readable description. |

> **`token_type` is not something you set.** Each auth method fixes the type of
> token its roles issue — `jwt_role`, `cert_role`, `kubernetes_role`, or
> `spiffe_role` — and the value is stamped automatically during role validation.
> See [Token Types](tokens.md#token-types).

## Binding Fields by Auth Method

The binding fields are what make a role specific to its auth method. They decide
which credentials match.

### JWT

| Field | Meaning |
|-------|---------|
| `bound_audiences` | `aud` claim values the JWT must carry. |
| `bound_subject` | Exact `sub` claim that must match. |
| `bound_claims` | Map of arbitrary claims that must all match. |
| `user_claim` | Claim used as the principal identity (default `sub`). |
| `groups_claim` | Claim holding group names, for dynamic group→policy mapping. |
| `group_policy_prefix` | Prefix prepended to each group name to form a policy name. |
| `max_age` | Rejects JWTs whose `iat` is older than this (e.g. `30m`), guarding against stale-token replay. |

### Certificate

| Field | Meaning |
|-------|---------|
| `allowed_common_names` | Glob patterns for the certificate CN. |
| `allowed_dns_sans` | Glob patterns for DNS SANs. |
| `allowed_email_sans` | Glob patterns for email SANs. |
| `allowed_uri_sans` | Segment-aware URI SAN patterns — `+` matches one segment, trailing `*` matches one or more (e.g. `spiffe://+/ns/*/sa/*`). |
| `allowed_organizational_units` | Allowed OUs. |
| `allowed_organizations` | Allowed organizations. |
| `certificate` | Role-specific trusted CA PEM, overriding the method's global CA. |
| `principal_claim` | Which field becomes the identity: `cn`, `dns_san`, `email_san`, `uri_san`, or `serial`. |

A certificate role must set **at least one** of the `allowed_*` constraints — a
role that would match any certificate is rejected at write time.

### Kubernetes

| Field | Meaning |
|-------|---------|
| `bound_service_account_names` | ServiceAccount names the workload must use. `*` matches any. |
| `bound_service_account_namespaces` | Namespaces the workload's ServiceAccount must live in. `*` matches any. |
| `audience` | Sent as `spec.audiences` in the TokenReview; the workload JWT must declare it or the kube-apiserver rejects the review. |
| `max_age` | Rejects ServiceAccount JWTs older than this. |

At least one of `bound_service_account_names` or
`bound_service_account_namespaces` must be a concrete value — both set to only
`*` is refused.

### SPIFFE

One SPIFFE role serves both SVID forms: an X.509-SVID (TLS client certificate)
or a JWT-SVID (bearer token).

| Field | Meaning |
|-------|---------|
| `trust_domain` | **Required.** The trust domain whose bundle the SVID must verify against. |
| `allowed_spiffe_ids` | Optional segment-aware SPIFFE ID patterns the verified SVID must match (e.g. `spiffe://example.org/ns/+/sa/*`). |
| `bound_audiences` | Audiences accepted for JWT-SVID logins. Ignored for X.509-SVIDs. |
| `groups_claim` | JWT-SVID claim holding group names for dynamic policy mapping. |
| `group_policy_prefix` | Prefix forming a policy name from each group (default `group-`). |

> **Note:** `bound_audiences` is optional at write time but required at JWT-SVID
> login. A role with no `bound_audiences` stays usable for X.509-SVIDs but
> rejects JWT-SVID logins **fail-closed** — writing such a role returns a warning
> to that effect.

## Selecting a Role

For an **explicit login**, the caller names the role directly.

For **transparent (implicit) authentication**, where the workload never logs in,
Warden resolves the role per request from the first of these that is present:

1. the `X-Warden-Role` header,
2. a role encoded in the request path — the canonical
   `<provider>/role/<role>/gateway/<api>` form — or a `role=` query parameter,
3. a provider-supplied default,
4. the auth method's **`default_role`**.

The `default_role` is set on the auth method's *config*, not on a role, and is
the fallback when a transparent caller supplies no role:

```bash
warden write auth/jwt/config default_role=workload
```

## Token TTL

A role's `token_ttl` caps, but does not extend, the life of an issued token. The
effective expiry is the **minimum** of the role's `token_ttl` and the lifetime
of the credential it was derived from (a JWT's `exp`, a certificate's validity
window). A token never outlives the credential that produced it.

There is no `max_ttl` field and tokens are **not renewable** — see
[Expiration and renewal](tokens.md#expiration-and-renewal). When a token
expires, an explicit caller logs in again; a transparent caller's next request
re-mints one automatically.

## See Also

- [Authentication](authentication.md) — how a credential is proven before a role
  is applied.
- [Tokens](tokens.md) — what a role issues.
- [Policies](policies.md) — what a role grants.
- [Credentials](credentials.md) — what `cred_spec_name` points at.
- [Namespaces](namespaces.md) — the scope roles and their tokens live in.
