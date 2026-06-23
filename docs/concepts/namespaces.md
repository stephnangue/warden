# Namespaces

A **namespace** is Warden's isolation boundary — its unit of multi-tenancy.
Every [provider](providers.md) mount, [auth method](authentication.md#auth-methods),
[role](roles.md), [policy](policies.md), [credential](credentials.md) source and
spec, and [token](tokens.md) belongs to exactly one namespace, and the boundary
between namespaces is hard: configuration in one is invisible to another, and a
policy in one cannot grant access in, or even name, another.

Namespaces let a single Warden serve many independent tenants — teams, products,
environments — each with its own mounts, identities, and policies, on shared
infrastructure.

## The Root Namespace

Every server has a **root namespace**. It is the top of the tree, its path is the
empty string `""`, and it is addressed with no namespace prefix at all
(`/v1/sys/...`, `/v1/<mount>/...`). The root namespace always exists, cannot be
deleted, and is where server-wide operations live (see
[Root-only operations](#root-only-operations)).

## Hierarchy

Namespaces are **hierarchical**. A namespace has a path like `team-a/` or
`team-a/service-b/`, and a child can only be created beneath a parent that
already exists. Paths are canonicalized to always end in `/`.

```
""                       ← root
├── team-a/
│   └── team-a/service-b/
└── team-c/
```

There is no fixed depth limit. Each namespace is identified three ways:

- **Path** — the addressable, hierarchical name (`team-a/service-b/`).
- **ID** — a short, stable, human-friendly accessor.
- **UUID** — the internal identifier used to prefix the namespace's storage,
  giving each namespace a fully separate slice of the backend.

## What Is Isolated

Everything operational is scoped to a namespace and stored under that namespace's
own storage prefix:

- provider mounts and auth-method mounts,
- roles and policies,
- credential sources and specs,
- tokens, and their rotation and expiration state.

Creating a mount, writing a policy, or issuing a token happens *in* a namespace
and is visible only there. Deleting a namespace tears all of it down together
(see [Lifecycle](#managing-namespaces)).

### The one cross-namespace rule

The boundary is one-directional along the hierarchy: a [token](tokens.md) issued
in a **parent** namespace is valid in that namespace **and all of its
descendants**, but never in a sibling or an ancestor. This is the *only* way
identity crosses a namespace line — a child's token cannot reach up to its
parent, and unrelated namespaces are completely sealed from one another.

## Addressing a Namespace

A request carries its namespace the same two ways the
[provider routing](providers.md#namespace-in-the-request) examples show — and
they are equivalent because Warden prepends the header to the path and resolves
the longest matching namespace prefix:

- **In the path**, right after the API prefix: `/v1/team-a/<mount>/...`.
- **In the `X-Warden-Namespace` header**, leaving it out of the URL. The CLI sets
  this from `WARDEN_NAMESPACE`.

The two even combine: a header naming a parent plus a path under a child resolves
to the child. The root namespace needs neither. A mount's agent-facing URL is
always reported with its namespace baked in (`/v1/team-a/<mount>/...`).

## Root-only Operations

Namespace-scoped management works in **any** namespace: mounts, auth methods,
policies, roles, tokens, credentials, and nested `namespaces` are all created and
managed inside whichever namespace the request resolves to.

Server-wide and operational endpoints, however, are restricted to the **root
namespace**. Attempting one in a child namespace returns *"operation unavailable
in namespaces."* These include the seal/unseal and `init` lifecycle, key
rotation and rekey, audit and CORS configuration, raw storage access, metrics
and health, and the other `sys/` endpoints that act on the server as a whole
rather than on a tenant's resources.

The principle: a namespace governs its own tenants' mounts and identities; it
does not touch the server everyone shares.

## Transparent Auth per Namespace

A namespace carries a `custom_metadata` map. One key is meaningful to Warden:
**`auto_auth_path`**, which names the auth mount used for
[transparent authentication](authentication.md#transparent-authentication)
on *operational* requests in that namespace — the namespace-level counterpart to
a [provider's](providers.md) own `auto_auth_path` for gateway requests. Set it so
that callers in the namespace can authenticate implicitly from a JWT or
certificate without an explicit login.

## Managing Namespaces

Namespaces are created, read, listed, updated, and deleted from the CLI. The
path is positional; `custom_metadata` is set with repeatable `-metadata` flags:

```bash
warden namespace create team-a
warden namespace create team-a/service-b -metadata=env=prod -metadata=owner=platform

warden namespace read   team-a            # id, uuid, path, custom_metadata, locked, tainted
warden namespace list                     # -recursive / -R to descend; -include-parent
warden namespace update team-a -metadata=env=staging
warden namespace delete team-a            # prompts; -f to skip
```

Namespaces live under `sys/namespaces/<path>`. A few lifecycle rules:

- **Deletion cascades.** Removing a namespace revokes its tokens and clears its
  mounts, policies, and credential configuration in one operation; large
  deletions run asynchronously.
- **No deleting a non-empty parent.** A namespace that still has child namespaces
  cannot be deleted — remove the children first.
- **Root is permanent.** The root namespace cannot be deleted.

The `read` output also reports two status fields: `tainted` (the namespace is
mid-creation or mid-deletion and should be treated as transient) and `locked`.

## See Also

- [Authentication](authentication.md) — identity is established within a namespace.
- [Tokens](tokens.md) — the parent→descendant validity rule in detail.
- [Policies](policies.md) — per-namespace, isolated authorization.
- [Providers](providers.md) — namespace addressing on gateway requests.
- [Credentials](credentials.md) — sources and specs are namespace-scoped.
