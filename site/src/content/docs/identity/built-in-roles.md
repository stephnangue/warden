---
title: "Built-in roles"
---

Warden defines four operator roles in code, so a deployment does not have to
write its own admin and read-only policies before anyone can run it:

| Role | For |
|---|---|
| `warden-admin` | Everything in this namespace and every namespace below it. |
| `warden-provider-admin` | Providers, credential sources and specs, and skills: mount, configure and tune providers, never call their upstreams. |
| `warden-security-admin` | Who may do what: policies, roles, groups, entities, auth methods and audit devices. It can grant itself any role by writing a group. |
| `warden-viewer` | Reads the configuration of this namespace and every namespace below it, secrets masked. Never a mount's own config paths, never audit-hash. |

They ship with the binary and are never stored: an upgrade changes them in
every namespace at once, and nobody can edit one. Each is a role like any
other in every other way: a [group](/identity/groups/) grants it, a request
names it, and the [policy](/concepts/policies/) it carries decides the call.
They are meant for people who sign in with `warden login` (see
[Human operators](/identity/human-operators/)).

## What each role grants

A built-in role has no credential spec and no named policies. Its whole grant
is one policy body, which `warden role read <name> -fields policy_document`
prints. Every body but `warden-admin`'s is a single `path "*"` stanza whose
[condition](/concepts/cel-conditions/) names the paths it covers.
`request.path` is relative to the namespace of the request, so a condition
reads the same in every namespace the role reaches.

**`warden-admin`** holds every capability, `sudo` included, on every path:

```hcl
path "*" {
  capabilities = ["create", "read", "update", "delete", "list", "patch", "scan", "sudo"]
}
```

**`warden-provider-admin`** holds every capability on the provider surfaces of
the system backend, and on every provider mount's control paths (its config,
its grants and the rest), never its gateway or access paths:

```hcl
path "*" {
  capabilities = ["create", "read", "update", "delete", "list", "patch", "scan", "sudo"]
  condition    = <<EOT
request.path == "sys/providers" ||
request.path == "sys/skills" ||
request.path.startsWith("sys/providers/") ||
request.path.startsWith("sys/cred/") ||
request.path.startsWith("sys/skills/") ||
(request.mount_class == "provider" && !request.data_plane)
EOT
}
```

**`warden-security-admin`** holds every capability but `scan` on roles,
policies, the identity store (groups, entities, lookup, config and usage),
auth methods and every auth mount's own paths, audit devices, the OIDC issuer
configuration and the protected-resource metadata:

```hcl
path "*" {
  capabilities = ["create", "read", "update", "delete", "list", "patch", "sudo"]
  condition    = <<EOT
request.path == "sys/roles" ||
request.path == "sys/auth" ||
request.path == "sys/audit" ||
request.path == "sys/oidc-issuer/config" ||
request.path == "sys/protected-resource/config" ||
request.path.startsWith("sys/policies/") ||
request.path.startsWith("sys/roles/") ||
request.path.startsWith("sys/identity/") ||
request.path.startsWith("sys/auth/") ||
request.path.startsWith("sys/audit/") ||
request.mount_class == "auth"
EOT
}
```

The [sponsor](/identity/sponsors/) paths under `sys/identity/` answer to the
entity's sponsor group, whatever this role grants.

**`warden-viewer`** holds `read` and `list` on the same configuration, with
`sudo` so it can read the paths that require it, such as roles and groups:

```hcl
path "*" {
  capabilities = ["read", "list", "sudo"]
  condition    = <<EOT
request.path == "sys/providers" ||
request.path == "sys/skills" ||
request.path == "sys/roles" ||
request.path == "sys/auth" ||
request.path == "sys/audit" ||
request.path == "sys/namespaces" ||
request.path == "sys/oidc-issuer/config" ||
request.path == "sys/protected-resource/config" ||
request.path.startsWith("sys/providers/") ||
request.path.startsWith("sys/cred/") ||
request.path.startsWith("sys/skills/") ||
request.path.startsWith("sys/policies/") ||
request.path.startsWith("sys/roles/") ||
request.path.startsWith("sys/identity/") ||
request.path.startsWith("sys/auth/") ||
request.path.startsWith("sys/audit/") ||
request.path.startsWith("sys/namespaces/")
EOT
}
```

A credential spec read masks every field that may hold a secret, and a
namespace read carries no unlock key. The viewer never reaches a mount's own
paths, such as `aws/config` or `auth/oidc/config`, because nothing masks what
they return, and never `sys/audit-hash`.

Audit devices, the OIDC issuer, the protected-resource metadata and the other
[root-only operations](/concepts/namespaces/#root-only-operations) stay
root-only: in any other namespace they are refused whatever the role, so the
roles that cover them use them in root only.

## Where they exist

The root namespace always has the built-in roles. Any other namespace has
them only when its parent turns on `enable_builtin_roles` in the namespace's
record:

```bash
warden namespace create acme -json '{
  "enable_builtin_roles": true
}'
```

For an existing namespace, `-enable-builtin-roles` turns them on and
`-enable-builtin-roles=false` off:

```bash
warden namespace update acme -enable-builtin-roles
```

- **Only the parent decides.** A namespace's record is written from its
  parent, never from inside it, so a tenant cannot turn the roles on for
  itself. A tenant's `warden-admin` writes the records of the tenant's
  children, so it decides for them.
- **Not inherited.** `acme/dev/` does not have them because `acme/` does.
- **Turning it off is refused** while a group of the namespace still grants a
  built-in role. The refusal names each group, its type and the role:

  ```
  enable_builtin_roles cannot be turned off: groups still grant
  built-in roles: platform-admins (virtual, warden-admin),
  terraform-runners (static, warden-provider-admin)
  ```

Role names starting `warden-`, in any case, are reserved. Creating or
updating a role under such a name is refused.

## Granting them

Groups grant the built-in roles, like any other role. For people, a virtual
group over their identity provider's claims:

```bash
warden identity group create platform-admins -json '{
  "type": "virtual",
  "description": "People holding the Warden.Admin app role",
  "roles": ["warden-admin"],
  "rules": [
    {
      "mount": ["auth/oidc/"],
      "kind": ["human"],
      "app_roles": ["Warden.Admin"]
    }
  ]
}'
```

For an agent, a static group listing its entity: the agent then holds the
role only while its entity is governed and active, and someone answers for it.

```bash
warden identity group create terraform-runners -json '{
  "type": "static",
  "description": "Terraform agents that manage providers",
  "members": ["terraform-runner"],
  "roles": ["warden-provider-admin"]
}'
```

A group write warns, without refusing, when:

- the namespace does not have the built-in roles yet: the group grants the
  role once they are turned on;
- a virtual group's rule trusts a mount that admits agents: any unclaimed
  agent from that mount would hold the operator role, so list a governed
  entity in a static group instead. A `"kind": ["human"]` selector keeps a
  rule to people;
- the group names a reserved role that is not one of the four.

A static group that lists a built-in raises no warning. No built-in role is
`governed_only`: that would refuse every person, since people are granted
roles through virtual groups only.

## Where a grant reaches

A built-in role's body is compiled in the namespace of the caller's token,
like every other policy. A person who signs in through an `acme/` mount and is
granted `warden-admin` there administers `acme/` and every namespace below
it, `sudo` included. The same grant is refused in root and in a sibling such
as `acme-other/`, and the root-only operations stay root-only. The
`warden-admin` of a tenant administers that tenant, not the cluster.

The grant itself also comes from the token's namespace. A ticket issued in
root and used in `acme/` holds the built-in roles that root's groups grant it,
whether or not `acme/` has them turned on.

## Never on a data plane

A built-in role manages Warden; it never calls an upstream. A request under
one on a provider's gateway or access path is refused with `400`, after it is
audited and before anything is minted or routed:

```
role "warden-admin" is a built-in operator role and has no data plane
```

Policies tell the two apart with `request.data_plane`, which is true on a
provider's gateway and access paths and false on its config and grant paths,
on system and auth paths, and on `sys/mcp`. Discovery lists the built-in roles
a caller holds without a `url` or a `skill`, with a warning that they are
used on Warden's own API, with `?role=` or `X-Warden-Role`.

## Reading them

```bash
warden role read warden-viewer -fields policy_document
warden role list -all
```

A read marks a built-in role as built-in and prints the body it grants.
`warden role list -all` shows them among the stored roles, in its Built-in
column; `-provider-path` leaves them out.

## Customising one

Copy the body into a policy of your own and give it to a role of your own:

```bash
warden policy write ops-viewer ops-viewer.hcl
warden role create ops-viewer -json '{
  "description": "Reads providers and roles",
  "policies": ["ops-viewer"]
}'
```

The copy is an ordinary policy and grants what the built-in grants, in the
namespace where the role is used and every namespace below it. Two
differences come with it: the copy is not refused on a data plane the way the
built-in is, so keep `!request.data_plane` in its condition; and it exists
in every namespace, whatever `enable_builtin_roles` says.

## Things to know

**`warden-security-admin` can make itself anything.** It writes groups, and a
group can grant any role, `warden-admin` included. That is by design: deciding
who may do what is the power to give yourself anything. Grant it as you would
`warden-admin`.

**A condition holds only while no other stanza drops it.** Stanzas at the same
path merge across the policies of a grant, and one without a condition makes
the path unconditional. An unconditional `path "*"` in another policy of the
role that holds a copied body applies the body's capabilities to every path.
The same goes for a built-in role if someone edits one of the namespace's
default policies to add an unconditional `path "*"`.

**An edited default policy outranks a built-in only in its own namespace.**
The token's namespace's default policies are attached beside the body, and the
most specific path decides. A stanza an operator adds there for a specific
path decides that path in the token's namespace; in the namespaces below it,
that stanza does not match and the body decides.

**A role read follows the namespace; a grant follows the token.**
`warden role read warden-admin` in a namespace finds the built-in when that
namespace has the roles turned on. A grant looks at the token's namespace. A
`warden-admin` of `acme/` working in `acme/dev/` holds the role there even
when a read of it in `acme/dev/` finds nothing.

## See also

- [Human operators](/identity/human-operators/) — signing people in and granting them roles.
- [Groups](/identity/groups/) — virtual and static groups.
- [Roles](/identity/roles/) — how a request selects a role.
- [Entities](/identity/entities/) — governing an agent before it holds an operator role.
- [Namespaces](/concepts/namespaces/) — the hierarchy the roles reach down.
