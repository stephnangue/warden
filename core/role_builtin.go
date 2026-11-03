package core

import (
	"fmt"
	"slices"
	"strings"

	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logical"
)

// The built-in operator roles. Defined here and versioned with the binary:
// they are never stored, so an upgrade changes them in every namespace at once,
// and no operator can edit one. To customize one, copy its body to a policy and
// a role of your own; the copy is an ordinary policy, and grants what the
// built-in grants.
//
// A built-in resolves in the root namespace always, and in another namespace
// only when that namespace's record enables built-in roles. Its body is a
// policy like any other, compiled in the token's namespace, and reaches every
// namespace below it (see builtinRoles); the policy's namespace prefix and the
// token store's namespace check (namespace.Within) both keep it out of the
// parent and the siblings. The server's
// root-only paths (restrictedSysAPIs, requireRootNamespace) stay root-only, so
// warden-admin of a namespace is that namespace's admin, not the cluster's.
//
// A built-in carries no credential spec and is refused on every data-plane
// path before routing: operators manage, agents call upstreams.

// builtinRolePrefix starts every built-in role name. The prefix is reserved:
// no stored role may take a name starting with it, in any case.
const builtinRolePrefix = "warden-"

type builtinRole struct {
	// role is the value a grant resolves to, shared by every request and read
	// only. Policies is nil and CredSpecName empty: the body below is the whole
	// grant.
	role *logical.Role
	// body is the CBP the role grants, its paths relative to the namespace it
	// is compiled in.
	body string
}

// builtinRoles lists the built-ins. The order is the order they are listed
// in.
//
// Each body but warden-admin's is one "*" stanza whose condition names the
// paths it covers. A path stanza is relative to the namespace its policy is
// compiled in, so "sys/roles/*" in acme/ would match acme/sys/roles/ and
// nothing in acme/dev/; request.path is relative to the namespace of the
// request, so the condition reads alike in the namespace and in every one
// below it. Stanzas at one path merge, so a body has one, holding the union of
// the role's capabilities: the condition decides where it applies. Sudo
// counts only on a Root path, and every Root path a condition admits is one
// the role administers (TestBuiltinRoles_RootPaths).
var builtinRoles = [...]builtinRole{
	{
		role: builtinRoleValueOf("warden-admin",
			"Everything in this namespace and every namespace below it."),
		body: `
path "*" {
  capabilities = ["create", "read", "update", "delete", "list", "patch", "scan", "sudo"]
}
`,
	},
	{
		role: builtinRoleValueOf("warden-provider-admin",
			"Providers, credential sources and specs, and skills: mount, configure and tune providers, never call their upstreams."),
		body: `
# The last line: every provider mount's control paths (its config, grants
# and the rest), never its gateway or access paths.
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
`,
	},
	{
		role: builtinRoleValueOf("warden-security-admin",
			"Who may do what: policies, roles, groups, entities, auth methods and audit devices. It can grant itself any role by writing a group."),
		body: `
# sys/identity/ holds groups, entities, lookup, config and usage; its sponsor
# paths answer to the sponsor group whatever this grants. The last line:
# every auth mount's own paths, its config and the rest.
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
`,
	},
	{
		role: builtinRoleValueOf("warden-viewer",
			"Reads the configuration of this namespace and every namespace below it, secrets masked. Never a mount's own config paths, never audit-hash."),
		body: `
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
`,
	},
}

// builtinRoleValueOf builds the shared value of a built-in.
func builtinRoleValueOf(name, description string) *logical.Role {
	return &logical.Role{
		Name:        name,
		Description: description,
		// Never governed_only: built-ins are for humans, granted through
		// virtual groups, and for governed agents through static groups. A
		// governed_only built-in would refuse every human.
		GovernedOnly: false,
	}
}

// builtinRoleIndex returns the index of the built-in named name in
// builtinRoles, or -1. Exact case: "Warden-Admin" names no built-in.
func builtinRoleIndex(name string) int {
	if !strings.HasPrefix(name, builtinRolePrefix) {
		return -1
	}
	for i := range builtinRoles {
		if builtinRoles[i].role.Name == name {
			return i
		}
	}
	return -1
}

// isBuiltinRoleName reports whether name is a built-in role.
func isBuiltinRoleName(name string) bool {
	return builtinRoleIndex(name) >= 0
}

// isReservedRoleName reports whether name is in the space reserved for
// built-in roles: it starts with builtinRolePrefix in any case, so no stored
// role can look like a built-in.
func isReservedRoleName(name string) bool {
	return len(name) >= len(builtinRolePrefix) && strings.EqualFold(name[:len(builtinRolePrefix)], builtinRolePrefix)
}

// errReservedRoleName refuses a write to a name in the reserved space: the
// built-in itself is read only, and any other name there is reserved.
func errReservedRoleName(name string) error {
	if isBuiltinRoleName(name) {
		return logical.ErrBadRequestf("role %q is built-in and read-only; copy policy_document to a policy and a role of your own", name)
	}
	return logical.ErrBadRequestf("role names starting %q are reserved for built-in roles; choose another name", builtinRolePrefix)
}

// builtinRolesEnabled reports whether the built-in roles resolve in the
// namespace nsID, whose record is ns: always in root, elsewhere when the
// record enables them.
func builtinRolesEnabled(nsID string, ns *namespace.Namespace) bool {
	return nsID == namespace.RootNamespaceID || (ns != nil && ns.ID == nsID && ns.EnableBuiltinRoles)
}

// builtinRoleValue returns the shared value of the built-in named name, or nil.
func builtinRoleValue(name string) *logical.Role {
	if i := builtinRoleIndex(name); i >= 0 {
		return builtinRoles[i].role
	}
	return nil
}

// namespaceRoles returns the roles a grant in namespace ns resolves, sorted by
// name: its stored roles, less any stored under a reserved name (they grant
// nothing), and the built-ins when ns has them. The roles are shared: read
// only.
func (c *Core) namespaceRoles(ns *namespace.Namespace) []*logical.Role {
	var out []*logical.Role
	if c.roleStore != nil {
		out = slices.DeleteFunc(c.roleStore.snapshot.Load().roles(ns.ID), func(r *logical.Role) bool {
			return isReservedRoleName(r.Name)
		})
	}
	if builtinRolesEnabled(ns.ID, ns) {
		for i := range builtinRoles {
			out = append(out, builtinRoles[i].role)
		}
		slices.SortFunc(out, func(a, b *logical.Role) int { return strings.Compare(a.Name, b.Name) })
	}
	return out
}

// builtinRoleGroupWarnings are the warnings of a write of group g, in
// namespace ns, listing role, a name in the reserved space. mounts are the
// namespace's auth mounts, for a virtual group.
func builtinRoleGroupWarnings(ns *namespace.Namespace, g *logical.Group, role string, mounts []authMountFacts) []string {
	if !isBuiltinRoleName(role) {
		return []string{fmt.Sprintf("role name %q is reserved for built-in roles and names none; the group grants nothing through it", role)}
	}
	if !builtinRolesEnabled(ns.ID, ns) {
		return []string{fmt.Sprintf("role %q is a built-in role and built-in roles are not enabled in this namespace (enable_builtin_roles=false); the group grants it once they are", role)}
	}
	// A static group lists governed entities: the accountable way to give an
	// agent an operator role, so it warns of nothing.
	if g.Type != logical.GroupTypeVirtual {
		return nil
	}
	var out []string
	for i, rule := range g.Rules {
		for _, m := range mounts {
			if m.kind == string(logical.EntityKindAgent) && ruleTrustsMount(rule, m.path) && ruleAdmitsKind(rule, m.kind) {
				out = append(out, fmt.Sprintf("rules[%d]: mount %q admits agents; an unclaimed agent would hold the operator role %q through this rule — list a governed entity in a static group instead", i, m.path, role))
				break
			}
		}
	}
	return out
}
