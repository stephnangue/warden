package logical

// Reasons a role grant records when it grants nothing. Each is a fixed string,
// written to audit as role_denied_reason; none carries a fact value, a group
// name or a selector value.
const (
	// RoleDeniedNoRole: the request named no role (no role/<name>/ segment, no
	// X-Warden-Role, no ?role=, no provider default_role).
	RoleDeniedNoRole = "no role selected"

	// RoleDeniedNotFound: the namespace has no role by the requested name.
	RoleDeniedNotFound = "role not found"

	// RoleDeniedNotAssumable: the role exists, but none of the caller's groups
	// grants it.
	RoleDeniedNotAssumable = "not assumable"

	// RoleDeniedExplicitAdmission: an admission token was presented as a
	// Warden token instead of the credential it was admitted from. An
	// admission token is granted a role only on the request that admitted the
	// credential.
	RoleDeniedExplicitAdmission = "admission token presented explicitly"

	// RoleDeniedNoAdmission: a token that takes its role per request carries
	// no admission to compute membership from.
	RoleDeniedNoAdmission = "no admission on token"
)

// Reasons an identity verdict refuses an agent before any role is considered:
// the native identity the credential presented, and the entity that claims it.
// Recorded as the role grant's DeniedReason, so a refused request is refused
// by construction.
const (
	// RoleDeniedIdentityNone: the credential presents no native identity
	// through its mount (the mount derives none from it), under
	// unknown_aliases=deny.
	RoleDeniedIdentityNone = "no native identity"

	// RoleDeniedIdentityUnclaimed: no entity claims the native identity, under
	// unknown_aliases=deny.
	RoleDeniedIdentityUnclaimed = "unclaimed"

	// RoleDeniedEntitySuspended: the entity that claims the native identity
	// is suspended. Refused in every mode.
	RoleDeniedEntitySuspended = "entity suspended"

	// RoleDeniedEntityRetired: the entity that claims the native identity is
	// retired. Refused in every mode.
	RoleDeniedEntityRetired = "entity retired"

	// RoleDeniedEntityNotGoverned: the entity that claims the native identity
	// is not governed (no accepted sponsor, or no description), under
	// unknown_aliases=deny.
	RoleDeniedEntityNotGoverned = "entity not governed"
)

// RoleGrant is the role a request runs under, resolved once per request from
// the caller's admission and never stored on a token. Core creates it when it
// resolves the grant, only for a token that takes its role per request; every
// other request has none.
//
// A RoleGrant belongs to one request and is read and written by that request's
// goroutine only. Role and Groups are shared with the published role and the
// cached membership and must not be modified.
type RoleGrant struct {
	// RoleName is the requested role.
	RoleName string

	// Role is the published role, when the namespace has one by RoleName.
	Role *Role

	// GrantedBy labels the group that grants the role ("group:<name>"); empty
	// when nothing grants it, in which case DeniedReason says why.
	GrantedBy string

	// GroupType is the type of the group GrantedBy names: virtual for an
	// unclaimed caller, static for a claimed one, never virtual when claimed.
	GroupType GroupType

	// Groups are the caller's groups, sorted. Shared with the cached
	// membership: read only.
	Groups []string

	// DeniedReason is one of the RoleDenied constants when GrantedBy is empty.
	DeniedReason string

	// IdentityStatus is what unknown_aliases=deny refuses the caller for, one
	// of the identity RoleDenied constants, in every mode; empty when the
	// caller's identity is accounted for, and for a human. Under observe it
	// refuses nothing: it is deny's dry run. When it refuses, DeniedReason
	// holds the same value.
	IdentityStatus string
}

// Granted reports whether g grants its role.
func (g *RoleGrant) Granted() bool {
	return g != nil && g.GrantedBy != ""
}
