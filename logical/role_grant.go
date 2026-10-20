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

// RoleGrant is the role a request runs under, resolved once per request from
// the caller's admission and never stored on a token. A transparent request
// creates it with the requested RoleName before it authenticates; core fills
// the rest when it resolves the grant, and drops it (sets Request.RoleGrant to
// nil) for a token that does not take its role per request.
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

	// Groups are the caller's groups, sorted. Shared with the cached
	// membership: read only.
	Groups []string

	// DeniedReason is one of the RoleDenied constants when GrantedBy is empty.
	DeniedReason string
}

// Granted reports whether g grants its role.
func (g *RoleGrant) Granted() bool {
	return g != nil && g.GrantedBy != ""
}
