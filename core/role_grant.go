package core

import (
	"fmt"
	"time"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/logical"
)

// takesRoleGrant reports whether te takes its role per request rather than
// carrying one: a token an auth mount issued (it names the mount) with no role
// of its own. Every login that names a role, and every token reloaded from
// storage, carries the role it was issued for; root and other tokens no mount
// issued name no mount. Neither qualifies, and both keep authorizing exactly as
// before.
//
// A qualifying token is an admission token. One without an admission (a token
// of that shape built any other way) qualifies too and is refused, never
// treated as a role token.
func takesRoleGrant(te *logical.TokenEntry) bool {
	return te.MountAccessor != "" && te.RoleName == ""
}

// resolveRoleGrant decides the role req runs under when its token te takes its
// role per request, and projects that role onto te. The role asked for is
// req.RequestedRole, which only implicit auth sets (with req.Transparent): a
// qualifying token on a request that is not transparent was presented
// explicitly and is refused. For any other token it clears req.RoleGrant,
// leaves te untouched and allocates nothing.
//
// te must be this request's own copy of the token entry: the role, its
// policies and spec, and the membership's metadata are written onto it, and
// every consumer downstream (the CBP, CEL, audit, the mint, assertions) reads
// them there. Every path that hands over a token entry hands over a copy.
//
// The grant is computed from the namespace's published groups and roles, read
// once each, and the admission's cached membership under them at now. On a
// grant it sets req.RoleGrant.GrantedBy; on a refusal, DeniedReason, and te
// keeps no policies and no spec, so the request is refused by the CBP even if
// nothing else refused it. A role edit, a group edit or a mapping edit is seen
// by the next request of a cached admission: nothing here is cached on the
// token.
//
// Lock-free; on a steady membership a granted request allocates only its
// RoleGrant.
func (c *Core) resolveRoleGrant(req *logical.Request, te *logical.TokenEntry, now time.Time) {
	if !takesRoleGrant(te) {
		req.RoleGrant = nil
		return
	}

	// Whatever happens below, an admission token runs with the granted role's
	// policies and spec or with none.
	te.Policies = nil
	te.CredentialSpec = ""

	if !req.Transparent {
		// Only implicit auth, admitting this request's own credential, asks
		// for a role: this admission token arrived as a Warden token.
		req.RoleGrant = &logical.RoleGrant{DeniedReason: logical.RoleDeniedExplicitAdmission, Groups: noGroups}
		return
	}
	rg := &logical.RoleGrant{RoleName: req.RequestedRole, Groups: noGroups}
	req.RoleGrant = rg

	adm := te.Admission
	if adm == nil {
		rg.DeniedReason = logical.RoleDeniedNoAdmission
		return
	}

	// The membership's metadata map is shared by every request of this
	// credential. TokenEntry.Metadata is read only on every copy, so it is
	// projected as is, not copied.
	m := membership(adm, c.grantGroups(te.NamespaceID), now)
	rg.Groups = m.Groups
	te.Metadata = m.Metadata

	if rg.RoleName == "" {
		rg.DeniedReason = logical.RoleDeniedNoRole
		return
	}
	role := c.grantRole(te.NamespaceID, rg.RoleName)
	if role == nil {
		rg.DeniedReason = logical.RoleDeniedNotFound
		return
	}
	g, ok := m.Roles[role.Name]
	if !ok {
		rg.DeniedReason = logical.RoleDeniedNotAssumable
		return
	}

	rg.Role, rg.GrantedBy = role, g.Label
	te.RoleName = role.Name
	te.Policies = role.Policies
	te.CredentialSpec = role.CredSpecName
}

// grantGroups returns the published groups of namespace nsID: none when the
// namespace has none or the store is not loaded (a standby, a sealed node), so
// nothing is granted there.
func (c *Core) grantGroups(nsID string) *nsGroups {
	if c.identityStore == nil {
		return emptyNSGroups
	}
	return c.identityStore.namespaceGroups(nsID)
}

// grantRole returns the published role name of namespace nsID, or nil when
// there is none or the store is not loaded. The role is shared: read only.
func (c *Core) grantRole(nsID, name string) *logical.Role {
	if c.roleStore == nil {
		return nil
	}
	e := c.roleStore.snapshot.Load().lookup(nsID, name)
	if e == nil {
		return nil
	}
	return e.role
}

// testHookSkipRoleVerdict, when set, makes performPolicyChecks skip the role
// verdict, so a test can show a refused grant is refused by the CBP alone.
// False outside tests, which set it before starting any request and clear it
// after the last one returns.
var testHookSkipRoleVerdict bool

// ErrRoleNotGranted refuses a request whose token takes its role per request
// and was granted none. It reads as the refusal's message and unwraps to
// ErrPermissionDenied, so it answers 403 and counts as a denial wherever one is
// recognised.
type ErrRoleNotGranted struct {
	DeniedReason string // one of the logical.RoleDenied constants
	Message      string
}

func (e *ErrRoleNotGranted) Error() string { return e.Message }

func (e *ErrRoleNotGranted) Unwrap() error { return sdklogical.ErrPermissionDenied }

// roleRefusal words the refusal of an ungranted rg for the caller. It names the
// requested role and the admitting mount, both of which the caller chose or
// presented, and never a group, a fact or a selector value.
func roleRefusal(rg *logical.RoleGrant, te *logical.TokenEntry) *ErrRoleNotGranted {
	var msg string
	switch rg.DeniedReason {
	case logical.RoleDeniedNoRole:
		msg = "no role selected: put the role in the URL (role/<name>/), set X-Warden-Role, or set the provider's default_role"
	case logical.RoleDeniedNotFound:
		msg = fmt.Sprintf("role %q not found", rg.RoleName)
	case logical.RoleDeniedNotAssumable:
		var mount string
		if te != nil && te.Admission != nil {
			mount = te.Admission.MountPath
		}
		if mount != "" {
			msg = fmt.Sprintf("role %q is not assumable through %s: no group grants it to this caller", rg.RoleName, mount)
		} else {
			msg = fmt.Sprintf("role %q is not assumable: no group grants it to this caller", rg.RoleName)
		}
	case logical.RoleDeniedExplicitAdmission:
		msg = "admission token presented explicitly; present the credential instead"
	case logical.RoleDeniedNoAdmission:
		msg = "token carries no admission to grant a role from; present the credential instead"
	default:
		msg = "no role granted"
	}
	return &ErrRoleNotGranted{DeniedReason: rg.DeniedReason, Message: msg}
}
